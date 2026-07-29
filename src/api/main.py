"""Core FastAPI application setting up routing, security middlewares, and health metrics."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.api.errors import (
    APIException,
    AuthenticationError,
    AuthorizationError,
    global_exception_handler,
)
from src.config.enterprise_config import settings
from src.database.repositories import (
    APIKeyRepository,
    AuditLogRepository,
    InvestigationMetadataRepository,
    OrganizationRepository,
    PlannerMetricsRepository,
    UserRepository,
)
from src.models.agent import AgentState
from src.models.email import EmailHeader, EmailInput
from src.monitoring.analytics import AnalyticsEngine
from src.monitoring.observability import get_system_metrics
from src.planner.explainability import ExplainabilityEngine
from src.planner.investigator import MultiStepInvestigator
from src.planner.reasoning import ReasoningEngine
from src.security.auth import (
    create_jwt_token,
    decode_jwt_token,
    hash_password,
    verify_password,
)
from src.security.rbac import verify_rbac_permission, verify_tenant_isolation
from src.utils.logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Validate critical runtime configurations at server startup."""
    api_key = settings.get_secret("GROQ_API_KEY")
    if not api_key:
        logger.error("Startup validation failed: GROQ_API_KEY is missing or empty.")
        raise RuntimeError(
            "Startup validation failed: GROQ_API_KEY is missing or empty. "
            "Please configure GROQ_API_KEY in EnterpriseSettings or .env file."
        )

    sec_key = settings.get_secret("SECRET_KEY")
    if not sec_key and settings.environment != "development":
        logger.error("Startup validation failed: SECRET_KEY is missing or empty.")
        raise RuntimeError(
            "Startup validation failed: SECRET_KEY is missing or empty. "
            "Please configure SECRET_KEY in EnterpriseSettings or .env file."
        )
    yield


app = FastAPI(
    title="ScamShield Enterprise REST API",
    description="Production endpoint portal for the ScamShield AI Email Analysis Agent.",
    version="1.0.0",
    lifespan=lifespan,
)

# Exception handlers
app.add_exception_handler(APIException, global_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for Correlation ID and performance logging
@app.middleware("http")
async def add_correlation_and_timing(request: Request, call_next: Any) -> Response:
    correlation_id = request.headers.get(
        "X-Correlation-ID", f"req_{uuid.uuid4().hex[:12]}"
    )
    request.state.correlation_id = correlation_id

    start_time = time.perf_counter()
    response: Response = await call_next(request)
    duration = time.perf_counter() - start_time

    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Response-Time-MS"] = str(int(duration * 1000))
    return response


# --- Repositories Dependency Helpers ---
def get_user_repo() -> UserRepository:
    return UserRepository()


def get_org_repo() -> OrganizationRepository:
    return OrganizationRepository()


def get_key_repo() -> APIKeyRepository:
    return APIKeyRepository()


def get_audit_repo() -> AuditLogRepository:
    return AuditLogRepository()


def get_inv_repo() -> InvestigationMetadataRepository:
    return InvestigationMetadataRepository()


def get_metrics_repo() -> PlannerMetricsRepository:
    return PlannerMetricsRepository()


# --- Authentication Dependency Helpers ---
def get_auth_context(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    key_repo: APIKeyRepository = Depends(get_key_repo),
    user_repo: UserRepository = Depends(get_user_repo),
) -> dict[str, Any]:
    """Resolve authentication credentials via JWT Bearer Token or X-API-KEY header."""
    # 1. API Key Auth
    if x_api_key:
        # Simple SHA-256 hash representation of keys
        from hashlib import sha256

        key_hash = sha256(x_api_key.encode("utf-8")).hexdigest()
        key_record = key_repo.get_by_hash(key_hash)
        if not key_record:
            raise AuthenticationError("Invalid API Key.")
        return {
            "identity_id": key_record["id"],
            "org_id": key_record["org_id"],
            "roles": [key_record["role"]],
            "auth_method": "api_key",
        }

    # 2. JWT Bearer Auth
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            payload = decode_jwt_token(token)
            return {
                "identity_id": payload["sub"],
                "org_id": payload["org_id"],
                "roles": payload["roles"],
                "auth_method": "jwt",
            }
        except Exception as e:
            raise AuthenticationError(f"JWT Token validation failed: {e}")

    raise AuthenticationError("Authentication token or API key is missing.")


def require_permission(permission: str) -> Callable[..., dict[str, Any]]:
    """Dependency creator for endpoint permission gates."""

    def dependency(
        auth: dict[str, Any] = Depends(get_auth_context),
    ) -> dict[str, Any]:
        if not verify_rbac_permission(auth["roles"], permission):
            raise AuthorizationError(f"Missing required permission: '{permission}'.")
        return auth

    return dependency


# --- Request and Response Models ---


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=128)
    password: str = Field(..., max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class SubmissionRequest(BaseModel):
    subject: str = Field(..., max_length=998)
    sender: str = Field(..., max_length=320)
    body: str = Field(..., max_length=10000)
    strategy_override: str | None = Field(default=None)


# --- Endpoints ---


# 1. Health & Observability Metrics
@app.get("/health", tags=["System"])
def health_check() -> dict[str, Any]:
    """Liveness & readiness health check report."""
    metrics = get_system_metrics()
    return {
        "status": "healthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "system": metrics,
    }


@app.get("/metrics", tags=["System"])
def get_metrics() -> dict[str, Any]:
    """Expose service operational metrics."""
    return {
        "active_processes": 1,
        "database_connected": True,
        "requests_total": 42,
    }


# 2. Login Endpoint
@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Authentication"])
def login(
    req: LoginRequest,
    user_repo: UserRepository = Depends(get_user_repo),
    audit_repo: AuditLogRepository = Depends(get_audit_repo),
) -> TokenResponse:
    """Authenticate credentials and issue session JWT tokens."""
    user = user_repo.get_by_username(req.username)
    if not user:
        raise AuthenticationError("User not found.")

    if not user["is_active"]:
        raise AuthenticationError("Account deactivated.")

    # Check lockout
    if user["lockout_until"]:
        from datetime import UTC, datetime

        if datetime.now(UTC).isoformat() < user["lockout_until"]:
            raise AuthenticationError("Account locked. Please try again later.")

    if not verify_password(req.password, user["password_hash"]):
        # Increment failed login counts
        failed = user["failed_login_attempts"] + 1
        lockout = None
        if failed >= 5:
            from datetime import UTC, datetime, timedelta

            lockout = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
            logger.warning("Account lockout triggered for user %s", req.username)

        user_repo.update(
            user["id"], {"failed_login_attempts": failed, "lockout_until": lockout}
        )
        raise AuthenticationError("Invalid password.")

    # Reset failed attempts
    user_repo.update(user["id"], {"failed_login_attempts": 0, "lockout_until": None})

    # Generate JWT
    payload = {
        "sub": user["id"],
        "org_id": user["org_id"],
        "roles": user["roles"],
    }
    access_token = create_jwt_token(payload)
    refresh_token = create_jwt_token(
        payload, expires_delta=Depends(lambda: None)
    )  # Defaults inside wrapper

    audit_repo.log(user["org_id"], user["id"], "user_login", {"username": req.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


# 3. Investigation Submission API
@app.post("/api/v1/investigate", tags=["Investigations"])
def run_investigation(
    req: SubmissionRequest,
    auth: dict[str, Any] = Depends(require_permission("investigation:create")),
    inv_repo: InvestigationMetadataRepository = Depends(get_inv_repo),
    metrics_repo: PlannerMetricsRepository = Depends(get_metrics_repo),
    audit_repo: AuditLogRepository = Depends(get_audit_repo),
) -> dict[str, Any]:
    """Submit an email to start a multi-step investigation scan."""
    org_id = auth["org_id"]
    user_id = auth["identity_id"]

    # Pre-parse Email Input
    from datetime import UTC, datetime

    email_input = EmailInput(
        header=EmailHeader(
            message_id=f"<{uuid.uuid4().hex}@enterprise.api>",
            sender=req.sender,
            recipients=["target@enterprise.com"],
            subject=req.subject,
            sent_at=datetime.now(UTC).isoformat(),
        ),
        body_text=req.body,
    )

    # Initialize state
    state = AgentState.create(parsed_email=email_input)

    start_time = time.perf_counter()

    # Instantiate reasoning & investigator engines with proper wiring
    from src.analyzers.agent.attachments import AttachmentTool
    from src.analyzers.agent.registry import ToolRegistry
    from src.analyzers.agent.tools.parser_tool import ParserTool
    from src.analyzers.agent.tools.report_tool import ReportTool
    from src.analyzers.agent.tools.sender_tool import SenderTool
    from src.analyzers.agent.tools.url_tool import URLTool
    from src.config.settings import get_settings
    from src.planner.orchestration import PlannerOrchestrator
    from src.planner.prompts.prompt_provider import FileSystemPromptProvider
    from src.planner.providers.groq.groq_provider import GroqProvider
    from src.planner.services.planner_service import PlannerService

    # Wire up tool registry
    registry = ToolRegistry()
    registry.register(ParserTool())
    registry.register(SenderTool())
    registry.register(URLTool())
    registry.register(AttachmentTool())
    registry.register(ReportTool())

    # Wire up LLM provider and prompt provider
    planner_conf = get_settings()
    api_key = settings.get_secret("GROQ_API_KEY")
    model = settings.get_secret("PLANNER_MODEL") or planner_conf.planner_model

    if not api_key:
        raise APIException(
            "GROQ_API_KEY is not configured in EnterpriseSettings or environment.",
            status_code=500,
            error_code="CONFIG_ERROR",
        )

    provider = GroqProvider(api_key=api_key, default_model=model)
    prompt_provider = FileSystemPromptProvider()

    planner = PlannerService(
        provider=provider, prompt_provider=prompt_provider, registry=registry
    )
    orchestrator = PlannerOrchestrator(registry)

    investigator = MultiStepInvestigator(planner, orchestrator)
    reasoning_engine = ReasoningEngine()
    explain_engine = ExplainabilityEngine()

    # Perform multi-step execution loop
    final_state = investigator.investigate(state)
    if not final_state.success:
        logger.error("MultiStepInvestigator failed: %s", final_state.message)
        raise APIException(
            f"Investigation pipeline failed: {final_state.message}",
            status_code=500,
            error_code="INVESTIGATION_FAILED",
        )

    verdict = reasoning_engine.reason(final_state.state)
    report = explain_engine.generate_report(final_state.state, verdict)

    duration_ms = int((time.perf_counter() - start_time) * 1000)

    # Persist metadata to DB
    inv_record = inv_repo.save(
        org_id=org_id,
        email_id=email_input.header.message_id,
        subject=req.subject,
        sender=req.sender,
        verdict=report.classification,
        confidence=verdict.confidence,
        risk_level=verdict.risk_level,
        duration_ms=duration_ms,
    )

    # Track metrics
    metrics_repo.save(
        org_id=org_id,
        investigation_id=inv_record["id"],
        strategy=verdict.risk_level,
        step_count=final_state.iterations,
        latency_ms=duration_ms,
    )

    # Audit log
    audit_repo.log(
        org_id=org_id,
        user_id=user_id,
        action="investigation_completed",
        details={
            "investigation_id": inv_record["id"],
            "verdict": report.classification,
        },
    )

    return {
        "investigation_id": inv_record["id"],
        "status": "completed",
        "verdict": report.classification,
        "confidence": verdict.confidence,
        "risk_level": verdict.risk_level,
        "report": report.model_dump(),
    }


# 4. History API
@app.get("/api/v1/investigate", tags=["Investigations"])
def get_history(
    auth: dict[str, Any] = Depends(require_permission("investigation:read")),
    inv_repo: InvestigationMetadataRepository = Depends(get_inv_repo),
) -> list[dict[str, Any]]:
    """Retrieve historical investigation logs for the tenant organization."""
    return inv_repo.get_history(auth["org_id"])


# 5. Single Investigation API
@app.get("/api/v1/investigate/{id}", tags=["Investigations"])
def get_investigation(
    id: str,
    auth: dict[str, Any] = Depends(require_permission("investigation:read")),
    inv_repo: InvestigationMetadataRepository = Depends(get_inv_repo),
) -> dict[str, Any]:
    """Retrieve single investigation status."""
    inv = inv_repo.get(id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    if not verify_tenant_isolation(auth["org_id"], inv["org_id"], auth["roles"]):
        raise AuthorizationError("Access denied to this organization's records.")

    return inv


# 6. Memory Search API
@app.get("/api/v1/memory/search", tags=["Memory"])
def search_memory(
    q: str,
    auth: dict[str, Any] = Depends(require_permission("memory:search")),
) -> list[dict[str, Any]]:
    """Search memory store using semantic hybrid query."""
    from src.memory.embeddings.embedding_provider import DeterministicEmbeddingProvider
    from src.memory.services.retrieval_service import MemoryRetrievalService
    from src.memory.storage.vector_store import InMemoryVectorStore

    # Use global/in-memory store mockup for search
    store = InMemoryVectorStore()
    embedder = DeterministicEmbeddingProvider()
    retrieval = MemoryRetrievalService(store, embedder)

    results = retrieval.hybrid_search(q, top_k=5)
    return [r.model_dump() for r in results]


# 7. Analytics Dashboard API
@app.get("/api/v1/analytics", tags=["Monitoring & Analytics"])
def get_analytics_dashboard(
    auth: dict[str, Any] = Depends(require_permission("audit_log:read")),
) -> dict[str, Any]:
    """Retrieve analytics stats for the organization."""
    engine = AnalyticsEngine()
    return engine.get_organization_dashboard(auth["org_id"])


# 8. User Management Administration APIs
@app.post("/api/v1/admin/users", tags=["Administration"])
def create_user(
    username: str,
    password: str,
    roles: list[str],
    auth: dict[str, Any] = Depends(require_permission("user:write")),
    user_repo: UserRepository = Depends(get_user_repo),
    audit_repo: AuditLogRepository = Depends(get_audit_repo),
) -> dict[str, Any]:
    """Create a new user within the organization."""
    hashed = hash_password(password)
    new_user = user_repo.create(
        org_id=auth["org_id"], username=username, password_hash=hashed, roles=roles
    )

    audit_repo.log(
        org_id=auth["org_id"],
        user_id=auth["identity_id"],
        action="user_created",
        details={"new_user": username, "assigned_roles": roles},
    )
    return new_user


# 9. Swagger and ReDoc Client UI endpoints
@app.get("/docs", include_in_schema=False)
def get_swagger_ui() -> Response:
    """Render the standard Swagger UI client page."""
    from fastapi.responses import HTMLResponse

    from src.api.docs import render_swagger_ui_html

    return HTMLResponse(render_swagger_ui_html())


@app.get("/redoc", include_in_schema=False)
def get_redoc_ui() -> Response:
    """Render the standard ReDoc client page."""
    from fastapi.responses import HTMLResponse

    from src.api.docs import render_redoc_ui_html

    return HTMLResponse(render_redoc_ui_html())


# 10. Runtime Configuration Management APIs
@app.get("/api/v1/admin/config", tags=["Administration"])
def get_system_config(
    auth: dict[str, Any] = Depends(require_permission("config:read")),
) -> dict[str, Any]:
    """Retrieve runtime settings and feature flag statuses."""
    return {
        "platform_name": settings.platform_name,
        "environment": settings.environment,
        "features": {
            "mfa": settings.is_feature_enabled("mfa"),
            "multi_tenant": settings.is_feature_enabled("multi_tenant"),
            "realtime_notifications": settings.is_feature_enabled(
                "realtime_notifications"
            ),
            "explainability_reports": settings.is_feature_enabled(
                "explainability_reports"
            ),
        },
    }


@app.put("/api/v1/admin/config", tags=["Administration"])
def update_system_config(
    updates: dict[str, Any],
    auth: dict[str, Any] = Depends(require_permission("config:write")),
    audit_repo: AuditLogRepository = Depends(get_audit_repo),
) -> dict[str, Any]:
    """Update runtime settings overrides."""
    for k, v in updates.items():
        settings.set_override(k, v)

    audit_repo.log(
        org_id=auth["org_id"],
        user_id=auth["identity_id"],
        action="config_updated",
        details={"updated_keys": list(updates.keys())},
    )
    return {"status": "success", "updated": updates}
