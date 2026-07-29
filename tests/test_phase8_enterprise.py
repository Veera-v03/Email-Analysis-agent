"""Comprehensive test suite verifying Phase 8 Enterprise Platform, security, APIs, and operations."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.config.enterprise_config import settings
from src.database.db_client import DatabaseClient
from src.database.repositories import (
    APIKeyRepository,
    AuditLogRepository,
    OrganizationRepository,
    UserRepository,
)
from src.security.auth import (
    create_jwt_token,
    decode_jwt_token,
    generate_api_key,
    hash_password,
    revoke_token,
    verify_password,
)
from src.security.rbac import verify_rbac_permission, verify_tenant_isolation

# --- 1. Configuration & Security Tests ---


def test_enterprise_configuration_overrides() -> None:
    assert settings.platform_name == "ScamShield Enterprise Platform"

    settings.set_override("PLATFORM_NAME", "Override Platform")
    assert settings.get_secret("PLATFORM_NAME") == "Override Platform"

    settings.set_override("ENABLE_MFA", True)
    assert settings.is_feature_enabled("mfa") is True


def test_password_hashing_and_verification() -> None:
    pwd = "my-secure-password"
    hashed = hash_password(pwd)

    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_jwt_token_claims_and_revocation() -> None:
    claims = {"sub": "user_123", "org_id": "org_abc", "roles": ["analyst"]}
    token = create_jwt_token(claims)

    decoded = decode_jwt_token(token)
    assert decoded["sub"] == "user_123"
    assert decoded["org_id"] == "org_abc"

    revoke_token(token)
    with pytest.raises(Exception):
        decode_jwt_token(token)


def test_rbac_inheritance_resolution() -> None:
    # SOC Analyst inherits read_only permissions
    assert verify_rbac_permission(["soc_analyst"], "investigation:read") is True
    # Analyst cannot write global configs
    assert verify_rbac_permission(["analyst"], "config:write") is False
    # Super Admin can do everything
    assert verify_rbac_permission(["super_admin"], "config:write") is True


def test_tenant_boundary_isolation() -> None:
    # Standard user has access to matching org ID
    assert verify_tenant_isolation("org_1", "org_1", ["analyst"]) is True
    # Standard user blocked from different org ID
    assert verify_tenant_isolation("org_1", "org_2", ["analyst"]) is False
    # Super Admin can cross boundaries
    assert verify_tenant_isolation("org_1", "org_2", ["super_admin"]) is True


# --- 2. SQLite Database & Repositories Tests ---


def test_sqlite_relational_repositories() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "test_enterprise.db"
        client = DatabaseClient(db_path=str(db_file))

        org_repo = OrganizationRepository(client)
        user_repo = UserRepository(client)
        key_repo = APIKeyRepository(client)
        audit_repo = AuditLogRepository(client)

        # 1. Organization
        org = org_repo.create("Acme Corp", org_id="org_acme")
        assert org["name"] == "Acme Corp"

        # 2. User
        hashed_pwd = hash_password("pass123")
        user = user_repo.create(
            org_id="org_acme",
            username="john_doe",
            password_hash=hashed_pwd,
            roles=["analyst"],
            user_id="user_john",
        )
        assert user["username"] == "john_doe"

        # 3. API Key
        raw_key, key_hash = generate_api_key()
        key_record = key_repo.create(
            org_id="org_acme",
            name="integration-token",
            key_hash=key_hash,
            key_id="key_1",
        )
        assert key_record["name"] == "integration-token"

        # 4. Audit Log
        audit_repo.log(
            org_id="org_acme",
            user_id="user_john",
            action="test_action",
            details={"ip": "127.0.0.1"},
        )
        logs = audit_repo.get_by_org("org_acme")
        assert len(logs) == 1
        assert logs[0]["action"] == "test_action"


# --- 3. REST API Web Endpoints Tests ---


def test_fastapi_rest_endpoints() -> None:
    client = TestClient(app)

    # 1. Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    # 2. Metrics check
    res_metrics = client.get("/metrics")
    assert res_metrics.status_code == 200
    assert "active_processes" in res_metrics.json()


def test_api_authentication_failure() -> None:
    client = TestClient(app)

    # Access restricted endpoint without auth headers
    res = client.get("/api/v1/investigate")
    assert res.status_code == 401
    assert "error" in res.json()
    assert res.json()["error"]["code"] == "UNAUTHORIZED"
