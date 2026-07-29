# Phase 8: Enterprise Platform, Security & Operations

## Overview
Phase 8 transforms the Email Analysis Agent from a command-line tool into a robust, secure, and observable multi-tenant **Enterprise Platform** powered by FastAPI, SQLite relational persistence, and cryptographically secure Authentication and Authorization (RBAC).

## Relational Persistence & Multi-Tenancy
The database layer (`src/database/`) is built on SQLite (zero-dependency, built-in) and structured to support multi-tenant bounds. Schema migrations initialize the following tables:
- `organizations`: Root tenant entity.
- `users`: Credentials, status, and role metadata.
- `api_keys`: Access tokens mapped to permissions for automated integrations.
- `audit_logs`: SOC investigator logs mapping actions, changes, and access timestamps.
- `investigations`: Saved metadata, verdicts, risk levels, and execution durations.
- `planner_metrics`: Analytical records of latency, planning strategies, and tool step counts.
- `analytics`: Cached metrics for daily SOC stats dashboard reporting.

## Identity & Access Management (IAM)
The security layer (`src/security/`) provides production-grade controls:
- **Authentication**: JWT token exchange for sessions. Revoked tokens are kept in a blacklist. Passwords are hashed using PBKDF2-HMAC-SHA256 with 100,000 iterations and base64 salt.
- **API Keys**: SHA-256 hashed API Keys verifying automated scanner integrations.
- **RBAC**: Multi-role support with hierarchy resolution:
  `super_admin` > `security_admin` > `soc_analyst` > `analyst` > `read_only`
- **Tenant Isolation**: Gatekeepers verify that user `org_id` matches the resource `org_id` for all queries.

## REST API Reference
Built on FastAPI (`src/api/`) and exposed on:
- `GET /health`: System telemetry, readiness, and resource usage.
- `GET /metrics`: Execution latency and database metrics.
- `POST /api/v1/auth/login`: Authenticate credentials, issue access & refresh tokens.
- `POST /api/v1/investigate`: Submit raw email for multi-step planner & reasoning scanning.
- `GET /api/v1/investigate`: List historical runs.
- `GET /api/v1/investigate/{id}`: Query detailed status.
- `GET /api/v1/memory/search`: Semantic vector query.
- `GET /api/v1/analytics`: SOC dashboard indicators.
- `POST /api/v1/admin/users`: Org user creation.
- `GET /api/v1/admin/config`: Get active feature flags.
- `PUT /api/v1/admin/config`: Dynamically update runtime configuration flags.

## Observability & Error Handling
- **Request Context**: Correlation/Request IDs injected into requests and response headers.
- **Central Exception Interceptor**: Catch validation, permission, and system exceptions to return standardized JSON payloads:
  ```json
  {
    "error": {
      "code": "ERROR_CODE",
      "message": "Error message description",
      "details": {},
      "correlation_id": "req_..."
    }
  }
  ```
- **System Metrics**: Monitors CPU usage, Memory limits, and Disk availability.

## Testing
Comprehensive validation suite in `tests/test_phase8_enterprise.py` covering JWT claims, PBKDF2 verification, tenant isolation, role inheritance, and API routing.
Run tests:
```bash
.venv\Scripts\pytest.exe tests/test_phase8_enterprise.py
```
