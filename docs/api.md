# API Guide

The OpenAPI UI is available at `/docs`; ReDoc is available at `/redoc`.

## Authentication

Protected endpoints require either `Authorization: Bearer <JWT>` or `X-API-KEY`. RBAC permissions are evaluated per endpoint. Errors use `{ "error": { "code", "message", "correlation_id" } }`.

## Core endpoints

| Endpoint | Permission | Purpose |
|---|---|---|
| `POST /api/v1/auth/login` | public | Issue JWT credentials. |
| `POST /api/v1/investigate` | `investigation:create` | Submit subject, sender, and body. |
| `GET /api/v1/investigate` | `investigation:read` | List tenant history. |
| `GET /api/v1/investigate/{id}` | `investigation:read` | Retrieve one investigation. |
| `GET /api/v1/memory/search?q=` | `memory:search` | Hybrid tenant-memory search. |
| `GET /health` | public | Liveness and system metrics. |
| `GET /metrics` | public | Basic operational metrics. |

`POST /api/v1/investigate` accepts `subject`, `sender`, `body`, and optional `strategy_override`; each string is length validated. Responses retain the stable `investigation_id`, `status`, `verdict`, `confidence`, `risk_level`, and `report` fields.

Use `X-Correlation-ID` to supply a request ID. The API returns it and `X-Response-Time-MS` on every response.
