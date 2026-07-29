# Deployment and Operations

Run the service behind TLS termination and a reverse proxy. Inject `GROQ_API_KEY` and `SECRET_KEY` through the platform secret manager; do not use image layers or source control.

## Health and scaling

- Use `GET /health` as liveness/readiness input after startup validation succeeds.
- Preserve `data/memory/` on durable storage or replace `IVectorStore` with a managed backend.
- Keep API instances stateless apart from configured memory storage; use tenant-scoped external storage before horizontal scaling.
- Collect correlation IDs, response-time headers, audit logs, and investigation metrics.

## Backup and recovery

Back up the relational database and `data/memory/` together. Test restore in an isolated environment. Provider failures are recorded as diagnostic evidence and should not be retried manually without respecting provider limits.
