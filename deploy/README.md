# ScamON Enterprise Email Analysis Agent — Staging & Deployment Runbook

## Overview
This directory contains orchestration manifests, database initialization scripts, and operational runbooks for deploying ScamON into Staging and Production environments.

---

## 1. Quickstart: Staging with Docker Compose

### Prerequisites:
- Docker Engine 24+ and Docker Compose v2+
- Port allocations: `8000` (FastAPI), `5432` (PostgreSQL), `6379` (Redis)

### Launch Staging Stack:
```bash
# 1. Clone & prepare environment
cp deploy/staging.env.example .env

# 2. Build & launch multi-container stack
docker compose up -d --build

# 3. Monitor container health
docker compose ps
docker compose logs -f app
```

---

## 2. Health & Readiness Verification

### Liveness Probe (`GET /health`):
```bash
curl -i http://localhost:8000/health
```
**Expected Response:** HTTP 200 OK
```json
{
  "status": "healthy",
  "timestamp": "2026-08-31T09:00:00Z",
  "system": { ... }
}
```

### Readiness Probe (`GET /ready`):
```bash
curl -i http://localhost:8000/ready
```
**Expected Response:** HTTP 200 OK
```json
{
  "status": "ready",
  "checks": {
    "redis": "connected",
    "pgvector": "connected",
    "embeddings": "connected",
    "database": "connected"
  }
}
```

---

## 3. Architecture & Container Network

```text
               Internet / SOC Client
                        │
                        ▼ (Port 8000)
            ┌───────────────────────┐
            │      scamon-app       │ (FastAPI ASGI Daemon)
            └───────────┬───────────┘
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
┌──────────────────┐          ┌──────────────────┐
│  scamon-postgres │          │   scamon-redis   │
│  (pg16 + vector) │          │   (Redis 7.2)    │
└──────────────────┘          └──────────────────┘
```

---

## 4. Operational Secrets Management

Production secrets must never be committed to Git or baked into container images. Inject via Kubernetes Secrets, AWS Secrets Manager, or HashiCorp Vault into the environment:

| Secret Environment Variable | Required For | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | Core Auth | 32+ character key for JWT token signing |
| `GROQ_API_KEY` | Core AI | Groq API key for Llama 3.3 LLM decision reasoning |
| `PGVECTOR_URL` | Memory Storage | PostgreSQL connection URI with pgvector |
| `REDIS_URL` | Distributed State | Redis connection URI for caching and locking |
| `EMBEDDING_API_KEY` | Semantic RAG | Google Gemini API key for `text-embedding-004` |
| `VIRUSTOTAL_API_KEY` | Threat Intel | VirusTotal API v3 key |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Threat Intel | Google Safe Browsing API v4 key |
| `ABUSEIPDB_API_KEY` | Threat Intel | AbuseIPDB API v2 key |
| `MSGRAPH_REMEDIATION_CLIENT_SECRET` | Remediation | Microsoft Graph OAuth2 client secret |
| `PANOS_API_KEY` | Remediation | Palo Alto PAN-OS XML API access key |
