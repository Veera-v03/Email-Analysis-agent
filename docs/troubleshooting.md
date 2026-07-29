# Troubleshooting

| Symptom | Check |
|---|---|
| API fails at startup | Configure `GROQ_API_KEY`; configure `SECRET_KEY` outside development. |
| `401` or `403` | Verify bearer/API key and assigned RBAC permission. |
| Provider diagnostic evidence | Check provider enablement, credentials, timeout, and rate limit. The investigation remains valid. |
| Memory missing after restart | Verify write access and persistence of `data/memory/`. |
| Slow investigations | Inspect `X-Response-Time-MS`, tool timeline, provider diagnostics, and planner metrics. |
| Unexpected result | Use report evidence, score breakdown, historical correlations, and correlation ID when escalating. |
