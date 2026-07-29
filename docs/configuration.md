# Configuration Guide

Settings are loaded from environment variables and an optional `.env` file. Never commit real secrets.

| Variable | Default | Production guidance |
|---|---:|---|
| `APP_NAME` | `Email Analysis Agent` | Set service identity. |
| `VERSION` | `0.1.0` | Inject release version. |
| `DEBUG` | `false` | Keep false. |
| `LOG_LEVEL` | `INFO` | Use INFO or WARNING. |
| `DATA_DIRECTORY` | `data` | Mount durable storage. |
| `GROQ_API_KEY` | empty | Required by API startup. Store in a secret manager. |
| `SECRET_KEY` | empty | Required outside development. Rotate regularly. |
| `PLANNER_MODEL` | configured default | Pin an approved model. |

Memory snapshots are stored below `data/memory/` per organization. Back up this directory, restrict filesystem access, and define a retention process appropriate to your policy.
