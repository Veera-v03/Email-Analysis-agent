# Development guide

## Prerequisites

- Python 3.13 or later
- A virtual environment (recommended)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

---

## Quality gates

All three gates must pass before merging any change.

```bash
python -m pytest          # 58 tests, all must pass
python -m ruff check .    # zero violations
python -m mypy src        # zero errors (strict mode)
```

---

## Development principles

- One responsibility per module. Analyzers analyze; models hold data; utils
  provide infrastructure.
- Explicit, typed dependencies. No global state, no hidden singletons.
- Validate untrusted inputs at boundaries. Use `extra="forbid"` on all Pydantic
  models that cross a boundary.
- Keep credentials in environment variables. Never commit `.env` or API keys.
- No security verdicts in Phase 3. Analyzers produce observations only.
- Keep tests deterministic. No live network calls, no random seeds, no
  time-dependent assertions.

---

## Coding conventions

- Target Python 3.13+. Use `from __future__ import annotations` in every module.
- Complete type annotations on all public functions and methods.
- Google-style docstrings on all public APIs.
- Follow PEP 8. Use Ruff for linting and import ordering (`ruff check .`).
- Use `collections.abc` for `Mapping`, `Sequence`, `Callable` — not `typing`.
- Use `str.encode()` without an explicit `"utf-8"` argument (it is the default).
- Pydantic v2 models: `extra="forbid"`, `strict=True`, `frozen=True` on all
  boundary models.
- Use the module logger (`get_logger(__name__)`). Never use `print()`.

---

## Adding a new analyzer

1. Create `src/analyzers/sender/<name>.py`.
2. Define a `@runtime_checkable` Protocol for the public interface.
3. Implement the concrete class. Accept configuration through `__init__`
   parameters, not environment variables.
4. Add the protocol type as an optional keyword argument to
   `SenderIntelligenceEngine.__init__` with the concrete class as the default.
5. Call the analyzer in `SenderIntelligenceEngine.analyze()` and emit evidence
   through the injected `EvidenceCollector`.
6. Add the output field to `SenderAnalysisResult` in
   `src/models/sender_analysis.py`.
7. Write a dedicated test module in `tests/`.

---

## Adding a new model

- Place it in `src/models/<name>.py`.
- Use `ConfigDict(extra="forbid", strict=True, frozen=True)`.
- Export it from `src/models/__init__.py` if it is a primary application
  boundary contract.
- Define length constants as module-level `MAX_*` names.

---

## Test conventions

- One test module per source module.
- Use `conftest.py` fixtures for shared component instances.
- Use helper functions (not fixtures) for shared data construction.
- Every test must be deterministic and isolated.
- Name tests as `test_<what>_<expected_outcome>`.
- Do not test implementation details — test observable behaviour.

---

## Environment variables

Copy `.env.example` to `.env` and adjust non-secret values for local
development. Never commit `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `APP_NAME` | `Email Analysis Agent` | Application display name |
| `VERSION` | `0.1.0` | Application version |
| `DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Root logger level |
| `DATA_DIRECTORY` | `data` | Base path for data files |
| `GROQ_API_KEY` | _(empty)_ | Reserved for Phase 4 LLM integration |

---

## Running the application

```bash
python -m src.main
```

The bootstrap loads configuration, initializes logging, reads the versioned
sample email, validates it against the Pydantic contract, logs a summary, and
exits with code 0.

---

## Phase roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: configuration, models, utilities, bootstrap | Complete |
| 2 | Parser boundary: ingestion contracts, raw-to-model conversion | Complete |
| 3 | Sender & Domain Intelligence Engine | Complete |
| 4 | Orchestration, risk scoring, LLM integration, service API | Planned |
| 5 | Observability, hardening, deployment operations | Planned |

See [Architecture](architecture.md) for engineering details.
