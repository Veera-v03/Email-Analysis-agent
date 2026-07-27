# Architecture

## Phase 1 boundary

The foundation separates operational concerns from future intelligence
concerns. The executable composition root is `src/main.py`; it depends on
configuration, utilities, and models, but contains no security-analysis
behaviour.

```text
main.py
  ├── config/settings.py  -> typed environment configuration
  ├── utils/logging.py    -> process-wide console logging
  ├── utils/files.py      -> JSON fixture loading
  └── models/email.py     -> strict email input contract
```

## Directory responsibilities

- `src/analyzers`: reserved for isolated future analysis use cases. It has no
  implementation in Phase 1 to preserve the scope boundary.
- `src/config`: application settings and configuration construction.
- `src/models`: framework-independent Pydantic contracts for data crossing
  application boundaries.
- `src/utils`: small operational utilities with a single, reusable purpose.
- `data/raw`: local, unprocessed source material; ignored by Git.
- `data/processed`: locally generated data; ignored by Git.
- `data/samples`: safe fixtures committed for predictable development.
- `tests`: automated verification of foundation behaviour.
- `docs`: durable architectural and engineering guidance.

## Configuration flow

`Settings` reads environment variables and an optional local `.env` file.
Its defaults make local startup deterministic. `to_application_config()`
converts runtime settings into the strict `ApplicationConfig` data model,
keeping the rest of the application independent of the settings framework.

## Extension approach

Future use cases should accept typed models and configuration through explicit
interfaces. They should not read environment variables, configure logging, or
perform file-system discovery directly. This keeps security logic testable and
lets the service composition root choose infrastructure implementations.
