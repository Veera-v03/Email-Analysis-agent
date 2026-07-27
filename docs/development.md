# Development guide

## Development principles

- Keep each module focused on one responsibility.
- Prefer explicit dependencies and typed data contracts.
- Validate untrusted inputs at boundaries.
- Keep credentials in environment variables, never source control.
- Add functionality through small, independently testable modules.
- Avoid coupling domain logic to process startup or I/O.

## Coding conventions

- Target Python 3.13 or later.
- Use complete type annotations and Google-style docstrings for public APIs.
- Follow PEP 8 and use Ruff for linting and import ordering.
- Use Pydantic v2 models with `extra="forbid"` for boundary data.
- Use the module logger; do not use `print()` for application output.
- Keep tests deterministic and avoid live network calls.

## Quality checks

Install development dependencies with:

```bash
python -m pip install -e ".[dev]"
```

Then run:

```bash
python -m pytest
python -m ruff check .
python -m mypy src
```

## Future phases

Future work can introduce normalization, security-analysis use cases,
orchestration, result contracts, and deployment concerns. Each phase should
retain the strict separation between infrastructure, application flow, and
security decision logic established here.
