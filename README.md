# Email Analysis Agent

Email Analysis Agent is the future email-security microservice for ScamShield AI.
This repository currently contains **Phase 1: Project Foundation** only. It
provides a typed configuration system, strict data contracts, structured
logging, sample-data loading, and a verified application bootstrap.

No phishing detection, spoofing detection, typosquatting, entity extraction,
LLM integration, or risk scoring is implemented in this phase.

## Goals

- Establish a maintainable Clean Architecture-oriented codebase.
- Define strict, reusable contracts at the application boundary.
- Keep configuration and operational concerns outside future analysis logic.
- Make subsequent capabilities easy to test and integrate safely.

## Project structure

```text
Email-Analysis-Agent/
├── src/
│   ├── analyzers/       # Reserved boundary for future analysis components
│   ├── config/          # Environment-backed application configuration
│   ├── models/          # Strict Pydantic data contracts
│   ├── utils/           # Shared logging and file-loading utilities
│   └── main.py          # Application bootstrap
├── data/
│   ├── raw/             # Local source data, excluded from version control
│   ├── processed/       # Derived local data, excluded from version control
│   └── samples/         # Versioned, safe development fixtures
├── tests/               # Automated foundation checks
├── docs/                # Architecture and engineering documentation
├── .env.example         # Safe environment-variable template
├── requirements.txt     # Runtime dependencies
└── pyproject.toml       # Package and tool configuration
```

## Installation

Python 3.13 or later is required.

```bash
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Optionally copy `.env.example` to `.env` and adjust non-secret runtime values.
Never commit `.env` or API keys.

## Running

From the repository root:

```bash
python -m src.main
```

The program loads configuration, initializes logging, reads the versioned
sample email, validates it against the Pydantic contract, logs a concise
summary, and exits successfully.

## Development status

Phase 1 is the active scope. It intentionally stops at application bootstrap
and validated input representation.

## Roadmap summary

1. **Foundation (current):** configuration, models, utilities, bootstrap, and documentation.
2. Sender and message normalization.
3. Independent security-analysis capabilities.
4. Orchestration, structured results, and service integration.
5. Observability, hardening, and deployment operations.

See [Architecture](docs/architecture.md) and
[Development guide](docs/development.md) for engineering details.
