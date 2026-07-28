# Email Analysis Agent

Email Analysis Agent is the email-security microservice for ScamShield AI.
This repository contains **Phase 1 through Phase 3** of the implementation.

Phase 3 delivers the complete **Sender & Domain Intelligence Engine**: a
production-ready, Clean Architecture-oriented pipeline that extracts, normalizes,
and analyzes sender identity evidence from email headers without making any
security verdict.

---

## What is implemented

### Phase 1 — Foundation
Typed configuration, strict data contracts, structured logging, sample-data
loading, and application bootstrap.

### Phase 2 — Parser boundary
Stable ingestion contracts (`EmailLoader`, `EmailParser`, `ParserError`) for
converting raw email representations into the normalized `EmailInput` model.

### Phase 3 — Sender & Domain Intelligence Engine
Eight independent, injectable analyzers coordinated by `SenderIntelligenceEngine`:

| Analyzer | Output |
|---|---|
| `StructuredSenderExtractor` | Parsed address evidence from all sender headers |
| `CanonicalEmailAddressNormalizer` | Canonical mailbox form with repair audit trail |
| `PublicSuffixDomainParser` | Structural domain components via PSL |
| `DeterministicDomainFeatureAnalyzer` | Entropy, keywords, typosquatting indicators |
| `DeterministicDisplayNameAnalyzer` | Lexical and formatting observations |
| `DeterministicSenderHeaderComparator` | From/Sender/Reply-To/Return-Path divergence |
| `DeterministicAuthenticationHeaderInterpreter` | SPF, DKIM, DMARC, ARC normalization |
| `DeterministicSenderRelationshipBuilder` | Graph-ready sender identity records |

All outputs compose into a single immutable `SenderAnalysisResult`. No risk
scores, phishing probabilities, or security verdicts are produced in Phase 3.

---

## Project structure

```text
Email-Analysis-Agent/
├── src/
│   ├── analyzers/
│   │   └── sender/          # Phase 3 — Sender Intelligence Engine
│   │       ├── authentication.py
│   │       ├── contracts.py
│   │       ├── display_name.py
│   │       ├── domain.py
│   │       ├── domain_features.py
│   │       ├── engine.py
│   │       ├── extractor.py
│   │       ├── header_comparison.py
│   │       ├── header_sources.py
│   │       ├── normalization.py
│   │       └── relationships.py
│   ├── config/              # Environment-backed application configuration
│   ├── models/              # Strict Pydantic data contracts
│   ├── parsers/             # Phase 2 — email ingestion boundary contracts
│   ├── utils/               # Logging, file loading, evidence collection
│   └── main.py              # Application bootstrap
├── data/
│   ├── raw/                 # Local source data (git-ignored)
│   ├── processed/           # Derived local data (git-ignored)
│   └── samples/             # Versioned development fixtures
├── tests/                   # 58 automated tests
├── docs/
│   ├── architecture.md      # Full pipeline and extension guide
│   ├── development.md       # Conventions, quality gates, contribution guide
│   └── phase-3-completion-report.md
├── .env.example             # Safe environment-variable template
├── requirements.txt         # Runtime dependencies
└── pyproject.toml           # Package, tool, and quality-gate configuration
```

---

## Installation

Python 3.13 or later is required.

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For development (includes pytest, ruff, mypy):

```bash
python -m pip install -e ".[dev]"
```

Optionally copy `.env.example` to `.env` and adjust non-secret runtime values.
Never commit `.env` or API keys.

---

## Running

```bash
python -m src.main
```

---

## Quality gates

```bash
python -m pytest          # 58 tests
python -m ruff check .    # 0 violations
python -m mypy src        # 0 errors (strict)
```

---

## Using the Sender Intelligence Engine

```python
from src.analyzers.sender.engine import SenderIntelligenceEngine
from src.models.email import EmailHeader, EmailInput

email = EmailInput(
    header=EmailHeader(
        message_id="<msg-001@example.com>",
        sender="Alice <alice@example.com>",
        recipients=["bob@example.net"],
        subject="Hello",
        sent_at="2026-01-01T00:00:00Z",
        reply_to="help@example.com",
    ),
    body_text="Message body.",
)

result = SenderIntelligenceEngine().analyze(email)

print(result.sender.from_address.email)          # alice@example.com
print(result.authentication.spf.status)          # UNKNOWN (no headers supplied)
print(result.consistency.missing_headers)        # (sender, return_path)
print(len(result.evidence.items))                # 8 (one per stage)
```

All analyzers are injectable for testing and customization:

```python
from src.analyzers.sender.domain_features import DeterministicDomainFeatureAnalyzer
from src.models.domain_features import DomainFeatureLexicon

engine = SenderIntelligenceEngine(
    domain_feature_analyzer=DeterministicDomainFeatureAnalyzer(
        DomainFeatureLexicon(
            suspicious_keywords=("secure", "verify"),
            brand_keywords=("paypal", "microsoft"),
            common_tlds=("com", "org", "net"),
        )
    )
)
```

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: configuration, models, utilities, bootstrap | ✓ Complete |
| 2 | Parser boundary: ingestion contracts | ✓ Complete |
| 3 | Sender & Domain Intelligence Engine | ✓ Complete |
| 4 | Orchestration, risk scoring, LLM integration, service API | Planned |
| 5 | Observability, hardening, deployment operations | Planned |

See [Architecture](docs/architecture.md),
[Development guide](docs/development.md), and the
[Phase 3 Completion Report](docs/phase-3-completion-report.md).
