# Architecture

## Overview

Email Analysis Agent follows a Clean Architecture-oriented layered design.
Each layer depends only inward. No analysis component reads environment
variables, configures logging, or performs file-system discovery directly.

```
src/
├── config/          Infrastructure — environment-backed settings
├── models/          Domain contracts — immutable Pydantic data models
├── parsers/         Parsing boundary — raw-to-model conversion contracts
├── analyzers/       Analysis — independent, injectable intelligence components
│   └── sender/      Phase 3 — Sender & Domain Intelligence Engine
└── utils/           Shared operational utilities
```

---

## Layer responsibilities

### config/

Reads environment variables and an optional `.env` file via `pydantic-settings`.
`Settings.to_application_config()` converts runtime settings into the strict
`ApplicationConfig` model, keeping the rest of the application independent of
the settings framework.

### models/

All application data contracts. Every model uses `ConfigDict(extra="forbid",
strict=True, frozen=True)` to enforce strict, immutable boundaries. No model
imports from `analyzers/` or `utils/`.

### parsers/

Stable protocol contracts for the email ingestion boundary. Concrete loaders
and MIME parsers can be introduced independently without changing consumers.
`ParserError` is the only exception type that crosses this boundary.

### analyzers/sender/ — Phase 3 Sender Intelligence Engine

The engine coordinates eight independent, protocol-backed analyzers. Each
component accepts typed models and returns typed models. None performs I/O,
reads configuration, or makes a security verdict.

### utils/

Small, single-purpose operational utilities: structured logging configuration
and JSON file loading. No domain logic.

---

## Phase 3 pipeline

```
EmailInput  (Phase 2 contract)
     │
     ▼
SenderIntelligenceEngine.analyze()
     │
     ├─► StructuredSenderExtractor          → SenderAnalysisResult (addresses)
     │       └─ RfcAddressParser
     │
     ├─► CanonicalEmailAddressNormalizer    → NormalizedAddressEvidence (per header)
     │
     ├─► PublicSuffixDomainParser           → DomainParseResult (per domain)
     │       └─ TldExtractPublicSuffixResolver
     │
     ├─► DeterministicDomainFeatureAnalyzer → DomainFeatureResult (per domain)
     │
     ├─► DeterministicDisplayNameAnalyzer   → DisplayNameAnalysisResult
     │
     ├─► DeterministicSenderHeaderComparator → SenderHeaderComparisonResult
     │
     ├─► DeterministicAuthenticationHeaderInterpreter → AuthenticationAnalysisResult
     │
     └─► DeterministicSenderRelationshipBuilder → SenderRelationshipGraph
     │
     ▼
SenderAnalysisResult  (Phase 3 unified output contract)
```

Every stage emits structured `Evidence` records through `EvidenceCollector`.
The final `SenderAnalysisResult` composes all stage outputs into one immutable
model with no risk score, phishing probability, or security verdict.

---

## Dependency direction

```
engine.py
  → analyzer protocols (contracts)
  → concrete analyzers (injected defaults)
  → models (data contracts only)
  → utils/evidence (EvidenceCollector)

models/
  → pydantic (external)
  → stdlib only

analyzers/sender/*
  → models/
  → stdlib + tldextract
```

No circular dependencies exist. `models/` has no upward dependencies.

---

## Injection and testability

Every Phase 3 analyzer is injectable through `SenderIntelligenceEngine.__init__`.
All analyzers satisfy `@runtime_checkable` Protocol contracts. Tests can
substitute any component with a minimal structural implementation without
subclassing.

```python
engine = SenderIntelligenceEngine(
    domain_parser=MyCustomDomainParser(),
    authentication_interpreter=MyAuthInterpreter(),
)
```

---

## Configuration flow

```
Environment / .env
     │
     ▼
Settings (pydantic-settings)
     │
     ▼
ApplicationConfig (frozen Pydantic model)
     │
     ▼
Application components (receive config, never read env directly)
```

---

## Evidence model

Every analyzer stage emits `Evidence` records through `EvidenceCollector`.
Evidence has:

- `evidence_id` — stable opaque SHA-256 digest
- `evidence_type` — dot-namespaced category string
- `title` / `description` — human-readable observation
- `severity` — `INFO | LOW | MEDIUM | HIGH | CRITICAL` (presentation only)
- `source` — producing component name
- `metadata` — JSON-compatible structured context

Evidence is intentionally free of risk scores, probabilities, and verdicts.

---

## Extension approach

### Adding a new Phase 3 analyzer

1. Define a `@runtime_checkable` Protocol in `analyzers/sender/contracts.py`
   or a dedicated module.
2. Implement the concrete class in a new module under `analyzers/sender/`.
3. Add the protocol type as an optional keyword argument to
   `SenderIntelligenceEngine.__init__` with a concrete default.
4. Call the analyzer inside `SenderIntelligenceEngine.analyze()` and emit
   evidence through the existing `EvidenceCollector`.
5. Add the output field to `SenderAnalysisResult` in `models/sender_analysis.py`.

### Adding a Phase 4 orchestration layer

Phase 4 should accept `SenderAnalysisResult` as its input contract. It must
not import from `analyzers/sender/` directly — it should depend on the output
model only. Risk scoring, verdict generation, and LLM integration belong in
Phase 4, not in Phase 3 analyzers.

---

## Directory responsibilities

| Path | Responsibility |
|---|---|
| `src/analyzers/sender/` | Phase 3 sender intelligence components |
| `src/config/` | Environment-backed application configuration |
| `src/models/` | Immutable Pydantic data contracts |
| `src/parsers/` | Email ingestion boundary contracts |
| `src/utils/` | Logging and file-loading utilities |
| `data/raw/` | Local unprocessed source material (git-ignored) |
| `data/processed/` | Locally generated data (git-ignored) |
| `data/samples/` | Versioned safe development fixtures |
| `tests/` | Automated verification |
| `docs/` | Architecture and engineering documentation |
