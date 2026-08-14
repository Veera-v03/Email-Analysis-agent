# Software Architecture Specification & Design Document: Module 19

**Document Version:** 1.0.0  
**Target Subsystem:** Sprint 1.9 — Module 19: Enterprise Threat Analytics, Security Compliance & Executive Reporting Engine  
**System Baseline:** ScamON Enterprise Monolith Baseline (Modules 1–18 Release Candidate `scamon-modules-1-18-rc1`)  
**Status:** READ-ONLY ARCHITECTURE REVIEW & DESIGN SPECIFICATION (ZERO CODE CREATED)  
**Protected Baseline Database:** `data/enterprise.db` (**STRICTLY UNTOUCHED & PROTECTED**)  

---

## Executive Summary & Architectural Mandate

This document defines the **Software Architecture Specification and Implementation Plan for Module 19: Enterprise Threat Analytics, Security Compliance & Executive Reporting Engine**.

### Mandatory Baseline Rules:
1. **Modules 1–18 Baseline Frozen**: Modules 1–18 source code, DTO contracts, pipeline stages, and security policies remain 100% frozen under Git tag `scamon-modules-1-18-rc1`.
2. **`data/enterprise.db` Protection**: `data/enterprise.db` is strictly untouched and read-only.
3. **Zero Duplication Policy**: Module 19 **MUST NOT** duplicate email parsing, URL extraction, threat intel lookups, risk scoring, AI decision planning, remediation policy validation, or database/cache infrastructure.
4. **Strict Boundary Isolation**: Module 11 (`AIDecisionEngine`) and Module 17 (`ResponsePolicyEngine`) boundaries remain completely isolated. Module 19 consumes validated analysis outputs *downstream* after execution.

---

## 1. Module 19 Purpose & Problem Statement

### 1.1 Purpose
Module 19 provides enterprise-grade **Threat Analytics Aggregation**, **Executive Security Posture Reporting**, and **Compliance Audit Package Generation** across multi-tenant organizations.

### 1.2 Problem Statement
While Modules 1–18 provide real-time email analysis, AI decision planning, and automated SOC remediation:
- SOC leadership lacks aggregate time-window visibility (24h / 7d / 30d trend metrics, top targeted users, threat vector distributions).
- Executive stakeholders require exportable, compliance-ready security posture reports (JSON / CSV executive summaries).
- Compliance auditors require historical SOC audit package extraction without querying raw databases directly.

Module 19 closes this enterprise platform gap cleanly without modifying any upstream analysis stages.

---

## 2. Capability Inventory & Classification Matrix

| Proposed Capability | Existing Implementation Location | Status Classification | Strategy & Justification |
| :--- | :--- | :---: | :--- |
| **`analytics` Database Table Schema** | `src/database/db_client.py` & PostgreSQL DDL | **ALREADY IMPLEMENTED** | `analytics` table exists in DDL (`id`, `org_id`, `metric_name`, `metric_value`, `timestamp`). |
| **Immutable Audit Storage** | `src/remediation/audit_repository.py` & `src/ops/postgres_client.py` | **ALREADY IMPLEMENTED** | `audit_logs` table stores structured remediation records via `IAuditRepository`. |
| **Real-Time System Metrics** | `src/ops/prometheus_exporter.py` | **ALREADY IMPLEMENTED** | `PrometheusMetricsExporter` exposes low-cardinality system metrics. |
| **Investigation Telemetry Persistence** | `src/database/db_client.py` (`save_investigation`) | **ALREADY IMPLEMENTED** | `investigations` table persists per-email verdict, confidence, and duration. |
| **Multi-Tenant Trend Aggregation Querying** | `src/database/db_client.py` | **EXISTS BUT MUST BE EXTENDED** | `DatabaseClient` stores raw records, but lacks tenant-filtered SQL aggregations (`COUNT`, `GROUP BY`). |
| **Threat Analytics Engine** | *None* | **GENUINELY MISSING** | Create `AnalyticsEngine` (`src/analytics/engine.py`) to calculate 24h/7d trend metrics. |
| **Executive Security Report Generator** | *None* | **GENUINELY MISSING** | Create `ExecutiveReportGenerator` (`src/analytics/report_generator.py`) for PDF/JSON/CSV summary generation. |
| **Analytics Event Contract** | *None* | **GENUINELY MISSING** | Create `AnalyticsAggregatedEvent` in `src/events/security_events.py` for publishing trend metrics. |
| **Analytics DI & Module Lifecycle** | *None* | **GENUINELY MISSING** | Create `AnalyticsModule` (`src/analytics/module.py`) implementing `IModule` and `IHealthCheckable`. |

---

## 3. Package Structure & Architectural Boundaries

```text
src/analytics/
├── __init__.py                # Package exports
├── exceptions.py              # Analytics domain exceptions (AnalyticsError, ReportingError)
├── models.py                  # Input/Output DTOs (TenantAnalyticsRequestDTO, ExecutiveReportDTO)
├── engine.py                  # AnalyticsEngine core service (trend aggregation & metrics)
├── report_generator.py        # ExecutiveReportGenerator (JSON & CSV report generation)
└── module.py                  # AnalyticsModule (IModule & IHealthCheckable implementation)
```

---

## 4. Input & Output DTO Specifications

### 4.1 Input DTO: `TenantAnalyticsRequestDTO`
```python
class TenantAnalyticsRequestDTO(BaseDTO):
    """Input payload for querying tenant threat analytics and generating executive reports."""

    tenant_id: UUID = Field(description="Target Tenant UUID")
    time_window_hours: int = Field(
        default=24, ge=1, le=720, description="Query time window in hours (1-720)"
    )
    include_top_targets: bool = Field(
        default=True, description="Include top targeted recipient emails"
    )
    include_remediation_summary: bool = Field(
        default=True, description="Include SOC remediation breakdown"
    )
```

### 4.2 Output DTO: `TenantAnalyticsSummaryDTO`
```python
class TenantAnalyticsSummaryDTO(BaseDTO):
    """Universal output object representing tenant threat analytics and security posture."""

    tenant_id: UUID = Field(description="Target Tenant UUID")
    time_window_hours: int = Field(description="Evaluation time window")
    total_emails_analyzed: int = Field(default=0, ge=0)
    total_threats_detected: int = Field(default=0, ge=0)
    threat_breakdown_by_verdict: dict[str, int] = Field(default_factory=dict)
    remediation_breakdown_by_action: dict[str, int] = Field(default_factory=dict)
    top_targeted_recipients: list[dict[str, Any]] = Field(default_factory=list)
    average_investigation_latency_ms: float = Field(default=0.0)
    generated_at: str = Field(description="ISO 8601 generation timestamp")
```

### 4.3 Output DTO: `ExecutiveReportDTO`
```python
class ExecutiveReportDTO(BaseDTO):
    """Exportable executive security report payload."""

    report_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID = Field(description="Target Tenant UUID")
    title: str = Field(default="Executive Threat & Security Posture Report")
    summary: TenantAnalyticsSummaryDTO = Field(
        description="Underlying analytics summary"
    )
    compliance_status: str = Field(
        default="COMPLIANT", description="COMPLIANT / ATTENTION_REQUIRED"
    )
    report_format: str = Field(default="JSON", description="JSON, CSV")
    report_data: str = Field(description="Serialized report body text")
```

---

## 5. Event Contract Specification

### `AnalyticsAggregatedEvent` (`src/events/security_events.py`)
```python
class AnalyticsAggregatedEvent(BaseEvent):
    """Security event published when tenant threat analytics are aggregated."""

    event_type: str = Field(default="scamon.analytics.aggregated.v1", frozen=True)
    tenant_id: UUID = Field(description="Target Tenant UUID")
    total_analyzed: int = Field(description="Total emails analyzed in window")
    threats_detected: int = Field(
        description="Total malicious/suspicious threats detected"
    )
    remediations_executed: int = Field(description="Total SOC actions executed")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
```

---

## 6. End-to-End Data Flow

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Modules 1–12 Pipeline Execution                           │
│  (Raw Email ──> Parsers ──> Auth/Intel ──> Risk Scoring ──> AIDecisionPlan ──> Orchestrator)│
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Module 17 / Module 18 Remediation & Storage                      │
│     (ResponsePolicyEngine ──> Remediation ──> PostgresAuditRepository & PostgreSQL DB) │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼ (Post-Pipeline Async Hook)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                         Module 19: Analytics & Reporting Engine                        │
│                                                                                        │
│   ┌────────────────────────┐    ┌─────────────────────────┐    ┌────────────────────┐  │
│   │ AnalyticsEngine        │───►│ExecutiveReportGenerator │───►│AnalyticsAggregated │  │
│   │ (Aggregates Trends)    │    │ (Generates Reports)     │    │Event (Publish Event)│  │
│   └────────────────────────┘    └─────────────────────────┘    └────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Subsystem Integration & Boundary Safety Protocols

1. **Module 10 (`RiskAssessmentEngine`) Integration**: Module 19 queries stored `investigations` records produced downstream by Module 10 (`verdict`, `confidence`, `risk_level`). It never recalculates risk features.
2. **Module 11 (`AIDecisionEngine`) Isolation**: Module 11 continues consuming only validated `RiskAssessment` objects. Module 19 does **NOT** touch or feed back into LLM prompts or decision planning.
3. **Module 12 (`EmailSecurityPipelineOrchestrator`) Integration**: Orchestrator invokes Module 19 as a non-blocking post-pipeline stage hook (`Stage 5.2 Analytics Hook`). If Module 19 fails, the main email analysis pipeline finishes successfully with zero interruption.
4. **Module 17 / 18 Storage Integration**: Module 19 reads audit metrics directly from `IAuditRepository` (`audit_logs`) and `DatabaseClient` (`investigations`) using strict `WHERE org_id = %s` multi-tenant parameterization.

---

## 8. Non-Functional Requirements & Safety Controls

- **Multi-Tenant Isolation**: Every SQL query strictly enforces `WHERE org_id = %s`. Zero cross-tenant data leakage.
- **Latency Requirement**: Analytics aggregations compute in `< 50ms` using indexed database columns (`idx_investigations_org_created`, `idx_audit_logs_org_id`).
- **Resiliency & Degraded Behavior**: If database access fails, Module 19 logs warning telemetry and returns a empty fallback `TenantAnalyticsSummaryDTO`. The pipeline never crashes.
- **Zero External Dependencies**: Implemented using standard Python libraries (`json`, `csv`, `datetime`, `uuid`). Zero new third-party packages required.
- **Prometheus Telemetry**: Module 19 records metrics via `PrometheusMetricsExporter` (`scamon_analytics_generated_total`).

---

## 9. Implementation Plan & Exact File-Change Matrix

### 9.1 Files Reused Unchanged
- `src/database/db_client.py`
- `src/remediation/audit_repository.py`
- `src/ops/postgres_client.py`
- `src/ops/prometheus_exporter.py`
- `src/config/settings.py`
- `src/ai_decision/engine.py` (Module 11 boundary strictly isolated)
- `src/remediation/engine.py` (Module 17 security controls untouched)
- `data/enterprise.db` (**Protected Baseline - Untouched**)

### 9.2 Files Requiring Extension
- `src/events/security_events.py`: Add `AnalyticsAggregatedEvent` class definition.
- `src/orchestrator/orchestrator.py`: Add Stage 5.2 post-remediation Analytics notification hook.

### 9.3 Genuinely New Files to Create
- `src/analytics/__init__.py`: Package exports.
- `src/analytics/exceptions.py`: Domain exceptions (`AnalyticsError`, `ReportingError`).
- `src/analytics/models.py`: DTO definitions (`TenantAnalyticsRequestDTO`, `TenantAnalyticsSummaryDTO`, `ExecutiveReportDTO`).
- `src/analytics/engine.py`: `AnalyticsEngine` service for calculating time-window trend metrics.
- `src/analytics/report_generator.py`: `ExecutiveReportGenerator` service for JSON/CSV report generation.
- `src/analytics/module.py`: `AnalyticsModule` implementing `IModule` and `IHealthCheckable`.
- `tests/test_analytics_module.py`: Unit and integration test suite for Module 19.

---

## 10. Quality Gate Targets

Upon completing Module 19 implementation:
- `python -m ruff check .` $\rightarrow$ **PASS**
- `python -m mypy src` $\rightarrow$ **PASS (0 issues)**
- `python -m pytest` $\rightarrow$ **PASS (663 + new Module 19 tests)**

---

## Conclusion & Readiness Declaration

This document presents the complete **Software Architecture Specification & Design Plan for Module 19**.

I await your explicit approval of this specification before performing the Pre-Implementation Verification!
