"""Explainability engine for generating human-readable planner explanations and final reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.models.agent import AgentState
from src.planner.models.planner import ExecutionPlan
from src.planner.reasoning import ReasoningOutput


class FinalReport(BaseModel):
    """The complete structured security assessment report."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    summary: str = Field(..., description="High-level analyst summary.")
    classification: str = Field(
        ..., description="Verdict classification (e.g. Clean, Phishing, Suspicious)."
    )
    risk_level: str = Field(
        ..., description="Calculated risk: low, medium, high, critical."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Overall investigation confidence score."
    )
    executed_tools: tuple[str, ...] = Field(default_factory=tuple)
    skipped_tools: tuple[str, ...] = Field(default_factory=tuple)
    evidence: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    reasoning: str = Field(..., description="Explanation of findings.")
    recommendations: str = Field(..., description="Mitigation recommendations.")
    timeline: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    execution_statistics: dict[str, Any] = Field(default_factory=dict)

    # Phase 9 Advanced Security fields
    mitre_attack_mapping: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    indicators_of_compromise: dict[str, list[str]] = Field(default_factory=dict)
    threat_classification: tuple[str, ...] = Field(default_factory=tuple)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    score_breakdown: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    executive_summary: str = Field(default="")
    incident_category: str = Field(default="unknown")
    recommended_priority: str = Field(default="P4")
    business_impact: str = Field(default="No material impact identified.")
    confidence_breakdown: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    analyst_notes: tuple[str, ...] = Field(default_factory=tuple)


class ExplainabilityEngine:
    """Generates explanations for planner selections and compiles detailed final reports."""

    def __init__(self) -> None:
        pass

    def explain_planning(
        self, plan: ExecutionPlan, executed_step_ids: set[str] | None = None
    ) -> str:
        """Provide detailed human-readable explanation of why specific tools were scheduled or skipped."""
        explanations = [
            f"Goal: {plan.goal}",
            f"Strategy: {plan.strategy.value.upper()}",
        ]

        executed = executed_step_ids or set()

        for idx, step in enumerate(plan.steps):
            status = "Scheduled"
            if step.step_id in executed:
                status = "Executed"
            explanations.append(
                f"- Step {idx + 1} [{status}]: '{step.tool}' (priority={step.priority}). Reason: {step.reason}"
            )
            if step.dependencies:
                explanations.append(f"  * Dependencies: {', '.join(step.dependencies)}")
            if step.conditions:
                explanations.append(f"  * Conditions: {', '.join(step.conditions)}")

        return "\n".join(explanations)

    def generate_report(
        self,
        state: AgentState,
        reasoning: ReasoningOutput,
        execution_history: list[Any] | None = None,
    ) -> FinalReport:
        """Compile a comprehensive final report summarizing the entire investigation sequence."""
        # 1. Classification mapping
        risk = reasoning.risk_level.lower()
        if risk == "critical":
            classification = "PHISHING / MALICIOUS"
        elif risk == "high":
            classification = "SUSPICIOUS (HIGH RISK)"
        elif risk == "medium":
            classification = "SUSPICIOUS (MODERATE RISK)"
        else:
            classification = "CLEAN / SAFE"

        # 2. Gather executed and skipped tools
        executed: list[str] = []
        skipped: list[str] = []
        timeline: list[dict[str, Any]] = []
        total_duration_ms = 0

        # Parse step runs from execution history
        for record in state.execution_history:
            executed.append(record.tool_name)
            timeline.append(
                {
                    "event": f"Tool Execution: {record.tool_name}",
                    "status": record.status.value,
                    "timestamp": record.timestamp,
                    "duration_ms": record.execution_time_ms,
                    "details": record.details,
                }
            )
            total_duration_ms += record.execution_time_ms

        # Check if planning decisions had skipped steps/tools
        for dec in state.planning_decisions:
            proposed_steps = dec.metadata.get("proposed_steps", [])
            step_tool_map = dec.metadata.get("step_tool_map", {})
            proposed_tools = dec.metadata.get("proposed_tools", [])

            if proposed_tools:
                for t in proposed_tools:
                    if t not in executed and t not in skipped:
                        skipped.append(str(t))
            else:
                for p in proposed_steps:
                    t_name = step_tool_map.get(p, str(p))
                    if t_name not in executed and t_name not in skipped:
                        skipped.append(t_name)

            timeline.append(
                {
                    "event": f"Planning Decision: {dec.reasoning}",
                    "status": "completed",
                    "timestamp": dec.timestamp,
                    "duration_ms": 0,
                    "details": dec.metadata,
                }
            )

        # 3. Evidence compilation
        evidence_items = []
        for ev in state.evidence.items:
            evidence_items.append(
                {
                    "id": ev.evidence_id,
                    "category": ev.category,
                    "title": ev.title,
                    "description": ev.description,
                    "severity": ev.severity.value,
                    "source": ev.source,
                    "confidence": ev.confidence,
                    "timestamp": ev.timestamp,
                }
            )

        # 4. Timeline sorting by timestamp
        try:
            timeline.sort(key=lambda t: t.get("timestamp", ""))
        except Exception:
            pass  # Fallback to unsorted order if timestamps parse error

        # Compute total investigation elapsed time from timeline timestamps
        if timeline:
            try:
                ts_list = [
                    datetime.fromisoformat(t["timestamp"])
                    for t in timeline
                    if t.get("timestamp")
                ]
                if len(ts_list) >= 2:
                    elapsed_calc = int(
                        (max(ts_list) - min(ts_list)).total_seconds() * 1000
                    )
                    total_duration_ms = max(total_duration_ms, elapsed_calc)
            except Exception:
                pass

        # 5. Execution statistics compilation
        success_count = sum(
            1 for r in state.execution_history if r.status.value == "completed"
        )
        failed_count = sum(
            1 for r in state.execution_history if r.status.value == "failed"
        )
        total_runs = len(state.execution_history)
        success_rate = (success_count / total_runs * 100.0) if total_runs > 0 else 100.0

        # Calculate estimated cost (simulated tokens: planning runs + tool execution)
        estimated_planning_cost = (
            len(state.planning_decisions) * 0.005
        )  # $0.005 per plan call
        estimated_cost = estimated_planning_cost + (
            len(state.execution_history) * 0.001
        )

        stats = {
            "total_investigation_time_ms": total_duration_ms,
            "tool_execution_count": total_runs,
            "success_rate_percent": round(success_rate, 1),
            "completed_tools_count": success_count,
            "failed_tools_count": failed_count,
            "planning_runs_count": len(state.planning_decisions),
            "estimated_api_cost_usd": round(estimated_cost, 4),
        }

        # Phase 9 Advanced Security Intelligence Enrichment
        from src.security_intelligence.behavior.behavior_analyzer import (
            BehaviorAnalyzer,
        )
        from src.security_intelligence.ioc.ioc_extractor import IOCExtractor
        from src.security_intelligence.malware.malware_service import MalwareService
        from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService

        iocs: dict[str, list[str]] = {}
        mitre_mapping: list[dict[str, Any]] = []
        threat_class: list[str] = []
        rec_list = [reasoning.recommended_action]

        if state.parsed_email:
            extractor = IOCExtractor()
            body_text = state.parsed_email.body_text or ""
            iocs = extractor.extract_iocs(
                f"{state.parsed_email.header.subject} {state.parsed_email.header.sender} {body_text}"
            )

            analyzer = BehaviorAnalyzer()
            behav = analyzer.analyze_text(body_text)

            malware_res = {"is_malicious": False}
            if state.parsed_email.attachments:
                malware_svc = MalwareService()
                att = state.parsed_email.attachments[0]
                malware_res = malware_svc.analyze_file(att.filename, b"")

            enricher = RiskEnrichmentService()
            profile = enricher.enrich_risk_profile(risk, behav, malware_res)

            mitre_mapping = profile.get("mitre_attack_mapping", [])
            threat_class = profile.get("threat_categories", [])
            for rec in profile.get("soc_recommendations", []):
                rec_list.append(rec)

        recommendations_str = "\n".join(f"- {r}" for r in rec_list)
        priority = {"critical": "P1", "high": "P2", "medium": "P3"}.get(risk, "P4")
        incident_category = (
            "phishing"
            if risk in {"critical", "high"}
            else "suspicious_email"
            if risk == "medium"
            else "benign"
        )
        confidence_breakdown = tuple(
            {
                "factor": item.get("factor", "general"),
                "contribution": item.get("points", 0.0),
                "evidence_id": item.get("evidence_id"),
            }
            for item in reasoning.score_breakdown
        )

        return FinalReport(
            summary=reasoning.summary,
            classification=classification,
            risk_level=risk,
            confidence=reasoning.confidence,
            executed_tools=tuple(executed),
            skipped_tools=tuple(skipped),
            evidence=tuple(evidence_items),
            reasoning=(
                f"{reasoning.security_explanation}\n\n{reasoning.analyst_notes}"
            ),
            recommendations=recommendations_str,
            timeline=tuple(timeline),
            execution_statistics=stats,
            mitre_attack_mapping=tuple(mitre_mapping),
            indicators_of_compromise=iocs,
            threat_classification=tuple(threat_class),
            risk_score=reasoning.risk_score,
            score_breakdown=reasoning.score_breakdown,
            executive_summary=(
                f"{priority} {incident_category.replace('_', ' ')} investigation: "
                f"{reasoning.summary}"
            ),
            incident_category=incident_category,
            recommended_priority=priority,
            business_impact=(
                "Potential credential, financial, or malware exposure requires review."
                if risk in {"critical", "high"}
                else "Limited impact pending analyst validation."
            ),
            confidence_breakdown=confidence_breakdown,
            analyst_notes=tuple(reasoning.analyst_notes.splitlines()),
        )
