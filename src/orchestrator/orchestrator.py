"""EmailSecurityPipelineOrchestrator coordinating Modules 5-11 with parallel execution, SLA monitoring, and cancellation."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.ai_decision.engine import AIDecisionEngine
from src.ai_decision.models import DecisionPlan
from src.authentication.engine import AuthenticationVerificationEngine
from src.authentication.models import (
    AuthenticationVerification,
    DMARCResultDTO,
    SPFResultDTO,
)
from src.config.logging import get_logger
from src.database.models import RawEmail
from src.orchestrator.exceptions import PipelineCancelledError, StageFailureError
from src.orchestrator.hooks import PipelineLifecycleHooks
from src.orchestrator.models import (
    EmailAnalysisResult,
    PipelineContext,
    StageResult,
    StageStatus,
)
from src.orchestrator.sla_monitor import SLAMonitoringEngine
from src.parsing.engine import MimeParserEngine
from src.parsing.models import ParsedEmail
from src.risk.engine import RiskAssessmentEngine
from src.risk.models import RiskAssessment
from src.threat_intel.engine import ThreatIntelEngine
from src.threat_intel.models import ConfidenceScoreDTO, ThreatIntelEnrichmentResult
from src.transmission.engine import TransmissionAnalysisEngine
from src.transmission.models import SenderIdentityAnalysisDTO, TransmissionAnalysis

logger = get_logger("scamon.orchestrator.pipeline")


class EmailSecurityPipelineOrchestrator:
    """End-to-end Pipeline Orchestrator coordinating Modules 5-11 across the Modular Monolith."""

    def __init__(
        self,
        mime_engine: MimeParserEngine | None = None,
        transmission_engine: TransmissionAnalysisEngine | None = None,
        auth_engine: AuthenticationVerificationEngine | None = None,
        intel_engine: ThreatIntelEngine | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        ai_engine: AIDecisionEngine | None = None,
        hooks: PipelineLifecycleHooks | None = None,
        sla_monitor: SLAMonitoringEngine | None = None,
    ) -> None:
        self.mime_engine = mime_engine or MimeParserEngine()
        self.transmission_engine = transmission_engine or TransmissionAnalysisEngine()
        self.auth_engine = auth_engine or AuthenticationVerificationEngine()
        self.intel_engine = intel_engine or ThreatIntelEngine()
        self.risk_engine = risk_engine or RiskAssessmentEngine()
        self.ai_engine = ai_engine or AIDecisionEngine()
        self.hooks = hooks or PipelineLifecycleHooks()
        self.sla_monitor = sla_monitor or SLAMonitoringEngine()

    async def execute_pipeline(
        self,
        raw_email: RawEmail,
        context: PipelineContext | None = None,
        cancellation_token: asyncio.Event | None = None,
    ) -> EmailAnalysisResult:
        """Execute end-to-end email analysis pipeline across Modules 5-11."""
        start_time = time.perf_counter()
        ctx = context or PipelineContext(tenant_id=raw_email.tenant_id)
        stage_durations: dict[str, float] = {}

        # 0. Check Cancellation
        self._check_cancellation(cancellation_token)

        raw_email_id = getattr(raw_email, "raw_email_id", raw_email.id)
        raw_eml_data: bytes = (
            getattr(raw_email, "raw_content", None)
            or getattr(raw_email, "raw_eml_data", b"")
            or b""
        )

        # Stage 1: MIME Parsing (CRITICAL)
        self.hooks.before_stage("mime_parsing", ctx)
        s1_start = time.perf_counter()
        try:
            parsed = await self.mime_engine.parse_email(
                raw_eml_bytes=raw_eml_data,
                raw_email_id=raw_email_id,
                account_id=raw_email.account_id,
                tenant_id=raw_email.tenant_id,
                message_id=raw_email.message_id or "unknown",
                internet_message_id=raw_email.internet_message_id or "",
            )
            s1_ms = (time.perf_counter() - s1_start) * 1000.0
            stage_durations["mime_parsing"] = s1_ms
            s1_res = StageResult[ParsedEmail](
                status=StageStatus.SUCCESS, execution_time_ms=s1_ms, dto=parsed
            )
            self.hooks.after_stage("mime_parsing", s1_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("mime_parsing", exc, ctx)
            raise StageFailureError("mime_parsing", str(exc)) from exc

        self._check_cancellation(cancellation_token)

        # Stage 2: Parallel Fan-Out (Transmission Analysis & Auth Verification) - OPTIONAL
        self.hooks.before_stage("stage2_parallel", ctx)
        s2_start = time.perf_counter()

        async def _run_trans() -> TransmissionAnalysis:
            return await self.transmission_engine.analyze_transmission(parsed)

        async def _run_auth() -> AuthenticationVerification:
            trans_temp = TransmissionAnalysis(
                parsed_id=parsed.parsed_id,
                raw_email_id=parsed.raw_email_id,
                account_id=parsed.account_id,
                tenant_id=parsed.tenant_id,
                message_id=parsed.message_id,
                internet_message_id=parsed.internet_message_id,
                sender_identity=SenderIdentityAnalysisDTO(
                    from_address=parsed.sender.address,
                    from_domain=parsed.sender.address.split("@")[-1]
                    if "@" in parsed.sender.address
                    else "",
                ),
            )
            return await self.auth_engine.verify_authentication(parsed, trans_temp)

        results = await asyncio.gather(
            _run_trans(), _run_auth(), return_exceptions=True
        )
        trans_res_raw, auth_res_raw = results[0], results[1]
        s2_ms = (time.perf_counter() - s2_start) * 1000.0
        stage_durations["transmission_analysis"] = s2_ms / 2.0
        stage_durations["auth_verification"] = s2_ms / 2.0

        if isinstance(trans_res_raw, TransmissionAnalysis):
            transmission = trans_res_raw
        else:
            self.hooks.on_stage_error(
                "transmission_analysis",
                trans_res_raw
                if isinstance(trans_res_raw, Exception)
                else Exception("Failed"),
                ctx,
            )
            transmission = TransmissionAnalysis(
                parsed_id=parsed.parsed_id,
                raw_email_id=parsed.raw_email_id,
                account_id=parsed.account_id,
                tenant_id=parsed.tenant_id,
                message_id=parsed.message_id,
                internet_message_id=parsed.internet_message_id,
                sender_identity=SenderIdentityAnalysisDTO(
                    from_address=parsed.sender.address,
                    from_domain=parsed.sender.address.split("@")[-1]
                    if "@" in parsed.sender.address
                    else "",
                ),
            )

        if isinstance(auth_res_raw, AuthenticationVerification):
            auth = auth_res_raw
        else:
            self.hooks.on_stage_error(
                "auth_verification",
                auth_res_raw
                if isinstance(auth_res_raw, Exception)
                else Exception("Failed"),
                ctx,
            )
            auth = AuthenticationVerification(
                parsed_id=parsed.parsed_id,
                transmission_id=transmission.analysis_id,
                account_id=parsed.account_id,
                tenant_id=parsed.tenant_id,
                message_id=parsed.message_id,
                internet_message_id=parsed.internet_message_id,
                spf=SPFResultDTO(
                    result="NONE", domain=transmission.sender_identity.from_domain
                ),
                dmarc=DMARCResultDTO(
                    result="NONE", domain=transmission.sender_identity.from_domain
                ),
            )

        self._check_cancellation(cancellation_token)

        # Stage 3: Threat Intelligence Enrichment (OPTIONAL)
        self.hooks.before_stage("threat_intel", ctx)
        s3_start = time.perf_counter()
        try:
            intel = await self.intel_engine.enrich_threat_intelligence(
                parsed, transmission, auth
            )
            s3_ms = (time.perf_counter() - s3_start) * 1000.0
            stage_durations["threat_intel"] = s3_ms
            s3_res = StageResult[ThreatIntelEnrichmentResult](
                status=StageStatus.SUCCESS, execution_time_ms=s3_ms, dto=intel
            )
            self.hooks.after_stage("threat_intel", s3_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("threat_intel", exc, ctx)
            s3_ms = (time.perf_counter() - s3_start) * 1000.0
            stage_durations["threat_intel"] = s3_ms
            intel = ThreatIntelEnrichmentResult(
                parsed_id=parsed.parsed_id,
                transmission_id=transmission.analysis_id,
                auth_verification_id=auth.verification_id,
                account_id=parsed.account_id,
                tenant_id=parsed.tenant_id,
                message_id=parsed.message_id,
                overall_confidence=ConfidenceScoreDTO(confidence=0.0),
            )

        # Stage 3.5: Content & Media Intelligence (OPTIONAL / DEGRADED)
        content_res = None
        url_res = None
        correlation_res = None
        self.hooks.before_stage("content_intelligence", ctx)
        s35_start = time.perf_counter()
        try:
            from src.content_intelligence.engine import ContentIntelligenceEngine

            content_engine = ContentIntelligenceEngine()
            content_res = await content_engine.analyze_content(parsed)
            s35_ms = (time.perf_counter() - s35_start) * 1000.0
            stage_durations["content_intelligence"] = s35_ms
            s35_stage_res = StageResult[Any](
                status=StageStatus.SUCCESS, execution_time_ms=s35_ms, dto=content_res
            )
            self.hooks.after_stage("content_intelligence", s35_stage_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("content_intelligence", exc, ctx)
            s35_ms = (time.perf_counter() - s35_start) * 1000.0
            stage_durations["content_intelligence"] = s35_ms

        # Stage 3.6: URL & Sandbox Intelligence (OPTIONAL / DEGRADED)
        self.hooks.before_stage("url_intelligence", ctx)
        s36_start = time.perf_counter()
        try:
            from src.url_intelligence.engine import URLIntelligenceEngine

            url_engine = URLIntelligenceEngine()
            url_res = await url_engine.analyze_urls(parsed, content_res=content_res)
            s36_ms = (time.perf_counter() - s36_start) * 1000.0
            stage_durations["url_intelligence"] = s36_ms
            s36_stage_res = StageResult[Any](
                status=StageStatus.SUCCESS, execution_time_ms=s36_ms, dto=url_res
            )
            self.hooks.after_stage("url_intelligence", s36_stage_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("url_intelligence", exc, ctx)
            s36_ms = (time.perf_counter() - s36_start) * 1000.0
            stage_durations["url_intelligence"] = s36_ms

        # Stage 3.7: Threat Correlation & Campaign Intelligence (OPTIONAL / DEGRADED)
        self.hooks.before_stage("threat_correlation", ctx)
        s37_start = time.perf_counter()
        try:
            from src.threat_correlation.engine import ThreatCorrelationEngine

            correlation_engine = ThreatCorrelationEngine()
            correlation_res = await correlation_engine.correlate_threats(
                parsed,
                transmission=transmission,
                auth=auth,
                intel=intel,
                content_res=content_res,
                url_res=url_res,
            )
            s37_ms = (time.perf_counter() - s37_start) * 1000.0
            stage_durations["threat_correlation"] = s37_ms
            s37_stage_res = StageResult[Any](
                status=StageStatus.SUCCESS,
                execution_time_ms=s37_ms,
                dto=correlation_res,
            )
            self.hooks.after_stage("threat_correlation", s37_stage_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("threat_correlation", exc, ctx)
            s37_ms = (time.perf_counter() - s37_start) * 1000.0
            stage_durations["threat_correlation"] = s37_ms

        self._check_cancellation(cancellation_token)

        # Stage 4: Enterprise Risk Assessment (CRITICAL)
        self.hooks.before_stage("risk_assessment", ctx)
        s4_start = time.perf_counter()
        try:
            risk = await self.risk_engine.assess_risk(
                parsed=parsed,
                transmission=transmission,
                auth=auth,
                intel=intel,
                content_res=content_res,
                url_res=url_res,
                correlation_res=correlation_res,
            )
            s4_ms = (time.perf_counter() - s4_start) * 1000.0
            stage_durations["risk_assessment"] = s4_ms
            s4_res = StageResult[RiskAssessment](
                status=StageStatus.SUCCESS, execution_time_ms=s4_ms, dto=risk
            )
            self.hooks.after_stage("risk_assessment", s4_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("risk_assessment", exc, ctx)
            raise StageFailureError("risk_assessment", str(exc)) from exc

        self._check_cancellation(cancellation_token)

        # Stage 5: Enterprise AI Decision Planning (OPTIONAL)
        self.hooks.before_stage("ai_decision", ctx)
        s5_start = time.perf_counter()
        try:
            decision = await self.ai_engine.generate_decision_plan(risk)
            s5_ms = (time.perf_counter() - s5_start) * 1000.0
            stage_durations["ai_decision"] = s5_ms
            s5_res = StageResult[DecisionPlan](
                status=StageStatus.SUCCESS, execution_time_ms=s5_ms, dto=decision
            )
            self.hooks.after_stage("ai_decision", s5_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("ai_decision", exc, ctx)
            s5_ms = (time.perf_counter() - s5_start) * 1000.0
            stage_durations["ai_decision"] = s5_ms
            decision = DecisionPlan(
                assessment_id=risk.assessment_id,
                tenant_id=risk.tenant_id,
                message_id=risk.message_id,
                executive_summary="Incident risk assessment completed. AI decision planning operating in degraded mode.",
                technical_summary="Header, authentication, threat intelligence, and risk scoring telemetry completed.",
                analyst_explanation=risk.explainability_summary,
                attack_summary="Threat analysis completed.",
                business_impact="Refer to risk score recommendations.",
                recommended_actions=risk.soc_recommendations,
                risk_confidence=risk.confidence_details.overall_confidence,
                ai_decision_confidence=0.5,
            )

        # Stage 5.1: Enterprise Remediation & Incident Response (OPTIONAL / DEGRADED)
        self.hooks.before_stage("remediation", ctx)
        s51_start = time.perf_counter()
        try:
            from src.remediation.engine import RemediationEngine

            remediation_engine = RemediationEngine()
            remediation_res = await remediation_engine.execute_remediation(
                tenant_id=risk.tenant_id,
                incident_id=risk.parsed_id,
                assessment=risk,
                decision_plan=decision,
                requested_action=risk.recommended_action,
                is_dry_run=True,  # Default safe dry-run mode for pipeline runs
            )
            s51_ms = (time.perf_counter() - s51_start) * 1000.0
            stage_durations["remediation"] = s51_ms
            s51_stage_res = StageResult[Any](
                status=StageStatus.SUCCESS,
                execution_time_ms=s51_ms,
                dto=remediation_res,
            )
            self.hooks.after_stage("remediation", s51_stage_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("remediation", exc, ctx)
            s51_ms = (time.perf_counter() - s51_start) * 1000.0
            stage_durations["remediation"] = s51_ms

        # Stage 5.2: Enterprise Threat Analytics & Reporting (OPTIONAL / DEGRADED)
        self.hooks.before_stage("analytics", ctx)
        s52_start = time.perf_counter()
        try:
            from src.analytics.engine import AnalyticsEngine
            from src.analytics.models import TenantAnalyticsRequestDTO

            analytics_engine = AnalyticsEngine()
            analytics_summary = analytics_engine.aggregate_tenant_analytics(
                TenantAnalyticsRequestDTO(
                    tenant_id=risk.tenant_id, time_window_hours=24
                )
            )
            s52_ms = (time.perf_counter() - s52_start) * 1000.0
            stage_durations["analytics"] = s52_ms
            s52_stage_res = StageResult[Any](
                status=StageStatus.SUCCESS,
                execution_time_ms=s52_ms,
                dto=analytics_summary,
            )
            self.hooks.after_stage("analytics", s52_stage_res, ctx)
        except Exception as exc:
            self.hooks.on_stage_error("analytics", exc, ctx)
            s52_ms = (time.perf_counter() - s52_start) * 1000.0
            stage_durations["analytics"] = s52_ms

        total_ms = (time.perf_counter() - start_time) * 1000.0

        # Evaluate SLA Telemetry
        sla_breached, breached_stages = self.sla_monitor.evaluate_sla(
            stage_durations, total_ms
        )

        return EmailAnalysisResult(
            analysis_id=ctx.analysis_id,
            raw_email_id=raw_email_id,
            account_id=raw_email.account_id,
            tenant_id=raw_email.tenant_id,
            message_id=parsed.message_id,
            pipeline_version="1.0.0",
            execution_mode="PARALLEL",
            schema_version="1.0.0",
            parsed_email=parsed,
            transmission_analysis=transmission,
            auth_verification=auth,
            threat_intel=intel,
            risk_assessment=risk,
            decision_plan=decision,
            sla_metrics=stage_durations,
            sla_breached=sla_breached,
            breached_stages=breached_stages,
            total_execution_time_ms=total_ms,
        )

    def _check_cancellation(self, token: asyncio.Event | None) -> None:
        """Raise PipelineCancelledError if cancellation token is set."""
        if token and token.is_set():
            raise PipelineCancelledError()
