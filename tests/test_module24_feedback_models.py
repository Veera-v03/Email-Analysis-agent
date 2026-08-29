"""Targeted unit tests for Module 24 Phase 1 (Domain Models & Event Contracts)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.common.constants import ActionTaken, Verdict
from src.events.feedback_events import (
    AnalystVerdictSubmittedEvent,
    FalseNegativeConfirmedEvent,
    FalsePositiveConfirmedEvent,
)
from src.feedback.models import (
    ANALYST_TRUST_WEIGHTS,
    AnalystFeedbackRecordDTO,
    AnalystFeedbackSubmissionDTO,
    AnalystTrustLevel,
    AnalystVerdictCorrection,
    FeedbackReasonCategory,
)


# ===========================================================================
# 1. Enum Validation Tests
# ===========================================================================
def test_analyst_verdict_correction_enum_members() -> None:
    expected = {
        "CONFIRMED_MALICIOUS",
        "CONFIRMED_SUSPICIOUS",
        "CONFIRMED_CLEAN",
        "FALSE_POSITIVE",
        "FALSE_NEGATIVE",
        "BENIGN_ANOMALY",
        "NEEDS_ESCALATION",
    }
    actual = {m.value for m in AnalystVerdictCorrection}
    assert actual == expected


def test_feedback_reason_category_enum_members() -> None:
    expected = {
        "LEGITIMATE_MARKETING",
        "INTERNAL_COMMUNICATION",
        "MISCONFIGURED_SPF_DKIM",
        "AUTHORIZED_EXTERNAL_VENDOR",
        "FALSE_POSITIVE_KEYWORD",
        "OBFUSCATED_MALICIOUS_LINK",
        "QR_CODE_CREDENTIAL_PHISH",
        "VIP_IMPERSONATION",
        "OTHER",
    }
    actual = {m.value for m in FeedbackReasonCategory}
    assert actual == expected


def test_analyst_trust_level_weights() -> None:
    assert ANALYST_TRUST_WEIGHTS[AnalystTrustLevel.JUNIOR_ANALYST] == 0.50
    assert ANALYST_TRUST_WEIGHTS[AnalystTrustLevel.SENIOR_ANALYST] == 0.85
    assert ANALYST_TRUST_WEIGHTS[AnalystTrustLevel.LEAD_SOC_ADMIN] == 1.00


# ===========================================================================
# 2. AnalystFeedbackSubmissionDTO Tests
# ===========================================================================
def test_valid_submission_dto() -> None:
    inc_id = uuid4()
    dto = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.AUTHORIZED_EXTERNAL_VENDOR,
        analyst_notes="Legitimate vendor payroll notification",
        override_remediation=True,
        evidence_tags=["dmarc_result", "spf_result"],
    )
    assert dto.incident_id == inc_id
    assert dto.message_id == "msg_001"
    assert dto.corrected_verdict == AnalystVerdictCorrection.FALSE_POSITIVE
    assert dto.reason_category == FeedbackReasonCategory.AUTHORIZED_EXTERNAL_VENDOR
    assert dto.analyst_notes == "Legitimate vendor payroll notification"
    assert dto.override_remediation is True
    assert dto.evidence_tags == ["dmarc_result", "spf_result"]


def test_submission_dto_invalid_uuid_rejection() -> None:
    with pytest.raises(ValidationError):
        AnalystFeedbackSubmissionDTO(
            incident_id="invalid-uuid-12345",  # type: ignore[arg-type]
            message_id="msg_001",
            corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
            reason_category=FeedbackReasonCategory.OTHER,
        )


def test_submission_dto_invalid_enum_rejection() -> None:
    with pytest.raises(ValidationError):
        AnalystFeedbackSubmissionDTO(
            incident_id=uuid4(),
            message_id="msg_001",
            corrected_verdict="NON_EXISTENT_VERDICT",  # type: ignore[arg-type]
            reason_category=FeedbackReasonCategory.OTHER,
        )


def test_submission_dto_analyst_notes_max_length() -> None:
    # 2000 chars is accepted
    notes_2000 = "x" * 2000
    dto = AnalystFeedbackSubmissionDTO(
        incident_id=uuid4(),
        message_id="msg_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
        analyst_notes=notes_2000,
    )
    assert len(dto.analyst_notes) == 2000

    # 2001 chars is rejected
    notes_2001 = "x" * 2001
    with pytest.raises(ValidationError):
        AnalystFeedbackSubmissionDTO(
            incident_id=uuid4(),
            message_id="msg_001",
            corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_notes=notes_2001,
        )


def test_submission_dto_immutability() -> None:
    dto = AnalystFeedbackSubmissionDTO(
        incident_id=uuid4(),
        message_id="msg_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )
    with pytest.raises(ValidationError):
        dto.message_id = "modified_msg"  # type: ignore[misc]


def test_submission_dto_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AnalystFeedbackSubmissionDTO(
            incident_id=uuid4(),
            message_id="msg_001",
            corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
            reason_category=FeedbackReasonCategory.OTHER,
            untrusted_tenant_id=uuid4(),  # type: ignore[call-arg]
        )


# ===========================================================================
# 3. AnalystFeedbackRecordDTO Tests
# ===========================================================================
def test_valid_audit_record_dto() -> None:
    t_id = uuid4()
    acc_id = uuid4()
    inc_id = uuid4()
    record = AnalystFeedbackRecordDTO(
        tenant_id=t_id,
        account_id=acc_id,
        incident_id=inc_id,
        message_id="msg_audit_001",
        original_risk_score=85,
        original_calibrated_prob=0.92,
        original_verdict=Verdict.MALICIOUS,
        original_action=ActionTaken.QUARANTINED,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.AUTHORIZED_EXTERNAL_VENDOR,
        analyst_id="analyst_alice@example.com",
        analyst_trust_level=AnalystTrustLevel.SENIOR_ANALYST,
        analyst_notes="Verified vendor email",
        convergence_applied=True,
        convergence_weight=0.85,
    )
    assert isinstance(record.feedback_id, UUID)
    assert record.tenant_id == t_id
    assert record.original_risk_score == 85
    assert record.original_calibrated_prob == 0.92
    assert record.original_verdict == Verdict.MALICIOUS
    assert record.original_action == ActionTaken.QUARANTINED
    assert record.corrected_verdict == AnalystVerdictCorrection.FALSE_POSITIVE
    assert record.analyst_trust_level == AnalystTrustLevel.SENIOR_ANALYST
    assert record.convergence_applied is True
    assert record.convergence_weight == 0.85
    assert isinstance(record.created_at, datetime)
    assert record.created_at.tzinfo == UTC


def test_audit_record_risk_score_boundaries() -> None:
    t_id, acc_id, inc_id = uuid4(), uuid4(), uuid4()

    # Score 0 is valid
    rec0 = AnalystFeedbackRecordDTO(
        tenant_id=t_id,
        account_id=acc_id,
        incident_id=inc_id,
        message_id="msg_0",
        original_risk_score=0,
        original_calibrated_prob=0.0,
        original_verdict=Verdict.CLEAN,
        original_action=ActionTaken.DELIVERED,
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_CLEAN,
        reason_category=FeedbackReasonCategory.OTHER,
        analyst_id="analyst@example.com",
        analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
    )
    assert rec0.original_risk_score == 0

    # Score 100 is valid
    rec100 = AnalystFeedbackRecordDTO(
        tenant_id=t_id,
        account_id=acc_id,
        incident_id=inc_id,
        message_id="msg_100",
        original_risk_score=100,
        original_calibrated_prob=1.0,
        original_verdict=Verdict.MALICIOUS,
        original_action=ActionTaken.BLOCKED,
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_MALICIOUS,
        reason_category=FeedbackReasonCategory.OBFUSCATED_MALICIOUS_LINK,
        analyst_id="analyst@example.com",
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN,
    )
    assert rec100.original_risk_score == 100

    # Score < 0 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_neg",
            original_risk_score=-1,
            original_calibrated_prob=0.5,
            original_verdict=Verdict.CLEAN,
            original_action=ActionTaken.DELIVERED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_CLEAN,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
        )

    # Score > 100 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_over",
            original_risk_score=101,
            original_calibrated_prob=0.5,
            original_verdict=Verdict.MALICIOUS,
            original_action=ActionTaken.BLOCKED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_MALICIOUS,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN,
        )


def test_audit_record_calibrated_probability_boundaries() -> None:
    t_id, acc_id, inc_id = uuid4(), uuid4(), uuid4()

    # Prob < 0.0 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_p_neg",
            original_risk_score=50,
            original_calibrated_prob=-0.01,
            original_verdict=Verdict.SUSPICIOUS,
            original_action=ActionTaken.BANNER_INJECTED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
        )

    # Prob > 1.0 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_p_over",
            original_risk_score=50,
            original_calibrated_prob=1.01,
            original_verdict=Verdict.SUSPICIOUS,
            original_action=ActionTaken.BANNER_INJECTED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
        )


def test_audit_record_convergence_weight_boundaries() -> None:
    t_id, acc_id, inc_id = uuid4(), uuid4(), uuid4()

    # Weight < 0.0 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_w_neg",
            original_risk_score=50,
            original_calibrated_prob=0.5,
            original_verdict=Verdict.SUSPICIOUS,
            original_action=ActionTaken.BANNER_INJECTED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
            convergence_weight=-0.1,
        )

    # Weight > 1.0 rejected
    with pytest.raises(ValidationError):
        AnalystFeedbackRecordDTO(
            tenant_id=t_id,
            account_id=acc_id,
            incident_id=inc_id,
            message_id="msg_w_over",
            original_risk_score=50,
            original_calibrated_prob=0.5,
            original_verdict=Verdict.SUSPICIOUS,
            original_action=ActionTaken.BANNER_INJECTED,
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS,
            reason_category=FeedbackReasonCategory.OTHER,
            analyst_id="analyst@example.com",
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST,
            convergence_weight=1.05,
        )


def test_audit_record_immutability() -> None:
    record = AnalystFeedbackRecordDTO(
        tenant_id=uuid4(),
        account_id=uuid4(),
        incident_id=uuid4(),
        message_id="msg_001",
        original_risk_score=80,
        original_calibrated_prob=0.88,
        original_verdict=Verdict.MALICIOUS,
        original_action=ActionTaken.QUARANTINED,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
        analyst_id="analyst@example.com",
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN,
    )
    with pytest.raises(ValidationError):
        record.convergence_applied = True  # type: ignore[misc]


def test_audit_record_json_roundtrip() -> None:
    t_id, acc_id, inc_id = uuid4(), uuid4(), uuid4()
    original = AnalystFeedbackRecordDTO(
        tenant_id=t_id,
        account_id=acc_id,
        incident_id=inc_id,
        message_id="msg_roundtrip",
        original_risk_score=75,
        original_calibrated_prob=0.82,
        original_verdict=Verdict.MALICIOUS,
        original_action=ActionTaken.QUARANTINED,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.LEGITIMATE_MARKETING,
        analyst_id="analyst_bob@example.com",
        analyst_trust_level=AnalystTrustLevel.SENIOR_ANALYST,
        analyst_notes="Marketing blast approved by corporate communications",
        convergence_applied=False,
        convergence_weight=0.85,
    )
    json_str = original.model_dump_json()
    reconstructed = AnalystFeedbackRecordDTO.model_validate_json(json_str)

    assert reconstructed.feedback_id == original.feedback_id
    assert reconstructed.tenant_id == original.tenant_id
    assert reconstructed.original_risk_score == 75
    assert reconstructed.corrected_verdict == AnalystVerdictCorrection.FALSE_POSITIVE
    assert reconstructed.analyst_trust_level == AnalystTrustLevel.SENIOR_ANALYST


# ===========================================================================
# 4. Event Contracts Tests
# ===========================================================================
def test_analyst_verdict_submitted_event() -> None:
    t_id = uuid4()
    fb_id = uuid4()
    inc_id = uuid4()
    event = AnalystVerdictSubmittedEvent(
        tenant_id=t_id,
        feedback_id=fb_id,
        incident_id=inc_id,
        message_id="msg_evt_001",
        original_verdict="MALICIOUS",
        corrected_verdict="FALSE_POSITIVE",
        reason_category="AUTHORIZED_EXTERNAL_VENDOR",
        analyst_id="analyst_carol@example.com",
        analyst_trust_level="SENIOR_ANALYST",
    )
    assert event.event_type == "scamon.prod.feedback.submitted.v1"
    assert event.tenant_id == t_id
    assert event.feedback_id == fb_id
    assert event.incident_id == inc_id
    assert event.message_id == "msg_evt_001"
    assert isinstance(event.event_id, UUID)
    assert isinstance(event.correlation_id, UUID)
    assert isinstance(event.timestamp, datetime)


def test_false_positive_confirmed_event() -> None:
    t_id = uuid4()
    fb_id = uuid4()
    inc_id = uuid4()
    event = FalsePositiveConfirmedEvent(
        tenant_id=t_id,
        feedback_id=fb_id,
        incident_id=inc_id,
        sender_domain="payroll-vendor.com",
        sender_address="notifications@payroll-vendor.com",
        evidence_tags=["dmarc_result", "has_credential_form"],
    )
    assert event.event_type == "scamon.prod.feedback.false_positive.v1"
    assert event.tenant_id == t_id
    assert event.sender_domain == "payroll-vendor.com"
    assert event.evidence_tags == ["dmarc_result", "has_credential_form"]


def test_false_negative_confirmed_event() -> None:
    t_id = uuid4()
    fb_id = uuid4()
    inc_id = uuid4()
    event = FalseNegativeConfirmedEvent(
        tenant_id=t_id,
        feedback_id=fb_id,
        incident_id=inc_id,
        sender_domain="attacker-c2.net",
        malicious_iocs=["198.51.100.99", "https://attacker-c2.net/payload.exe"],
    )
    assert event.event_type == "scamon.prod.feedback.false_negative.v1"
    assert event.tenant_id == t_id
    assert event.sender_domain == "attacker-c2.net"
    assert len(event.malicious_iocs) == 2


def test_events_json_serialization() -> None:
    t_id = uuid4()
    event = AnalystVerdictSubmittedEvent(
        tenant_id=t_id,
        feedback_id=uuid4(),
        incident_id=uuid4(),
        message_id="msg_serialize_test",
        original_verdict="CLEAN",
        corrected_verdict="FALSE_NEGATIVE",
        reason_category="OBFUSCATED_MALICIOUS_LINK",
        analyst_id="analyst@example.com",
        analyst_trust_level="LEAD_SOC_ADMIN",
    )
    dumped_json = event.model_dump_json()
    reloaded = AnalystVerdictSubmittedEvent.model_validate_json(dumped_json)
    assert reloaded.event_type == "scamon.prod.feedback.submitted.v1"
    assert reloaded.corrected_verdict == "FALSE_NEGATIVE"
    assert reloaded.tenant_id == t_id
