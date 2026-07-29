"""Comprehensive test suite verifying Phase 9 Advanced Security Intelligence."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.database.db_client import DatabaseClient
from src.database.repositories import InvestigationMetadataRepository
from src.models.agent import AgentState
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.planner.explainability import ExplainabilityEngine
from src.planner.reasoning import ReasoningEngine
from src.security_intelligence import (
    BehaviorAnalyzer,
    BrandService,
    CampaignCorrelationEngine,
    IOCExtractor,
    MalwareService,
    OCRService,
    QRService,
    RiskEnrichmentService,
    ThreatIntelService,
)

# --- 1. OCR & QR Intelligence Tests ---


def test_ocr_intelligence_extraction() -> None:
    ocr = OCRService()

    # PDF / scanned format
    res = ocr.extract_text("invoice_123.pdf", b"%PDF-1.4 mock pdf structure")
    assert "invoice" in res["extracted_text"].lower()
    assert res["confidence"] > 0.90

    # Image format
    res2 = ocr.extract_text("screenshot.png", b"png mock data")
    assert res2["confidence"] > 0.80


def test_qr_intelligence_redirect_resolution() -> None:
    qr = QRService()

    res = qr.extract_and_decode("qr_login.png", b"QR code containing url")
    assert res["qr_detected"] is True
    assert "phishing-portal.com" in res["resolved_url"]
    assert res["is_malicious"] is True


# --- 2. Brand Impersonation Tests ---


def test_brand_impersonation_scenarios() -> None:
    brand_svc = BrandService()

    # 1. Display name spoofing
    res1 = brand_svc.analyze_sender("PayPal Support Alert", "hacker@gmail.com")
    assert res1["impersonation_detected"] is True
    assert res1["type"] == "display_name_spoofing"

    # 2. Typosquatting (Levenshtein distance)
    res2 = brand_svc.analyze_sender("Billing", "support@micr0soft.com")
    assert res2["impersonation_detected"] is True
    assert res2["type"] == "typosquatting"

    # 3. Homograph domain checking (Punycode spoofing)
    res3 = brand_svc.analyze_sender("System Account", "service@xn--appl-j4a.com")
    assert res3["impersonation_detected"] is True
    assert res3["type"] == "homograph_impersonation"

    # 4. Hyphenated visual indicator domain
    res4 = brand_svc.analyze_sender("System Billing", "accounts@google-login.support")
    assert res4["impersonation_detected"] is True
    assert res4["type"] == "hyphen_impersonation"


# --- 3. IOC Extraction & Threat Intel Tests ---


def test_ioc_extractor_regex() -> None:
    extractor = IOCExtractor()
    sample_text = """
    Alert! Host 198.51.100.42 is communicating with malware-server.com.
    Payload hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Check files: invoice.pdf.exe, backdoor.exe.
    Registry keys: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    """
    iocs = extractor.extract_iocs(sample_text)

    assert "198.51.100.42" in iocs["ips"]
    assert "malware-server.com" in iocs["domains"]
    assert "backdoor.exe" in iocs["filenames"]
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in iocs["hashes"]
    )


def test_threat_intel_enricher() -> None:
    intel = ThreatIntelService()

    iocs = {"ips": ["198.51.100.42"], "domains": ["phishing-portal.com"]}
    enrichment = intel.enrich_iocs(iocs)

    assert enrichment["is_threat_detected"] is True
    assert enrichment["max_threat_score"] > 0.90
    assert len(enrichment["threats"]) == 2


# --- 4. Malware static analysis Tests ---


def test_malware_file_inspections() -> None:
    malware = MalwareService()

    # Double extension check
    res1 = malware.analyze_file("statement.pdf.exe", b"MZ mock executable")
    assert res1["is_malicious"] is True
    assert res1["detected_format"] == "pe_executable"

    # Macros check in VBA payload
    res2 = malware.analyze_file("document.doc", b"AutoOpen shell injection payload")
    assert res2["is_malicious"] is True
    assert res2["vba_macros_detected"] is True

    # High entropy check
    high_entropy_bytes = bytes([x % 256 for x in range(2000)])  # High dispersion
    res3 = malware.analyze_file("random_data.bin", high_entropy_bytes)
    assert res3["entropy"] > 7.0


# --- 5. Campaign Correlation Tests ---


def test_campaign_correlation_db() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "test_campaign.db"
        client = DatabaseClient(db_path=str(db_file))

        inv_repo = InvestigationMetadataRepository(client)
        correlator = CampaignCorrelationEngine(client)

        # Save historical runs
        from src.database.repositories import OrganizationRepository

        OrganizationRepository(client).create("Acme Corp", org_id="org_1")

        inv_repo.save(
            org_id="org_1",
            email_id="<msg-1>",
            subject="Urgent Invoice Payment",
            sender="scammer@malicious.com",
            verdict="phishing",
            confidence=0.95,
            risk_level="high",
            duration_ms=100,
        )
        inv_repo.save(
            org_id="org_1",
            email_id="<msg-2>",
            subject="Invoice Overdue Notification",
            sender="scammer@malicious.com",
            verdict="phishing",
            confidence=0.98,
            risk_level="high",
            duration_ms=90,
        )

        # Correlate identical sender
        correlation = correlator.correlate_investigation(
            org_id="org_1",
            sender="scammer@malicious.com",
            subject="Urgent Invoice Payment Request",
            extracted_iocs={"urls": []},
        )

        assert correlation["campaign_detected"] is True
        assert "sender_match" in correlation["indicators_matched"]
        assert correlation["campaign_score"] > 3.0


# --- 6. Behavioral Analysis & Risk Enrichment Tests ---


def test_behavioral_analysis_and_mitre_mapping() -> None:
    analyzer = BehaviorAnalyzer()
    enricher = RiskEnrichmentService()

    text = "CEO requests urgent wire transfer invoice payment details today."
    behav = analyzer.analyze_text(text)

    assert behav["social_engineering_detected"] is True
    assert "bec_impersonation" in behav["detected_tactics"]

    profile = enricher.enrich_risk_profile("critical", behav)
    assert "Business Email Compromise (BEC)" in profile["threat_categories"]
    assert any(tech["id"] == "T1566.003" for tech in profile["mitre_attack_mapping"])


# --- 7. End-to-End Advanced Reasoning and Report Integration ---


def test_e2e_advanced_security_report() -> None:
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<e2e-msg>",
                sender="alert@pay-pal.com",  # Visual impersonation
                recipients=["user@corp.com"],
                subject="URGENT: Verify PayPal Login Account Information",
                sent_at="2026-07-28T12:00:00Z",
            ),
            body_text="Dear Paypal user, verify account immediately at http://fakebank-login.com.",
            attachments=[
                EmailAttachment(
                    filename="security_statement.pdf.exe",  # Double extension
                    content_type="application/octet-stream",
                    size_bytes=2048,
                )
            ],
        )
    )

    # 1. Trigger Reasoning
    reasoning_engine = ReasoningEngine()
    verdict = reasoning_engine.reason(state)

    # Impersonation and social engineering triggers should flag Critical risk
    assert verdict.risk_level == "critical"
    assert any(
        "Brand Impersonation Detected" in c["indicator"]
        for c in verdict.evidence_correlation
    )

    # 2. Compile Explainability Report
    explain = ExplainabilityEngine()
    report = explain.generate_report(state, verdict)

    # Check Phase 9 report parameters
    assert "Credential Phishing" in report.threat_classification
    assert "127.0.0.1" not in report.indicators_of_compromise.get("ips", [])
    assert any(
        "fakebank-login.com" in url
        for url in report.indicators_of_compromise.get("urls", [])
    )
    assert any(tech.get("id") == "T1566.002" for tech in report.mitre_attack_mapping)
