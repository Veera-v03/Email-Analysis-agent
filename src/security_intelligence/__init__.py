"""Phase 9 - Advanced Security Intelligence Module Exports."""

from src.security_intelligence.behavior.behavior_analyzer import BehaviorAnalyzer
from src.security_intelligence.brand.brand_service import BrandService
from src.security_intelligence.campaign.campaign_correlation import (
    CampaignCorrelationEngine,
)
from src.security_intelligence.ioc.ioc_extractor import IOCExtractor
from src.security_intelligence.malware.malware_service import MalwareService
from src.security_intelligence.models.security_report import (
    EnterpriseSecurityReport,
    MitreAttackTechnique,
)
from src.security_intelligence.ocr.ocr_service import OCRService
from src.security_intelligence.qr.qr_service import QRService
from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelligenceFramework,
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)
from src.security_intelligence.threat_intel.threat_intel_service import (
    IThreatIntelProvider,
    LocalThreatIntelProvider,
    ThreatIntelService,
)

__all__ = [
    # Services
    "OCRService",
    "QRService",
    "BrandService",
    "IOCExtractor",
    "IThreatIntelProvider",
    "LocalThreatIntelProvider",
    "ThreatIntelService",
    "ThreatIntelObservation",
    "ThreatIntelProvider",
    "ThreatIntelTargetType",
    "ThreatIntelligenceFramework",
    "MalwareService",
    "CampaignCorrelationEngine",
    "BehaviorAnalyzer",
    "RiskEnrichmentService",
    # Models
    "MitreAttackTechnique",
    "EnterpriseSecurityReport",
]
