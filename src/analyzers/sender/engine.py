"""Composition root for Phase 3 sender intelligence.

The engine adapts the existing ``EmailInput`` contract to independently
testable sender analyzers. It does not parse raw email content or modify the
Phase 2 parsing boundary.
"""

from __future__ import annotations

from collections.abc import Callable

from src.analyzers.sender.authentication import (
    AuthenticationHeaderInterpreter,
    DeterministicAuthenticationHeaderInterpreter,
)
from src.analyzers.sender.contracts import SenderExtractor
from src.analyzers.sender.display_name import (
    DeterministicDisplayNameAnalyzer,
    DisplayNameAnalyzer,
)
from src.analyzers.sender.domain import DomainParser, PublicSuffixDomainParser
from src.analyzers.sender.domain_features import (
    DeterministicDomainFeatureAnalyzer,
    DomainFeatureAnalyzer,
)
from src.analyzers.sender.extractor import StructuredSenderExtractor
from src.analyzers.sender.header_comparison import (
    DeterministicSenderHeaderComparator,
    SenderHeaderComparator,
)
from src.analyzers.sender.header_sources import HeaderValue, MappingHeaderProvider
from src.analyzers.sender.normalization import (
    CanonicalEmailAddressNormalizer,
    EmailAddressNormalizer,
)
from src.analyzers.sender.relationships import (
    DeterministicSenderRelationshipBuilder,
    SenderRelationshipBuilder,
)
from src.models.authentication import AuthenticationAnalysisResult
from src.models.display_name import DisplayNameAnalysisResult
from src.models.email import EmailInput
from src.models.evidence import EvidenceSeverity
from src.models.sender import (
    ParsedEmailAddress,
)
from src.models.sender import (
    SenderAnalysisResult as AddressAnalysisResult,
)
from src.models.sender_analysis import (
    NormalizedAddressEvidence,
    SenderAnalysisMetadata,
    SenderAnalysisResult,
    SenderDomainEvidence,
    SenderIdentity,
    SenderMetadataEntry,
)
from src.models.sender_consistency import SenderHeaderName
from src.utils.evidence import EvidenceCollector


class SenderIntelligenceEngine:
    """Coordinate Phase 3 analyzers through dependency-injected interfaces."""

    def __init__(
        self,
        *,
        sender_extractor: SenderExtractor | None = None,
        address_normalizer: EmailAddressNormalizer | None = None,
        domain_parser: DomainParser | None = None,
        domain_feature_analyzer: DomainFeatureAnalyzer | None = None,
        display_name_analyzer: DisplayNameAnalyzer | None = None,
        header_comparator: SenderHeaderComparator | None = None,
        authentication_interpreter: AuthenticationHeaderInterpreter | None = None,
        relationship_builder: SenderRelationshipBuilder | None = None,
        evidence_collector_factory: Callable[[], EvidenceCollector] = EvidenceCollector,
    ) -> None:
        """Create an engine with independently replaceable Phase 3 components."""
        self._sender_extractor = sender_extractor or StructuredSenderExtractor()
        self._address_normalizer = (
            address_normalizer or CanonicalEmailAddressNormalizer()
        )
        self._domain_parser = domain_parser or PublicSuffixDomainParser()
        self._domain_feature_analyzer = (
            domain_feature_analyzer or DeterministicDomainFeatureAnalyzer()
        )
        self._display_name_analyzer = (
            display_name_analyzer or DeterministicDisplayNameAnalyzer()
        )
        self._header_comparator = (
            header_comparator or DeterministicSenderHeaderComparator()
        )
        self._authentication_interpreter = (
            authentication_interpreter or DeterministicAuthenticationHeaderInterpreter()
        )
        self._relationship_builder = (
            relationship_builder or DeterministicSenderRelationshipBuilder()
        )
        self._evidence_collector_factory = evidence_collector_factory

    def analyze(self, email: EmailInput) -> SenderAnalysisResult:
        """Transform a validated Phase 2 email model into sender intelligence.

        Args:
            email: Validated normalized email input supplied by the parser layer.

        Returns:
            Unified Phase 3 sender evidence without any security verdict.
        """
        headers = self._header_provider(email)
        collector = self._evidence_collector_factory()
        addresses = self._sender_extractor.extract(headers)
        self._emit_extraction_evidence(collector, addresses)

        normalized_addresses = self._normalized_addresses(addresses)
        self._emit_normalization_evidence(collector, len(normalized_addresses))

        domains = self._domain_evidence(addresses)
        self._emit_domain_evidence(collector, domains)

        display_name = self._display_name_evidence(addresses)
        self._emit_display_name_evidence(collector, display_name is not None)

        consistency = self._header_comparator.compare(addresses)
        self._emit_consistency_evidence(collector, len(consistency.mismatches))

        authentication = self._authentication_interpreter.interpret(headers)
        self._emit_authentication_evidence(collector, authentication)

        relationships = self._relationship_builder.build(addresses)
        self._emit_relationship_evidence(collector, len(relationships.nodes))

        collector.emit(
            evidence_type="sender.engine.completed",
            title="Sender intelligence processing completed",
            description="All configured Phase 3 sender analyzers completed.",
            severity=EvidenceSeverity.INFO,
            source="sender_intelligence_engine",
            metadata={"message_id": email.header.message_id},
        )
        return SenderAnalysisResult(
            sender=self._sender_identity(addresses),
            addresses=addresses,
            normalized_addresses=normalized_addresses,
            domains=domains,
            authentication=authentication,
            consistency=consistency,
            display_name=display_name,
            relationships=relationships,
            evidence=collector.snapshot(),
            metadata=SenderAnalysisMetadata(
                analysis_id=email.header.message_id,
                producer="sender_intelligence_engine",
                entries=(
                    SenderMetadataEntry(key="subject", value=email.header.subject),
                    SenderMetadataEntry(key="sent_at", value=email.header.sent_at),
                ),
            ),
        )

    @staticmethod
    def _header_provider(email: EmailInput) -> MappingHeaderProvider:
        """Adapt available Phase 2 header fields without reading raw message data."""
        headers: dict[str, HeaderValue] = {
            "From": email.header.sender,
            "To": tuple(email.header.recipients),
        }
        if email.header.reply_to:
            headers["Reply-To"] = email.header.reply_to
        return MappingHeaderProvider(headers)

    @staticmethod
    def _header_address_groups(
        addresses: AddressAnalysisResult,
    ) -> tuple[tuple[SenderHeaderName, tuple[ParsedEmailAddress, ...]], ...]:
        """Return sender-header groups while keeping downstream processing ordered."""
        return (
            (SenderHeaderName.FROM, addresses.from_addresses),
            (SenderHeaderName.SENDER, addresses.sender_addresses),
            (SenderHeaderName.REPLY_TO, addresses.reply_to_addresses),
            (SenderHeaderName.RETURN_PATH, addresses.return_path_addresses),
        )

    def _normalized_addresses(
        self,
        addresses: AddressAnalysisResult,
    ) -> tuple[NormalizedAddressEvidence, ...]:
        """Normalize every compared sender-header address occurrence."""
        normalized: list[NormalizedAddressEvidence] = []
        for header_name, header_addresses in self._header_address_groups(addresses):
            for address in header_addresses:
                normalized.append(
                    NormalizedAddressEvidence(
                        source_header=header_name,
                        normalized_address=self._address_normalizer.normalize(
                            address.email or address.raw_value
                        ),
                    )
                )
        return tuple(normalized)

    def _domain_evidence(
        self,
        addresses: AddressAnalysisResult,
    ) -> tuple[SenderDomainEvidence, ...]:
        """Parse and feature every syntactically extracted sender-header domain."""
        evidence: list[SenderDomainEvidence] = []
        for header_name, header_addresses in self._header_address_groups(addresses):
            for address in header_addresses:
                if not address.domain:
                    continue
                parsed_domain = self._domain_parser.parse(address.domain)
                evidence.append(
                    SenderDomainEvidence(
                        source_header=header_name,
                        parsed_domain=parsed_domain,
                        features=self._domain_feature_analyzer.analyze(parsed_domain),
                    )
                )
        return tuple(evidence)

    def _display_name_evidence(
        self,
        addresses: AddressAnalysisResult,
    ) -> DisplayNameAnalysisResult | None:
        """Analyze the first available sender-chain display name, if present."""
        for _, header_addresses in self._header_address_groups(addresses):
            for address in header_addresses:
                if address.display_name:
                    return self._display_name_analyzer.analyze(address.display_name)
        return None

    @staticmethod
    def _sender_identity(addresses: AddressAnalysisResult) -> SenderIdentity:
        """Create a convenience primary-identity view from address collections."""
        return SenderIdentity(
            from_address=(
                addresses.from_addresses[0] if addresses.from_addresses else None
            ),
            sender_address=(
                addresses.sender_addresses[0] if addresses.sender_addresses else None
            ),
            reply_to_address=(
                addresses.reply_to_addresses[0]
                if addresses.reply_to_addresses
                else None
            ),
            return_path_address=(
                addresses.return_path_addresses[0]
                if addresses.return_path_addresses
                else None
            ),
        )

    @staticmethod
    def _emit_extraction_evidence(
        collector: EvidenceCollector,
        addresses: AddressAnalysisResult,
    ) -> None:
        """Emit extraction-stage summary evidence without exposing a verdict."""
        collector.emit(
            evidence_type="sender.address_extraction",
            title="Sender addresses extracted",
            description="Address-bearing sender headers were structurally extracted.",
            severity=EvidenceSeverity.INFO,
            source="sender_extractor",
            metadata={"from_count": len(addresses.from_addresses)},
        )

    @staticmethod
    def _emit_normalization_evidence(collector: EvidenceCollector, count: int) -> None:
        """Emit address-normalization summary evidence."""
        collector.emit(
            evidence_type="sender.address_normalization",
            title="Sender addresses normalized",
            description=(
                "Available sender-header addresses received canonical processing."
            ),
            severity=EvidenceSeverity.INFO,
            source="email_address_normalizer",
            metadata={"address_count": count},
        )

    @staticmethod
    def _emit_domain_evidence(
        collector: EvidenceCollector,
        domains: tuple[SenderDomainEvidence, ...],
    ) -> None:
        """Emit summary evidence for domain parsing and feature extraction."""
        collector.emit(
            evidence_type="sender.domain_analysis",
            title="Sender domains analyzed",
            description=(
                "Parsed sender domains received deterministic feature extraction."
            ),
            severity=EvidenceSeverity.INFO,
            source="domain_feature_analyzer",
            metadata={"domain_count": len(domains)},
        )

    @staticmethod
    def _emit_display_name_evidence(
        collector: EvidenceCollector,
        display_name_available: bool,
    ) -> None:
        """Emit display-name analyzer summary evidence."""
        collector.emit(
            evidence_type="sender.display_name_analysis",
            title="Display name analyzed",
            description=(
                "Available sender display-name text received deterministic analysis."
            ),
            severity=EvidenceSeverity.INFO,
            source="display_name_analyzer",
            metadata={"display_name_available": display_name_available},
        )

    @staticmethod
    def _emit_consistency_evidence(
        collector: EvidenceCollector,
        mismatch_count: int,
    ) -> None:
        """Emit sender-header comparison summary evidence."""
        collector.emit(
            evidence_type="sender.header_consistency",
            title="Sender headers compared",
            description="Available sender-header values were compared structurally.",
            severity=EvidenceSeverity.INFO,
            source="sender_header_comparator",
            metadata={"mismatch_count": mismatch_count},
        )

    @staticmethod
    def _emit_authentication_evidence(
        collector: EvidenceCollector,
        authentication: AuthenticationAnalysisResult,
    ) -> None:
        """Emit authentication-header interpretation summary evidence."""
        collector.emit(
            evidence_type="sender.authentication_interpretation",
            title="Authentication headers interpreted",
            description="Available authentication header claims were normalized.",
            severity=EvidenceSeverity.INFO,
            source="authentication_header_interpreter",
            metadata={
                "spf_status": authentication.spf.status.value,
                "dkim_status": authentication.dkim.status.value,
                "dmarc_status": authentication.dmarc.status.value,
                "arc_status": authentication.arc.status.value,
            },
        )

    @staticmethod
    def _emit_relationship_evidence(
        collector: EvidenceCollector,
        node_count: int,
    ) -> None:
        """Emit sender relationship graph preparation summary evidence."""
        collector.emit(
            evidence_type="sender.relationship_graph",
            title="Sender relationship graph prepared",
            description="Graph-ready sender relationship records were created.",
            severity=EvidenceSeverity.INFO,
            source="sender_relationship_builder",
            metadata={"node_count": node_count},
        )
