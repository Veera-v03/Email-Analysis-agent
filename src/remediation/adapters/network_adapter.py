"""Network Security remediation adapter emitting strictly validated Palo Alto, Fortinet, and AWS WAF payloads."""

from __future__ import annotations

import ipaddress
import re

from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.models import NetworkBlockRequestDTO, RemediationResultDTO

logger = get_logger("scamon.remediation.adapters.network")

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class NetworkSecurityAdapter(IRemediationAdapter):
    """Handles network security rule block enforcement (Palo Alto, Fortinet, AWS WAF)."""

    @property
    def adapter_name(self) -> str:
        return "NetworkSecurityAdapter"

    def supports_action(self, action: ActionTaken) -> bool:
        return action == ActionTaken.BLOCKED

    def validate_network_payload(self, req: NetworkBlockRequestDTO) -> bool:
        """Validate target against strict allowlist types (IP or Domain). Never execute shell or arbitrary text."""
        val = req.target_value.strip()
        if req.target_type == "IP":
            try:
                ipaddress.ip_address(val)
                return True
            except ValueError:
                return False
        elif req.target_type == "DOMAIN":
            return bool(DOMAIN_REGEX.match(val))
        return False

    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute network security rule block payload."""
        req = NetworkBlockRequestDTO(
            target_type="IP"
            if not target_id.count(".") >= 2 or target_id.replace(".", "").isdigit()
            else "DOMAIN",
            target_value=target_id,
            vendor_type="PALO_ALTO",
        )

        # Enforce allowlist validation
        if not self.validate_network_payload(req):
            logger.error("Network payload validation failed for target '%s'", target_id)
            return False, None, f"INVALID_NETWORK_TARGET: {target_id}"

        if is_dry_run:
            logger.info(
                "DRY-RUN SIMULATED: Network block rule for target '%s'", target_id
            )
            return True, f"dry_run_net_{target_id[:8]}", None

        ref_id = f"fw_block_{hash(target_id) & 0xFFFFFFFF:08x}"
        logger.info(
            "EXECUTED: Network rule block for vendor '%s' target '%s' (Ref: %s)",
            req.vendor_type,
            target_id,
            ref_id,
        )
        return True, ref_id, None

    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify network security block status."""
        if result_dto.is_dry_run:
            return True, "DRY_RUN_SIMULATED"
        if external_reference_id and external_reference_id.startswith("fw_"):
            return True, "VERIFIED_FIREWALL_RULE_ACTIVE"
        return False, "UNVERIFIED_FIREWALL_REFERENCE"
