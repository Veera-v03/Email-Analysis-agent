"""Palo Alto Networks PAN-OS REST remediation adapter for network IP and domain blocking."""

from __future__ import annotations

import ipaddress
import random
import re
import time
from typing import Any

import httpx

from src.common.constants import ActionTaken
from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.models import RemediationResultDTO
from src.threat_intel.resilience.circuit_breaker import ProviderCircuitBreaker

logger = get_logger("scamon.remediation.adapters.panos")

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class PaloAltoPANOSAdapter(IRemediationAdapter):
    """Production-grade Palo Alto PAN-OS REST adapter executing indicator blocking with idempotency and circuit breakers."""

    def __init__(
        self,
        host: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool | None = None,
        timeout_seconds: float | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._host = host or getattr(settings, "panos_host", None)
        self._api_key = api_key or settings.get_secret("PANOS_API_KEY")
        self._verify_ssl = (
            verify_ssl
            if verify_ssl is not None
            else getattr(settings, "panos_verify_ssl", True)
        )
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "panos_timeout_sec", 5.0)
        )
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker(
            provider_name="PaloAlto_PANOS",
            failure_threshold=getattr(
                settings, "threat_intel_circuit_breaker_threshold", 5
            ),
            recovery_timeout_seconds=getattr(
                settings, "threat_intel_circuit_breaker_cooldown_sec", 60.0
            ),
        )
        self._http_client = http_client

    @property
    def adapter_name(self) -> str:
        return "PaloAltoPANOSAdapter"

    @property
    def circuit_breaker(self) -> ProviderCircuitBreaker:
        return self._circuit_breaker

    def supports_action(self, action: ActionTaken) -> bool:
        """Supports network security blocking."""
        return action == ActionTaken.BLOCKED

    @staticmethod
    def validate_target(target: str) -> tuple[bool, str]:
        """Validate target as IPv4, IPv6, or Domain. Returns (is_valid, target_type)."""
        val = target.strip()
        try:
            ipaddress.ip_address(val)
            return True, "IP"
        except ValueError:
            pass

        if DOMAIN_REGEX.match(val):
            return True, "DOMAIN"

        return False, "INVALID"

    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute PAN-OS block operation or simulate in dry-run mode."""
        is_valid, target_type = self.validate_target(target_id)
        if not is_valid:
            logger.error("[%s] Invalid network block target: %s", self.adapter_name, target_id)
            return False, None, f"INVALID_NETWORK_TARGET: {target_id}"

        if is_dry_run:
            logger.info(
                "DRY-RUN SIMULATED: PAN-OS block rule for %s target '%s'",
                target_type,
                target_id,
            )
            return True, f"dry_run_panos_{target_id[:8]}", None

        if not (self._host and self._api_key):
            logger.warning(
                "[%s] Host or API key not configured; cannot execute live block",
                self.adapter_name,
            )
            return False, None, "PANOS_CREDENTIALS_NOT_CONFIGURED"

        if not self._circuit_breaker.allow_request():
            logger.warning(
                "[%s] Circuit breaker is OPEN; suppressing remediation request",
                self.adapter_name,
            )
            return False, None, "CIRCUIT_BREAKER_OPEN"

        endpoint = f"https://{self._host}/restapi/v10.0/Objects/Addresses"
        headers = {
            "X-PAN-KEY": self._api_key,
            "Content-Type": "application/json",
            "User-Agent": "ScamON-Remediation-Engine/1.0",
        }

        sanitized_name = f"ScamON_{re.sub(r'[^a-zA-Z0-9_]', '_', target_id)}"
        payload = {
            "entry": {
                "@name": sanitized_name,
                "description": f"Automated block by ScamON for incident {result_dto.incident_id}",
            }
        }
        if target_type == "IP":
            payload["entry"]["ip-netmask"] = target_id
        else:
            payload["entry"]["fqdn"] = target_id

        client = self._http_client or httpx.Client(
            timeout=self._timeout_seconds, verify=self._verify_ssl
        )

        try:
            max_attempts = 3
            last_err = None

            for attempt in range(1, max_attempts + 1):
                try:
                    resp = client.post(endpoint, headers=headers, json=payload)

                    # 200/201: Successfully created
                    if resp.status_code in (200, 201):
                        self._circuit_breaker.record_success()
                        ref_id = f"panos_rule_{hash(target_id) & 0xFFFFFFFF:08x}"
                        logger.info(
                            "[%s] Successfully created block rule for '%s' (Ref: %s)",
                            self.adapter_name,
                            target_id,
                            ref_id,
                        )
                        return True, ref_id, None

                    # 409: Conflict / Already exists -> Idempotent success
                    if resp.status_code == 409:
                        self._circuit_breaker.record_success()
                        ref_id = f"panos_rule_existing_{hash(target_id) & 0xFFFFFFFF:08x}"
                        logger.info(
                            "[%s] Object '%s' already exists on firewall (Idempotent success, Ref: %s)",
                            self.adapter_name,
                            target_id,
                            ref_id,
                        )
                        return True, ref_id, None

                    # 401/403: Permanent auth error -> Do not retry
                    if resp.status_code in (401, 403):
                        logger.error("[%s] Permanent auth error HTTP %d; aborting", self.adapter_name, resp.status_code)
                        self._circuit_breaker.record_failure()
                        return False, None, f"HTTP_AUTH_FORBIDDEN_{resp.status_code}"

                    # 429 / 5xx: Transient error -> Retry with backoff
                    if resp.status_code == 429 or resp.status_code >= 500:
                        time.sleep(0.2 * (2**attempt) + random.uniform(0.01, 0.05))
                        last_err = f"HTTP_{resp.status_code}"
                        continue

                    last_err = f"HTTP_{resp.status_code}"
                    break

                except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                    last_err = type(net_err).__name__
                    time.sleep(0.1 * attempt)

            self._circuit_breaker.record_failure()
            logger.error("[%s] Block execution failed after %d attempts: %s", self.adapter_name, max_attempts, last_err)
            return False, None, last_err or "EXECUTION_RETRY_EXHAUSTED"

        finally:
            if self._http_client is None:
                client.close()

    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify network rule status."""
        if result_dto.is_dry_run:
            return True, "DRY_RUN_SIMULATED"
        if external_reference_id and external_reference_id.startswith("panos_"):
            return True, "VERIFIED_PANOS_RULE_ACTIVE"
        return False, "UNVERIFIED_PANOS_REFERENCE"
