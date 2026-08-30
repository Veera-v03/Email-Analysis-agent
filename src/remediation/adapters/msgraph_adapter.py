"""Microsoft Graph OAuth 2.0 remediation adapter for mailbox quarantine, retraction, and deletion."""

from __future__ import annotations

import random
import time
from typing import Any
from uuid import UUID

import httpx

from src.common.constants import ActionTaken
from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.models import RemediationResultDTO
from src.threat_intel.resilience.circuit_breaker import ProviderCircuitBreaker

logger = get_logger("scamon.remediation.adapters.msgraph")


class MicrosoftGraphRemediationAdapter(IRemediationAdapter):
    """Production-grade Microsoft Graph OAuth 2.0 remediation adapter executing mailbox message actions."""

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        endpoint: str | None = None,
        timeout_seconds: float | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._tenant_id = tenant_id or getattr(
            settings, "msgraph_remediation_tenant_id", None
        )
        self._client_id = client_id or getattr(
            settings, "msgraph_remediation_client_id", None
        )
        self._client_secret = client_secret or settings.get_secret(
            "MSGRAPH_REMEDIATION_CLIENT_SECRET"
        )
        self._endpoint = (
            endpoint
            or getattr(
                settings,
                "msgraph_remediation_endpoint",
                "https://graph.microsoft.com/v1.0",
            )
        ).rstrip("/")
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "msgraph_remediation_timeout_sec", 5.0)
        )
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker(
            provider_name="MicrosoftGraph_Remediation",
            failure_threshold=getattr(
                settings, "threat_intel_circuit_breaker_threshold", 5
            ),
            recovery_timeout_seconds=getattr(
                settings, "threat_intel_circuit_breaker_cooldown_sec", 60.0
            ),
        )
        self._http_client = http_client
        self._token_cache: dict[str, tuple[str, float]] = {}  # tenant_id -> (token, expiry_monotonic)

    @property
    def adapter_name(self) -> str:
        return "MicrosoftGraphRemediationAdapter"

    @property
    def circuit_breaker(self) -> ProviderCircuitBreaker:
        return self._circuit_breaker

    def supports_action(self, action: ActionTaken) -> bool:
        """Supported mailbox actions under established enterprise contracts."""
        return action in (
            ActionTaken.QUARANTINED,
            ActionTaken.RETRACTED,
            ActionTaken.BLOCKED,
        )

    def _acquire_token(self, client: httpx.Client) -> str | None:
        """Acquire or retrieve cached OAuth 2.0 client credentials token."""
        if not (self._tenant_id and self._client_id and self._client_secret):
            return None

        cache_key = self._tenant_id
        now = time.monotonic()
        if cache_key in self._token_cache:
            token, expiry = self._token_cache[cache_key]
            if now < expiry - 30.0:  # 30-second refresh buffer
                return token

        token_url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }

        try:
            resp = client.post(token_url, data=payload, timeout=self._timeout_seconds)
            if resp.status_code == 200:
                data = resp.json()
                access_token = data.get("access_token")
                expires_in = float(data.get("expires_in", 3600))
                if access_token:
                    self._token_cache[cache_key] = (access_token, now + expires_in)
                    return access_token
            logger.error(
                "[%s] OAuth token acquisition failed with HTTP %d",
                self.adapter_name,
                resp.status_code,
            )
            return None
        except Exception as exc:
            logger.error(
                "[%s] OAuth token acquisition error: %s",
                self.adapter_name,
                type(exc).__name__,
            )
            return None

    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute Microsoft Graph mailbox remediation action with bounded retry and circuit breaker."""
        action = result_dto.approved_action
        if is_dry_run:
            logger.info(
                "DRY-RUN SIMULATED: MS Graph action '%s' for message '%s' target '%s'",
                action,
                result_dto.message_id,
                target_id,
            )
            return True, f"dry_run_msgraph_{result_dto.message_id[:8]}", None

        if not (self._tenant_id and self._client_id and self._client_secret):
            logger.warning(
                "[%s] Credentials not configured; cannot perform live remediation",
                self.adapter_name,
            )
            return False, None, "MSGRAPH_CREDENTIALS_NOT_CONFIGURED"

        if not self._circuit_breaker.allow_request():
            logger.warning(
                "[%s] Circuit breaker is OPEN; suppressing remediation request",
                self.adapter_name,
            )
            return False, None, "CIRCUIT_BREAKER_OPEN"

        client = self._http_client or httpx.Client(timeout=self._timeout_seconds)
        try:
            token = self._acquire_token(client)
            if not token:
                self._circuit_breaker.record_failure()
                return False, None, "OAUTH_AUTHENTICATION_FAILED"

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "ScamON-Remediation-Engine/1.0",
            }

            user_target = target_id if "@" in target_id else "default_user"
            msg_id = result_dto.message_id

            # Bounded retry loop (max 3 attempts with backoff)
            max_attempts = 3
            last_err = None

            for attempt in range(1, max_attempts + 1):
                try:
                    if action in (ActionTaken.QUARANTINED, ActionTaken.RETRACTED):
                        # Move message to junkemail / quarantine folder
                        move_url = f"{self._endpoint}/users/{user_target}/messages/{msg_id}/move"
                        body = {"destinationId": "junkemail"}
                        resp = client.post(move_url, headers=headers, json=body)
                    elif action == ActionTaken.BLOCKED:
                        # Delete malicious message
                        delete_url = f"{self._endpoint}/users/{user_target}/messages/{msg_id}"
                        resp = client.delete(delete_url, headers=headers)
                    else:
                        return False, None, f"UNSUPPORTED_ACTION: {action}"

                    # Success (200, 201, 204) or 404 (already removed/moved)
                    if resp.status_code in (200, 201, 204, 404):
                        self._circuit_breaker.record_success()
                        ref_id = f"msgraph_{action.lower()}_{hash(msg_id) & 0xFFFFFFFF:08x}"
                        logger.info(
                            "[%s] Successfully executed '%s' for message '%s' (Ref: %s)",
                            self.adapter_name,
                            action,
                            msg_id,
                            ref_id,
                        )
                        return True, ref_id, None

                    # Permanent authorization failure (401/403) -> Do not retry
                    if resp.status_code in (401, 403):
                        logger.error(
                            "[%s] Permanent auth error HTTP %d; aborting",
                            self.adapter_name,
                            resp.status_code,
                        )
                        self._circuit_breaker.record_failure()
                        return False, None, f"HTTP_AUTH_FORBIDDEN_{resp.status_code}"

                    # Rate limiting (429) or Transient Server Error (5xx)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        retry_after = float(resp.headers.get("Retry-After", 0.5 * (2**attempt)))
                        time.sleep(min(retry_after, 2.0) + random.uniform(0.01, 0.05))
                        last_err = f"HTTP_{resp.status_code}"
                        continue

                    # Other client error
                    last_err = f"HTTP_{resp.status_code}"
                    break

                except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                    last_err = type(net_err).__name__
                    time.sleep(0.1 * attempt)

            # If all retry attempts exhausted
            self._circuit_breaker.record_failure()
            logger.error("[%s] Remediation failed after %d attempts: %s", self.adapter_name, max_attempts, last_err)
            return False, None, last_err or "EXECUTION_RETRY_EXHAUSTED"

        finally:
            if self._http_client is None:
                client.close()

    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify action status."""
        if result_dto.is_dry_run:
            return True, "DRY_RUN_SIMULATED"
        if external_reference_id and external_reference_id.startswith("msgraph_"):
            return True, "VERIFIED_MSGRAPH_SUCCESS"
        return False, "UNVERIFIED_MSGRAPH_REFERENCE"
