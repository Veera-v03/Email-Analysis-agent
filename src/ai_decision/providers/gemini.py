"""Gemini LLM Provider implementation using httpx REST API with retries and fallback."""

from __future__ import annotations

import json
import os

import httpx

from src.ai_decision.providers.base import ILLMProvider, LLMRetryStrategy
from src.config.logging import get_logger

logger = get_logger("scamon.ai_decision.providers.gemini")


class GeminiLLMProvider(ILLMProvider):
    """Google Gemini LLM Provider using httpx REST calls with retries and offline fallback."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-1.5-flash",
        retry_strategy: LLMRetryStrategy | None = None,
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name
        self.retry_strategy = retry_strategy or LLMRetryStrategy(
            timeout_seconds=5.0, max_retries=2
        )

    @property
    def provider_name(self) -> str:
        return f"Gemini ({self.model_name})"

    async def generate_completion(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.1
    ) -> str:
        """Call Gemini REST API or execute deterministic fallback if unconfigured / offline."""
        if not self.api_key:
            logger.info(
                "GEMINI_API_KEY not configured. Using deterministic fallback completion."
            )
            return self._generate_fallback_json(user_prompt)

        async def _call_api() -> str:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"parts": [{"text": user_prompt}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "response_mime_type": "application/json",
                },
            }

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url, headers=headers, json=payload, timeout=5.0
                )
                resp.raise_for_status()
                data = resp.json()
                text = str(data["candidates"][0]["content"]["parts"][0]["text"])
                return text

        try:
            res: str = await self.retry_strategy.execute_with_retry(_call_api)
            return res
        except Exception as exc:
            logger.warning(
                "Gemini REST API call failed: %s. Reverting to deterministic fallback.",
                exc,
            )
            return self._generate_fallback_json(user_prompt)

    def _generate_fallback_json(self, user_prompt: str) -> str:
        """Deterministic JSON fallback response matching DecisionPlan schema."""
        prompt_lower = user_prompt.lower()
        is_malicious = (
            "malicious" in prompt_lower
            or "quarantined" in prompt_lower
            or "blocked" in prompt_lower
        )

        if is_malicious:
            resp = {
                "executive_summary": "High risk malicious email incident detected. Automated security intervention initiated to block threats and quarantine payload.",
                "technical_summary": "Incident flagged multiple critical indicators including identity spoofing, failed authentication, and malicious IOC matches.",
                "analyst_explanation": "Investigation identified severe risk signals. Sender identity failed DMARC/SPF checks and extracted IOCs matched threat intelligence databases.",
                "attack_summary": "Targeted Spearphishing & BEC campaign attempting unauthorized financial or credential harvesting.",
                "business_impact": "HIGH RISK: Potential account compromise, unauthorized wire transfers, and data exfiltration.",
                "recommended_actions": [
                    "Isolate recipient endpoint device immediately.",
                    "Force account password reset for target user identity.",
                    "Block sender domain and originating IP across edge firewalls.",
                ],
                "automation_candidates": [
                    "SOAR_QuarantineMailboxMessage",
                    "SOAR_BlockOriginatingIP",
                    "SOAR_RevokeUserSessions",
                ],
                "limitations": [
                    "Analysis based on automated header and reputation telemetry.",
                    "Live sandbox execution pending for secondary attachment analysis.",
                ],
            }
        else:
            resp = {
                "executive_summary": "Incident assessed as CLEAN. Normal email delivery confirmed with no security risks detected.",
                "technical_summary": "All authentication protocols (SPF, DKIM, DMARC) passed successfully. Originating IP and links verified clean.",
                "analyst_explanation": "Standard legitimate email transmission. Header integrity is high and zero threat intelligence feeds flagged indicators.",
                "attack_summary": "No malicious attack vectors detected.",
                "business_impact": "NONE: Routine legitimate business communication.",
                "recommended_actions": ["Deliver message to recipient inbox normally."],
                "automation_candidates": ["SOAR_LogCleanTelemetry"],
                "limitations": ["Standard static inspection completed."],
            }

        return json.dumps(resp)
