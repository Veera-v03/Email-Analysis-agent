"""Multi-layered prompt-injection detection engine neutralizing adversarial inputs in retrieved memory."""

from __future__ import annotations

import re
from typing import ClassVar

from src.config.logging import get_logger

logger = get_logger("scamon.memory.rag.prompt_guard")


class PromptGuard:
    """Detects instruction-override, prompt extraction, tool-hijacking, and jailbreak patterns."""

    INJECTION_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "OVERRIDE_PREVIOUS_INSTRUCTIONS": re.compile(
            r"(?i)\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|system|above|prior)\s+(?:instructions|prompts|directives|rules)\b"
        ),
        "SYSTEM_PROMPT_OVERRIDE": re.compile(
            r"(?i)\b(?:override|overwrite|replace)\s+(?:the\s+)?(?:system|developer|agent)\s+(?:prompt|instructions|persona)\b"
        ),
        "SYSTEM_PROMPT_EXTRACTION": re.compile(
            r"(?i)\b(?:reveal|print|disclose|show|output|leak|repeat)\s+(?:the\s+)?(?:system\s+prompt|developer\s+instructions|hidden\s+prompt|system\s+instructions|api\s+keys?|passwords?|secrets?)\b"
        ),
        "CONTROL_ROLE_INJECTION": re.compile(
            r"(?i)\b(?:system|developer|assistant|human|user)\s*:\s*(?:you\s+are\s+now|new\s+instructions|ignore|execute)\b"
        ),
        "TOOL_EXECUTION_HIJACK": re.compile(
            r"(?i)\b(?:execute\s+(?:this\s+)?command|call\s+(?:the\s+)?tool|run\s+terminal\s+command|remediate\s+immediately)\b"
        ),
        "JAILBREAK_ATTEMPT": re.compile(
            r"(?i)\b(?:jailbreak|dan\s+mode|developer\s+mode\s+enabled|always\s+say\s+yes|sudo\s+mode|unrestricted\s+mode)\b"
        ),
        "DELIMITER_ESCAPING": re.compile(
            r"(?i)<\/?(?:system|instruction|developer|historical_retrieved_incidents|retrieved_incident)[^>]*>"
        ),
    }

    @classmethod
    def inspect_text(cls, text: str) -> tuple[bool, list[str]]:
        """Inspect text for prompt-injection markers. Returns (is_injection_detected, matched_rule_names)."""
        if not text:
            return False, []

        matched_rules: list[str] = []
        for rule_name, pattern in cls.INJECTION_PATTERNS.items():
            if pattern.search(text):
                matched_rules.append(rule_name)

        if matched_rules:
            logger.warning(
                "Prompt injection pattern(s) detected in retrieved text: %s",
                ", ".join(matched_rules),
            )
            return True, matched_rules

        return False, []
