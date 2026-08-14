"""DOM Analyzer inspecting HTML DOM structural anomalies using html_normalizer."""

from __future__ import annotations

from src.content_intelligence.models import DOMContentSignalsDTO
from src.parsing.body.html_normalizer import extract_dom_signals
from src.parsing.models import ParsedEmail


class DOMAnalyzer:
    """Surfaces DOM structural anomalies (hidden CSS text, form action URLs, scripts, hex obfuscations)."""

    def analyze_dom(self, parsed: ParsedEmail) -> DOMContentSignalsDTO:
        """Extract DOM signals from ParsedEmail.body_html."""
        raw_signals = extract_dom_signals(parsed.body_html)

        return DOMContentSignalsDTO(
            has_hidden_text=raw_signals.get("has_hidden_text", False),
            hidden_text_snippets=raw_signals.get("hidden_text_snippets", []),
            external_form_actions=raw_signals.get("external_form_actions", []),
            script_tag_count=raw_signals.get("script_tag_count", 0),
            html_entity_obfuscation_count=raw_signals.get(
                "html_entity_obfuscation_count", 0
            ),
        )
