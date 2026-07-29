"""Optional presentation renderers for the stable FinalReport contract."""

from __future__ import annotations

import html
import json
from typing import Protocol

from src.planner.explainability import FinalReport


class ReportRenderer(Protocol):
    """Format-independent report presentation extension point."""

    def render(self, report: FinalReport) -> str | bytes:
        """Render a FinalReport without changing its canonical JSON structure."""


class JsonReportRenderer:
    def render(self, report: FinalReport) -> str:
        return report.model_dump_json(indent=2)


class MarkdownReportRenderer:
    def render(self, report: FinalReport) -> str:
        lines = [
            f"# Investigation: {report.classification}",
            "",
            report.executive_summary,
            "",
            f"- Priority: {report.recommended_priority}",
            f"- Risk score: {report.risk_score}/100",
            f"- Confidence: {report.confidence:.0%}",
            "",
            "## Score Breakdown",
        ]
        lines.extend(
            f"- +{item['points']}: {item['factor']} — {item['reason']}"
            for item in report.score_breakdown
        )
        lines.extend(["", "## Recommendations", report.recommendations])
        return "\n".join(lines)


class HtmlReportRenderer:
    def render(self, report: FinalReport) -> str:
        payload = html.escape(json.dumps(report.model_dump(), indent=2))
        return f"<html><body><pre>{payload}</pre></body></html>"
