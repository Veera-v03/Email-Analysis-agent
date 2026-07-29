"""Campaign correlation engine querying historical runs to group coordinated phishing indicators."""

from __future__ import annotations

from typing import Any

from src.database.db_client import DatabaseClient, db_client


class CampaignCorrelationEngine:
    """Correlates multiple investigations using SQLite to track coordinated security threats."""

    def __init__(self, client: DatabaseClient | None = None) -> None:
        self._db = client or db_client

    def correlate_investigation(
        self,
        org_id: str,
        sender: str,
        subject: str,
        extracted_iocs: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Correlate active email markers against historical organization runs.

        Detects matches for:
          - Identical sender addresses.
          - Visually matched subject headers (templates).
          - Matching malicious URLs / domains.
          - Coordinated campaigns.
        """
        conn = self._db.get_connection()
        try:
            correlated_runs = []
            matching_reasons = []

            # 1. Check identical senders
            sender_rows = conn.execute(
                "SELECT id, subject, created_at FROM investigations WHERE org_id = ? AND sender = ? LIMIT 10;",
                (org_id, sender),
            ).fetchall()

            if sender_rows:
                matching_reasons.append("sender_match")
                for r in sender_rows:
                    correlated_runs.append(
                        {
                            "investigation_id": r["id"],
                            "match_type": "sender",
                            "subject": r["subject"],
                            "created_at": r["created_at"],
                        }
                    )

            # 2. Check visually similar templates (Subject matches)
            subject_clean = subject.strip().lower()
            subject_rows = conn.execute(
                "SELECT id, sender, created_at FROM investigations WHERE org_id = ? AND LOWER(subject) = ? LIMIT 10;",
                (org_id, subject_clean),
            ).fetchall()

            if subject_rows:
                matching_reasons.append("template_subject_match")
                for r in subject_rows:
                    correlated_runs.append(
                        {
                            "investigation_id": r["id"],
                            "match_type": "subject_template",
                            "sender": r["sender"],
                            "created_at": r["created_at"],
                        }
                    )

            # 3. Check for matching URLs in threat intel
            for url in extracted_iocs.get("urls", []):
                # Search database investigations containing visual indicators
                url_clean = f"%{url}%"
                url_rows = conn.execute(
                    """
                    SELECT id, sender, subject, created_at 
                    FROM investigations 
                    WHERE org_id = ? AND (subject LIKE ? OR sender LIKE ?) 
                    LIMIT 5;
                    """,
                    (org_id, url_clean, url_clean),
                ).fetchall()
                if url_rows:
                    matching_reasons.append("infrastructure_match")
                    for r in url_rows:
                        correlated_runs.append(
                            {
                                "investigation_id": r["id"],
                                "match_type": "url_indicator",
                                "created_at": r["created_at"],
                            }
                        )

            # Calculate campaign score based on correlation triggers (scale 0.0 to 10.0)
            campaign_score = 0.0
            if "sender_match" in matching_reasons:
                campaign_score += 4.0
            if "template_subject_match" in matching_reasons:
                campaign_score += 3.0
            if "infrastructure_match" in matching_reasons:
                campaign_score += 3.0

            # Limit campaign score ceiling to 10.0
            campaign_score = min(campaign_score, 10.0)

            return {
                "campaign_detected": len(correlated_runs) > 1,
                "campaign_score": campaign_score,
                "indicators_matched": list(set(matching_reasons)),
                "correlated_investigations": correlated_runs[:10],
            }
        finally:
            conn.close()
