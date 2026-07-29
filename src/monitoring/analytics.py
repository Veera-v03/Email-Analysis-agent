"""Analytics engine querying relational SQLite metadata to aggregate operational insights."""

from __future__ import annotations

from typing import Any

from src.database.db_client import db_client


class AnalyticsEngine:
    """Aggregates and compiles analytics reports from historical database records."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def get_organization_dashboard(self, org_id: str) -> dict[str, Any]:
        """Aggregate all metrics for a given organization."""
        conn = self._db.get_connection()
        try:
            # 1. Total Investigations
            total_row = conn.execute(
                "SELECT COUNT(*) as count, AVG(duration_ms) as avg_duration FROM investigations WHERE org_id = ?;",
                (org_id,),
            ).fetchone()
            total_count = total_row["count"] if total_row else 0
            avg_duration = (
                round(total_row["avg_duration"], 1)
                if total_row and total_row["avg_duration"]
                else 0.0
            )

            # 2. Risk Distribution
            risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) as count FROM investigations WHERE org_id = ? GROUP BY risk_level;",
                (org_id,),
            ).fetchall()
            risk_distribution = {row["risk_level"]: row["count"] for row in risk_rows}

            # 3. Verdict Breakdown
            verdict_rows = conn.execute(
                "SELECT verdict, COUNT(*) as count FROM investigations WHERE org_id = ? GROUP BY verdict;",
                (org_id,),
            ).fetchall()
            verdict_distribution = {
                row["verdict"]: row["count"] for row in verdict_rows
            }

            # 4. Top Sender Domains
            sender_rows = conn.execute(
                "SELECT sender, COUNT(*) as count FROM investigations WHERE org_id = ? GROUP BY sender ORDER BY count DESC LIMIT 5;",
                (org_id,),
            ).fetchall()
            top_senders = [{row["sender"]: row["count"]} for row in sender_rows]

            # 5. Planner Latency Analytics
            planner_row = conn.execute(
                "SELECT AVG(latency_ms) as avg_lat, AVG(step_count) as avg_steps FROM planner_metrics WHERE org_id = ?;",
                (org_id,),
            ).fetchone()
            avg_planner_latency = (
                round(planner_row["avg_lat"], 1)
                if planner_row and planner_row["avg_lat"]
                else 0.0
            )
            avg_planner_steps = (
                round(planner_row["avg_steps"], 1)
                if planner_row and planner_row["avg_steps"]
                else 0.0
            )

            # 6. Daily Investigations Activity
            daily_rows = conn.execute(
                """
                SELECT strftime('%Y-%m-%d', created_at) as date, COUNT(*) as count 
                FROM investigations 
                WHERE org_id = ? 
                GROUP BY date 
                ORDER BY date DESC 
                LIMIT 7;
                """,
                (org_id,),
            ).fetchall()
            daily_activity = {row["date"]: row["count"] for row in daily_rows}

            return {
                "total_investigations": total_count,
                "average_execution_time_ms": avg_duration,
                "risk_level_distribution": risk_distribution,
                "verdict_distribution": verdict_distribution,
                "top_sender_domains": top_senders,
                "average_planner_latency_ms": avg_planner_latency,
                "average_planner_steps": avg_planner_steps,
                "daily_activity_last_7_days": daily_activity,
            }
        finally:
            conn.close()
