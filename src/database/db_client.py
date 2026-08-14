"""Database client handling SQLite connections, connection pools, and relational migrations."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.config.enterprise_config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


class DatabaseClient:
    """Manages raw SQLite database sessions, transactions, and structural table initialization."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.db_path
        self._initialize_db()

    def get_connection(self) -> sqlite3.Connection:
        """Open a new connection to the database file."""
        conn = sqlite3.connect(self.db_path)
        # Enable foreign key validation
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_db(self) -> None:
        """Create the database file and schema tables if they do not exist."""
        # Ensure directories exist
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        conn = self.get_connection()
        try:
            with conn:
                # 1. Organizations
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS organizations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL
                    );
                """)

                # 2. Users
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        roles TEXT NOT NULL, -- JSON list of roles
                        is_active INTEGER NOT NULL DEFAULT 1,
                        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                        lockout_until TEXT,
                        preferences TEXT, -- JSON preferences
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                    );
                """)

                # 3. API Keys
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        role TEXT NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                    );
                """)

                # 4. Audit Logs
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id TEXT PRIMARY KEY,
                        org_id TEXT,
                        user_id TEXT,
                        action TEXT NOT NULL,
                        details TEXT, -- JSON details
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                    );
                """)

                # 5. Investigation Metadata
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS investigations (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        email_id TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        risk_level TEXT NOT NULL,
                        duration_ms INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                    );
                """)

                # 6. Planner Metrics
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS planner_metrics (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        investigation_id TEXT NOT NULL,
                        strategy TEXT NOT NULL,
                        step_count INTEGER NOT NULL,
                        latency_ms INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                    );
                """)

                # 7. Analytics Cache
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS analytics (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                    );
                """)

                # Create indices for performance
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_investigations_org ON investigations(org_id);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_planner_metrics_org ON planner_metrics(org_id);"
                )

            logger.info(
                "SQLite database schema initialized successfully at %s", self.db_path
            )
        except Exception as e:
            logger.error("Failed to initialize database schema: %s", e)
            raise e
        finally:
            conn.close()

    def get_tenant_investigation_stats(
        self, tenant_id: str, time_window_hours: int = 24
    ) -> dict[str, Any]:
        """Query tenant-isolated investigation aggregate metrics from investigations table."""
        conn = self.get_connection()
        try:
            # Total analyzed
            row = conn.execute(
                "SELECT count(*) as total, avg(duration_ms) as avg_latency FROM investigations WHERE org_id = ?;",
                (tenant_id,),
            ).fetchone()
            total_analyzed = row["total"] if row and row["total"] else 0
            avg_latency = (
                float(row["avg_latency"])
                if row and row["avg_latency"] is not None
                else 0.0
            )

            # Verdict breakdown
            verdict_rows = conn.execute(
                "SELECT verdict, count(*) as cnt FROM investigations WHERE org_id = ? GROUP BY verdict;",
                (tenant_id,),
            ).fetchall()
            verdict_breakdown = {r["verdict"]: r["cnt"] for r in verdict_rows}

            # Total threats
            threats_row = conn.execute(
                "SELECT count(*) as cnt FROM investigations WHERE org_id = ? AND verdict IN ('MALICIOUS', 'SUSPICIOUS');",
                (tenant_id,),
            ).fetchone()
            total_threats = threats_row["cnt"] if threats_row else 0

            # Top threat senders
            sender_rows = conn.execute(
                """
                SELECT sender, count(*) as cnt 
                FROM investigations 
                WHERE org_id = ? AND verdict IN ('MALICIOUS', 'SUSPICIOUS')
                GROUP BY sender 
                ORDER BY cnt DESC 
                LIMIT 5;
                """,
                (tenant_id,),
            ).fetchall()
            top_senders = [
                {"sender": r["sender"], "count": r["cnt"]} for r in sender_rows
            ]

            return {
                "total_emails_analyzed": total_analyzed,
                "total_threats_detected": total_threats,
                "threat_breakdown_by_verdict": verdict_breakdown,
                "top_threat_senders": top_senders,
                "average_investigation_latency_ms": avg_latency,
            }
        finally:
            conn.close()

    def get_tenant_remediation_stats(
        self, tenant_id: str, time_window_hours: int = 24
    ) -> dict[str, int]:
        """Query tenant-isolated remediation action statistics from audit_logs details JSON."""
        conn = self.get_connection()
        try:
            rows = conn.execute(
                "SELECT details FROM audit_logs WHERE org_id = ? AND action LIKE 'REMEDIATION_%';",
                (tenant_id,),
            ).fetchall()

            remediation_counts: dict[str, int] = {}
            for r in rows:
                if not r["details"]:
                    continue
                try:
                    payload = json.loads(r["details"])
                    action = payload.get("approved_action", "UNKNOWN")
                    remediation_counts[action] = remediation_counts.get(action, 0) + 1
                except Exception:
                    continue

            return remediation_counts
        finally:
            conn.close()


# Global central database client
db_client = DatabaseClient()
