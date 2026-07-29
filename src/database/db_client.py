"""Database client handling SQLite connections, connection pools, and relational migrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

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


# Global central database client
db_client = DatabaseClient()
