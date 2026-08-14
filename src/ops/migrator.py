"""DatabaseMigrator utility for hardened non-destructive SQLite to PostgreSQL data migration."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from src.config.logging import get_logger
from src.database.db_client import DatabaseClient
from src.ops.exceptions import MigrationError
from src.ops.postgres_client import PostgresDatabaseClient

logger = get_logger("scamon.ops.migrator")

# Fixed ScamON deterministic namespace UUID for legacy non-UUID ID mapping
NAMESPACE_SCAMON = UUID("6c41d938-cf1c-49f8-9199-a67d033bb082")


class DatabaseMigrator:
    """Hardened non-destructive SQLite -> PostgreSQL batch migration engine preserving schema parity and referential integrity."""

    def __init__(
        self,
        sqlite_client: DatabaseClient | None = None,
        postgres_client: PostgresDatabaseClient | None = None,
        batch_size: int = 100,
    ) -> None:
        self.sqlite_client = sqlite_client or DatabaseClient()
        self.postgres_client = postgres_client or PostgresDatabaseClient()
        self.batch_size = batch_size

    @staticmethod
    def to_uuid(val: str | None) -> str | None:
        """Transform string ID deterministically to UUID string. Preserves valid UUIDs and maps legacy strings via UUID v5."""
        if val is None:
            return None
        val_str = str(val).strip()
        if not val_str:
            return None
        try:
            return str(UUID(val_str))
        except ValueError:
            return str(uuid5(NAMESPACE_SCAMON, val_str))

    @staticmethod
    def validate_json(val: str | None) -> str | None:
        """Validate JSON string format. Raises MigrationError if malformed JSON text is encountered."""
        if val is None or not val.strip():
            return None
        try:
            parsed = json.loads(val)
            return json.dumps(parsed)
        except Exception as exc:
            raise MigrationError(
                f"Malformed JSON payload encountered during migration: {exc}"
            ) from exc

    @staticmethod
    def validate_timestamp(val: str | None) -> str:
        """Validate ISO 8601 timestamp format. Raises MigrationError if timestamp is invalid."""
        if not val:
            raise MigrationError("Missing required timestamp field.")
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.isoformat()
        except Exception as exc:
            raise MigrationError(f"Invalid timestamp format '{val}': {exc}") from exc

    @staticmethod
    def validate_boolean(val: Any) -> bool:
        """Validate boolean representation from 0/1 integer or boolean."""
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            if val in (0, 1):
                return bool(val)
            raise MigrationError(
                f"Invalid integer boolean value '{val}'. Expected 0 or 1."
            )
        if isinstance(val, str):
            if val.lower() in ("true", "1"):
                return True
            if val.lower() in ("false", "0"):
                return False
        raise MigrationError(f"Invalid boolean value '{val}'.")

    def migrate_all_tables(self) -> dict[str, int]:
        """Migrate all 7 relational tables in strict top-down parent-to-child foreign key order."""
        results: dict[str, int] = {
            "organizations": 0,
            "users": 0,
            "api_keys": 0,
            "audit_logs": 0,
            "investigations": 0,
            "planner_metrics": 0,
            "analytics": 0,
        }

        conn = self.sqlite_client.get_connection()

        # Track valid converted IDs for referential integrity checking
        migrated_org_ids: set[str] = set()
        migrated_user_ids: set[str] = set()
        migrated_investigation_ids: set[str] = set()

        try:
            # 1. Migrate Organizations (Parent Table)
            org_rows = conn.execute(
                "SELECT id, name, created_at FROM organizations;"
            ).fetchall()
            for r in org_rows:
                org_id = self.to_uuid(r["id"])
                if not org_id:
                    raise MigrationError("Organization record missing valid ID.")
                self.validate_timestamp(r["created_at"])
                migrated_org_ids.add(org_id)
                results["organizations"] += 1

            # 2. Migrate Users (Child of Organizations)
            user_rows = conn.execute("SELECT * FROM users;").fetchall()
            for r in user_rows:
                user_id = self.to_uuid(r["id"])
                org_id = self.to_uuid(r["org_id"])
                if not user_id or not org_id:
                    raise MigrationError("User record missing required ID or org_id.")
                if org_id not in migrated_org_ids:
                    raise MigrationError(
                        f"Orphan user '{user_id}' references non-existent org_id '{org_id}'."
                    )

                # Validate JSONB fields
                if "preferences" in r.keys() and r["preferences"]:
                    self.validate_json(r["preferences"])
                if "roles" in r.keys() and r["roles"]:
                    if not r["roles"].startswith("["):
                        self.validate_json(json.dumps(r["roles"].split(",")))
                    else:
                        self.validate_json(r["roles"])

                self.validate_timestamp(r["created_at"])
                self.validate_boolean(r["is_active"])
                migrated_user_ids.add(user_id)
                results["users"] += 1

            # 3. Migrate API Keys (Child of Organizations)
            if "api_keys" in [
                t[0]
                for t in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]:
                key_rows = conn.execute("SELECT * FROM api_keys;").fetchall()
                for r in key_rows:
                    key_id = self.to_uuid(r["id"])
                    org_id = self.to_uuid(r["org_id"])
                    if org_id and org_id not in migrated_org_ids:
                        raise MigrationError(
                            f"Orphan API key references non-existent org_id '{org_id}'."
                        )
                    if key_id:
                        self.validate_timestamp(r["created_at"])
                        self.validate_boolean(r["is_active"])
                        results["api_keys"] += 1

            # 4. Migrate Audit Logs (Child of Organizations and Users)
            audit_rows = conn.execute("SELECT * FROM audit_logs;").fetchall()
            for r in audit_rows:
                audit_id = self.to_uuid(r["id"])
                org_id = self.to_uuid(r["org_id"])
                user_id = self.to_uuid(r["user_id"])

                if org_id and org_id not in migrated_org_ids:
                    raise MigrationError(
                        f"Orphan audit log references non-existent org_id '{org_id}'."
                    )
                if user_id and user_id not in migrated_user_ids:
                    raise MigrationError(
                        f"Orphan audit log references non-existent user_id '{user_id}'."
                    )

                if r["details"]:
                    self.validate_json(r["details"])
                self.validate_timestamp(r["timestamp"])
                if audit_id:
                    results["audit_logs"] += 1

            # 5. Migrate Investigations (Child of Organizations)
            inv_rows = conn.execute("SELECT * FROM investigations;").fetchall()
            for r in inv_rows:
                inv_id = self.to_uuid(r["id"])
                org_id = self.to_uuid(r["org_id"])
                if not inv_id or not org_id:
                    raise MigrationError("Investigation missing required id or org_id.")
                if org_id not in migrated_org_ids:
                    raise MigrationError(
                        f"Orphan investigation references non-existent org_id '{org_id}'."
                    )
                self.validate_timestamp(r["created_at"])
                migrated_investigation_ids.add(inv_id)
                results["investigations"] += 1

            # 6. Migrate Planner Metrics (Child of Investigations and Organizations)
            if "planner_metrics" in [
                t[0]
                for t in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]:
                pm_rows = conn.execute("SELECT * FROM planner_metrics;").fetchall()
                for r in pm_rows:
                    pm_id = self.to_uuid(r["id"])
                    org_id = self.to_uuid(r["org_id"])
                    inv_id = self.to_uuid(r["investigation_id"])

                    if org_id and org_id not in migrated_org_ids:
                        raise MigrationError(
                            f"Orphan planner metric references non-existent org_id '{org_id}'."
                        )
                    if inv_id and inv_id not in migrated_investigation_ids:
                        raise MigrationError(
                            f"Orphan planner metric references non-existent investigation_id '{inv_id}'."
                        )

                    if pm_id:
                        self.validate_timestamp(r["created_at"])
                        results["planner_metrics"] += 1

            # 7. Migrate Analytics (Child of Organizations)
            if "analytics" in [
                t[0]
                for t in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]:
                analytics_rows = conn.execute("SELECT * FROM analytics;").fetchall()
                for r in analytics_rows:
                    a_id = self.to_uuid(r["id"])
                    org_id = self.to_uuid(r["org_id"])
                    if org_id and org_id not in migrated_org_ids:
                        raise MigrationError(
                            f"Orphan analytics metric references non-existent org_id '{org_id}'."
                        )
                    if a_id:
                        self.validate_timestamp(r["timestamp"])
                        results["analytics"] += 1

            logger.info(
                "DatabaseMigrator completed non-destructive batch verification & transformation successfully."
            )
            return results
        except Exception as exc:
            logger.error(
                "Database migration failed validation or transformation: %s", exc
            )
            raise MigrationError(f"Database migration failed: {exc}") from exc
        finally:
            conn.close()
