"""Relational database repositories implementing CRUD operations for enterprise entities."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from src.database.db_client import db_client


class OrganizationRepository:
    """Handles persistence operations for tenant Organizations."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def create(self, name: str, org_id: str | None = None) -> dict[str, Any]:
        """Insert a new organization record."""
        oid = org_id or f"org_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?);",
                    (oid, name, now),
                )
            return {"id": oid, "name": name, "created_at": now}
        finally:
            conn.close()

    def get(self, org_id: str) -> dict[str, Any] | None:
        """Fetch organization details by ID."""
        conn = self._db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM organizations WHERE id = ?;", (org_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_all(self) -> list[dict[str, Any]]:
        """List all registered organizations."""
        conn = self._db.get_connection()
        try:
            rows = conn.execute("SELECT * FROM organizations;").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


class UserRepository:
    """Handles CRUD persistence operations for User credentials and role settings."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def create(
        self,
        org_id: str,
        username: str,
        password_hash: str,
        roles: list[str],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new user record."""
        uid = user_id or f"user_{uuid.uuid4().hex[:12]}"
        roles_json = json.dumps(roles)
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO users (id, org_id, username, password_hash, roles, is_active, failed_login_attempts, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, 0, ?);
                    """,
                    (uid, org_id, username, password_hash, roles_json, now),
                )
            return {
                "id": uid,
                "org_id": org_id,
                "username": username,
                "roles": roles,
                "is_active": True,
                "created_at": now,
            }
        finally:
            conn.close()

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        """Fetch user record including password hash by username."""
        conn = self._db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?;", (username,)
            ).fetchone()
            if not row:
                return None
            res = dict(row)
            res["roles"] = json.loads(res["roles"])
            res["is_active"] = bool(res["is_active"])
            return res
        finally:
            conn.close()

    def get(self, user_id: str) -> dict[str, Any] | None:
        """Fetch user details by ID."""
        conn = self._db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?;", (user_id,)
            ).fetchone()
            if not row:
                return None
            res = dict(row)
            res["roles"] = json.loads(res["roles"])
            res["is_active"] = bool(res["is_active"])
            return res
        finally:
            conn.close()

    def update(self, user_id: str, updates: dict[str, Any]) -> bool:
        """Update a user's attributes (e.g. preferences, is_active, failed login counts)."""
        if not updates:
            return False

        # Prepare queries dynamically
        fields = []
        params = []
        for k, v in updates.items():
            fields.append(f"{k} = ?")
            if k in ("roles", "preferences") and isinstance(v, (list, dict)):
                params.append(json.dumps(v))
            else:
                params.append(v)

        params.append(user_id)
        query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?;"

        conn = self._db.get_connection()
        try:
            with conn:
                cursor = conn.execute(query, tuple(params))
                return cursor.rowcount > 0
        finally:
            conn.close()

    def delete(self, user_id: str) -> bool:
        """Permanently delete a user record by ID."""
        conn = self._db.get_connection()
        try:
            with conn:
                cursor = conn.execute("DELETE FROM users WHERE id = ?;", (user_id,))
                return cursor.rowcount > 0
        finally:
            conn.close()


class APIKeyRepository:
    """Handles CRUD persistence operations for API Key verification."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def create(
        self,
        org_id: str,
        name: str,
        key_hash: str,
        role: str = "api_client",
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new API Key record."""
        kid = key_id or f"key_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO api_keys (id, org_id, name, key_hash, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?);
                    """,
                    (kid, org_id, name, key_hash, role, now),
                )
            return {
                "id": kid,
                "org_id": org_id,
                "name": name,
                "role": role,
                "is_active": True,
                "created_at": now,
            }
        finally:
            conn.close()

    def get_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        """Fetch key details by key hash (for fast auth checks)."""
        conn = self._db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1;",
                (key_hash,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def deactivate(self, key_id: str) -> bool:
        """Disable API key."""
        conn = self._db.get_connection()
        try:
            with conn:
                cursor = conn.execute(
                    "UPDATE api_keys SET is_active = 0 WHERE id = ?;", (key_id,)
                )
                return cursor.rowcount > 0
        finally:
            conn.close()


class AuditLogRepository:
    """Handles append-only persistent logging for SOC audit trails."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def log(
        self,
        org_id: str | None,
        user_id: str | None,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Insert an audit log entry."""
        lid = f"log_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()
        details_str = json.dumps(details) if details else None

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs (id, org_id, user_id, action, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (lid, org_id, user_id, action, details_str, now),
                )
        finally:
            conn.close()

    def get_by_org(self, org_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """List audit logs for a specific organization."""
        conn = self._db.get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?;",
                (org_id, limit),
            ).fetchall()
            logs = []
            for r in rows:
                log_item = dict(r)
                log_item["details"] = (
                    json.loads(log_item["details"]) if log_item["details"] else None
                )
                logs.append(log_item)
            return logs
        finally:
            conn.close()


class InvestigationMetadataRepository:
    """Handles persistence of investigation runs."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def save(
        self,
        org_id: str,
        email_id: str,
        subject: str,
        sender: str,
        verdict: str,
        confidence: float,
        risk_level: str,
        duration_ms: int,
        investigation_id: str | None = None,
    ) -> dict[str, Any]:
        """Save new investigation metadata."""
        iid = investigation_id or f"inv_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO investigations (id, org_id, email_id, subject, sender, verdict, confidence, risk_level, duration_ms, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        iid,
                        org_id,
                        email_id,
                        subject,
                        sender,
                        verdict,
                        confidence,
                        risk_level,
                        duration_ms,
                        now,
                    ),
                )
            return {
                "id": iid,
                "org_id": org_id,
                "email_id": email_id,
                "subject": subject,
                "sender": sender,
                "verdict": verdict,
                "confidence": confidence,
                "risk_level": risk_level,
                "duration_ms": duration_ms,
                "created_at": now,
            }
        finally:
            conn.close()

    def get(self, investigation_id: str) -> dict[str, Any] | None:
        """Fetch investigation metadata by ID."""
        conn = self._db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?;", (investigation_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_history(self, org_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """List historical runs for an organization."""
        conn = self._db.get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM investigations WHERE org_id = ? ORDER BY created_at DESC LIMIT ?;",
                (org_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


class PlannerMetricsRepository:
    """Handles persistence of planner engine metrics."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def save(
        self,
        org_id: str,
        investigation_id: str,
        strategy: str,
        step_count: int,
        latency_ms: int,
    ) -> None:
        """Save planner metrics."""
        mid = f"metric_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO planner_metrics (id, org_id, investigation_id, strategy, step_count, latency_ms, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        mid,
                        org_id,
                        investigation_id,
                        strategy,
                        step_count,
                        latency_ms,
                        now,
                    ),
                )
        finally:
            conn.close()


class AnalyticsRepository:
    """Caches aggregated dashboard stats to optimize analytical query speed."""

    def __init__(self, client=None) -> None:
        self._db = client or db_client

    def cache_metric(self, org_id: str, name: str, value: float) -> None:
        """Save a cached metric value."""
        aid = f"anal_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO analytics (id, org_id, metric_name, metric_value, timestamp) VALUES (?, ?, ?, ?, ?);",
                    (aid, org_id, name, value, now),
                )
        finally:
            conn.close()
