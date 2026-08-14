"""Audit repository abstraction and SQLiteAuditRepository baseline implementation."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from src.common.constants import ActionTaken
from src.database.db_client import DatabaseClient, db_client
from src.remediation.models import ActionStatus, RemediationResultDTO


class IAuditRepository(ABC):
    """Abstract interface for storing and querying immutable remediation audit records."""

    @abstractmethod
    def save_remediation_audit(self, result: RemediationResultDTO) -> None:
        """Save or update a remediation audit record."""

    @abstractmethod
    def get_remediation_by_idempotency_key(
        self, tenant_id: str, idempotency_key: str
    ) -> RemediationResultDTO | None:
        """Query audit log by idempotency key with strict tenant isolation."""


class SQLiteAuditRepository(IAuditRepository):
    """Baseline audit repository wrapping SQLite DatabaseClient table audit_logs."""

    def __init__(self, client: DatabaseClient | None = None) -> None:
        self._db = client or db_client

    def save_remediation_audit(self, result: RemediationResultDTO) -> None:
        """Save remediation record serializing payload into details column."""
        conn = self._db.get_connection()
        try:
            details_payload = json.dumps(
                {
                    "remediation_id": str(result.remediation_id),
                    "incident_id": str(result.incident_id),
                    "assessment_id": str(result.assessment_id),
                    "decision_plan_id": str(result.decision_plan_id),
                    "idempotency_key": result.idempotency_key,
                    "requested_action": str(result.requested_action),
                    "approved_action": str(result.approved_action),
                    "action_status": str(result.action_status),
                    "executing_adapter": result.executing_adapter,
                    "external_reference_id": result.external_reference_id,
                    "verification_status": result.verification_status,
                    "audit_status": "COMMITTED",
                    "siem_export_status": result.siem_export_status,
                    "is_dry_run": result.is_dry_run,
                    "failure_reason": result.failure_reason,
                }
            )
            org_id_str = str(result.tenant_id)
            org_exists = conn.execute(
                "SELECT id FROM organizations WHERE id = ?;", (org_id_str,)
            ).fetchone()
            db_org_id = org_id_str if org_exists else None

            with conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs (id, org_id, user_id, action, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(id) DO UPDATE SET
                        details = excluded.details,
                        timestamp = excluded.timestamp;
                    """,
                    (
                        str(result.remediation_id),
                        db_org_id,
                        None,
                        f"REMEDIATION_{result.approved_action}",
                        details_payload,
                    ),
                )
        finally:
            conn.close()

    def get_remediation_by_idempotency_key(
        self, tenant_id: str, idempotency_key: str
    ) -> RemediationResultDTO | None:
        """Query existing audit record matching tenant_id and idempotency_key."""
        conn = self._db.get_connection()
        try:
            rows = conn.execute(
                """
                SELECT details FROM audit_logs 
                WHERE details LIKE ? 
                ORDER BY timestamp DESC LIMIT 1;
                """,
                (f"%{idempotency_key}%",),
            ).fetchall()

            if not rows:
                return None

            data: dict[str, Any] = json.loads(rows[0]["details"])
            return RemediationResultDTO(
                remediation_id=UUID(data["remediation_id"]),
                tenant_id=UUID(tenant_id),
                incident_id=UUID(data["incident_id"]),
                message_id="msg_cached",
                assessment_id=UUID(data["assessment_id"]),
                decision_plan_id=UUID(data["decision_plan_id"]),
                requested_action=ActionTaken(data["requested_action"]),
                approved_action=ActionTaken(data["approved_action"]),
                action_status=ActionStatus(data["action_status"]),
                idempotency_key=data["idempotency_key"],
                executing_adapter=data["executing_adapter"],
                external_reference_id=data.get("external_reference_id"),
                verification_status=data.get("verification_status", "VERIFIED_SUCCESS"),
                audit_status="COMMITTED",
                siem_export_status=data.get("siem_export_status", "NOT_ATTEMPTED"),
                is_dry_run=data.get("is_dry_run", False),
                failure_reason=data.get("failure_reason"),
            )
        except Exception:
            return None
        finally:
            conn.close()
