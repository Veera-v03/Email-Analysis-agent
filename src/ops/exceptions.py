"""Ops module domain exceptions for ScamON Enterprise Module 18."""

from __future__ import annotations


class OpsError(Exception):
    """Base exception for all Module 18 Ops and Infrastructure errors."""

    pass


class InfrastructureError(OpsError):
    """Raised when underlying database, Redis, or telemetry infrastructure fails."""

    pass


class ConnectorError(OpsError):
    """Raised when external production remediation connectors (Graph, Okta, PAN-OS) encounter API errors."""

    pass


class MigrationError(OpsError):
    """Raised when SQLite to PostgreSQL database migration encounters schema or data transfer errors."""

    pass
