"""Database module exposing raw client connection utilities and typed repositories."""

from src.database.db_client import DatabaseClient, db_client
from src.database.repositories import (
    AnalyticsRepository,
    APIKeyRepository,
    AuditLogRepository,
    InvestigationMetadataRepository,
    OrganizationRepository,
    PlannerMetricsRepository,
    UserRepository,
)

__all__ = [
    "DatabaseClient",
    "db_client",
    "OrganizationRepository",
    "UserRepository",
    "APIKeyRepository",
    "AuditLogRepository",
    "InvestigationMetadataRepository",
    "PlannerMetricsRepository",
    "AnalyticsRepository",
]
