"""Database repositories package for ScamON Enterprise."""

from __future__ import annotations

from src.database.legacy_repositories import (
    AnalyticsRepository,
    APIKeyRepository,
    AuditLogRepository,
    InvestigationMetadataRepository,
    LegacyUserRepository,
    OrganizationRepository,
    PlannerMetricsRepository,
)
from src.database.repositories.base import BaseRepository
from src.database.repositories.email_account_repository import EmailAccountRepository
from src.database.repositories.incident_repository import IncidentRepository
from src.database.repositories.mailbox_sync_repository import MailboxSyncStateRepository
from src.database.repositories.raw_email_repository import RawEmailRepository
from src.database.repositories.tenant_policy_repository import TenantPolicyRepository
from src.database.repositories.tenant_repository import TenantRepository
from src.database.repositories.user_repository import UserRepository

__all__ = [
    "APIKeyRepository",
    "AnalyticsRepository",
    "AuditLogRepository",
    "BaseRepository",
    "EmailAccountRepository",
    "IncidentRepository",
    "InvestigationMetadataRepository",
    "LegacyUserRepository",
    "MailboxSyncStateRepository",
    "OrganizationRepository",
    "PlannerMetricsRepository",
    "RawEmailRepository",
    "TenantPolicyRepository",
    "TenantRepository",
    "UserRepository",
]
