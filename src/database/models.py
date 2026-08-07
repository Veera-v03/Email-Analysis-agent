"""SQLAlchemy 2.x enterprise ORM model definitions matching SAS v1.1.0."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.base import (
    Base,
    SoftDeleteMixin,
    TenantIsolationMixin,
    TimestampMixin,
)


class Tenant(Base, TimestampMixin):
    """Master Organization / Tenant entity."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    org_name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain_name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    subscription_tier: Mapped[str] = mapped_column(
        String(50), nullable=False, default="ENTERPRISE"
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="ACTIVE", index=True
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User", back_populates="tenant", cascade="all, delete-orphan"
    )
    policies: Mapped[list[TenantPolicy]] = relationship(
        "TenantPolicy", back_populates="tenant", cascade="all, delete-orphan"
    )
    incidents: Mapped[list[Incident]] = relationship(
        "Incident", back_populates="tenant", cascade="all, delete-orphan"
    )


class User(Base, TimestampMixin, TenantIsolationMixin):
    """User account entity within an enterprise tenant."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="ANALYST")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="ACTIVE")

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="users")


class TenantPolicy(Base, TenantIsolationMixin):
    """Per-tenant security policy and risk threshold rule configuration."""

    __tablename__ = "tenant_policies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="policies")


class Incident(Base, TimestampMixin, SoftDeleteMixin, TenantIsolationMixin):
    """Master Security Incident record for processed emails."""

    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    internet_message_id: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )
    sender_address: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    recipient_address: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="INGESTED", index=True
    )
    risk_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )
    verdict: Mapped[str] = mapped_column(
        String(50), nullable=False, default="CLEAN", index=True
    )
    threat_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    action_taken: Mapped[str] = mapped_column(
        String(50), nullable=False, default="DELIVERED"
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="incidents")
