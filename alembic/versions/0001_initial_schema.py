"""Initial enterprise database schema with PostgreSQL RLS support.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-04 12:00:00.000000

"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Tenants Table
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_name", sa.String(length=255), nullable=False),
        sa.Column("domain_name", sa.String(length=255), nullable=False),
        sa.Column(
            "subscription_tier",
            sa.String(length=50),
            nullable=False,
            server_default="ENTERPRISE",
        ),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="ACTIVE"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
    )
    op.create_index(
        op.f("ix_tenants_domain_name"), "tenants", ["domain_name"], unique=True
    )
    op.create_index(op.f("ix_tenants_status"), "tenants", ["status"], unique=False)

    # 2. Users Table
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column(
            "role", sa.String(length=50), nullable=False, server_default="ANALYST"
        ),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="ACTIVE"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_users_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=False)
    op.create_index(op.f("ix_users_tenant_id"), "users", ["tenant_id"], unique=False)

    # 3. Tenant Policies Table
    op.create_table(
        "tenant_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("policy_name", sa.String(length=255), nullable=False),
        sa.Column("policy_value", sa.String(length=1024), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_tenant_policies_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenant_policies")),
    )
    op.create_index(
        op.f("ix_tenant_policies_policy_name"),
        "tenant_policies",
        ["policy_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tenant_policies_tenant_id"),
        "tenant_policies",
        ["tenant_id"],
        unique=False,
    )

    # 4. Incidents Table
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.String(length=255), nullable=False),
        sa.Column("internet_message_id", sa.String(length=512), nullable=False),
        sa.Column("sender_address", sa.String(length=320), nullable=False),
        sa.Column("recipient_address", sa.String(length=320), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="INGESTED"
        ),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "verdict", sa.String(length=50), nullable=False, server_default="CLEAN"
        ),
        sa.Column("threat_category", sa.String(length=100), nullable=True),
        sa.Column(
            "action_taken",
            sa.String(length=50),
            nullable=False,
            server_default="DELIVERED",
        ),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_incidents_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
    )
    op.create_index(
        op.f("ix_incidents_tenant_id"), "incidents", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_message_id"), "incidents", ["message_id"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_internet_message_id"),
        "incidents",
        ["internet_message_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_sender_address"),
        "incidents",
        ["sender_address"],
        unique=False,
    )
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_index(
        op.f("ix_incidents_risk_score"), "incidents", ["risk_score"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_verdict"), "incidents", ["verdict"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_received_at"), "incidents", ["received_at"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_is_deleted"), "incidents", ["is_deleted"], unique=False
    )

    # 5. Enable PostgreSQL Row-Level Security (RLS)
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;")


def downgrade() -> None:
    # 1. Disable RLS
    op.execute("ALTER TABLE incidents DISABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenant_policies DISABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE users DISABLE ROW LEVEL SECURITY;")

    # 2. Drop Tables
    op.drop_table("incidents")
    op.drop_table("tenant_policies")
    op.drop_table("users")
    op.drop_table("tenants")
