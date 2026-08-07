"""Email Ingestion platform tables with PostgreSQL RLS support.

Revision ID: 0002_email_ingestion_schema
Revises: 0001_initial_schema
Create Date: 2026-08-07 10:00:00.000000

"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa

from alembic import op

revision: str = "0002_email_ingestion_schema"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Email Accounts Table
    op.create_table(
        "email_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "provider", sa.String(length=50), nullable=False, server_default="GMAIL"
        ),
        sa.Column("email_address", sa.String(length=255), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_email_accounts_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_accounts")),
        sa.UniqueConstraint(
            "tenant_id", "email_address", name="uq_email_accounts_tenant_email"
        ),
    )
    op.create_index(
        op.f("ix_email_accounts_tenant_id"),
        "email_accounts",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_accounts_provider"), "email_accounts", ["provider"], unique=False
    )
    op.create_index(
        op.f("ix_email_accounts_email_address"),
        "email_accounts",
        ["email_address"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_accounts_is_active"),
        "email_accounts",
        ["is_active"],
        unique=False,
    )

    # 2. Mailbox Sync States Table
    op.create_table(
        "mailbox_sync_states",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("last_history_id", sa.String(length=255), nullable=True),
        sa.Column("last_sync_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="IDLE"
        ),
        sa.Column("watch_expiration", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["email_accounts.id"],
            name=op.f("fk_mailbox_sync_states_account_id_email_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_mailbox_sync_states_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mailbox_sync_states")),
    )
    op.create_index(
        op.f("ix_mailbox_sync_states_account_id"),
        "mailbox_sync_states",
        ["account_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_mailbox_sync_states_tenant_id"),
        "mailbox_sync_states",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_mailbox_sync_states_status"),
        "mailbox_sync_states",
        ["status"],
        unique=False,
    )

    # 3. Raw Emails Table
    op.create_table(
        "raw_emails",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.String(length=255), nullable=False),
        sa.Column("internet_message_id", sa.String(length=512), nullable=False),
        sa.Column("raw_eml_data", sa.LargeBinary(), nullable=False),
        sa.Column("raw_size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["email_accounts.id"],
            name=op.f("fk_raw_emails_account_id_email_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_raw_emails_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_emails")),
    )
    op.create_index(
        op.f("ix_raw_emails_account_id"), "raw_emails", ["account_id"], unique=False
    )
    op.create_index(
        op.f("ix_raw_emails_tenant_id"), "raw_emails", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_raw_emails_message_id"), "raw_emails", ["message_id"], unique=False
    )
    op.create_index(
        op.f("ix_raw_emails_internet_message_id"),
        "raw_emails",
        ["internet_message_id"],
        unique=False,
    )

    # 4. Email Metadata Records Table
    op.create_table(
        "email_metadata_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("raw_email_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.String(length=255), nullable=False),
        sa.Column("internet_message_id", sa.String(length=512), nullable=False),
        sa.Column("sender_address", sa.String(length=320), nullable=False),
        sa.Column(
            "recipient_addresses", sa.Text(), nullable=False, server_default="[]"
        ),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "has_attachments", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column("attachment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["email_accounts.id"],
            name=op.f("fk_email_metadata_records_account_id_email_accounts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_email_id"],
            ["raw_emails.id"],
            name=op.f("fk_email_metadata_records_raw_email_id_raw_emails"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_email_metadata_records_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_metadata_records")),
    )
    op.create_index(
        op.f("ix_email_metadata_records_account_id"),
        "email_metadata_records",
        ["account_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_metadata_records_tenant_id"),
        "email_metadata_records",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_metadata_records_raw_email_id"),
        "email_metadata_records",
        ["raw_email_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_metadata_records_message_id"),
        "email_metadata_records",
        ["message_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_metadata_records_sender_address"),
        "email_metadata_records",
        ["sender_address"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_metadata_records_received_at"),
        "email_metadata_records",
        ["received_at"],
        unique=False,
    )

    # 5. Enable RLS
    op.execute("ALTER TABLE email_accounts ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE mailbox_sync_states ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE raw_emails ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE email_metadata_records ENABLE ROW LEVEL SECURITY;")


def downgrade() -> None:
    op.execute("ALTER TABLE email_metadata_records DISABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE raw_emails DISABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE mailbox_sync_states DISABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE email_accounts DISABLE ROW LEVEL SECURITY;")

    op.drop_table("email_metadata_records")
    op.drop_table("raw_emails")
    op.drop_table("mailbox_sync_states")
    op.drop_table("email_accounts")
