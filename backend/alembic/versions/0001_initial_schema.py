"""initial schema

Creates the six core tables (users, log_sources, detection_rules, events,
alerts, ip_enrichment) and the four PostgreSQL enum types they depend on.
Hand-authored to mirror app/models exactly and validated by CI, which applies
it against a real PostgreSQL service before the tests run.

Revision ID: 0001
Revises:
Create Date: 2026-06-10
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Enum types are created explicitly (checkfirst=False renders cleanly with
# `alembic upgrade --sql`); the columns reference them with create_type=False
# so create_table never tries to recreate a type — important because `severity`
# is shared by both detection_rules and alerts.
role_enum = postgresql.ENUM("admin", "analyst", "viewer", name="role", create_type=False)
sourcetype_enum = postgresql.ENUM(
    "auth_log", "nginx", "apache", "suricata", "custom", name="sourcetype", create_type=False
)
severity_enum = postgresql.ENUM(
    "info", "low", "medium", "high", "critical", name="severity", create_type=False
)
alertstatus_enum = postgresql.ENUM(
    "open", "acknowledged", "resolved", "false_positive", name="alertstatus", create_type=False
)

_ALL_ENUMS = (role_enum, sourcetype_enum, severity_enum, alertstatus_enum)


def upgrade() -> None:
    bind = op.get_bind()
    for enum in _ALL_ENUMS:
        enum.create(bind, checkfirst=False)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", role_enum, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "log_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("type", sourcetype_enum, nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_log_sources_name", "log_sources", ["name"], unique=True)

    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_detection_rules_key", "detection_rules", ["key"], unique=True)

    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "source_id",
            sa.Integer(),
            sa.ForeignKey("log_sources.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("dest_ip", sa.String(45), nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index("ix_events_source_ip_timestamp", "events", ["source_ip", "timestamp"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "event_id", sa.Integer(), sa.ForeignKey("events.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column(
            "rule_id",
            sa.Integer(),
            sa.ForeignKey("detection_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("status", alertstatus_enum, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])

    op.create_table(
        "ip_enrichment",
        sa.Column("ip", sa.String(45), primary_key=True),
        sa.Column("country", sa.String(80), nullable=True),
        sa.Column("city", sa.String(120), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("abuse_score", sa.Integer(), nullable=True),
        sa.Column("is_tor", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("ip_enrichment")
    op.drop_table("alerts")
    op.drop_table("events")
    op.drop_table("detection_rules")
    op.drop_table("log_sources")
    op.drop_table("users")

    bind = op.get_bind()
    for enum in _ALL_ENUMS:
        enum.drop(bind, checkfirst=False)
