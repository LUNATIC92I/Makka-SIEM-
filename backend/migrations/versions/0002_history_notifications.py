"""Enrichment history and notification channels

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-26
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

import app.database.base

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enrichment_results") as batch:
        batch.add_column(sa.Column("run_number", sa.Integer(), server_default="1", nullable=False))
        batch.add_column(sa.Column("superseded_at", app.database.base.UTCDateTime(timezone=True), nullable=True))
        batch.create_index("ix_enrichment_results_superseded_at", ["superseded_at"])
    with op.batch_alter_table("investigations") as batch:
        batch.add_column(sa.Column("enrichment_runs", sa.Integer(), server_default="0", nullable=False))
        batch.add_column(sa.Column("notified_risk_level", sa.String(length=16), nullable=True))
    with op.batch_alter_table("connector_configs") as batch:
        batch.drop_constraint(op.f("ck_connector_configs_kind"), type_="check")
        batch.create_check_constraint(op.f("ck_connector_configs_kind"), "kind IN ('siem','osint','ai','notification')")
    # Existing results belong to the first run of their investigation.
    op.execute("UPDATE investigations SET enrichment_runs = 1 WHERE id IN (SELECT DISTINCT investigation_id FROM enrichment_results)")


def downgrade() -> None:
    op.execute("DELETE FROM connector_configs WHERE kind = 'notification'")
    op.execute("DELETE FROM enrichment_results WHERE superseded_at IS NOT NULL")
    with op.batch_alter_table("connector_configs") as batch:
        batch.drop_constraint(op.f("ck_connector_configs_kind"), type_="check")
        batch.create_check_constraint(op.f("ck_connector_configs_kind"), "kind IN ('siem','osint','ai')")
    with op.batch_alter_table("investigations") as batch:
        batch.drop_column("notified_risk_level")
        batch.drop_column("enrichment_runs")
    with op.batch_alter_table("enrichment_results") as batch:
        batch.drop_index("ix_enrichment_results_superseded_at")
        batch.drop_column("superseded_at")
        batch.drop_column("run_number")
