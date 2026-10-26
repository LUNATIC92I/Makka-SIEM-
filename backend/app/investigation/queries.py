"""Shared query helpers."""

from __future__ import annotations

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models import EnrichmentResult


def current_results_stmt(investigation_id: str) -> Select:
    """Enrichment results of the latest run (earlier runs are kept as history)."""
    return (select(EnrichmentResult)
            .where(EnrichmentResult.investigation_id == investigation_id, EnrichmentResult.superseded_at.is_(None))
            .order_by(EnrichmentResult.id))


def current_results(db: Session, investigation_id: str) -> list[EnrichmentResult]:
    return list(db.scalars(current_results_stmt(investigation_id)))
