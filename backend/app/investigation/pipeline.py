"""Investigation pipeline and task handlers.

run_investigation: enrichment (all active OSINT sources, concurrently, bounded)
-> correlation -> scoring -> AI analysis -> status. Each step is persisted and
audited so the investigation can be reconstructed afterwards.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.ai.service import run_analysis
from app.connectors.osint.base import OsintProvider, ProviderResult
from app.connectors.osint.registry import active_providers
from app.connectors.siem.base import ConnectorContext
from app.connectors.siem.connectors import SIEM_CONNECTORS
from app.core.config import get_settings
from app.core.errors import ConnectorError
from app.core.logging import get_logger
from app.core.timeutil import utc_now
from app.investigation.correlation import correlate
from app.investigation.queries import current_results
from app.models import (
    ConnectorConfig, EnrichmentResult, Indicator, IndicatorRelation, IngestionCheckpoint, Investigation,
    InvestigationIndicator, Task,
)
from app.scoring.engine import compute
from app.security.secrets_vault import decrypt_secrets
from app.services import audit
from app.services.app_settings import get_setting
from app.services.ingestion import ingest_events
from app.services.notifications import maybe_notify
from app.services.tasks import enqueue, handler

log = get_logger("makkadi.pipeline")
GLOBAL_CONCURRENCY = 8
PER_PROVIDER_CONCURRENCY = 2


async def enrich(providers: list[OsintProvider], indicators: list[Indicator]) -> list[tuple[Indicator, ProviderResult]]:
    sem = asyncio.Semaphore(GLOBAL_CONCURRENCY)
    per: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(PER_PROVIDER_CONCURRENCY))

    async def one(p: OsintProvider, ind: Indicator) -> tuple[Indicator, ProviderResult]:
        async with sem, per[p.name]:
            return ind, await p.lookup(ind.type, ind.value)

    jobs = [one(p, ind) for ind in indicators for p in providers if ind.type in p.supported_types]
    return list(await asyncio.gather(*jobs))


async def run_investigation(db: Session, investigation_id: str, *, actor: str = "system",
                            user_id: int | None = None, with_ai: bool = True) -> dict[str, Any]:
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise ConnectorError("Investigation introuvable")
    inv.pipeline_status = "running"
    db.commit()
    links = list(db.scalars(select(InvestigationIndicator).where(InvestigationIndicator.investigation_id == inv.id)))
    enrichable = {link.indicator_id: link.indicator for link in links if link.indicator.scope == "public"}
    providers = active_providers(db)

    # 1. enrichment, previous results are kept as history (superseded), relations are rebuilt
    pairs = await enrich(providers, list(enrichable.values()))
    run_number = (inv.enrichment_runs or 0) + 1
    db.execute(delete(IndicatorRelation).where(IndicatorRelation.investigation_id == inv.id))
    db.execute(update(EnrichmentResult)
               .where(EnrichmentResult.investigation_id == inv.id, EnrichmentResult.superseded_at.is_(None))
               .values(superseded_at=utc_now()))
    inv.enrichment_runs = run_number
    for ind, res in pairs:
        db.add(EnrichmentResult(
            investigation_id=inv.id, indicator_id=ind.id, source_name=res.source_name, status=res.status,
            queried_at=res.queried_at, data_updated_at=res.data_updated_at, duration_ms=res.duration_ms,
            findings=res.findings.model_dump(mode="json", exclude_none=True), raw=res.raw, raw_sha256=res.raw_sha256,
            reference_url=res.reference_url, source_confidence=res.source_confidence, error_message=res.error_message,
            access_notes=res.access_notes, is_synthetic=res.is_synthetic, run_number=run_number,
        ))
    db.flush()
    results = current_results(db, inv.id)

    # 2. correlation
    scoring_cfg = get_setting(db, "scoring")
    corr = correlate(list(inv.events), links, results, scoring_cfg["stale_after_days"])
    for r in corr.relations:
        db.add(IndicatorRelation(investigation_id=inv.id, **r.__dict__))
    inv.correlation = corr.summary()

    # 3. scoring
    assert corr.scoring_input is not None
    scoring = compute(corr.scoring_input, scoring_cfg, get_setting(db, "assets"))
    inv.scoring = scoring
    inv.risk_score, inv.risk_level = scoring["risk_score"], scoring["risk_level"]
    inv.confidence_score, inv.confidence_level = scoring["confidence_score"], scoring["confidence_level"]
    errors = len(corr.collection_errors)
    inv.pipeline_status = "partial" if errors else "completed"
    maybe_notify(db, inv)
    inv.updated_at = utc_now()
    db.flush()
    audit.record(db, "investigation.enriched", actor=actor, actor_user_id=user_id, target_type="investigation", target_id=inv.id,
                 details={"providers": sorted({p.name for p in providers}), "indicators": len(enrichable),
                          "results": len(results), "errors": errors, "risk": scoring["risk_score"],
                          "confidence": scoring["confidence_score"]})

    # 4. AI analysis (failures do not invalidate the enrichment)
    ai_status = None
    if with_ai:
        analysis = await run_analysis(db, inv, user_id=user_id, actor=actor)
        ai_status = analysis.status
    db.commit()
    return {"results": len(results), "errors": errors, "risk": scoring["risk_score"], "ai": ai_status}


@handler("run_investigation")
async def _h_run_investigation(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    return await run_investigation(db, payload["investigation_id"])


# --------------------------------------------------------------------------- SIEM polling


def build_siem_connector(row: ConnectorConfig):  # noqa: ANN201
    cls = SIEM_CONNECTORS.get(row.provider)
    if cls is None:
        raise ConnectorError(f"Connecteur SIEM inconnu : {row.provider}")
    return cls(ConnectorContext(name=row.name, settings=row.settings or {}, secrets=decrypt_secrets(row.secret_ciphertext)))


async def poll_connector(db: Session, connector_id: int) -> dict[str, Any]:
    row = db.get(ConnectorConfig, connector_id)
    if row is None or row.kind != "siem" or not row.enabled:
        return {"skipped": True}
    connector = build_siem_connector(row)
    checkpoint = db.get(IngestionCheckpoint, row.id) or IngestionCheckpoint(connector_id=row.id, cursor=None)
    limit = int(get_setting(db, "ingestion").get("max_events_per_poll", 200))
    row.last_run_at = utc_now()
    total = {"created": 0, "duplicates": 0, "pages": 0, "warnings": []}
    try:
        for _page in range(10):  # bounded catch-up per run
            result = await connector.fetch(checkpoint.cursor, limit)
            stats = ingest_events(db, result.events, method="poll", connector_id=row.id)
            # cursor advanced only once events are persisted (same transaction)
            checkpoint.cursor = result.next_cursor
            db.merge(checkpoint)
            db.commit()
            total["created"] += stats.created
            total["duplicates"] += stats.duplicates
            total["pages"] += 1
            total["warnings"].extend(result.warnings)
            if not result.has_more or not result.events:
                break
        row.last_status, row.last_error, row.last_success_at = "ok", None, utc_now()
    except ConnectorError as exc:
        db.rollback()
        row = db.get(ConnectorConfig, connector_id)
        row.last_status, row.last_error, row.last_run_at = "error", str(exc), utc_now()
        db.commit()
        raise
    db.commit()
    return total


@handler("poll_siem")
async def _h_poll(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    return await poll_connector(db, int(payload["connector_id"]))


def schedule_due_polls(db: Session) -> int:
    """Enqueue a poll for each enabled SIEM connector whose interval has elapsed."""
    now = utc_now()
    n = 0
    for row in db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "siem", ConnectorConfig.enabled.is_(True))):
        if row.provider not in SIEM_CONNECTORS:
            continue
        due = row.last_run_at is None or now - row.last_run_at >= timedelta(seconds=max(30, row.poll_interval_seconds))
        if not due:
            continue
        busy = db.scalars(select(Task.id).where(Task.dedup_key == f"poll:{row.id}", Task.status.in_(("pending", "running")))).first()
        if busy:
            continue
        enqueue(db, "poll_siem", {"connector_id": row.id}, dedup_key=f"poll:{row.id}", max_attempts=3)
        n += 1
    db.commit()
    return n


async def scheduler_loop(session_factory, stop: asyncio.Event) -> None:  # noqa: ANN001
    tick = get_settings().scheduler_tick_seconds
    last_retention = None
    while not stop.is_set():
        try:
            with session_factory() as db:
                schedule_due_polls(db)
                if last_retention is None or utc_now() - last_retention > timedelta(hours=24):
                    enqueue(db, "retention_purge", {}, dedup_key="retention")
                    db.commit()
                    last_retention = utc_now()
        except Exception:  # noqa: BLE001
            log.exception("scheduler error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=tick)
        except TimeoutError:
            pass
