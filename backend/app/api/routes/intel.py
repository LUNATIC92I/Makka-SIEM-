"""Threat-intelligence views: indicators, observation history, map."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, can_access_investigation, require
from app.api.routes.investigations import visible_filter
from app.core.timeutil import iso
from app.models import EnrichmentResult, Indicator, Investigation, InvestigationIndicator, User
from app.schemas.serializers import result_out

router = APIRouter(tags=["threat-intel"])


@router.get("/indicators")
def list_indicators(db: Session = DbDep, user: User = Depends(require("investigations:read")),
                    type: str | None = Query(default=None, max_length=16), q: str | None = Query(default=None, max_length=200),
                    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200)) -> dict:
    visible_inv = select(Investigation.id).where(visible_filter(user))
    stmt = select(Indicator).where(Indicator.id.in_(
        select(InvestigationIndicator.indicator_id).where(InvestigationIndicator.investigation_id.in_(visible_inv))))
    if type:
        stmt = stmt.where(Indicator.type == type)
    if q:
        stmt = stmt.where(Indicator.value.ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.scalars(stmt.order_by(Indicator.last_seen.desc()).offset((page - 1) * page_size).limit(page_size)))
    ids = [r.id for r in rows]
    verdicts: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    counts: dict[int, int] = defaultdict(int)
    synth: dict[int, bool] = defaultdict(bool)
    if ids:
        for r in db.scalars(select(EnrichmentResult).where(EnrichmentResult.indicator_id.in_(ids),
                                                           EnrichmentResult.investigation_id.in_(visible_inv))):
            counts[r.indicator_id] += 1
            synth[r.indicator_id] |= r.is_synthetic
            v = ((r.findings or {}).get("reputation") or {}).get("verdict")
            if r.status == "ok" and v:
                verdicts[r.indicator_id][v] += 1
    inv_counts = dict(db.execute(select(InvestigationIndicator.indicator_id, func.count(func.distinct(InvestigationIndicator.investigation_id)))
                                 .where(InvestigationIndicator.indicator_id.in_(ids)).group_by(InvestigationIndicator.indicator_id)).all()) if ids else {}
    return {"total": total, "items": [{
        "id": r.id, "type": r.type, "value": r.value, "scope": r.scope, "first_seen": iso(r.first_seen),
        "last_seen": iso(r.last_seen), "results": counts[r.id], "verdicts": dict(verdicts[r.id]),
        "investigations": inv_counts.get(r.id, 0), "has_synthetic": synth[r.id],
    } for r in rows]}


@router.get("/indicators/{indicator_id}")
def indicator_detail(indicator_id: int, db: Session = DbDep, user: User = Depends(require("investigations:read"))) -> dict:
    ind = db.get(Indicator, indicator_id)
    if ind is None:
        raise HTTPException(404, "Indicateur introuvable")
    invs = [i for i in db.scalars(select(Investigation).join(InvestigationIndicator, InvestigationIndicator.investigation_id == Investigation.id)
                                  .where(InvestigationIndicator.indicator_id == ind.id).distinct())
            if can_access_investigation(db, user, i)]
    if not invs:
        raise HTTPException(404, "Indicateur introuvable")
    inv_ids = [i.id for i in invs]
    history = db.scalars(select(EnrichmentResult).where(EnrichmentResult.indicator_id == ind.id,
                                                        EnrichmentResult.investigation_id.in_(inv_ids))
                         .order_by(EnrichmentResult.queried_at.desc()).limit(500))
    return {"id": ind.id, "type": ind.type, "value": ind.value, "scope": ind.scope, "classification": ind.classification,
            "first_seen": iso(ind.first_seen), "last_seen": iso(ind.last_seen),
            "investigations": [{"id": i.id, "reference": i.reference, "title": i.title, "risk_level": i.risk_level} for i in invs],
            "history": [result_out(r) for r in history]}


@router.get("/map")
def map_points(db: Session = DbDep, user: User = Depends(require("investigations:read")),
               investigation_id: str | None = Query(default=None, max_length=36), limit: int = Query(default=500, le=2000)) -> dict:
    visible = select(Investigation.id).where(visible_filter(user))
    stmt = select(EnrichmentResult).where(EnrichmentResult.status == "ok", EnrichmentResult.superseded_at.is_(None),
                                          EnrichmentResult.investigation_id.in_(visible))
    if investigation_id:
        stmt = stmt.where(EnrichmentResult.investigation_id == investigation_id)
    points = []
    for r in db.scalars(stmt.order_by(EnrichmentResult.queried_at.desc()).limit(limit * 5)):
        geo = (r.findings or {}).get("geo") or {}
        if geo.get("latitude") is None or geo.get("longitude") is None:
            continue
        inv = db.get(Investigation, r.investigation_id)
        points.append({
            "indicator": r.indicator.value, "source": r.source_name, "latitude": geo["latitude"], "longitude": geo["longitude"],
            "accuracy_radius_km": geo.get("accuracy_radius_km"), "country": geo.get("country") or geo.get("country_code"),
            "city": geo.get("city"), "region": geo.get("region"), "precision_note": geo.get("precision_note"),
            "queried_at": iso(r.queried_at), "is_synthetic": r.is_synthetic, "investigation_id": r.investigation_id,
            "investigation_reference": inv.reference if inv else None, "risk_level": inv.risk_level if inv else None,
            "event_times": [iso(e.event_time) for e in inv.events] if inv else [],
            "targets": sorted({e.hostname or e.dst_ip for e in inv.events if e.hostname or e.dst_ip}) if inv else [],
        })
        if len(points) >= limit:
            break
    return {"points": points, "warning": "Emplacements ESTIMÉS à partir de bases de géolocalisation IP. Ils n'identifient ni une "
            "personne ni une position physique exacte ; VPN, proxys, réseaux mobiles, hébergements cloud et infrastructures "
            "compromises faussent l'interprétation."}
