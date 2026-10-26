from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from app.ai.service import run_analysis
from app.api.deps import DbDep, client_ip, has_perm, load_investigation, require
from app.core.errors import ConnectorError, ValidationFailed
from app.core.timeutil import iso, utc_now
from app.investigation.pipeline import run_investigation
from app.investigation.queries import current_results_stmt
from app.models import (
    AIAnalysis, EnrichmentResult, Indicator, IndicatorRelation, Investigation, InvestigationAssignee, InvestigationEvent,
    InvestigationIndicator, InvestigationNote, Report, SiemEvent, User,
)
from app.reporting.builder import build_timeline
from app.reporting.service import generate_report
from app.schemas.serializers import (
    analysis_out, event_out, investigation_summary, link_out, note_out, relation_out, report_out, result_out,
)
from app.services import audit
from app.services.indicators import validate_indicator
from app.services.ingestion import _upsert_indicator
from app.services.tasks import enqueue

router = APIRouter(prefix="/investigations", tags=["investigations"])
Status = Literal["new", "in_progress", "pending_review", "closed_true_positive", "closed_false_positive", "closed_benign"]


def visible_filter(user: User):  # noqa: ANN201
    if has_perm(user, "investigations:restricted"):
        return True
    assigned = exists().where(InvestigationAssignee.investigation_id == Investigation.id, InvestigationAssignee.user_id == user.id)
    return or_(Investigation.restricted.is_(False), Investigation.owner_id == user.id, assigned)


@router.get("")
def list_investigations(
    db: Session = DbDep, user: User = Depends(require("investigations:read")),
    date_from: datetime | None = None, date_to: datetime | None = None,
    ip: str | None = Query(default=None, max_length=64), domain: str | None = Query(default=None, max_length=253),
    indicator_type: str | None = Query(default=None, pattern=r"^(ipv4|ipv6|domain|url|md5|sha1|sha256)$"),
    source_system: str | None = Query(default=None, max_length=64),
    severity: str | None = Query(default=None, max_length=16), status: str | None = Query(default=None, max_length=32),
    confidence_level: str | None = Query(default=None, max_length=16), risk_level: str | None = Query(default=None, max_length=16),
    q: str | None = Query(default=None, max_length=200), synthetic: bool | None = None,
    page: int = Query(default=1, ge=1), page_size: int = Query(default=25, ge=1, le=200),
) -> dict:
    stmt = select(Investigation).where(visible_filter(user))
    if date_from:
        stmt = stmt.where(Investigation.created_at >= date_from)
    if date_to:
        stmt = stmt.where(Investigation.created_at <= date_to)
    for value, col in ((source_system, Investigation.source_system), (severity, Investigation.severity),
                       (status, Investigation.status), (confidence_level, Investigation.confidence_level),
                       (risk_level, Investigation.risk_level)):
        if value:
            stmt = stmt.where(col == value)
    if synthetic is not None:
        stmt = stmt.where(Investigation.is_synthetic.is_(synthetic))
    ind_conds = []
    if ip:
        ind_conds.append((Indicator.type.in_(("ipv4", "ipv6")), Indicator.value == ip.strip()))
    if domain:
        ind_conds.append((Indicator.type == "domain", Indicator.value == domain.strip().lower()))
    if indicator_type:
        ind_conds.append((Indicator.type == indicator_type,))
    for conds in ind_conds:
        stmt = stmt.where(exists().where(InvestigationIndicator.investigation_id == Investigation.id,
                                         InvestigationIndicator.indicator_id == Indicator.id, *conds))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Investigation.title.ilike(like), Investigation.reference.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Investigation.created_at.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "page": page, "page_size": page_size, "items": [investigation_summary(i) for i in rows]}


class ManualInvestigation(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    indicators: list[dict[str, str]] = Field(min_length=1, max_length=50)
    restricted: bool = False


@router.post("", status_code=201)
def create_manual(body: ManualInvestigation, request: Request, db: Session = DbDep,
                  user: User = Depends(require("investigations:write"))) -> dict:
    """Manual investigation from analyst-supplied indicators (no SIEM event)."""
    from app.services.ingestion import _next_reference, _ref_lock

    parsed = []
    for item in body.indicators:
        try:
            parsed.append(validate_indicator(item.get("type", ""), item.get("value", "")))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    with _ref_lock:
        inv = Investigation(reference=_next_reference(db), title=body.title, owner_id=user.id, restricted=body.restricted,
                            source_system="manual")
        db.add(inv)
        db.flush()
    for ind in parsed:
        row = _upsert_indicator(db, ind)
        if db.get(InvestigationIndicator, (inv.id, row.id, "observed")) is None:
            db.add(InvestigationIndicator(investigation_id=inv.id, indicator_id=row.id, role="observed", extracted_from="analyst"))
    db.flush()
    enqueue(db, "run_investigation", {"investigation_id": inv.id}, dedup_key=f"investigate:{inv.id}")
    audit.record(db, "investigation.created_manual", actor=user.username, actor_user_id=user.id,
                 target_type="investigation", target_id=inv.id, client_ip=client_ip(request),
                 details={"indicators": [f"{i.type}:{i.value}" for i in parsed]})
    db.commit()
    return investigation_summary(inv)


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str, db: Session = DbDep, user: User = Depends(require("investigations:read"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    links = db.scalars(select(InvestigationIndicator).where(InvestigationIndicator.investigation_id == inv.id))
    results = db.scalars(current_results_stmt(inv.id))
    previous = db.scalar(select(func.count()).select_from(EnrichmentResult).where(
        EnrichmentResult.investigation_id == inv.id, EnrichmentResult.superseded_at.is_not(None))) or 0
    relations = db.scalars(select(IndicatorRelation).where(IndicatorRelation.investigation_id == inv.id))
    analyses = list(db.scalars(select(AIAnalysis).where(AIAnalysis.investigation_id == inv.id).order_by(AIAnalysis.id.desc())))
    notes = db.scalars(select(InvestigationNote).where(InvestigationNote.investigation_id == inv.id).order_by(InvestigationNote.id))
    reports = db.scalars(select(Report).where(Report.investigation_id == inv.id).order_by(Report.id.desc()))
    return {
        **investigation_summary(inv),
        "events": [event_out(e, with_raw=True) for e in inv.events],
        "indicators": [link_out(l) for l in links],
        "results": [result_out(r) for r in results],
        "relations": [relation_out(r) for r in relations],
        "correlation": inv.correlation, "scoring": inv.scoring,
        "enrichment_runs": inv.enrichment_runs, "superseded_results": previous,
        "analysis": analysis_out(analyses[0]) if analyses else None,
        "analyses": [{"id": a.id, "provider": a.provider, "status": a.status, "created_at": iso(a.created_at)} for a in analyses],
        "notes": [note_out(n) for n in notes],
        "reports": [report_out(r) for r in reports],
        "timeline": build_timeline(db, inv),
    }


@router.get("/{investigation_id}/results/{result_id}/raw")
def get_raw_result(investigation_id: str, result_id: int, db: Session = DbDep,
                   user: User = Depends(require("investigations:read"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    r = db.get(EnrichmentResult, result_id)
    if r is None or r.investigation_id != inv.id:
        raise HTTPException(404, "Résultat introuvable")
    return result_out(r, with_raw=True)


class InvestigationPatch(BaseModel):
    status: Status | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    restricted: bool | None = None
    assignees: list[int] | None = Field(default=None, max_length=20)


@router.patch("/{investigation_id}")
def update_investigation(investigation_id: str, body: InvestigationPatch, request: Request, db: Session = DbDep,
                         user: User = Depends(require("investigations:write"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    changes: dict = {}
    if body.status and body.status != inv.status:
        changes["status"] = [inv.status, body.status]
        inv.status = body.status
        inv.closed_at = utc_now() if body.status.startswith("closed") else None
        db.add(InvestigationNote(investigation_id=inv.id, user_id=user.id, kind="status",
                                 content=f"Statut : {changes['status'][0]} vers {body.status}"))
    if body.priority and body.priority != inv.priority:
        changes["priority"] = [inv.priority, body.priority]
        inv.priority = body.priority
    if body.restricted is not None and body.restricted != inv.restricted:
        changes["restricted"] = body.restricted
        inv.restricted = body.restricted
        if inv.owner_id is None:
            inv.owner_id = user.id
    if body.assignees is not None:
        users = [db.get(User, uid) for uid in body.assignees]
        if any(u is None for u in users):
            raise HTTPException(422, "Utilisateur inconnu")
        inv.assignees = users  # type: ignore[assignment]
        changes["assignees"] = [u.username for u in users]  # type: ignore[union-attr]
    inv.updated_at = utc_now()
    audit.record(db, "investigation.updated", actor=user.username, actor_user_id=user.id, target_type="investigation",
                 target_id=inv.id, details=changes, client_ip=client_ip(request))
    db.commit()
    return investigation_summary(inv)


class NoteIn(BaseModel):
    kind: Literal["note", "decision"] = "note"
    content: str = Field(min_length=1, max_length=10_000)


@router.post("/{investigation_id}/notes", status_code=201)
def add_note(investigation_id: str, body: NoteIn, request: Request, db: Session = DbDep,
             user: User = Depends(require("investigations:write"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    note = InvestigationNote(investigation_id=inv.id, user_id=user.id, kind=body.kind, content=body.content)
    db.add(note)
    db.flush()
    audit.record(db, f"investigation.{body.kind}", actor=user.username, actor_user_id=user.id, target_type="investigation",
                 target_id=inv.id, details={"note_id": note.id, "length": len(body.content)}, client_ip=client_ip(request))
    db.commit()
    db.refresh(note)
    return note_out(note)


@router.post("/{investigation_id}/rerun")
async def rerun(investigation_id: str, request: Request, db: Session = DbDep,
                user: User = Depends(require("investigations:write"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    task = enqueue(db, "run_investigation", {"investigation_id": inv.id}, dedup_key=f"investigate:{inv.id}")
    audit.record(db, "investigation.rerun_requested", actor=user.username, actor_user_id=user.id,
                 target_type="investigation", target_id=inv.id, client_ip=client_ip(request))
    db.commit()
    return {"task_id": task.id, "status": task.status}


@router.post("/{investigation_id}/run-now")
async def run_now(investigation_id: str, db: Session = DbDep, user: User = Depends(require("investigations:write"))) -> dict:
    """Synchronous pipeline run (used by the UI 'Relancer maintenant' button and tests)."""
    inv = load_investigation(db, user, investigation_id)
    try:
        return await run_investigation(db, inv.id, actor=user.username, user_id=user.id)
    except ConnectorError as exc:
        raise HTTPException(502, str(exc)) from exc


class AIRun(BaseModel):
    provider: Literal["deterministic", "anthropic", "openai_compatible"] | None = None


@router.post("/{investigation_id}/ai-analysis")
async def ai_analysis(investigation_id: str, body: AIRun, db: Session = DbDep, user: User = Depends(require("ai:run"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    try:
        analysis = await run_analysis(db, inv, provider_override=body.provider, user_id=user.id, actor=user.username)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    return analysis_out(analysis)


@router.get("/{investigation_id}/graph")
def graph(investigation_id: str, db: Session = DbDep, user: User = Depends(require("investigations:read"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    nodes: dict[str, dict] = {}
    edges = []
    for r in db.scalars(select(IndicatorRelation).where(IndicatorRelation.investigation_id == inv.id)):
        for kind, value in ((r.from_kind, r.from_value), (r.to_kind, r.to_value)):
            nid = f"{kind}:{value}"
            nodes.setdefault(nid, {"id": nid, "kind": kind, "label": value, "is_synthetic": r.is_synthetic})
        edges.append({"id": f"e{r.id}", "source": f"{r.from_kind}:{r.from_value}", "target": f"{r.to_kind}:{r.to_value}",
                      **relation_out(r)})
    return {"nodes": list(nodes.values()), "edges": edges,
            "disclaimer": "Les liens sont des observations qualifiées par leur source ; ils ne prouvent pas une causalité."}


class ReportIn(BaseModel):
    kind: Literal["technical", "executive"] = "technical"
    format: Literal["pdf", "json"] = "pdf"


@router.post("/{investigation_id}/reports", status_code=201)
def create_report(investigation_id: str, body: ReportIn, db: Session = DbDep, user: User = Depends(require("reports:write"))) -> dict:
    inv = load_investigation(db, user, investigation_id)
    try:
        report = generate_report(db, inv, body.kind, body.format, user)
    except ValidationFailed as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return report_out(report)


@router.get("/{investigation_id}/events")
def investigation_events(investigation_id: str, db: Session = DbDep, user: User = Depends(require("investigations:read"))) -> list[dict]:
    inv = load_investigation(db, user, investigation_id)
    rows = db.scalars(select(SiemEvent).join(InvestigationEvent, InvestigationEvent.event_id == SiemEvent.id)
                      .where(InvestigationEvent.investigation_id == inv.id).order_by(SiemEvent.event_time))
    return [event_out(e, with_raw=True) for e in rows]
