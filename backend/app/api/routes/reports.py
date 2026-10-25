from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, can_access_investigation, require
from app.models import Investigation, Report, User
from app.reporting.service import report_path, verify_report
from app.schemas.serializers import report_out
from app.services import audit

router = APIRouter(prefix="/reports", tags=["reports"])


def _load(db: Session, user: User, report_id: int) -> tuple[Report, Investigation]:
    report = db.get(Report, report_id)
    inv = db.get(Investigation, report.investigation_id) if report else None
    if report is None or inv is None or not can_access_investigation(db, user, inv):
        raise HTTPException(404, "Rapport introuvable")
    return report, inv


@router.get("")
def list_reports(db: Session = DbDep, user: User = Depends(require("reports:read"))) -> list[dict]:
    out = []
    for r in db.scalars(select(Report).order_by(Report.id.desc()).limit(500)):
        inv = db.get(Investigation, r.investigation_id)
        if inv and can_access_investigation(db, user, inv):
            out.append({**report_out(r), "investigation_reference": inv.reference, "investigation_title": inv.title,
                        "is_synthetic": inv.is_synthetic})
    return out


@router.get("/{report_id}/download")
def download(report_id: int, db: Session = DbDep, user: User = Depends(require("reports:read"))) -> FileResponse:
    report, inv = _load(db, user, report_id)
    path = report_path(report)
    if not path.is_file():
        raise HTTPException(404, "Fichier de rapport introuvable")
    audit.record(db, "report.downloaded", actor=user.username, actor_user_id=user.id, target_type="report", target_id=report.id)
    db.commit()
    media = "application/pdf" if report.format == "pdf" else "application/json"
    return FileResponse(path, media_type=media, filename=report.file_name,
                        headers={"X-Content-SHA256": report.sha256})


@router.get("/{report_id}/verify")
def verify(report_id: int, db: Session = DbDep, user: User = Depends(require("reports:read"))) -> dict:
    report, _ = _load(db, user, report_id)
    return verify_report(report)
