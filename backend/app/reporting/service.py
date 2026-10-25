from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.core.timeutil import utc_now
from app.models import Investigation, Report, User
from app.reporting.builder import build_report_data, canonical_json, sha256
from app.reporting.pdf_report import render_pdf
from app.services import audit


def generate_report(db: Session, inv: Investigation, kind: str, fmt: str, user: User | None) -> Report:
    if kind not in ("technical", "executive") or fmt not in ("pdf", "json"):
        raise ValidationFailed("Type ou format de rapport invalide")
    data = build_report_data(db, inv, kind, user.username if user else "system")
    content = canonical_json(data) if fmt == "json" else render_pdf(data)
    settings = get_settings()
    settings.ensure_dirs()
    name = f"{inv.reference}_{kind}_{utc_now().strftime('%Y%m%dT%H%M%SZ')}.{fmt}"
    path = settings.reports_dir / name
    path.write_bytes(content)
    report = Report(investigation_id=inv.id, kind=kind, format=fmt, file_name=name, sha256=sha256(content),
                    size_bytes=len(content), created_by=user.id if user else None)
    db.add(report)
    db.flush()
    audit.record(db, "report.generated", actor=user.username if user else "system", actor_user_id=user.id if user else None,
                 target_type="investigation", target_id=inv.id,
                 details={"report_id": report.id, "kind": kind, "format": fmt, "sha256": report.sha256})
    return report


def report_path(report: Report) -> Path:
    path = (get_settings().reports_dir / report.file_name).resolve()
    if path.parent != get_settings().reports_dir.resolve():
        raise ValidationFailed("Chemin de rapport invalide")
    return path


def verify_report(report: Report) -> dict:
    path = report_path(report)
    if not path.is_file():
        return {"valid": False, "reason": "Fichier introuvable"}
    actual = sha256(path.read_bytes())
    return {"valid": actual == report.sha256, "expected_sha256": report.sha256, "actual_sha256": actual}
