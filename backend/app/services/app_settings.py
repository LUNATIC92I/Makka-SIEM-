"""Runtime-editable settings stored in the database (with documented defaults)."""

from __future__ import annotations

import copy
from typing import Any

from sqlalchemy.orm import Session

from app.models import AppSetting

DEFAULTS: dict[str, dict[str, Any]] = {
    "scoring": {
        # Risk = weighted mean of the factors that are *known*. Unknown factors are
        # excluded (and lower the confidence) instead of being treated as "benign".
        "risk_weights": {
            "reputation": 0.35, "event_context": 0.20, "frequency": 0.10,
            "target_criticality": 0.15, "associations": 0.15, "recency": 0.05,
        },
        "risk_levels": {"modéré": 30, "élevé": 55, "critique": 80},
        "confidence_levels": {"moyenne": 40, "élevée": 70},
        "stale_after_days": 180,
        "recent_days": 30,
        "reliability_overrides": {},
        # Pairs of upstream groups known to share data (partial dependence).
        "overlapping_groups": [["virustotal-aggregate", "abusech"], ["otx-community", "abusech"],
                               ["virustotal-aggregate", "otx-community"]],
        "overlap_discount": 0.5,
    },
    "ingestion": {
        "auto_investigate_min_severity": "low",
        "group_window_minutes": 60,
        "group_by_source_ip": True,
        "max_events_per_poll": 200,
    },
    "assets": {
        "default_criticality": "medium",
        # fnmatch patterns on hostname or destination IP -> low|medium|high|critical
        "patterns": {"srv-*": "high", "dc*": "critical", "*-prod-*": "high", "10.0.0.*": "high"},
    },
    "retention": {"investigations_days": 365, "raw_events_days": 180, "tasks_days": 30},
    "notifications": {"enabled": False, "min_risk_level": "élevé", "webhook_url": ""},
}


def get_setting(db: Session, key: str) -> dict[str, Any]:
    row = db.get(AppSetting, key)
    base = copy.deepcopy(DEFAULTS.get(key, {}))
    if row and isinstance(row.value, dict):
        base.update(row.value)
    return base


def put_setting(db: Session, key: str, value: dict[str, Any]) -> dict[str, Any]:
    if key not in DEFAULTS:
        raise KeyError(key)
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    db.flush()
    return get_setting(db, key)
