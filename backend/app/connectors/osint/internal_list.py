"""Internal reputation lists (allow/deny lists maintained by the SOC).

Configured inline (``entries``) and/or from a local JSON/CSV file with columns
``type,value,verdict,comment``.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from app.connectors.osint.base import Findings, OsintProvider, ProviderResult, Reputation

def _decode(data: bytes) -> str:
    """Files edited on Windows (Excel, Notepad) are often UTF-8 with BOM or cp1252."""
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


_SCORES = {"malicious": 90.0, "suspicious": 55.0, "benign": 0.0, "unknown": None}


class InternalListProvider(OsintProvider):
    name = "internal_list"
    display_name = "Listes de réputation internes"
    category = "reputation"
    supported_types = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    upstream_group = "internal"
    reliability = 0.85
    description = "Listes blanches/noires du SOC (fichier local JSON/CSV ou saisie)."
    settings_schema = {"file_path": "Chemin du fichier JSON/CSV", "entries": "Entrées [{type,value,verdict,comment}]"}
    maturity = "implemented-tested"

    def _entries(self) -> list[dict[str, Any]]:
        entries = list(self.ctx.settings.get("entries") or [])
        path = self.ctx.settings.get("file_path")
        if path and Path(path).is_file():
            p = Path(path)
            text = _decode(p.read_bytes())
            if p.suffix.lower() == ".csv":
                entries.extend(csv.DictReader(io.StringIO(text)))
            else:
                entries.extend(json.loads(text))
        return entries

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        for e in self._entries():
            if str(e.get("value", "")).strip().lower() == value.lower() and e.get("type", ind_type) == ind_type:
                verdict = e.get("verdict") if e.get("verdict") in _SCORES else "unknown"
                findings = Findings(reputation=Reputation(
                    verdict=verdict, score=_SCORES[verdict], raw_score=verdict,
                    explanation=str(e.get("comment") or "Entrée de liste interne")[:500],
                ))
                return self._result(ind_type, value, "ok", findings=findings, raw=e, source_confidence="liste interne SOC")
        return self._result(ind_type, value, "no_data", error_message="Absent des listes internes")
