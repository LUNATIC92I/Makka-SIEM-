"""Explainable risk & confidence scoring.

* **Risk** (0-100): how likely the observed activity is malicious.
* **Confidence** (0-100): how solid the available evidence is.

They are computed separately and must never be conflated. Each factor is
reported with its value, weight, contribution and a plain-language rationale.

Key principles (see docs/SCORING.md):
* unknown factors are *excluded* from the risk mean (absence of signal is not a
  proof of innocuousness) and reduce confidence instead;
* sources sharing an upstream feed (same ``upstream_group``) count once; known
  partially-overlapping groups are discounted;
* contradictions, stale data and collection errors reduce confidence.
"""

from __future__ import annotations

import fnmatch
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.timeutil import utc_now

SEVERITY_VALUE = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.75, "critical": 0.95}
CRITICALITY_VALUE = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
SUSPICIOUS_EVENT_KEYWORDS = {
    "brute": "force brute", "bruteforce": "force brute", "failed": "échecs d'authentification",
    "échec": "échecs d'authentification", "auth": "authentification", "scan": "balayage",
    "malware": "logiciel malveillant", "c2": "commande et contrôle", "beacon": "balise C2",
    "exfil": "exfiltration", "suspicious": "activité suspecte", "suspect": "activité suspecte",
}


@dataclass
class ReputationEvidence:
    source: str
    group: str
    reliability: float
    verdict: str
    score: float | None
    last_reported_at: datetime | None = None
    is_synthetic: bool = False


@dataclass
class EventEvidence:
    severity: str
    event_type: str
    title: str
    attempt_count: int | None
    hostname: str | None
    dst_ip: str | None


@dataclass
class ScoringInput:
    events: list[EventEvidence]
    reputation: list[ReputationEvidence]
    campaigns: list[tuple[str, str]] = field(default_factory=list)  # (campaign name, upstream group)
    categories_answered: set[str] = field(default_factory=set)
    categories_expected: set[str] = field(default_factory=lambda: {"network", "geolocation", "reputation"})
    contradictions: int = 0
    stale_results: int = 0
    errors: int = 0
    synthetic_used: bool = False
    enrichable_indicators: int = 1
    threat_intel_sources_ok: int = 0


@dataclass
class Factor:
    key: str
    label: str
    value: float | None  # 0..1, None = unknown
    weight: float
    rationale: str

    def as_dict(self, total_weight: float) -> dict[str, Any]:
        contribution = None if self.value is None or total_weight == 0 else round(100 * self.weight * self.value / total_weight, 1)
        return {
            "key": self.key, "label": self.label, "value": None if self.value is None else round(self.value, 3),
            "weight": self.weight, "contribution": contribution, "status": "inconnu" if self.value is None else "pris en compte",
            "rationale": self.rationale,
        }


def _level(score: float, levels: dict[str, float], base: str) -> str:
    result = base
    for name, threshold in sorted(levels.items(), key=lambda kv: kv[1]):
        if score >= threshold:
            result = name
    return result


def effective_independent_sources(
    groups: dict[str, float], overlapping: list[list[str]], discount: float
) -> tuple[float, list[str]]:
    """Sum of per-group reliability, discounting groups known to overlap with an already counted one."""
    notes: list[str] = []
    counted: list[str] = []
    total = 0.0
    for group, rel in sorted(groups.items(), key=lambda kv: -kv[1]):
        overlap_with = [g for g in counted if [g, group] in overlapping or [group, g] in overlapping]
        if overlap_with:
            total += rel * discount
            notes.append(f"'{group}' partage des données avec '{overlap_with[0]}' : poids réduit (coefficient {discount}).")
        else:
            total += rel
        counted.append(group)
    return total, notes


def compute(inp: ScoringInput, cfg: dict[str, Any], assets: dict[str, Any] | None = None) -> dict[str, Any]:
    weights = cfg["risk_weights"]
    now = utc_now()
    factors: list[Factor] = []

    # --- 1. reputation: one value per upstream group (max within group) ------------------
    rep_by_group: dict[str, tuple[float, float, list[str]]] = {}
    for r in inp.reputation:
        val = 0.0 if r.verdict == "benign" else (r.score if r.score is not None else None)
        if val is None:
            continue
        rel = cfg.get("reliability_overrides", {}).get(r.source, r.reliability)
        prev = rep_by_group.get(r.group)
        if prev is None or val > prev[0]:
            rep_by_group[r.group] = (val, rel, (prev[2] if prev else []) + [r.source])
        else:
            prev[2].append(r.source)
    if rep_by_group:
        num = sum(v * rel for v, rel, _ in rep_by_group.values())
        den = sum(rel for _, rel, _ in rep_by_group.values())
        rep_value = num / den / 100
        dup = [", ".join(srcs) for _, _, srcs in rep_by_group.values() if len(srcs) > 1]
        rationale = (
            f"{len(rep_by_group)} groupe(s) de sources indépendant(s) avec un score ; moyenne pondérée par la fiabilité = "
            f"{rep_value * 100:.0f}/100."
        )
        if dup:
            rationale += f" Sources de même amont comptées une seule fois : {'; '.join(dup)}."
    else:
        rep_value = None
        rationale = "Aucune source de réputation n'a fourni de score. L'absence de signalement n'est pas une preuve d'innocuité."
    factors.append(Factor("reputation", "Réputation documentée", rep_value, weights["reputation"], rationale))

    # --- 2. event context ----------------------------------------------------------------
    sev_values = [SEVERITY_VALUE[e.severity] for e in inp.events if e.severity in SEVERITY_VALUE]
    if sev_values:
        ctx_value = max(sev_values)
        text = " ".join(f"{e.event_type} {e.title}".lower() for e in inp.events)
        hits = sorted({label for kw, label in SUSPICIOUS_EVENT_KEYWORDS.items() if kw in text})
        if hits:
            ctx_value = min(1.0, ctx_value + 0.1)
        ctx_rationale = f"Sévérité SIEM maximale : {max((e.severity for e in inp.events if e.severity in SEVERITY_VALUE), key=lambda s: SEVERITY_VALUE[s])}."
        if hits:
            ctx_rationale += f" Nature de l'événement : {', '.join(hits)} (+0,1)."
    else:
        ctx_value, ctx_rationale = None, "Sévérité de l'événement inconnue."
    factors.append(Factor("event_context", "Contexte de l'événement SIEM", ctx_value, weights["event_context"], ctx_rationale))

    # --- 3. frequency ------------------------------------------------------------------
    attempts = sum(max(1, e.attempt_count or 1) for e in inp.events)
    freq_value = min(1.0, math.log10(attempts) / 3) if attempts > 0 else None
    factors.append(Factor(
        "frequency", "Fréquence des tentatives", freq_value, weights["frequency"],
        f"{attempts} tentative(s) observée(s) sur {len(inp.events)} événement(s) (échelle logarithmique : 1000 = maximum).",
    ))

    # --- 4. target criticality ------------------------------------------------------------
    assets = assets or {}
    crit_label = None
    matched = None
    for e in inp.events:
        for target in filter(None, [e.hostname, e.dst_ip]):
            for pattern, level in (assets.get("patterns") or {}).items():
                if fnmatch.fnmatch(target.lower(), pattern.lower()) and (
                    crit_label is None or CRITICALITY_VALUE[level] > CRITICALITY_VALUE[crit_label]
                ):
                    crit_label, matched = level, f"{target} ~ {pattern}"
    if crit_label is None:
        crit_label = assets.get("default_criticality", "medium")
        crit_rationale = f"Aucun actif référencé : criticité par défaut {crit_label}."
    else:
        crit_rationale = f"Cible identifiée dans l'inventaire ({matched}) : criticité {crit_label}."
    factors.append(Factor("target_criticality", "Criticité de la cible", CRITICALITY_VALUE.get(crit_label, 0.5),
                          weights["target_criticality"], crit_rationale))

    # --- 5. documented associations -------------------------------------------------------
    if inp.threat_intel_sources_ok or inp.campaigns:
        groups = {g for _, g in inp.campaigns}
        names = {n for n, _ in inp.campaigns}
        assoc_value = min(1.0, 0.3 * len(groups) + 0.1 * min(len(names), 3))
        assoc_rationale = (
            f"{len(names)} campagne(s)/rapport(s) associé(s) par {len(groups)} source(s) indépendante(s)."
            if names else "Sources de renseignement interrogées : aucune association documentée."
        )
    else:
        assoc_value, assoc_rationale = None, "Aucune source de renseignement (campagnes) disponible."
    factors.append(Factor("associations", "Associations documentées", assoc_value, weights["associations"], assoc_rationale))

    # --- 6. recency ---------------------------------------------------------------------
    dates = [r.last_reported_at for r in inp.reputation if r.last_reported_at and r.verdict in ("malicious", "suspicious")]
    if dates:
        age = (now - max(dates)).days
        recency_value = 1.0 if age <= cfg["recent_days"] else 0.5 if age <= cfg["stale_after_days"] else 0.1
        recency_rationale = f"Dernier signalement défavorable il y a {age} jour(s)."
    else:
        recency_value, recency_rationale = None, "Aucun signalement daté."
    factors.append(Factor("recency", "Récence des observations", recency_value, weights["recency"], recency_rationale))

    known = [f for f in factors if f.value is not None]
    total_weight = sum(f.weight for f in known)
    risk = round(100 * sum(f.weight * f.value for f in known) / total_weight, 1) if total_weight else None

    # --- confidence -------------------------------------------------------------------
    groups_rel = {g: rel for g, (_, rel, _) in rep_by_group.items()}
    eff, overlap_notes = effective_independent_sources(groups_rel, cfg["overlapping_groups"], cfg["overlap_discount"])
    expected = inp.categories_expected or {"reputation"}
    coverage = len(inp.categories_answered & expected) / len(expected)
    all_weight = sum(f.weight for f in factors)
    known_fraction = total_weight / all_weight if all_weight else 0
    corroboration = min(1.0, eff / 2.0)
    conf = 100 * (0.45 * corroboration + 0.35 * coverage + 0.20 * known_fraction)
    penalties: list[dict[str, Any]] = []
    for count, per, cap, label in (
        (inp.contradictions, 10, 30, "contradiction(s) entre sources"),
        (inp.stale_results, 5, 15, "donnée(s) obsolète(s)"),
        (inp.errors, 3, 15, "erreur(s) de collecte"),
    ):
        if count:
            p = min(cap, count * per)
            conf -= p
            penalties.append({"label": f"{count} {label}", "points": -p})
    conf = max(0.0, min(100.0, round(conf, 1)))
    confidence_factors = [
        {"label": "Corroboration indépendante", "value": round(corroboration, 3), "weight": 0.45,
         "rationale": f"{len(inp.reputation)} résultat(s) de réputation issus de {len(groups_rel)} groupe(s) d'amont "
                      f"soit {eff:.2f} source(s) indépendante(s) effective(s) (2 = maximum)."},
        {"label": "Couverture des dimensions", "value": round(coverage, 3), "weight": 0.35,
         "rationale": f"Dimensions documentées : {', '.join(sorted(inp.categories_answered & expected)) or 'aucune'} "
                      f"sur {', '.join(sorted(expected))}."},
        {"label": "Facteurs de risque connus", "value": round(known_fraction, 3), "weight": 0.20,
         "rationale": f"{len(known)}/{len(factors)} facteurs de risque documentés."},
    ]
    notes = list(overlap_notes)
    if inp.synthetic_used:
        notes.append("Calcul réalisé sur des DONNÉES DE DÉMONSTRATION synthétiques : aucune valeur opérationnelle.")
    if inp.enrichable_indicators == 0:
        notes.append("Aucun indicateur public enrichissable (adresses internes ou réservées).")

    risk_level = _level(risk, cfg["risk_levels"], "faible") if risk is not None else "indéterminé"
    confidence_level = _level(conf, cfg["confidence_levels"], "faible")
    return {
        "risk_score": risk,
        "risk_level": risk_level,
        "confidence_score": conf,
        "confidence_level": confidence_level,
        "risk_factors": [f.as_dict(total_weight) for f in factors],
        "confidence_factors": confidence_factors,
        "confidence_penalties": penalties,
        "notes": notes,
        "effective_independent_sources": round(eff, 2),
        "summary": (
            f"Risque {risk_level} ({risk if risk is not None else 'N/D'}/100) avec une confiance {confidence_level} "
            f"({conf}/100). Le risque estime le caractère potentiellement malveillant ; la confiance mesure la "
            "solidité des éléments disponibles."
        ),
        "computed_at": now.isoformat(),
    }
