"""Cross-source correlation.

Produces, from stored enrichment results:
* qualified relations (graph edges) — observations, never proofs of causality;
* attributed facts ("source S declares X"), agreements, contradictions,
  stale data and missing information;
* the inputs of the scoring engine.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from app.connectors.osint.base import Findings
from app.connectors.osint.registry import CATALOG
from app.core.timeutil import iso, utc_now
from app.models import EnrichmentResult, Indicator, InvestigationIndicator, SiemEvent
from app.scoring.engine import EventEvidence, ReputationEvidence, ScoringInput

CATEGORY_LABELS = {
    "network": "attribution réseau (organisation / ASN)",
    "geolocation": "géolocalisation estimée",
    "reputation": "réputation",
    "infrastructure": "infrastructures associées",
    "threat_intel": "renseignement (campagnes)",
    "services": "services exposés (passif)",
}


@dataclass
class RelationSpec:
    from_kind: str
    from_value: str
    to_kind: str
    to_value: str
    relation_type: str
    source_name: str
    temporality: str = "unknown"
    confidence: float = 0.5
    observed_at: Any = None
    evidence_result_id: int | None = None
    is_synthetic: bool = False


@dataclass
class CorrelationOutput:
    relations: list[RelationSpec] = field(default_factory=list)
    facts: list[dict[str, Any]] = field(default_factory=list)
    agreements: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    collection_errors: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    scoring_input: ScoringInput | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "facts": self.facts, "agreements": self.agreements, "contradictions": self.contradictions,
            "stale": self.stale, "missing": self.missing, "collection_errors": self.collection_errors,
            "notes": self.notes,
        }


def _src_meta(name: str) -> tuple[str, float, str]:
    cls = CATALOG.get(name)
    if cls is None:
        return name, 0.5, "unknown"
    return cls.upstream_group, cls.reliability, cls.category


def _ind_kind(ind_type: str) -> str:
    return "ip" if ind_type in ("ipv4", "ipv6") else ind_type


def correlate(
    events: list[SiemEvent], links: list[InvestigationIndicator], results: list[EnrichmentResult],
    stale_after_days: int = 180,
) -> CorrelationOutput:
    out = CorrelationOutput()
    now = utc_now()
    indicators: dict[int, Indicator] = {link.indicator_id: link.indicator for link in links}
    enrichable = [i for i in indicators.values() if i.scope == "public"]

    # --- events -> indicators -------------------------------------------------------
    for ev in events:
        ev_node = f"{ev.source_system}:{ev.original_id}"
        if ev.hostname:
            out.relations.append(RelationSpec("event", ev_node, "host", ev.hostname, "targets_host", "siem",
                                              "current", 0.9, ev.event_time, None, ev.is_synthetic))
        for link in links:
            if link.event_id == ev.id:
                rel = {"source": "observed_as_source", "destination": "observed_as_destination"}.get(link.role, "observed_in_event")
                out.relations.append(RelationSpec(
                    "event", ev_node, _ind_kind(link.indicator.type), link.indicator.value, rel, "siem",
                    "current", 0.95, ev.event_time, None, ev.is_synthetic,
                ))
    for ind in indicators.values():
        if ind.scope != "public":
            out.notes.append(f"{ind.value} : {ind.classification.get('note', ind.scope)}")

    # --- per-result facts & relations ------------------------------------------------
    by_ind: dict[int, list[EnrichmentResult]] = defaultdict(list)
    answered: set[str] = set()
    reputation: list[ReputationEvidence] = []
    campaigns: list[tuple[str, str]] = []
    ti_ok = 0
    synthetic_used = any(e.is_synthetic for e in events)
    for r in results:
        by_ind[r.indicator_id].append(r)
        group, reliability, category = _src_meta(r.source_name)
        ind = indicators.get(r.indicator_id) or r.indicator
        node_kind, node_value = _ind_kind(ind.type), ind.value
        if r.status not in ("ok", "no_data"):
            out.collection_errors.append({
                "source": r.source_name, "indicator": ind.value, "status": r.status,
                "message": r.error_message or "Donnée indisponible", "queried_at": iso(r.queried_at),
            })
            continue
        if r.status == "no_data":
            if category in ("reputation", "threat_intel"):
                ti_ok += 1 if category == "threat_intel" else 0
                out.facts.append(_fact(r, f"{r.source_name} : aucune donnée pour {ind.value} "
                                          "(absence de signalement ≠ innocuité).", "absence"))
            continue
        synthetic_used = synthetic_used or r.is_synthetic
        f = Findings.model_validate(r.findings or {})
        if f.network and (f.network.asn or f.network.registered_org or f.network.as_name):
            answered.add("network")
            n = f.network
            if n.registered_org:
                out.facts.append(_fact(r, f"{r.source_name} déclare que le bloc de {ind.value} est enregistré au nom de "
                                          f"« {n.registered_org} » (organisation enregistrée, pas l'utilisateur de l'adresse).", "network"))
                out.relations.append(_rel(r, node_kind, node_value, "organisation", n.registered_org, "registered_to", 0.8))
            if n.asn:
                out.facts.append(_fact(r, f"{r.source_name} indique l'ASN AS{n.asn}{f' ({n.as_name})' if n.as_name else ''} "
                                          f"pour {ind.value}.", "network"))
                out.relations.append(_rel(r, node_kind, node_value, "asn", f"AS{n.asn}", "announced_by_asn", 0.8))
            if n.isp:
                out.facts.append(_fact(r, f"{r.source_name} associe {ind.value} au fournisseur « {n.isp} ».", "network"))
        if f.geo and (f.geo.country_code or f.geo.latitude is not None):
            answered.add("geolocation")
            loc = ", ".join(x for x in [f.geo.city, f.geo.region, f.geo.country or f.geo.country_code] if x)
            out.facts.append(_fact(r, f"{r.source_name} estime la localisation de {ind.value} : {loc} "
                                      "(estimation, pas une position GPS).", "geolocation"))
        if f.reputation:
            answered.add("reputation")
            reputation.append(ReputationEvidence(
                r.source_name, group, reliability, f.reputation.verdict, f.reputation.score,
                f.reputation.last_reported_at, r.is_synthetic,
            ))
            out.facts.append(_fact(r, f"{r.source_name} : verdict « {f.reputation.verdict} »"
                                      f"{f' ({f.reputation.raw_score})' if f.reputation.raw_score else ''} pour {ind.value}.", "reputation"))
            last = f.reputation.last_reported_at
            if last and now - last > timedelta(days=stale_after_days):
                out.stale.append({"source": r.source_name, "indicator": ind.value, "last_reported_at": iso(last),
                                  "message": f"Dernier signalement il y a {(now - last).days} jours."})
        if category == "threat_intel":
            ti_ok += 1
        for c in f.campaigns:
            answered.add("threat_intel")
            campaigns.append((c.name, group))
            out.relations.append(_rel(r, node_kind, node_value, "campaign", c.name, "associated_by_source", 0.4))
        for rel in f.related:
            temporality = "historical" if "historical" in rel.relation else "current" if (
                "current" in rel.relation or rel.relation.startswith("dns_")) else "unknown"
            answered.add("infrastructure")
            out.relations.append(_rel(r, node_kind, node_value, _ind_kind(rel.type), rel.value, rel.relation,
                                      0.6, temporality, rel.last_seen or rel.first_seen))
        for cert in f.certificates[:10]:
            answered.add("infrastructure")
            label = cert.subject_cn or cert.reference_url or "certificat"
            temporality = "current" if cert.not_after and cert.not_after > now else "historical"
            out.relations.append(_rel(r, node_kind, node_value, "certificate", label, "certificate_observed", 0.6,
                                      temporality, cert.not_before))
        if f.services and f.services.ports:
            answered.add("services")
            out.facts.append(_fact(r, f"{r.source_name} a observé les ports {', '.join(map(str, f.services.ports[:15]))} "
                                      f"exposés sur {ind.value} (donnée passive tierce).", "services"))
        if r.data_updated_at and now - r.data_updated_at > timedelta(days=stale_after_days):
            out.stale.append({"source": r.source_name, "indicator": ind.value, "last_reported_at": iso(r.data_updated_at),
                              "message": "Donnée source ancienne."})

    # --- agreements / contradictions --------------------------------------------------
    for ind_id, rows in by_ind.items():
        ind = indicators.get(ind_id) or rows[0].indicator
        ok_rows = [(r, Findings.model_validate(r.findings or {})) for r in rows if r.status == "ok"]
        _compare(out, ind.value, "ASN", {(r.source_name, _src_meta(r.source_name)[0]): f"AS{f.network.asn}"
                                         for r, f in ok_rows if f.network and f.network.asn}, [r for r, _ in ok_rows])
        _compare(out, ind.value, "pays estimé", {(r.source_name, _src_meta(r.source_name)[0]): f.geo.country_code
                                                 for r, f in ok_rows if f.geo and f.geo.country_code}, [r for r, _ in ok_rows])
        verdicts = {(r.source_name, _src_meta(r.source_name)[0]): f.reputation.verdict
                    for r, f in ok_rows if f.reputation and f.reputation.verdict != "unknown"}
        bad = {k for k, v in verdicts.items() if v in ("malicious", "suspicious")}
        good = {k for k, v in verdicts.items() if v == "benign"}
        if bad and good:
            out.contradictions.append({
                "indicator": ind.value, "dimension": "réputation",
                "description": f"Verdicts opposés : défavorable selon {', '.join(s for s, _ in bad)}, "
                               f"favorable selon {', '.join(s for s, _ in good)}.",
                "evidence_ids": [_eid(r) for r, _ in ok_rows if (r.source_name, _src_meta(r.source_name)[0]) in bad | good],
            })
        elif len({g for _, g in bad}) >= 2:
            out.agreements.append({"indicator": ind.value, "dimension": "réputation",
                                   "description": f"Verdict défavorable concordant de {len({g for _, g in bad})} groupes de sources indépendants."})
        elif len(bad) >= 2:
            out.notes.append(f"{ind.value} : {len(bad)} sources défavorables mais issues du même amont "
                             f"({', '.join(sorted({g for _, g in bad}))}) — corroboration non indépendante.")

    # --- missing information ------------------------------------------------------------
    if enrichable:
        for cat in ("network", "geolocation", "reputation", "infrastructure"):
            if cat not in answered:
                out.missing.append(f"Aucune donnée de {CATEGORY_LABELS[cat]} obtenue.")
        if not any(r.status == "ok" for r in results):
            out.missing.append("Aucune source OSINT n'a répondu : vérifier la configuration des connecteurs.")
    else:
        out.missing.append("Aucun indicateur public à enrichir : l'analyse repose uniquement sur l'événement SIEM.")
    rep_rows = [r for r in results if _src_meta(r.source_name)[2] == "reputation"]
    if rep_rows and not any(r.status == "ok" for r in rep_rows):
        out.notes.append("Aucune source de réputation n'a signalé ces indicateurs : l'absence de signalement ne "
                         "constitue pas une preuve d'innocuité.")
    if not any(e.dst_ip or e.hostname for e in events):
        out.missing.append("Cible de l'événement non précisée par le SIEM.")

    out.scoring_input = ScoringInput(
        events=[EventEvidence(e.severity, e.event_type, e.title, e.attempt_count, e.hostname, e.dst_ip) for e in events],
        reputation=reputation,
        campaigns=campaigns,
        categories_answered=answered,
        categories_expected={"network", "geolocation", "reputation"} if enrichable else {"reputation"},
        contradictions=len(out.contradictions),
        stale_results=len(out.stale),
        errors=len(out.collection_errors),
        synthetic_used=synthetic_used,
        enrichable_indicators=len(enrichable),
        threat_intel_sources_ok=ti_ok,
    )
    return out


def _eid(r: EnrichmentResult) -> str:
    return f"R{r.id}"


def _fact(r: EnrichmentResult, statement: str, category: str) -> dict[str, Any]:
    return {"statement": statement, "category": category, "evidence_ids": [_eid(r)], "source": r.source_name,
            "queried_at": iso(r.queried_at), "is_synthetic": r.is_synthetic}


def _rel(r: EnrichmentResult, fk: str, fv: str, tk: str, tv: str, rt: str, conf: float,
         temporality: str = "unknown", observed_at: Any = None) -> RelationSpec:
    return RelationSpec(fk, fv, tk, tv, rt, r.source_name, temporality, conf, observed_at or r.queried_at, r.id, r.is_synthetic)


def _compare(out: CorrelationOutput, indicator: str, dimension: str, values: dict[tuple[str, str], Any],
             rows: list[EnrichmentResult]) -> None:
    distinct = set(values.values())
    if len(distinct) > 1:
        detail = "; ".join(f"{s} → {v}" for (s, _), v in values.items())
        out.contradictions.append({
            "indicator": indicator, "dimension": dimension, "description": f"Valeurs divergentes ({detail}).",
            "evidence_ids": [_eid(r) for r in rows if any(r.source_name == s for s, _ in values)],
        })
    elif len(distinct) == 1 and len({g for _, g in values}) >= 2:
        out.agreements.append({"indicator": indicator, "dimension": dimension,
                               "description": f"{dimension} {next(iter(distinct))} confirmé par {len({g for _, g in values})} groupes de sources indépendants."})
