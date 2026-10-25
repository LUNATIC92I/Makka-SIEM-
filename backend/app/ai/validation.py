"""Post-validation of AI output against the evidence package.

Rejects or repairs outputs that would otherwise present unverifiable claims:
* every evidence ID cited must exist in the package;
* every fact and MITRE technique must cite at least one evidence item;
* reference URLs must be URLs present in the evidence (no invented sources);
* threat-actor attribution requires evidence from threat-intelligence results
  (campaign/report associations), never network/geolocation data alone;
* recommended actions always require human validation.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.ai.schemas import AIAnalysisOutput
from app.security.sanitize import clean_text, detect_injection


def validate_output(raw: Any, package: dict[str, Any]) -> tuple[AIAnalysisOutput | None, list[str]]:
    issues: list[str] = []
    try:
        out = AIAnalysisOutput.model_validate(raw)
    except ValidationError as exc:
        return None, [f"Schéma invalide : {e['loc']} {e['msg']}" for e in exc.errors()[:20]]

    allowed = set(package["allowed_evidence_ids"])
    allowed_urls = set(package.get("allowed_reference_urls", []))
    ti_ids = {
        r["id"] for r in package["osint_results"]
        if r["status"] == "ok" and (r.get("findings") or {}).get("campaigns")
    }

    def check_ids(ids: list[str], where: str) -> list[str]:
        bad = [i for i in ids if i not in allowed]
        if bad:
            issues.append(f"{where} : preuves inexistantes citées {bad}")
        return [i for i in ids if i in allowed]

    facts = []
    for f in out.established_facts:
        f.evidence_ids = check_ids(f.evidence_ids, "Fait")
        if f.evidence_ids:
            facts.append(f)
        else:
            issues.append(f"Fait sans preuve valide retiré : « {f.statement[:80]} »")
    out.established_facts = facts
    for h in out.hypotheses:
        h.evidence_ids = check_ids(h.evidence_ids, "Hypothèse")
    for c in out.contradictions:
        c.evidence_ids = check_ids(c.evidence_ids, "Contradiction")
    for s in out.osint_results:
        s.evidence_ids = check_ids(s.evidence_ids, "Résultat OSINT")
    mitre = []
    for t in out.mitre_attack:
        t.evidence_ids = check_ids(t.evidence_ids, f"MITRE {t.technique_id}")
        if t.evidence_ids:
            mitre.append(t)
    out.mitre_attack = mitre
    refs = []
    for ref in out.references:
        if ref.evidence_id not in allowed:
            issues.append(f"Référence inventée retirée : {ref.evidence_id}")
            continue
        if ref.url and ref.url not in allowed_urls:
            issues.append(f"URL non présente dans les preuves retirée : {ref.url[:100]}")
            ref.url = None
        refs.append(ref)
    out.references = refs
    attributions = []
    for a in out.threat_actor_attribution:
        a.evidence_ids = check_ids(a.evidence_ids, "Attribution")
        if not set(a.evidence_ids) & ti_ids:
            issues.append(f"Attribution « {a.actor[:60]} » retirée : aucune preuve de renseignement documentée "
                          "(une adresse IP ou une géolocalisation ne suffit pas).")
            continue
        if a.confidence == "élevée" and len(set(a.evidence_ids) & ti_ids) < 2:
            a.confidence = "moyenne"
            issues.append(f"Confiance de l'attribution « {a.actor[:60]} » abaissée (une seule source).")
        attributions.append(a)
    out.threat_actor_attribution = attributions
    if attributions and not any("attribution" in lim.lower() for lim in out.limitations):
        out.limitations.append("Toute attribution reste une hypothèse fondée sur des sources tierces.")
    for action in out.recommended_actions:
        action.requires_human_validation = True
    # Output must not echo injected instructions as if they were conclusions.
    for field in ("executive_summary", "initial_event"):
        value = getattr(out, field)
        if detect_injection(value):
            issues.append(f"Contenu suspect (injection) détecté dans « {field} » : texte neutralisé.")
            setattr(out, field, "[Contenu retiré : motif d'injection détecté]")
        else:
            setattr(out, field, clean_text(value, 4000))
    return out, issues
