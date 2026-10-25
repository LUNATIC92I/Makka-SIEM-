"""Deterministic, rule-based analyst (no LLM).

Always available offline. It only restates the evidence package with explicit
attribution, applies conservative rules and never introduces information that
is not in the package. Its output follows the same schema as LLM providers and
goes through the same validation.
"""

from __future__ import annotations

from typing import Any

from app.ai.providers import AIConfig, AIProvider

MITRE_RULES = [
    (("brute", "failed login", "failed password", "échec", "authentication failure", "auth fail", "connexions suspectes répétées",
      "repeated", "répétées"), "T1110", "Brute Force",
     "Des tentatives d'authentification répétées sont décrites par l'événement SIEM. Hypothèse à confirmer par les journaux d'authentification."),
    (("scan", "balayage", "port sweep", "reconnaissance"), "T1595", "Active Scanning",
     "L'événement décrit une activité de balayage. Hypothèse : reconnaissance préalable."),
    (("exploit", "cve-", "injection", "rce"), "T1190", "Exploit Public-Facing Application",
     "L'événement mentionne une tentative d'exploitation d'un service exposé."),
    (("beacon", "c2", "command and control"), "T1071", "Application Layer Protocol",
     "L'événement évoque une communication de type commande et contrôle."),
]


class DeterministicProvider(AIProvider):
    name = "deterministic"
    external = False

    def __init__(self, cfg: AIConfig | None = None):
        super().__init__(cfg or AIConfig(provider="deterministic"))

    @property
    def model(self) -> str:
        return "makkadi-rules-v1"

    async def analyze(self, package: dict[str, Any]) -> dict[str, Any]:
        events = package["events"]
        results = package["osint_results"]
        corr = package.get("correlation") or {}
        scoring = package.get("scoring") or {}
        synthetic = package["investigation"].get("synthetic_data") or any(r.get("synthetic_data") for r in results)
        ok = [r for r in results if r["status"] == "ok"]

        first = events[0] if events else {}
        target = first.get("target_host") or first.get("dst_ip") or "cible non précisée"
        initial = (
            f"Le SIEM {first.get('source_system', '?')} a enregistré « {first.get('title', '')} » "
            f"(type : {first.get('event_type', '?')}, sévérité : {first.get('severity', '?')}) le {first.get('time_utc') or 'horodatage inconnu'} "
            f"depuis {first.get('src_ip') or 'source inconnue'} vers {target}"
            + (f", port {first.get('dst_port')}/{first.get('protocol') or '?'}" if first.get("dst_port") else "")
            + (f", {first.get('attempt_count')} tentative(s)" if first.get("attempt_count") else "")
            + f". Identifiant d'origine : {first.get('original_id', '?')}."
        ) if events else "Aucun événement SIEM associé."
        if len(events) > 1:
            initial += f" {len(events) - 1} autre(s) événement(s) corrélé(s) à cette investigation."

        facts = [{"statement": f"Événement {e['id']} : « {e['title']} » ({e['severity']}) à {e['time_utc'] or 'heure inconnue'} "
                               f"depuis {e['src_ip'] or '?'} vers {e.get('target_host') or e.get('dst_ip') or '?'}.",
                  "evidence_ids": [e["id"]]} for e in events]
        facts += [{"statement": f["statement"], "evidence_ids": f["evidence_ids"]}
                  for f in corr.get("facts", []) if f.get("category") != "absence"][:40]

        bad = [r for r in ok if ((r.get("findings") or {}).get("reputation") or {}).get("verdict") in ("malicious", "suspicious")]
        hypotheses = []
        if bad:
            hypotheses.append({
                "statement": "L'adresse source pourrait être associée à une activité malveillante.",
                "rationale": f"{len(bad)} résultat(s) de réputation défavorable(s) : "
                             + ", ".join(f"{r['source']} ({r['id']})" for r in bad[:6]) + ".",
                "evidence_ids": [r["id"] for r in bad[:10]],
                "how_to_verify": "Vérifier l'indépendance des sources, la date des signalements et corréler avec les journaux internes.",
            })
        text = " ".join(f"{e.get('title', '')} {e.get('event_type', '')}".lower() for e in events)
        mitre = []
        for keywords, tid, name, justification in MITRE_RULES:
            if any(k in text for k in keywords):
                mitre.append({"technique_id": tid, "name": name, "justification": justification,
                              "evidence_ids": [e["id"] for e in events]})
                hypotheses.append({
                    "statement": f"Hypothèse de technique {tid} ({name}).", "rationale": justification,
                    "evidence_ids": [e["id"] for e in events],
                    "how_to_verify": "Examiner les journaux de la cible sur la période (succès éventuels après échecs, comptes visés).",
                })
        alternatives = [
            {"statement": "Balayage opportuniste non ciblé d'Internet.",
             "rationale": "De nombreuses adresses scannent en permanence les services exposés sans viser spécifiquement l'organisation."},
            {"statement": "Client légitime mal configuré (mot de passe expiré, script, supervision).",
             "rationale": "Des connexions répétées peuvent provenir d'un usage légitime défaillant."},
            {"statement": "Adresse partagée (NAT, VPN, proxy, cloud, relais compromis).",
             "rationale": "L'adresse observée peut être utilisée par de nombreux utilisateurs ; elle n'identifie pas l'auteur."},
            {"statement": "Faux positif de la règle de détection.",
             "rationale": "Le seuil ou la logique de la règle SIEM peut produire des alertes non pertinentes."},
        ]
        missing = list(corr.get("missing", [])) + [
            f"{e['source']} : {e['status']} — {e['message']}" for e in corr.get("collection_errors", [])
        ][:30]
        contradictions = [{"description": f"{c['indicator']} — {c['dimension']} : {c['description']}",
                           "evidence_ids": c.get("evidence_ids", [])} for c in corr.get("contradictions", [])]
        risk_level, conf_level = scoring.get("risk_level") or "indéterminé", scoring.get("confidence_level") or "faible"
        factors = scoring.get("risk_factors") or []
        top = sorted((f for f in factors if f.get("contribution") is not None), key=lambda f: -f["contribution"])[:3]
        actions = [
            {"action": f"Rechercher dans le SIEM toutes les connexions de {first.get('src_ip') or 'la source'} sur 30 jours (autres cibles, succès d'authentification).",
             "priority": "haute", "requires_human_validation": True},
            {"action": f"Examiner les journaux d'authentification de {target} sur la période de l'alerte.",
             "priority": "haute", "requires_human_validation": True},
            {"action": "Vérifier les comptes ciblés et l'activation du verrouillage / MFA.", "priority": "moyenne",
             "requires_human_validation": True},
        ]
        if risk_level in ("élevé", "critique"):
            actions.append({"action": "Envisager un blocage temporaire de l'adresse en périphérie après validation par l'analyste (impact à évaluer).",
                            "priority": "moyenne", "requires_human_validation": True})
        if conf_level == "faible":
            actions.append({"action": "Configurer ou interroger des sources OSINT supplémentaires indépendantes avant toute conclusion.",
                            "priority": "moyenne", "requires_human_validation": True})
        limitations = [
            "Analyse générée par le moteur déterministe MAKKADi (sans modèle de langage) à partir des seules preuves listées.",
            "La géolocalisation IP est une estimation et n'identifie ni une personne ni un emplacement physique précis.",
            "L'organisation enregistrée d'un bloc IP n'est pas nécessairement l'utilisateur de l'adresse.",
            "L'absence de signalement dans une source ne constitue pas une preuve d'innocuité.",
        ]
        if synthetic:
            limitations.insert(0, "DONNÉES DE DÉMONSTRATION : les résultats sont synthétiques et sans valeur opérationnelle.")
        summary = (
            f"{'[DÉMONSTRATION] ' if synthetic else ''}{initial} Le moteur de scoring estime un risque {risk_level} "
            f"({scoring.get('risk_score', '—')}/100) avec une confiance {conf_level} ({scoring.get('confidence_score', '—')}/100). "
            f"{len(ok)} résultat(s) OSINT exploitable(s) sur {len(results)} requête(s)"
            + (f", {len(contradictions)} contradiction(s)" if contradictions else "") + "."
        )
        return {
            "executive_summary": summary,
            "initial_event": initial,
            "observed_indicators": [{"indicator": i["value"], "type": i["type"],
                                     "note": f"rôle : {i['role']} — {i.get('scope_note') or i['scope']}"} for i in package["indicators"]],
            "osint_results": [{"source": r["source"],
                               "summary": f"{r['status']}" + (f" — {r['error']}" if r.get("error") else ""),
                               "evidence_ids": [r["id"]]} for r in results],
            "established_facts": facts,
            "hypotheses": hypotheses,
            "contradictions": contradictions,
            "missing_information": missing or ["Aucune information manquante identifiée par les règles."],
            "alternative_hypotheses": alternatives,
            "mitre_attack": mitre,
            "estimated_risk": {"level": risk_level, "rationale": "Facteurs principaux : " + (
                "; ".join(f"{f['label']} ({f['contribution']} pts) — {f['rationale']}" for f in top) or "aucun facteur documenté")},
            "confidence": {"level": conf_level, "rationale": "; ".join(
                c.get("rationale", "") for c in (package.get("scoring") or {}).get("confidence_factors", []) or []) or
                "Voir la décomposition du score de confiance."},
            "recommended_actions": actions,
            "references": [{"evidence_id": r["id"], "source": r["source"], "url": r.get("reference_url")} for r in ok],
            "limitations": limitations,
            "threat_actor_attribution": [],
        }
