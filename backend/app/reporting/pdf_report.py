"""PDF rendering (ReportLab). Technical and executive variants.

All dynamic text is XML-escaped before being passed to ReportLab paragraphs:
SIEM/OSINT data is untrusted and must not be interpreted as markup.
"""

from __future__ import annotations

import io
import math
import os
import sys
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Line, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import get_settings

NAVY = colors.HexColor("#0b1220")
BLUE = colors.HexColor("#1f6feb")
CYAN = colors.HexColor("#0891b2")
GREY = colors.HexColor("#475569")
LIGHT = colors.HexColor("#e2e8f0")
PROVENANCE_LABEL = {
    "observed": "Donnée observée (SIEM)",
    "third_party": "Information de sources tierces (OSINT)",
    "computed": "Calcul déterministe MAKKADi",
    "ai_generated": "Contenu généré par le module d'analyse (IA)",
}

_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"
_UNICODE = False


def _register_fonts() -> None:
    global _FONT, _FONT_BOLD, _UNICODE
    if _UNICODE:
        return
    candidates = [
        ("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("Arial", os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
         os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arialbd.ttf")),
    ]
    if getattr(sys, "_MEIPASS", None):
        base = Path(sys._MEIPASS) / "fonts"  # type: ignore[attr-defined]
        candidates.insert(0, ("DejaVuSans", str(base / "DejaVuSans.ttf"), str(base / "DejaVuSans-Bold.ttf")))
    for name, regular, bold in candidates:
        if Path(regular).is_file() and Path(bold).is_file():
            try:
                pdfmetrics.registerFont(TTFont(name, regular))
                pdfmetrics.registerFont(TTFont(name + "-Bold", bold))
            except Exception:  # noqa: BLE001
                continue
            _FONT, _FONT_BOLD, _UNICODE = name, name + "-Bold", True
            return


_TRANSLIT = {"\u2192": " vers ", "\u2260": " différent de ", "\u2265": ">=", "\u2264": "<=", "\u2713": "", "\u2022": "",
             "\u2026": "...", "\u2019": "'", "\u2014": ",", "\u2013": ","}


def _t(value: Any, max_len: int = 1500) -> str:
    text = "N/D" if value is None or value == "" else str(value)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    if not _UNICODE:
        for k, v in _TRANSLIT.items():
            text = text.replace(k, v)
        text = text.encode("latin-1", "replace").decode("latin-1")
    return escape(text)


class _Styles:
    def __init__(self) -> None:
        base = getSampleStyleSheet()
        self.h1 = ParagraphStyle("h1", parent=base["Heading1"], fontName=_FONT_BOLD, textColor=NAVY, fontSize=18, spaceAfter=6)
        self.h2 = ParagraphStyle("h2", parent=base["Heading2"], fontName=_FONT_BOLD, textColor=BLUE, fontSize=13, spaceBefore=10, spaceAfter=4)
        self.body = ParagraphStyle("body", parent=base["BodyText"], fontName=_FONT, fontSize=9, leading=12, alignment=TA_LEFT)
        self.small = ParagraphStyle("small", parent=self.body, fontSize=7.5, leading=9.5, textColor=GREY)
        self.tag = ParagraphStyle("tag", parent=self.small, textColor=CYAN, fontName=_FONT_BOLD)
        self.warn = ParagraphStyle("warn", parent=self.body, textColor=colors.HexColor("#b45309"), fontName=_FONT_BOLD)


def _table(rows: list[list[Any]], widths: list[float], st: _Styles, header: bool = True) -> Table:
    data = [[Paragraph(_t(c, 600), st.small if i else st.small) for c in row] for i, row in enumerate(rows)]
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe"))]
    table.setStyle(TableStyle(style))
    return table


def _graph(relations: list[dict[str, Any]], width: float = 17 * cm, height: float = 11 * cm) -> Drawing:
    nodes: list[str] = []
    for r in relations:
        for n in (r["from"], r["to"]):
            if n not in nodes:
                nodes.append(n)
    nodes = nodes[:40]
    d = Drawing(width, height)
    if not nodes:
        d.add(String(10, height / 2, "Aucune relation", fontName=_FONT, fontSize=9))
        return d
    cx, cy, radius = width / 2, height / 2, min(width, height) / 2 - 1.2 * cm
    pos = {n: (cx + radius * math.cos(2 * math.pi * i / len(nodes)), cy + radius * math.sin(2 * math.pi * i / len(nodes)))
           for i, n in enumerate(nodes)}
    palette = {"event": colors.HexColor("#f59e0b"), "ip": BLUE, "domain": CYAN, "asn": colors.HexColor("#7c3aed"),
               "organisation": colors.HexColor("#64748b"), "campaign": colors.HexColor("#dc2626"),
               "certificate": colors.HexColor("#059669"), "host": colors.HexColor("#0f172a")}
    for r in relations:
        if r["from"] in pos and r["to"] in pos:
            (x1, y1), (x2, y2) = pos[r["from"]], pos[r["to"]]
            d.add(Line(x1, y1, x2, y2, strokeColor=LIGHT if r["temporality"] != "historical" else colors.HexColor("#cbd5e1"),
                       strokeWidth=0.6, strokeDashArray=[2, 2] if r["temporality"] == "historical" else None))
    for n, (x, y) in pos.items():
        kind = n.split(":", 1)[0]
        d.add(Circle(x, y, 4, fillColor=palette.get(kind, GREY), strokeColor=colors.white, strokeWidth=0.5))
        label = n.split(":", 1)[1] if ":" in n else n
        label = (label[:28] + "...") if len(label) > 29 else label
        if not _UNICODE:
            label = label.encode("latin-1", "replace").decode("latin-1")
        anchor = "start" if x >= cx else "end"
        d.add(String(x + (6 if anchor == "start" else -6), y - 2.5, f"{kind}: {label}", fontName=_FONT, fontSize=5.5,
                     fillColor=NAVY, textAnchor=anchor))
    return d


def render_pdf(data: dict[str, Any]) -> bytes:
    _register_fonts()
    st = _Styles()
    buf = io.BytesIO()
    app = get_settings().app_name
    inv = data["investigation"]
    synthetic = data["contains_synthetic_data"]

    def on_page(canvas, doc) -> None:  # noqa: ANN001
        canvas.saveState()
        canvas.setFont(_FONT, 7)
        canvas.setFillColor(GREY)
        canvas.drawString(1.5 * cm, 1 * cm, f"{app}, {inv['reference']}, généré le {data['generated_at']} (UTC)")
        canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f"Page {doc.page}")
        if synthetic:
            canvas.setFillColor(colors.HexColor("#b45309"))
            canvas.setFont(_FONT_BOLD, 8)
            canvas.drawCentredString(A4[0] / 2, A4[1] - 1 * cm, "DONNÉES DE DÉMONSTRATION, SANS VALEUR OPÉRATIONNELLE"
                                     if _UNICODE else "DONNEES DE DEMONSTRATION - SANS VALEUR OPERATIONNELLE")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm, topMargin=1.6 * cm,
                            bottomMargin=1.6 * cm, title=f"{app} {inv['reference']}", author=app)
    story: list[Any] = []
    kind_label = "Rapport technique détaillé (analystes SOC)" if data["report_kind"] == "technical" else "Rapport de synthèse (responsables cybersécurité)"

    def section(n: int, title: str, provenance: str | None = None) -> None:
        story.append(Paragraph(_t(f"{n}. {title}"), st.h2))
        if provenance:
            story.append(Paragraph(_t(PROVENANCE_LABEL[provenance]), st.tag))

    ai = data["ai_analysis"]
    out = ai.get("output") or {}
    risk = data["risk_assessment"]
    corr = data["correlation"]

    story.append(Paragraph(_t(f"{app}, {kind_label}"), st.h1))
    if synthetic:
        story.append(Paragraph(_t("Ce rapport contient des DONNÉES DE DÉMONSTRATION synthétiques."), st.warn))
    section(1, "Identification de l'investigation")
    story.append(_table([["Référence", "Identifiant", "Statut", "Sévérité", "Créée le (UTC)"],
                         [inv["reference"], inv["id"], inv["status"], inv["severity"], inv["created_at"]]],
                        [3 * cm, 6 * cm, 2.6 * cm, 2 * cm, 4.4 * cm], st))
    story.append(Paragraph(_t(inv["title"]), st.body))

    section(2, "Résumé exécutif", "ai_generated")
    story.append(Paragraph(_t(out.get("executive_summary") or "Analyse IA indisponible : " + str(ai.get("error") or ai.get("status"))), st.body))
    story.append(Paragraph(_t(risk.get("summary")), st.body))

    section(3, "Contexte de l'alerte", "observed")
    rows = [["Source / ID d'origine", "Horodatage (UTC)", "Événement", "Sévérité", "Source et cible", "Tentatives"]]
    for e in data["alert_context"]["events"]:
        rows.append([f"{e['source_system']} / {e['original_id']}", e["event_time"], f"{e['title']} [{e['event_type']}]",
                     f"{e['severity']} ({e['severity_raw']})", f"{e['src_ip']} vers {e['hostname'] or e['dst_ip']}"
                     + (f":{e['dst_port']}/{e['protocol']}" if e["dst_port"] else ""), e["attempt_count"]])
    story.append(_table(rows, [3.6 * cm, 3 * cm, 4 * cm, 1.8 * cm, 3.6 * cm, 2 * cm], st))

    section(4, "Indicateurs", "computed")
    story.append(_table([["Type", "Valeur", "Rôle", "Portée"]] + [
        [i["type"], i["value"], i["role"], f"{i['scope']}, {i['note'] or ''}"] for i in data["indicators"]],
        [1.6 * cm, 5.5 * cm, 2.2 * cm, 8.7 * cm], st))

    section(5, "Résultats OSINT", "third_party")
    items = data["osint_results"]["items"]
    story.append(_table([["Preuve", "Source", "Indicateur", "Statut", "Consulté le (UTC)", "Donnée du", "Référence / erreur"]] + [
        [r["evidence_id"], r["source"] + (" [DÉMO]" if r["is_synthetic"] else ""), r["indicator"], r["status"],
         r["queried_at"], r["data_updated_at"], r["reference_url"] or r["error"] or ""] for r in items],
        [1.3 * cm, 2.6 * cm, 3 * cm, 1.7 * cm, 3 * cm, 2.6 * cm, 3.8 * cm], st))
    if data["report_kind"] == "technical":
        for f in (corr.get("facts") or [])[:60]:
            story.append(Paragraph(_t(f"{f['statement']} [{', '.join(f.get('evidence_ids', []))}]"), st.small))

    section(6, "Chronologie", "computed")
    tl = data["timeline"] if data["report_kind"] == "technical" else [t for t in data["timeline"] if t["kind"] != "osint_query"]
    story.append(_table([["Horodatage (UTC)", "Type", "Provenance", "Description"]] + [
        [t["ts"], t["kind"], PROVENANCE_LABEL.get(t["provenance"], t["provenance"]), f"{t['label']}, {t['detail']}"] for t in tl[:150]],
        [3.2 * cm, 2.6 * cm, 4 * cm, 8.2 * cm], st))

    section(7, "Graphe des relations", "third_party")
    story.append(Paragraph(_t(data["relations"]["disclaimer"] + " Traits pointillés : relations historiques."), st.small))
    story.append(KeepTogether([_graph(data["relations"]["items"])]))
    if data["report_kind"] == "technical":
        story.append(_table([["De", "Vers", "Nature", "Source", "Temporalité", "Preuve"]] + [
            [r["from"], r["to"], r["type"], r["source"], r["temporality"], r["evidence_id"]] for r in data["relations"]["items"][:120]],
            [3.8 * cm, 3.8 * cm, 3.4 * cm, 2.8 * cm, 2 * cm, 2.2 * cm], st))

    section(8, "Évaluation du risque", "computed")
    story.append(Paragraph(_t(f"Niveau de risque : {risk.get('risk_level')} ({risk.get('risk_score')}/100)"), st.body))
    story.append(_table([["Facteur", "Valeur", "Poids", "Contribution", "Justification"]] + [
        [f["label"], f["value"] if f["value"] is not None else "inconnu", f["weight"], f["contribution"], f["rationale"]]
        for f in risk.get("risk_factors", [])], [3.4 * cm, 1.6 * cm, 1.3 * cm, 2 * cm, 9.7 * cm], st))

    section(9, "Niveau de confiance", "computed")
    story.append(Paragraph(_t(f"Niveau de confiance : {risk.get('confidence_level')} ({risk.get('confidence_score')}/100)"), st.body))
    story.append(_table([["Composante", "Valeur", "Poids", "Justification"]] + [
        [c["label"], c["value"], c["weight"], c["rationale"]] for c in risk.get("confidence_factors", [])]
        + [[p["label"], "", "", f"{p['points']} points"] for p in risk.get("confidence_penalties", [])],
        [4 * cm, 1.6 * cm, 1.3 * cm, 11.1 * cm], st))
    for n in risk.get("notes", []):
        story.append(Paragraph(_t(f"{n}"), st.small))
    for c in corr.get("contradictions", []):
        story.append(Paragraph(_t(f"Contradiction, {c['indicator']} ({c['dimension']}) : {c['description']}"), st.small))

    section(10, "Analyse assistée par IA", "ai_generated")
    story.append(Paragraph(_t(f"Fournisseur : {ai.get('provider')} / modèle : {ai.get('model')} / statut : {ai.get('status')} / "
                              f"empreinte des données d'entrée : {ai.get('input_sha256')}"), st.small))
    if ai.get("injection_flags"):
        story.append(Paragraph(_t(f"{len(ai['injection_flags'])} tentative(s) d'injection détectée(s) dans les données et neutralisée(s)."), st.warn))
    for title, key in (("Faits établis", "established_facts"), ("Hypothèses à vérifier", "hypotheses")):
        if out.get(key):
            story.append(Paragraph(_t(title), st.body))
            for item in out[key][:40]:
                story.append(Paragraph(_t(f"{item['statement']} [{', '.join(item.get('evidence_ids', []))}]"), st.small))
    if out.get("mitre_attack"):
        story.append(Paragraph(_t("Techniques MITRE ATT&CK (hypothèses)"), st.body))
        for m in out["mitre_attack"]:
            story.append(Paragraph(_t(f"{m['technique_id']} {m['name']}, {m['justification']}"), st.small))
    if out.get("threat_actor_attribution"):
        for a in out["threat_actor_attribution"]:
            story.append(Paragraph(_t(f"Attribution (hypothèse, confiance {a['confidence']}) : {a['actor']} "
                                      f"[{', '.join(a['evidence_ids'])}], alternatives : {', '.join(a['alternatives'])}"), st.small))
    else:
        story.append(Paragraph(_t("Aucune attribution à un acteur de menace : éléments insuffisants."), st.small))

    section(11, "Hypothèses alternatives, éléments manquants et limites")
    for item in out.get("alternative_hypotheses", []):
        story.append(Paragraph(_t(f"Alternative : {item['statement']}, {item['rationale']}"), st.small))
    for m in (out.get("missing_information") or corr.get("missing") or []):
        story.append(Paragraph(_t(f"Manquant : {m}"), st.small))
    for lim in data["limitations"] + list(out.get("limitations", [])):
        story.append(Paragraph(_t(f"Limite : {lim}"), st.small))

    section(12, "Recommandations (soumises à validation humaine)", "ai_generated")
    for a in out.get("recommended_actions", []):
        story.append(Paragraph(_t(f"[{a['priority']}] {a['action']}"), st.body))
    if data["analyst_decisions"]:
        story.append(Paragraph(_t("Décisions de l'analyste"), st.body))
        for n in data["analyst_decisions"]:
            story.append(Paragraph(_t(f"{n['ts']}, {n['author']} ({n['kind']}) : {n['content']}"), st.small))

    section(13, "Références des sources", "third_party")
    for r in items:
        if r["status"] == "ok":
            story.append(Paragraph(_t(f"{r['evidence_id']}, {r['source']}, {r['reference_url'] or 'référence non fournie'} "
                                      f", consulté le {r['queried_at']}, sha256 brut : {r['raw_sha256'] or 'N/D'}"), st.small))

    section(14, "Horodatage et intégrité")
    story.append(Paragraph(_t(f"Rapport généré le {data['generated_at']} (UTC) par {data['generated_by']} avec "
                              f"{data['generator']['application']} {data['generator']['version']}. L'empreinte SHA-256 du "
                              "fichier est enregistrée dans la base et vérifiable depuis l'application."), st.body))
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


__all__ = ["render_pdf", "PageBreak", "Spacer"]
