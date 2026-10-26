import cytoscape, { Core } from "cytoscape";
import { useEffect, useRef, useState } from "react";
import type { Relation } from "../types";
import { fmtDate } from "../lib/format";

const KIND_COLORS: Record<string, string> = {
  event: "#f59e0b", ip: "#2f6bff", domain: "#22d3ee", url: "#67e8f9", asn: "#a78bfa", organisation: "#94a3b8",
  campaign: "#f43f5e", certificate: "#34d399", host: "#e2e8f0", md5: "#fb923c", sha1: "#fb923c", sha256: "#fb923c",
};
export const RELATION_LABELS: Record<string, string> = {
  observed_as_source: "source de l'événement", observed_as_destination: "destination de l'événement", observed_in_event: "observé dans l'événement",
  targets_host: "cible", registered_to: "bloc enregistré au nom de", announced_by_asn: "annoncé par l'ASN",
  dns_resolution_observed: "résolution DNS observée", passive_dns_current: "DNS passif (actuel)", passive_dns_historical: "DNS passif (historique)",
  certificate_observed: "certificat observé", certificate_shared_san_current: "certificat partagé (actuel)",
  certificate_shared_san_historical: "certificat partagé (historique)", associated_by_source: "association déclarée par une source",
  malware_url_hosted: "URL malveillante hébergée", nameserver_declared: "serveur de noms déclaré",
};

export default function InvestigationGraph({ relations, height = 520 }: { relations: Relation[]; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [selected, setSelected] = useState<{ kind: "node" | "edge"; data: Record<string, unknown> } | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const nodes = new Map<string, { id: string; kind: string; label: string }>();
    relations.forEach((r) => {
      [[r.from_kind, r.from_value], [r.to_kind, r.to_value]].forEach(([k, v]) => {
        const id = `${k}:${v}`;
        if (!nodes.has(id)) nodes.set(id, { id, kind: k, label: v.length > 34 ? v.slice(0, 33) + "..." : v });
      });
    });
    cy.current = cytoscape({
      container: ref.current,
      elements: [
        ...[...nodes.values()].map((n) => ({ data: { ...n, color: KIND_COLORS[n.kind] ?? "#64748b" } })),
        ...relations.map((r) => ({
          data: { ...r, rel_source: r.source, id: `e${r.id}`, source: `${r.from_kind}:${r.from_value}`,
                  target: `${r.to_kind}:${r.to_value}`, label: RELATION_LABELS[r.relation_type] ?? r.relation_type },
        })),
      ],
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(label)", color: "#cbd5e1", "font-size": 9,
          "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18, "border-width": 2, "border-color": "#0a0e15" } },
        { selector: "node[kind = 'event']", style: { shape: "diamond", width: 24, height: 24 } },
        { selector: "node[kind = 'campaign']", style: { shape: "hexagon" } },
        { selector: "edge", style: { width: 1.2, "line-color": "#33415c", "target-arrow-color": "#33415c", "target-arrow-shape": "triangle",
          "curve-style": "bezier", label: "data(label)", "font-size": 7, color: "#64748b", "text-rotation": "autorotate" } },
        { selector: "edge[temporality = 'historical']", style: { "line-style": "dashed" } },
        { selector: ":selected", style: { "border-color": "#22d3ee", "line-color": "#22d3ee", "target-arrow-color": "#22d3ee" } },
      ],
      layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: () => 40000, idealEdgeLength: () => 140, nodeOverlap: 20, componentSpacing: 120 } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.3,
    });
    cy.current.on("tap", "node", (e) => setSelected({ kind: "node", data: e.target.data() }));
    cy.current.on("tap", "edge", (e) => setSelected({ kind: "edge", data: e.target.data() }));
    cy.current.on("tap", (e) => { if (e.target === cy.current) setSelected(null); });
    return () => cy.current?.destroy();
  }, [relations]);

  const d = selected?.data ?? {};
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
      <div ref={ref} style={{ height }} className="rounded-lg border border-ink-700 bg-ink-950" aria-label="Graphe des relations" />
      <div className="space-y-3 text-sm">
        <div className="rounded-lg border border-ink-700 p-3 text-xs text-slate-400">
          Les liens sont des <strong>observations qualifiées</strong> rapportées par une source. Ils ne constituent pas une preuve de
          causalité. Pointillés : relation historique.
        </div>
        <div className="flex flex-wrap gap-2 text-[11px]">
          {Object.entries(KIND_COLORS).slice(0, 10).map(([k, c]) => (
            <span key={k} className="inline-flex items-center gap-1 text-slate-400"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />{k}</span>
          ))}
        </div>
        {selected ? (
          <div className="rounded-lg border border-ink-700 p-3">
            {selected.kind === "node" ? (
              <>
                <div className="text-xs uppercase text-slate-500">{String(d.kind)}</div>
                <div className="mono break-all text-cyanx-300">{String(d.id).split(":").slice(1).join(":")}</div>
                <div className="mt-2 text-xs text-slate-500">Cliquez sur un lien pour voir sa source et sa date d'observation.</div>
              </>
            ) : (
              <dl className="space-y-1 text-xs">
                <div><dt className="text-slate-500">Nature</dt><dd className="text-slate-200">{String(d.label)}</dd></div>
                <div><dt className="text-slate-500">Source</dt><dd>{String(d.rel_source)}{d.is_synthetic ? " (démonstration)" : ""}</dd></div>
                <div><dt className="text-slate-500">Observé le</dt><dd>{fmtDate(d.observed_at as string)}</dd></div>
                <div><dt className="text-slate-500">Temporalité</dt><dd>{String(d.temporality)}</dd></div>
                <div><dt className="text-slate-500">Confiance du lien</dt><dd>{String(d.confidence)}</dd></div>
                <div><dt className="text-slate-500">Preuve</dt><dd className="mono">{String(d.evidence_id ?? "événement SIEM")}</dd></div>
              </dl>
            )}
          </div>
        ) : (
          <div className="text-xs text-slate-500">Sélectionnez un nœud ou un lien.</div>
        )}
      </div>
    </div>
  );
}
