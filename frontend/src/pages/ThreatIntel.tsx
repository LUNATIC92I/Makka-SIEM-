import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, Mono, Pill, ResultStatusPill, Spinner } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { fmtDate, VERDICT_LABELS, verdictTone } from "../lib/format";
import { qs } from "../services/api";
import type { EnrichmentResult } from "../types";

interface IndicatorRow { id: number; type: string; value: string; scope: string; first_seen: string; last_seen: string; results: number; verdicts: Record<string, number>; investigations: number; has_synthetic: boolean }
interface IndicatorDetail { id: number; type: string; value: string; scope: string; classification: Record<string, unknown>; investigations: { id: string; reference: string; title: string; risk_level: string | null }[]; history: EnrichmentResult[] }

export default function ThreatIntelPage() {
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [applied, setApplied] = useState({ q: "", type: "" });
  const [selected, setSelected] = useState<number | null>(null);
  const { data, error, loading } = useApi<{ total: number; items: IndicatorRow[] }>("/indicators" + qs({ ...applied, page_size: 100 }));
  const detail = useApi<IndicatorDetail>(selected ? `/indicators/${selected}` : null);
  const { data: sources } = useApi<{ name: string; display_name?: string; enabled: boolean; state: string; category?: string; reliability?: number; upstream_group?: string }[]>("/connectors");

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-slate-50">Threat Intelligence</h1>
      <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
        <Card title={`Indicateurs connus (${data?.total ?? "…"})`} actions={
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); setApplied({ q, type }); }}>
            <input className="input w-48" placeholder="Rechercher" value={q} onChange={(e) => setQ(e.target.value)} />
            <select className="input w-28" value={type} onChange={(e) => setType(e.target.value)}><option value="">Tous</option>{["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"].map((t) => <option key={t}>{t}</option>)}</select>
            <button className="btn-ghost">OK</button>
          </form>}>
          {loading && !data ? <Spinner /> : error ? <ErrorBox error={error} /> : !data?.items.length ? <Empty>Aucun indicateur.</Empty> : (
            <table className="table">
              <thead><tr><th>Type</th><th>Valeur</th><th>Portée</th><th>Verdicts des sources</th><th>Invest.</th><th>Vu pour la dernière fois</th></tr></thead>
              <tbody>{data.items.map((i) => (
                <tr key={i.id} className={`cursor-pointer ${selected === i.id ? "bg-ink-800" : ""}`} onClick={() => setSelected(i.id)}>
                  <td><Pill className="border-ink-500 text-slate-400">{i.type}</Pill></td>
                  <td className="mono max-w-[320px] truncate text-cyanx-300">{i.value}{i.has_synthetic && <span className="ml-1 text-[10px] text-amber-300">DÉMO</span>}</td>
                  <td className={i.scope === "public" ? "text-emerald-300" : "text-amber-300"}>{i.scope}</td>
                  <td className="text-xs">{Object.entries(i.verdicts).map(([v, n]) => <span key={v} className={`mr-2 ${verdictTone(v)}`}>{VERDICT_LABELS[v] ?? v} ×{n}</span>)}{!Object.keys(i.verdicts).length && <span className="text-slate-500">—</span>}</td>
                  <td>{i.investigations}</td><td className="mono text-xs text-slate-400">{fmtDate(i.last_seen)}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
        <div className="space-y-4">
          <Card title="Historique des observations">
            {!selected ? <Empty>Sélectionnez un indicateur.</Empty> : detail.loading ? <Spinner /> : detail.data && (
              <div className="space-y-3 text-sm">
                <Mono value={detail.data.value} />
                <div className="text-xs text-slate-500">{String(detail.data.classification.note ?? "")}</div>
                <div>{detail.data.investigations.map((i) => <Link key={i.id} to={`/investigations/${i.id}`} className="mr-2 mono text-xs text-cyanx-400">{i.reference}</Link>)}</div>
                <ul className="max-h-[480px] space-y-2 overflow-auto">{detail.data.history.map((r) => (
                  <li key={r.id} className="rounded border border-ink-700 p-2">
                    <div className="flex items-center gap-2"><span className="text-slate-200">{r.source_display}</span><ResultStatusPill status={r.status} /></div>
                    <div className="text-xs text-slate-500">consulté {fmtDate(r.queried_at)} · donnée du {fmtDate(r.data_updated_at)}</div>
                    {r.findings.reputation && <div className={`text-xs ${verdictTone(r.findings.reputation.verdict)}`}>{VERDICT_LABELS[r.findings.reputation.verdict]} {r.findings.reputation.raw_score}</div>}
                  </li>
                ))}</ul>
              </div>
            )}
          </Card>
          <Card title="Sources de renseignement">
            <ul className="space-y-1 text-xs">{(sources ?? []).filter((s) => s.category).map((s) => (
              <li key={s.name} className="flex justify-between gap-2"><span className="text-slate-300">{s.display_name}</span><span className="text-slate-500">{s.category} · fiab. {s.reliability} · {s.enabled ? s.state : "désactivée"}</span></li>
            ))}</ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
