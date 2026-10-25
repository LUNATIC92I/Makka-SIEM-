import { ChangeEvent, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, ConfidenceBadge, Empty, ErrorBox, LevelBadge, SeverityBadge, Spinner, SyntheticTag } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate, STATUS_LABELS } from "../lib/format";
import { api, qs } from "../services/api";
import type { InvestigationSummary } from "../types";

const EMPTY = { date_from: "", date_to: "", ip: "", domain: "", indicator_type: "", source_system: "", severity: "", status: "", confidence_level: "", q: "" };

export default function InvestigationsPage() {
  const nav = useNavigate();
  const { can } = useAuth();
  const [filters, setFilters] = useState(EMPTY);
  const [applied, setApplied] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const path = useMemo(() => "/investigations" + qs({
    ...applied, date_from: applied.date_from ? `${applied.date_from}T00:00:00Z` : "", date_to: applied.date_to ? `${applied.date_to}T23:59:59Z` : "", page, page_size: 25,
  }), [applied, page]);
  const { data, error, loading, reload } = useApi<{ total: number; items: InvestigationSummary[] }>(path, { refreshMs: 8000 });

  const set = (k: keyof typeof EMPTY) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setFilters({ ...filters, [k]: e.target.value });

  const upload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErr(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await api.upload<{ created: number; duplicates: number; investigations_created: number }>("/ingest/file", form);
      setMsg(`${r.created} événement(s) importé(s), ${r.duplicates} doublon(s), ${r.investigations_created} investigation(s) créée(s).`);
      reload();
    } catch (ex) { setErr(ex); }
    e.target.value = "";
  };

  const manual = async () => {
    const value = window.prompt("Indicateur à investiguer (IP, domaine, URL ou empreinte) :");
    if (!value) return;
    const v = value.trim();
    const type = /^[0-9.]+$/.test(v) ? "ipv4" : v.includes(":") && !v.includes("/") ? "ipv6" : /^https?:\/\//i.test(v) ? "url"
      : /^[a-f0-9]{64}$/i.test(v) ? "sha256" : /^[a-f0-9]{40}$/i.test(v) ? "sha1" : /^[a-f0-9]{32}$/i.test(v) ? "md5" : "domain";
    try {
      const inv = await api.post<InvestigationSummary>("/investigations", { title: `Investigation manuelle — ${v}`, indicators: [{ type, value: v }] });
      nav(`/investigations/${inv.id}`);
    } catch (ex) { setErr(ex); }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-50">Centre d'investigation</h1>
          <p className="text-sm text-slate-400">{data?.total ?? "…"} investigation(s)</p>
        </div>
        {can("ingest:write") && (
          <div className="flex gap-2">
            <label className="btn-ghost cursor-pointer">Importer des événements JSON<input type="file" accept="application/json,.json" className="hidden" onChange={upload} /></label>
            <button className="btn-primary" onClick={manual}>Nouvelle investigation</button>
          </div>
        )}
      </div>
      {msg && <div className="rounded-lg border border-emerald-700/60 bg-emerald-950/30 p-3 text-sm text-emerald-200">{msg}</div>}
      <ErrorBox error={err} />

      <Card>
        <form className="grid grid-cols-2 gap-3 md:grid-cols-5 xl:grid-cols-10" onSubmit={(e) => { e.preventDefault(); setPage(1); setApplied(filters); }}>
          <div className="xl:col-span-2"><label className="label">Recherche</label><input className="input" placeholder="Titre ou référence" value={filters.q} onChange={set("q")} /></div>
          <div><label className="label">Du</label><input type="date" className="input" value={filters.date_from} onChange={set("date_from")} /></div>
          <div><label className="label">Au</label><input type="date" className="input" value={filters.date_to} onChange={set("date_to")} /></div>
          <div><label className="label">Adresse IP</label><input className="input mono" value={filters.ip} onChange={set("ip")} /></div>
          <div><label className="label">Domaine</label><input className="input mono" value={filters.domain} onChange={set("domain")} /></div>
          <div><label className="label">Type d'indicateur</label>
            <select className="input" value={filters.indicator_type} onChange={set("indicator_type")}>
              <option value="">Tous</option>{["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"].map((t) => <option key={t}>{t}</option>)}
            </select></div>
          <div><label className="label">Source SIEM</label><input className="input" value={filters.source_system} onChange={set("source_system")} /></div>
          <div><label className="label">Sévérité</label>
            <select className="input" value={filters.severity} onChange={set("severity")}>
              <option value="">Toutes</option>{["info", "low", "medium", "high", "critical", "unknown"].map((t) => <option key={t}>{t}</option>)}
            </select></div>
          <div><label className="label">Statut</label>
            <select className="input" value={filters.status} onChange={set("status")}>
              <option value="">Tous</option>{Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select></div>
          <div><label className="label">Confiance</label>
            <select className="input" value={filters.confidence_level} onChange={set("confidence_level")}>
              <option value="">Toutes</option>{["faible", "moyenne", "élevée"].map((t) => <option key={t}>{t}</option>)}
            </select></div>
          <div className="col-span-2 flex items-end gap-2 md:col-span-5 xl:col-span-10">
            <button className="btn-primary" type="submit">Filtrer</button>
            <button className="btn-ghost" type="button" onClick={() => { setFilters(EMPTY); setApplied(EMPTY); }}>Réinitialiser</button>
          </div>
        </form>
      </Card>

      <Card>
        {loading && !data ? <Spinner /> : error ? <ErrorBox error={error} /> : !data?.items.length ? <Empty>Aucune investigation ne correspond aux filtres.</Empty> : (
          <>
            <div className="overflow-x-auto">
              <table className="table">
                <thead><tr><th>Référence</th><th>Titre</th><th>Source</th><th>Cible</th><th>Sévérité</th><th>Risque</th><th>Confiance</th><th>Statut</th><th>Traitement</th><th>Créée (UTC)</th></tr></thead>
                <tbody>
                  {data.items.map((i) => (
                    <tr key={i.id} className="cursor-pointer" onClick={() => nav(`/investigations/${i.id}`)}>
                      <td className="mono whitespace-nowrap text-cyanx-300">{i.reference}{i.restricted && <span title="Accès restreint"> 🔒</span>}</td>
                      <td className="max-w-[380px]"><div className="truncate">{i.title}</div>{i.is_synthetic && <SyntheticTag />}</td>
                      <td className="mono">{i.src_ip ?? "—"}<div className="text-xs text-slate-500">{i.source_system}</div></td>
                      <td>{i.target ?? "—"}</td>
                      <td><SeverityBadge severity={i.severity} /></td>
                      <td><LevelBadge level={i.risk_level} score={i.risk_score} /></td>
                      <td><ConfidenceBadge level={i.confidence_level} score={i.confidence_score} /></td>
                      <td className="whitespace-nowrap text-slate-300">{STATUS_LABELS[i.status] ?? i.status}</td>
                      <td className={i.pipeline_status === "running" || i.pipeline_status === "pending" ? "pulse-soft text-cyanx-300" : i.pipeline_status === "partial" ? "text-amber-300" : "text-slate-400"}>{i.pipeline_status}</td>
                      <td className="mono whitespace-nowrap text-slate-400">{fmtDate(i.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-end gap-2 text-sm">
              <button className="btn-ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>Précédent</button>
              <span className="text-slate-400">Page {page} / {Math.max(1, Math.ceil(data.total / 25))}</span>
              <button className="btn-ghost" disabled={page * 25 >= data.total} onClick={() => setPage(page + 1)}>Suivant</button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
