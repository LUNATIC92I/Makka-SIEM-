import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, ConfidenceBadge, Empty, ErrorBox, LevelBadge, SeverityBadge, Spinner, Stat, SyntheticTag } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate, fmtRelative } from "../lib/format";
import { api } from "../services/api";
import type { InvestigationSummary } from "../types";
import { useState } from "react";

interface Dashboard {
  counts: Record<string, number>;
  risk_distribution: Record<string, number>;
  confidence_distribution: Record<string, number>;
  per_day: { date: string; count: number }[];
  priority_investigations: InvestigationSummary[];
  recent_alerts: { id: number; title: string; severity: string; src_ip: string | null; hostname: string | null; event_time: string | null; source_system: string; is_synthetic: boolean }[];
  connectors: { name: string; kind: string; state: string; last_error: string | null; display_name: string }[];
  activities: { ts: string; actor: string; action: string; target: string }[];
  demo_mode: boolean;
}

const RISK_COLORS: Record<string, string> = { critique: "#f43f5e", "élevé": "#fb923c", "modéré": "#fbbf24", faible: "#38bdf8", "indéterminé": "#64748b", "en attente": "#33415c" };
const tooltipStyle = { background: "#0e131c", border: "1px solid #243047", borderRadius: 8, color: "#e2e8f0", fontSize: 12 };

export default function OverviewPage() {
  const { data, error, loading, reload } = useApi<Dashboard>("/dashboard", { refreshMs: 10000 });
  const { can } = useAuth();
  const nav = useNavigate();
  const [busy, setBusy] = useState(false);

  const loadDemo = async () => {
    setBusy(true);
    try { await api.post("/ingest/demo"); await reload(); } finally { setBusy(false); }
  };

  if (loading && !data) return <Spinner />;
  if (!data) return <ErrorBox error={error} />;
  const riskData = Object.entries(data.risk_distribution).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-50">Vue d'ensemble</h1>
          <p className="text-sm text-slate-400">Activité des investigations et état de la collecte</p>
        </div>
        {data.demo_mode && can("ingest:write") && (
          <button className="btn-primary" onClick={loadDemo} disabled={busy}>
            {busy ? "Ingestion…" : "Charger le scénario de démonstration"}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="Investigations" value={data.counts.investigations} hint={`${data.counts.open} ouvertes`} />
        <Stat label="Événements SIEM" value={data.counts.events} />
        <Stat label="Indicateurs" value={data.counts.indicators} />
        <Stat label="En cours d'analyse" value={data.counts.indicators_in_analysis} tone="text-cyanx-300" hint="indicateurs" />
        <Stat label="File de tâches" value={data.counts.tasks_in_queue} hint="en attente / en cours" />
        <Stat label="Connecteurs actifs" value={data.connectors.length} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Investigations prioritaires" className="xl:col-span-2">
          {data.priority_investigations.length === 0 ? <Empty>Aucune investigation ouverte.</Empty> : (
            <div className="overflow-x-auto"><table className="table">
              <thead><tr><th>Référence</th><th>Titre</th><th>Risque</th><th>Confiance</th><th>Créée</th></tr></thead>
              <tbody>
                {data.priority_investigations.map((i) => (
                  <tr key={i.id} className="cursor-pointer" onClick={() => nav(`/investigations/${i.id}`)}>
                    <td className="mono whitespace-nowrap text-cyanx-300">{i.reference}</td>
                    <td className="max-w-[360px] truncate">{i.title} {i.is_synthetic && <SyntheticTag />}</td>
                    <td><LevelBadge level={i.risk_level} score={i.risk_score} /></td>
                    <td><ConfidenceBadge level={i.confidence_level} score={i.confidence_score} /></td>
                    <td className="whitespace-nowrap text-slate-400">{fmtRelative(i.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </Card>
        <Card title="Répartition des niveaux de risque (ouvertes)">
          {riskData.length === 0 ? <Empty>Pas encore de données.</Empty> : (
            <div className="h-56">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={riskData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2} stroke="none">
                    {riskData.map((d) => <Cell key={d.name} fill={RISK_COLORS[d.name] ?? "#64748b"} />)}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
          <div className="mt-2 flex flex-wrap gap-3 text-xs">
            {riskData.map((d) => <span key={d.name} className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: RISK_COLORS[d.name] ?? "#64748b" }} />{d.name} ({d.value})</span>)}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Alertes récentes" className="xl:col-span-2">
          {data.recent_alerts.length === 0 ? <Empty>Aucune alerte ingérée. Configurez un connecteur SIEM ou importez un fichier JSON.</Empty> : (
            <table className="table">
              <thead><tr><th>Horodatage (UTC)</th><th>Événement</th><th>Source</th><th>Cible</th><th>Sévérité</th></tr></thead>
              <tbody>
                {data.recent_alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="mono text-slate-400">{fmtDate(a.event_time)}</td>
                    <td>{a.title} {a.is_synthetic && <SyntheticTag />}</td>
                    <td className="mono text-cyanx-300">{a.src_ip ?? "—"}</td>
                    <td>{a.hostname ?? "—"}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Investigations créées (14 jours)">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={data.per_day}>
                <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(d: string) => d.slice(5)} />
                <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} width={28} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2333" }} />
                <Bar dataKey="count" name="Investigations" fill="#2f6bff" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="État des connecteurs" actions={<Link to="/connectors" className="text-xs text-cyanx-400">Configurer</Link>}>
          {data.connectors.length === 0 ? <Empty>Aucun connecteur activé. {data.demo_mode ? "Seules les sources synthétiques de démonstration sont utilisées." : ""}</Empty> : (
            <ul className="divide-y divide-ink-800 text-sm">
              {data.connectors.map((c) => (
                <li key={c.name} className="flex items-center justify-between py-2">
                  <span><span className="text-slate-500">{c.kind.toUpperCase()}</span> · {c.display_name}</span>
                  <span className={c.state.startsWith("opérationnel") ? "text-emerald-300" : c.state === "en erreur" ? "text-rose-300" : "text-amber-300"} title={c.last_error ?? ""}>{c.state}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Dernières activités">
          {data.activities.length === 0 ? <Empty>—</Empty> : (
            <ul className="space-y-1.5 text-sm">
              {data.activities.map((a, idx) => (
                <li key={idx} className="flex gap-3"><span className="mono w-40 shrink-0 text-slate-500">{fmtDate(a.ts)}</span><span className="text-slate-300">{a.action}</span><span className="truncate text-slate-500">{a.actor} {a.target}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
