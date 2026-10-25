import { Card, Empty, ErrorBox, Pill, Spinner } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate } from "../lib/format";
import { api } from "../services/api";
import type { Task } from "../types";

const TONE: Record<string, string> = { pending: "border-electric-600 text-electric-400", running: "border-cyan-600 text-cyanx-300 pulse-soft", succeeded: "border-emerald-700 text-emerald-300", failed: "border-rose-700 text-rose-300", dead: "border-rose-700 text-rose-300" };

export default function TasksPage() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<{ counts: Record<string, number>; items: Task[] }>("/tasks?limit=200", { refreshMs: 4000 });
  if (loading && !data) return <Spinner />;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-slate-50">File de tâches</h1>
      <p className="text-sm text-slate-400">Collecte SIEM, enrichissements et purges. Les tâches interrompues sont reprises au redémarrage ; les échecs sont relancés avec temporisation exponentielle.</p>
      <div className="flex flex-wrap gap-2">{Object.entries(data?.counts ?? {}).map(([k, v]) => <Pill key={k} className={TONE[k] ?? "border-ink-500"}>{k} : {v}</Pill>)}</div>
      <ErrorBox error={error} />
      <Card>
        {!data?.items.length ? <Empty>File vide.</Empty> : (
          <table className="table">
            <thead><tr><th>#</th><th>Type</th><th>Statut</th><th>Tentatives</th><th>Prochaine exécution</th><th>Créée</th><th>Dernière erreur</th><th /></tr></thead>
            <tbody>{data.items.map((t) => (
              <tr key={t.id}>
                <td className="mono">{t.id}</td><td>{t.type}<div className="mono text-[11px] text-slate-500">{JSON.stringify(t.payload)}</div></td>
                <td><Pill className={TONE[t.status] ?? ""}>{t.status}</Pill></td><td>{t.attempts}/{t.max_attempts}</td>
                <td className="mono text-xs">{fmtDate(t.next_run_at)}</td><td className="mono text-xs">{fmtDate(t.created_at)}</td>
                <td className="max-w-[320px] text-xs text-rose-300">{t.last_error}</td>
                <td>{can("tasks:write") && (t.status === "failed" || t.status === "dead") && <button className="btn-ghost" onClick={async () => { await api.post(`/tasks/${t.id}/retry`); reload(); }}>Relancer</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
