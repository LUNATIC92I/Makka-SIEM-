import GlitchText from "../fx/GlitchText";
import { useEffect, useState } from "react";
import { Card, ErrorBox, Pill, Spinner, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate } from "../lib/format";
import PasswordDialog from "../components/PasswordDialog";
import { api } from "../services/api";
import type { User } from "../types";

type Key = "scoring" | "ingestion" | "assets" | "retention" | "users" | "audit" | "system";
type SettingsData = Record<string, Record<string, any>>; // eslint-disable-line @typescript-eslint/no-explicit-any

export default function SettingsPage() {
  const { can } = useAuth();
  const [tab, setTab] = useState<Key>("scoring");
  const { data, error, loading, reload } = useApi<SettingsData>("/settings");
  if (loading && !data) return <Spinner />;
  if (!data) return <ErrorBox error={error} />;
  const tabs: { key: Key; label: string }[] = [
    { key: "scoring", label: "Seuils et pondérations" }, { key: "ingestion", label: "Règles d'ingestion" },
    { key: "assets", label: "Criticité des actifs" }, { key: "retention", label: "Rétention" },
    ...(can("users:manage") ? [{ key: "users" as Key, label: "Utilisateurs et rôles" }] : []),
    ...(can("audit:read") ? [{ key: "audit" as Key, label: "Audit" }] : []),
    { key: "system", label: "Système" },
  ];
  const ro = !can("settings:write");
  return (
    <div className="space-y-4">
      <GlitchText className="text-2xl font-semibold text-slate-50">Paramètres</GlitchText>
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "scoring" && <ScoringEditor value={data.scoring} readOnly={ro} onSaved={reload} />}
      {tab === "ingestion" && <JsonEditor title="Règles d'ingestion" k="ingestion" value={data.ingestion} readOnly={ro} onSaved={reload}
        help="auto_investigate_min_severity : seuil de création automatique (info|low|medium|high|critical). group_window_minutes / group_by_source_ip : regroupement des événements d'une même source dans une investigation ouverte. max_events_per_poll : taille des lots de collecte." />}
      {tab === "assets" && <JsonEditor title="Criticité des actifs" k="assets" value={data.assets} readOnly={ro} onSaved={reload}
        help="patterns : motifs (fnmatch) sur le nom d'hôte ou l'IP de destination, valeurs : low, medium, high, critical. default_criticality s'applique aux cibles non référencées." />}
      {tab === "retention" && <JsonEditor title="Politique de conservation" k="retention" value={data.retention} readOnly={ro} onSaved={reload}
        help="Durées en jours : investigations clôturées, événements bruts non rattachés, tâches terminées. Les journaux d'audit ne sont jamais purgés automatiquement." extra={!ro && <button className="btn-ghost" onClick={async () => { const r = await api.post<Record<string, number>>("/admin/retention/run"); alert(`Purge : ${JSON.stringify(r)}`); }}>Lancer la purge maintenant</button>} />}
      {tab === "users" && <UsersAdmin />}
      {tab === "audit" && <AuditView />}
      {tab === "system" && <Card title="Configuration d'exécution (lecture seule, variables MAKKADI_* / fichier .env)"><pre className="text-xs text-slate-300">{JSON.stringify(data.runtime, null, 2)}</pre></Card>}
    </div>
  );
}

function ScoringEditor({ value, readOnly, onSaved }: { value: Record<string, any>; readOnly: boolean; onSaved: () => void }) { // eslint-disable-line @typescript-eslint/no-explicit-any
  const [weights, setWeights] = useState<Record<string, number>>(value.risk_weights);
  const [risk, setRisk] = useState<Record<string, number>>(value.risk_levels);
  const [conf, setConf] = useState<Record<string, number>>(value.confidence_levels);
  const [stale, setStale] = useState<number>(value.stale_after_days);
  const [err, setErr] = useState<unknown>(null);
  const [ok, setOk] = useState(false);
  const save = async () => {
    setErr(null); setOk(false);
    try { await api.put("/settings/scoring", { value: { risk_weights: weights, risk_levels: risk, confidence_levels: conf, stale_after_days: stale } }); setOk(true); onSaved(); } catch (e) { setErr(e); }
  };
  const num = (obj: Record<string, number>, set: (v: Record<string, number>) => void, step = 0.05) => Object.entries(obj).map(([k, v]) => (
    <div key={k}><label className="label">{k}</label><input type="number" step={step} className="input mono" disabled={readOnly} value={v} onChange={(e) => set({ ...obj, [k]: Number(e.target.value) })} /></div>
  ));
  return (
    <Card title="Mécanisme de scoring">
      <p className="mb-4 text-xs text-slate-400">Le <b>risque</b> est la moyenne pondérée des facteurs connus (les facteurs inconnus sont exclus et réduisent la confiance). La <b>confiance</b> mesure la solidité des preuves : sources indépendantes effectives (même amont compté une fois), couverture des dimensions, pénalités pour contradictions, données obsolètes et erreurs. Voir docs/SCORING.md.</p>
      <h3 className="mb-2 text-sm font-semibold">Pondérations des facteurs de risque (de 0 à 1)</h3>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">{num(weights, setWeights)}</div>
      <h3 className="mb-2 mt-4 text-sm font-semibold">Seuils des niveaux de risque (de 0 à 100)</h3>
      <div className="grid grid-cols-3 gap-3 md:grid-cols-6">{num(risk, setRisk, 1)}</div>
      <h3 className="mb-2 mt-4 text-sm font-semibold">Seuils des niveaux de confiance (de 0 à 100)</h3>
      <div className="grid grid-cols-3 gap-3 md:grid-cols-6">{num(conf, setConf, 1)}</div>
      <div className="mt-4 w-56"><label className="label">Donnée obsolète après (jours)</label><input type="number" className="input" disabled={readOnly} value={stale} onChange={(e) => setStale(Number(e.target.value))} /></div>
      <ErrorBox error={err} />
      {!readOnly && <button className="btn-primary mt-4" onClick={save}>Enregistrer (journalisé)</button>}
      {ok && <span className="ml-3 text-sm text-emerald-300">Enregistré. Les nouveaux calculs utiliseront ces valeurs.</span>}
    </Card>
  );
}

function JsonEditor({ title, k, value, readOnly, onSaved, help, extra }: { title: string; k: string; value: unknown; readOnly: boolean; onSaved: () => void; help: string; extra?: React.ReactNode }) {
  const [text, setText] = useState(JSON.stringify(value, null, 2));
  const [err, setErr] = useState<unknown>(null);
  const [ok, setOk] = useState(false);
  useEffect(() => setText(JSON.stringify(value, null, 2)), [value]);
  const save = async () => {
    setErr(null); setOk(false);
    try { await api.put(`/settings/${k}`, { value: JSON.parse(text) }); setOk(true); onSaved(); } catch (e) { setErr(e instanceof SyntaxError ? new Error("JSON invalide") : e); }
  };
  return (
    <Card title={title} actions={extra}>
      <p className="mb-3 text-xs text-slate-400">{help}</p>
      <textarea className="input mono h-72" value={text} disabled={readOnly} onChange={(e) => setText(e.target.value)} spellCheck={false} />
      <ErrorBox error={err} />
      {!readOnly && <button className="btn-primary mt-3" onClick={save}>Enregistrer (journalisé)</button>}
      {ok && <span className="ml-3 text-sm text-emerald-300">Enregistré.</span>}
    </Card>
  );
}

function UsersAdmin() {
  const { data, reload } = useApi<User[]>("/users");
  const roles = useApi<{ name: string; description: string; permissions: string[] }[]>("/users/roles");
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [err, setErr] = useState<unknown>(null);
  const [resetFor, setResetFor] = useState<User | null>(null);
  const [notice, setNotice] = useState("");
  const patch = async (u: User, body: Record<string, unknown>) => {
    setErr(null);
    try { await api.patch(`/users/${u.id}`, body); reload(); } catch (ex) { setErr(ex); }
  };
  const resetPassword = async (next: string) => {
    if (!resetFor) return;
    await api.patch(`/users/${resetFor.id}`, { password: next });
    setNotice(`Mot de passe de ${resetFor.username} réinitialisé : compte déverrouillé, sessions fermées. Communiquez-lui le nouveau mot de passe par un canal sûr.`);
    setResetFor(null);
    reload();
  };
  const create = async () => {
    setErr(null);
    try { await api.post("/users", form); setForm({ username: "", password: "", role: "analyst" }); reload(); } catch (e) { setErr(e); }
  };
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Utilisateurs" className="xl:col-span-2">
        <table className="table">
          <thead><tr><th>Identifiant</th><th>Rôle</th><th>Statut</th><th>Dernière connexion</th><th /></tr></thead>
          <tbody>{(data ?? []).map((u) => (
            <tr key={u.id}><td>{u.username}</td>
              <td><select className="input w-32" value={u.role} onChange={async (e) => { try { await api.patch(`/users/${u.id}`, { role: e.target.value }); reload(); } catch (ex) { setErr(ex); } }}>{["admin", "analyst", "viewer"].map((r) => <option key={r}>{r}</option>)}</select></td>
              <td>{u.is_active ? <Pill className="border-emerald-700 text-emerald-300">actif</Pill> : <Pill className="border-ink-500 text-slate-500">désactivé</Pill>}{u.locked && <Pill className="ml-1 border-amber-700 text-amber-300">verrouillé</Pill>}</td>
              <td className="mono text-xs">{fmtDate(u.last_login_at)}</td>
              <td className="whitespace-nowrap">
                <button className="btn-ghost" onClick={() => { setNotice(""); setResetFor(u); }}>Réinitialiser le mot de passe</button>
                {u.locked && <button className="btn-ghost ml-1" onClick={() => patch(u, { unlock: true })}>Déverrouiller</button>}
                <button className="btn-ghost ml-1" onClick={() => patch(u, { is_active: !u.is_active })}>{u.is_active ? "Désactiver" : "Réactiver"}</button>
              </td></tr>
          ))}</tbody>
        </table>
        {notice && <div className="mt-3 text-sm text-emerald-300">{notice}</div>}
        <ErrorBox error={err} />
        {resetFor && (
          <PasswordDialog title={`Réinitialiser le mot de passe de ${resetFor.username}`} submitLabel="Réinitialiser"
            intro="Le compte sera déverrouillé et toutes ses sessions ouvertes seront fermées. L'opération est inscrite au journal d'audit."
            onSubmit={resetPassword} onClose={() => setResetFor(null)} />
        )}
      </Card>
      <div className="space-y-4">
        <Card title="Créer un utilisateur">
          <label className="label">Identifiant</label><input className="input mb-2" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <label className="label">Mot de passe initial</label><input type="password" className="input mb-2" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <label className="label">Rôle</label><select className="input mb-3" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{["analyst", "viewer", "admin"].map((r) => <option key={r}>{r}</option>)}</select>
          <button className="btn-primary" onClick={create}>Créer</button>
        </Card>
        <Card title="Rôles et permissions">
          <ul className="space-y-2 text-xs">{(roles.data ?? []).map((r) => <li key={r.name}><b className="text-slate-200">{r.name}</b>, {r.description}<div className="text-slate-500">{r.permissions.join(", ")}</div></li>)}</ul>
        </Card>
      </div>
    </div>
  );
}

function AuditView() {
  const { data } = useApi<{ id: number; ts: string; actor: string; action: string; target_type: string | null; target_id: string | null; details: unknown; client_ip: string | null; entry_hash: string }[]>("/audit?limit=300");
  const [verify, setVerify] = useState<{ valid: boolean; entries_checked: number; first_invalid_id?: number } | null>(null);
  return (
    <Card title="Journal d'audit (chaîné par empreintes SHA-256)" actions={<button className="btn-ghost" onClick={async () => setVerify(await api.get("/audit/verify"))}>Vérifier l'intégrité de la chaîne</button>}>
      {verify && <div className={`mb-3 text-sm ${verify.valid ? "text-emerald-300" : "text-rose-300"}`}>{verify.valid ? `Chaîne intègre (${verify.entries_checked} entrées).` : `Rupture détectée à l'entrée #${verify.first_invalid_id}.`} Journal inviolable au sens modification détectable, pas modification impossible.</div>}
      <div className="max-h-[600px] overflow-auto">
        <table className="table">
          <thead><tr><th>#</th><th>Horodatage (UTC)</th><th>Acteur</th><th>Action</th><th>Cible</th><th>Détails</th></tr></thead>
          <tbody>{(data ?? []).map((a) => (
            <tr key={a.id}><td className="mono text-xs">{a.id}</td><td className="mono text-xs">{fmtDate(a.ts)}</td><td>{a.actor}</td><td>{a.action}</td><td className="mono text-xs">{a.target_type} {a.target_id}</td>
              <td className="mono max-w-[420px] truncate text-[11px] text-slate-500" title={JSON.stringify(a.details)}>{JSON.stringify(a.details)}</td></tr>
          ))}</tbody>
        </table>
      </div>
    </Card>
  );
}
