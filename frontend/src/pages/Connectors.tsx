import { useState } from "react";
import { Card, Empty, ErrorBox, Pill, Spinner } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate } from "../lib/format";
import { api } from "../services/api";
import type { Connector } from "../types";

interface Catalog {
  siem: { provider: string; display_name: string; description: string; settings_schema: Record<string, string>; secret_fields: string[]; maturity: string }[];
  osint: { provider: string; display_name: string }[];
  ai: { provider: string; display_name: string }[];
}

const stateTone = (s: string) => s.startsWith("opérationnel") ? "border-emerald-700 text-emerald-300" : s === "en erreur" ? "border-rose-700 text-rose-300"
  : s === "non configuré" ? "border-amber-700 text-amber-300" : s === "désactivé" ? "border-ink-500 text-slate-500" : "border-electric-600 text-electric-400";

export default function ConnectorsPage() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<Connector[]>("/connectors");
  const catalog = useApi<Catalog>("/connectors/catalog");
  if (loading && !data) return <Spinner />;
  const list = data ?? [];
  const editable = can("connectors:write");
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-50">Connecteurs</h1>
        <p className="text-sm text-slate-400">Un connecteur n'est déclaré « opérationnel » qu'après un test réussi ou une collecte réelle. Les secrets sont chiffrés (clé maîtresse hors base) et ne sont jamais réaffichés.</p>
      </div>
      <ErrorBox error={error} />
      <Card title="SIEM">
        <div className="space-y-3">
          {list.filter((c) => c.kind === "siem").map((c) => <ConnectorRow key={c.id} c={c} editable={editable} onChange={reload} />)}
          {!list.some((c) => c.kind === "siem") && <Empty>Aucun SIEM configuré. Le mode démonstration et l'import JSON restent disponibles.</Empty>}
        </div>
        {editable && catalog.data && <NewSiem catalog={catalog.data} onCreated={reload} />}
      </Card>
      <Card title="Sources OSINT et Threat Intelligence">
        <p className="mb-3 text-xs text-slate-500">Activer une source revient à lui transmettre les indicateurs publics investigués. Respectez les conditions d'utilisation et quotas de chaque fournisseur.</p>
        <div className="space-y-3">{list.filter((c) => c.kind === "osint").map((c) => <ConnectorRow key={c.id} c={c} editable={editable} onChange={reload} />)}</div>
      </Card>
      <Card title="Fournisseur d'IA">
        <AISection list={list.filter((c) => c.kind === "ai")} editable={editable} onChange={reload} />
      </Card>
    </div>
  );
}

function FieldInputs({ schema, values, onChange, secret = false }: { schema: Record<string, string> | string[]; values: Record<string, string>; onChange: (v: Record<string, string>) => void; secret?: boolean }) {
  const entries = Array.isArray(schema) ? schema.map((k) => [k, k] as const) : Object.entries(schema);
  return (
    <>
      {entries.map(([key, help]) => (
        <div key={key}>
          <label className="label">{key}{secret && " (secret)"}</label>
          <input className="input mono" type={secret ? "password" : "text"} placeholder={secret ? (values[key] ? "inchangé" : "non défini") : help}
            autoComplete="off" value={values[key] ?? ""} onChange={(e) => onChange({ ...values, [key]: e.target.value })} />
        </div>
      ))}
    </>
  );
}

function ConnectorRow({ c, editable, onChange }: { c: Connector; editable: boolean; onChange: () => void }) {
  const [open, setOpen] = useState(false);
  const [settings, setSettings] = useState<Record<string, string>>(Object.fromEntries(Object.entries(c.settings).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)])));
  const [secrets, setSecrets] = useState<Record<string, string>>(c.secrets);
  const [pollInterval, setPollInterval] = useState(c.poll_interval_seconds);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [testValue, setTestValue] = useState("1.1.1.1");

  const parsedSettings = () => Object.fromEntries(Object.entries(settings).filter(([, v]) => v !== "").map(([k, v]) => {
    try { return [k, /^[[{]/.test(v.trim()) ? JSON.parse(v) : v]; } catch { return [k, v]; }
  }));
  const save = async (extra: Record<string, unknown> = {}) => {
    setErr(null);
    try {
      await api.patch(`/connectors/${c.id}`, { settings: parsedSettings(), secrets, ...(c.kind === "siem" ? { poll_interval_seconds: pollInterval } : {}), ...extra });
      setMsg("Enregistré."); onChange();
    } catch (e) { setErr(e); }
  };
  const test = async () => {
    setMsg("Test en cours…"); setErr(null);
    try {
      const type = testValue.includes(":") ? "ipv6" : /^[\d.]+$/.test(testValue) ? "ipv4" : "domain";
      const r = await api.post<{ ok: boolean; message: string }>(`/connectors/${c.id}/test`, { indicator_type: type, indicator_value: testValue });
      setMsg((r.ok ? "✓ " : "✗ ") + r.message); onChange();
    } catch (e) { setErr(e); setMsg(null); }
  };

  return (
    <div className="rounded-lg border border-ink-700 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-slate-100">{c.display_name ?? c.provider}</span>
        <span className="mono text-xs text-slate-500">{c.name}</span>
        {c.category && <Pill className="border-ink-500 text-slate-400">{c.category}</Pill>}
        <Pill className={stateTone(c.state)}>{c.state}</Pill>
        {c.requires_api_key && <span className="text-[11px] text-slate-500">clé API requise</span>}
        <div className="ml-auto flex items-center gap-2">
          {editable && (
            <label className="flex items-center gap-1 text-xs text-slate-300">
              <input type="checkbox" checked={c.enabled} onChange={(e) => save({ enabled: e.target.checked })} /> activé
            </label>
          )}
          <button className="btn-ghost" onClick={() => setOpen(!open)}>{open ? "Fermer" : "Configurer"}</button>
        </div>
      </div>
      {c.description && <p className="mt-1 text-xs text-slate-500">{c.description} {c.maturity && <em className="text-slate-600">— {c.maturity}</em>}</p>}
      {c.last_error && <p className="mt-1 text-xs text-rose-300">Dernière erreur : {c.last_error}</p>}
      {c.last_run_at && <p className="text-[11px] text-slate-500">Dernière exécution {fmtDate(c.last_run_at)} · dernier succès {fmtDate(c.last_success_at)}</p>}
      {open && (
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <FieldInputs schema={c.settings_schema ?? {}} values={settings} onChange={setSettings} />
          <FieldInputs schema={[...(c.secret_fields ?? []), ...(c.kind === "siem" ? ["webhook_secret"] : [])]} values={secrets} onChange={setSecrets} secret />
          {c.kind === "siem" && <div><label className="label">Fréquence de collecte (s)</label><input type="number" min={30} className="input" value={pollInterval} onChange={(e) => setPollInterval(Number(e.target.value))} /></div>}
          {c.kind === "siem" && <div className="md:col-span-3 text-xs text-slate-500">Webhook : <span className="mono">POST /api/v1/ingest/webhook/{c.name}</span> signé HMAC-SHA256 (en-têtes X-Makkadi-Timestamp et X-Makkadi-Signature).</div>}
          <div className="flex flex-wrap items-end gap-2 md:col-span-3">
            {editable && <button className="btn-primary" onClick={() => save()}>Enregistrer</button>}
            {editable && c.kind === "osint" && <input className="input mono w-48" value={testValue} onChange={(e) => setTestValue(e.target.value)} aria-label="Indicateur de test" />}
            {editable && <button className="btn-ghost" onClick={test}>Tester la connexion</button>}
            {editable && c.kind === "siem" && <button className="btn-ghost" onClick={async () => { await api.post(`/connectors/${c.id}/poll`); setMsg("Collecte planifiée."); }}>Collecter maintenant</button>}
            {editable && c.kind !== "osint" && <button className="btn-danger" onClick={async () => { if (confirm("Supprimer ce connecteur ?")) { await api.del(`/connectors/${c.id}`); onChange(); } }}>Supprimer</button>}
            {c.terms_url && <a className="text-xs text-cyanx-400" href={c.terms_url} target="_blank" rel="noopener noreferrer">Conditions d'utilisation ↗</a>}
          </div>
          {msg && <div className="md:col-span-3 text-sm text-slate-300">{msg}</div>}
          <div className="md:col-span-3"><ErrorBox error={err} /></div>
        </div>
      )}
    </div>
  );
}

function NewSiem({ catalog, onCreated }: { catalog: Catalog; onCreated: () => void }) {
  const [provider, setProvider] = useState(catalog.siem[0]?.provider ?? "");
  const [name, setName] = useState("");
  const [err, setErr] = useState<unknown>(null);
  const meta = catalog.siem.find((s) => s.provider === provider);
  const create = async () => {
    setErr(null);
    try { await api.post("/connectors", { kind: "siem", provider, name, enabled: false, settings: {} }); setName(""); onCreated(); } catch (e) { setErr(e); }
  };
  return (
    <div className="mt-4 rounded-lg border border-dashed border-ink-600 p-3">
      <div className="mb-2 text-sm font-medium text-slate-200">Ajouter un connecteur SIEM</div>
      <div className="flex flex-wrap items-end gap-2">
        <div><label className="label">Type</label><select className="input w-64" value={provider} onChange={(e) => setProvider(e.target.value)}>{catalog.siem.map((s) => <option key={s.provider} value={s.provider}>{s.display_name}</option>)}</select></div>
        <div><label className="label">Nom unique</label><input className="input w-56 mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="ex. sentinel-prod" /></div>
        <button className="btn-primary" disabled={name.length < 2} onClick={create}>Créer</button>
      </div>
      {meta && <p className="mt-2 text-xs text-slate-500">{meta.description} — <em>{meta.maturity}</em></p>}
      <ErrorBox error={err} />
    </div>
  );
}

function AISection({ list, editable, onChange }: { list: Connector[]; editable: boolean; onChange: () => void }) {
  const current = list.find((c) => c.enabled) ?? list[0];
  const [provider, setProvider] = useState(current?.provider ?? "deterministic");
  const [model, setModel] = useState(String(current?.settings.model ?? ""));
  const [baseUrl, setBaseUrl] = useState(String(current?.settings.base_url ?? ""));
  const [apiKey, setApiKey] = useState(current?.secrets.api_key ?? "");
  const [ack, setAck] = useState(Boolean(current?.settings.external_processing_acknowledged));
  const [pseudo, setPseudo] = useState(current?.settings.pseudonymize !== false);
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const save = async () => {
    setErr(null);
    const settings = { model, base_url: baseUrl, external_processing_acknowledged: ack, pseudonymize: pseudo };
    try {
      const existing = list.find((c) => c.provider === provider);
      if (existing) await api.patch(`/connectors/${existing.id}`, { enabled: true, settings, secrets: { api_key: apiKey } });
      else await api.post("/connectors", { kind: "ai", provider, name: `ai-${provider}`, enabled: true, settings, secrets: { api_key: apiKey } });
      setMsg("Fournisseur IA enregistré et activé."); onChange();
    } catch (e) { setErr(e); }
  };
  return (
    <div className="space-y-3 text-sm">
      <p className="text-xs text-slate-500">Par défaut, MAKKADi utilise son moteur d'analyse déterministe local (aucune donnée ne quitte le poste). Un fournisseur externe n'est utilisé qu'après validation explicite de la politique de traitement des données. Le modèle ne dispose d'aucun outil et ne peut déclencher aucune action.</p>
      <div className="grid gap-3 md:grid-cols-3">
        <div><label className="label">Fournisseur</label>
          <select className="input" value={provider} onChange={(e) => setProvider(e.target.value)} disabled={!editable}>
            <option value="deterministic">Moteur déterministe local (sans LLM)</option>
            <option value="anthropic">Anthropic Claude (API)</option>
            <option value="openai_compatible">Compatible OpenAI (Ollama, vLLM, LM Studio, service hébergé)</option>
          </select></div>
        {provider !== "deterministic" && <>
          <div><label className="label">Modèle</label><input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder={provider === "anthropic" ? "claude-opus-5-5 (défaut)" : "ex. llama3.1:8b"} /></div>
          {provider === "openai_compatible" && <div><label className="label">URL de base</label><input className="input mono" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://127.0.0.1:11434/v1" /></div>}
          <div><label className="label">Clé API (secret)</label><input className="input mono" type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={apiKey ? "inchangée" : "non définie"} /></div>
          <label className="flex items-center gap-2 md:col-span-3"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />J'ai validé la politique de traitement : les données d'investigation (minimisées) peuvent être envoyées à ce fournisseur.</label>
          <label className="flex items-center gap-2 md:col-span-3"><input type="checkbox" checked={pseudo} onChange={(e) => setPseudo(e.target.checked)} />Pseudonymiser les noms d'hôtes et adresses internes avant envoi.</label>
        </>}
      </div>
      {editable && <button className="btn-primary" onClick={save}>Enregistrer</button>}
      {msg && <p className="text-emerald-300">{msg}</p>}
      <ErrorBox error={err} />
    </div>
  );
}
