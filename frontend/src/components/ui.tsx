import { ReactNode, useState } from "react";
import { confidenceTone, levelTone, RESULT_STATUS, UNAVAILABLE } from "../lib/format";

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {title && <header className="card-h"><span>{title}</span>{actions}</header>}
      <div className="card-b">{children}</div>
    </section>
  );
}

export function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`inline-flex items-center whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${className}`}>{children}</span>;
}

export const LevelBadge = ({ level, score, prefix = "Risque" }: { level: string | null | undefined; score?: number | null; prefix?: string }) => (
  <Pill className={levelTone(level)}>{prefix} {level ?? "en attente"}{score != null ? ` · ${Math.round(score)}` : ""}</Pill>
);

export const ConfidenceBadge = ({ level, score }: { level: string | null | undefined; score?: number | null }) => (
  <Pill className={confidenceTone(level)}>Confiance {level ?? "—"}{score != null ? ` · ${Math.round(score)}` : ""}</Pill>
);

export const SeverityBadge = ({ severity }: { severity: string }) => <Pill className={levelTone(severity)}>{severity}</Pill>;

export const SyntheticTag = ({ show = true }: { show?: boolean }) =>
  show ? <Pill className="border-amber-500/60 bg-amber-500/10 text-amber-300" >Donnée de démonstration</Pill> : null;

export const ResultStatusPill = ({ status }: { status: string }) => {
  const s = RESULT_STATUS[status] ?? { label: status, tone: "text-slate-300 border-ink-600" };
  return <Pill className={s.tone}>{s.label}</Pill>;
};

export const Unavailable = ({ reason }: { reason?: string | null }) => (
  <span className="text-sm italic text-slate-500">{UNAVAILABLE}{reason ? ` — ${reason}` : ""}</span>
);

export function Spinner({ label = "Chargement…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 p-6 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyanx-400 border-t-transparent" />
      {label}
    </div>
  );
}

export const ErrorBox = ({ error }: { error: unknown }) =>
  error ? <div className="rounded-lg border border-rose-800 bg-rose-950/40 p-3 text-sm text-rose-200">{String((error as Error).message ?? error)}</div> : null;

export const Empty = ({ children }: { children: ReactNode }) => <div className="p-6 text-center text-sm text-slate-500">{children}</div>;

export function Mono({ value, copy = true }: { value: string; copy?: boolean }) {
  const [done, setDone] = useState(false);
  return (
    <span className="group inline-flex items-center gap-1 mono text-cyanx-300">
      {value}
      {copy && (
        <button
          type="button"
          className="opacity-0 transition-opacity group-hover:opacity-100 text-[10px] text-slate-500 hover:text-cyanx-300"
          onClick={() => { navigator.clipboard?.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}
          aria-label="Copier"
        >{done ? "copié" : "copier"}</button>
      )}
    </span>
  );
}

export function Stat({ label, value, hint, tone = "text-slate-100" }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: { key: T; label: ReactNode }[]; active: T; onChange: (k: T) => void }) {
  return (
    <nav className="flex flex-wrap gap-1 border-b border-ink-700" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={active === t.key} className={`tab ${active === t.key ? "tab-active" : ""}`} onClick={() => onChange(t.key)}>
          {t.label}
        </button>
      ))}
    </nav>
  );
}

export function ScoreBar({ value, tone = "bg-cyanx-400" }: { value: number | null; tone?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-700">
      {value != null && <div className={`h-full ${tone}`} style={{ width: `${Math.max(2, Math.min(100, value))}%` }} />}
    </div>
  );
}

export const ProvenanceTag = ({ kind }: { kind: "observed" | "third_party" | "computed" | "ai_generated" | string }) => {
  const map: Record<string, [string, string]> = {
    observed: ["Observé (SIEM)", "border-slate-600 text-slate-300"],
    third_party: ["Source tierce (OSINT)", "border-electric-600/60 text-electric-400"],
    computed: ["Calculé (MAKKADi)", "border-cyan-700/60 text-cyanx-300"],
    ai_generated: ["Généré par IA", "border-fuchsia-700/60 text-fuchsia-300"],
  };
  const [label, tone] = map[kind] ?? [kind, "border-ink-600 text-slate-400"];
  return <Pill className={tone}>{label}</Pill>;
};
