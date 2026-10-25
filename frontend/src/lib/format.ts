export const fmtDate = (iso: string | null | undefined): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z").replace(/:\d\dZ$/, (m) => m);
};

export const fmtRelative = (iso: string | null | undefined): string => {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "à l'instant";
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)} min`;
  if (diff < 86400) return `il y a ${Math.floor(diff / 3600)} h`;
  return `il y a ${Math.floor(diff / 86400)} j`;
};

export const STATUS_LABELS: Record<string, string> = {
  new: "Nouvelle", in_progress: "En cours", pending_review: "En revue", closed_true_positive: "Clôturée — vrai positif",
  closed_false_positive: "Clôturée — faux positif", closed_benign: "Clôturée — bénigne",
};

export const RESULT_STATUS: Record<string, { label: string; tone: string }> = {
  ok: { label: "Données obtenues", tone: "text-emerald-300 border-emerald-700/60 bg-emerald-950/40" },
  no_data: { label: "Aucune donnée", tone: "text-slate-300 border-ink-500 bg-ink-800" },
  error: { label: "Erreur", tone: "text-rose-300 border-rose-800 bg-rose-950/40" },
  not_configured: { label: "Non configuré", tone: "text-amber-300 border-amber-800 bg-amber-950/30" },
  rate_limited: { label: "Quota atteint", tone: "text-amber-300 border-amber-800 bg-amber-950/30" },
  unsupported: { label: "Hors périmètre", tone: "text-slate-400 border-ink-600 bg-ink-850" },
  skipped: { label: "Ignoré", tone: "text-slate-400 border-ink-600 bg-ink-850" },
};

export const levelTone = (level: string | null | undefined): string => {
  switch (level) {
    case "critique": case "critical": return "bg-rose-600/20 text-rose-300 border-rose-600/60";
    case "élevé": case "high": case "élevée": return "bg-orange-500/15 text-orange-300 border-orange-600/50";
    case "modéré": case "medium": case "moyenne": return "bg-amber-500/10 text-amber-300 border-amber-600/50";
    case "faible": case "low": return "bg-sky-500/10 text-sky-300 border-sky-700/60";
    case "info": return "bg-slate-500/10 text-slate-300 border-slate-600";
    default: return "bg-ink-800 text-slate-400 border-ink-600";
  }
};

export const confidenceTone = (level: string | null | undefined): string => {
  switch (level) {
    case "élevée": return "bg-cyan-500/15 text-cyanx-300 border-cyan-600/60";
    case "moyenne": return "bg-electric-500/10 text-electric-400 border-electric-600/50";
    case "faible": return "bg-ink-800 text-slate-400 border-ink-500";
    default: return "bg-ink-800 text-slate-500 border-ink-600";
  }
};

export const verdictTone = (v: string | undefined): string =>
  v === "malicious" ? "text-rose-300" : v === "suspicious" ? "text-amber-300" : v === "benign" ? "text-emerald-300" : "text-slate-400";

export const VERDICT_LABELS: Record<string, string> = { malicious: "malveillant", suspicious: "suspect", benign: "bénin", unknown: "inconnu" };
export const UNAVAILABLE = "Donnée indisponible";
