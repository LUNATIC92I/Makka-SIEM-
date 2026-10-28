import { FormEvent, useState } from "react";
import { ErrorBox } from "./ui";

export const PASSWORD_RULES = "12 caractères minimum, majuscules, minuscules et au moins un chiffre.";

/** Modal asking for a new password (twice), and optionally the current one. */
export default function PasswordDialog({ title, intro, askCurrent = false, submitLabel, onSubmit, onClose }: {
  title: string; intro?: string; askCurrent?: boolean; submitLabel: string;
  onSubmit: (newPassword: string, currentPassword: string) => Promise<void>; onClose: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next !== confirm) { setError(new Error("Les deux saisies du nouveau mot de passe sont différentes")); return; }
    setBusy(true);
    try { await onSubmit(next, current); } catch (err) { setError(err); } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label={title}
      onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}>
      <form onSubmit={submit} className="card w-full max-w-md p-6">
        <h2 className="mb-2 text-lg font-semibold text-slate-50">{title}</h2>
        {intro && <p className="mb-3 text-xs text-slate-400">{intro}</p>}
        {askCurrent && (
          <>
            <label className="label" htmlFor="pw-current">Mot de passe actuel</label>
            <input id="pw-current" type="password" className="input mb-3" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </>
        )}
        <label className="label" htmlFor="pw-new">Nouveau mot de passe</label>
        <input id="pw-new" type="password" className="input mb-3" autoComplete="new-password" autoFocus={!askCurrent} value={next} onChange={(e) => setNext(e.target.value)} required />
        <label className="label" htmlFor="pw-confirm">Confirmation</label>
        <input id="pw-confirm" type="password" className="input mb-2" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        <p className="mb-3 text-[11px] text-slate-500">{PASSWORD_RULES}</p>
        <ErrorBox error={error} />
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Annuler</button>
          <button className="btn-primary" disabled={busy}>{busy ? "Enregistrement..." : submitLabel}</button>
        </div>
      </form>
    </div>
  );
}
