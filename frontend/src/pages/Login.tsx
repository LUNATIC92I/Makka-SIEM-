import { FormEvent, useState } from "react";
import { ErrorBox } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";

export default function LoginPage() {
  const { meta, needsSetup, login, refreshSetup } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (needsSetup) {
        if (password !== confirm) throw new Error("Les mots de passe ne correspondent pas");
        await api.post("/auth/bootstrap", { username, password });
        await refreshSetup();
      }
      await login(username, password);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-[radial-gradient(ellipse_at_top,rgba(47,107,255,0.15),transparent_60%)]">
      <form onSubmit={submit} className="card w-[380px] p-6">
        <div className="mb-6 flex items-center gap-3">
          <img src="./favicon.svg" alt="" className="h-10 w-10" />
          <div>
            <h1 className="text-xl font-bold text-slate-50">{meta?.app_name ?? "MAKKADi"}</h1>
            <p className="text-xs text-slate-400">{meta?.tagline}</p>
          </div>
        </div>
        {needsSetup && (
          <p className="mb-4 rounded-lg border border-cyan-700/50 bg-cyan-500/10 p-3 text-xs text-cyanx-300">
            Premier démarrage : créez le compte administrateur (12 caractères minimum, majuscules, minuscules et chiffres).
            Cette opération n'est possible que depuis ce poste.
          </p>
        )}
        <label className="label" htmlFor="u">Identifiant</label>
        <input id="u" className="input mb-3" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label className="label" htmlFor="p">Mot de passe</label>
        <input id="p" type="password" className="input mb-3" autoComplete={needsSetup ? "new-password" : "current-password"} value={password} onChange={(e) => setPassword(e.target.value)} required />
        {needsSetup && (
          <>
            <label className="label" htmlFor="c">Confirmation</label>
            <input id="c" type="password" className="input mb-3" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
          </>
        )}
        <ErrorBox error={error} />
        <button className="btn-primary mt-4 w-full justify-center" disabled={busy}>
          {needsSetup ? "Créer l'administrateur" : "Se connecter"}
        </button>
        <p className="mt-4 text-center text-[11px] text-slate-500">Serveur local — aucune exposition réseau par défaut.</p>
      </form>
    </div>
  );
}
