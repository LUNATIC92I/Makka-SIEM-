import { FormEvent, useState } from "react";
import { ErrorBox } from "../components/ui";
import GlitchText from "../fx/GlitchText";
import Radar from "../fx/Radar";
import Typewriter from "../fx/Typewriter";
import { useFx } from "../fx/useFx";

const BOOT = [
  "> Connexion au noyau MAKKADi............ [OK]",
  "> Chargement des modules OSINT.......... [OK]",
  "> Moteur de corrélation................. [OK]",
  "> Coffre de secrets chiffré............. [OK]",
  "> Journal d'audit chaîné SHA-256........ [OK]",
  "> Écoute réseau limitée à 127.0.0.1..... [OK]",
  "> Authentification requise",
];
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";

type DesktopBridge = { desktop?: boolean; openPasswordReset?: () => Promise<{ ok: boolean; message?: string }> };
const desktopBridge = (): DesktopBridge | undefined => (window as unknown as { makkadiDesktop?: DesktopBridge }).makkadiDesktop;

function readNotice(): string {
  try {
    const n = sessionStorage.getItem("makkadi.notice") ?? "";
    sessionStorage.removeItem("makkadi.notice");
    return n;
  } catch { return ""; }
}

function ForgotPassword() {
  const bridge = desktopBridge();
  const [msg, setMsg] = useState("");
  const open = async () => {
    try {
      const r = await bridge!.openPasswordReset!();
      setMsg(r.ok ? "Outil ouvert dans une fenêtre de commande : suivez les instructions puis reconnectez-vous ici." : (r.message ?? "Ouverture impossible."));
    } catch { setMsg("Ouverture impossible."); }
  };
  return (
    <div className="mt-3 space-y-2 rounded-lg border border-ink-600 bg-ink-800/60 p-3 text-xs text-slate-300">
      <p><b className="text-slate-100">Un autre administrateur existe :</b> demandez-lui de réinitialiser votre mot de passe
        (Paramètres, Utilisateurs, Réinitialiser le mot de passe).</p>
      <p><b className="text-slate-100">Vous êtes le seul administrateur :</b> utilisez l'outil de réinitialisation local. Il ne
        fonctionne que sur ce poste et ne supprime aucune donnée.</p>
      {bridge?.openPasswordReset ? (
        <button type="button" className="btn-ghost w-full justify-center" onClick={open}>Ouvrir l'outil de réinitialisation</button>
      ) : (
        <p className="font-mono text-[11px] text-neon-300">makkadi-backend --reset-password</p>
      )}
      {msg && <p className="text-emerald-300">{msg}</p>}
    </div>
  );
}

export default function LoginPage() {
  const { meta, needsSetup, login, refreshSetup } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const { enabled } = useFx();
  const [booted, setBooted] = useState(!enabled);
  const [notice] = useState(readNotice);
  const [forgot, setForgot] = useState(false);

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
    <div className="flex h-full items-center justify-center gap-10 px-6">
      <div className="hidden w-[420px] flex-col gap-6 lg:flex">
        <div className="card p-4">
          <div className="mb-2 flex items-center gap-2 border-b border-neon-500/20 pb-2 font-mono text-[10px] text-slate-500">
            <span className="h-2 w-2 rounded-full bg-rose-500" /><span className="h-2 w-2 rounded-full bg-amber-400" /><span className="h-2 w-2 rounded-full bg-neon-400" />
            <span className="ml-2">makkadi@soc:~$ ./initialisation</span>
          </div>
          <Typewriter lines={BOOT} onDone={() => setBooted(true)} />
        </div>
        <div className="flex justify-center"><Radar blips={7} size={170} label="ANALYSE DU PÉRIMÈTRE" /></div>
      </div>
      <form onSubmit={submit} className={`card w-[380px] p-6 ${booted ? "reveal" : "invisible"}`}>
        <div className="mb-6 flex items-center gap-3">
          <img src="./favicon.svg" alt="" className="h-10 w-10" />
          <div>
            <GlitchText className="text-xl font-bold text-slate-50 text-glow">{meta?.app_name ?? "MAKKADi"}</GlitchText>
            <p className="text-xs text-slate-400">{meta?.tagline}</p>
          </div>
        </div>
        {needsSetup && (
          <p className="mb-4 rounded-lg border border-cyan-700/50 bg-cyan-500/10 p-3 text-xs text-cyanx-300">
            Premier démarrage : créez le compte administrateur (12 caractères minimum, majuscules, minuscules et chiffres).
            Cette opération n'est possible que depuis ce poste.
          </p>
        )}
        {notice && <p className="mb-4 rounded-lg border border-emerald-700/50 bg-emerald-500/10 p-3 text-xs text-emerald-300">{notice}</p>}
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
        <button className="btn-primary mt-4 w-full justify-center font-mono tracking-wider" disabled={busy}>
          {busy ? "AUTHENTIFICATION..." : needsSetup ? "Créer l'administrateur" : "Se connecter"}
        </button>
        {!needsSetup && (
          <button type="button" className="mt-3 w-full text-center text-xs text-cyanx-300 hover:underline" aria-expanded={forgot} onClick={() => setForgot(!forgot)}>
            Mot de passe oublié ?
          </button>
        )}
        {!needsSetup && forgot && <ForgotPassword />}
        <p className="mt-4 text-center text-[11px] text-slate-500">Serveur local, aucune exposition réseau par défaut.</p>
      </form>
    </div>
  );
}
