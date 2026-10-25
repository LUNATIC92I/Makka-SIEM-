import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

const NAV: { to: string; label: string; icon: string; perm?: string }[] = [
  { to: "/", label: "Vue d'ensemble", icon: "M3 12l9-9 9 9M5 10v10h14V10" },
  { to: "/investigations", label: "Investigations", icon: "M11 4a7 7 0 105.2 11.7L21 20.5M11 8v6M8 11h6" },
  { to: "/map", label: "Cartographie", icon: "M9 4l-6 2v14l6-2 6 2 6-2V4l-6 2-6-2zm0 0v14m6-12v14" },
  { to: "/intel", label: "Threat Intelligence", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" },
  { to: "/reports", label: "Rapports", icon: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6" },
  { to: "/connectors", label: "Connecteurs", icon: "M8 7V3m8 4V3M6 7h12v4a6 6 0 01-12 0zM12 17v4", perm: "connectors:read" },
  { to: "/tasks", label: "File de tâches", icon: "M4 6h16M4 12h16M4 18h10", perm: "tasks:read" },
  { to: "/settings", label: "Paramètres", icon: "M12 15a3 3 0 100-6 3 3 0 000 6zm7.4-3a7.4 7.4 0 00-.1-1.3l2-1.6-2-3.4-2.4 1a7.6 7.6 0 00-2.2-1.3L14.4 3h-4l-.4 2.4a7.6 7.6 0 00-2.2 1.3l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 000 2.6l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 002.2 1.3l.4 2.4h4l.4-2.4a7.6 7.6 0 002.2-1.3l2.4 1 2-3.4-2-1.6c.1-.4.1-.9.1-1.3z", perm: "settings:read" },
];

export const Icon = ({ d, className = "h-4 w-4" }: { d: string; className?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true"><path d={d} /></svg>
);

export default function Layout() {
  const { user, meta, logout, can } = useAuth();
  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-ink-700 bg-ink-900">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="./favicon.svg" alt="" className="h-8 w-8" />
          <div>
            <div className="text-base font-bold tracking-wide text-slate-50">{meta?.app_name ?? "MAKKADi"}</div>
            <div className="text-[10px] uppercase tracking-widest text-cyanx-400">OSINT Intelligence</div>
          </div>
        </div>
        {meta?.demo_mode && (
          <div className="mx-3 mb-2 rounded-md border border-amber-600/50 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-300">
            Mode démonstration actif : les sources synthétiques sont signalées « DONNÉE DE DÉMONSTRATION ».
          </div>
        )}
        <nav className="flex-1 space-y-0.5 px-2">
          {NAV.filter((n) => !n.perm || can(n.perm)).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
              className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-electric-500/15 text-cyanx-300" : "text-slate-400 hover:bg-ink-800 hover:text-slate-100"}`}>
              <Icon d={n.icon} />{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-ink-700 p-3 text-xs">
          <div className="text-slate-300">{user?.display_name || user?.username}</div>
          <div className="mb-2 text-slate-500">{user?.role} · v{meta?.version}</div>
          <button className="btn-ghost w-full justify-center" onClick={logout}>Se déconnecter</button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1600px] p-6"><Outlet /></div>
      </main>
    </div>
  );
}
