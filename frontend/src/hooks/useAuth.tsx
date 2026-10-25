import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, setUnauthorizedHandler, tokenStore } from "../services/api";
import type { Meta, User } from "../types";

interface AuthState {
  user: User | null; meta: Meta | null; ready: boolean; needsSetup: boolean;
  login: (u: string, p: string) => Promise<void>; logout: () => Promise<void>; refreshSetup: () => Promise<void>;
  can: (perm: string) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [ready, setReady] = useState(false);
  const [needsSetup, setNeedsSetup] = useState(false);

  const refreshSetup = useCallback(async () => {
    const s = await api.get<{ needs_setup: boolean }>("/auth/setup-status");
    setNeedsSetup(s.needs_setup);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    (async () => {
      try {
        const m = await api.get<Meta>("/meta");
        setMeta(m);
        document.title = m.app_name;
        await refreshSetup();
        if (tokenStore.get()) setUser(await api.get<User>("/auth/me"));
      } catch { /* not logged in */ } finally { setReady(true); }
    })();
  }, [refreshSetup]);

  const login = async (username: string, password: string) => {
    const r = await api.post<{ access_token: string; user: User }>("/auth/login", { username, password });
    tokenStore.set(r.access_token);
    setUser(r.user);
  };
  const logout = async () => {
    try { await api.post("/auth/logout"); } catch { /* ignore */ }
    tokenStore.set(null);
    setUser(null);
  };
  const can = (perm: string) => !!user?.permissions.includes(perm);

  return <Ctx.Provider value={{ user, meta, ready, needsSetup, login, logout, refreshSetup, can }}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("AuthProvider manquant");
  return v;
}
