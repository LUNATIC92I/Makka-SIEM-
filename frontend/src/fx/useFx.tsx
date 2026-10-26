import { createContext, ReactNode, useContext, useEffect, useState } from "react";

const KEY = "makkadi.fx";
const reducedMotion = () => typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

interface FxState { enabled: boolean; toggle: () => void }
const Ctx = createContext<FxState>({ enabled: false, toggle: () => {} });

/** Visual effects switch (cinema "hacker" theme). Off when the OS asks for reduced motion. */
export function FxProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabled] = useState<boolean>(() => {
    try { const v = localStorage.getItem(KEY); return v === null ? !reducedMotion() : v === "1"; } catch { return !reducedMotion(); }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("fx-on", enabled);
    try { localStorage.setItem(KEY, enabled ? "1" : "0"); } catch { /* ignore */ }
  }, [enabled]);
  return <Ctx.Provider value={{ enabled, toggle: () => setEnabled((v) => !v) }}>{children}</Ctx.Provider>;
}

export const useFx = () => useContext(Ctx);
