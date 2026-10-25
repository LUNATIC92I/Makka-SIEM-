import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../services/api";

export function useApi<T>(path: string | null, { refreshMs }: { refreshMs?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(!!path);
  const alive = useRef(true);

  const load = useCallback(async (silent = false) => {
    if (!path) return;
    if (!silent) setLoading(true);
    try {
      const d = await api.get<T>(path);
      if (alive.current) { setData(d); setError(null); }
    } catch (e) {
      if (alive.current) setError(e);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    alive.current = true;
    load();
    let timer: number | undefined;
    if (refreshMs) timer = window.setInterval(() => load(true), refreshMs);
    return () => { alive.current = false; if (timer) window.clearInterval(timer); };
  }, [load, refreshMs]);

  return { data, error, loading, reload: load, setData };
}
