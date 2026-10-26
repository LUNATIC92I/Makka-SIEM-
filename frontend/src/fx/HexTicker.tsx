import { useEffect, useState } from "react";
import { useFx } from "./useFx";

const hex = (n: number) => Array.from({ length: n }, () => ((Math.random() * 256) | 0).toString(16).padStart(2, "0")).join(" ").toUpperCase();

/** Scrolling stream of hexadecimal "packets" + UTC clock (header decoration). */
export default function HexTicker() {
  const { enabled } = useFx();
  const [stream, setStream] = useState(() => hex(96));
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => { setNow(new Date()); if (enabled) setStream(hex(96)); }, 1000);
    return () => window.clearInterval(t);
  }, [enabled]);
  return (
    <div className="relative flex items-center gap-4 overflow-hidden border-b border-neon-500/20 bg-black/60 px-4 py-1 font-mono text-[10px] text-neon-500/70" aria-hidden="true">
      <span className="shrink-0 text-neon-400"><span className="status-dot" /> SYSTÈME EN LIGNE</span>
      <div className="min-w-0 flex-1 overflow-hidden whitespace-nowrap">
        <span className={enabled ? "ticker" : ""}>{stream}&nbsp;&nbsp;&nbsp;{stream}</span>
      </div>
      <span className="shrink-0 text-cyanx-300">UTC {now.toISOString().slice(11, 19)}</span>
    </div>
  );
}
