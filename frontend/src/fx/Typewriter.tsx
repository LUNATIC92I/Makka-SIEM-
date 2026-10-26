import { useEffect, useState } from "react";
import { useFx } from "./useFx";

/** Lines typed one character at a time, like a terminal boot log. */
export default function Typewriter({ lines, speed = 14, onDone }: { lines: string[]; speed?: number; onDone?: () => void }) {
  const { enabled } = useFx();
  const total = lines.join("\n");
  const [count, setCount] = useState(enabled ? 0 : total.length);

  useEffect(() => {
    if (!enabled) { setCount(total.length); onDone?.(); return; }
    setCount(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1 + ((Math.random() * 2) | 0);
      setCount(Math.min(i, total.length));
      if (i >= total.length) { window.clearInterval(id); onDone?.(); }
    }, speed);
    return () => window.clearInterval(id);
  }, [enabled, total, speed]); // eslint-disable-line react-hooks/exhaustive-deps

  const shown = total.slice(0, count).split("\n");
  return (
    <pre className="whitespace-pre-wrap font-mono text-[11px] leading-5 text-neon-400">
      {shown.map((l, idx) => (
        <div key={idx}>
          {l.endsWith("[OK]") ? <>{l.slice(0, -4)}<span className="text-cyanx-300">[OK]</span></> : l}
          {idx === shown.length - 1 && <span className="cursor-blink">_</span>}
        </div>
      ))}
    </pre>
  );
}
