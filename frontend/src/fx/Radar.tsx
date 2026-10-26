import { useFx } from "./useFx";

/** Rotating radar sweep with blips (decorative "surveillance" widget). */
export default function Radar({ blips = 5, size = 180, label = "SURVEILLANCE ACTIVE" }: { blips?: number; size?: number; label?: string }) {
  const { enabled } = useFx();
  const points = Array.from({ length: blips }, (_, i) => {
    const a = (i * 137.5 * Math.PI) / 180;
    const r = 0.25 + ((i * 0.37) % 0.65);
    return { x: 50 + Math.cos(a) * r * 45, y: 50 + Math.sin(a) * r * 45, d: (i * 0.7) % 3 };
  });
  return (
    <div className="flex flex-col items-center gap-2" aria-hidden="true">
      <div className="radar" style={{ width: size, height: size }}>
        <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full">
          {[15, 30, 45].map((r) => <circle key={r} cx="50" cy="50" r={r} fill="none" stroke="rgba(34,255,136,0.25)" strokeWidth="0.4" />)}
          <line x1="50" y1="2" x2="50" y2="98" stroke="rgba(34,255,136,0.15)" strokeWidth="0.3" />
          <line x1="2" y1="50" x2="98" y2="50" stroke="rgba(34,255,136,0.15)" strokeWidth="0.3" />
          {points.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="1.6" className={enabled ? "radar-blip" : ""} style={{ animationDelay: `${p.d}s` }} fill="#22ff88" />)}
        </svg>
        {enabled && <div className="radar-sweep" />}
      </div>
      <div className="font-mono text-[10px] tracking-[0.3em] text-neon-400">{label}<span className="cursor-blink">_</span></div>
    </div>
  );
}
