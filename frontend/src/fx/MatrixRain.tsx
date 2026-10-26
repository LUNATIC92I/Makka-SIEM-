import { useEffect, useRef } from "react";
import { useFx } from "./useFx";

const GLYPHS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン0123456789ABCDEF<>/{}[]#$%&*+=";

/** Digital rain in the background (canvas, ~24 fps, paused when the tab is hidden). */
export default function MatrixRain({ opacity = 0.16 }: { opacity?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const { enabled } = useFx();

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !enabled) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const size = 15;
    let drops: number[] = [];
    let speeds: number[] = [];
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const cols = Math.ceil(canvas.width / size);
      drops = Array.from({ length: cols }, () => Math.random() * -canvas.height / size);
      speeds = Array.from({ length: cols }, () => 0.35 + Math.random() * 0.9);
    };
    resize();
    window.addEventListener("resize", resize);
    let raf = 0;
    let last = 0;
    const draw = (t: number) => {
      raf = requestAnimationFrame(draw);
      if (document.hidden || t - last < 42) return;
      last = t;
      ctx.fillStyle = "rgba(3, 6, 8, 0.12)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${size}px "JetBrains Mono", Consolas, monospace`;
      for (let i = 0; i < drops.length; i++) {
        const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
        const y = drops[i] * size;
        ctx.fillStyle = Math.random() > 0.975 ? "#d9ffe8" : i % 7 === 0 ? "#22d3ee" : "#22ff88";
        ctx.fillText(ch, i * size, y);
        drops[i] += speeds[i];
        if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      }
    };
    raf = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, [enabled]);

  if (!enabled) return null;
  return <canvas ref={ref} aria-hidden="true" className="pointer-events-none fixed inset-0 z-0" style={{ opacity }} />;
}
