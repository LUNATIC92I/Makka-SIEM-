import { useFx } from "./useFx";

/** CRT scanlines, vignette and a slow scan beam over the whole screen (purely decorative). */
export default function CrtOverlay() {
  const { enabled } = useFx();
  if (!enabled) return null;
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-50">
      <div className="crt-scanlines absolute inset-0" />
      <div className="crt-vignette absolute inset-0" />
      <div className="crt-beam absolute inset-x-0 h-24" />
    </div>
  );
}
