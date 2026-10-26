import { ElementType, ReactNode } from "react";

/** Title with a cinema-style RGB split glitch (CSS only, disabled when effects are off). */
export default function GlitchText({ children, as: Tag = "h1", className = "" }: { children: string; as?: ElementType; className?: string }) {
  return <Tag className={`glitch ${className}`} data-text={children}>{children as ReactNode}</Tag>;
}
