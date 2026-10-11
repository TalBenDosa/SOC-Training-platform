"use client";
/**
 * <Term k="ioc">IOCs</Term> — inline glossary tooltip.
 *
 * Renders its children with a dotted underline; hovering, focusing (Tab) or
 * tapping shows the plain-English definition from src/lib/glossary.ts. Escape,
 * blur, or a tap elsewhere closes it. Used at key spots so a first-time SOC
 * student never has to guess an acronym.
 *
 * The trigger is a real <button> (keyboard + screen-reader reachable) styled as
 * inline text — no button chrome. Its `aria-describedby` points at the tooltip
 * so the definition is read out with the term.
 */
import { useEffect, useId, useRef, useState } from "react";
import { BookOpen } from "lucide-react";
import { GLOSSARY } from "@/lib/glossary";

export function Term({ k, children }: { k: string; children: React.ReactNode }) {
  const [visible, setVisible] = useState(false);
  const tipId = useId();
  const wrapRef = useRef<HTMLSpanElement>(null);
  const entry = GLOSSARY[k];

  // A tap/click outside closes it (iOS Safari doesn't focus buttons on tap, so
  // blur alone wouldn't fire there).
  useEffect(() => {
    if (!visible) return;
    const onDown = (e: PointerEvent) => {
      if (wrapRef.current && e.target instanceof Node && !wrapRef.current.contains(e.target)) setVisible(false);
    };
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [visible]);

  if (!entry) return <>{children}</>;

  return (
    <span
      ref={wrapRef}
      className="relative inline-block"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      <button
        type="button"
        aria-expanded={visible}
        aria-describedby={visible ? tipId : undefined}
        onFocus={() => setVisible(true)}
        onBlur={() => setVisible(false)}
        onClick={(e) => { e.stopPropagation(); setVisible(true); }}
        onKeyDown={(e) => {
          if (e.key === "Escape" && visible) { e.stopPropagation(); setVisible(false); }
        }}
        /* Inline-text look: inherit everything (preflight forces text-transform:none on buttons). */
        className="inline cursor-help border-b border-dotted border-cyber-500/60 bg-transparent p-0 text-inherit [font:inherit] [letter-spacing:inherit] [text-transform:inherit] hover:border-cyber-400 transition-colors"
      >
        {children}
      </button>
      {visible && (
        <span id={tipId} role="tooltip" className="absolute left-0 top-full mt-1.5 z-[60] block w-72 rounded-lg border border-border/80 bg-[#080d14] px-3 py-2.5 shadow-2xl">
          <span className="flex items-center gap-1.5 mb-1">
            <BookOpen className="h-3 w-3 text-cyber-400" aria-hidden="true" />
            <span className="text-[10px] font-bold uppercase tracking-wider text-cyber-300">{entry.term}</span>
          </span>
          <span className="block text-[10px] leading-relaxed text-slate-300 normal-case font-normal tracking-normal">{entry.def}</span>
          {entry.example && (
            <span className="mt-1 block text-[10px] leading-relaxed text-slate-400 italic normal-case font-normal tracking-normal">
              e.g. {entry.example}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
