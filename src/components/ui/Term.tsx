"use client";
/**
 * <Term k="ioc">IOCs</Term> — inline glossary tooltip.
 *
 * Renders its children with a dotted underline; hovering (or tapping) shows
 * the plain-English definition from src/lib/glossary.ts. Used at key spots so
 * a first-time SOC student never has to guess an acronym.
 */
import { useState } from "react";
import { BookOpen } from "lucide-react";
import { GLOSSARY } from "@/lib/glossary";

export function Term({ k, children }: { k: string; children: React.ReactNode }) {
  const [visible, setVisible] = useState(false);
  const entry = GLOSSARY[k];
  if (!entry) return <>{children}</>;

  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
      onClick={(e) => { e.stopPropagation(); setVisible(v => !v); }}
    >
      <span className="cursor-help border-b border-dotted border-cyber-500/60 hover:border-cyber-400 transition-colors">
        {children}
      </span>
      {visible && (
        <span className="absolute left-0 top-full mt-1.5 z-[60] block w-72 rounded-lg border border-border/80 bg-[#080d14] px-3 py-2.5 shadow-2xl">
          <span className="flex items-center gap-1.5 mb-1">
            <BookOpen className="h-3 w-3 text-cyber-400" />
            <span className="text-[10px] font-bold uppercase tracking-wider text-cyber-300">{entry.term}</span>
          </span>
          <span className="block text-[10px] leading-relaxed text-slate-300 normal-case font-normal tracking-normal">{entry.def}</span>
          {entry.example && (
            <span className="mt-1 block text-[10px] leading-relaxed text-slate-500 italic normal-case font-normal tracking-normal">
              e.g. {entry.example}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
