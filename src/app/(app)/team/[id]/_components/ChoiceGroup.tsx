"use client";
import { useId } from "react";

/**
 * A row of pill choices built on native radio inputs: arrow keys move between options, Space
 * selects, screen readers announce "radio, 2 of 4", and the focus ring is visible. Replaces the
 * hand-rolled role="radio" buttons that had no keyboard model.
 */
export function ChoiceGroup<T extends string | number>({ legend, options, value, onChange, size = "sm", hideLegend = true, tone = "purple" }: {
  legend: string;
  options: { value: T; label: string; hint?: string }[];
  value: T | null;
  onChange: (v: T) => void;
  size?: "sm" | "xs";
  hideLegend?: boolean;
  tone?: "purple" | "cyan";
}) {
  const name = useId();
  const on = tone === "cyan" ? "peer-checked:border-cyber-500/60 peer-checked:bg-cyber-500/15 peer-checked:text-cyber-100" : "peer-checked:border-neon-purple/60 peer-checked:bg-neon-purple/15 peer-checked:text-white";
  return (
    <fieldset className="min-w-0">
      <legend className={hideLegend ? "sr-only" : "mb-1 text-[11px] text-slate-300"}>{legend}</legend>
      <div className="flex flex-wrap gap-1">
        {options.map(o => (
          <label key={String(o.value)} title={o.hint} className="relative cursor-pointer">
            <input type="radio" name={name} value={String(o.value)} checked={value === o.value} onChange={() => onChange(o.value)} className="peer sr-only" />
            <span className={`block rounded border border-border px-2 ${size === "xs" ? "py-0.5 text-[11px]" : "py-1 text-[11px] font-mono font-semibold"} text-slate-300 transition hover:text-white peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-1 peer-focus-visible:outline-cyber-400 ${on}`}>{o.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
