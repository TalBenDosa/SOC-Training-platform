"use client";
/**
 * The named organization's environment for a team exercise: the platforms it runs beyond its
 * Microsoft workplace and its industry. Decides which attacks the exercise can draw and which
 * platform logs its feed carries (src/lib/team/environment.ts).
 */
import { useState } from "react";
import { ChevronDown, Server } from "lucide-react";
import { cn } from "@/lib/utils";
import { PLATFORM_CHOICES, INDUSTRY_CHOICES, DEFAULT_ENV, type TeamEnv, type Platform, type Industry } from "@/lib/team/environment";

export function EnvironmentPicker({ value, onChange, storyCount, defaultOpen = false, idPrefix = "env" }: {
  value: TeamEnv; onChange: (e: TeamEnv) => void; storyCount?: number | null; defaultOpen?: boolean; idPrefix?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const has = (p: Platform) => value.platforms.includes(p);
  const toggle = (p: Platform) => onChange({ ...value, platforms: PLATFORM_CHOICES.map(c => c.id).filter(id => id === p ? !has(p) : has(id)) });
  const industry = INDUSTRY_CHOICES.find(i => i.id === value.industry) ?? INDUSTRY_CHOICES[0];
  const summary = [industry.label, ...PLATFORM_CHOICES.filter(c => has(c.id)).map(c => c.label)].join(" · ");
  const isDefault = value.industry === DEFAULT_ENV.industry && value.platforms.join() === DEFAULT_ENV.platforms.join();

  return (
    <div className="rounded-lg border border-border bg-bg">
      <button type="button" onClick={() => setOpen(o => !o)} aria-expanded={open} aria-controls={`${idPrefix}-panel`}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left">
        <Server className="h-4 w-4 shrink-0 text-cyber-300" aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-white">
            Environment
            {typeof storyCount === "number" && <span className="ml-2 text-[11px] font-normal text-slate-400">{storyCount} attack storyline{storyCount === 1 ? "" : "s"} available</span>}
          </span>
          <span className="block truncate text-[11px] text-slate-500">{summary}</span>
        </span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-slate-400 transition", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div id={`${idPrefix}-panel`} className="space-y-3 border-t border-border px-3 py-3">
          <p className="text-[11px] leading-relaxed text-slate-400">
            Describe the organization: Windows endpoints, Microsoft 365 and its identity provider are always there.
            The attacks the exercise can draw — and the platform logs in the feed — follow what you select here.
          </p>
          <div className="flex items-center gap-3">
            <label htmlFor={`${idPrefix}-industry`} className="w-36 shrink-0 text-xs text-slate-400">Industry</label>
            <select id={`${idPrefix}-industry`} value={value.industry} onChange={e => onChange({ ...value, industry: e.target.value as Industry })}
              className="h-8 min-w-0 flex-1 rounded-md border border-border bg-bg-elevated px-2 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none">
              {INDUSTRY_CHOICES.map(i => <option key={i.id} value={i.id}>{i.label}</option>)}
            </select>
          </div>
          <p className="ml-[9.75rem] -mt-2 text-[10px] text-slate-500">{industry.hint}</p>
          <fieldset>
            <legend className="mb-1.5 text-xs text-slate-400">Platforms the organization runs</legend>
            <div className="grid gap-1.5 sm:grid-cols-2">
              {PLATFORM_CHOICES.map(c => {
                const id = `${idPrefix}-platform-${c.id}`;
                return (
                  <label key={c.id} htmlFor={id}
                    className={cn("flex cursor-pointer items-start gap-2 rounded-md border px-2.5 py-2 transition focus-within:ring-1 focus-within:ring-cyber-500/60",
                      has(c.id) ? "border-cyber-500/40 bg-cyber-500/[0.07]" : "border-border bg-bg-elevated hover:border-slate-600")}>
                    <input id={id} type="checkbox" checked={has(c.id)} onChange={() => toggle(c.id)} className="mt-0.5 accent-cyan-400" />
                    <span className="min-w-0">
                      <span className="block text-xs font-medium text-slate-200">{c.label}</span>
                      <span className="block text-[10px] leading-snug text-slate-500">{c.hint}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>
          {!isDefault && (
            <button type="button" onClick={() => onChange({ ...DEFAULT_ENV, platforms: [...DEFAULT_ENV.platforms] })} className="text-[11px] text-cyber-300 hover:underline">Reset to the default environment</button>
          )}
        </div>
      )}
    </div>
  );
}
