"use client";
/**
 * Pick the security products a training session runs on (spec §3, step 2): one
 * vendor per category, defaulting to the company's own architecture. Every log in
 * the session is then rendered in the chosen product's native format, and only
 * attacks the chosen products can really show are picked.
 */
import { useState } from "react";
import { ChevronDown, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { STACK_CHOICES, PRODUCT_LABEL, COMPANY_STACKS, type Stack } from "@/lib/logs/native/stack";
import { lsGet, lsSet } from "@/lib/storage/safeStorage";

const storeKey = (companyId: string) => `soc_stack_${companyId}`;

/** The stack this browser last chose for a company (empty = the company's own products). */
export function savedStack(companyId: string): Stack {
  try { const v = JSON.parse(lsGet(storeKey(companyId)) ?? "{}"); return v && typeof v === "object" ? v as Stack : {}; } catch { return {}; }
}
export function saveStack(companyId: string, stack: Stack): void {
  lsSet(storeKey(companyId), JSON.stringify(stack));
}

/** Only the categories that differ from the company default (what gets stored / sent). */
export function stackDelta(companyId: string, stack: Stack): Stack {
  const base = COMPANY_STACKS[companyId] ?? {};
  const out: Stack = {};
  for (const c of STACK_CHOICES) if (stack[c.category] && stack[c.category] !== base[c.category]) out[c.category] = stack[c.category];
  return out;
}

export function StackPicker({ companyId, value, onChange, defaultOpen = false, idPrefix = "stack" }: {
  companyId: string; value: Stack; onChange: (s: Stack) => void; defaultOpen?: boolean; idPrefix?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const base = COMPANY_STACKS[companyId] ?? {};
  const effective = (cat: (typeof STACK_CHOICES)[number]["category"]) => value[cat] ?? base[cat] ?? "";
  const changed = STACK_CHOICES.filter(c => value[c.category] && value[c.category] !== base[c.category]).length;
  const summary = STACK_CHOICES.map(c => PRODUCT_LABEL[effective(c.category) as keyof typeof PRODUCT_LABEL]).filter(Boolean).join(" · ");

  return (
    <div className="rounded-lg border border-border bg-bg">
      <button type="button" onClick={() => setOpen(o => !o)} aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left">
        <Shield className="h-4 w-4 shrink-0 text-cyber-300" />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-white">Security products{changed ? <span className="ml-2 text-[11px] font-normal text-neon-amber">{changed} changed</span> : null}</span>
          <span className="block truncate text-[11px] text-slate-500">{summary || "The company's own products"}</span>
        </span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-slate-400 transition", open && "rotate-180")} />
      </button>
      {open && (
        <div className="space-y-2.5 border-t border-border px-3 py-3">
          <p className="text-[11px] leading-relaxed text-slate-400">
            Match the products your team really runs. Every log is shown in the chosen product&apos;s native format, and only attacks those products can really show are picked.
          </p>
          {STACK_CHOICES.map(c => {
            const id = `${idPrefix}-${c.category}`;
            const current = effective(c.category);
            return (
              <div key={c.category}>
                <div className="flex items-center gap-3">
                  <label htmlFor={id} className="w-36 shrink-0 text-xs text-slate-400">{c.label}</label>
                  <select id={id} value={current}
                    onChange={e => onChange({ ...value, [c.category]: e.target.value || undefined })}
                    className="h-8 min-w-0 flex-1 rounded-md border border-border bg-bg-elevated px-2 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                    {!current && <option value="">— not in this environment —</option>}
                    {c.options.map(o => (
                      <option key={o} value={o}>{PRODUCT_LABEL[o]}{base[c.category] === o ? " (company default)" : ""}</option>
                    ))}
                  </select>
                </div>
                {c.note && current && (current === "sophos" || current === "zscaler_zpa" || current === "cloudflare_access" || current === "google_workspace") && (
                  <p className="ml-[9.75rem] mt-1 text-[10px] leading-relaxed text-slate-500">{c.note}</p>
                )}
              </div>
            );
          })}
          {changed > 0 && (
            <button type="button" onClick={() => onChange({})} className="text-[11px] text-cyber-300 hover:underline">Reset to the company&apos;s products</button>
          )}
        </div>
      )}
    </div>
  );
}
