"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Siren } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useServerNow } from "@/lib/team/clock";

// ── Team intel (shared — everyone sees published intel) ───────────────────────
// TI playtest: the card hid the IOC and relevance and lived in a folded tab, so all
// of TI's influence went through chat. It now shows the indicator, relevance,
// recommendation and the case it enriches, and sits on its own (visible) card with a
// "new" marker for fresh intel.
const FRESH_MS = 3 * 60 * 1000;
export function TeamIntel({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  const [all, setAll] = useState(false);
  const now = useServerNow(15_000);
  const intel = events.filter(e => e.type === "intel.published");
  if (intel.length === 0) return null;
  const shown = intel.slice().reverse().slice(0, all ? intel.length : 3);
  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Team intel ({intel.length})</h3>
      <div className="mt-2 space-y-2">
        {shown.map(e => {
          const p = e.payload as { actor?: string; technique?: string; next_expected?: string; recommendation?: string; confidence?: number; relevance?: string; ioc?: string; ioc_type?: string; case_label?: string };
          const fresh = !!e.occurred_at && now - Date.parse(e.occurred_at) < FRESH_MS;
          const rel = asStr(p.relevance);
          return (
            <div key={e.seq} className={`rounded-lg border px-3 py-2 text-xs ${fresh ? "border-cyber-500/50 bg-cyber-500/[0.06]" : "border-border bg-bg"}`}>
              <div className="flex items-center gap-1.5">
                {fresh && <span className="rounded bg-cyber-500/20 px-1 py-0.5 text-[9px] font-bold uppercase text-cyber-300">new</span>}
                <p className="min-w-0 flex-1 text-slate-200">{[asStr(p.actor), asStr(p.technique)].filter(Boolean).join(" · ") || "intel"}</p>
                {rel && <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${rel === "high" ? "border-severity-high/50 bg-severity-high/10 text-severity-high" : rel === "medium" ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : "border-border text-slate-400"}`}>relevance {rel}</span>}
                {p.confidence != null && <span className="shrink-0 text-[10px] text-slate-500">conf {p.confidence}</span>}
              </div>
              {asStr(p.ioc) && <p className="mt-1 break-all font-mono text-[11px] text-slate-200"><span className="text-slate-500">{asStr(p.ioc_type) || "ioc"}:</span> {asStr(p.ioc)}</p>}
              {asStr(p.case_label) && <p className="mt-0.5 text-[10px] text-slate-500">re: {asStr(p.case_label)}</p>}
              {asStr(p.next_expected) && <p className="mt-0.5 text-slate-400">next: {asStr(p.next_expected)}</p>}
              {asStr(p.recommendation) && <p className="mt-0.5 text-cyber-300">→ {asStr(p.recommendation)}</p>}
              <p className="mt-0.5 font-mono text-[10px] text-slate-500"><bdi>{nameOf(e.actor_id)}</bdi></p>
            </div>
          );
        })}
      </div>
      {intel.length > 3 && <button onClick={() => setAll(a => !a)} aria-expanded={all} className="mt-1.5 text-[11px] text-cyber-300 underline-offset-2 hover:underline">{all ? "show latest only" : `show all ${intel.length}`}</button>}
    </Card>
  );
}
