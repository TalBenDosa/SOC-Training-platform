"use client";
import { Card } from "@/components/ui/Card";
import { Siren } from "lucide-react";
import type { Ev } from "@/lib/team/types";

// ── Team intel (shared — everyone sees published intel) ───────────────────────
export function TeamIntel({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  const intel = events.filter(e => e.type === "intel.published");
  if (intel.length === 0) return null;
  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Team intel</h3>
      <div className="mt-2 space-y-2">
        {intel.slice().reverse().map(e => {
          const p = e.payload as { actor?: string; technique?: string; next_expected?: string; recommendation?: string; confidence?: number };
          return (
            <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2 text-xs">
              <p className="text-slate-200">{[p.actor, p.technique].filter(Boolean).join(" · ") || "intel"}{p.confidence != null && <span className="ml-1 text-slate-500">conf {p.confidence}</span>}</p>
              {p.next_expected && <p className="mt-0.5 text-slate-400">next: {p.next_expected}</p>}
              {p.recommendation && <p className="mt-0.5 text-cyber-300">→ {p.recommendation}</p>}
              <p className="mt-0.5 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</p>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
