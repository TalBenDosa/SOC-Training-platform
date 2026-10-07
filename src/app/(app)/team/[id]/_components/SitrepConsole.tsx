"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── G-15: SITREP (Lead) — a 4-question situation report ───────────────────────
export function SitrepConsole({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ situation: "", actions: "", status: "", next: "" });
  const [busy, setBusy] = useState(false);
  const sitreps = events.filter(e => e.type === "sitrep.sent");
  // Quality gate (parity with T1's escalation gate): a real SITREP answers all four
  // questions, with a substantive situation line (≥8 words), not one-word fields.
  const canSend = !!f.situation.trim() && !!f.actions.trim() && !!f.status.trim() && !!f.next.trim();
  async function send() {
    if (!canSend) return;
    setBusy(true); const ok = await act("sitrep.sent", { situation: f.situation.trim(), actions: f.actions.trim(), status: f.status.trim(), next: f.next.trim() }); setBusy(false);
    if (ok) setF({ situation: "", actions: "", status: "", next: "" });
  }
  return (
    <div id="team-sitrep" className="scroll-mt-24">
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-cyber-300" /> SITREP ({sitreps.length})</h3>
      {sitreps.length > 0 && (
        <div className="mt-2 max-h-40 space-y-1 overflow-y-auto">
          {sitreps.slice().reverse().map(e => { const p = e.payload as { situation?: string; status?: string }; return (
            <div key={e.seq} className="rounded border border-border/60 bg-bg px-2 py-1 text-xs">
              <p className="text-slate-200">{asStr(p.situation)}</p>
              <p className="text-[10px] text-slate-500">status: {asStr(p.status)} · <bdi>{nameOf(e.actor_id)}</bdi></p>
            </div>
          ); })}
        </div>
      )}
      <div className="mt-2 space-y-1.5">
        <input aria-label="What is happening" value={f.situation} onChange={e => setF(s => ({ ...s, situation: e.target.value }))} placeholder="1. What's happening?" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input aria-label="Actions taken" value={f.actions} onChange={e => setF(s => ({ ...s, actions: e.target.value }))} placeholder="2. Actions taken" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input aria-label="Current status" value={f.status} onChange={e => setF(s => ({ ...s, status: e.target.value }))} placeholder="3. Current status" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input aria-label="Next steps" value={f.next} onChange={e => setF(s => ({ ...s, next: e.target.value }))} placeholder="4. Next steps" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        {!canSend && <p className="text-[10px] text-slate-500">Answer all four.</p>}
        <Button variant="outline" size="sm" disabled={busy || !canSend} onClick={send}>Send SITREP</Button>
      </div>
    </Card>
    </div>
  );
}
