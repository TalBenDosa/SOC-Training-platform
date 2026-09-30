"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Check } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── G-15: Decision Log (Lead/Mgr) — decision.logged is already gated ──────────
export function DecisionLog({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ decision: "", rationale: "" });
  const [busy, setBusy] = useState(false);
  const decisions = events.filter(e => e.type === "decision.logged");
  // A decision needs its "why" — but no length minimum (0079); the rationale's
  // depth is reflected in the end-of-exercise scoring, not a send gate.
  const canLog = !!f.decision.trim() && !!f.rationale.trim();
  async function log() {
    if (!canLog) return;
    setBusy(true); const ok = await act("decision.logged", { decision: f.decision.trim(), rationale: f.rationale.trim() }); setBusy(false);
    if (ok) setF({ decision: "", rationale: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Check className="h-4 w-4 text-cyber-300" /> Decision log ({decisions.length})</h3>
      {decisions.length > 0 && (
        <div className="mt-2 max-h-40 space-y-1 overflow-y-auto">
          {decisions.slice().reverse().map(e => { const p = e.payload as { decision?: string; rationale?: string }; return (
            <div key={e.seq} className="rounded border border-border/60 bg-bg px-2 py-1 text-xs">
              <p className="text-slate-200">{asStr(p.decision)}</p>
              {asStr(p.rationale) && <p className="text-[10px] text-slate-500">why: {asStr(p.rationale)} · {nameOf(e.actor_id)}</p>}
            </div>
          ); })}
        </div>
      )}
      <div className="mt-2 space-y-1.5">
        <input value={f.decision} onChange={e => setF(s => ({ ...s, decision: e.target.value }))} placeholder="Decision (e.g. 'isolate FIN-WS-07, keep DC online')" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <textarea value={f.rationale} onChange={e => setF(s => ({ ...s, rationale: e.target.value }))} placeholder="Rationale — why this call, and the business impact considered " rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        {!canLog && <p className="text-[10px] text-slate-500">Needs: a decision and its rationale.</p>}
        <Button variant="outline" size="sm" disabled={busy || !canLog} onClick={log}>Log decision</Button>
      </div>
    </Card>
  );
}
