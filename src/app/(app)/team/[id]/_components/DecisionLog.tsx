"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Check } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── G-15: Decision Log (Lead/Mgr) ─────────────────────────────────────────────
// One truthful log of the manager's decisions: what they logged by hand, the decision cards
// they decided on the Command desk, and the containments they approved or denied. Only the
// hand-written entry is typed here; the others are recorded where they were made.
interface Entry { seq: number; source: "logged" | "card" | "containment"; what: string; why: string; by: string | null }
const SOURCE_LABEL: Record<Entry["source"], string> = { logged: "logged", card: "decision card", containment: "containment" };

export function DecisionLog({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ decision: "", rationale: "" });
  const [busy, setBusy] = useState(false);
  const cards = new Map(events.filter(e => e.type === "staff.inject" && (e.payload as { kind?: unknown }).kind === "decision")
    .map(e => [asStr((e.payload as { inject_id?: unknown }).inject_id), e.payload as { from?: { name?: string }; options?: { id: string; label: string }[] }]));
  const entries: Entry[] = events.flatMap((e): Entry[] => {
    const p = e.payload as Record<string, unknown>;
    if (e.type === "decision.logged") return [{ seq: e.seq, source: "logged", what: asStr(p.decision), why: asStr(p.rationale), by: e.actor_id }];
    if (e.type === "decision.answered") {
      const c = cards.get(asStr(p.inject_id));
      const label = c?.options?.find(o => o.id === asStr(p.option))?.label ?? "an option";
      return [{ seq: e.seq, source: "card", what: `${c?.from?.name ? `${c.from.name}: ` : ""}${label}`, why: asStr(p.rationale), by: e.actor_id }];
    }
    if (e.type === "containment.approved" || e.type === "containment.denied") {
      return [{ seq: e.seq, source: "containment", what: `${e.type === "containment.approved" ? "Approved" : "Denied"} containment of ${asStr(p.target) || "the target"}`, why: asStr(p.reason), by: e.actor_id }];
    }
    return [];
  });
  // A decision needs its "why", but no length minimum (0079); the rationale's depth is
  // reflected in the end-of-exercise scoring, not a send gate.
  const canLog = !!f.decision.trim() && !!f.rationale.trim();
  async function log() {
    if (!canLog) return;
    setBusy(true); const ok = await act("decision.logged", { decision: f.decision.trim(), rationale: f.rationale.trim() }); setBusy(false);
    if (ok) setF({ decision: "", rationale: "" });
  }
  const field = "mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60";
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Check className="h-4 w-4 text-cyber-300" aria-hidden /> Decision log ({entries.length})</h3>
      <p className="mt-0.5 text-[11px] text-slate-400">Every decision you made this shift, with its reason: cards from the desk, containment approvals and the ones you log here.</p>
      {entries.length > 0 && (
        <div className="mt-2 max-h-48 space-y-1 overflow-y-auto">
          {entries.slice().reverse().map(x => (
            <div key={x.seq} className="rounded border border-border/60 bg-bg px-2 py-1 text-xs">
              <p className="text-slate-200"><span className="mr-1 rounded border border-border px-1 font-mono text-[10px] uppercase text-slate-400">{SOURCE_LABEL[x.source]}</span><bdi>{x.what}</bdi></p>
              <p className={`text-[11px] ${x.why ? "text-slate-400" : "text-neon-amber"}`}>{x.why ? <>why: <bdi>{x.why}</bdi></> : "no reason recorded"} · <bdi>{nameOf(x.by)}</bdi></p>
            </div>
          ))}
        </div>
      )}
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <label className="block text-[11px] font-semibold text-slate-300">Log another decision
          <input value={f.decision} onChange={e => setF(s => ({ ...s, decision: e.target.value }))} placeholder="e.g. isolate FIN-WS-07, keep DC online" className={field} />
        </label>
        <label className="block text-[11px] font-semibold text-slate-300">Rationale
          <textarea value={f.rationale} onChange={e => setF(s => ({ ...s, rationale: e.target.value }))} placeholder="Why this call, and the business impact you weighed" rows={2} className={`${field} resize-y`} />
        </label>
        {!canLog && <p className="text-[11px] text-slate-400">Needs a decision and its rationale.</p>}
        <Button variant="outline" size="sm" disabled={busy || !canLog} onClick={log}>Log decision</Button>
      </div>
    </Card>
  );
}
