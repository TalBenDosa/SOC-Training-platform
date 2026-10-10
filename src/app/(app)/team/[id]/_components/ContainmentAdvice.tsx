"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Scale } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { containmentRequests } from "@/lib/team/projections";

/**
 * Tier-2 / Tier-3: a second opinion on a teammate's pending containment request. "Support" or
 * "Object, keep watching" with a reason goes on the record for the SOC Manager; a real objection
 * is the ONLY thing that raises the "isolate or wait" decision on the manager's desk.
 */
export function ContainmentAdvice({ events, meId, nameOf, act }: { events: Ev[]; meId: string; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const pending = useMemo(() => containmentRequests(events).filter(c => c.status === "pending" && c.request.actor_id !== meId), [events, meId]);
  const mine = useMemo(() => new Map(events.filter(e => e.type === "containment.advised" && e.actor_id === meId).map(e => [Number((e.payload as { request_seq?: unknown }).request_seq), asStr((e.payload as { stance?: unknown }).stance)])), [events, meId]);
  const [reason, setReason] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | null>(null);
  if (!pending.length) return null;

  async function advise(seq: number, stance: "support" | "object") {
    const r = (reason[seq] ?? "").trim();
    if (stance === "object" && !r) return;
    setBusy(seq);
    await act("containment.advised", { request_seq: seq, stance, reason: r.slice(0, 300) });
    setBusy(null);
  }

  return (
    <Card className="border-neon-amber/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Scale className="h-4 w-4 text-neon-amber" aria-hidden /> Containment waiting for the SOC Manager</h3>
      <p className="mt-1 text-[11px] text-slate-400">A teammate asked to contain. If you agree or think it is too early (scope not known, it would tip off the attacker), say so: the SOC Manager sees your view before deciding.</p>
      <div className="mt-2 space-y-2">
        {pending.map(c => {
          const p = c.request.payload as { target?: unknown; containment_type?: unknown; reason?: unknown };
          const done = mine.get(c.seq);
          return (
            <div key={c.seq} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
              <p className="text-slate-200"><bdi>{nameOf(c.request.actor_id)}</bdi> asks to {asStr(p.containment_type) || "isolate"} <bdi className="font-mono">{asStr(p.target)}</bdi>{asStr(p.reason) && <span className="text-slate-400">: &quot;{asStr(p.reason)}&quot;</span>}</p>
              {done ? <p className={`mt-1 text-[11px] ${done === "object" ? "text-neon-amber" : "text-neon-green"}`}>You {done === "object" ? "objected" : "supported it"}. The SOC Manager can see it.</p> : (
                <div className="mt-1.5 space-y-1.5">
                  <input aria-label="Your reason" value={reason[c.seq] ?? ""} maxLength={300} onChange={e => setReason(m => ({ ...m, [c.seq]: e.target.value }))}
                    placeholder="Why (required to object): e.g. scope not confirmed, two more hosts beaconing" className="w-full rounded border border-border bg-bg-elevated px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  <div className="flex gap-1.5">
                    <Button variant="outline" size="sm" disabled={busy === c.seq} onClick={() => advise(c.seq, "support")}>Support</Button>
                    <Button variant="outline" size="sm" disabled={busy === c.seq || !(reason[c.seq] ?? "").trim()} onClick={() => advise(c.seq, "object")}>Object, keep watching</Button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}
