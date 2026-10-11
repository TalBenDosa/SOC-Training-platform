"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Users } from "lucide-react";
import type { RosterMember, Ev } from "@/lib/team/types";
import { ROLE_LABEL } from "./shared";
import { useServerNow } from "@/lib/team/clock";
import { openLoadByUser } from "@/lib/team/projections";

// ── SOC Manager console ──────────────────────────────────────────────────────
export function MgrConsole({ roster, events, act }: { roster: RosterMember[]; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  // G-16: structured passdown (App. D) instead of a free-text blob.
  const [ho, setHo] = useState({ open_cases: "", blockers: "", next: "" });
  const [busy, setBusy] = useState(false);
  // Open work (claims + owned cases) is the load that matters; a raw action count
  // made a fast clicker look "busiest" (Manager playtest) — it's shown only as context.
  const now = useServerNow(15_000);
  const load = openLoadByUser(events, now);
  const workload = roster.filter(r => r.role !== "instructor" && r.role !== "observer" && r.status !== "left").map(m => ({
    user_id: m.user_id, name: m.name, role: m.role, open: load.get(m.user_id) ?? 0,
    actions: events.filter(e => e.actor_id === m.user_id && e.type !== "event.opened" && e.type !== "member.ready" && e.type !== "message.sent").length,
  }));
  const canPost = !!ho.open_cases.trim() && !!ho.next.trim();
  async function post() {
    if (!canPost) return;
    setBusy(true);
    // Compose a `text` summary so downstream (rubric completeness, activity) still reads a single field.
    const text = `Open: ${ho.open_cases.trim()} · Blockers: ${ho.blockers.trim() || "none"} · Next: ${ho.next.trim()}`;
    const ok = await act("handover.noted", { open_cases: ho.open_cases.trim(), blockers: ho.blockers.trim(), next: ho.next.trim(), text, summary: text });
    setBusy(false);
    if (ok) setHo({ open_cases: "", blockers: "", next: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Shift management</h3>
      <div className="mt-2 space-y-1">
        {workload.map(w => (
          <div key={w.user_id} className="flex items-center justify-between text-xs">
            <span className="text-slate-300"><bdi>{w.name}</bdi> <span className="font-mono text-[10px] text-slate-500">{ROLE_LABEL[w.role] ?? w.role}</span></span>
            <span className="font-mono text-slate-400"><b className={w.open >= 3 ? "text-neon-amber" : "text-slate-300"}>{w.open} open</b> · <span className="text-slate-500">{w.actions} actions</span></span>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Shift passdown</p>
        <label className="block text-[11px] font-semibold text-slate-300">Open cases
          <textarea value={ho.open_cases} onChange={e => setHo(s => ({ ...s, open_cases: e.target.value }))} placeholder="Open cases (id · sev · status · last action)" rows={2} className="mt-1 w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
        </label>
        <label className="block text-[11px] font-semibold text-slate-300">Blockers (optional)
          <input value={ho.blockers} onChange={e => setHo(s => ({ ...s, blockers: e.target.value }))} placeholder="Blockers (optional)" className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
        </label>
        <label className="block text-[11px] font-semibold text-slate-300">Next actions and deadline
          <input value={ho.next} onChange={e => setHo(s => ({ ...s, next: e.target.value }))} placeholder="Next actions + deadline" className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
        </label>
        <Button variant="primary" size="sm" disabled={busy || !canPost} onClick={post}>Sign passdown</Button>
      </div>
    </Card>
  );
}
