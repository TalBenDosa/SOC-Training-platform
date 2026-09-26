"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Users } from "lucide-react";
import type { RosterMember, Ev } from "@/lib/team/types";
import { ROLE_LABEL } from "./shared";

// ── SOC Manager console ──────────────────────────────────────────────────────
export function MgrConsole({ roster, events, act }: { roster: RosterMember[]; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  // G-16: structured passdown (App. D) instead of a free-text blob.
  const [ho, setHo] = useState({ open_cases: "", blockers: "", next: "" });
  const [busy, setBusy] = useState(false);
  const workload = roster.filter(r => r.role !== "instructor").map(m => ({
    name: m.name, role: m.role,
    actions: events.filter(e => e.actor_id === m.user_id && e.type !== "event.opened" && e.type !== "member.ready").length,
  }));
  const canPost = ho.open_cases.trim().length >= 5 && ho.next.trim().length >= 3;
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
          <div key={w.name} className="flex items-center justify-between text-xs">
            <span className="text-slate-300">{w.name} <span className="font-mono text-[10px] text-slate-500">{ROLE_LABEL[w.role] ?? w.role}</span></span>
            <span className="font-mono text-slate-400">{w.actions} actions</span>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Shift passdown</p>
        <textarea value={ho.open_cases} onChange={e => setHo(s => ({ ...s, open_cases: e.target.value }))} placeholder="Open cases (id · sev · status · last action)" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={ho.blockers} onChange={e => setHo(s => ({ ...s, blockers: e.target.value }))} placeholder="Blockers (optional)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={ho.next} onChange={e => setHo(s => ({ ...s, next: e.target.value }))} placeholder="Next actions + deadline" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <Button variant="primary" size="sm" disabled={busy || !canPost} onClick={post}>Sign passdown</Button>
      </div>
    </Card>
  );
}
