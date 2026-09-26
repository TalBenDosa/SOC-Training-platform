"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Siren } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// No-hints: a player must judge a curveball on its content, so the live tag never
// reveals the scripted kind ("false lead", "twist"). Staff see the real kind; the
// AAR reveals it to everyone after the shift.
function injectLabel(kind: string, isStaff: boolean): string {
  if (isStaff) return kind.replace("_", " ");
  if (kind === "ticket") return "help-desk ticket";
  if (kind === "announcement") return "announcement";
  return "update"; // mgmt_pressure · twist · false_lead — indistinguishable live
}

// ── G-14: injects/announcements banner (everyone) + help-desk tickets (Tier-1) ─
export function InjectFeed({ events, me, nameOf, act }: { events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const injects = events.filter(e => e.type === "staff.inject");
  if (injects.length === 0) return null;
  const answered = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: number }).ticket_seq)));
  const isT1 = me.role === "t1";
  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Injects & help-desk</h3>
      <div className="mt-2 space-y-1.5">
        {injects.slice().reverse().map(e => {
          const p = e.payload as { kind?: string; text?: string }; const kind = asStr(p.kind) || "announcement";
          const isTicket = kind === "ticket"; const done = answered.has(String(e.seq)); const b = busy === e.seq + "";
          return (
            <div key={e.seq} className={`rounded-lg border px-2 py-1.5 text-xs ${isTicket ? "border-neon-amber/30 bg-neon-amber/[0.05]" : "border-border bg-bg"}`}>
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-slate-500">{injectLabel(kind, !!me.is_staff)}</span>{asStr(p.text)}</p>
              {isTicket && isT1 && !done && (
                <div className="mt-1.5 flex gap-1.5">
                  <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision: "handled", response: "verified caller, no code shared" }); setBusy(null); }}>Handle</Button>
                  <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision: "rejected", response: "refused the request and escalated to security" }); setBusy(null); }}>Refuse &amp; escalate to security</Button>
                </div>
              )}
              {isTicket && done && <p className="mt-0.5 text-[10px] text-neon-green">✓ answered by Tier-1</p>}
            </div>
          );
        })}
      </div>
    </Card>
  );
}
