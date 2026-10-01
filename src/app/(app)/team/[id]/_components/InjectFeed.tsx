"use client";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Siren } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

// No-hints: a player must judge a curveball on its content, so the live tag never
// reveals the scripted kind ("false lead", "twist"). The public payload itself now
// carries a neutral kind (migration 0071); staff see the REAL kind, read from the
// staff-only session_injects table. The AAR reveals it to everyone after the shift.
function injectLabel(kind: string, isStaff: boolean): string {
  if (isStaff) return kind.replace("_", " ");
  if (kind === "ticket") return "help-desk ticket";
  if (kind === "announcement") return "announcement";
  return "update"; // mgmt_pressure · twist · false_lead — indistinguishable live
}

// ── G-14: injects/announcements banner (everyone) + help-desk tickets (Tier-1) ─
export function InjectFeed({ sessionId, events, me, nameOf, act }: { sessionId: string; events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  void nameOf;
  const [busy, setBusy] = useState<string | null>(null);
  // T1 playtest: a ticket answer was two canned strings — the analyst can now record
  // what they actually did (caller, verification, whether a code was shared).
  const [details, setDetails] = useState<Record<number, string>>({});
  const injects = useMemo(() => events.filter(e => e.type === "staff.inject"), [events]);
  // Staff: map inject_id → the real (answer-key) kind. RLS lets only session staff read it.
  const [realKind, setRealKind] = useState<Record<string, string>>({});
  const injectCount = injects.length;
  useEffect(() => {
    if (!me.is_staff || injectCount === 0) return;
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let cancelled = false;
    void sb.from("session_injects").select("id, expected_action").eq("session_id", sessionId).eq("channel", "inject")
      .then(({ data }) => {
        if (cancelled || !data) return;
        const m: Record<string, string> = {};
        for (const r of data as { id: string; expected_action: { kind?: string } | null }[]) if (r.expected_action?.kind) m[r.id] = r.expected_action.kind;
        setRealKind(m);
      });
    return () => { cancelled = true; };
  }, [me.is_staff, sessionId, injectCount]);

  if (injects.length === 0) return null;
  const answered = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: number }).ticket_seq)));
  const isT1 = me.role === "t1";
  return (
    <div id="team-injects" className="scroll-mt-24">
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Injects & help-desk</h3>
      {/* Scenario review fix 6: who acts on what was never said. */}
      <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
        <b className="text-neon-amber">Help-desk tickets</b> are answered by <b className="text-slate-300">Tier-1</b> (right here).{" "}
        <b className="text-slate-300">Updates</b> need no reply: if one changes the picture, act in your own console — analysts escalate / scope / hunt, the SOC Manager answers requests for status with a SITREP.
      </p>
      <div className="mt-2 space-y-1.5">
        {injects.slice().reverse().map(e => {
          const p = e.payload as { kind?: string; text?: string; inject_id?: string };
          const publicKind = asStr(p.kind) || "announcement";
          const kind = (me.is_staff && p.inject_id && realKind[p.inject_id]) || publicKind;
          const isTicket = publicKind === "ticket"; const done = answered.has(String(e.seq)); const b = busy === e.seq + "";
          return (
            <div key={e.seq} className={`rounded-lg border px-2 py-1.5 text-xs ${isTicket ? "border-neon-amber/30 bg-neon-amber/[0.05]" : "border-border bg-bg"}`}>
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-slate-400">{injectLabel(kind, !!me.is_staff)}</span>{asStr(p.text)}</p>
              {isTicket && isT1 && !done && (() => { const d = (details[e.seq] ?? "").trim(); const answer = async (decision: string, base: string) => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision, response: d ? `${base} — ${d}` : base, details: d || undefined }); setBusy(null); }; return (
                <div className="mt-1.5 space-y-1.5">
                  <input value={details[e.seq] ?? ""} onChange={ev => setDetails(m => ({ ...m, [e.seq]: ev.target.value }))} placeholder="What you did — caller / user, how you verified, was anything shared? (optional)" className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  <div className="flex flex-wrap gap-1.5">
                    <Button variant="primary" size="sm" disabled={b} onClick={() => answer("handled", "handled the user's request as asked")}>Handle request</Button>
                    <Button variant="outline" size="sm" disabled={b} onClick={() => answer("rejected", "refused the request and escalated to security")}>Refuse &amp; escalate to security</Button>
                  </div>
                </div>
              ); })()}
              {isTicket && done && <p className="mt-0.5 text-[10px] text-neon-green">✓ answered by Tier-1</p>}
              {isTicket && !done && !isT1 && <p className="mt-0.5 text-[10px] text-neon-amber">Waiting for Tier-1 to answer it.</p>}
            </div>
          );
        })}
      </div>
    </Card>
    </div>
  );
}
