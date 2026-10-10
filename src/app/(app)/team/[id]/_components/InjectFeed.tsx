"use client";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Siren } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { useNewItemsAnnouncement, LiveRegion, clip } from "./useLiveAnnounce";

// No-hints: a player must judge a curveball on its content, so the live tag never
// reveals the scripted kind ("false lead", "twist"). The public payload itself now
// carries a neutral kind (migration 0071); staff see the REAL kind, read from the
// staff-only session_injects table. The AAR reveals it to everyone after the shift.
function injectLabel(kind: string, isStaff: boolean): string {
  if (isStaff) return kind.replace("_", " ");
  if (kind === "ticket") return "help-desk ticket";
  if (kind === "announcement") return "announcement";
  if (kind === "mgmt_request") return "management request";
  if (kind === "decision") return "decision for the SOC Manager";
  return "update"; // mgmt_pressure · twist · false_lead — indistinguishable live
}

// ── G-14: injects/announcements banner (everyone) + help-desk tickets (Tier-1) ─
export function InjectFeed({ sessionId, events, me, nameOf, act, hasManager = true, onWriteSitrep }: { sessionId: string; events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; hasManager?: boolean; onWriteSitrep?: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  // T1 playtest: a ticket answer was two canned strings — the analyst can now record
  // what they actually did (caller, verification, whether a code was shared).
  const [details, setDetails] = useState<Record<number, string>>({});
  const injects = useMemo(() => events.filter(e => e.type === "staff.inject"), [events]);
  const decided = useMemo(() => new Set(events.filter(e => e.type === "decision.answered").map(e => asStr((e.payload as { inject_id?: unknown }).inject_id))), [events]);
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
  // Announce new injects (throttled) — the label never leaks the scripted kind to players.
  const announcement = useNewItemsAnnouncement(injects, e => e.seq, fresh => {
    const last = fresh[fresh.length - 1];
    const p = last.payload as { kind?: string; text?: string };
    const latest = clip(`${injectLabel(asStr(p.kind) || "announcement", false)}: ${asStr(p.text)}`);
    return fresh.length === 1 ? `New inject — ${latest}` : `${fresh.length} new injects. Latest — ${latest}`;
  }, { throttleMs: 5000 });

  // The region stays mounted (same tree position) so the FIRST inject is announced too.
  if (injects.length === 0) return <><LiveRegion message={announcement} /></>;
  const answered = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: number }).ticket_seq)));
  const isT1 = me.role === "t1";
  const isMgr = me.role === "mgr" || me.role === "lead";
  const sitreps = events.filter(e => e.type === "sitrep.sent");
  return (
    <>
    <LiveRegion message={announcement} />
    <div id="team-injects" data-tour="injects" className="scroll-mt-24">
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" aria-hidden="true" /> Injects & help-desk</h3>
      {/* Scenario review fix 6: who acts on what was never said. */}
      <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
        <b className="text-neon-amber">Help-desk tickets</b> are answered by <b className="text-slate-300">Tier-1</b> (right here).{" "}
        <b className="text-neon-purple">Management requests</b> (CISO, Legal, execs) are answered by the <b className="text-slate-300">SOC Manager</b> with a SITREP.{" "}
        <b className="text-slate-300">Updates</b> need no reply: if one changes the picture, act in your own console — escalate, re-scope or hunt.
      </p>
      <div className="mt-2 space-y-1.5">
        {injects.slice().reverse().map(e => {
          const p = e.payload as { kind?: string; text?: string; inject_id?: string };
          const publicKind = asStr(p.kind) || "announcement";
          const kind = (me.is_staff && p.inject_id && realKind[p.inject_id]) || publicKind;
          const isTicket = publicKind === "ticket"; const done = answered.has(String(e.seq)); const b = busy === e.seq + "";
          // A management request (public kind, or the real kind for staff on an
          // instructor-typed one) — answered by the first SITREP sent after it.
          // A decision card is the SOC Manager's, answered on the Command desk; the team sees who asked what.
          if (publicKind === "decision") {
            const dp = e.payload as { from?: { name?: string; role?: string } };
            const done = !!p.inject_id && decided.has(p.inject_id);
            return (
              <div key={e.seq} className="rounded-lg border border-neon-purple/30 bg-neon-purple/[0.05] px-2 py-1.5 text-xs">
                <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-slate-400">{injectLabel("decision", false)}</span><b className="text-slate-100"><bdi>{asStr(dp.from?.name)}</bdi></b>{asStr(dp.from?.role) && <span className="text-slate-400"> ({asStr(dp.from?.role)})</span>}: <bdi>{asStr(p.text)}</bdi></p>
                {done ? <p className="mt-0.5 text-[10px] text-neon-green">✓ the SOC Manager decided</p>
                  : isMgr ? <Button variant="outline" size="sm" className="mt-1.5" onClick={() => document.querySelector("[data-command-desk]")?.scrollIntoView({ behavior: "smooth", block: "start" })}>Decide on the Command desk</Button>
                    : <p className="mt-0.5 text-[10px] text-neon-purple">The SOC Manager is deciding. Keep your case notes current: they decide from what you write.</p>}
              </div>
            );
          }
          const isMgmt = publicKind === "mgmt_request" || kind === "mgmt_pressure";
          const reply = isMgmt ? sitreps.find(s => s.seq > e.seq) : undefined;
          return (
            <div key={e.seq} className={`rounded-lg border px-2 py-1.5 text-xs ${isTicket ? "border-neon-amber/30 bg-neon-amber/[0.05]" : isMgmt ? "border-neon-purple/30 bg-neon-purple/[0.05]" : "border-border bg-bg"}`}>
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-slate-400">{injectLabel(kind, !!me.is_staff)}</span><bdi>{asStr(p.text)}</bdi></p>
              {isTicket && isT1 && !done && (() => { const d = (details[e.seq] ?? "").trim(); const answer = async (decision: string, base: string) => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision, response: d ? `${base} — ${d}` : base, details: d || undefined }); setBusy(null); }; return (
                <div className="mt-1.5 space-y-1.5">
                  <input aria-label="What you did for this ticket (optional)" value={details[e.seq] ?? ""} onChange={ev => setDetails(m => ({ ...m, [e.seq]: ev.target.value }))} placeholder="What you did — caller / user, how you verified, was anything shared? (optional)" className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  <div className="flex flex-wrap gap-1.5">
                    <Button variant="primary" size="sm" disabled={b} onClick={() => answer("handled", "handled the user's request as asked")}>Handle request</Button>
                    <Button variant="outline" size="sm" disabled={b} onClick={() => answer("rejected", "refused the request and escalated to security")}>Refuse &amp; escalate to security</Button>
                  </div>
                </div>
              ); })()}
              {isTicket && done && <p className="mt-0.5 text-[10px] text-neon-green">✓ answered by Tier-1</p>}
              {isTicket && !done && !isT1 && <p className="mt-0.5 text-[10px] text-neon-amber">Waiting for Tier-1 to answer it.</p>}
              {isMgmt && reply && <p className="mt-0.5 text-[10px] text-neon-green">✓ SITREP sent by <bdi>{nameOf(reply.actor_id)}</bdi></p>}
              {isMgmt && !reply && isMgr && (
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  <span className="text-[10px] text-neon-purple">Yours to answer — send a SITREP within ~15 min.</span>
                  <Button variant="outline" size="sm" onClick={() => (onWriteSitrep ? onWriteSitrep() : document.getElementById("team-sitrep")?.scrollIntoView({ behavior: "smooth", block: "center" }))}>Write SITREP</Button>
                </div>
              )}
              {isMgmt && !reply && !isMgr && (
                <p className="mt-0.5 text-[10px] text-neon-purple">
                  {hasManager ? "Waiting for the SOC Manager's SITREP — keep the case notes current so they can report accurately." : "No SOC Manager on this team, so nobody can answer this — ask the instructor to assign one."}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </Card>
    </div>
    </>
  );
}
