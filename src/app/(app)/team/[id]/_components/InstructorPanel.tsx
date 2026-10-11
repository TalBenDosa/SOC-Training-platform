"use client";
import { useState } from "react";
import { displayError } from "@/lib/http/apiError";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ShieldCheck } from "lucide-react";
import type { RosterMember, Ev } from "@/lib/team/types";
import { ROLE_LABEL } from "./shared";
import { AddMemberPanel } from "./AddMemberPanel";
import { AnswerKeyPanel } from "./AnswerKeyPanel";
import { RemoveMemberButton } from "./RemoveMemberButton";

/** Roles the reassign control offers (the route also accepts lead/de — legacy seats). Observer parks a seat without dropping the member (QA L8). */
export const REASSIGN_ROLES = ["t1", "t2", "t3", "mgr", "ti", "observer"] as const;

// canInject: only the session's own instructor SEAT posts injects (staff.inject is an
// action of that seat); another instructor of the org gets every other tool (QA L4).
export function InstructorPanel({ sessionId, roster, online, events, act, isStaff, nameOf, canInject = true, onError }: { sessionId: string; roster: RosterMember[]; online: Set<string>; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; isStaff: boolean; nameOf: (u: string | null) => string; canInject?: boolean; onError?: (msg: string) => void }) {
  // G-14: inject-composer — the instructor injects an announcement or a help-desk
  // ticket mid-exercise (staff.inject). Tickets land in Tier-1's queue to answer.
  // expected_response goes to the staff-only answer key (never to players) so a
  // manual curveball shows what "good" looked like in the AAR.
  const [inj, setInj] = useState({ kind: "announcement", text: "", expected: "" });
  const [busy, setBusy] = useState(false);
  const injects = events.filter(e => e.type === "staff.inject");
  const members = roster.filter(r => r.role !== "instructor" && r.status !== "left");   // a removed member is off the board
  // F7: recover a dropped single-seat by handing the role to another member.
  const [ra, setRa] = useState({ user_id: "", role: "" });
  const [raBusy, setRaBusy] = useState(false);
  const [raMsg, setRaMsg] = useState<{ ok: boolean; text: string } | null>(null);
  async function reassign() {
    if (!ra.user_id || !ra.role) return;
    setRaBusy(true); setRaMsg(null);
    try {
      const res = await fetch(`/api/team/sessions/${sessionId}/reassign`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ra),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "Reassign failed.");
      const who = roster.find(r => r.user_id === ra.user_id)?.name ?? "member";
      setRaMsg({ ok: true, text: `${who} → ${ROLE_LABEL[ra.role] ?? ra.role}. Their screen switches automatically.` });
      setRa({ user_id: "", role: "" });
    } catch (e) {
      setRaMsg({ ok: false, text: displayError(e, "Reassign failed.") });
    } finally {
      setRaBusy(false);
    }
  }
  async function post() {
    if (!inj.text.trim()) return;
    setBusy(true); const ok = await act("staff.inject", { kind: inj.kind, text: inj.text.trim(), expected_response: inj.expected.trim() || undefined }); setBusy(false);
    if (ok) setInj({ kind: inj.kind, text: "", expected: "" });
  }
  return (
    <>
    {/* Live answer key vs team — staff only (RLS enforces it server-side too) */}
    {isStaff && <AnswerKeyPanel sessionId={sessionId} events={events} nameOf={nameOf} />}
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Instructor view</h3>
      <div className="mt-2 space-y-1">
        {members.map(m => (
          <div key={m.user_id} className="flex items-center gap-2 text-xs">
            <span className={`h-1.5 w-1.5 rounded-full ${online.has(m.user_id) ? "bg-neon-green" : "bg-slate-600"}`} aria-hidden="true" /><span className="sr-only">{online.has(m.user_id) ? "online" : "offline"}</span>
            <bdi className="text-slate-300">{m.name}</bdi>
            <span className="font-mono text-[10px] text-slate-500">{ROLE_LABEL[m.role] ?? m.role}</span>
            {m.lapsed && <span className="text-[10px] text-severity-high" title="Their access to your organisation has expired — they can't act.">access expired</span>}
            {isStaff && <span className="ml-auto"><RemoveMemberButton sessionId={sessionId} userId={m.user_id} name={m.name} onError={onError} /></span>}
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Inject ({injects.length} sent)</p>
        {!canInject && <p className="text-[11px] text-slate-500">Injects are sent from the session owner&apos;s instructor seat.</p>}
        {canInject && <>
        <select aria-label="Inject type" value={inj.kind} onChange={e => setInj(s => ({ ...s, kind: e.target.value }))} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
          <option value="announcement">announcement (all roles)</option>
          <option value="ticket">help-desk ticket (Tier-1 answers)</option>
          <option value="mgmt_pressure">management pressure (Manager)</option>
          <option value="twist">plot twist (forces a re-scope)</option>
          <option value="false_lead">false lead (a decoy to reject)</option>
        </select>
        <textarea aria-label="Inject text" value={inj.text} onChange={e => setInj(s => ({ ...s, text: e.target.value }))} placeholder="Inject text (e.g. 'User in Finance says a vendor called asking for an MFA code')" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        {inj.kind !== "announcement" && <input aria-label="Expected response (staff-only answer key)" value={inj.expected} onChange={e => setInj(s => ({ ...s, expected: e.target.value }))} placeholder="Expected response (staff-only answer key — shown in the review)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />}
        <Button variant="primary" size="sm" disabled={busy || !inj.text.trim()} onClick={post}>Send inject</Button>
        </>}
      </div>

      {/* F7: reassign a role — recover a dropped Tier-3 / Manager so the relay continues */}
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Reassign a role (recover a dropped seat)</p>
        <div className="flex gap-1.5">
          <select aria-label="Member to reassign" value={ra.user_id} onChange={e => setRa(s => ({ ...s, user_id: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
            <option value="">— member —</option>
            {members.map(m => <option key={m.user_id} value={m.user_id}>{m.name}{online.has(m.user_id) ? "" : " (offline)"}</option>)}
          </select>
          <select aria-label="New role" value={ra.role} onChange={e => setRa(s => ({ ...s, role: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
            <option value="">— role —</option>
            {REASSIGN_ROLES.map(r => <option key={r} value={r}>{ROLE_LABEL[r] ?? r}</option>)}
          </select>
        </div>
        <Button variant="outline" size="sm" disabled={raBusy || !ra.user_id || !ra.role} onClick={reassign}>Reassign</Button>
        {raMsg && <p className={`text-[11px] ${raMsg.ok ? "text-neon-green" : "text-severity-high"}`}>{raMsg.text}</p>}
      </div>

      {/* Grow the team mid-shift — add a member to a role */}
      <AddMemberPanel sessionId={sessionId} roster={roster} />
    </Card>
    </>
  );
}
