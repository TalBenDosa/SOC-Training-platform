"use client";
import { useState } from "react";
import { MonitorX } from "lucide-react";
import { Button } from "@/components/ui/Button";
import type { Ev, Me, RosterMember } from "@/lib/team/types";
import { canApproveIsolation, isolationRequests, type ApproverMember, type IsolationRequest } from "@/lib/team/isolationApproval";
import { answerIsolation } from "@/lib/team/useIsolationRequest";
import { ROLE_LABEL } from "./shared";

/**
 * Isolation requests waiting for THIS viewer's approval (owner, 2026-11-07: "a pop-up at the side,
 * or somewhere it does not get in the way, saying user X wants to isolate host Y"). Rendered in the
 * side column, in the page flow, so it never covers the feed or an input; one card per request,
 * stacked, until answered. Deny needs a reason, which the requester sees.
 */
export function isolationRequestsForMe(events: Ev[], roster: RosterMember[], online: Set<string>, meId: string | undefined): IsolationRequest[] {
  if (!meId) return [];
  const members: ApproverMember[] = roster.map(m => ({ user_id: m.user_id, role: m.role, status: m.status, active: online.has(m.user_id) }));
  return isolationRequests(events).filter(r => r.state === "pending" && canApproveIsolation(members, r.requestedBy, meId));
}

export function IsolationApprovals({ sessionId, events, roster, online, me, nameOf, onError }: {
  sessionId: string; events: Ev[]; roster: RosterMember[]; online: Set<string>; me: Me;
  nameOf: (u: string | null) => string; onError?: (msg: string) => void;
}) {
  const mine = isolationRequestsForMe(events, roster, online, me.id);
  const [denying, setDenying] = useState<number | null>(null);
  const [why, setWhy] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  if (!mine.length) return null;
  async function answer(r: IsolationRequest, approve: boolean) {
    setBusy(r.seq);
    const err = await answerIsolation(sessionId, r.seq, approve, approve ? undefined : why);
    setBusy(null);
    if (err) { onError?.(err); return; }
    setDenying(null); setWhy("");
  }
  return (
    <section data-tour="isolation-approvals" aria-label="Isolation requests waiting for you" className="space-y-2">
      {mine.map(r => {
        const role = r.requesterRole ? ROLE_LABEL[r.requesterRole] ?? r.requesterRole : "";
        const id = `iso-deny-${r.seq}`;
        return (
          <div key={r.seq} role="alert" className="rounded-lg border border-neon-amber/60 bg-neon-amber/[0.07] px-3 py-2.5 text-xs">
            <p className="flex items-start gap-2 text-slate-100">
              <MonitorX className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" aria-hidden />
              <span><b><bdi>{nameOf(r.requestedBy)}</bdi></b>{role ? ` (${role})` : ""} wants to isolate <b className="font-mono"><bdi>{r.host}</bdi></b>.</span>
            </p>
            <p className="mt-1 text-slate-300"><span className="text-slate-400">Reason:</span> <bdi>{r.reason || "none given"}</bdi></p>
            {r.incident && <p className="mt-0.5 text-slate-300"><span className="text-slate-400">Incident:</span> <bdi>{r.incident}</bdi></p>}
            <p className="mt-1 text-[11px] text-slate-400">Isolating cuts the host off the network: it stops the attacker, and the user loses the machine until it is released.</p>
            {denying === r.seq ? (
              <div className="mt-2 space-y-1.5">
                <label htmlFor={id} className="block text-[11px] text-slate-300">Why not? The requester sees your reason.</label>
                <input id={id} value={why} onChange={e => setWhy(e.target.value)} maxLength={500} dir="auto" autoFocus
                  onKeyDown={e => { if (e.key === "Enter" && why.trim()) void answer(r, false); }}
                  className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50" />
                <div className="flex gap-1.5">
                  <Button size="sm" variant="primary" disabled={busy === r.seq || !why.trim()} onClick={() => answer(r, false)}>Send denial</Button>
                  <Button size="sm" variant="outline" onClick={() => { setDenying(null); setWhy(""); }}>Back</Button>
                </div>
              </div>
            ) : (
              <div className="mt-2 flex gap-1.5">
                <Button size="sm" variant="primary" disabled={busy === r.seq} onClick={() => answer(r, true)}>Approve</Button>
                <Button size="sm" variant="outline" disabled={busy === r.seq} onClick={() => { setDenying(r.seq); setWhy(""); }}>Deny</Button>
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}
