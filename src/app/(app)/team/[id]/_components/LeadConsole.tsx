"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ShieldCheck, Check, Siren } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { SitrepConsole } from "./SitrepConsole";
import { DecisionLog } from "./DecisionLog";
import { useServerNow } from "@/lib/team/clock";
import { containmentRequests, escalationStates, isOpenEscalation, scopeByIncident, latestScope as latestScopeOf } from "@/lib/team/projections";
import { containmentVerb } from "./T2Console";

// ── Lead console: containment requests → approve / deny ──────────────────────
export function LeadConsole({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({}); // per-request decision rationale (keyed by request seq)
  // P0-4: every pending REQUEST, keyed by its seq — a new request after a denial is
  // its own row (it used to vanish because the log's event_id was already "decided").
  const allReqs = useMemo(() => containmentRequests(events), [events]);
  const pending = allReqs.filter(r => r.status === "pending");
  // A1: T2's determination/recommendation per case + the working scope, so the
  // Manager approves containment WITH the justification, not blind.
  const now = useServerNow(15_000);   // C5: backlog ages on the server clock
  const reportByEid = useMemo(() => { const m = new Map<string, { verdict?: string; recommendation?: string; findings?: string; summary?: string }>(); for (const e of events) if (e.type === "report.submitted") m.set(String((e.payload as { event_id?: string }).event_id), e.payload as { verdict?: string; recommendation?: string; findings?: string; summary?: string }); return m; }, [events]);
  const scopes = useMemo(() => scopeByIncident(events), [events]);
  const latestScope = useMemo(() => latestScopeOf(events), [events]);
  // Oversight queue: escalations still waiting for a Tier-2 to pick up (not taken,
  // not bounced back, not resolved) — so the Manager sees the backlog from the first
  // minute and can chase it, instead of only getting work once a containment request lands.
  const escStates = useMemo(() => escalationStates(events), [events]);
  const waiting = [...escStates.values()].filter(s => s.rounds > 0 && isOpenEscalation(s)).map(s => s.request)
    .map(e => { const p = e.payload as { event_id?: string; summary?: string; what?: string; severity?: string }; const mins = e.occurred_at ? Math.max(0, Math.floor((now - Date.parse(e.occurred_at)) / 60000)) : 0; return { seq: e.seq, label: asStr(p.summary) || asStr(p.what) || "escalation", sev: asStr(p.severity), mins }; })
    .sort((a, b) => b.mins - a.mins);
  return (
    <div className="space-y-4">
      {/* Manager oversight — the queue state at a glance (no raw feed) */}
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Queue oversight</h3>
        {waiting.length === 0 ? (
          <p className="mt-2 text-xs text-slate-400">No escalations waiting to be picked up. Tier-2 is on top of the queue.</p>
        ) : (
          <>
            <p className="mt-1 text-[11px] text-slate-400">{waiting.length} escalation{waiting.length !== 1 ? "s" : ""} not yet picked up by Tier-2 — chase the oldest / highest-severity first.</p>
            <div className="mt-2 space-y-1">
              {waiting.slice(0, 6).map(w => (
                <div key={w.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-[11px]">
                  <span className="min-w-0 flex-1 truncate text-slate-300">{w.label}</span>
                  {w.sev && <span className="shrink-0 rounded border border-border px-1 py-0.5 font-mono text-[9px] uppercase text-slate-400">{w.sev}</span>}
                  <span className={`shrink-0 rounded border px-1 py-0.5 font-mono text-[9px] font-bold ${(w.sev === "high" || w.sev === "critical") && w.mins >= 5 ? "border-neon-amber/50 bg-neon-amber/10 text-neon-amber" : "border-border text-slate-400"}`}>⏱ {w.mins}m</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Card>
      <Card className="border-neon-amber/30">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-neon-amber" /> Containment approvals ({pending.length})</h3>
        {pending.length === 0 ? <p className="mt-2 text-xs text-slate-400">No requests waiting. Tier-2 asks you to approve containment here.</p> : (
          <div className="mt-2 space-y-2">
            {pending.map(r => {
              const e = r.request;
              const p = e.payload as { event_id?: string; target?: string; reason?: string; asset_criticality?: string; blast_radius?: string; business_owner?: string; containment_type?: string; incident?: string }; const eid = r.eid; const b = busy === e.seq + "";
              const note = notes[e.seq] ?? "";
              const crit = asStr(p.asset_criticality);
              // Earlier requests on the same case (e.g. a denied wrong target) — context for this one.
              const prior = allReqs.filter(x => x.eid === eid && x.seq < r.seq);
              const sc = (asStr(p.incident) && scopes.get(asStr(p.incident))) || latestScope;
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <p className="text-sm text-slate-200">{containmentVerb(asStr(p.containment_type))} <b className="text-white">{asStr(p.target) || "—"}</b>{asStr(p.incident) && <span className="ml-1.5 rounded border border-cyber-500/40 bg-cyber-500/10 px-1 py-0.5 font-mono text-[9px] text-cyber-300">{asStr(p.incident)}</span>}</p>
                  <p className="mt-0.5 text-[11px] text-slate-400">{asStr(p.reason)} · requested by <bdi>{nameOf(e.actor_id)}</bdi></p>
                  {prior.length > 0 && <p className="mt-0.5 text-[10px] text-slate-500">request #{prior.length + 1} on this case — before: {prior.map(x => `${asStr((x.request.payload as { target?: string }).target) || "?"} (${x.status}${x.decisionReason ? `: ${x.decisionReason}` : ""})`).join(" · ")}</p>}
                  {/* B10: business-impact so approve/deny is a real risk trade-off */}
                  {(crit || asStr(p.blast_radius) || asStr(p.business_owner)) && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {crit && <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${crit === "crown_jewel" ? "border-severity-high/50 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>{crit.replace("_", "-")}</span>}
                      {asStr(p.blast_radius) && <span className="rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-[9px] text-neon-amber">if isolated: {asStr(p.blast_radius)}</span>}
                      {asStr(p.business_owner) && <span className="rounded border border-border px-1.5 py-0.5 text-[9px] text-slate-400">{asStr(p.business_owner)}</span>}
                    </div>
                  )}
                  {/* A1: T2's determination + recommendation + scope, so this isn't a blind approval */}
                  {(() => { const r = reportByEid.get(eid); return r ? (
                    <div className="mt-1.5 rounded border border-cyber-500/25 bg-cyber-500/[0.05] px-2 py-1.5 text-[11px]">
                      <p className="text-slate-300"><span className="font-semibold text-cyber-200">T2 determination:</span> {asStr(r.verdict).replace("_", " ") || "—"}</p>
                      {asStr(r.recommendation) && <p className="mt-0.5 text-slate-300"><span className="text-slate-500">recommends:</span> {asStr(r.recommendation)}</p>}
                      {sc && <p className="mt-0.5 font-mono text-[10px] text-slate-500">scope: {sc.hosts.length}h · {sc.users.length}u · {sc.techniques.length}t{sc.hosts.length || sc.users.length ? ` — ${[...sc.hosts, ...sc.users].join(", ")}` : ""}</p>}
                    </div>
                  ) : <p className="mt-1 text-[10px] text-neon-amber">⚠ No incident report filed for this case yet — ask Tier-2 to file it before you approve.</p>; })()}
                  {/* Decision rationale — optional to Approve (fast confident call), required to Deny */}
                  <input aria-label="Decision rationale" value={note} onChange={ev => setNotes(n => ({ ...n, [e.seq]: ev.target.value }))} placeholder="Decision rationale — business impact / why (required to deny; say what to target instead)" className="mt-2 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  <div className="mt-2 flex gap-1.5">
                    <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("containment.approved", { event_id: eid, request_seq: e.seq, target: asStr(p.target) || undefined, reason: note.trim() || undefined }); setBusy(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Approve</Button>
                    <Button variant="outline" size="sm" disabled={b || !note.trim()} onClick={async () => { setBusy(e.seq + ""); await act("containment.denied", { event_id: eid, request_seq: e.seq, target: asStr(p.target) || undefined, reason: note.trim() }); setBusy(null); }}>Deny</Button>
                  </div>
                  <p className="mt-1 text-[10px] text-slate-500">Wrong target? Deny with the reason — Tier-2 can send a new request for the right asset.</p>
                </div>
              );
            })}
          </div>
        )}
      </Card>
      {/* G-15: Decision Log — the Lead records key decisions with rationale (feeds the AAR + rubric) */}
      <DecisionLog events={events} nameOf={nameOf} act={act} />
      {/* G-15 tail: SITREP — the 4-question situation report to the team/management */}
      <SitrepConsole events={events} nameOf={nameOf} act={act} />
    </div>
  );
}
