"use client";
import { useEffect, useId, useRef, useState } from "react";
import { TeamImageThumb, imagesOf } from "./teamImages";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DetailPanelBody } from "@/app/(app)/dashboard/EventFeed";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { CheckCircle2, ShieldCheck, ArrowUpRight, Check, ShieldAlert, Siren, ChevronDown, Search, FileText, Maximize2, X } from "lucide-react";
import type { Ev, Ioc, ScopeState } from "@/lib/team/types";
import { asStr, type ActR } from "@/lib/team/format";
import type { ContainmentRequest, EscalationState, ScopeSnapshot } from "@/lib/team/projections";
import { enrichSnapshot, slaMinFor } from "./shared";
import { ScopeConsole } from "./ScopeConsole";
import { useServerNow } from "@/lib/team/clock";
import { activeMs, type PauseSpan } from "@/lib/team/pauses";

// ── T2/T3 console: escalation inbox → ack → request/execute containment + scope ─
const BOUNCE_REASONS = ["Missing a clear indicator", "Looks like noise / benign", "Needs more context or evidence", "Duplicate of another case", "Other"];
const T2_REPORT_VERDICTS = ["true_positive", "false_positive", "benign", "escalate"];
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0.5 };
// P0-4: containment is not only "isolate the host" — an account or an indicator can be the right target.
export const CONTAINMENT_TYPES: [string, string][] = [["isolate_host", "Isolate host"], ["disable_account", "Disable account / revoke sessions"], ["block_indicator", "Block indicator (IP / domain / hash)"]];
export const containmentVerb = (t?: string) => (t === "disable_account" ? "Disable" : t === "block_indicator" ? "Block" : "Isolate");
const EMPTY_REP = { summary: "", findings: "", verdict: "true_positive", recommendation: "", incident: "" };

export function T2Console({ sessionId, role, meId, escalations, escState, reportedIds, reportByEid, elevatedIds, containments, scope, scopes, incidents, incidentOf, nameOf, act, actR, onEdr, onPivot, pauses = [] }: {
  sessionId: string; role: string; meId: string;
  /** The CURRENT round of every escalated log (one row per log). */
  escalations: Ev[]; escState: Map<string, EscalationState>;
  reportedIds: Set<string>; reportByEid: Map<string, { verdict?: string; findings?: string; recommendation?: string; summary?: string }>; elevatedIds: Set<string>;
  containments: ContainmentRequest[];
  scope: ScopeState; scopes: Map<string, ScopeSnapshot>; incidents: string[]; incidentOf: Map<string, string>;
  nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; actR: ActR; onEdr?: (description?: string, host?: string) => void;
  onPivot?: (field: "user" | "host" | "ip", value: string) => void;
  /** Paused spans of the session (pausedSpans) — waits and SLA badges skip them. */
  pauses?: PauseSpan[];
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [openLog, setOpenLog] = useState<number | null>(null); // which escalation's full log is expanded
  // The escalated log opened full-screen — the inbox column is too narrow to read a
  // real log comfortably, so Tier-2 can lift it into a wide reading view.
  const [fullLog, setFullLog] = useState<{ title: string; from: string; notes: string; snap: NonNullable<ReturnType<typeof enrichSnapshot>> } | null>(null);
  const [bouncingId, setBouncingId] = useState<string | null>(null); // eid being bounced (shows reason input)
  const [bounceReason, setBounceReason] = useState(BOUNCE_REASONS[0]);
  const [bounceMsg, setBounceMsg] = useState("");
  const [reportFor, setReportFor] = useState<string | null>(null); // eid whose report form is open
  const [rep, setRep] = useState(EMPTY_REP);
  const [elevatingId, setElevatingId] = useState<string | null>(null); // A2: eid being elevated (shows the "what to hunt" compose)
  const [huntAsk, setHuntAsk] = useState("");
  const [containingId, setContainingId] = useState<string | null>(null); // B10: eid whose containment-request form is open
  const [contForm, setContForm] = useState({ target: "", type: "isolate_host", incident: "", criticality: "standard", blast: "", owner: "" });
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null); // A3: live threat-intel enrichment
  useEffect(() => {
    if (!fullLog) return;
    const onKey = (ev: KeyboardEvent) => { if (ev.key === "Escape" && !threatQuery) setFullLog(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fullLog, threatQuery]);
  // P0-3: explicit take-over — `ownedPrompt` = the server said case_owned (or the lock
  // is visible); `confirmTake` = the analyst asked to take it over (second click sends).
  const [ownedPrompt, setOwnedPrompt] = useState<string | null>(null);
  const [confirmTake, setConfirmTake] = useState<string | null>(null);
  // scope-first: containment can't be requested until a working scope exists.
  const scopeSet = !!scope && (scope.hosts.length > 0 || scope.users.length > 0 || scope.techniques.length > 0);
  const eidOf = (e: Ev) => String((e.payload as { event_id?: string }).event_id);
  const stOf = (eid: string) => escState.get(eid);
  const isMine = (eid: string) => stOf(eid)?.owner === meId;
  async function ack(eid: string, takeover = false) {
    setBusy("ack" + eid);
    const r = await actR("escalation.acknowledged", takeover ? { event_id: eid, takeover: true } : { event_id: eid }, { handled: ["case_owned"] });
    setBusy(null);
    if (r.ok) { setOwnedPrompt(null); setConfirmTake(null); }
    else if (r.code === "case_owned") setOwnedPrompt(eid);
  }
  async function submitReport(eid: string) {
    // No length minimums (0079) — write as much or as little as the case needs.
    if (!rep.summary.trim() || !rep.findings.trim() || !rep.recommendation.trim()) return;
    setBusy("rep" + eid);
    const ok = await act("report.submitted", { event_id: eid, summary: rep.summary.trim(), findings: rep.findings.trim(), verdict: rep.verdict, recommendation: rep.recommendation.trim(), incident: rep.incident.trim() || undefined });
    setBusy(null);
    if (ok) { setReportFor(null); setRep(EMPTY_REP); }
  }
  // For Tier-3 the inbox is secondary (hunting is the dominant action) → collapse it
  // by default so the console isn't a wall of always-open cards.
  const [inboxOpen, setInboxOpen] = useState(role !== "t3");
  // Approved but not yet executed → the analyst must carry out the containment (G-09).
  // Keyed by REQUEST (a re-request after a deny is its own row).
  const toExecute = containments.filter(r => r.status === "approved");
  // Prioritized queue: open cases first, ranked by severity × waiting × confidence
  // (a 'contain' request weighs heavier). Acked/bounced/resolved sink to the bottom.
  // C5: waiting time / SLA on the server clock, ticking every 15s.
  const now = useServerNow(15_000);
  // QA M3: an escalation's wait / SLA counts running time only (paused spans skipped).
  const waitedMs = (iso: string) => activeMs(Date.parse(iso), now, pauses);
  const prioKey = (e: Ev) => {
    const p = e.payload as { event_id?: string; severity?: string; confidence?: number; requested_action?: string };
    const st = stOf(String(p.event_id));
    const open = !!st && !st.acked && !st.bounced && !st.resolved;
    const sev = asStr(p.severity) || "medium";
    const wait = e.occurred_at ? Math.max(0, waitedMs(e.occurred_at) / 60000) : 0;
    const conf = typeof p.confidence === "number" ? p.confidence : 0.5;
    const contain = p.requested_action === "contain" ? 1.5 : 1;
    return { open, score: (SEV_RANK[sev] ?? 2) * (1 + wait / 5) * (0.5 + conf) * contain };
  };
  const prioritized = [...escalations].sort((a, b) => { const ka = prioKey(a), kb = prioKey(b); if (ka.open !== kb.open) return ka.open ? -1 : 1; return kb.score - ka.score; });
  // Cases THIS analyst owns (took, or took over) and hasn't resolved — the ones a
  // report can be attached to in the bottom "your report" section (§5 handover).
  const myCases = prioritized.filter(e => { const eid = eidOf(e); const st = stOf(eid); return isMine(eid) && !st?.resolved && !st?.bounced; });
  const selEid = (reportFor && myCases.some(e => eidOf(e) === reportFor)) ? reportFor : (myCases[0] ? eidOf(myCases[0]) : null);
  const selCase = myCases.find(e => eidOf(e) === selEid) || null;
  const selLabel = selCase ? (asStr((selCase.payload as { summary?: string; what?: string }).summary) || asStr((selCase.payload as { what?: string }).what)) : "";
  // Assisted pull: the most urgent case nobody has taken yet.
  const nextUnacked = prioritized.find(e => { const st = stOf(eidOf(e)); return !!st && !st.acked && !st.bounced && !st.resolved; }) || null;
  async function takeNextCase() { if (nextUnacked) await ack(eidOf(nextUnacked)); }
  const fullLogRef = useRef<HTMLDivElement>(null);
  // Trap focus in the full-screen log; hand off while the threat-intel drawer is on top of it.
  useFocusTrap(!!fullLog && !threatQuery, fullLogRef, { onEscape: () => setFullLog(null) });
  const uid = useId();
  const incidentList = <datalist id="team-incidents">{incidents.map(i => <option key={i} value={i} />)}</datalist>;
  return (
    <div className="space-y-4">
      {incidentList}
      <Card>
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white">
            {role === "t3" && <button onClick={() => setInboxOpen(o => !o)} aria-expanded={inboxOpen} aria-label={inboxOpen ? "Collapse escalations" : "Expand escalations"} className="text-slate-400 hover:text-white"><ChevronDown aria-hidden="true" className={`h-4 w-4 transition-transform ${inboxOpen ? "" : "-rotate-90"}`} /></button>}
            <Siren className="h-4 w-4 text-neon-amber" /> Escalations for you ({escalations.length})
          </h3>
          <div className="flex items-center gap-2">
            {nextUnacked && <Button variant="outline" size="sm" disabled={busy != null} onClick={takeNextCase}>Take next case</Button>}
            {onEdr && <Button variant="outline" size="sm" onClick={() => onEdr()}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>}
          </div>
        </div>
        {!inboxOpen ? <p className="mt-2 text-[11px] text-slate-500">{escalations.length} case(s) waiting — expand to review. Your focus is hunting &amp; scope below; a case you take here you can also report and close.</p>
          : escalations.length === 0 ? <p className="mt-2 text-xs text-slate-400">Nothing escalated yet. Tier-1 sends cases here.</p> : (
          <div className="mt-2 space-y-2">
            {prioritized.map(e => {
              const p = e.payload as { event_id?: string; what?: string; summary?: string; why?: string; observations?: string; assessment?: string; impact?: string; severity?: string; confidence?: number; requested_action?: string; entity?: string; hostname?: string; low_confidence?: boolean; iocs?: Ioc[]; snapshot?: Record<string, unknown>; images?: unknown };
              const eid = String(p.event_id); const st = stOf(eid);
              const isAck = !!st?.acked; const isBounced = !!st?.bounced; const isResolved = !!st?.resolved; const mine = isMine(eid);
              const b = busy === e.seq + "" || busy === "ack" + eid;
              const iocs = Array.isArray(p.iocs) ? p.iocs : [];
              const snap = enrichSnapshot(p.snapshot); const isOpen = openLog === e.seq;
              const so = (p.snapshot ?? {}) as { hostname?: unknown; user_email?: unknown; user?: { email?: unknown }; src_ip?: unknown };
              // Containment target: PREFILLED from the log, but editable (P0-4) — quick picks
              // from the log's own entities and the working scope.
              const defTarget = asStr(p.entity) || asStr(p.hostname) || asStr(p.impact) || "";
              const picks = [...new Set([asStr(p.hostname), asStr(so.hostname), asStr(so.user_email), asStr(so.user?.email), asStr(p.entity), ...(scope?.hosts ?? []), ...(scope?.users ?? [])].filter(Boolean))].slice(0, 8);
              const myReqs = containments.filter(r => r.eid === eid);
              const lastReq = myReqs[myReqs.length - 1];
              const canRequest = !lastReq || lastReq.status === "denied" || lastReq.status === "executed";
              const inc = incidentOf.get(eid);
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <div className="flex items-start gap-2">
                    <p className="min-w-0 flex-1 text-sm text-slate-200">{asStr(p.summary) || asStr(p.what)}</p>
                    {inc && <span className="shrink-0 rounded border border-cyber-500/40 bg-cyber-500/10 px-1 py-0.5 font-mono text-[9px] text-cyber-300" title="incident">{inc}</span>}
                    {p.low_confidence && <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">low-conf</span>}
                    {(st?.rounds ?? 1) > 1 && <span className="shrink-0 rounded border border-border px-1 py-0.5 text-[9px] font-bold uppercase text-slate-400" title="escalated again after a bounce/resolve">re-escalated</span>}
                    {isResolved ? <span className="shrink-0 rounded border border-neon-green/40 bg-neon-green/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-green">resolved</span>
                      : isBounced ? <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">bounced</span> : null}
                  </div>
                  {/* The ticket carries T1's initial investigation — the label makes the
                      bundle explicit (investigation + indicators + the log below). */}
                  {(asStr(p.observations) || asStr(p.why) || asStr(p.assessment)) && (
                    <div className="mt-1 rounded border border-border/50 bg-bg-elevated/30 px-2 py-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Tier-1 initial investigation</p>
                      <p className="mt-0.5 text-[11px] text-slate-300">{asStr(p.observations) || asStr(p.why)}</p>
                      {asStr(p.assessment) && <p className="mt-0.5 text-[11px] text-slate-400">Assessment: {asStr(p.assessment)}</p>}
                    </div>
                  )}
                  {imagesOf(p.images).length > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Screenshots ({imagesOf(p.images).length})</p>
                      <div className="mt-0.5 flex flex-wrap gap-1.5">
                        {imagesOf(p.images).map((img, i) => <TeamImageThumb key={img.path} sessionId={sessionId} image={img} alt={`Tier-1 screenshot ${i + 1} for this escalation`} className="max-h-28" />)}
                      </div>
                    </div>
                  )}
                  {iocs.length > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Indicators ({iocs.length})</p>
                      <div className="mt-0.5 flex flex-wrap gap-1">{iocs.slice(0, 8).map(i => <span key={i.value} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[9px] text-slate-300"><span className="text-slate-500">{i.type}:</span>{i.value}</span>)}</div>
                    </div>
                  )}
                  <p className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-slate-500">
                    <span>from {nameOf(e.actor_id)} · sev {asStr(p.severity) || asStr(p.impact) || "—"} · conf {p.confidence}{p.requested_action ? ` · asks: ${p.requested_action}` : ""}</span>
                    {!isAck && !isBounced && !isResolved && e.occurred_at && (() => {
                      const mins = Math.max(0, Math.floor(waitedMs(e.occurred_at) / 60000));
                      const breached = mins >= slaMinFor(asStr(p.severity) || "medium"); // SLA by severity
                      return <span className={`rounded border px-1 py-px font-bold ${breached ? "border-severity-high/60 bg-severity-high/15 text-severity-high" : "border-border text-slate-400"}`}>⏱ waiting {mins}m{breached ? " · SLA" : ""}</span>;
                    })()}
                  </p>
                  {isBounced && st?.bounceReason && <p className="mt-1 text-[10px] text-neon-amber">↩ bounced to Tier-1: {st.bounceReason}</p>}
                  {/* Open the FULL original log T1 flagged — investigate the real event, not just the words */}
                  {snap && (
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
                      <button onClick={() => setFullLog({ title: asStr(p.summary) || asStr(p.what) || "Escalated log", from: nameOf(e.actor_id), notes: asStr(p.observations) || asStr(p.why), snap })}
                        className="flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 text-[11px] font-semibold text-cyber-300 hover:bg-cyber-500/20">
                        <Maximize2 className="h-3 w-3" /> Read the log full-screen
                      </button>
                      <button onClick={() => setOpenLog(isOpen ? null : e.seq)} aria-expanded={isOpen} className="flex items-center gap-1 text-[11px] text-cyber-300 underline-offset-2 hover:underline">
                        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? "" : "-rotate-90"}`} /> {isOpen ? "Hide the log" : "Show it here"}
                      </button>
                    </div>
                  )}
                  {snap && isOpen && (
                    <div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40">
                      <DetailPanelBody event={snap} onThreatQuery={setThreatQuery} onPivot={onPivot} />
                    </div>
                  )}
                  {/* Routed handling: whoever acknowledges first owns the case (server-enforced,
                      P0-3); a backup takes it over explicitly (confirm step → takeover: true). */}
                  {!isResolved && ((isAck && !mine) || ownedPrompt === eid) && (
                    <div className="mt-1 rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px]">
                      <div className="flex items-center gap-2">
                        <span className="text-neon-amber">🔒 handled by {st?.owner ? nameOf(st.owner) : "another analyst"}</span>
                        {confirmTake !== eid && <Button variant="outline" size="sm" className="ml-auto" disabled={b} onClick={() => setConfirmTake(eid)}>Take over (backup)</Button>}
                      </div>
                      {confirmTake === eid && (
                        <div className="mt-1 flex flex-wrap items-center gap-1.5">
                          <span className="text-slate-300">Take this case over? Only if they asked for help or went quiet — say so in the war room.</span>
                          <Button variant="primary" size="sm" disabled={b} onClick={() => ack(eid, true)}>Confirm take-over</Button>
                          <Button variant="outline" size="sm" onClick={() => setConfirmTake(null)}>Cancel</Button>
                        </div>
                      )}
                    </div>
                  )}
                  {isAck && mine && !isResolved && <p className="mt-1 text-[11px] text-neon-green">✓ you&apos;re handling this</p>}
                  {/* EDR prompt — once taken, nudge the analyst to investigate on the endpoint
                      (both Tier-2 and Tier-3 can). Opens the EDR console with THIS event's
                      description in its header. Shown when the flagged log has endpoint context. */}
                  {isAck && mine && (() => {
                    const sn = p.snapshot as { source?: string; hostname?: string } | undefined;
                    const hasEndpoint = !!sn && (sn.source === "edr" || sn.source === "sysmon" || !!sn.hostname);
                    if (!hasEndpoint || !onEdr) return null;
                    return (
                      <div className="mt-2 flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/[0.08] px-2.5 py-1.5">
                        <span className="text-sm leading-none">🖥</span>
                        <span className="min-w-0 flex-1 text-[11px] text-cyber-200">Endpoint activity on this host — investigate it in EDR before you decide.</span>
                        <Button variant="primary" size="sm" className="shrink-0" onClick={() => onEdr(asStr(p.summary) || asStr(p.what) || "Escalated incident", sn?.hostname)}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>
                      </div>
                    );
                  })()}
                  {/* Containment history on this case — a denial shows WHY, and a new request can follow */}
                  {myReqs.length > 0 && (
                    <div className="mt-1.5 space-y-0.5">
                      {myReqs.map(r => { const rp = r.request.payload as { target?: string; containment_type?: string }; return (
                        <p key={r.seq} className={`text-[10px] ${r.status === "denied" ? "text-severity-high" : r.status === "executed" ? "text-neon-green" : "text-cyber-300"}`}>
                          <ShieldAlert className="mr-1 inline h-3 w-3" />{containmentVerb(asStr(rp.containment_type))} <b>{asStr(rp.target) || "target"}</b> — {r.status === "pending" ? "waiting for the Manager" : r.status === "approved" ? "approved — execute below" : r.status === "executed" ? "executed" : `denied${r.decidedBy ? ` by ${nameOf(r.decidedBy)}` : ""}${r.decisionReason ? `: ${r.decisionReason}` : ""}`}
                        </p>
                      ); })}
                    </div>
                  )}
                  {!isResolved && !isBounced && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {!isAck && ownedPrompt !== eid
                        ? <Button variant="outline" size="sm" disabled={b} onClick={() => ack(eid)}><Check className="mr-1 h-3.5 w-3.5" /> Acknowledge (take this case)</Button>
                        : null}
                      {/* Report is a hard gate for containment + resolve (§5). The case OWNER files it —
                          Tier-2, or Tier-3 when it took the case (so T3 can close what it owns). */}
                      {mine && !reportedIds.has(eid) && <Button variant="outline" size="sm" onClick={() => { setReportFor(eid); setRep({ ...EMPTY_REP, incident: inc ?? "" }); if (typeof document !== "undefined") document.getElementById("t2-report")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}><FileText className="mr-1 h-3.5 w-3.5" /> Write report ↓</Button>}
                      {isAck && reportedIds.has(eid) && <span className="inline-flex items-center gap-1 text-[11px] text-neon-green"><CheckCircle2 className="h-3.5 w-3.5" /> report filed</span>}
                      {mine && canRequest && containingId !== eid && <Button variant="primary" size="sm" disabled={b || !scopeSet || !reportedIds.has(eid)} onClick={() => { setContainingId(eid); setContForm({ target: lastReq?.status === "denied" ? "" : defTarget, type: "isolate_host", incident: inc ?? "", criticality: "standard", blast: "", owner: "" }); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> {lastReq?.status === "denied" ? "Request again (new target / justification)" : lastReq?.status === "executed" ? "Contain another target" : "Request containment"}</Button>}
                      {/* Escalate a hard case to Tier-3 for a deep hunt (routed handover, not shared) */}
                      {role === "t2" && mine && (elevatedIds.has(eid)
                        ? <span className="inline-flex items-center gap-1 text-[11px] text-neon-purple"><ArrowUpRight className="h-3.5 w-3.5" /> escalated to Tier-3</span>
                        : elevatingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setElevatingId(eid); setHuntAsk(""); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Escalate to Tier-3</Button>)}
                      {role === "t2" && !isAck && bouncingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setBouncingId(eid); setBounceReason(BOUNCE_REASONS[0]); setBounceMsg(""); }}>Bounce</Button>}
                      {mine && <Button variant="outline" size="sm" disabled={b || !reportedIds.has(eid)} onClick={async () => { setBusy(e.seq + ""); await act("escalation.resolved", { event_id: eid }); setBusy(null); }}>Resolve</Button>}
                      {/* Pin the key evidence to the Shared Case (wires the evidence.pinned rubric signal) */}
                      {isAck && <Button variant="outline" size="sm" disabled={b} onClick={async () => { const label = asStr(p.summary) || asStr(p.what) || "flagged log"; setBusy(e.seq + ""); await act("evidence.pinned", { event_id: eid, label, summary: label, iocs }); setBusy(null); }}>📌 Pin to case</Button>}
                    </div>
                  )}
                  {/* What's blocking containment/resolve on this ticket */}
                  {mine && !isResolved && (!scopeSet || !reportedIds.has(eid)) && (
                    <p className="mt-1 text-[10px] text-slate-500">Before containment/resolve:{!reportedIds.has(eid) ? " write the incident report ·" : ""}{!scopeSet ? " set the scope (needed for containment)" : ""}</p>
                  )}
                  {/* Bounce from a preset reason list (+ optional detail) — real, specific feedback to T1 */}
                  {!isResolved && bouncingId === eid && (
                    <div className="mt-2 space-y-1.5">
                      <select aria-label="Bounce reason" value={bounceReason} onChange={ev => setBounceReason(ev.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">{BOUNCE_REASONS.map(r => <option key={r} value={r}>{r}</option>)}</select>
                      <div className="flex gap-1.5">
                        <input aria-label="Optional detail for Tier-1" value={bounceMsg} onChange={ev => setBounceMsg(ev.target.value)} placeholder="Optional detail for Tier-1…" className="flex-1 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                        <Button variant="outline" size="sm" disabled={b} onClick={async () => { const reason = bounceReason + (bounceMsg.trim() ? ` — ${bounceMsg.trim()}` : ""); setBusy(e.seq + ""); await act("escalation.bounced", { event_id: eid, reason }); setBusy(null); setBouncingId(null); }}>Send bounce</Button>
                        <Button variant="outline" size="sm" aria-label="Cancel bounce" onClick={() => setBouncingId(null)}>✕</Button>
                      </div>
                    </div>
                  )}
                  {/* A2: elevate-to-Tier-3 compose — a required "what to hunt / why", and T2's filed
                      findings ride along so the hunter starts from context, not the raw alert. */}
                  {!isResolved && elevatingId === eid && (() => { const rpt = reportByEid.get(eid); return (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-neon-purple/30 bg-neon-purple/[0.05] p-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Hand off to Tier-3 — what should they hunt?</p>
                      <textarea aria-label="What to hunt and why you are elevating" value={huntAsk} onChange={ev => setHuntAsk(ev.target.value)} placeholder="What to hunt & why you're elevating (e.g. 'confirmed C2 beacon from WS-FIN-2847 — hunt lateral movement to the DC and check other finance hosts for the same hash')" rows={2} className="w-full resize-y rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      {rpt ? <p className="text-[10px] text-neon-green">✓ your filed report (verdict + findings + recommendation) will travel with this elevation.</p>
                           : <p className="text-[10px] text-neon-amber">⚠ no report filed yet — Tier-3 gets more to work with if you write the report first.</p>}
                      <div className="flex gap-1.5">
                        <Button variant="primary" size="sm" disabled={b || !huntAsk.trim()} onClick={async () => { setBusy(e.seq + ""); await act("elevation.requested", { event_id: eid, summary: asStr(p.summary) || asStr(p.what), snapshot: p.snapshot, hostname: asStr(p.hostname), entity: asStr(p.entity), severity: asStr(p.severity), iocs, hunt_ask: huntAsk.trim(), t2_verdict: rpt?.verdict, t2_findings: rpt?.findings, t2_recommendation: rpt?.recommendation }); setBusy(null); setElevatingId(null); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Send to Tier-3</Button>
                        <Button variant="outline" size="sm" aria-label="Cancel elevation" onClick={() => setElevatingId(null)}>✕</Button>
                      </div>
                    </div>
                  ); })()}
                  {/* B10 + P0-4: containment-request compose — an EDITABLE target (free text: a host, an
                      account, a DC, an indicator), its type, and the business-impact context so the
                      Manager's approval is a real risk decision, not a rubber stamp. */}
                  {!isResolved && containingId === eid && (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-severity-high/30 bg-severity-high/[0.05] p-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Request containment — give the Manager the trade-off</p>
                      <div className="flex gap-1.5">
                        <select aria-label="Containment type" value={contForm.type} onChange={ev => setContForm(s => ({ ...s, type: ev.target.value }))} className="rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">{CONTAINMENT_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
                        <input aria-label="Containment target" value={contForm.target} onChange={ev => setContForm(s => ({ ...s, target: ev.target.value }))} placeholder="Target — host, account, DC or indicator" className="min-w-0 flex-1 rounded border border-border bg-bg px-2 py-1 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      </div>
                      {picks.length > 0 && <div className="flex flex-wrap gap-1">{picks.map(v => <button key={v} aria-pressed={contForm.target === v} onClick={() => setContForm(s => ({ ...s, target: v }))} className={`rounded border px-1.5 py-0.5 font-mono text-[9px] ${contForm.target === v ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400 hover:text-white"}`}>{v}</button>)}</div>}
                      <p className="text-[9px] text-slate-500">Prefilled from the log — check it&apos;s the asset that actually matters (a domain change is on the DC, a compromised identity is the account).</p>
                      <select aria-label="Asset criticality" value={contForm.criticality} onChange={ev => setContForm(s => ({ ...s, criticality: ev.target.value }))} className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">
                        <option value="crown_jewel">asset criticality: crown-jewel (domain controller / core system)</option>
                        <option value="standard">asset criticality: standard</option>
                        <option value="low">asset criticality: low (spare / test)</option>
                      </select>
                      <input aria-label="What breaks if contained" value={contForm.blast} onChange={ev => setContForm(s => ({ ...s, blast: ev.target.value }))} placeholder="What breaks if contained? (e.g. 'payroll run in progress' / 'none')" className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      <div className="flex gap-1.5">
                        <input aria-label="Business owner and hours" value={contForm.owner} onChange={ev => setContForm(s => ({ ...s, owner: ev.target.value }))} placeholder="Business owner / hours (e.g. 'Finance · business hours')" className="min-w-0 flex-1 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                        <input aria-label="Incident (optional)" value={contForm.incident} onChange={ev => setContForm(s => ({ ...s, incident: ev.target.value }))} list="team-incidents" placeholder="Incident (optional)" className="w-32 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      </div>
                      <div className="flex gap-1.5">
                        <Button variant="primary" size="sm" disabled={b || !contForm.blast.trim() || !contForm.target.trim()} onClick={async () => { setBusy(e.seq + ""); const ok = await act("containment.requested", { event_id: eid, target: contForm.target.trim(), containment_type: contForm.type, incident: contForm.incident.trim() || undefined, reason: asStr(p.summary) || asStr(p.what), asset_criticality: contForm.criticality, blast_radius: contForm.blast.trim(), business_owner: contForm.owner.trim() || undefined }); setBusy(null); if (ok) setContainingId(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Send request</Button>
                        <Button variant="outline" size="sm" aria-label="Cancel containment request" onClick={() => setContainingId(null)}>✕</Button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* G-09: Manager approved → execute the containment (real MTTC starts at request, ends here) */}
      {toExecute.length > 0 && (
        <Card className="border-neon-green/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-neon-green" /> Approved — execute containment ({toExecute.length})</h3>
          <div className="mt-2 space-y-2">
            {toExecute.map(r => {
              const p = r.request.payload as { target?: string; containment_type?: string }; const b = busy === "x" + r.seq;
              return (
                <div key={r.seq} className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2">
                  <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{containmentVerb(asStr(p.containment_type))} <b className="text-white">{asStr(p.target) || "host"}</b></span>
                  <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy("x" + r.seq); await act("containment.executed", { event_id: r.eid, target: p.target, containment_type: p.containment_type, request_seq: r.seq }); setBusy(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Execute</Button>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* T2 sets the scope here; T3 gets the confirm-scope panel in its Hunt console
          instead (avoids showing two scope panels to Tier-3). */}
      {role === "t2" && <ScopeConsole scope={scope} scopes={scopes} incidents={incidents} mode="set" act={act} />}

      {/* ── Bottom of the page: the case owner's report ── §5 handover. A dedicated
          place (not buried in a ticket) to attach the report, the determination and
          the recommendations. Filing it is what unlocks containment & resolve.
          Tier-3 gets it too for cases it owns (it may take a case and must be able to close it). */}
      {(role === "t2" || myCases.length > 0) && (
      <Card className="border-cyber-500/30">
        <div id="t2-report" className="scroll-mt-4" />
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FileText className="h-4 w-4 text-cyber-300" /> Your incident report — determination &amp; recommendations</h3>
        <p className="mt-0.5 text-[11px] text-slate-400">Attach your report to a case you own. This is the handover {role === "t2" ? "Tier-3" : "Tier-2"} and the SOC Manager read: your findings, your determination (verdict), and what you recommend next. Filing it unlocks <b className="text-slate-300">containment</b> and <b className="text-slate-300">resolve</b> on that case.</p>
        {myCases.length === 0 ? (
          <p className="mt-2 text-xs text-slate-400">Acknowledge a case in the inbox above, then write its report here.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {/* Which case is this report for */}
            <div>
              <label htmlFor={`${uid}-case`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Case this report is for</label>
              <select id={`${uid}-case`} value={selEid ?? ""} onChange={ev => { setReportFor(ev.target.value); setRep({ ...EMPTY_REP, incident: incidentOf.get(ev.target.value) ?? "" }); }} className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                {myCases.map(e => { const eid = eidOf(e); const p = e.payload as { summary?: string; what?: string }; return <option key={eid} value={eid}>{reportedIds.has(eid) ? "✓ " : ""}{asStr(p.summary) || asStr(p.what) || eid}</option>; })}
              </select>
            </div>
            {selEid && reportedIds.has(selEid) ? (
              <div className="flex items-start gap-2 rounded-lg border border-neon-green/30 bg-neon-green/[0.06] px-3 py-2 text-[11px] text-neon-green"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /><span>Report filed for <b>{selLabel}</b>. Containment &amp; resolve are unlocked for this case. Pick another case above to report it, or resolve this one in the inbox.</span></div>
            ) : selEid ? (
              <div className="space-y-1.5 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.05] p-3">
                <p className="text-[10px] text-slate-400">Reporting on: <b className="text-slate-200">{selLabel}</b></p>
                <div>
                  <label htmlFor={`${uid}-summary`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Summary — what this incident is</label>
                  <input id={`${uid}-summary`} value={rep.summary} onChange={ev => setRep(s => ({ ...s, summary: ev.target.value }))} placeholder="e.g. Malicious macro on WS-FIN-2847 dropped an encoded PowerShell C2 beacon" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div>
                  <label htmlFor={`${uid}-findings`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Findings — what you investigated, the evidence, the scope</label>
                  <textarea id={`${uid}-findings`} value={rep.findings} onChange={ev => setRep(s => ({ ...s, findings: ev.target.value }))} placeholder="What you confirmed in the log/EDR, the indicators, the affected hosts/users, whether it spread…" rows={3} className="mt-1 w-full resize-y rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label htmlFor={`${uid}-verdict`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Determination (verdict)</label>
                    <select id={`${uid}-verdict`} value={rep.verdict} onChange={ev => setRep(s => ({ ...s, verdict: ev.target.value }))} className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 focus:border-cyber-500/50 focus:outline-none">{T2_REPORT_VERDICTS.map(v => <option key={v} value={v}>{v.replace("_", " ")}</option>)}</select>
                  </div>
                  <div className="flex-1">
                    <label htmlFor={`${uid}-incident`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Incident (optional — group related cases)</label>
                    <input id={`${uid}-incident`} value={rep.incident} onChange={ev => setRep(s => ({ ...s, incident: ev.target.value }))} list="team-incidents" placeholder="e.g. INC-B drive-by" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  </div>
                </div>
                <div>
                  <label htmlFor={`${uid}-rec`} className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Recommendations — what should happen next</label>
                  <input id={`${uid}-rec`} value={rep.recommendation} onChange={ev => setRep(s => ({ ...s, recommendation: ev.target.value }))} placeholder="e.g. Isolate the host, block the domain, reset the user, hunt the hash fleet-wide" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div className="flex items-center gap-2 pt-0.5">
                  <Button variant="primary" size="sm" disabled={busy === "rep" + selEid || !rep.summary.trim() || !rep.findings.trim() || !rep.recommendation.trim()} onClick={() => submitReport(selEid)}><FileText className="mr-1 h-3.5 w-3.5" /> File report</Button>
                  <span className="text-[10px] text-slate-500">{rep.findings.trim().split(/\s+/).filter(Boolean).length} words</span>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Card>
      )}
      {fullLog && (
        <div className="fixed inset-0 z-[35] flex items-start justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-sm" onClick={() => setFullLog(null)}>
          <div ref={fullLogRef} role="dialog" aria-modal="true" aria-labelledby={`${uid}-fulllog-title`} tabIndex={-1} className="my-4 w-full max-w-5xl rounded-xl border border-border bg-bg shadow-2xl" onClick={ev => ev.stopPropagation()}>
            <div className="flex items-start gap-3 border-b border-border px-5 py-3">
              <div className="min-w-0 flex-1">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Escalated by {fullLog.from}</p>
                <h2 id={`${uid}-fulllog-title`} className="break-words text-sm font-bold text-white">{fullLog.title}</h2>
                {fullLog.notes && <p className="mt-1 whitespace-pre-wrap break-words text-xs text-slate-400">{fullLog.notes}</p>}
              </div>
              <button onClick={() => setFullLog(null)} aria-label="Close" className="rounded p-1 text-slate-400 hover:bg-bg-elevated hover:text-white"><X className="h-5 w-5" aria-hidden="true" /></button>
            </div>
            <DetailPanelBody event={fullLog.snap} onThreatQuery={setThreatQuery} onPivot={onPivot ? (f, v) => { onPivot(f, v); setFullLog(null); } : undefined} />
          </div>
        </div>
      )}
      {/* A3: live threat-intel enrichment when a hash/IP/domain is checked in a log */}
      {threatQuery && <ThreatIntelDrawer key="t2-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}
