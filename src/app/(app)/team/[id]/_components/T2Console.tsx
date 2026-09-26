"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DetailPanelBody } from "@/app/(app)/dashboard/EventFeed";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { CheckCircle2, ShieldCheck, ArrowUpRight, Check, ShieldAlert, Siren, ChevronDown, Search, FileText } from "lucide-react";
import type { Ev, Ioc, ScopeState } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { enrichSnapshot, slaMinFor } from "./shared";
import { ScopeConsole } from "./ScopeConsole";
import { useServerNow } from "@/lib/team/clock";

// ── T2/T3 console: escalation inbox → ack → request/execute containment + scope ─
const BOUNCE_REASONS = ["Missing a clear indicator", "Looks like noise / benign", "Needs more context or evidence", "Duplicate of another case", "Other"];
const T2_REPORT_VERDICTS = ["true_positive", "false_positive", "benign", "escalate"];
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0.5 };

export function T2Console({ role, meId, escalations, acked, ackedBy, escBounced, escResolved, reportedIds, reportByEid, elevatedIds, contReq, contApproved, contExecuted, scope, nameOf, act, onEdr, onPivot }: {
  role: string; meId: string; escalations: Ev[]; acked: Set<string>; ackedBy: Map<string, string>; escBounced: Set<string>; escResolved: Set<string>; reportedIds: Set<string>; reportByEid: Map<string, { verdict?: string; findings?: string; recommendation?: string; summary?: string }>; elevatedIds: Set<string>; contReq: Ev[]; contApproved: Set<string>; contExecuted: Set<string>;
  scope: ScopeState; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onEdr?: (description?: string) => void;
  onPivot?: (field: "user" | "host" | "ip", value: string) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [openLog, setOpenLog] = useState<number | null>(null); // which escalation's full log is expanded
  const [bouncingId, setBouncingId] = useState<string | null>(null); // eid being bounced (shows reason input)
  const [bounceReason, setBounceReason] = useState(BOUNCE_REASONS[0]);
  const [bounceMsg, setBounceMsg] = useState("");
  const [reportFor, setReportFor] = useState<string | null>(null); // eid whose report form is open
  const [rep, setRep] = useState({ summary: "", findings: "", verdict: "true_positive", recommendation: "" });
  const [elevatingId, setElevatingId] = useState<string | null>(null); // A2: eid being elevated (shows the "what to hunt" compose)
  const [huntAsk, setHuntAsk] = useState("");
  const [containingId, setContainingId] = useState<string | null>(null); // B10: eid whose containment-request form is open
  const [contForm, setContForm] = useState({ criticality: "standard", blast: "", owner: "" });
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null); // A3: live threat-intel enrichment
  // scope-first: containment can't be requested until a working scope exists.
  const scopeSet = !!scope && (scope.hosts.length > 0 || scope.users.length > 0 || scope.techniques.length > 0);
  async function submitReport(eid: string) {
    const words = rep.findings.trim().split(/\s+/).filter(Boolean).length;
    if (!rep.summary.trim() || words < 12 || !rep.recommendation.trim()) return;
    setBusy("rep" + eid);
    const ok = await act("report.submitted", { event_id: eid, summary: rep.summary.trim(), findings: rep.findings.trim(), verdict: rep.verdict, recommendation: rep.recommendation.trim() });
    setBusy(null);
    if (ok) { setReportFor(null); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); }
  }
  // For Tier-3 the inbox is secondary (hunting is the dominant action) → collapse it
  // by default so the console isn't a wall of always-open cards.
  const [inboxOpen, setInboxOpen] = useState(role !== "t3");
  // Approved but not yet executed → the analyst must carry out the isolation (G-09).
  const toExecute = contReq.filter(e => { const eid = String((e.payload as { event_id?: string }).event_id); return contApproved.has(eid) && !contExecuted.has(eid); });
  // Which escalations already have a containment request (so the button reflects it).
  const requestedIds = new Set(contReq.map(e => String((e.payload as { event_id?: string }).event_id)));
  // Prioritized queue: open cases first, ranked by severity × waiting × confidence
  // (a 'contain' request weighs heavier). Acked/bounced/resolved sink to the bottom.
  // C5: waiting time / SLA on the server clock, ticking every 15s.
  const now = useServerNow(15_000);
  const prioKey = (e: Ev) => {
    const p = e.payload as { event_id?: string; severity?: string; confidence?: number; requested_action?: string };
    const eid = String(p.event_id);
    const open = !acked.has(eid) && !escBounced.has(eid) && !escResolved.has(eid);
    const sev = asStr(p.severity) || "medium";
    const wait = e.occurred_at ? Math.max(0, (now - Date.parse(e.occurred_at)) / 60000) : 0;
    const conf = typeof p.confidence === "number" ? p.confidence : 0.5;
    const contain = p.requested_action === "contain" ? 1.5 : 1;
    return { open, score: (SEV_RANK[sev] ?? 2) * (1 + wait / 5) * (0.5 + conf) * contain };
  };
  const prioritized = [...escalations].sort((a, b) => { const ka = prioKey(a), kb = prioKey(b); if (ka.open !== kb.open) return ka.open ? -1 : 1; return kb.score - ka.score; });
  // Cases this analyst has taken (acked, not resolved) — the ones a report can be
  // attached to in the bottom "your report" section (§5 handover to T3/Manager).
  const eidOf = (e: Ev) => String((e.payload as { event_id?: string }).event_id);
  const myCases = prioritized.filter(e => { const eid = eidOf(e); return acked.has(eid) && !escResolved.has(eid); });
  const selEid = (reportFor && myCases.some(e => eidOf(e) === reportFor)) ? reportFor : (myCases[0] ? eidOf(myCases[0]) : null);
  const selCase = myCases.find(e => eidOf(e) === selEid) || null;
  const selLabel = selCase ? (asStr((selCase.payload as { summary?: string; what?: string }).summary) || asStr((selCase.payload as { what?: string }).what)) : "";
  // Assisted pull: the most urgent case nobody has taken yet.
  const nextUnacked = prioritized.find(e => { const eid = eidOf(e); return !acked.has(eid) && !escBounced.has(eid) && !escResolved.has(eid); }) || null;
  async function takeNextCase() {
    if (!nextUnacked) return;
    const eid = eidOf(nextUnacked);
    setBusy("ack" + eid);
    await act("escalation.acknowledged", { event_id: eid });
    setBusy(null);
  }
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white">
            {role === "t3" && <button onClick={() => setInboxOpen(o => !o)} className="text-slate-400 hover:text-white"><ChevronDown className={`h-4 w-4 transition-transform ${inboxOpen ? "" : "-rotate-90"}`} /></button>}
            <Siren className="h-4 w-4 text-neon-amber" /> Escalations for you ({escalations.length})
          </h3>
          <div className="flex items-center gap-2">
            {nextUnacked && <Button variant="outline" size="sm" disabled={busy != null} onClick={takeNextCase}>Take next case</Button>}
            {onEdr && <Button variant="outline" size="sm" onClick={() => onEdr()}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>}
          </div>
        </div>
        {!inboxOpen ? <p className="mt-2 text-[11px] text-slate-500">{escalations.length} case(s) waiting — expand to review. Your focus is hunting &amp; scope below.</p>
          : escalations.length === 0 ? <p className="mt-2 text-xs text-slate-400">Nothing escalated yet. Tier-1 sends cases here.</p> : (
          <div className="mt-2 space-y-2">
            {prioritized.map(e => {
              const p = e.payload as { event_id?: string; what?: string; summary?: string; why?: string; observations?: string; assessment?: string; impact?: string; severity?: string; confidence?: number; requested_action?: string; entity?: string; hostname?: string; low_confidence?: boolean; iocs?: Ioc[]; snapshot?: Record<string, unknown> };
              const eid = String(p.event_id); const isAck = acked.has(eid); const isBounced = escBounced.has(eid); const isResolved = escResolved.has(eid); const b = busy === e.seq + "";
              const target = asStr(p.entity) || asStr(p.hostname) || asStr(p.impact) || "the affected asset";
              const iocs = Array.isArray(p.iocs) ? p.iocs : [];
              const snap = enrichSnapshot(p.snapshot); const isOpen = openLog === e.seq;
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <div className="flex items-start gap-2">
                    <p className="min-w-0 flex-1 text-sm text-slate-200">{asStr(p.summary) || asStr(p.what)}</p>
                    {p.low_confidence && <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">low-conf</span>}
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
                  {iocs.length > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Indicators ({iocs.length})</p>
                      <div className="mt-0.5 flex flex-wrap gap-1">{iocs.slice(0, 8).map(i => <span key={i.value} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[9px] text-slate-300"><span className="text-slate-500">{i.type}:</span>{i.value}</span>)}</div>
                    </div>
                  )}
                  <p className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-slate-500">
                    <span>from {nameOf(e.actor_id)} · sev {asStr(p.severity) || asStr(p.impact) || "—"} · conf {p.confidence}{p.requested_action ? ` · asks: ${p.requested_action}` : ""}</span>
                    {!isAck && !isBounced && !isResolved && e.occurred_at && (() => {
                      const mins = Math.max(0, Math.floor((now - Date.parse(e.occurred_at)) / 60000));
                      const breached = mins >= slaMinFor(asStr(p.severity) || "medium"); // SLA by severity
                      return <span className={`rounded border px-1 py-px font-bold ${breached ? "border-severity-high/60 bg-severity-high/15 text-severity-high" : "border-border text-slate-400"}`}>⏱ waiting {mins}m{breached ? " · SLA" : ""}</span>;
                    })()}
                  </p>
                  {/* Open the FULL original log T1 flagged — investigate the real event, not just the words */}
                  {snap && (
                    <button onClick={() => setOpenLog(isOpen ? null : e.seq)} className="mt-1 flex items-center gap-1 text-[11px] text-cyber-300 underline-offset-2 hover:underline">
                      <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? "" : "-rotate-90"}`} /> {isOpen ? "Hide the log" : "View the full log (raw event + JSON)"}
                    </button>
                  )}
                  {snap && isOpen && (
                    <div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40">
                      <DetailPanelBody event={snap} onThreatQuery={setThreatQuery} onPivot={onPivot} />
                    </div>
                  )}
                  {/* Routed handling: whoever acknowledges first has claimed the case;
                      a second Tier-2 sees the lock instead of double-handling it. */}
                  {isAck && (() => { const claimer = ackedBy.get(eid); return claimer && claimer !== meId
                    ? <p className="mt-1 text-[11px] text-neon-amber">🔒 handled by {nameOf(claimer)}</p>
                    : <p className="mt-1 text-[11px] text-neon-green">✓ you&apos;re handling this</p>; })()}
                  {/* EDR prompt — once taken, nudge the analyst to investigate on the endpoint
                      (both Tier-2 and Tier-3 can). Opens the EDR console with THIS event's
                      description in its header. Shown when the flagged log has endpoint context. */}
                  {isAck && (() => {
                    const so = p.snapshot as { source?: string; hostname?: string } | undefined;
                    const hasEndpoint = !!so && (so.source === "edr" || so.source === "sysmon" || !!so.hostname);
                    if (!hasEndpoint || !onEdr) return null;
                    return (
                      <div className="mt-2 flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/[0.08] px-2.5 py-1.5">
                        <span className="text-sm leading-none">🖥</span>
                        <span className="min-w-0 flex-1 text-[11px] text-cyber-200">Endpoint activity on this host — investigate it in EDR before you decide.</span>
                        <Button variant="primary" size="sm" className="shrink-0" onClick={() => onEdr(asStr(p.summary) || asStr(p.what) || "Escalated incident")}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>
                      </div>
                    );
                  })()}
                  {!isResolved && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {!isAck && !isBounced
                        ? <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("escalation.acknowledged", { event_id: eid }); setBusy(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Acknowledge (take this case)</Button>
                        : null}
                      {/* Report is a hard gate for containment + resolve (§5). B12: T2-only artifact. */}
                      {role === "t2" && isAck && !reportedIds.has(eid) && <Button variant="outline" size="sm" onClick={() => { setReportFor(eid); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); if (typeof document !== "undefined") document.getElementById("t2-report")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}><FileText className="mr-1 h-3.5 w-3.5" /> Write report ↓</Button>}
                      {isAck && reportedIds.has(eid) && <span className="inline-flex items-center gap-1 text-[11px] text-neon-green"><CheckCircle2 className="h-3.5 w-3.5" /> report filed</span>}
                      {isAck && (requestedIds.has(eid)
                        ? <span className="inline-flex items-center gap-1 text-[11px] text-cyber-300"><ShieldAlert className="h-3.5 w-3.5" /> containment requested</span>
                        : containingId !== eid && <Button variant="primary" size="sm" disabled={b || !scopeSet || !reportedIds.has(eid)} onClick={() => { setContainingId(eid); setContForm({ criticality: "standard", blast: "", owner: "" }); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Request containment</Button>)}
                      {/* Escalate a hard case to Tier-3 for a deep hunt (routed handover, not shared) */}
                      {role === "t2" && isAck && (elevatedIds.has(eid)
                        ? <span className="inline-flex items-center gap-1 text-[11px] text-neon-purple"><ArrowUpRight className="h-3.5 w-3.5" /> escalated to Tier-3</span>
                        : elevatingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setElevatingId(eid); setHuntAsk(""); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Escalate to Tier-3</Button>)}
                      {role === "t2" && !isAck && !isBounced && bouncingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setBouncingId(eid); setBounceReason(BOUNCE_REASONS[0]); setBounceMsg(""); }}>Bounce</Button>}
                      {isAck && <Button variant="outline" size="sm" disabled={b || !reportedIds.has(eid)} onClick={async () => { setBusy(e.seq + ""); await act("escalation.resolved", { event_id: eid }); setBusy(null); }}>Resolve</Button>}
                      {/* Pin the key evidence to the Shared Case (wires the evidence.pinned rubric signal) */}
                      {isAck && <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("evidence.pinned", { event_id: eid, label: asStr(p.summary) || asStr(p.what) || "flagged log", iocs }); setBusy(null); }}>📌 Pin to case</Button>}
                    </div>
                  )}
                  {/* What's blocking containment/resolve on this ticket */}
                  {isAck && !isResolved && (!scopeSet || !reportedIds.has(eid)) && (
                    <p className="mt-1 text-[10px] text-slate-500">Before containment/resolve:{!reportedIds.has(eid) ? " write the incident report ·" : ""}{!scopeSet ? " set the scope (needed for containment)" : ""}</p>
                  )}
                  {/* Bounce from a preset reason list (+ optional detail) — real, specific feedback to T1 */}
                  {!isResolved && bouncingId === eid && (
                    <div className="mt-2 space-y-1.5">
                      <select value={bounceReason} onChange={ev => setBounceReason(ev.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">{BOUNCE_REASONS.map(r => <option key={r} value={r}>{r}</option>)}</select>
                      <div className="flex gap-1.5">
                        <input value={bounceMsg} onChange={ev => setBounceMsg(ev.target.value)} placeholder="Optional detail for Tier-1…" className="flex-1 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                        <Button variant="outline" size="sm" disabled={b} onClick={async () => { const reason = bounceReason + (bounceMsg.trim() ? ` — ${bounceMsg.trim()}` : ""); setBusy(e.seq + ""); await act("escalation.bounced", { event_id: eid, reason }); setBusy(null); setBouncingId(null); }}>Send bounce</Button>
                        <Button variant="outline" size="sm" onClick={() => setBouncingId(null)}>✕</Button>
                      </div>
                    </div>
                  )}
                  {/* A2: elevate-to-Tier-3 compose — a required "what to hunt / why", and T2's filed
                      findings ride along so the hunter starts from context, not the raw alert. */}
                  {!isResolved && elevatingId === eid && (() => { const rpt = reportByEid.get(eid); return (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-neon-purple/30 bg-neon-purple/[0.05] p-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Hand off to Tier-3 — what should they hunt?</p>
                      <textarea value={huntAsk} onChange={ev => setHuntAsk(ev.target.value)} placeholder="What to hunt & why you're elevating (e.g. 'confirmed C2 beacon from WS-FIN-2847 — hunt lateral movement to the DC and check other finance hosts for the same hash')" rows={2} className="w-full resize-y rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      {rpt ? <p className="text-[10px] text-neon-green">✓ your filed report (verdict + findings + recommendation) will travel with this elevation.</p>
                           : <p className="text-[10px] text-neon-amber">⚠ no report filed yet — Tier-3 gets more to work with if you write the report first.</p>}
                      <div className="flex gap-1.5">
                        <Button variant="primary" size="sm" disabled={b || huntAsk.trim().length < 8} onClick={async () => { setBusy(e.seq + ""); await act("elevation.requested", { event_id: eid, summary: asStr(p.summary) || asStr(p.what), snapshot: p.snapshot, hostname: asStr(p.hostname), entity: asStr(p.entity), severity: asStr(p.severity), iocs, hunt_ask: huntAsk.trim(), t2_verdict: rpt?.verdict, t2_findings: rpt?.findings, t2_recommendation: rpt?.recommendation }); setBusy(null); setElevatingId(null); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Send to Tier-3</Button>
                        <Button variant="outline" size="sm" onClick={() => setElevatingId(null)}>✕</Button>
                      </div>
                    </div>
                  ); })()}
                  {/* B10: containment-request compose — business-impact context so the Manager's
                      approval is a real risk decision, not a rubber stamp. */}
                  {!isResolved && containingId === eid && (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-severity-high/30 bg-severity-high/[0.05] p-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Request containment of <span className="text-slate-200">{target}</span> — give the Manager the trade-off</p>
                      <select value={contForm.criticality} onChange={ev => setContForm(s => ({ ...s, criticality: ev.target.value }))} className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">
                        <option value="crown_jewel">asset criticality: crown-jewel (domain controller / core system)</option>
                        <option value="standard">asset criticality: standard</option>
                        <option value="low">asset criticality: low (spare / test)</option>
                      </select>
                      <input value={contForm.blast} onChange={ev => setContForm(s => ({ ...s, blast: ev.target.value }))} placeholder="What breaks if isolated? (e.g. 'payroll run in progress' / 'none')" className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      <input value={contForm.owner} onChange={ev => setContForm(s => ({ ...s, owner: ev.target.value }))} placeholder="Business owner / hours (e.g. 'Finance · business hours')" className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      <div className="flex gap-1.5">
                        <Button variant="primary" size="sm" disabled={b || !contForm.blast.trim()} onClick={async () => { setBusy(e.seq + ""); await act("containment.requested", { event_id: eid, target, reason: asStr(p.summary) || asStr(p.what), asset_criticality: contForm.criticality, blast_radius: contForm.blast.trim(), business_owner: contForm.owner.trim() || undefined }); setBusy(null); setContainingId(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Send request</Button>
                        <Button variant="outline" size="sm" onClick={() => setContainingId(null)}>✕</Button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* G-09: Lead approved → execute the isolation (real MTTC starts at request, ends here) */}
      {toExecute.length > 0 && (
        <Card className="border-neon-green/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-neon-green" /> Approved — execute isolation ({toExecute.length})</h3>
          <div className="mt-2 space-y-2">
            {toExecute.map(e => {
              const p = e.payload as { event_id?: string; target?: string; reason?: string }; const eid = String(p.event_id); const b = busy === "x" + e.seq;
              return (
                <div key={e.seq} className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2">
                  <span className="min-w-0 flex-1 truncate text-sm text-slate-200">Isolate <b className="text-white">{asStr(p.target) || "host"}</b></span>
                  <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy("x" + e.seq); await act("containment.executed", { event_id: eid, target: p.target }); setBusy(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Execute</Button>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* T2 sets the scope here; T3 gets the confirm-scope panel in its Hunt console
          instead (avoids showing two scope panels to Tier-3). */}
      {role === "t2" && <ScopeConsole scope={scope} mode="set" act={act} />}

      {/* ── Bottom of the page: the analyst's own report ── §5 handover. A dedicated
          place (not buried in a ticket) to attach the report, the determination and
          the recommendations. Filing it is what unlocks containment & resolve.
          B12: T2 artifact — Tier-3 files hunt findings, not T2 incident reports. */}
      {role === "t2" && (
      <Card className="border-cyber-500/30">
        <div id="t2-report" className="scroll-mt-4" />
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FileText className="h-4 w-4 text-cyber-300" /> Your incident report — determination &amp; recommendations</h3>
        <p className="mt-0.5 text-[11px] text-slate-400">Attach your report to a case you&apos;ve taken. This is the handover Tier-3 and the SOC Manager read: your findings, your determination (verdict), and what you recommend next. Filing it unlocks <b className="text-slate-300">containment</b> and <b className="text-slate-300">resolve</b> on that case.</p>
        {myCases.length === 0 ? (
          <p className="mt-2 text-xs text-slate-400">Acknowledge a case in the inbox above, then write its report here.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {/* Which case is this report for */}
            <div>
              <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Case this report is for</label>
              <select value={selEid ?? ""} onChange={ev => { setReportFor(ev.target.value); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); }} className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                {myCases.map(e => { const eid = eidOf(e); const p = e.payload as { summary?: string; what?: string }; return <option key={eid} value={eid}>{reportedIds.has(eid) ? "✓ " : ""}{asStr(p.summary) || asStr(p.what) || eid}</option>; })}
              </select>
            </div>
            {selEid && reportedIds.has(selEid) ? (
              <div className="flex items-start gap-2 rounded-lg border border-neon-green/30 bg-neon-green/[0.06] px-3 py-2 text-[11px] text-neon-green"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /><span>Report filed for <b>{selLabel}</b>. Containment &amp; resolve are unlocked for this case. Pick another case above to report it, or resolve this one in the inbox.</span></div>
            ) : selEid ? (
              <div className="space-y-1.5 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.05] p-3">
                <p className="text-[10px] text-slate-400">Reporting on: <b className="text-slate-200">{selLabel}</b></p>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Summary — what this incident is</label>
                  <input value={rep.summary} onChange={ev => setRep(s => ({ ...s, summary: ev.target.value }))} placeholder="e.g. Malicious macro on WS-FIN-2847 dropped an encoded PowerShell C2 beacon" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Findings — what you investigated, the evidence, the scope (≥ 12 words)</label>
                  <textarea value={rep.findings} onChange={ev => setRep(s => ({ ...s, findings: ev.target.value }))} placeholder="What you confirmed in the log/EDR, the indicators, the affected hosts/users, whether it spread…" rows={3} className="mt-1 w-full resize-y rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Determination (verdict)</label>
                  <select value={rep.verdict} onChange={ev => setRep(s => ({ ...s, verdict: ev.target.value }))} className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 focus:border-cyber-500/50 focus:outline-none">{T2_REPORT_VERDICTS.map(v => <option key={v} value={v}>{v.replace("_", " ")}</option>)}</select>
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Recommendations — what should happen next</label>
                  <input value={rep.recommendation} onChange={ev => setRep(s => ({ ...s, recommendation: ev.target.value }))} placeholder="e.g. Isolate the host, block the domain, reset the user, hunt the hash fleet-wide" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div className="flex items-center gap-2 pt-0.5">
                  <Button variant="primary" size="sm" disabled={busy === "rep" + selEid || !rep.summary.trim() || rep.findings.trim().split(/\s+/).filter(Boolean).length < 12 || !rep.recommendation.trim()} onClick={() => submitReport(selEid)}><FileText className="mr-1 h-3.5 w-3.5" /> File report</Button>
                  <span className="text-[10px] text-slate-500">{rep.findings.trim().split(/\s+/).filter(Boolean).length}/12 words in findings</span>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Card>
      )}
      {/* A3: live threat-intel enrichment when a hash/IP/domain is checked in a log */}
      {threatQuery && <ThreatIntelDrawer key="t2-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}
