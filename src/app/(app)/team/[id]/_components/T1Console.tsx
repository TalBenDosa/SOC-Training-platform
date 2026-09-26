"use client";
import { useEffect, useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight, ShieldAlert, Siren, X } from "lucide-react";
import type { Ev, Ioc } from "@/lib/team/types";
import { asStr, detectIocType, isValidIoc, wordCount } from "@/lib/team/format";
import { slaMinFor } from "./shared";

// ── T1 console: pick a log → disposition + structured escalation report ───────
const REQUESTED_ACTIONS = ["investigate", "contain", "monitor", "escalate-to-mgr"];
const SEVERITIES = ["low", "medium", "high", "critical"];
const MIN_RATIONALE_WORDS = 12; // T1-6 hard gate: "meaningful rationale"

export function T1Console({ feed, dispositions, events, meId, iocDraft, setIocDraft, nameOf, act, sel, setSel, reportOpen, setReportOpen }: {
  feed: Ev[]; dispositions: Map<string, string>; events: Ev[]; meId: string;
  iocDraft: Ioc[]; setIocDraft: React.Dispatch<React.SetStateAction<Ioc[]>>;
  nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  // sel + reportOpen live in the parent so the 🚩 button on a LOG (in the feed's
  // DetailPanel) can select that event and open this report modal directly.
  sel: string; setSel: (v: string) => void; reportOpen: boolean; setReportOpen: (v: boolean) => void;
}) {
  const [form, setForm] = useState({ summary: "", observations: "", assessment: "", requested_action: "investigate", severity: "medium" });
  const [iocText, setIocText] = useState("");
  const [busy, setBusy] = useState(false);
  const selDisp = sel ? dispositions.get(sel) : undefined;
  // B6: a real T1 alert QUEUE — a prioritized, aging worklist of the high-signal
  // alerts still needing a disposition (drains as you triage; noise never enters).
  // A sorted projection over the same feed, NOT a second SIEM.
  const nowMs = Date.now();
  const queue = feed
    .map(e => { const p = e.payload as { id?: string; severity?: string; source?: string; description?: string; summary?: string; what?: string; hostname?: string }; return { e, eid: String(p.id ?? e.seq), p }; })
    .filter(({ eid, p }) => !dispositions.has(eid) && (p.severity === "high" || p.severity === "critical"))
    .map(x => { const mins = x.e.occurred_at ? Math.max(0, Math.floor((nowMs - Date.parse(x.e.occurred_at)) / 60000)) : 0; const rank = x.p.severity === "critical" ? 4 : 3; return { ...x, mins, rank, score: rank * (1 + mins / 5) }; })
    .sort((a, b) => b.score - a.score);
  const isLowConf = selDisp === "suspicious"; // T1-2: Suspicious → low-confidence lead

  // T1-3: soft-lock claims — latest alert.claimed/released per event wins; a claim
  // is active for ~5 min unless released or the alert was dispositioned.
  const CLAIM_TTL = 5 * 60 * 1000;
  const claims = useMemo(() => {
    const m = new Map<string, { by: string; at: number }>();
    for (const e of events) {
      if (e.type !== "alert.claimed" && e.type !== "alert.released") continue;
      const eid = String((e.payload as { event_id?: string }).event_id); if (!eid) continue;
      if (e.type === "alert.released") m.delete(eid);
      else m.set(eid, { by: e.actor_id ?? "", at: e.occurred_at ? Date.parse(e.occurred_at) : Date.now() });
    }
    return m;
  }, [events]);
  const claimerOf = (eid: string): { by: string; at: number } | null => {
    const c = claims.get(eid); if (!c) return null;
    if (dispositions.has(eid)) return null;              // dispositioned → off the clock
    if (Date.now() - c.at > CLAIM_TTL) return null;       // stale claim expired
    return c;
  };
  const options = feed.map(e => {
    const p = e.payload as { id?: string; description?: unknown; event_type?: unknown }; const id = String(p.id ?? e.seq);
    const c = claimerOf(id); const lock = c && c.by !== meId ? "🔒 " : "";
    return { id, label: `${lock}#${e.seq} ${asStr(p.description) || asStr(p.event_type) || "event"}` };
  });
  const selClaim = sel ? claimerOf(sel) : null;
  async function claim() { if (!sel) return; setBusy(true); await act("alert.claimed", { event_id: sel }); setBusy(false); }
  async function release() { if (!sel) return; setBusy(true); await act("alert.released", { event_id: sel }); setBusy(false); }

  // Work-division: escalated (handed-off) alerts, so an orphan check doesn't flag a
  // case that's already moving up the chain.
  const escalatedSet = useMemo(() => new Set(events.filter(e => e.type === "escalation.requested").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  // Orphan = past SLA, still unclaimed, and not yet escalated — nobody is working it.
  const isOrphan = (eid: string, sev: string | undefined, mins: number) => mins >= slaMinFor(sev ?? "high") && !claimerOf(eid) && !escalatedSet.has(eid);
  // Display order: orphans first (a breached, unclaimed high can't sit mid-list), then
  // the existing severity×age score order.
  const queueDisplay = useMemo(() => {
    const withFlag = queue.map(q => ({ ...q, orphan: isOrphan(q.eid, q.p.severity, q.mins) }));
    return withFlag.sort((a, b) => (a.orphan === b.orphan ? 0 : a.orphan ? -1 : 1));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queue, claims, escalatedSet, dispositions]);
  // Assisted pull: grab the most urgent alert nobody has claimed and open its report
  // (report-open auto-claims it), so two T1s don't lunge at the same row and the top
  // of the queue never goes orphaned because everyone assumed someone else took it.
  function takeNext() {
    const next = queueDisplay.find(q => { const c = claimerOf(q.eid); return !c || c.by === meId; });
    if (next) { setSel(next.eid); setReportOpen(true); }
  }

  // T1-7: my escalations with live status (sent → acknowledged → bounced/resolved).
  const myEsc = useMemo(() => {
    const acked = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id)));
    const bounced = new Set(events.filter(e => e.type === "escalation.bounced").map(e => String((e.payload as { event_id?: string }).event_id)));
    const resolved = new Set(events.filter(e => e.type === "escalation.resolved").map(e => String((e.payload as { event_id?: string }).event_id)));
    return events.filter(e => e.type === "escalation.requested" && e.actor_id === meId).map(e => {
      const p = e.payload as { event_id?: string; summary?: string; what?: string; reason?: string }; const eid = String(p.event_id);
      const status = resolved.has(eid) ? "resolved" : bounced.has(eid) ? "bounced" : acked.has(eid) ? "acknowledged" : "sent";
      const reason = asStr((events.filter(e2 => e2.type === "escalation.bounced" && String((e2.payload as { event_id?: string }).event_id) === eid).slice(-1)[0]?.payload as { reason?: string } | undefined)?.reason);
      return { seq: e.seq, eid, label: asStr(p.summary) || asStr(p.what) || "escalation", status, reason };
    });
  }, [events, meId]);

  const [iocErr, setIocErr] = useState("");
  function addIoc(value: string, source: "picked" | "manual") {
    const v = value.trim(); if (!v) return;
    // A4: a MANUAL indicator must look like a real IOC; picked-from-log values are trusted.
    if (source === "manual" && !isValidIoc(v)) { setIocErr(`"${v}" isn't a valid indicator (hash / IP / domain / email / hostname).`); return; }
    setIocErr("");
    setIocDraft(d => d.some(x => x.value.toLowerCase() === v.toLowerCase()) ? d : [...d, { type: detectIocType(v), value: v, source }]);
  }
  const rationaleWords = wordCount(form.observations);
  // T1-6 quality gate — every condition must hold before Escalate is allowed.
  const gate = {
    summary: !!form.summary.trim(),
    rationale: rationaleWords >= MIN_RATIONALE_WORDS,
    ioc: iocDraft.length >= 1,
    severity: !!form.severity,
    // A4: escalate only an attack-ish call — you can't escalate a log you marked benign/FP.
    disposition: selDisp === "true_positive" || selDisp === "suspicious",
  };
  const canEscalate = !!sel && !busy && gate.summary && gate.rationale && gate.ioc && gate.severity && gate.disposition;

  // When the report opens (from the 🚩 on a log OR the dropdown button), take the
  // soft-claim automatically so two Tier-1s don't work the same log — unless a
  // teammate already holds it (then the modal shows a "Take over" banner instead).
  useEffect(() => {
    if (reportOpen && sel && !selClaim) { act("alert.claimed", { event_id: sel }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportOpen, sel]);

  async function disp(v: string) {
    if (!sel) return; setBusy(true); await act("disposition.set", { event_id: sel, verdict: v }); setBusy(false);
    // FP/Benign close at T1 and release any soft claim so a teammate can reuse the row.
    if (v === "false_positive" || v === "benign") await act("alert.released", { event_id: sel });
  }
  async function escalate() {
    if (!canEscalate) return;
    setBusy(true);
    // Carry the FULL original log with the escalation so Tier-2 investigates the
    // real event (all raw fields), not just T1's words — and independent of feed state.
    const snapshot = feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel)?.payload as Record<string, unknown> | undefined;
    const fe = snapshot as { hostname?: string; user_email?: string; user?: { email?: string } } | undefined;
    const entity = asStr(fe?.hostname) || asStr(fe?.user_email) || asStr(fe?.user?.email) || "the affected asset";
    const ok = await act("escalation.requested", {
      event_id: sel, summary: form.summary, observations: form.observations, assessment: form.assessment,
      iocs: iocDraft, requested_action: form.requested_action, severity: form.severity,
      confidence: isLowConf ? 0.3 : 0.7, low_confidence: isLowConf || undefined,
      hostname: asStr(fe?.hostname) || undefined, entity, snapshot,
      what: form.summary, why: form.observations, // back-compat aliases
    });
    if (ok) await act("alert.released", { event_id: sel }); // escalated → hand off the claim
    setBusy(false);
    if (ok) { setForm({ summary: "", observations: "", assessment: "", requested_action: "investigate", severity: "medium" }); setIocDraft([]); setSel(""); setReportOpen(false); }
  }
  // The selected log's payload — powers the modal's log-summary header + the escalate snapshot.
  const selRaw = sel ? feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel) : undefined;
  const selP = selRaw?.payload as { id?: string; description?: unknown; event_type?: unknown; hostname?: unknown; user_email?: unknown; user?: { email?: unknown }; severity?: unknown; source?: unknown } | undefined;
  const selDesc = asStr(selP?.description) || asStr(selP?.event_type) || "event";
  const selHost = asStr(selP?.hostname);
  const selUser = asStr(selP?.user_email) || asStr(selP?.user?.email);
  const selSev = asStr(selP?.severity);
  const selSource = asStr(selP?.source);
  return (
    <>
    {/* B6: the alert queue — highest-severity, oldest-aging first; drains as you disposition */}
    <Card className="border-neon-amber/30">
      <div className="flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-neon-amber" /> Alert queue ({queue.length})</h3>
        <div className="flex items-center gap-2">
          {queue.length > 0 && <Button variant="outline" size="sm" disabled={busy} onClick={takeNext}>Take next</Button>}
          <span className="font-mono text-[10px] text-slate-500">high/critical · un-triaged</span>
        </div>
      </div>
      {queue.length === 0 ? (
        <p className="mt-2 text-xs text-slate-400">Queue clear — no high/critical alert is waiting for a disposition. Watch the feed.</p>
      ) : (
        <div className="mt-2 space-y-1">
          {queueDisplay.slice(0, 8).map(({ e, eid, p, mins, rank, orphan }) => { const breached = mins >= slaMinFor(p.severity ?? "high"); return (
            <button key={e.seq} onClick={() => { setSel(eid); setReportOpen(true); }} className={`flex w-full items-center gap-2 rounded border px-2 py-1 text-left text-[11px] transition hover:bg-white/[0.03] ${sel === eid ? "border-cyber-500/50 bg-cyber-500/[0.06]" : orphan ? "border-severity-high/50 bg-severity-high/[0.06]" : "border-border/60 bg-bg"}`}>
              <span className={`shrink-0 rounded border px-1 py-0.5 font-mono text-[9px] font-bold uppercase ${rank === 4 ? "border-severity-high/50 bg-severity-high/10 text-severity-high" : "border-neon-amber/50 bg-neon-amber/10 text-neon-amber"}`}>{p.severity}</span>
              <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.description) || asStr(p.summary) || asStr(p.what) || asStr(p.hostname) || "alert"}</span>
              {orphan && <span className="shrink-0 rounded border border-severity-high/60 bg-severity-high/15 px-1 py-0.5 font-mono text-[9px] font-bold text-severity-high" title="past SLA and unclaimed — nobody is working it">⚠ unclaimed</span>}
              {asStr(p.source) && <span className="shrink-0 font-mono text-[9px] text-slate-500">{asStr(p.source)}</span>}
              <span className={`shrink-0 rounded border px-1 py-0.5 font-mono text-[9px] font-bold ${breached ? "border-severity-high/60 bg-severity-high/15 text-severity-high" : "border-border text-slate-400"}`}>⏱ {mins}m{breached ? " · SLA" : ""}</span>
            </button>
          ); })}
          {queue.length > 8 && <p className="text-[10px] text-slate-500">+{queue.length - 8} more — work the top of the queue first.</p>}
        </div>
      )}
    </Card>
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Tier-1 triage</h3>
      <p className="mt-1 text-[11px] text-slate-400">Open a log in the feed and hit <span className="font-semibold text-amber-300">🚩 Escalate this log</span> — or pick one below.</p>

      {/* T1-7: my escalations + status tracking (sent/ack/bounced/resolved) */}
      {myEsc.length > 0 && (
        <div className="mt-2 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">My escalations ({myEsc.length})</p>
          {myEsc.slice().reverse().slice(0, 6).map(e => (
            <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-[11px]">
              <span className="min-w-0 flex-1 truncate text-slate-300">{e.label}{e.status === "bounced" && e.reason ? ` — ${e.reason}` : ""}</span>
              <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${e.status === "resolved" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : e.status === "bounced" ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : e.status === "acknowledged" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400"}`}>{e.status}</span>
            </div>
          ))}
        </div>
      )}

      <label className="mt-3 block text-xs">
        <span className="mb-1 block uppercase tracking-wider text-slate-400">Pick a log</span>
        <select value={sel} onChange={e => setSel(e.target.value)} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
          <option value="">— select an event —</option>
          {options.map(o => <option key={o.id} value={o.id}>{o.label}{dispositions.get(o.id) ? ` · ${dispositions.get(o.id)}` : ""}</option>)}
        </select>
      </label>
      {/* T1-3: soft-claim so two Tier-1 analysts don't work the same alert */}
      {sel && (
        selClaim && selClaim.by !== meId
          ? <div className="mt-2 flex items-center gap-2 rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px]">
              <span className="text-neon-amber">🔒 claimed by {nameOf(selClaim.by)}</span>
              <Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={claim}>Take over</Button>
            </div>
          : selClaim && selClaim.by === meId
            ? <div className="mt-2 flex items-center gap-2 text-[11px] text-neon-green"><span>✓ you claimed this alert</span><Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={release}>Release</Button></div>
            : <div className="mt-2"><Button variant="outline" size="sm" disabled={busy} onClick={claim}>Take this alert</Button></div>
      )}
      {/* T1-2: four dispositions incl. Suspicious */}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {[["true_positive", "true positive"], ["false_positive", "false positive"], ["benign", "benign"], ["suspicious", "suspicious"]].map(([v, label]) => (
          <Button key={v} variant={selDisp === v ? "primary" : "outline"} size="sm" disabled={!sel || busy} onClick={() => disp(v)}>{label}</Button>
        ))}
      </div>

      {/* Open the escalation report for the selected log (same modal the 🚩 button opens) */}
      <div className="mt-3 border-t border-border/50 pt-3">
        <Button variant="primary" size="sm" className="w-full" disabled={!sel} onClick={() => setReportOpen(true)}>
          <ArrowUpRight className="mr-1.5 h-4 w-4" /> Write escalation report{sel ? ` — #${selRaw?.seq}` : ""}
        </Button>
        {!sel && <p className="mt-1 text-[10px] text-slate-500">Select a log first (feed 🚩 or the dropdown above).</p>}
      </div>
    </Card>

    {/* ── Escalation report modal — opens ON the log (🚩) or via "Write escalation report" ── */}
    {reportOpen && sel && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setReportOpen(false)}>
        <div className="max-h-[88vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-white"><span className="text-lg leading-none">🚩</span> Escalation report → Tier-2</h2>
            <button onClick={() => setReportOpen(false)} aria-label="Close" className="text-xl leading-none text-slate-400 hover:text-white">&times;</button>
          </div>

          {/* Which log you're reporting on — pulled straight from the flagged event */}
          <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-300/80">Flagged log · #{selRaw?.seq}</p>
            <p className="mt-0.5 text-sm text-slate-200">{selDesc}</p>
            <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
              {selSev && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">severity: {selSev}</span>}
              {selSource && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">{selSource}</span>}
              {selHost && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">host: {selHost}</span>}
              {selUser && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">user: {selUser}</span>}
            </div>
          </div>

          {/* Claim status — surfaced INSIDE the modal so the 🚩 path can't hide a teammate's lock */}
          {selClaim && selClaim.by !== meId ? (
            <div className="mt-2 flex items-center gap-2 rounded border border-neon-amber/40 bg-neon-amber/[0.08] px-2 py-1.5 text-[11px]">
              <span className="text-neon-amber">🔒 {nameOf(selClaim.by)} is already working this alert.</span>
              <Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={claim}>Take over</Button>
            </div>
          ) : selClaim && selClaim.by === meId ? (
            <p className="mt-2 text-[11px] text-neon-green">✓ you claimed this alert</p>
          ) : null}

          {/* Disposition — triage before escalate. Set it right here if it isn't yet. */}
          <div className="mt-2">
            {selDisp ? (
              <p className="text-[11px] text-slate-400">Disposition: <span className="font-semibold text-slate-200">{selDisp.replace("_", " ")}</span></p>
            ) : (
              <>
                <p className="text-[11px] text-neon-amber">Set a disposition first (triage → escalate):</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {[["true_positive", "true positive"], ["suspicious", "suspicious"]].map(([v, label]) => (
                    <Button key={v} variant="outline" size="sm" disabled={busy} onClick={() => disp(v)}>{label}</Button>
                  ))}
                </div>
              </>
            )}
          </div>

          <div className="mt-3 space-y-2">
            {isLowConf && <p className="rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px] text-neon-amber">Low-confidence lead — sending to Tier-2 for a second look.</p>}
            <input value={form.summary} onChange={e => setForm(f => ({ ...f, summary: e.target.value }))} placeholder="Summary — one line: what happened + on what" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <textarea value={form.observations} onChange={e => setForm(f => ({ ...f, observations: e.target.value }))} placeholder={`Observations — the process/sequence/evidence (≥ ${MIN_RATIONALE_WORDS} words)`} rows={3} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            {/* T1-5: IOCs — pre-seeded from the flagged log; click "+IOC" on raw fields, or type here */}
            <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Indicators (IOCs) — click ＋IOC on the log&apos;s fields, or add below</p>
              {iocDraft.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {iocDraft.map(i => (
                    <span key={i.value} className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyber-300">
                      <span className="text-slate-500">{i.type}:</span>{i.value}
                      <button onClick={() => setIocDraft(d => d.filter(x => x.value !== i.value))} className="text-slate-400 hover:text-white"><X className="h-3 w-3" /></button>
                    </span>
                  ))}
                </div>
              )}
              <div className="mt-1 flex gap-1.5">
                <input value={iocText} onChange={e => setIocText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { addIoc(iocText, "manual"); setIocText(""); } }} placeholder="add an IOC (ip / domain / hash / user)…" className="flex-1 rounded border border-border bg-bg px-2 py-1 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                <Button variant="outline" size="sm" onClick={() => { addIoc(iocText, "manual"); setIocText(""); }}>Add</Button>
              </div>
              {iocErr && <p className="mt-1 text-[10px] text-severity-high">{iocErr}</p>}
            </div>
            <input value={form.assessment} onChange={e => setForm(f => ({ ...f, assessment: e.target.value }))} placeholder="Assessment — what you think this is" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <div className="flex gap-2">
              <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{SEVERITIES.map(s => <option key={s} value={s}>severity: {s}</option>)}</select>
              <select value={form.requested_action} onChange={e => setForm(f => ({ ...f, requested_action: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{REQUESTED_ACTIONS.map(a => <option key={a} value={a}>action: {a}</option>)}</select>
            </div>
            {/* T1-6: live checklist for the hard gate — ✓/○ per item + positive "all set" */}
            <div className="text-[10px] leading-relaxed text-slate-500">
              {canEscalate ? (
                <span className="font-semibold text-neon-green">✓ all set — ready to escalate</span>
              ) : (
                <>Before escalating:{" "}
                  {([[gate.disposition, "disposition"], [gate.summary, "summary"], [gate.rationale, `observations (${rationaleWords}/${MIN_RATIONALE_WORDS} words)`], [gate.ioc, "≥1 IOC"], [gate.severity, "severity"]] as [boolean, string][]).map(([ok, label]) => (
                    <span key={label} className={ok ? "text-neon-green" : ""}>{ok ? "✓" : "○"} {label}&nbsp;&nbsp;</span>
                  ))}
                </>
              )}
            </div>
            <div className="flex gap-2 pt-1">
              <Button variant="outline" size="sm" className="flex-1" onClick={() => setReportOpen(false)}>Cancel</Button>
              <Button variant="primary" size="sm" className="flex-1" disabled={!canEscalate} onClick={escalate}><ArrowUpRight className="mr-1.5 h-4 w-4" /> Escalate to Tier-2</Button>
            </div>
          </div>
        </div>
      </div>
    )}
    </>
  );
}
