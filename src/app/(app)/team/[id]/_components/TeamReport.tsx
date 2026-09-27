"use client";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight, ShieldAlert, Siren, Clock } from "lucide-react";
import type { RosterMember, Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import type { computeReport } from "@/lib/team/report/computeReport";
import { mergeAnswers, type AnswerMap } from "@/lib/team/report/serverReport";
import { ROLE_LABEL, Metric } from "./shared";

// ── Guided hot-wash (§6.6) — a dual-track replay reconstructed from the event log:
// attack activity vs the team's response, key moments, and reflection prompts. This
// is the "conversation, not a scorecard" half of the debrief (research: a guided
// debrief ≈ half the learning). All derived from `events`, no new instrumentation.
function HotWash({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  // Anchor relative times to session START (not events[0], which is the earliest
  // lobby member.ready — that inflated every time and disagreed with the AAR). Fall
  // back to the first event's timestamp only if there's no session.started (G1).
  const startedEv = events.find(e => e.type === "session.started");
  const t0 = startedEv?.occurred_at ? Date.parse(startedEv.occurred_at)
    : (events.length && events[0].occurred_at ? Date.parse(events[0].occurred_at) : 0);
  const rel = (ts?: string) => (ts && t0 ? Math.max(0, Math.round((Date.parse(ts) - t0) / 1000)) : 0);
  const fmt = (s: number) => (s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`);
  const RESPONSE_LABEL: Record<string, string> = {
    "escalation.requested": "escalated to Tier-2", "escalation.acknowledged": "acknowledged", "escalation.bounced": "bounced back",
    "elevation.requested": "elevated to Tier-3", "containment.requested": "requested containment", "containment.approved": "approved containment",
    "containment.denied": "denied containment", "containment.executed": "executed isolation", "decision.logged": "logged a decision",
    "sitrep.sent": "sent a SITREP", "scope.confirmed": "confirmed scope",
  };
  const rows = useMemo(() => {
    const out: { t: number; track: "attack" | "response"; label: string; who?: string }[] = [];
    for (const e of events) {
      const p = e.payload as Record<string, unknown>;
      if (e.type === "feed.event" && (p.expected_verdict === "tp" || p.expected_verdict === "escalate")) {
        out.push({ t: rel(e.occurred_at), track: "attack", label: asStr(p.description) || asStr(p.event_type) || "attack activity" });
      } else if (RESPONSE_LABEL[e.type]) {
        out.push({ t: rel(e.occurred_at), track: "response", label: RESPONSE_LABEL[e.type], who: nameOf(e.actor_id) });
      }
    }
    return out.sort((a, b) => a.t - b.t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events]);

  const firstAttack = events.find(e => e.type === "feed.event" && ((e.payload as Record<string, unknown>).expected_verdict === "tp" || (e.payload as Record<string, unknown>).expected_verdict === "escalate"));
  const firstEsc = events.find(e => e.type === "escalation.requested");
  const decision = events.find(e => e.type === "containment.approved" || e.type === "containment.denied");
  const exec = events.find(e => e.type === "containment.executed");
  const dwellS = firstAttack && firstEsc ? rel(firstEsc.occurred_at) - rel(firstAttack.occurred_at) : null;

  const moments: { t: string; title: string; note: string }[] = [];
  if (firstEsc) moments.push({ t: fmt(rel(firstEsc.occurred_at)), title: "First escalation", note: `${nameOf(firstEsc.actor_id)} raised the first case${dwellS != null && dwellS >= 0 ? ` — ${fmt(dwellS)} after the attack first showed in the feed` : ""}.` });
  if (decision) moments.push({ t: fmt(rel(decision.occurred_at)), title: decision.type === "containment.approved" ? "Containment approved" : "Containment denied", note: `${nameOf(decision.actor_id)} made the call.` });
  if (exec) moments.push({ t: fmt(rel(exec.occurred_at)), title: "Host isolated", note: `${nameOf(exec.actor_id)} executed the containment.` });

  // Ground-truth facts to pre-fill the structured arc.
  const attackCount = rows.filter(r => r.track === "attack").length;
  const contained = events.some(e => e.type === "containment.executed");
  const denied = !contained && events.some(e => e.type === "containment.denied");
  const whatHappened = [
    firstEsc ? `first escalation at ${fmt(rel(firstEsc.occurred_at))}${dwellS != null && dwellS >= 0 ? ` (${fmt(dwellS)} after the attack first surfaced)` : ""}` : "no escalation was raised",
    contained ? `the host was isolated at ${fmt(rel(exec!.occurred_at))}` : denied ? "containment was denied" : "the incident was not contained",
  ].join("; ") + ".";

  if (rows.length === 0) return null;
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Clock className="h-4 w-4 text-cyber-300" /> Hot-wash — what happened, and when</h3>
      <p className="mt-1 text-[11px] text-slate-400">Attack activity vs the team&apos;s response, side by side. Use it to talk through the timeline together.</p>

      {moments.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {moments.map((m, i) => (
            <div key={i} className="rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2">
              <p className="font-mono text-[10px] text-cyber-300">{m.t}</p>
              <p className="text-[11px] font-semibold text-white">{m.title}</p>
              <p className="text-[10px] text-slate-400 leading-snug">{m.note}</p>
            </div>
          ))}
        </div>
      )}

      {/* Dual-track timeline: attack on the left, response on the right */}
      <div className="mt-3 max-h-72 overflow-y-auto rounded-lg border border-border/50 bg-bg">
        {rows.map((r, i) => (
          <div key={i} className="flex items-stretch gap-2 border-b border-border/30 px-2 py-1 text-[11px] last:border-0">
            <span className="w-14 shrink-0 pt-0.5 text-right font-mono text-[10px] text-slate-500">{fmt(r.t)}</span>
            <div className="min-w-0 flex-1">
              {r.track === "attack"
                ? <div className="rounded border-l-2 border-severity-high/60 bg-severity-high/[0.06] px-2 py-1 text-severity-high/90"><span className="text-[9px] font-bold uppercase tracking-wider text-severity-high/70">attack</span> {r.label}</div>
                : <div className="ms-auto w-[85%] rounded border-l-2 border-cyber-500/60 bg-cyber-500/[0.06] px-2 py-1 text-slate-200"><span className="text-[9px] font-bold uppercase tracking-wider text-cyber-300/80">{r.who}</span> {r.label}</div>}
            </div>
          </div>
        ))}
      </div>

      {/* Structured debrief arc (research: a facilitated 4-step debrief ≈ the learning).
          The first two steps are pre-filled from ground truth; the last two are the
          team's conversation. */}
      <div className="mt-3 space-y-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Debrief together — work through it in order</p>
        {[
          { n: 1, q: "What should have happened", a: `${attackCount} real attack event${attackCount === 1 ? "" : "s"} were hidden in the noise. The shift should catch them, escalate with evidence, scope the incident, and contain the right asset.` },
          { n: 2, q: "What actually happened", a: whatHappened },
          { n: 3, q: "Why the gap?", a: "Talk it through: the earliest log you walked past, where hand-offs stalled (T1→T2→Manager→execute), any wrong call and how it was caught." },
          { n: 4, q: "What we'd do differently", a: "Name one concrete change for the first five minutes of the next shift." },
        ].map(s => (
          <div key={s.n} className="flex gap-2 rounded-lg border border-border/50 bg-bg-elevated/40 px-3 py-2">
            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-cyber-500/20 font-mono text-[9px] font-bold text-cyber-300">{s.n}</span>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold text-white">{s.q}</p>
              <p className={`mt-0.5 text-[11px] leading-snug ${s.n <= 2 ? "text-slate-300" : "text-slate-400 italic"}`}>{s.a}</p>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Handoff ladder (research P0) — the closed-loop coordination chain per case:
// escalate → acknowledge → elevate → contain → resolve, with per-hop latency and a
// closed/open/DROPPED status (an escalation nobody acknowledged = a broken loop).
// Reconstructed from the event log; makes closed-loop communication visible at debrief.
function HandoffLadder({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  const HOP: Record<string, string> = {
    "escalation.requested": "T1 escalated", "escalation.acknowledged": "T2 acknowledged", "escalation.bounced": "bounced back",
    "elevation.requested": "elevated to T3", "elevation.acknowledged": "T3 took it", "containment.requested": "containment requested",
    "containment.approved": "Mgr approved", "containment.denied": "Mgr denied", "containment.executed": "isolated", "escalation.resolved": "resolved",
  };
  const fmtD = (s: number | null) => s == null ? "" : s >= 60 ? `+${Math.floor(s / 60)}m${String(Math.round(s % 60)).padStart(2, "0")}s` : `+${Math.round(s)}s`;
  const cases = useMemo(() => {
    const byEid = new Map<string, { type: string; at: number | null; who: string; label?: string }[]>();
    for (const e of events) {
      if (!HOP[e.type]) continue;
      const p = e.payload as { event_id?: string; summary?: string; what?: string };
      const eid = String(p.event_id ?? ""); if (!eid) continue;
      if (!byEid.has(eid)) byEid.set(eid, []);
      byEid.get(eid)!.push({ type: e.type, at: e.occurred_at ? Date.parse(e.occurred_at) : null, who: nameOf(e.actor_id), label: asStr(p.summary) || asStr(p.what) || undefined });
    }
    const out: { eid: string; title: string; status: "closed" | "open" | "dropped"; steps: { type: string; who: string; d: number | null }[] }[] = [];
    for (const [eid, raw] of byEid) {
      const start = raw.find(h => h.type === "escalation.requested");
      if (!start) continue; // only real T1→ handoff chains
      const hops = raw.slice().sort((a, b) => (a.at ?? 0) - (b.at ?? 0));
      const acked = hops.some(h => h.type === "escalation.acknowledged");
      // A bounce is an explicit answer back to Tier-1 — the loop CLOSED (same rule as the report).
      const closed = hops.some(h => h.type === "escalation.resolved" || h.type === "containment.executed" || h.type === "escalation.bounced");
      const status = closed ? "closed" : !acked ? "dropped" : "open";
      let prev = start.at;
      const steps = hops.map(h => { const d = prev != null && h.at != null ? (h.at - prev) / 1000 : null; prev = h.at ?? prev; return { type: h.type, who: h.who, d }; });
      out.push({ eid, title: start.label || "escalated case", status, steps });
    }
    // Dropped loops first (they need the most discussion), then by chain length.
    return out.sort((a, b) => (a.status === "dropped" ? 0 : 1) - (b.status === "dropped" ? 0 : 1) || b.steps.length - a.steps.length);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events]);
  if (cases.length === 0) return null;
  const STATUS_STYLE: Record<string, string> = {
    closed: "border-neon-green/40 bg-neon-green/10 text-neon-green",
    open: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
    dropped: "border-severity-high/50 bg-severity-high/15 text-severity-high",
  };
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-cyber-300" /> Handoff chains — did the loop close?</h3>
      <p className="mt-1 text-[11px] text-slate-400">Each escalated case, tier to tier, with the delay at each hop. A <b className="text-severity-high/90">dropped</b> chain was escalated but never acknowledged — a broken loop worth talking through.</p>
      <div className="mt-3 max-h-80 space-y-2 overflow-y-auto">
        {cases.slice(0, 8).map(c => (
          <div key={c.eid} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
            <div className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate text-[11px] font-semibold text-slate-200">{c.title}</span>
              <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${STATUS_STYLE[c.status]}`}>{c.status}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-1 gap-y-1">
              {c.steps.map((s, i) => (
                <span key={i} className="inline-flex items-center gap-1">
                  {i > 0 && <span className="font-mono text-[9px] text-slate-600">{fmtD(s.d)}→</span>}
                  <span className="rounded border border-border/60 bg-bg-elevated/40 px-1.5 py-0.5 text-[10px] text-slate-300" title={s.who}>{HOP[s.type]}</span>
                </span>
              ))}
              {c.status === "dropped" && <span className="ml-1 text-[10px] text-severity-high/80">— nobody acknowledged</span>}
            </div>
          </div>
        ))}
        {cases.length > 8 && <p className="text-[10px] text-slate-500">+{cases.length - 8} more chains.</p>}
      </div>
    </Card>
  );
}

type Report = ReturnType<typeof computeReport>;

// S10: a spreadsheet evaluates a cell starting with = + - @ (or a tab/CR) as a
// formula even inside quotes — a display name like =HYPERLINK(...) would run in the
// instructor's Excel. Prefix those cells with an apostrophe.
function csvCell(v: unknown): string {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

const LEGEND: Record<string, string> = {
  "Incidents detected": "Real incidents the team caught — any of an incident's attack logs escalated, or marked true positive / suspicious. Scored per incident, not per log.",
  "MTTD": "Mean time to detect — shift start → the first CORRECT escalation of a real attack log.",
  "Handoff latency": "How long an escalation waited before a Tier-2 acknowledged it (median).",
  "Handoff loop closure": "Share of escalated logs a Tier-2 closed the loop on — acknowledged, bounced back or resolved.",
  "MTTC": "Mean time to contain — containment request → isolation executed.",
  "MTTR": "Mean time to resolve — FIRST escalation → case resolved.",
  "Shared picture": "Contested = two analysts gave opposite verdicts on the same event.",
  "Insufficient evidence": "Fewer than 2 criteria could be measured for this seat — no score is shown rather than a misleading 100%.",
};

/**
 * The after-action report. v2+ (and legacy) sessions are scored SERVER-SIDE from the
 * full log with the answer key joined back (audit A1/S4): everyone sees the same
 * numbers, and a non-staff viewer only ever receives their own card (S9). The live
 * room never had the answer key; it is revealed here, after the shift, to rebuild
 * the hot-wash and handoff ladder.
 */
export function TeamReport({ sessionId, events, roster, me }: { sessionId: string; events: Ev[]; roster: RosterMember[]; me: Me }) {
  const [report, setReport] = useState<Report | null>(null);
  const [answers, setAnswers] = useState<AnswerMap>({});
  const [seesAll, setSeesAll] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoadError(null);
    (async () => {
      try {
        const res = await fetch(`/api/team/sessions/${sessionId}/report`);
        const data = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) { setLoadError(data?.error ?? "Couldn't load the report."); return; }
        setReport({ team: data.team, perUser: data.perUser } as Report);
        setAnswers(data.answers ?? {});
        setSeesAll(!!data.seesAll);
      } catch { if (!cancelled) setLoadError("Couldn't load the report — check your connection."); }
    })();
    return () => { cancelled = true; };
  }, [sessionId, attempt]);

  // Answer key merged onto the local log — for the hot-wash/handoff ladder only.
  const revealed = useMemo(() => mergeAnswers(events, answers), [events, answers]);
  const nameOf = (u: string | null) => roster.find(r => r.user_id === u)?.name ?? "someone";

  if (loadError) return (
    <Card className="border-severity-high/30">
      <p className="text-sm text-severity-high">{loadError}</p>
      <Button variant="outline" size="sm" className="mt-3" onClick={() => setAttempt(a => a + 1)}>Try again</Button>
    </Card>
  );
  if (!report) return <Card><p className="text-sm text-slate-400">Building the shift review…</p></Card>;

  const { team, perUser } = report;
  const visible = perUser;   // the server already limited this to my card unless I'm staff / the Manager

  function exportCsv() {
    const header = ["Name", "Role", "Rubric score %", "Criteria measured", "Logs opened", "Avg dwell (s)", "Dispositions", "Disposition accuracy %", "Dispositions on unopened logs", "Escalations", "Escalation quality", "Acks", "Containment requests", "Containment decisions", "Role actions", "First action (s)", "Contribution"];
    const rows = perUser.map(u => [u.name, u.role, u.insufficientEvidence ? "insufficient evidence" : (u.rubricPct ?? ""), u.measuredCells ?? "", u.opened, u.avgDwellS ?? "", u.dispCount, u.dispAcc ?? "", u.dispUnopened ?? "", u.escCount, u.escQuality ?? "", u.acks, u.contReq, u.contDecided, u.roleActions, u.firstActionS ?? "", u.contribution]);
    const csv = [header, ...rows].map(r => r.map(csvCell).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const a = document.createElement("a"); a.href = url; a.download = `team-exercise-report-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    URL.revokeObjectURL(url);
  }
  const lcTone = team.loopClosure != null ? (team.loopClosure >= 80 ? "good" as const : team.loopClosure < 50 ? "warn" as const : undefined) : undefined;
  // Per-incident detection (fix round 2026-09-27). A report cached before it existed
  // has no incident fields — fall back to the old yes/no.
  const incidents = team.incidents ?? [];
  const incTotal = team.incidentsTotal ?? 0;
  const incDetected = team.incidentsDetected ?? 0;
  const incValue = incTotal ? `${incDetected}/${incTotal}` : (team.detected ? "Yes" : "No");
  const incTone = incTotal ? (incDetected === incTotal ? "good" as const : "warn" as const) : (team.detected ? "good" as const : "warn" as const);
  const groups: { title: string; items: [string, string, ("good" | "warn" | undefined)?][] }[] = [
    { title: "Detection", items: [
      ["Incidents detected", incValue, incTone],
      ["MTTD", team.timeToDetectS != null ? `${team.timeToDetectS}s` : "—"],
      ["Logs", String(team.logs)],
      ["Disposition accuracy", team.dispAcc != null ? `${team.dispAcc}%` : "—"],
    ] },
    { title: "Coordination", items: [
      ["Escalations", String(team.escalations)],
      ["Acknowledged", String(team.acknowledged)],
      ["Handoff loop closure", team.loopClosure != null ? `${team.loopClosure}%` : "—", lcTone],
      ["Handoff latency", team.handoffLatS != null ? `${team.handoffLatS}s` : "—", team.handoffLatS != null && team.handoffLatS > 300 ? "warn" : undefined],
      ["Shared picture", team.contested === 0 ? "aligned" : `${team.contested} contested`, team.contested === 0 ? "good" : "warn"],
    ] },
    { title: "Response", items: [
      ["Containment requests", String(team.containmentReq)],
      ["Contained", String(team.contained), team.contained > 0 ? "good" : undefined],
      ["Isolated", String(team.executed), team.executed > 0 ? "good" : undefined],
      ["MTTC", team.mttcS != null ? `${team.mttcS}s` : "—"],
    ] },
    { title: "Resolution", items: [
      ["MTTR", team.mttrS != null ? `${team.mttrS}s` : "—"],
      ["Case status", team.caseStatus, team.caseStatus === "closed" || team.caseStatus === "contained" ? "good" : undefined],
      ["Evidence pinned", String(team.evidencePinned)],
    ] },
  ];

  return (
    <div className="space-y-5">
      <Card className={incTone === "good" ? "border-neon-green/30" : "border-neon-amber/30"}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white">Shift review</h2>
          {me.is_staff && seesAll && <Button variant="outline" size="sm" onClick={exportCsv}>Export CSV</Button>}
        </div>
        <p className="mt-0.5 text-[11px] text-slate-400">A no-fault learning debrief — surfacing and fixing a mistake scores <b className="text-slate-300">for</b> you, not against. Start with the debrief below; the numbers support the conversation.</p>
        {/* U2: the four headline numbers the briefing promised (accuracy · timeliness · coordination) */}
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <span title={LEGEND["Incidents detected"]}><Metric label={incTotal ? "Incidents detected" : "Attack detected"} value={incValue} tone={incTone} /></span>
          <span title={LEGEND["MTTD"]}><Metric label="MTTD (time to detect)" value={team.timeToDetectS != null ? `${team.timeToDetectS}s` : "—"} /></span>
          <Metric label="Disposition accuracy" value={team.dispAcc != null ? `${team.dispAcc}%` : "—"} />
          <span title={LEGEND["Handoff loop closure"]}><Metric label="Handoff loop closure" value={team.loopClosure != null ? `${team.loopClosure}%` : "—"} tone={lcTone} /></span>
        </div>
        <button onClick={() => setShowAll(s => !s)} aria-expanded={showAll}
          className="mt-3 rounded text-[11px] font-semibold text-cyber-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">
          {showAll ? "Hide the full metrics" : "Show all metrics"}
        </button>
        {showAll && (
          <div className="mt-3 space-y-3">
            {groups.map(g => (
              <div key={g.title}>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{g.title}</p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {g.items.map(([label, value, tone]) => (
                    <span key={label} title={LEGEND[label]}><Metric label={label} value={value} tone={tone} /></span>
                  ))}
                </div>
              </div>
            ))}
            <dl className="grid gap-1 rounded-lg border border-border/50 bg-bg px-3 py-2 text-[11px] sm:grid-cols-2">
              {Object.entries(LEGEND).map(([k, v]) => (
                <div key={k}><dt className="inline font-semibold text-slate-300">{k}: </dt><dd className="inline text-slate-400">{v}</dd></div>
              ))}
            </dl>
          </div>
        )}
      </Card>

      {/* Per-incident detection — was each real incident caught? (fix round 2026-09-27, P0-1) */}
      {incidents.length > 0 && (
        <Card>
          <div className="flex items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Incidents — did we catch each one?</h3>
            <span className="font-mono text-[10px] text-slate-400">{incDetected}/{incTotal} detected</span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">Scored per incident, not per log: an incident counts as caught once <b className="text-slate-300">any</b> of its attack logs was escalated or marked true positive / suspicious.</p>
          <div className="mt-3 space-y-2">
            {incidents.map(inc => (
              <div key={inc.id} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                <div className="flex items-start gap-2">
                  <span className="min-w-0 flex-1 text-[11px] text-slate-300">{inc.label}</span>
                  <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${!inc.detected ? "border-severity-high/50 bg-severity-high/15 text-severity-high" : inc.escalated ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"}`}>{!inc.detected ? "missed" : inc.escalated ? "escalated" : "marked only"}</span>
                </div>
                <p className="mt-1 text-[10px] text-slate-500">
                  {inc.attackEvents} attack log{inc.attackEvents === 1 ? "" : "s"}
                  {inc.firstSeenS != null ? ` · first seen ${inc.firstSeenS}s` : ""}
                  {inc.detected && inc.detectS != null ? ` · caught at ${inc.detectS}s` : ""}
                  {inc.detected && inc.dwellS != null ? ` (${inc.dwellS}s after it surfaced)` : ""}
                  {inc.contained ? " · contained" : ""}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Guided hot-wash FIRST — the debrief conversation, reconstructed from the log (U2) */}
      <HotWash events={revealed} nameOf={nameOf} />

      {/* Handoff chains — closed-loop coordination made visible (research P0) */}
      <HandoffLadder events={revealed} nameOf={nameOf} />

      {/* Shared-picture coherence — contested calls to reconcile (research P2) */}
      {team.contestedList.length > 0 && (
        <Card className="border-neon-amber/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-neon-amber" /> Contested calls — reconcile the picture</h3>
          <p className="mt-1 text-[11px] text-slate-400">Same event, different analysts, opposite verdicts. A split mental model — talk through who was right and why.</p>
          <div className="mt-3 space-y-2">
            {team.contestedList.map((c, i) => (
              <div key={i} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                <p className="text-[11px] font-semibold text-slate-200">{c.label}</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {c.calls.map((call, j) => (
                    <span key={j} className={`rounded border px-1.5 py-0.5 text-[10px] ${call.cls === "attack" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : call.cls === "benign" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-border text-slate-400"}`}>{roster.find(r => r.user_id === call.actor)?.name ?? "someone"}: {call.cls}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* MSEL curveballs — each inject scored against its expected response (research P1) */}
      {team.injects.length > 0 && (
        <Card>
          <div className="flex items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-neon-amber" /> Curveballs (MSEL)</h3>
            <span className="font-mono text-[10px] text-slate-400">{team.injectsHandled}/{team.injectsScored} handled</span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">Scripted pressure &amp; tickets during the shift — and whether the team produced the expected response.</p>
          <div className="mt-3 space-y-2">
            {team.injects.map((inj, i) => {
              // `evaluable` is absent on reports cached before the fix round ⇒ treat as evaluable.
              const notEvaluable = inj.evaluable === false;
              const badge = notEvaluable ? "not evaluable" : !inj.scored ? (inj.decoy ? "decoy" : "FYI") : inj.decoy ? (inj.handled ? "decoy · rejected" : "decoy · chased") : inj.handled ? "handled" : "missed";
              const tone = notEvaluable || !inj.scored ? (inj.decoy && !notEvaluable ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-500")
                : inj.handled ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/50 bg-severity-high/15 text-severity-high";
              return (
              <div key={i} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                <div className="flex items-start gap-2">
                  <span className="min-w-0 flex-1 text-[11px] text-slate-300">{inj.text}</span>
                  <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${tone}`}>{badge}</span>
                </div>
                {inj.note && <p className="mt-1 text-[10px] text-slate-400">{inj.note}</p>}
                {inj.decoy && <p className="mt-1 text-[10px] text-cyber-300/80">Decoy — did the team correctly reject it, or chase a false lead?</p>}
                {inj.expected && <p className="mt-1 text-[10px] text-slate-500"><span className="text-slate-400">Expected:</span> {inj.expected}{inj.objective && inj.objective !== "—" ? ` · ${inj.objective}` : ""}</p>}
              </div>
              );
            })}
          </div>
        </Card>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        {visible.map(u => (
          <Card key={u.user_id}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-bold text-white">{u.name}</p>
              <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{ROLE_LABEL[u.role] ?? u.role}</span>
            </div>
            {/* G-11: role rubric is the real score; contribution kept as a secondary signal */}
            {u.insufficientEvidence ? (
              // Fewer than 2 measured criteria: no % (a 100% built on one cell misleads).
              <div className="mt-2 flex items-center gap-2" title={LEGEND["Insufficient evidence"]}>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg" />
                <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-[10px] font-bold uppercase text-neon-amber">insufficient evidence</span>
              </div>
            ) : (
              <div className="mt-2 flex items-center gap-2">
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg"><span className="block h-full bg-cyber-500" style={{ width: `${u.rubricPct ?? 0}%` }} /></div>
                <span className="shrink-0 font-mono text-xs font-bold text-cyber-300">{u.rubricPct != null ? `${u.rubricPct}` : "—"}<span className="text-slate-500">/100</span></span>
              </div>
            )}
            <p className="mt-1 text-[10px] text-slate-500">
              {u.insufficientEvidence
                ? `only ${u.measuredCells ?? 0} of ${u.rubric.length} criteria could be measured this shift — no score`
                : `role rubric score${u.measuredCells != null ? ` · ${u.measuredCells}/${u.rubric.length} criteria measured` : ""}`} · contribution {u.contribution}/100
            </p>
            {u.rubric.length > 0 && (
              <div className="mt-2 space-y-1">
                {u.rubric.map(cell => (
                  <div key={cell.label} className="flex items-center gap-2 text-[11px]" title={cell.note}>
                    <span className="min-w-0 flex-1 truncate text-slate-400">{cell.label}</span>
                    {cell.score == null
                      // A null cell never shows its (positive-sounding) description as if it were a result.
                      ? <span className="shrink-0 rounded border border-border/60 px-1 py-0.5 text-[9px] uppercase text-slate-600">{cell.note === "not yet measured" ? "not measured" : "n/a"}</span>
                      : <span className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${cell.score >= 12 ? "bg-neon-green/15 text-neon-green" : cell.score >= 8 ? "bg-cyber-500/15 text-cyber-300" : cell.score >= 4 ? "bg-neon-amber/15 text-neon-amber" : "bg-severity-high/15 text-severity-high"}`}>{cell.score}</span>}
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-xs">
              <Line label="Logs opened" value={String(u.opened)} />
              <Line label="Avg dwell" value={u.avgDwellS != null ? `${u.avgDwellS}s` : "—"} />
              <Line label="First action" value={u.firstActionS != null ? `${u.firstActionS}s` : "—"} />
              <Line label="Dispositions" value={`${u.dispCount}${u.dispAcc != null ? ` · ${u.dispAcc}%` : ""}${u.dispUnopened ? ` · ${u.dispUnopened} unread` : ""}`} />
              <Line label="Escalations" value={`${u.escCount}${u.escQuality != null ? ` · q${u.escQuality}` : ""}`} />
              <Line label="Acknowledged" value={String(u.acks)} />
              <Line label="Containment" value={`${u.contReq} req · ${u.contDecided} dec`} />
              <Line label="Role actions" value={String(u.roleActions)} />
            </div>
          </Card>
        ))}
      </div>
      <p className="text-xs text-slate-400">Per-user rubric (0/4/8/12 per criterion) + team report, computed on the server from the full action log. A criterion marked n/a or not measured had nothing to measure in this shift — it is left out of the score, and a card with fewer than 2 measured criteria shows <b className="text-neon-amber">insufficient evidence</b> instead of a %. &quot;Suspicious&quot; earns partial credit; a verdict on a log you never opened counts at reduced weight. Hover a criterion for how it is measured.</p>
    </div>
  );
}
function Line({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between border-b border-border/40 pb-1"><span className="text-slate-400">{label}</span><span className="font-mono text-slate-200">{value}</span></div>;
}
