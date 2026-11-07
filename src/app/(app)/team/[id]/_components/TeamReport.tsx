"use client";
import { sentinelActivity } from "@/lib/team/report/sentinelActivity";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { setTotalXp } from "@/lib/storage/progress";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight, ShieldAlert, Siren, Clock, Timer, EyeOff, MonitorX, ChevronDown, Presentation, Users, Gavel, Microscope, UserRound } from "lucide-react";
import type { RosterMember, Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import type { computeReport, ReportedItem, MissItem, MissedAttack, IsolationItem, MissedHost, RubricCell, UserReport, IncidentReport } from "@/lib/team/report/computeReport";
import type * as ReportTypes from "@/lib/team/report/computeReport";
import { mergeAnswers, type AnswerMap } from "@/lib/team/report/serverReport";
import { ROLE_LABEL, Metric } from "./shared";
import { CommandReview } from "./CommandReview";
import { ForensicTeamCard, ForensicUserSection } from "./ForensicReviewPanel";
import type { ManagerReview } from "@/lib/team/report/managerReview";
import { attackStories, fmtDur, type AttackStory } from "./debriefStory";

/** One duration format across the report (review 2026-11): 40s, 1m 05s. Never raw seconds. */
const dur = fmtDur;

// ── Guided hot-wash (§6.6): a dual-track replay reconstructed from the event log (attack activity
// vs the team's response), key moments, and the four debrief questions. This is the
// "conversation, not a scorecard" half of the debrief. All derived from `events`.
const RESPONSE_LABEL: Record<string, string> = {
  "escalation.requested": "escalated to Tier-2", "escalation.acknowledged": "acknowledged", "escalation.bounced": "bounced back",
  "elevation.requested": "elevated to Tier-3", "containment.requested": "requested containment", "containment.approved": "approved containment",
  "containment.denied": "denied containment", "containment.executed": "executed isolation", "edr.host_isolated": "isolated a host", "decision.logged": "logged a decision",
  "sitrep.sent": "sent a SITREP", "scope.confirmed": "confirmed scope", "isolation.requested": "asked to isolate a host", "isolation.approved": "approved an isolation", "isolation.denied": "denied an isolation",
};
const isAttackFeed = (e: Ev) => {
  if (e.type !== "feed.event") return false;
  const v = (e.payload as Record<string, unknown>).expected_verdict;
  return v === "tp" || v === "escalate";
};

interface HotWashData {
  rows: { t: number; track: "attack" | "response"; label: string; who?: string }[];
  moments: { t: string; title: string; note: string }[];
  attackCount: number;
  whatHappened: string;
}

/** The hot-wash, built once for the report card and the staff debrief screen. `who` names an actor. */
export function hotWash(events: Ev[], who: (e: Ev) => string): HotWashData {
  // Anchor relative times to session START (not events[0], the earliest lobby member.ready).
  const startedEv = events.find(e => e.type === "session.started");
  const t0 = startedEv?.occurred_at ? Date.parse(startedEv.occurred_at)
    : (events.length && events[0].occurred_at ? Date.parse(events[0].occurred_at) : 0);
  const rel = (ts?: string) => (ts && t0 ? Math.max(0, Math.round((Date.parse(ts) - t0) / 1000)) : 0);
  const rows: HotWashData["rows"] = [];
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    if (isAttackFeed(e)) rows.push({ t: rel(e.occurred_at), track: "attack", label: asStr(p.description) || asStr(p.event_type) || "attack activity" });
    else if (RESPONSE_LABEL[e.type]) rows.push({ t: rel(e.occurred_at), track: "response", label: RESPONSE_LABEL[e.type], who: who(e) });
  }
  rows.sort((a, b) => a.t - b.t);

  const firstAttack = events.find(isAttackFeed);
  const firstEsc = events.find(e => e.type === "escalation.requested");
  const decision = events.find(e => e.type === "containment.approved" || e.type === "containment.denied");
  const exec = events.find(e => e.type === "containment.executed" || e.type === "edr.host_isolated");
  const dwellS = firstAttack && firstEsc ? rel(firstEsc.occurred_at) - rel(firstAttack.occurred_at) : null;

  const moments: HotWashData["moments"] = [];
  if (firstEsc) moments.push({ t: dur(rel(firstEsc.occurred_at)), title: "First escalation", note: `${who(firstEsc)} raised the first case${dwellS != null && dwellS >= 0 ? `, ${dur(dwellS)} after the attack first showed in the feed` : ""}.` });
  if (decision) moments.push({ t: dur(rel(decision.occurred_at)), title: decision.type === "containment.approved" ? "Containment approved" : "Containment denied", note: `${who(decision)} made the call.` });
  if (exec) moments.push({ t: dur(rel(exec.occurred_at)), title: "Host isolated", note: `${who(exec)} carried out the containment.` });

  const attackCount = rows.filter(r => r.track === "attack").length;
  const denied = !exec && events.some(e => e.type === "containment.denied");
  const whatHappened = [
    firstEsc ? `first escalation at ${dur(rel(firstEsc.occurred_at))}${dwellS != null && dwellS >= 0 ? ` (${dur(dwellS)} after the attack first surfaced)` : ""}` : "no escalation was raised",
    exec ? `a host was isolated at ${dur(rel(exec.occurred_at))}` : denied ? "containment was denied" : "no host was contained",
  ].join("; ") + ".";
  return { rows, moments, attackCount, whatHappened };
}

/** The server's hot-wash (0104: on running time, pauses cut out) in the shape the cards draw. */
type ServerHotWash = { rows: { tS: number; track: "attack" | "response"; label: string; who: string | null }[]; moments: { tS: number; title: string; note: string; who: string | null }[]; firstAttackS: number | null; firstEscalationS: number | null; dwellS: number | null; contained: boolean; containedS: number | null; denied: boolean };
export function hotWashFromServer(h: ServerHotWash, who: (actorId: string | null) => string): HotWashData {
  // The report calls a host isolation what it is, wherever it was done (EDR or Sentinel).
  const clean = (l: string) => l.replace(/ in EDR\b/g, "");
  const rows = h.rows.map(r => ({ t: r.tS, track: r.track, label: clean(r.label), who: r.track === "response" ? who(r.who) : undefined }));
  const moments = h.moments.map(m => ({ t: dur(m.tS), title: clean(m.title), note: ((n: string) => (n ? n.replace(/\.?$/, ".") : ""))([m.who ? `By ${who(m.who)}` : "", clean(m.note)].filter(Boolean).join(". ")) }));
  const whatHappened = [
    h.firstEscalationS != null ? `first escalation at ${dur(h.firstEscalationS)}${h.dwellS != null ? ` (${dur(h.dwellS)} after the attack first surfaced)` : ""}` : "no escalation was raised",
    h.contained ? `a host was isolated at ${dur(h.containedS)}` : h.denied ? "containment was denied" : "no host was contained",
  ].join("; ") + ".";
  return { rows, moments, attackCount: h.rows.filter(r => r.track === "attack").length, whatHappened };
}

/** The four debrief questions: the first two pre-filled from the truth, the last two are the team's. */
function debriefSteps(h: HotWashData) {
  return [
    { n: 1, q: "What should have happened", a: `${h.attackCount} real attack log${h.attackCount === 1 ? " was" : "s were"} hidden in the noise. The shift should catch them, escalate with evidence, scope the incident, and contain the right asset.`, given: true },
    { n: 2, q: "What actually happened", a: h.whatHappened.charAt(0).toUpperCase() + h.whatHappened.slice(1), given: true },
    { n: 3, q: "Why the gap?", a: "Talk it through: the earliest log you walked past, where hand-offs stalled (Tier-1 to Tier-2 to the Manager to the action), any wrong call and how it was caught.", given: false },
    { n: 4, q: "What we would do differently", a: "Name one concrete change for the first five minutes of the next shift.", given: false },
  ];
}

function HotWash({ events, nameOf, server }: { events: Ev[]; nameOf: (u: string | null) => string; server?: ServerHotWash | null }) {
  const h = useMemo(() => (server ? hotWashFromServer(server, nameOf) : hotWash(events, e => nameOf(e.actor_id))), [events, nameOf, server]);
  if (h.rows.length === 0) return null;
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Clock className="h-4 w-4 text-cyber-300" aria-hidden /> Hot-wash: what happened, and when</h3>
      <p className="mt-1 text-xs text-slate-400">Attack activity and the team&apos;s response, side by side. Use it to talk the timeline through together.</p>

      {h.moments.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {h.moments.map((m, i) => (
            <div key={i} className="rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2">
              <p className="font-mono text-[11px] text-cyber-300">{m.t}</p>
              <p className="text-xs font-semibold text-white">{m.title}</p>
              <p className="text-[11px] leading-snug text-slate-400"><bdi>{m.note}</bdi></p>
            </div>
          ))}
        </div>
      )}

      {/* Dual-track timeline: attack on the left, response on the right */}
      <div className="mt-3 max-h-72 overflow-y-auto rounded-lg border border-border/50 bg-bg" tabIndex={0} aria-label="Hot-wash timeline">
        {h.rows.map((r, i) => (
          <div key={i} className="flex items-stretch gap-2 border-b border-border/30 px-2 py-1 text-xs last:border-0">
            <span className="w-16 shrink-0 pt-0.5 text-right font-mono text-[11px] text-slate-500">{dur(r.t)}</span>
            <div className="min-w-0 flex-1">
              {r.track === "attack"
                ? <div className="rounded border-l-2 border-severity-high/60 bg-severity-high/[0.06] px-2 py-1 text-severity-high/90"><span className="text-[11px] font-bold uppercase tracking-wider text-severity-high/80">attack</span> <bdi>{r.label}</bdi></div>
                : <div className="ms-auto w-[85%] rounded border-l-2 border-cyber-500/60 bg-cyber-500/[0.06] px-2 py-1 text-slate-200"><span className="text-[11px] font-bold uppercase tracking-wider text-cyber-300"><bdi>{r.who}</bdi></span> {r.label}</div>}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3 space-y-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Debrief together: work through it in order</p>
        {debriefSteps(h).map(s => (
          <div key={s.n} className="flex gap-2 rounded-lg border border-border/50 bg-bg-elevated/40 px-3 py-2">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyber-500/20 font-mono text-[11px] font-bold text-cyber-300">{s.n}</span>
            <div className="min-w-0">
              <p className="text-xs font-semibold text-white">{s.q}</p>
              <p className={`mt-0.5 text-xs leading-snug ${s.given ? "text-slate-300" : "italic text-slate-400"}`}>{s.a}</p>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Handoff ladder (research P0): the closed-loop chain per case, escalate → acknowledge →
// elevate → contain → resolve, with per-hop latency and a closed / open / dropped status.
const HOP: Record<string, string> = {
  "escalation.requested": "Tier-1 escalated", "escalation.acknowledged": "Tier-2 acknowledged", "escalation.bounced": "bounced back",
  "elevation.requested": "elevated to Tier-3", "elevation.acknowledged": "Tier-3 took it", "containment.requested": "containment requested",
  "containment.approved": "Manager approved", "containment.denied": "Manager denied", "containment.executed": "isolated", "escalation.resolved": "resolved",
};
type ServerChain = { eid: string; title: string; status: "closed" | "open" | "dropped"; selfOpened: boolean; steps: { type: string; who: string | null; atS: number | null; dS: number | null }[] };
function HandoffLadder({ events, nameOf, server }: { events: Ev[]; nameOf: (u: string | null) => string; server?: ServerChain[] | null }) {
  const cases = useMemo((): { eid: string; title: string; status: "closed" | "open" | "dropped"; selfOpened?: boolean; steps: { type: string; who: string; d: number | null }[] }[] => {
    if (server) return server.map(c => ({ eid: c.eid, title: c.title, status: c.status, selfOpened: c.selfOpened, steps: c.steps.map(st => ({ type: st.type, who: nameOf(st.who), d: st.dS })) }));
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
      if (!start) continue; // only real Tier-1 hand-off chains
      const hops = raw.slice().sort((a, b) => (a.at ?? 0) - (b.at ?? 0));
      const acked = hops.some(h => h.type === "escalation.acknowledged");
      // A bounce is an explicit answer back to Tier-1: the loop CLOSED (same rule as the report).
      const closed = hops.some(h => h.type === "escalation.resolved" || h.type === "containment.executed" || h.type === "escalation.bounced");
      const status = closed ? "closed" : !acked ? "dropped" : "open";
      let prev = start.at;
      const steps = hops.map(h => { const d = prev != null && h.at != null ? (h.at - prev) / 1000 : null; prev = h.at ?? prev; return { type: h.type, who: h.who, d }; });
      out.push({ eid, title: start.label || "escalated case", status, steps });
    }
    // Dropped loops first (they need the most discussion), then by chain length.
    return out.sort((a, b) => (a.status === "dropped" ? 0 : 1) - (b.status === "dropped" ? 0 : 1) || b.steps.length - a.steps.length);
  }, [events, nameOf, server]);
  if (cases.length === 0) return null;
  const STATUS_STYLE: Record<string, string> = {
    closed: "border-neon-green/40 bg-neon-green/10 text-neon-green",
    open: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
    dropped: "border-severity-high/50 bg-severity-high/15 text-severity-high",
  };
  return (
    <>
      <p className="text-xs text-slate-400">Each escalated case, tier to tier, with the delay at each hop. A <b className="text-severity-high">dropped</b> chain was escalated but never acknowledged: a broken loop worth talking through. A <b className="text-slate-300">self-opened</b> case was opened and acknowledged by the same person, so it is no hand-off and does not count toward the hand-off numbers.</p>
      <div className="mt-3 max-h-80 space-y-2 overflow-y-auto">
        {cases.slice(0, 8).map(c => (
          <div key={c.eid} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
            <div className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate text-xs font-semibold text-slate-200"><bdi>{c.title}</bdi></span>
              {c.selfOpened && <span className="shrink-0 rounded border border-border px-1 py-0.5 text-[11px] font-bold uppercase text-slate-400" title="Opened and acknowledged by the same person: no hand-off">self-opened</span>}
              <span className={`shrink-0 rounded border px-1 py-0.5 text-[11px] font-bold uppercase ${STATUS_STYLE[c.status]}`}>{c.status}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-1 gap-y-1">
              {c.steps.map((s, i) => (
                <span key={i} className="inline-flex items-center gap-1">
                  {i > 0 && <span className="font-mono text-[11px] text-slate-500">{s.d != null ? `+${dur(s.d)} ` : ""}→</span>}
                  <span className="rounded border border-border/60 bg-bg-elevated/40 px-1.5 py-0.5 text-[11px] text-slate-300" title={s.who}>{HOP[s.type]}</span>
                </span>
              ))}
              {c.status === "dropped" && <span className="ml-1 text-[11px] text-severity-high">nobody acknowledged it</span>}
            </div>
          </div>
        ))}
        {cases.length > 8 && <p className="text-[11px] text-slate-500">+{cases.length - 8} more chains.</p>}
      </div>
    </>
  );
}

const SEV_STYLE: Record<string, string> = {
  critical: "border-severity-high/60 bg-severity-high/15 text-severity-high",
  high: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  medium: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
};
function SevChip({ sev }: { sev: string }) {
  return <span className={`shrink-0 rounded border px-1 py-px font-mono text-[11px] font-bold uppercase ${SEV_STYLE[sev] ?? "border-border text-slate-400"}`}>{sev === "informational" ? "info" : sev}</span>;
}

/** Per-analyst: every event they escalated (or triaged, when high/critical) against its SLA. */
function ReportedTable({ items, met, total, pct }: { items: ReportedItem[]; met: number; total: number; pct: number | null }) {
  if (items.length === 0) return null;
  const TRUTH: Record<string, [string, string]> = {
    attack: ["real attack", "text-severity-high"],
    related: ["incident step", "text-neon-amber"],
    benign: ["benign", "text-slate-400"],
  };
  return (
    <div className="mt-3 border-t border-border/40 pt-2">
      <div className="flex items-center justify-between">
        <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><Timer className="h-3 w-3" aria-hidden /> SLA per reported event</p>
        <span className={`font-mono text-[11px] font-bold ${pct == null ? "text-slate-500" : pct >= 80 ? "text-neon-green" : pct >= 50 ? "text-neon-amber" : "text-severity-high"}`}>{met}/{total} within SLA{pct != null ? ` · ${pct}%` : ""}</span>
      </div>
      <div className="mt-1.5 max-h-56 space-y-1 overflow-y-auto pr-1">
        {items.map((r, i) => (
          <div key={i} className="rounded border border-border/40 bg-bg px-2 py-1 text-xs">
            <div className="flex items-center gap-1.5">
              <SevChip sev={r.severity} />
              <span className="min-w-0 flex-1 truncate text-slate-300" title={r.label}><bdi>{r.label}</bdi></span>
              <span className={`shrink-0 font-mono text-[11px] font-bold ${r.withinSla == null ? "text-slate-500" : r.withinSla ? "text-neon-green" : "text-severity-high"}`}>
                {r.withinSla == null ? "-" : r.withinSla ? "✓" : "✗"} {dur(r.responseS)}<span className="font-normal text-slate-500"> / {dur(r.slaS)}</span>
              </span>
            </div>
            <p className="mt-0.5 text-[11px] text-slate-500">
              {r.kind === "escalation" ? "escalated" : `triaged${r.verdict ? ` as ${r.verdict.replace("_", " ")}` : ""}`}
              {r.arrivedS != null ? ` · arrived ${dur(r.arrivedS)}` : ""}
              {" · "}<span className={TRUTH[r.truth]?.[1]}>{TRUTH[r.truth]?.[0]}</span>
              {(r as ReportedItem & { selfOpened?: boolean }).selfOpened ? " · self-opened, so no hand-off and no SLA judgement" : r.outcome ? ` · ${r.outcome === "open" ? "no Tier-2 answer" : r.outcome}` : ""}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

/** A labelled list of logs worth discussing (misses / false alarms). */
function MissList({ title, items, tone, empty }: { title: string; items: MissItem[]; tone: "high" | "amber"; empty?: string }) {
  if (items.length === 0) return empty ? <p className="text-[11px] text-slate-500">{title}: {empty}</p> : null;
  return (
    <div>
      <p className={`text-[11px] font-semibold ${tone === "high" ? "text-severity-high" : "text-neon-amber"}`}>{title} ({items.length})</p>
      <ul className="mt-0.5 space-y-0.5">
        {items.map((m, i) => (
          <li key={i} className="text-[11px] text-slate-300">
            <span className="flex items-center gap-1.5">
              <SevChip sev={m.severity} />
              <span className="min-w-0 flex-1 truncate" title={m.label}><bdi>{m.label}</bdi></span>
              {m.arrivedS != null && <span className="shrink-0 font-mono text-slate-500">{dur(m.arrivedS)}</span>}
            </span>
            {/* Where to learn it (2026-10-18 review): the practice room for the log's technique. */}
            {m.practice && <Link href={`/rooms/${m.practice.id}`} className="mt-0.5 block truncate text-cyber-300 underline-offset-2 hover:underline" title={`Practice: ${m.practice.title}`}>practice: {m.practice.title}</Link>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The measurable criteria (Tal, 2026-10-27): each row shows what was measured, the target and the
 *  score out of 100 it earned. Criteria with nothing to measure this shift fold into one line. */
function RubricCells({ cells }: { cells: RubricCell[] }) {
  const measured = cells.filter(c => c.score != null);
  const idle = cells.filter(c => c.score == null);
  return (
    <div className="mt-2">
      <ul className="space-y-1.5">
        {measured.map(cell => {
          const pts = Math.round(((cell.score ?? 0) / 12) * 100);
          return (
            <li key={cell.label} className="flex items-start gap-2 text-xs" title={cell.note}>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-slate-300">{cell.label}</span>
                {(cell.value || cell.target) && (
                  <span className="block text-[11px] text-slate-500">
                    {cell.value && <span className="font-mono text-slate-300">{cell.value}</span>}
                    {cell.value && cell.target ? " · " : ""}
                    {cell.target && <>target {cell.target}</>}
                  </span>
                )}
              </span>
              <span className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[11px] font-bold tabular-nums ${pts >= 100 ? "bg-neon-green/15 text-neon-green" : pts >= 67 ? "bg-cyber-500/15 text-cyber-300" : pts >= 33 ? "bg-neon-amber/15 text-neon-amber" : "bg-severity-high/15 text-severity-high"}`}>{pts}</span>
            </li>
          );
        })}
      </ul>
      {/* A null cell never shows its (positive-sounding) description as if it were a result. */}
      {idle.length > 0 && <p className="mt-1.5 text-[11px] text-slate-500">Nothing to measure this shift: {idle.map(c => c.label).join(", ")}.</p>}
    </div>
  );
}

function XpChip({ xp }: { xp?: number }) {
  if (typeof xp !== "number") return null;
  return <span className="rounded border border-neon-green/40 bg-neon-green/10 px-1.5 py-0.5 font-mono text-[11px] font-bold text-neon-green" title="XP added to the account for this shift">+{xp} XP</span>;
}
function ScoreBar({ score }: { score: number | null }) {
  return (
    <div className="mt-2 flex items-center gap-2">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg" aria-hidden><span className="block h-full bg-cyber-500" style={{ width: `${score ?? 0}%` }} /></div>
      <span className="shrink-0 font-mono text-xs font-bold text-cyber-300">{score ?? "-"}<span className="text-slate-500">/100</span></span>
    </div>
  );
}

/** The SOC Manager's card in the per-person grid: the Command Review score and its measured criteria. */
function ManagerCard({ review, xp }: { review: ManagerReview; xp?: number }) {
  const cells: RubricCell[] = review.pillars.flatMap(p => p.cells.map(c => ({ label: c.label, score: c.score, value: c.score != null ? c.note : undefined })));
  return (
    <Card>
      <div className="flex items-center justify-between">
        <p className="text-sm font-bold text-white"><bdi>{review.managerName}</bdi></p>
        <span className="flex items-center gap-1.5">
          <XpChip xp={xp} />
          <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-slate-400">{ROLE_LABEL.mgr ?? "SOC Manager"}</span>
        </span>
      </div>
      <ScoreBar score={review.score} />
      <p className="mt-1 text-[11px] text-slate-500">
        Command Review score{review.levelLabel ? ` · ${review.levelLabel}` : ""}{review.criticalErrors.length ? ` · capped by ${review.criticalErrors.length} critical error${review.criticalErrors.length === 1 ? "" : "s"}` : ""} · full review in its section
      </p>
      <RubricCells cells={cells} />
    </Card>
  );
}

/** Attacks nobody caught (Tal, 2026-10-27): one line per attack with its main log, not every log of it. */
function MissedAttackList({ items }: { items: MissedAttack[] }) {
  return (
    <div>
      <p className="text-[11px] font-semibold text-severity-high">Attacks nobody caught ({items.length})</p>
      <ul className="mt-1 space-y-1.5">
        {items.map((a, i) => (
          <li key={i} className="rounded-lg border border-severity-high/30 bg-severity-high/[0.04] px-2.5 py-2 text-xs text-slate-300">
            <span className="block text-xs font-semibold text-white"><bdi>{a.name}</bdi></span>
            <span className="mt-1 flex items-center gap-1.5">
              <span className="shrink-0 text-[11px] text-slate-500">Main log</span>
              <SevChip sev={a.severity} />
              <span className="min-w-0 flex-1 truncate" title={a.label}><bdi>{a.label}</bdi></span>
            </span>
            <span className="mt-0.5 block text-[11px] text-slate-500">
              {a.host && <>on <bdi className="font-mono text-slate-300">{a.host}</bdi> · </>}
              {a.arrivedS != null ? `landed at ${dur(a.arrivedS)}` : "time unknown"}
              {a.hosts.length > 1 ? ` · the attack touched ${a.hosts.length} hosts` : ""}
            </span>
            {a.calledBenign && <span className="mt-0.5 block text-[11px] text-neon-amber">Someone looked at it and called it benign.</span>}
            {a.relatedLogs > 0 && (
              <span className="mt-0.5 block text-[11px] text-slate-400">
                {a.relatedLogs} related log{a.relatedLogs === 1 ? "" : "s"} of the same attack. Escalating any one of them would have caught it.
              </span>
            )}
            {a.practice && <Link href={`/rooms/${a.practice.id}`} className="mt-1 block truncate text-[11px] text-cyber-300 underline-offset-2 hover:underline" title={`Practice: ${a.practice.title}`}>practice: {a.practice.title}</Link>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Host isolations, each judged against the answer key (v4). */
function IsolationList({ items, nameOf }: { items: IsolationItem[]; nameOf?: (u: string | null) => string }) {
  if (items.length === 0) return null;
  return (
    <ul className="space-y-1">
      {items.map((it, i) => (
        <li key={i} className={`rounded border px-2 py-1 text-xs ${it.correct ? "border-neon-green/30 bg-neon-green/[0.05]" : "border-severity-high/40 bg-severity-high/[0.06]"}`}>
          <div className="flex items-center gap-1.5">
            <span className={`shrink-0 font-mono text-[11px] font-bold ${it.correct ? "text-neon-green" : "text-severity-high"}`}>{it.correct ? "✓ right call" : "✗ wrong call"}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-slate-200" title={it.host}>{it.host}</span>
            {it.atS != null && <span className="shrink-0 font-mono text-[11px] text-slate-500">{dur(it.atS)}</span>}
          </div>
          <p className="mt-0.5 text-[11px] text-slate-400">
            {it.verdict === "compromised"
              ? <>compromised: real attack activity on this host{it.timeToIsolateS != null ? ` · isolated ${dur(it.timeToIsolateS)} after its first attack log` : ""}</>
              : <>clean: no attack activity on this host; isolating it cut a user off for nothing</>}
            {nameOf ? <> · by <bdi>{nameOf(it.by)}</bdi></> : ""}
            {it.releasedS != null ? ` · released at ${dur(it.releasedS)}` : ""}
          </p>
        </li>
      ))}
    </ul>
  );
}

type IsoRequestItem = { host: string; requestedBy: string | null; requestedS: number | null; reason: string; state: "pending" | "approved" | "denied"; answeredBy: string | null; answeredS: number | null; delayS: number | null; verdict: "compromised" | "clean"; requestRight: boolean; answerRight: boolean | null };
/** Isolation requests (0104: isolating needs the senior on shift's approval), each judged. */
function IsolationRequestList({ items, nameOf }: { items: IsoRequestItem[]; nameOf: (u: string | null) => string }) {
  if (!items.length) return null;
  return (
    <div>
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Isolation requests ({items.length})</p>
      <ul className="space-y-1">
        {items.map((r, i) => (
          <li key={i} className={`rounded border px-2 py-1 text-xs ${r.requestRight && r.answerRight !== false ? "border-border bg-bg" : "border-severity-high/40 bg-severity-high/[0.06]"}`}>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="min-w-0 flex-1 truncate font-mono text-slate-200" title={r.host}>{r.host}</span>
              <span className={`shrink-0 rounded border px-1 text-[11px] font-bold uppercase ${r.state === "approved" ? "border-neon-green/40 text-neon-green" : r.state === "denied" ? "border-severity-high/50 text-severity-high" : "border-neon-amber/40 text-neon-amber"}`}>{r.state === "pending" ? "never answered" : r.state}</span>
              {r.requestedS != null && <span className="shrink-0 font-mono text-[11px] text-slate-500">{dur(r.requestedS)}</span>}
            </div>
            <p className="mt-0.5 text-[11px] text-slate-400">
              Asked by <bdi>{nameOf(r.requestedBy)}</bdi>: <bdi className="text-slate-300">{r.reason || "no reason given"}</bdi>
              {r.answeredBy ? <> · {r.state} by <bdi>{nameOf(r.answeredBy)}</bdi>{r.delayS != null ? ` after ${dur(r.delayS)}` : ""}</> : r.delayS != null ? ` · waited ${dur(r.delayS)}` : ""}
            </p>
            <p className={`text-[11px] ${r.requestRight ? "text-neon-green" : "text-severity-high"}`}>
              {r.verdict === "compromised" ? "The host was compromised: right to ask." : "The host was clean: isolating it would cut a user off for nothing."}
              {r.answerRight === true ? " The answer was right." : r.answerRight === false ? " The answer was the wrong call." : ""}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Compromised hosts nobody isolated. */
function HostsLeftOnline({ items }: { items: MissedHost[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="text-[11px] font-semibold text-neon-amber">Compromised hosts nobody isolated ({items.length})</p>
      <ul className="mt-0.5 space-y-0.5">
        {items.map((h, i) => (
          <li key={i} className="flex items-center gap-1.5 text-[11px] text-slate-300">
            <span className="min-w-0 flex-1 truncate font-mono" title={h.host}>{h.host}</span>
            <span className="shrink-0 text-slate-500">{h.attackLogs} attack log{h.attackLogs === 1 ? "" : "s"}{h.firstAttackS != null ? ` · first at ${dur(h.firstAttackS)}` : ""}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

type Report = ReturnType<typeof computeReport>;

// S10: a spreadsheet evaluates a cell starting with = + - @ (or a tab/CR) as a
// formula even inside quotes: a display name like =HYPERLINK(...) would run in the
// instructor's Excel. Prefix those cells with an apostrophe.
function csvCell(v: unknown): string {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

/** Plain labels on the page; the acronym and how it is measured in the tooltip and the legend. */
const LEGEND: Record<string, string> = {
  "Time to detect": "MTTD (mean time to detect): from an incident's first log to the first time anyone flagged it (a verdict, an escalation or an isolation). Median across incidents.",
  "Time to contain": "MTTR (mean time to respond): from an incident's first log to it being contained (host isolated, containment carried out, or its case resolved). Median across incidents.",
  "Escalation SLA": "SLA (service level agreement): an incident that needs escalation must reach Tier-2 (escalated, or its host isolated) within 15 minutes of its first alert. A verdict alone does not meet it; an incident that surfaced in the last 15 minutes of the shift is not judged.",
  "Incidents caught": "Real incidents the team caught: any of an incident's attack logs escalated, or marked true positive / suspicious. Scored per incident, not per log.",
  "Wait for Tier-2": "Handoff latency: how long an escalation waited before a Tier-2 acknowledged it (median).",
  "Escalations answered": "Handoff loop closure: share of escalated logs a Tier-2 closed the loop on (acknowledged, bounced back or resolved).",
  "Request to isolation": "MTTC (mean time to contain): from a containment request to the isolation being carried out.",
  "Shared picture": "Contested = two analysts gave opposite verdicts on the same event.",
  "Insufficient evidence": "Fewer than 2 criteria could be measured for this seat: no score is shown rather than a misleading 100%.",
  "Attack logs within SLA": "SLA (service level agreement): share of real attack logs the team first triaged (verdict or escalation) within the time for their severity: critical 1 min · high 3 min · medium 10 min · other 30 min.",
  "High/critical triaged": "Share of high and critical alerts that got any triage action (verdict or escalation) from anyone.",
  "Time to triage": "Median time from a high/critical alert landing in the feed to the first triage action on it.",
  "Attack logs missed": "Real attack logs nobody judged or escalated. Some still belong to an incident the team caught through another log.",
  "Attacks missed": "Attacks nobody caught: none of the attack's logs was escalated or judged true positive / suspicious, and none of its hosts was isolated. One handled log is enough to count the attack as caught.",
  "False negatives": "Attack logs whose standing call was benign / false positive and that nobody escalated.",
  "False alarms": "Benign logs (not part of any incident) that were escalated.",
  "Busiest analyst": "Share of all triage actions (verdicts and escalations) done by the busiest analyst: a high share means the work was not spread.",
  "Verdict accuracy": "Balanced disposition accuracy: how often a verdict matched the truth, attack logs and benign logs weighted equally.",
  "Surprise events": "Curveballs from the exercise script (MSEL, master scenario events list): pressure and tickets during the shift, each with an expected response.",
};

/** A labelled metric with its explanation as a tooltip. */
function Tip({ label, value, tone, shown }: { label: string; value: string; tone?: "good" | "warn"; shown?: string }) {
  return <span title={LEGEND[label]}><Metric label={shown ?? label} value={value} tone={tone} /></span>;
}

/** A folded detail section: the title and one status line show, the rest opens on demand. */
function Fold({ title, icon, status, tone, children, defaultOpen = false, id }: { title: string; icon: ReactNode; status?: string; tone?: "good" | "warn" | "bad"; children: ReactNode; defaultOpen?: boolean; id?: string }) {
  return (
    <details open={defaultOpen} id={id} className={`group rounded-lg border bg-bg-elevated/60 ${tone === "bad" ? "border-severity-high/30" : tone === "warn" ? "border-neon-amber/30" : "border-border"}`}>
      <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg px-4 py-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60 [&::-webkit-details-marker]:hidden">
        {icon}
        <span className="text-sm font-bold text-white">{title}</span>
        {status && <span className={`ml-auto min-w-0 truncate font-mono text-[11px] ${tone === "good" ? "text-neon-green" : tone === "bad" ? "text-severity-high" : tone === "warn" ? "text-neon-amber" : "text-slate-400"}`}>{status}</span>}
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform group-open:rotate-180 ${status ? "" : "ml-auto"}`} aria-hidden />
      </summary>
      <div className="border-t border-border/50 px-4 pb-4 pt-3">{children}</div>
    </details>
  );
}

/** What the shift really was (0104): how long it ran, the pauses, and what never reached the feed. */
function ShiftFacts({ team }: { team: Report["team"] }) {
  const t = team as Report["team"] & { shift?: ReportTypes.ShiftTruth | null; pauses?: ReportTypes.PauseSummary | null; ghosts?: number };
  const lines: string[] = [];
  const sh = t.shift;
  if (sh) {
    lines.push(`The shift ran ${dur(sh.ranMs / 1000)}${sh.plannedMs ? ` of ${dur(sh.plannedMs / 1000)} planned` : ""}${sh.endedEarly ? ", ended early" : ""}${sh.endReason && sh.endReason !== "manual" ? ` (${sh.endReason.replace(/_/g, " ")})` : ""}.`);
    const notYet = [...sh.attacksNeverStarted, ...sh.attacksNotReached];
    if (notYet.length) lines.push(`${notYet.length} attack${notYet.length === 1 ? " had" : "s had"} not reached the feed when it ended, so ${notYet.length === 1 ? "it is" : "they are"} not judged: ${notYet.map(a => a.name).join("; ")}.`);
    if (sh.preventedByIsolation) lines.push(`${sh.preventedByIsolation} log${sh.preventedByIsolation === 1 ? "" : "s"} never arrived because ${sh.preventedByIsolation === 1 ? "its" : "their"} host was isolated.`);
  }
  if (t.pauses && t.pauses.count > 0) lines.push(`Paused ${t.pauses.count} time${t.pauses.count === 1 ? "" : "s"}, ${dur(t.pauses.totalS)} in all. Every time in this report leaves the pauses out.`);
  if (!lines.length) return null;
  return <ul className="mt-2 space-y-0.5 text-xs text-slate-300">{lines.map((l, i) => <li key={i}>{l}</li>)}</ul>;
}

// ── "You" first (review 2026-11): one short card per player with one score, one strength, one thing
// to fix, one practice room and the XP. The full breakdown sits in its section below.
interface PlayerSummary {
  userId: string; name: string; role: string; you: boolean;
  score: number | null; scoreLabel: string;
  strength: string; fix: string;
  practice: { id: string; title: string } | null;
  xp?: number;
}
const cellText = (c: RubricCell) => `${c.label}${c.value ? `: ${c.value}` : ""}`;
export function summarizePlayer(u: UserReport, opts: { you: boolean; xp?: number; fallbackPractice?: { id: string; title: string } | null }): PlayerSummary {
  const measured = u.rubric.filter(c => c.score != null).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
  const best = measured[0];
  const worst = [...measured].reverse().find(c => (c.score ?? 0) < 12);
  const strength = u.insufficientEvidence ? "Too little was measured this shift to name one."
    : best && (best.score ?? 0) >= 8 ? cellText(best)
    : best && (best.score ?? 0) >= 4 ? `${cellText(best)} (closest to its target)`
    : "No criterion reached its target this shift.";
  const fn = u.falseNegatives?.[0];
  const fix = fn ? `An attack you called benign: ${fn.label}`
    : worst ? `${cellText(worst)}${worst.target ? ` (target ${worst.target})` : ""}`
    : u.walkedPast?.[0] ? `An attack you opened and left: ${u.walkedPast[0].label}`
    : u.insufficientEvidence ? "Take on more of the queue next shift, so your work can be measured."
    : "Nothing from this shift's measures. Keep it up.";
  const practice = [...(u.falseNegatives ?? []), ...(u.walkedPast ?? [])].find(m => m.practice)?.practice ?? opts.fallbackPractice ?? null;
  return {
    userId: u.user_id, name: u.name, role: u.role, you: opts.you,
    score: u.insufficientEvidence ? null : u.rubricPct,
    scoreLabel: u.insufficientEvidence ? "Not enough evidence for a score" : "Role score",
    strength, fix, practice, xp: opts.xp,
  };
}
export function summarizeManager(r: ManagerReview, opts: { you: boolean; xp?: number; fallbackPractice?: { id: string; title: string } | null }): PlayerSummary {
  const cells = r.pillars.flatMap(p => p.cells).filter(c => c.score != null).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
  const best = cells[0];
  const worst = [...cells].reverse().find(c => (c.score ?? 0) < 12);
  return {
    userId: r.managerId, name: r.managerName, role: "mgr", you: opts.you,
    score: r.score, scoreLabel: "Command Review score",
    strength: r.keep[0] ?? (best && (best.score ?? 0) >= 8 ? best.label : "No part of the command work reached its target this shift."),
    fix: r.criticalErrors[0] ? `${r.criticalErrors[0].label}. ${r.criticalErrors[0].detail}` : r.improve[0] ?? (worst ? worst.label : "Nothing from this shift's measures. Keep it up."),
    practice: opts.fallbackPractice ?? null, xp: opts.xp,
  };
}

function SummaryCard({ s, large }: { s: PlayerSummary; large?: boolean }) {
  return (
    <Card className={s.you ? "border-cyber-500/50" : undefined}>
      <div className="flex flex-wrap items-center gap-2">
        <p className={`${large ? "text-base" : "text-sm"} font-bold text-white`}><bdi>{s.name}</bdi>{s.you && <span className="ml-1.5 rounded bg-cyber-500/20 px-1.5 py-0.5 text-[11px] font-semibold uppercase text-cyber-200">you</span>}</p>
        <span className="ml-auto flex items-center gap-1.5">
          <XpChip xp={s.xp} />
          <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-slate-400">{ROLE_LABEL[s.role] ?? s.role}</span>
        </span>
      </div>
      <div className="mt-3 flex items-end gap-3">
        <span className={`font-mono font-bold ${large ? "text-4xl" : "text-3xl"} ${s.score == null ? "text-slate-400" : s.score >= 80 ? "text-neon-green" : s.score >= 50 ? "text-cyber-300" : "text-neon-amber"}`}>{s.score ?? "-"}</span>
        <span className="pb-1 text-xs text-slate-400">{s.score != null ? "/100 · " : ""}{s.scoreLabel}</span>
      </div>
      <dl className="mt-3 space-y-2 text-xs">
        <div><dt className="text-[11px] font-semibold uppercase tracking-wider text-neon-green">Strength</dt><dd className="mt-0.5 text-slate-200"><bdi>{s.strength}</bdi></dd></div>
        <div><dt className="text-[11px] font-semibold uppercase tracking-wider text-neon-amber">One thing to fix</dt><dd className="mt-0.5 text-slate-200"><bdi>{s.fix}</bdi></dd></div>
        <div><dt className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">Practice room</dt>
          <dd className="mt-0.5">{s.practice ? <Link href={`/rooms/${s.practice.id}`} className="text-cyber-300 underline-offset-2 hover:underline">{s.practice.title}</Link> : <span className="text-slate-400">None suggested from this shift.</span>}</dd></div>
      </dl>
    </Card>
  );
}

/** The roles a debrief screen names instead of people (no blame, nobody singled out). */
const roleOf = (e: Ev, roster: RosterMember[]) => {
  const r = e.role ?? roster.find(m => m.user_id === e.actor_id)?.role ?? null;
  return r ? ROLE_LABEL[r] ?? r : e.actor_id ? "A teammate" : "The system";
};

/**
 * Staff debrief mode (review 2026-11): a shared-screen view of the hot-wash, the attack story of each
 * incident and the four debrief questions, in large type. Team facts only: no individual score and no
 * names (actors show as their role).
 */
function DebriefView({ events, roster, team, onExit }: { events: Ev[]; roster: RosterMember[]; team: Report["team"]; onExit: () => void }) {
  const root = useRef<HTMLDivElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [full, setFull] = useState(false);
  const canFull = typeof document !== "undefined" && !!document.fullscreenEnabled;
  const server = (team as { hotWash?: ServerHotWash }).hotWash ?? null;
  const h = useMemo(() => {
    const roleById = (u: string | null) => { const r = roster.find(m => m.user_id === u)?.role; return r ? ROLE_LABEL[r] ?? r : u ? "A teammate" : "The system"; };
    return server ? hotWashFromServer(server, roleById) : hotWash(events, e => roleOf(e, roster));
  }, [events, roster, server]);
  const incidents = useMemo(() => team.incidents ?? [], [team.incidents]);
  const stories = useMemo(() => {
    const names: Record<string, string> = {};
    for (const i of incidents) names[i.id] = i.name || i.label;
    return attackStories(events, names, e => roleOf(e, roster));
  }, [events, roster, incidents]);
  useEffect(() => { heading.current?.focus(); }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !document.fullscreenElement) onExit(); };
    const onFs = () => setFull(!!document.fullscreenElement);
    window.addEventListener("keydown", onKey);
    document.addEventListener("fullscreenchange", onFs);
    return () => { window.removeEventListener("keydown", onKey); document.removeEventListener("fullscreenchange", onFs); };
  }, [onExit]);
  const toggleFull = () => {
    if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
    else void root.current?.requestFullscreen().catch(() => {});
  };
  const caught = team.incidentsDetected ?? incidents.filter(i => i.detected).length;
  const total = team.incidentsTotal ?? incidents.length;

  return (
    <div ref={root} className="space-y-6 overflow-y-auto rounded-xl border border-cyber-500/30 bg-bg p-6 text-base text-slate-200 md:p-8" data-testid="debrief-mode">
      <div className="flex flex-wrap items-center gap-3">
        <h2 ref={heading} tabIndex={-1} className="flex items-center gap-3 text-2xl font-bold text-white focus:outline-none md:text-3xl"><Presentation className="h-7 w-7 text-cyber-300" aria-hidden /> Shift debrief</h2>
        <span className="ml-auto flex flex-wrap gap-2">
          {canFull && <Button variant="outline" size="sm" onClick={toggleFull}>{full ? "Leave full screen" : "Full screen"}</Button>}
          <Button variant="outline" size="sm" onClick={() => { if (document.fullscreenElement) void document.exitFullscreen().catch(() => {}); onExit(); }}>Back to the report</Button>
        </span>
      </div>
      <p className="text-lg text-slate-300">A no-fault conversation. {total ? <>The team caught <b className="text-white">{caught} of {total}</b> attack{total === 1 ? "" : "s"}.</> : null} People show by role, and no one&apos;s score is on this screen.</p>

      {/* 1. Hot-wash */}
      <section aria-labelledby="dbf-hw" className="space-y-3">
        <h3 id="dbf-hw" className="flex items-center gap-2 text-xl font-bold text-white"><Clock className="h-5 w-5 text-cyber-300" aria-hidden /> What happened, and when</h3>
        {h.moments.length > 0 && (
          <div className="grid gap-3 md:grid-cols-3">
            {h.moments.map((m, i) => (
              <div key={i} className="rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-4 py-3">
                <p className="font-mono text-base text-cyber-300">{m.t}</p>
                <p className="text-lg font-semibold text-white">{m.title}</p>
                <p className="text-base text-slate-300"><bdi>{m.note}</bdi></p>
              </div>
            ))}
          </div>
        )}
        {h.rows.length > 0 ? (
          <div className="max-h-[50vh] overflow-y-auto rounded-lg border border-border/50" tabIndex={0} aria-label="Attack and response timeline">
            {h.rows.map((r, i) => (
              <div key={i} className="flex items-stretch gap-3 border-b border-border/30 px-3 py-2 last:border-0">
                <span className="w-20 shrink-0 pt-0.5 text-right font-mono text-sm text-slate-400">{dur(r.t)}</span>
                <div className="min-w-0 flex-1">
                  {r.track === "attack"
                    ? <div className="rounded border-l-4 border-severity-high/60 bg-severity-high/[0.06] px-3 py-1.5 text-severity-high"><span className="text-sm font-bold uppercase tracking-wider">attack</span> <bdi>{r.label}</bdi></div>
                    : <div className="ms-auto w-[85%] rounded border-l-4 border-cyber-500/60 bg-cyber-500/[0.06] px-3 py-1.5 text-slate-100"><span className="text-sm font-bold uppercase tracking-wider text-cyber-300"><bdi>{r.who}</bdi></span> {r.label}</div>}
                </div>
              </div>
            ))}
          </div>
        ) : <p className="text-slate-400">Nothing from the attack or the response reached the log.</p>}
      </section>

      {/* 2. The attack story per incident */}
      {stories.length > 0 && (
        <section aria-labelledby="dbf-story" className="space-y-3">
          <h3 id="dbf-story" className="flex items-center gap-2 text-xl font-bold text-white"><ShieldAlert className="h-5 w-5 text-cyber-300" aria-hidden /> The attack{stories.length === 1 ? "" : "s"}, step by step</h3>
          {stories.map(s => <StoryCard key={s.id} s={s} inc={incidents.find(i => i.id === s.id)} />)}
        </section>
      )}

      {/* 3. The four questions */}
      <section aria-labelledby="dbf-q" className="space-y-3">
        <h3 id="dbf-q" className="text-xl font-bold text-white">Debrief together</h3>
        <ol className="space-y-3">
          {debriefSteps(h).map(s => (
            <li key={s.n} className="flex gap-4 rounded-lg border border-border/60 bg-bg-elevated/40 px-4 py-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-cyber-500/20 font-mono text-lg font-bold text-cyber-300" aria-hidden>{s.n}</span>
              <div>
                <p className="text-xl font-semibold text-white">{s.q}</p>
                <p className={`mt-1 text-lg leading-snug ${s.given ? "text-slate-200" : "italic text-slate-400"}`}>{s.a}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}

const GRADE: Record<string, [string, string]> = {
  caught_well: ["caught well", "border-neon-green/40 bg-neon-green/10 text-neon-green"],
  partial: ["partly caught", "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"],
  noticed: ["noticed only", "border-neon-amber/30 bg-neon-amber/5 text-neon-amber"],
  missed: ["missed", "border-severity-high/50 bg-severity-high/15 text-severity-high"],
  not_reached: ["not reached yet", "border-border text-slate-400"],
};
function StoryCard({ s, inc }: { s: AttackStory; inc?: IncidentReport }) {
  const grade = inc ? GRADE[inc.grade] ?? (inc.detected ? GRADE.partial : GRADE.missed) : null;
  return (
    <article className="rounded-lg border border-border/60 bg-bg-elevated/40 px-5 py-4">
      <div className="flex flex-wrap items-start gap-3">
        <h4 className="min-w-0 flex-1 text-lg font-bold text-white"><bdi>{s.name}</bdi></h4>
        {grade && <span className={`shrink-0 rounded border px-2 py-0.5 text-sm font-bold uppercase ${grade[1]}`}>{grade[0]}</span>}
      </div>
      {s.stages.length > 0 && (
        <ol className="mt-3 flex flex-wrap items-center gap-2" aria-label="Attack stages">
          {s.stages.map((st, i) => (
            <li key={st} className="flex items-center gap-2">
              {i > 0 && <span className="text-slate-500" aria-hidden>→</span>}
              <span className="rounded border border-severity-high/40 bg-severity-high/[0.08] px-2 py-0.5 text-base text-slate-100">{st}</span>
            </li>
          ))}
        </ol>
      )}
      <dl className="mt-3 grid gap-x-6 gap-y-1 text-base sm:grid-cols-2">
        <div><dt className="inline text-slate-400">Patient zero: </dt><dd className="inline font-mono text-white"><bdi>{s.patientZero ?? "unknown"}</bdi></dd></div>
        <div><dt className="inline text-slate-400">Hosts involved: </dt><dd className="inline text-white">{s.hosts.length || "-"}</dd></div>
        <div><dt className="inline text-slate-400">First attack log: </dt><dd className="inline font-mono text-white">{dur(inc?.firstSeenS ?? s.firstSeenS)}</dd></div>
        <div><dt className="inline text-slate-400">Caught at: </dt><dd className="inline font-mono text-white">{inc?.detected && inc.detectS != null ? dur(inc.detectS) : "not caught"}</dd></div>
        {s.isolated.length > 0 && <div className="sm:col-span-2"><dt className="inline text-slate-400">Isolated: </dt><dd className="inline font-mono text-white"><bdi>{s.isolated.join(", ")}</bdi></dd></div>}
      </dl>
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-neon-green">What the team saw ({s.seen.length} of {s.total})</p>
          {s.seen.length ? (
            <ul className="mt-1 space-y-1">
              {s.seen.slice(0, 5).map(l => <li key={l.id} className="text-base text-slate-200"><span className="font-mono text-sm text-slate-400">{dur(l.atS)}</span> {l.who ? <b className="font-semibold text-cyber-200"><bdi>{l.who}</bdi></b> : "Someone"} {l.how}: <bdi className="text-slate-300">{l.label}</bdi></li>)}
              {s.seen.length > 5 && <li className="text-sm text-slate-400">+{s.seen.length - 5} more</li>}
            </ul>
          ) : <p className="mt-1 text-base text-slate-400">Nobody acted on any of its logs.</p>}
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-severity-high">What the team missed ({s.missed.length})</p>
          {s.missed.length ? (
            <ul className="mt-1 space-y-1">
              {s.missed.slice(0, 5).map(l => <li key={l.id} className="text-base text-slate-200"><span className="font-mono text-sm text-slate-400">{dur(l.atS)}</span> <bdi>{l.label}</bdi>{l.host && !l.label.toLowerCase().includes(l.host.toLowerCase()) ? <span className="text-slate-400"> on <bdi className="font-mono">{l.host}</bdi></span> : null}</li>)}
              {s.missed.length > 5 && <li className="text-sm text-slate-400">+{s.missed.length - 5} more</li>}
            </ul>
          ) : <p className="mt-1 text-base text-slate-400">Every log of it was handled.</p>}
        </div>
      </div>
    </article>
  );
}

/**
 * The after-action report. v2+ (and legacy) sessions are scored SERVER-SIDE from the
 * full log with the answer key joined back (audit A1/S4): everyone sees the same
 * numbers, and a non-staff viewer only ever receives their own card (S9). The live
 * room never had the answer key; it is revealed here, after the shift, to rebuild
 * the hot-wash and handoff ladder.
 *
 * Order (review 2026-11): you first (one card per player), then the team headline, the hot-wash,
 * and the detail folded by section. Staff can switch to the debrief mode for a shared screen.
 * The SOC Manager (a trainee) still sees every teammate's card, as before: an owner decision.
 */
/** Quiet retries while another request builds the report (~30 s at 2 s apart). */
export const REPORT_BUILD_RETRIES = 15;

export function TeamReport({ sessionId, events, roster, me }: { sessionId: string; events: Ev[]; roster: RosterMember[]; me: Me }) {
  const [report, setReport] = useState<Report | null>(null);
  const [answers, setAnswers] = useState<AnswerMap>({});
  const [seesAll, setSeesAll] = useState(false);
  // 0087: team training XP awarded per player (server-computed from this report).
  const [xp, setXp] = useState<Record<string, number>>({});
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [showAll, setShowAll] = useState(false);
  const [debrief, setDebrief] = useState(false);
  const debriefBtn = useRef<HTMLButtonElement>(null);
  // QA M5: another viewer's request may be building the report (single-flight):
  // the route answers 503 `building`; retry quietly instead of showing an error.
  const buildingRetries = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    setLoadError(null);
    (async () => {
      try {
        const res = await fetch(`/api/team/sessions/${sessionId}/report`);
        const data = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok && res.status === 503 && data?.building && buildingRetries.current < REPORT_BUILD_RETRIES) {
          buildingRetries.current++;
          retry = setTimeout(() => { if (!cancelled) setAttempt(a => a + 1); }, 2000);
          return;
        }
        if (!res.ok) { setLoadError(data?.error ?? "Couldn't load the report."); return; }
        buildingRetries.current = 0;
        setReport({ team: data.team, perUser: data.perUser, managerReview: data.managerReview ?? null } as Report);
        setAnswers(data.answers ?? {});
        setSeesAll(!!data.seesAll);
        setXp(data.xp && typeof data.xp === "object" ? data.xp : {});
        if (typeof data.myTotalXp === "number") setTotalXp(data.myTotalXp);
      } catch { if (!cancelled) setLoadError("Couldn't load the report. Check your connection."); }
    })();
    return () => { cancelled = true; if (retry) clearTimeout(retry); };
  }, [sessionId, attempt]);

  // Answer key merged onto the local log: for the hot-wash, handoff ladder and debrief only.
  const revealed = useMemo(() => mergeAnswers(events, answers), [events, answers]);
  const nameOf = useMemo(() => (u: string | null) => roster.find(r => r.user_id === u)?.name ?? "someone", [roster]);

  if (loadError) return (
    <Card className="border-severity-high/30">
      <p className="text-sm text-severity-high">{loadError}</p>
      <Button variant="outline" size="sm" className="mt-3" onClick={() => { buildingRetries.current = 0; setAttempt(a => a + 1); }}>Try again</Button>
    </Card>
  );
  if (!report) return <Card><p className="text-sm text-slate-400">Building the shift review…</p></Card>;

  const { team, perUser } = report;
  const managerReview = (report.managerReview ?? null) as ManagerReview | null;
  const mgrGraded = !!managerReview && !managerReview.redacted;
  // The server already limited this to my card unless I'm staff / the Manager. The Manager's
  // own work is graded in the Command Review, so their generic card steps aside for it.
  const visible = mgrGraded ? perUser.filter(u => u.user_id !== managerReview!.managerId) : perUser;

  if (debrief && me.is_staff) {
    return <DebriefView events={revealed} roster={roster} team={team} onExit={() => { setDebrief(false); window.setTimeout(() => debriefBtn.current?.focus(), 0); }} />;
  }

  function exportCsv() {
    const header = ["Name", "Role", "Rubric score %", "Criteria measured", "Logs opened", "Avg dwell (s)", "Dispositions", "Disposition accuracy %", "Dispositions on unopened logs", "Escalations", "Escalation quality", "Acks", "Containment requests", "Containment decisions", "Role actions", "First action (s)", "Contribution", "Reported within SLA", "Reported (SLA judged)", "SLA %", "False negatives", "Walked past", "False alarms", "Hosts isolated", "Isolations correct"];
    const rows = perUser.map(u => [u.name, u.role, u.insufficientEvidence ? "insufficient evidence" : (u.rubricPct ?? ""), u.measuredCells ?? "", u.opened, u.avgDwellS ?? "", u.dispCount, u.dispAcc ?? "", u.dispUnopened ?? "", u.escCount, u.escQuality ?? "", u.acks, u.contReq, u.contDecided, u.roleActions, u.firstActionS ?? "", u.contribution,
      u.slaMet ?? "", u.slaTotal ?? "", u.slaPct ?? "", u.falseNegatives?.length ?? "", u.walkedPast?.length ?? "", u.falseAlarms?.length ?? "", u.isolations?.length ?? "", u.isoCorrect ?? ""]);
    const csv = [header, ...rows].map(r => r.map(csvCell).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const a = document.createElement("a"); a.href = url; a.download = `team-exercise-report-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    URL.revokeObjectURL(url);
  }
  const lcTone = team.loopClosure != null ? (team.loopClosure >= 80 ? "good" as const : team.loopClosure < 50 ? "warn" as const : undefined) : undefined;
  // Per-incident detection (fix round 2026-09-27). A report cached before it existed
  // has no incident fields: fall back to the old yes/no.
  const incidents = team.incidents ?? [];
  const incTotal = team.incidentsTotal ?? 0;
  const incDetected = team.incidentsDetected ?? 0;
  const incValue = incTotal ? `${incDetected}/${incTotal}` : (team.detected ? "Yes" : "No");
  const incTone = incTotal ? (incDetected === incTotal ? "good" as const : "warn" as const) : (team.detected ? "good" as const : "warn" as const);
  // Misses per attack, not per log (Tal, 2026-10-27). A report cached before it keeps the per-log count.
  const perAttack = Array.isArray(team.missedAttacks);
  const missedAttacks = team.missedAttacks ?? [];
  const missLabel = perAttack ? "Attacks missed" : "Attack logs missed";
  const missValue = perAttack ? missedAttacks.length : (team.missedAttackCount ?? 0);
  const fallbackPractice = missedAttacks.find(a => a.practice)?.practice ?? null;

  // ── the "you" cards ──
  const summaries: PlayerSummary[] = [
    ...(mgrGraded ? [summarizeManager(managerReview!, { you: me.id === managerReview!.managerId, xp: xp[managerReview!.managerId], fallbackPractice })] : []),
    ...visible.map(u => summarizePlayer(u, { you: u.user_id === me.id, xp: xp[u.user_id], fallbackPractice })),
  ];
  const mine = summaries.find(s => s.you) ?? null;
  const others = seesAll ? summaries.filter(s => !s.you) : [];

  const groups: { title: string; items: [string, string, ("good" | "warn" | undefined)?][] }[] = [
    { title: "Detection", items: [
      ["Incidents caught", incValue, incTone],
      ["Time to detect", dur(team.incMttdS ?? null)],
      ["Logs", String(team.logs)],
      ["Verdict accuracy", team.dispAcc != null ? `${team.dispAcc}%` : "-"],
    ] },
    { title: "Coordination", items: [
      ["Escalations", String(team.escalations)],
      ["Acknowledged", String(team.acknowledged)],
      ["Escalations answered", team.loopClosure != null ? `${team.loopClosure}%` : "-", lcTone],
      ["Wait for Tier-2", dur(team.handoffLatS ?? null), team.handoffLatS != null && team.handoffLatS > 300 ? "warn" : undefined],
      ["Shared picture", team.contested === 0 ? "aligned" : `${team.contested} contested`, team.contested === 0 ? "good" : "warn"],
    ] },
    { title: "Response", items: [
      ["Containment requests", String(team.containmentReq)],
      ["Contained", String(team.contained), team.contained > 0 ? "good" : undefined],
      ["Isolated", String(team.executed), team.executed > 0 ? "good" : undefined],
      ["Request to isolation", dur(team.mttcS ?? null)],
    ] },
    { title: "Triage", items: [
      ["Attack logs within SLA", team.attackSlaPct != null ? `${team.attackSlaPct}%` : "-", team.attackSlaPct == null ? undefined : team.attackSlaPct >= 80 ? "good" : "warn"],
      ["High/critical triaged", team.highCritCoverage != null ? `${team.highCritTriaged}/${team.highCritTotal}` : "-", team.highCritCoverage == null ? undefined : team.highCritCoverage === 100 ? "good" : "warn"],
      ["Time to triage", dur(team.mtttS)],
      [missLabel, String(missValue), missValue === 0 ? "good" : "warn"],
      ["False negatives", String(team.falseNegativeCount ?? 0), (team.falseNegativeCount ?? 0) === 0 ? "good" : "warn"],
      ["False alarms", String(team.falseAlarmCount ?? 0), (team.falseAlarmCount ?? 0) === 0 ? "good" : "warn"],
      ["Busiest analyst", team.busiestShare != null ? `${team.busiestShare}%${team.busiestName ? ` · ${team.busiestName}` : ""}` : "-", team.busiestShare != null && (team.triagers ?? 0) > 1 && team.busiestShare > 70 ? "warn" : undefined],
    ] },
    { title: "Resolution", items: [
      ["Time to contain", dur(team.incMttrS ?? null)],
      ["Case status", team.caseStatus, team.caseStatus === "closed" || team.caseStatus === "contained" ? "good" : undefined],
      ["Evidence pinned", String(team.evidencePinned)],
    ] },
  ];

  const missTotal = (perAttack ? missedAttacks.length : (team.missedAttackLogs?.length ?? 0)) + (team.falseNegatives?.length ?? 0) + (team.falseAlarms?.length ?? 0);
  const isoTotal = team.isoTotal ?? 0;
  const isoRequests = ((team as { isolationRequests?: IsoRequestItem[] }).isolationRequests ?? []);
  const forensicGraded = team.forensic ? team.forensic.findings.filter(f => f.verdict !== "ungraded") : [];
  const icon = (I: typeof Clock, cls = "text-cyber-300") => <I className={`h-4 w-4 shrink-0 ${cls}`} aria-hidden />;

  return (
    <div className="space-y-5">
      {/* 1. You first */}
      {mine && (
        <section aria-labelledby="rep-you">
          <h2 id="rep-you" className="mb-2 flex items-center gap-2 text-base font-bold text-white">{icon(UserRound)} Your shift</h2>
          <div className="max-w-xl"><SummaryCard s={mine} large /></div>
        </section>
      )}
      {others.length > 0 && (
        <section aria-labelledby="rep-each">
          <h2 id="rep-each" className="mb-2 flex items-center gap-2 text-base font-bold text-white">{icon(Users)} Each player</h2>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{others.map(s => <SummaryCard key={s.userId} s={s} />)}</div>
        </section>
      )}

      {/* 2. The team headline */}
      <Card className={incTone === "good" ? "border-neon-green/30" : "border-neon-amber/30"}>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-base font-bold text-white">Shift review: the team</h2>
          <span className="ml-auto flex flex-wrap gap-2">
            {me.is_staff && <Button ref={debriefBtn} variant="primary" size="sm" onClick={() => setDebrief(true)}><Presentation className="mr-1.5 h-4 w-4" aria-hidden />Debrief mode</Button>}
            {me.is_staff && seesAll && <Button variant="outline" size="sm" onClick={exportCsv}>Export CSV</Button>}
          </span>
        </div>
        <p className="mt-0.5 text-xs text-slate-400">A no-fault learning debrief: surfacing and fixing a mistake scores <b className="text-slate-300">for</b> you, not against. Start with the hot-wash below; the numbers support the conversation.</p>
        <ShiftFacts team={team} />
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Tip label="Incidents caught" shown={incTotal ? "Incidents caught" : "Attack detected"} value={incValue} tone={incTone} />
          <Tip label="Time to detect" shown="Time to detect (median)" value={dur(team.incMttdS ?? null)} />
          <Tip label="Verdict accuracy" value={team.dispAcc != null ? `${team.dispAcc}%` : "-"} />
          <Tip label="Escalations answered" value={team.loopClosure != null ? `${team.loopClosure}%` : "-"} tone={lcTone} />
        </div>
        {/* v3: triage quality as a team: SLA, coverage, speed and blind spots */}
        {team.attackSlaTotal != null && (
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Tip label="Attack logs within SLA" value={team.attackSlaPct != null ? `${team.attackSlaMet}/${team.attackSlaTotal}` : "-"} tone={team.attackSlaPct == null ? undefined : team.attackSlaPct >= 80 ? "good" : "warn"} />
            <Tip label="High/critical triaged" value={team.highCritCoverage != null ? `${team.highCritCoverage}%` : "-"} tone={team.highCritCoverage == null ? undefined : team.highCritCoverage === 100 ? "good" : "warn"} />
            <Tip label="Time to triage" shown="Time to triage (median)" value={dur(team.mtttS)} />
            <Tip label={missLabel} value={String(missValue)} tone={missValue === 0 ? "good" : "warn"} />
          </div>
        )}
        <button type="button" onClick={() => setShowAll(s => !s)} aria-expanded={showAll}
          className="mt-3 rounded text-xs font-semibold text-cyber-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">
          {showAll ? "Hide the full metrics" : "Show all metrics"}
        </button>
        {showAll && (
          <div className="mt-3 space-y-3">
            {groups.map(g => (
              <div key={g.title}>
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{g.title}</p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {g.items.map(([label, value, tone]) => <Tip key={label} label={label} value={value} tone={tone} />)}
                </div>
              </div>
            ))}
            <dl className="grid gap-1 rounded-lg border border-border/50 bg-bg px-3 py-2 text-xs sm:grid-cols-2">
              {Object.entries(LEGEND).map(([k, v]) => (
                <div key={k}><dt className="inline font-semibold text-slate-300">{k}: </dt><dd className="inline text-slate-400">{v}</dd></div>
              ))}
            </dl>
          </div>
        )}
      </Card>

      {/* 3. The hot-wash: the debrief conversation, reconstructed from the log (U2) */}
      <HotWash events={revealed} nameOf={nameOf} server={(team as { hotWash?: ServerHotWash }).hotWash ?? null} />

      {/* 4. The detail, folded by section */}
      <section aria-labelledby="rep-detail" className="space-y-3">
        <h2 id="rep-detail" className="text-base font-bold text-white">The detail</h2>

        {/* The SOC Manager: Command Review (decision quality, stakeholders, reporting) */}
        {managerReview && (
          <Fold title="Command Review" icon={icon(Gavel, "text-neon-purple")} defaultOpen={mgrGraded && me.id === managerReview.managerId}
            status={mgrGraded && managerReview.score != null ? `${managerReview.score}/100` : "the command timeline"}>
            <CommandReview review={managerReview} xp={managerReview.redacted ? undefined : xp[managerReview.managerId]} bare />
          </Fold>
        )}

        {/* Per-incident detection: was each real incident caught? (fix round 2026-09-27, P0-1) */}
        {incidents.length > 0 && (
          <Fold title="Incidents: did we catch each one?" icon={icon(ShieldAlert)} status={`${incDetected}/${incTotal} caught`} tone={incDetected === incTotal ? "good" : "warn"}>
            <p className="text-xs text-slate-400">An incident is built from several logs, so a catch is <b className="text-slate-300">graded</b>, not yes/no: detection, timeliness against the SLA, how much of the incident you surfaced (scope), and verdict quality.</p>
            {/* The incident clock (Tal, 2026-10-26): time to detect, time to contain and the 15-minute escalation SLA */}
            {team.incSlaJudged != null && (
              <div className="mt-2 grid grid-cols-3 gap-2">
                <Tip label="Time to detect" shown="Time to detect (median)" value={dur(team.incMttdS)} />
                <Tip label="Time to contain" shown="Time to contain (median)" value={dur(team.incMttrS)} />
                <Tip label="Escalation SLA" shown={`Escalated within ${team.escalationSlaMin ?? 15} min`} value={team.incSlaJudged ? `${team.incSlaMet}/${team.incSlaJudged}` : "-"} tone={!team.incSlaJudged ? undefined : team.incSlaMet === team.incSlaJudged ? "good" : "warn"} />
              </div>
            )}
            {typeof team.incidentsCaughtWell === "number" && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] font-bold uppercase">
                <span className="rounded border border-neon-green/40 bg-neon-green/10 px-1.5 py-0.5 text-neon-green">{team.incidentsCaughtWell} caught well</span>
                <span className="rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-neon-amber">{team.incidentsPartial ?? 0} partial</span>
                <span className="rounded border border-neon-amber/25 bg-neon-amber/5 px-1.5 py-0.5 text-neon-amber">{team.incidentsNoticed ?? 0} noticed</span>
                <span className="rounded border border-severity-high/50 bg-severity-high/15 px-1.5 py-0.5 text-severity-high">{team.incidentsMissed ?? 0} missed</span>
                {team.avgScopeCoverage != null && <span className="ml-auto font-mono normal-case text-slate-400">avg scope {team.avgScopeCoverage}%</span>}
              </div>
            )}
            <div className="mt-3 space-y-2">
              {incidents.map(inc => {
                const meta = (inc.grade as string) === "not_reached" ? { label: "not reached", cls: "border-border text-slate-400" }
                  : inc.grade === "caught_well" ? { label: "caught well", cls: "border-neon-green/40 bg-neon-green/10 text-neon-green" }
                  : inc.grade === "partial" ? { label: "partial", cls: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" }
                  : inc.grade === "noticed" ? { label: "noticed", cls: "border-neon-amber/25 bg-neon-amber/5 text-neon-amber" }
                  : inc.grade === "missed" ? { label: "missed", cls: "border-severity-high/50 bg-severity-high/15 text-severity-high" }
                  // Fallback for reports cached before grading existed.
                  : { label: !inc.detected ? "missed" : inc.escalated ? "escalated" : "marked only", cls: !inc.detected ? "border-severity-high/50 bg-severity-high/15 text-severity-high" : inc.escalated ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" };
                return (
                  <div key={inc.id} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                    <div className="flex items-start gap-2">
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-semibold text-white"><bdi>{inc.name || inc.label}</bdi></span>
                        {inc.name && <span className="block text-[11px] text-slate-500">first log: <bdi>{inc.label}</bdi></span>}
                      </span>
                      <span className={`shrink-0 rounded border px-1 py-0.5 text-[11px] font-bold uppercase ${meta.cls}`}>{meta.label}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1.5 text-[11px]">
                      <span className="rounded border border-border px-1.5 py-0.5 text-slate-300" title={LEGEND["Time to detect"]}>Time to detect: {inc.detected ? dur(inc.dwellS) : "not detected"}</span>
                      <span className="rounded border border-border px-1.5 py-0.5 text-slate-300" title={LEGEND["Time to contain"]}>Time to contain: {inc.respondS != null ? dur(inc.respondS) : "not contained"}</span>
                      <span title={LEGEND["Escalation SLA"]} className={`rounded border px-1.5 py-0.5 ${inc.slaMet === true ? "border-neon-green/40 text-neon-green" : inc.slaMet === false ? "border-severity-high/50 text-severity-high" : "border-border text-slate-400"}`}>
                        SLA {Math.round((inc.slaSec ?? 900) / 60)} min: {inc.slaMet === true ? "met" : inc.slaMet === false ? "missed" : "not judged"}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      {inc.attackEvents} attack log{inc.attackEvents === 1 ? "" : "s"}
                      {inc.scopeCoverage != null ? ` · scope ${inc.scopeCoverage}%` : ""}
                      {inc.hostCoverage != null ? ` · hosts ${inc.hostCoverage}%` : ""}
                      {inc.techCoverage != null ? ` · techniques ${inc.techCoverage}%` : ""}
                      {inc.firstSeenS != null ? ` · first seen at ${dur(inc.firstSeenS)}` : ""}
                      {inc.detected && inc.detectS != null ? ` · caught at ${dur(inc.detectS)}` : ""}
                      {inc.detected && inc.dwellS != null ? ` (${dur(inc.dwellS)} after it surfaced)` : ""}
                      {inc.contained ? " · contained" : ""}
                    </p>
                  </div>
                );
              })}
            </div>
          </Fold>
        )}

        {/* v3: blind spots: attack logs nobody handled, wrong "benign" calls, false alarms */}
        {missTotal > 0 && (
          <Fold title="What the team missed" icon={icon(EyeOff, "text-severity-high")} tone="bad"
            status={`${missValue} ${perAttack ? "attack" : "attack log"}${missValue === 1 ? "" : "s"} missed · ${team.falseAlarmCount ?? team.falseAlarms?.length ?? 0} false alarm${(team.falseAlarmCount ?? team.falseAlarms?.length ?? 0) === 1 ? "" : "s"}`}>
            {perAttack ? (
              <>
                <p className="text-xs text-slate-400">Measured per attack, not per log: an attack counts as caught once anyone escalated, judged or isolated one of its logs. No blame, just the gaps to walk through together. Time is when the log landed in the feed.</p>
                {missedAttacks.length > 0 && <div className="mt-3"><MissedAttackList items={missedAttacks} /></div>}
                {((team.falseNegatives?.length ?? 0) + (team.falseAlarms?.length ?? 0)) > 0 && (
                  <div className="mt-3 grid gap-3 sm:grid-cols-2">
                    <MissList title="Attacks called benign" items={team.falseNegatives ?? []} tone="high" />
                    <MissList title="False alarms escalated" items={team.falseAlarms ?? []} tone="amber" />
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Reports cached before the per-attack view: the old per-log list. */}
                <p className="text-xs text-slate-400">The logs to walk through together. No blame, just the gaps. Time is when the log landed in the feed.</p>
                <div className="mt-3 grid gap-3 sm:grid-cols-3">
                  <MissList title="Attack logs nobody handled" items={team.missedAttackLogs ?? []} tone="high" />
                  <MissList title="Attacks called benign" items={team.falseNegatives ?? []} tone="high" />
                  <MissList title="False alarms escalated" items={team.falseAlarms ?? []} tone="amber" />
                </div>
                {(team.missedAttackLogs ?? []).some(m => m.detail?.startsWith("its incident was caught")) && (
                  <p className="mt-2 text-[11px] text-slate-500">Some unhandled logs belong to an incident the team still caught through another of its logs.</p>
                )}
              </>
            )}
          </Fold>
        )}

        {/* v4: host isolation: was each isolation the right call? (EDR or Sentinel) */}
        {(isoTotal > 0 || (team.hostsLeftOnline?.length ?? 0) > 0 || isoRequests.length > 0) && (
          <Fold title="Host isolation" icon={icon(MonitorX)} tone={isoTotal > 0 && (team.isoCorrect ?? 0) < isoTotal ? "bad" : undefined}
            status={isoTotal > 0 || isoRequests.length === 0 ? `${team.isoCorrect}/${isoTotal} right calls${team.mttiS != null ? ` · median time to isolate ${dur(team.mttiS)}` : ""}` : `${isoRequests.length} request${isoRequests.length === 1 ? "" : "s"}, ${team.hostsLeftOnline?.length ?? 0} compromised host${(team.hostsLeftOnline?.length ?? 0) === 1 ? "" : "s"} left online`}>
            <p className="text-xs text-slate-400">A host that carried real attack activity was right to isolate. A clean host means a user was cut off for nothing: in a real SOC that is a business outage.</p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <div>{isoTotal > 0 ? <IsolationList items={team.isolations ?? []} nameOf={nameOf} /> : <p className="text-[11px] text-slate-500">No host was isolated during the shift.</p>}</div>
              <HostsLeftOnline items={team.hostsLeftOnline ?? []} />
            </div>
            {isoRequests.length > 0 && <div className="mt-3"><IsolationRequestList items={isoRequests} nameOf={nameOf} /></div>}
          </Fold>
        )}

        {/* Tier-3: forensic work judged against what really happened */}
        {team.forensic && (
          <Fold title="Forensic review (Tier-3)" icon={icon(Microscope)} tone={forensicGraded.some(f => f.verdict === "wrong") ? "bad" : undefined}
            status={forensicGraded.length ? `${forensicGraded.filter(f => f.verdict === "confirmed").length}/${forensicGraded.length} confirmed` : undefined}>
            <ForensicTeamCard forensic={team.forensic} nameOf={nameOf} bare />
          </Fold>
        )}

        {/* Handoff chains: closed-loop coordination made visible (research P0) */}
        {revealed.some(e => e.type === "escalation.requested") && (
          <Fold title="Handoff chains: did the loop close?" icon={icon(ArrowUpRight)} status={`${team.escalations} escalation${team.escalations === 1 ? "" : "s"}${team.loopClosure != null ? ` · ${team.loopClosure}% answered` : ""}${(team as { selfOpened?: number }).selfOpened ? ` · ${(team as { selfOpened?: number }).selfOpened} self-opened` : ""}`}>
            <HandoffLadder events={revealed} nameOf={nameOf} server={(team as { handoffChains?: ServerChain[] }).handoffChains ?? null} />
          </Fold>
        )}

        {/* Shared-picture coherence: contested calls to reconcile (research P2) */}
        {team.contestedList.length > 0 && (
          <Fold title="Contested calls: reconcile the picture" icon={icon(ShieldAlert, "text-neon-amber")} tone="warn" status={`${team.contestedList.length} contested`}>
            <p className="text-xs text-slate-400">Same event, different analysts, opposite verdicts. A split mental model: talk through who was right and why.</p>
            <div className="mt-3 space-y-2">
              {team.contestedList.map((c, i) => (
                <div key={i} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                  <p className="text-xs font-semibold text-slate-200"><bdi>{c.label}</bdi></p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {c.calls.map((call, j) => (
                      <span key={j} className={`rounded border px-1.5 py-0.5 text-[11px] ${call.cls === "attack" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : call.cls === "benign" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-border text-slate-400"}`}><bdi>{nameOf(call.actor)}</bdi>: {call.cls}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Fold>
        )}

        {/* Scripted surprises (MSEL curveballs): each scored against its expected response (research P1) */}
        {team.injects.length > 0 && (
          <Fold title="Surprise events" icon={<span title={LEGEND["Surprise events"]}>{icon(Siren, "text-neon-amber")}</span>} status={`${team.injectsHandled}/${team.injectsScored} handled`}>
            <p className="text-xs text-slate-400" title={LEGEND["Surprise events"]}>Scripted pressure and tickets during the shift (the exercise&apos;s MSEL), and whether the team produced the expected response.</p>
            <div className="mt-3 space-y-2">
              {team.injects.map((inj, i) => {
                // `evaluable` is absent on reports cached before the fix round ⇒ treat as evaluable.
                const notEvaluable = inj.evaluable === false;
                const badge = notEvaluable ? "not evaluable" : !inj.scored ? (inj.decoy ? "decoy" : "FYI") : inj.decoy ? (inj.handled ? "decoy · rejected" : "decoy · chased") : inj.handled ? "handled" : "missed";
                const tone = notEvaluable || !inj.scored ? (inj.decoy && !notEvaluable ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400")
                  : inj.handled ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/50 bg-severity-high/15 text-severity-high";
                return (
                  <div key={i} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                    <div className="flex items-start gap-2">
                      <span className="min-w-0 flex-1 text-xs text-slate-300"><bdi>{inj.text}</bdi></span>
                      <span className={`shrink-0 rounded border px-1 py-0.5 text-[11px] font-bold uppercase ${tone}`}>{badge}</span>
                    </div>
                    {inj.note && <p className="mt-1 text-[11px] text-slate-400">{inj.note}</p>}
                    {inj.decoy && <p className="mt-1 text-[11px] text-cyber-300">Decoy: did the team correctly reject it, or chase a false lead?</p>}
                    {inj.expected && <p className="mt-1 text-[11px] text-slate-500"><span className="text-slate-400">Expected:</span> {inj.expected}{inj.objective && inj.objective !== "—" && inj.objective !== "-" ? ` · ${inj.objective}` : ""}</p>}
                  </div>
                );
              })}
            </div>
          </Fold>
        )}

        {/* The full breakdown per player (one score per card: the role score) */}
        {(visible.length > 0 || mgrGraded) && (
          <Fold title={visible.length + (mgrGraded ? 1 : 0) > 1 ? "Full breakdown per player" : "Your full breakdown"} icon={icon(Users)}>
            <div className="grid gap-3 sm:grid-cols-2">
              {/* The SOC Manager sits with the analysts too (Tal, 2026-10-27), scored by the Command Review. */}
              {mgrGraded && <ManagerCard review={managerReview!} xp={xp[managerReview!.managerId]} />}
              {visible.map(u => <PlayerCard key={u.user_id} u={u} xp={xp[u.user_id]} events={events} revealed={revealed} />)}
            </div>
            <p className="mt-3 text-xs text-slate-400">Scores are computed on the server from the full action log. Every criterion is a measured value (a time, a percentage or a count) against a target: at the target it scores 100, then 67, 33 or 0. A criterion with nothing to measure this shift is left out of the score, and a card with fewer than 2 measured criteria shows <b className="text-neon-amber">insufficient evidence</b> instead of a score. &quot;Suspicious&quot; earns partial credit; a verdict on a log you never opened counts at reduced weight. Hover a criterion for how it is measured.</p>
          </Fold>
        )}
      </section>
    </div>
  );
}

function PlayerCard({ u, xp, events, revealed }: { u: UserReport; xp?: number; events: Ev[]; revealed: Ev[] }) {
  const sentinel = useMemo(() => {
    const attack = new Set(revealed.filter(isAttackFeed).map(e => String((e.payload as { id?: unknown }).id)));
    return sentinelActivity(events, u.user_id, attack);
  }, [events, revealed, u.user_id]);
  return (
    <Card>
      <div className="flex items-center justify-between">
        <p className="text-sm font-bold text-white"><bdi>{u.name}</bdi></p>
        <span className="flex items-center gap-1.5">
          <XpChip xp={xp} />
          <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-slate-400">{ROLE_LABEL[u.role] ?? u.role}</span>
        </span>
      </div>
      {/* G-11: the role rubric is the one score on the card. */}
      {u.insufficientEvidence ? (
        // Fewer than 2 measured criteria: no % (a 100% built on one cell misleads).
        <div className="mt-2 flex items-center gap-2" title={LEGEND["Insufficient evidence"]}>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg" />
          <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-[11px] font-bold uppercase text-neon-amber">insufficient evidence</span>
        </div>
      ) : <ScoreBar score={u.rubricPct} />}
      <p className="mt-1 text-[11px] text-slate-500">
        {u.insufficientEvidence
          ? `only ${u.measuredCells ?? 0} of ${u.rubric.length} criteria could be measured this shift, so no score`
          : `role score${u.measuredCells != null ? ` · ${u.measuredCells}/${u.rubric.length} criteria measured` : ""}`}
      </p>
      {u.rubric.length > 0 && <RubricCells cells={u.rubric} />}
      <div className="mt-3 grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-xs">
        <Line label="Logs opened" value={String(u.opened)} />
        <Line label="Avg read time" value={dur(u.avgDwellS)} />
        <Line label="First action" value={u.firstActionS != null ? `at ${dur(u.firstActionS)}` : "-"} />
        <Line label="Verdicts" value={`${u.dispCount}${u.dispAcc != null ? ` · ${u.dispAcc}% balanced` : ""}${u.dispUnopened ? ` · ${u.dispUnopened} unread` : ""}`} />
        {(u.attackHandling != null || u.benignAcc != null) && (
          <Line label="Attack / benign" value={`${u.attackHandling != null ? `${u.attackHandling}% attacks` : "no attack logs"} · ${u.benignAcc != null ? `${u.benignAcc}% benign` : "no benign logs"}`} />
        )}
        <Line label="Escalations" value={`${u.escCount}${u.escQuality != null ? ` · quality ${u.escQuality}` : ""}`} />
        <Line label="Acknowledged" value={String(u.acks)} />
        <Line label="Containment" value={`${u.contReq} requested · ${u.contDecided} decided`} />
        <Line label="Role actions" value={String(u.roleActions)} />
        {sentinel && <Line label="Sentinel" value={`${sentinel.queriesOk}/${sentinel.queries} queries · ${sentinel.bookmarks} bookmarks · ${sentinel.closed} closed${sentinel.judged ? ` · ${sentinel.judgedRight}/${sentinel.judged} classified right` : ""}`} />}
      </div>
      <ReportedTable items={u.reported ?? []} met={u.slaMet ?? 0} total={u.slaTotal ?? 0} pct={u.slaPct ?? null} />
      {(u.isolations?.length ?? 0) > 0 && (
        <div className="mt-3 border-t border-border/40 pt-2">
          <div className="mb-1.5 flex items-center justify-between">
            <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><MonitorX className="h-3 w-3" aria-hidden /> Hosts you isolated</p>
            <span className={`font-mono text-[11px] font-bold ${u.isoCorrect === u.isolations.length ? "text-neon-green" : "text-severity-high"}`}>{u.isoCorrect}/{u.isolations.length} right calls</span>
          </div>
          <IsolationList items={u.isolations} />
        </div>
      )}
      {u.forensic && <ForensicUserSection f={u.forensic} />}
      {((u.falseNegatives?.length ?? 0) + (u.walkedPast?.length ?? 0) + (u.falseAlarms?.length ?? 0)) > 0 ? (
        <div className="mt-3 space-y-2 border-t border-border/40 pt-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Missed &amp; misjudged</p>
          <MissList title="Attacks you called benign" items={u.falseNegatives ?? []} tone="high" />
          <MissList title="Attacks you opened but left, and nobody else caught them" items={u.walkedPast ?? []} tone="high" />
          <MissList title="Benign logs you escalated or called malicious" items={u.falseAlarms ?? []} tone="amber" />
        </div>
      ) : (u.reported?.length ?? 0) > 0 ? (
        <p className="mt-2 text-[11px] text-neon-green">No missed attacks and no false alarms from this seat.</p>
      ) : null}
    </Card>
  );
}
function Line({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between gap-2 border-b border-border/40 pb-1"><span className="text-slate-400">{label}</span><span className="text-right font-mono text-slate-200">{value}</span></div>;
}
