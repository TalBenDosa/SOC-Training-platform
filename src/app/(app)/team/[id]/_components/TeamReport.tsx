"use client";
import { useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight, ShieldAlert, Siren, Clock } from "lucide-react";
import type { RosterMember, Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { computeReport } from "@/lib/team/report/computeReport";
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
      const closed = hops.some(h => h.type === "escalation.resolved" || h.type === "containment.executed");
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

export function TeamReport({ events, roster, me }: { events: Ev[]; roster: RosterMember[]; me: Me }) {
  const { team, perUser } = useMemo(() => computeReport(events, roster), [events, roster]);
  // A5: staff AND the SOC Manager (the coordinator who runs the debrief) see the whole
  // team's cards; other players see only their own.
  const seesAll = me.is_staff || me.role === "mgr";
  const visible = seesAll ? perUser : perUser.filter(u => u.user_id === me.id);

  function exportCsv() {
    const header = ["Name", "Role", "Rubric score %", "Logs opened", "Avg dwell (s)", "Dispositions", "Disposition accuracy %", "Escalations", "Escalation quality", "Acks", "Containment requests", "Containment decisions", "Role actions", "First action (s)", "Contribution"];
    const rows = perUser.map(u => [u.name, u.role, u.rubricPct ?? "", u.opened, u.avgDwellS ?? "", u.dispCount, u.dispAcc ?? "", u.escCount, u.escQuality ?? "", u.acks, u.contReq, u.contDecided, u.roleActions, u.firstActionS ?? "", u.contribution].map(String));
    const csv = [header, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const a = document.createElement("a"); a.href = url; a.download = `team-exercise-report-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-5">
      <Card className={team.detected ? "border-neon-green/30" : "border-neon-amber/30"}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white">Shift review</h2>
          {me.is_staff && <Button variant="outline" size="sm" onClick={exportCsv}>Export CSV</Button>}
        </div>
        <p className="mt-0.5 text-[11px] text-slate-400">A no-fault learning debrief — surfacing and fixing a mistake scores <b className="text-slate-300">for</b> you, not against.</p>
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric label="Attack detected" value={team.detected ? "Yes" : "No"} tone={team.detected ? "good" : "warn"} />
          <Metric label="MTTD (detect)" value={team.timeToDetectS != null ? `${team.timeToDetectS}s` : "—"} />
          <Metric label="Logs" value={String(team.logs)} />
          <Metric label="Disposition acc." value={team.dispAcc != null ? `${team.dispAcc}%` : "—"} />
          <Metric label="Escalations" value={String(team.escalations)} />
          <Metric label="Acknowledged" value={String(team.acknowledged)} />
          <Metric label="Handoff loop closure" value={team.loopClosure != null ? `${team.loopClosure}%` : "—"} tone={team.loopClosure != null ? (team.loopClosure >= 80 ? "good" : team.loopClosure < 50 ? "warn" : undefined) : undefined} />
          <Metric label="Shared picture" value={team.contested === 0 ? "aligned" : `${team.contested} contested`} tone={team.contested === 0 ? "good" : "warn"} />
          <Metric label="Containment req." value={String(team.containmentReq)} />
          <Metric label="Contained" value={String(team.contained)} tone={team.contained > 0 ? "good" : undefined} />
          <Metric label="Isolated (exec)" value={String(team.executed)} tone={team.executed > 0 ? "good" : undefined} />
          <Metric label="Handoff latency" value={team.handoffLatS != null ? `${team.handoffLatS}s` : "—"} tone={team.handoffLatS != null && team.handoffLatS > 300 ? "warn" : undefined} />
          <Metric label="MTTC" value={team.mttcS != null ? `${team.mttcS}s` : "—"} />
          <Metric label="MTTR" value={team.mttrS != null ? `${team.mttrS}s` : "—"} />
          <Metric label="Case status" value={team.caseStatus} tone={team.caseStatus === "closed" || team.caseStatus === "contained" ? "good" : undefined} />
          <Metric label="Evidence pinned" value={String(team.evidencePinned)} />
        </div>
      </Card>

      {/* Guided hot-wash — the debrief conversation, reconstructed from the log */}
      <HotWash events={events} nameOf={(u) => roster.find(r => r.user_id === u)?.name ?? "someone"} />

      {/* Handoff chains — closed-loop coordination made visible (research P0) */}
      <HandoffLadder events={events} nameOf={(u) => roster.find(r => r.user_id === u)?.name ?? "someone"} />

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
            {team.injects.map((inj, i) => (
              <div key={i} className="rounded-lg border border-border/50 bg-bg px-2.5 py-2">
                <div className="flex items-start gap-2">
                  <span className="min-w-0 flex-1 text-[11px] text-slate-300">{inj.text}</span>
                  <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${inj.decoy ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : !inj.scored ? "border-border text-slate-500" : inj.handled ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/50 bg-severity-high/15 text-severity-high"}`}>{inj.decoy ? "decoy" : !inj.scored ? "FYI" : inj.handled ? "handled" : "missed"}</span>
                </div>
                {inj.decoy && <p className="mt-1 text-[10px] text-cyber-300/80">Decoy — did the team correctly reject it, or chase a false lead?</p>}
                {inj.expected && <p className="mt-1 text-[10px] text-slate-500"><span className="text-slate-400">Expected:</span> {inj.expected}{inj.objective && inj.objective !== "—" ? ` · ${inj.objective}` : ""}</p>}
              </div>
            ))}
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
            <div className="mt-2 flex items-center gap-2">
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg"><span className="block h-full bg-cyber-500" style={{ width: `${u.rubricPct ?? 0}%` }} /></div>
              <span className="shrink-0 font-mono text-xs font-bold text-cyber-300">{u.rubricPct != null ? `${u.rubricPct}` : "—"}<span className="text-slate-500">/100</span></span>
            </div>
            <p className="mt-1 text-[10px] text-slate-500">role rubric score · contribution {u.contribution}/100</p>
            {u.rubric.length > 0 && (
              <div className="mt-2 space-y-1">
                {u.rubric.map(cell => (
                  <div key={cell.label} className="flex items-center gap-2 text-[11px]">
                    <span className="min-w-0 flex-1 truncate text-slate-400">{cell.label}</span>
                    {cell.score == null
                      ? <span className="shrink-0 rounded border border-border/60 px-1 py-0.5 text-[9px] uppercase text-slate-600">{cell.note ?? "n/a"}</span>
                      : <span className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${cell.score >= 12 ? "bg-neon-green/15 text-neon-green" : cell.score >= 8 ? "bg-cyber-500/15 text-cyber-300" : cell.score >= 4 ? "bg-neon-amber/15 text-neon-amber" : "bg-severity-high/15 text-severity-high"}`}>{cell.score}</span>}
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-xs">
              <Line label="Logs opened" value={String(u.opened)} />
              <Line label="Avg dwell" value={u.avgDwellS != null ? `${u.avgDwellS}s` : "—"} />
              <Line label="First action" value={u.firstActionS != null ? `${u.firstActionS}s` : "—"} />
              <Line label="Dispositions" value={`${u.dispCount}${u.dispAcc != null ? ` · ${u.dispAcc}%` : ""}`} />
              <Line label="Escalations" value={`${u.escCount}${u.escQuality != null ? ` · q${u.escQuality}` : ""}`} />
              <Line label="Acknowledged" value={String(u.acks)} />
              <Line label="Containment" value={`${u.contReq} req · ${u.contDecided} dec`} />
              <Line label="Role actions" value={String(u.roleActions)} />
            </div>
          </Card>
        ))}
      </div>
      <p className="text-xs text-slate-500">Per-user rubric (0/4/8/12 per criterion, §3.f–§9.f) + team report from the action log. Criteria marked n/a await instrumentation (scope.set, SITREP, report grading).</p>
    </div>
  );
}
function Line({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between border-b border-border/40 pb-1"><span className="text-slate-400">{label}</span><span className="font-mono text-slate-200">{value}</span></div>;
}
