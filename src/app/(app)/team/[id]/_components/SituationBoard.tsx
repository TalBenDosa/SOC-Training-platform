"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import type { LiveEvent } from "@/app/(app)/dashboard/useLiveEvents";
import { ShieldCheck, ArrowUpRight, ShieldAlert, Siren } from "lucide-react";
import type { RosterMember, Ev } from "@/lib/team/types";
import { sevColor, asStr } from "@/lib/team/format";
import { OVERLOAD_CASES } from "@/lib/team/report/computeReport";
import { ROLE_LABEL, Metric } from "./shared";
import { useServerNow } from "@/lib/team/clock";
import { openLoadByUser, escalationStates, isOpenEscalation } from "@/lib/team/projections";

const MAX_SPAN = 7;
export function SituationBoard({ liveFeed, events, feed, nameOf, roster, online, act }: { liveFeed: LiveEvent[]; events: Ev[]; feed: Ev[]; nameOf: (u: string | null) => string; roster: RosterMember[]; online: Set<string>; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const pulse = useMemo(() => {
    let high = 0, med = 0, low = 0;
    for (const e of liveFeed) { const l = e.ruleLevel ?? 1; if (l >= 7) high++; else if (l >= 4) med++; else low++; }
    return { high, med, low, total: liveFeed.length };
  }, [liveFeed]);
  const bySource = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of liveFeed) { const s = e.source || "other"; m.set(s, (m.get(s) ?? 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [liveFeed]);
  const feedById = useMemo(() => new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.payload as Record<string, unknown>])), [feed]);
  // One row per escalated log (its current round) with the state machine: open →
  // taken (owner) → resolved, or bounced back to Tier-1 — a bounced case is NOT open
  // (Manager playtest: "oldest unacked" warned from T+13 to the end on bounced rows).
  const escStates = useMemo(() => escalationStates(events), [events]);
  const escs = useMemo(() => [...escStates.values()].filter(s => s.rounds > 0).map(s => s.request).sort((a, b) => a.seq - b.seq), [escStates]);
  // B11: command awareness — team presence + per-analyst open load + live MTTA +
  // oldest-unacked, so the Manager commands from state instead of waiting for a request.
  // C5: ages on the server clock (re-rendered every 15s, so "oldest unacked" climbs live).
  const now = useServerNow(15_000);
  const team = useMemo(() => {
    const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");
    const ackEvents = events.filter(e => e.type === "escalation.acknowledged");
    const escTs = new Map(escs.map(e => [String((e.payload as { event_id?: string }).event_id), e.occurred_at ? Date.parse(e.occurred_at) : null]));
    const mttas = ackEvents.map(e => { const id = String((e.payload as { event_id?: string }).event_id); const rt = escTs.get(id); const at = e.occurred_at ? Date.parse(e.occurred_at) : null; return rt != null && at != null ? (at - rt) / 60000 : null; }).filter((x): x is number => x != null && x >= 0);
    const mtta = mttas.length ? Math.round((mttas.reduce((a, b) => a + b, 0) / mttas.length) * 10) / 10 : null;
    // A3: the room's ONE open-work projection — active T1 soft-claims (claimed, not
    // released / dispositioned, not stale) + first-acked unresolved T2/T3 cases. The
    // AAR replays the same rule, so the Manager is scored on what this board showed.
    const loadByUser = openLoadByUser(events, now);
    const stOf = (e: Ev) => escStates.get(String((e.payload as { event_id?: string }).event_id));
    const unacked = escs.filter(e => { const s = stOf(e); return !!s && isOpenEscalation(s); });
    const bounced = escs.filter(e => stOf(e)?.bounced).length;
    const oldestUnacked = unacked.length ? Math.max(...unacked.map(e => e.occurred_at ? Math.max(0, Math.floor((now - Date.parse(e.occurred_at)) / 60000)) : 0)) : null;
    return { players, loadByUser, mtta, oldestUnacked, openCount: unacked.length, bounced, onlineCount: players.filter(p => online.has(p.user_id)).length };
  }, [roster, events, escs, escStates, online, now]);
  // Active mutual-monitoring (Salas): online analysts carrying ≥ OVERLOAD_CASES open
  // cases — the Manager nudges the team to rebalance instead of only watching load.
  const overloaded = useMemo(() => team.players
    .filter(p => online.has(p.user_id) && (team.loadByUser.get(p.user_id) ?? 0) >= OVERLOAD_CASES)
    .map(p => ({ ...p, load: team.loadByUser.get(p.user_id) ?? 0 }))
    .sort((a, b) => b.load - a.load), [team, online]);
  // Targets already nudged (button reflects it; the prompt clears when load drops).
  const nudgedTargets = useMemo(() => new Set(events.filter(e => e.type === "coordination.nudge").map(e => String((e.payload as { target?: string }).target))), [events]);
  const [nudgeBusy, setNudgeBusy] = useState<string | null>(null);
  async function nudge(uid: string, load: number) { setNudgeBusy(uid); await act("coordination.nudge", { target: uid, reason: "overloaded", load }); setNudgeBusy(null); }
  const spanWarn = team.onlineCount > MAX_SPAN; // NIMS/ICS span-of-control guard
  return (
    <div className="space-y-3">
      <Card>
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Situation Board</h2>
        <p className="mt-0.5 text-[11px] text-slate-500">Coordinator view — summaries, not raw logs. Direct your team; don&apos;t dive into the feed.</p>
        {/* B11: team command state */}
        <div className="mt-3 grid grid-cols-3 gap-2">
          <Metric label="Online" value={`${team.onlineCount}/${team.players.length}`} tone={spanWarn ? "warn" : undefined} />
          <Metric label="MTTA" value={team.mtta == null ? "—" : `${team.mtta}m`} tone={team.mtta != null && team.mtta > 5 ? "warn" : undefined} />
          <Metric label="Oldest unacked" value={team.oldestUnacked == null ? "—" : `${team.oldestUnacked}m`} tone={team.oldestUnacked != null && team.oldestUnacked >= 5 ? "warn" : undefined} />
        </div>
        <div className="mt-3">
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Team &amp; load</p>
          <div className="space-y-1">
            {team.players.length === 0 ? <span className="text-[11px] text-slate-600">no analysts assigned</span> : team.players.map(m => { const load = team.loadByUser.get(m.user_id) ?? 0; const on = online.has(m.user_id); return (
              <div key={m.user_id} className="flex items-center gap-2 text-[11px]">
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${on ? "bg-neon-green" : "bg-slate-600"}`} title={on ? "online" : "offline"} />
                <span className="min-w-0 flex-1 truncate text-slate-300">{m.name}</span>
                <span className="shrink-0 font-mono text-[9px] uppercase text-slate-500">{ROLE_LABEL[m.role] ?? m.role}</span>
                <span className={`shrink-0 rounded border px-1 py-0.5 font-mono text-[9px] ${load >= 3 ? "border-neon-amber/50 bg-neon-amber/10 text-neon-amber" : "border-border text-slate-400"}`}>{load} open</span>
              </div>
            ); })}
          </div>
        </div>
        <div className="mt-3 grid grid-cols-4 gap-2">
          <Metric label="Logs" value={String(pulse.total)} />
          <Metric label="High" value={String(pulse.high)} tone={pulse.high > 0 ? "warn" : undefined} />
          <Metric label="Medium" value={String(pulse.med)} />
          <Metric label="Low" value={String(pulse.low)} />
        </div>
        <div className="mt-3">
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Top sources</p>
          <div className="flex flex-wrap gap-1">
            {bySource.length === 0 ? <span className="text-[11px] text-slate-600">—</span> : bySource.map(([s, n]) => (
              <span key={s} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{s} · {n}</span>
            ))}
          </div>
        </div>
        {spanWarn && <p className="mt-3 flex items-center gap-1.5 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-2.5 py-1.5 text-[11px] text-neon-amber"><ShieldAlert className="h-3.5 w-3.5 shrink-0" /> {team.onlineCount} analysts online — beyond a ~7 span of control. Consider splitting coordination or pausing intake.</p>}
      </Card>
      {overloaded.length > 0 && (
        <Card className="border-neon-amber/40">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-neon-amber" /> Rebalance load</h3>
          <p className="mt-0.5 text-[11px] text-slate-500">These analysts are overloaded — nudge the team to pick up the slack.</p>
          <div className="mt-2 space-y-1.5">
            {overloaded.map(m => (
              <div key={m.user_id} className="flex items-center gap-2 rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1.5 text-[11px]">
                <span className="min-w-0 flex-1 truncate text-slate-200">{m.name} <span className="font-mono text-[9px] uppercase text-slate-500">{ROLE_LABEL[m.role] ?? m.role}</span></span>
                <span className="shrink-0 rounded border border-neon-amber/50 bg-neon-amber/10 px-1 py-0.5 font-mono text-[9px] font-bold text-neon-amber">{m.load} open</span>
                <Button variant="outline" size="sm" className="ml-1" disabled={nudgeBusy === m.user_id} onClick={() => nudge(m.user_id, m.load)}>{nudgedTargets.has(m.user_id) ? "Nudge again" : "Nudge"}</Button>
              </div>
            ))}
          </div>
        </Card>
      )}
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-neon-amber" /> Escalation queue ({escs.length})
          <span className="ml-auto font-mono text-[10px] font-normal text-slate-400">{team.openCount} open{team.bounced ? ` · ${team.bounced} bounced` : ""}</span></h3>
        {escs.length === 0 ? <p className="mt-2 text-xs text-slate-500">No escalations from Tier-1 yet.</p> : (
          <div className="mt-2 max-h-[420px] space-y-1.5 overflow-y-auto">
            {escs.slice().reverse().map(e => {
              const p = e.payload as { what?: string; summary?: string; event_id?: string; impact?: string };
              const fe = feedById.get(String(p.event_id)) as { severity?: string; hostname?: string } | undefined;
              const st = escStates.get(String(p.event_id));
              const state = st?.resolved ? "resolved" : st?.bounced ? "bounced" : st?.acked ? "taken" : "open";
              const tone = state === "resolved" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : state === "taken" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : state === "bounced" ? "border-border text-slate-500" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber";
              const mins = e.occurred_at ? Math.max(0, Math.floor((now - Date.parse(e.occurred_at)) / 60000)) : 0;
              return (
                <div key={e.seq} className={`flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1.5 text-xs ${state === "bounced" || state === "resolved" ? "opacity-70" : ""}`}>
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevColor(fe?.severity)}`} />
                  <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.summary) || asStr(p.what) || "escalation"}{fe?.hostname ? ` · ${fe.hostname}` : ""}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500" title="escalated by → owner">{nameOf(e.actor_id)}{st?.owner ? ` → ${nameOf(st.owner)}` : ""}</span>
                  {state === "open" && <span className="shrink-0 font-mono text-[9px] text-slate-500">{mins}m</span>}
                  <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${tone}`} title={state === "bounced" && st?.bounceReason ? st.bounceReason : undefined}>{state}</span>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}
