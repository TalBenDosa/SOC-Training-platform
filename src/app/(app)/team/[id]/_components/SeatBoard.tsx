"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Users } from "lucide-react";
import type { Ev, RosterMember } from "@/lib/team/types";
import { openLoadByUser } from "@/lib/team/projections";
import { ROLE_LABEL } from "./shared";
import { seatActivity, IDLE_MIN } from "./shiftClock";

const SHORT_ROLE: Record<string, string> = { t1: "T1", t2: "T2", t3: "T3", mgr: "Mgr", lead: "Lead", de: "DE", ti: "TI" };
const ago = (now: number, t: number | null) => {
  if (t == null) return "nothing yet";
  const m = Math.floor((now - t) / 60000);
  return m < 1 ? "just now" : `${m} min ago`;
};

/**
 * Who is stuck (2026-11 review: the Manager was silent for 20:35 and the instructor's screen showed a
 * green "online" dot). Instructor: per seat, the last real action, idle minutes (running time, reading
 * a log counts as activity), the open load, and a one-line coach message to that seat.
 */
export function SeatBoard({ events, roster, online, now, startedAt, act, nameOf }: {
  events: Ev[]; roster: RosterMember[]; online: Set<string>; now: number; startedAt: number | null;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; nameOf: (u: string | null) => string;
}) {
  const seats = seatActivity(events, roster, now, startedAt);
  const load = openLoadByUser(events, now);
  const [coachTo, setCoachTo] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState<string | null>(null);
  async function send() {
    if (!coachTo || !text.trim()) return;
    setBusy(true);
    const ok = await act("message.sent", { text: text.trim(), kind: "coach", to: coachTo });
    setBusy(false);
    if (ok) { setSent(`Sent to ${nameOf(coachTo)}.`); setCoachTo(null); setText(""); }
  }
  return (
    <div data-tour="seat-board"><Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" aria-hidden /> Seats</h3>
      <p className="mt-0.5 text-[11px] text-slate-400">Idle means no action and no log opened for {IDLE_MIN} minutes of shift time.</p>
      <table className="mt-2 w-full text-left text-[11px]">
        <thead className="text-slate-400"><tr><th className="py-1 font-semibold">Seat</th><th className="py-1 font-semibold">Last action</th><th className="py-1 font-semibold">Idle</th><th className="py-1 font-semibold">Load</th><th className="py-1"><span className="sr-only">Coach</span></th></tr></thead>
        <tbody>
          {seats.map(s => {
            const isOn = online.has(s.userId);
            const n = load.get(s.userId) ?? 0;
            return (
              <tr key={s.userId} className={`border-t border-border/50 ${s.idle || !isOn ? "bg-neon-amber/[0.06]" : ""}`}>
                <td className="py-1 pr-2">
                  <span className={`mr-1 inline-block h-1.5 w-1.5 rounded-full ${isOn ? "bg-neon-green" : "bg-slate-600"}`} aria-hidden />
                  <span className="sr-only">{isOn ? "online, " : "offline, "}</span>
                  <bdi className="text-slate-200">{s.name}</bdi> <span className="font-mono text-slate-400" title={ROLE_LABEL[s.role] ?? s.role}>{SHORT_ROLE[s.role] ?? s.role}</span>
                </td>
                <td className="py-1 pr-2 text-slate-300">{ago(now, s.lastActionMs)}</td>
                <td className={`py-1 pr-2 font-mono ${s.idle ? "font-bold text-neon-amber" : "text-slate-300"}`}>{s.idleMin == null ? "-" : `${s.idleMin}m`}{s.idle ? " idle" : ""}</td>
                <td className={`py-1 pr-2 font-mono ${n >= 3 ? "text-neon-amber" : "text-slate-300"}`}>{n}</td>
                <td className="py-1 text-right"><Button size="sm" variant="outline" aria-label={`Coach ${s.name}`} onClick={() => { setCoachTo(s.userId); setText(""); setSent(null); }}>Coach</Button></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {coachTo && (
        <div className="mt-2 space-y-1.5 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.05] p-2">
          <label htmlFor="coach-text" className="block text-[11px] text-slate-200">A short nudge for <bdi className="font-semibold">{nameOf(coachTo)}</bdi>. It shows on their screen only, not in the team chat. It is still stored in the session log.</label>
          <input id="coach-text" value={text} onChange={e => setText(e.target.value)} maxLength={400} dir="auto" autoFocus
            onKeyDown={e => { if (e.key === "Enter") void send(); }}
            placeholder="For example: the oldest alert in your queue has waited 12 minutes, take it next"
            className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <div className="flex gap-1.5">
            <Button size="sm" variant="primary" disabled={busy || !text.trim()} onClick={send}>Send to {nameOf(coachTo)}</Button>
            <Button size="sm" variant="outline" onClick={() => setCoachTo(null)}>Cancel</Button>
          </div>
        </div>
      )}
      {sent && <p role="status" className="mt-1.5 text-[11px] text-neon-green">{sent}</p>}
    </Card></div>
  );
}

/** The one-line roster every player sees in the shift bar; idle and offline seats are flagged. */
export function TeamLine({ events, roster, online, now, startedAt, meId }: { events: Ev[]; roster: RosterMember[]; online: Set<string>; now: number; startedAt: number | null; meId: string }) {
  const seats = seatActivity(events, roster, now, startedAt);
  if (!seats.length) return null;
  return (
    <p className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-slate-400" aria-label="Team">
      <span className="font-semibold text-slate-300">Team</span>
      {seats.map(s => {
        const off = !online.has(s.userId);
        const flag = off ? "offline" : s.idle ? `idle ${s.idleMin}m` : "";
        return (
          <span key={s.userId} className={flag ? "text-neon-amber" : ""}>
            <span className="font-mono">{SHORT_ROLE[s.role] ?? s.role}</span> <bdi className={flag ? "" : "text-slate-300"}>{s.userId === meId ? "you" : s.name}</bdi>{flag ? ` (${flag})` : ""}
          </span>
        );
      })}
    </p>
  );
}
