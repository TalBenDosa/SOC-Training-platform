"use client";
import { forwardRef } from "react";
import { X } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { useServerNow } from "@/lib/team/clock";
import { fmtClock, shiftClock } from "./shiftClock";

/**
 * The one compact, sticky bar at the top of the running room (2026-11 review: at 1280x720 a stack of
 * banners, the case bar and five tiles pushed the feed below the fold). Row one: connection, shift
 * clock, role, queue counts and the controls. Row two: the team line. Then one line per notice;
 * every toast that used to float over the inputs docks here instead.
 */
export interface BarNotice {
  key: string;
  tone: "info" | "warn" | "good" | "alert";
  /** The notice text (one line on a wide screen). */
  text: React.ReactNode;
  /** Buttons for the notice (Open, Approve, ...). */
  actions?: React.ReactNode;
  onDismiss?: () => void;
  /** role="alert" for what needs an answer now; status otherwise. */
  urgent?: boolean;
}

const TONE: Record<BarNotice["tone"], string> = {
  info: "border-cyber-500/40 bg-cyber-500/[0.07] text-cyber-100",
  warn: "border-neon-amber/50 bg-neon-amber/[0.08] text-neon-amber",
  good: "border-neon-green/40 bg-neon-green/[0.07] text-neon-green",
  alert: "border-severity-high/50 bg-severity-high/[0.08] text-severity-high",
};

export const ShiftBar = forwardRef<HTMLDivElement, {
  top: number;
  status: React.ReactNode;
  clock: React.ReactNode;
  role: React.ReactNode;
  stats?: React.ReactNode;
  controls: React.ReactNode;
  team?: React.ReactNode;
  notices: BarNotice[];
}>(function ShiftBar({ top, status, clock, role, stats, controls, team, notices }, ref) {
  return (
    <div ref={ref} data-tour="status" style={{ top }} className="sticky z-30 -mx-1 space-y-1 rounded-lg border border-border bg-bg-elevated/95 px-2.5 py-1.5 shadow-lg backdrop-blur">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        {status}
        {clock}
        {role}
        {stats}
        <div className="ml-auto flex flex-wrap items-center gap-1.5">{controls}</div>
      </div>
      {team}
      {notices.length > 0 && (
        <ul className="max-h-40 space-y-1 overflow-y-auto" aria-label="Notices">
          {notices.map(n => (
            <li key={n.key} role={n.urgent ? "alert" : "status"} className={`flex flex-wrap items-center gap-x-2 gap-y-1 rounded border px-2 py-1 text-xs ${TONE[n.tone]}`}>
              <span className="min-w-0 flex-1">{n.text}</span>
              {n.actions && <span className="flex shrink-0 flex-wrap items-center gap-1.5">{n.actions}</span>}
              {n.onDismiss && (
                <button type="button" onClick={n.onDismiss} aria-label="Dismiss this notice" className="shrink-0 rounded p-0.5 text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">
                  <X className="h-3.5 w-3.5" aria-hidden />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
});

/**
 * Shift time for every player, from the session log on the server clock: running time (paused time
 * removed) against the planned length. Ticks on its own, so the rest of the room does not re-render.
 */
export function ShiftClockView({ events, startedAt, plannedMs }: { events: Ev[]; startedAt: string | null | undefined; plannedMs: number }) {
  const now = useServerNow(1000);
  const c = shiftClock(events, { startedAt, plannedMs, now });
  if (!c.started) return null;
  const left = Math.ceil(c.remainingMs / 60000);
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs" title="Shift time: paused time is not counted">
      <span className="sr-only">Shift time</span>
      <span className={c.overtime ? "text-neon-amber" : "text-slate-100"}>{fmtClock(c.activeMs)}</span>
      {c.plannedMs > 0 && <span className="text-slate-400">/ {fmtClock(c.plannedMs)}</span>}
      {c.paused ? <span className="rounded border border-neon-amber/40 px-1 text-[11px] text-neon-amber">paused</span>
        : c.plannedMs > 0 && !c.overtime ? <span className="text-[11px] text-slate-400">{left} min left</span>
        : c.overtime ? <span className="text-[11px] text-neon-amber">planned time reached</span> : null}
    </span>
  );
}

/** "Shift ends in 1:42": the scheduled end, counted down on the server clock. */
export function EndCountdown({ endsAt }: { endsAt: number }) {
  const now = useServerNow(1000);
  return <b className="font-mono">{fmtClock(Math.max(0, endsAt - now))}</b>;
}
