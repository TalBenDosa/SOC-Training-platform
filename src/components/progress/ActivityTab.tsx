"use client";
import { Fragment, useMemo, useState } from "react";
import Link from "next/link";
import { BarChart, Bar as RBar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from "recharts";
import { ChevronDown, ChevronRight, Activity as ActivityIcon, CalendarRange } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import type { ActivityKind, ProgressPayload, TimelineItem } from "@/lib/progress/selfView";
import { dayLabel, fmtDate, fmtMinutes, scoreTone } from "./format";
import { EmptyState, SectionTitle } from "./ui";

const KINDS: { kind: ActivityKind; label: string; color: string }[] = [
  { kind: "room", label: "Rooms", color: "#22c9f7" },
  { kind: "quiz", label: "Quizzes", color: "#a855f7" },
  { kind: "lesson", label: "Lesson checks", color: "#818cf8" },
  { kind: "scenario", label: "Scenarios", color: "#f59e0b" },
  { kind: "shift", label: "Live shifts", color: "#22c55e" },
  { kind: "team", label: "Team", color: "#f472b6" },
  { kind: "edr", label: "EDR cases", color: "#94a3b8" },
];
const KIND_LABEL: Record<ActivityKind, string> = { room: "Room", quiz: "Quiz", lesson: "Lesson", scenario: "Scenario", shift: "Live feed", team: "Team", edr: "EDR" };

export function ActivityTab({ data }: { data: ProgressPayload["activity"] }) {
  const [filter, setFilter] = useState<ActivityKind | "all">("all");
  const [open, setOpen] = useState<string | null>(null);
  const chart = data.weeks.map(w => ({ week: fmtDate(w.start), minutes: w.minutes, ...w.counts }));
  const used = KINDS.filter(k => data.weeks.some(w => w.counts[k.kind] > 0));
  const items = useMemo(() => data.timeline.filter(t => filter === "all" || t.kind === filter), [data.timeline, filter]);
  const groups = useMemo(() => {
    const out: { day: string; items: TimelineItem[] }[] = [];
    for (const it of items.slice(0, 120)) {
      const day = dayLabel(it.at);
      const last = out[out.length - 1];
      if (last && last.day === day) last.items.push(it); else out.push({ day, items: [it] });
    }
    return out;
  }, [items]);
  const max = Math.max(1, ...data.days.map(d => d.count));

  if (data.totals.items === 0 && data.timeline.length === 0) {
    return <EmptyState title="No activity yet" body="Complete a room, a quiz or a scenario, or run a live shift, and everything you do will be listed here by day." action={<Link className="text-xs font-semibold text-cyber-300" href="/rooms">Browse rooms →</Link>} />;
  }

  return (
    <div className="space-y-4">
      <Card>
        <SectionTitle icon={<ActivityIcon aria-hidden="true" className="h-4 w-4 text-cyber-300" />}
          right={<span className="text-[11px] text-slate-400">{fmtMinutes(data.totals.minutes)} active in total</span>}
          info="Completed items per week by type. Active time adds question decision times (capped at 5 minutes each), scenario time, live shifts, team exercises and EDR cases.">
          Weekly volume (8 weeks)
        </SectionTitle>
        <div className="mt-3 h-52" role="img"
          aria-label={`Completed items per week: ${data.weeks.map(w => `${fmtDate(w.start)} ${Object.values(w.counts).reduce((s, x) => s + x, 0)} items, ${w.minutes} minutes`).join("; ")}.`}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chart} margin={{ left: -20, right: 4, top: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" vertical={false} />
              <XAxis dataKey="week" tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0d1520", border: "1px solid #1e2a38", borderRadius: 6, fontSize: 12 }} labelStyle={{ color: "#94a3b8" }} />
              {used.map(k => <RBar key={k.kind} dataKey={k.kind} name={k.label} stackId="a" fill={k.color} />)}
            </BarChart>
          </ResponsiveContainer>
        </div>
        <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1" aria-hidden="true">
          {used.map(k => <li key={k.kind} className="flex items-center gap-1.5 text-[11px] text-slate-400"><span className="h-2 w-2 rounded-sm" style={{ background: k.color }} />{k.label}</li>)}
        </ul>
      </Card>

      <Card>
        <SectionTitle icon={<CalendarRange aria-hidden="true" className="h-4 w-4 text-neon-green" />}
          info="One square per day for the last 12 weeks. Darker means more completed items and answered questions that day.">
          Consistency
        </SectionTitle>
        <div className="mt-3 overflow-x-auto">
          <div className="grid w-max grid-flow-col grid-rows-7 gap-1" role="img"
            aria-label={`Active on ${data.days.filter(d => d.count > 0).length} of the last ${data.days.length} days.`}>
            {data.days.map(d => (
              <span key={d.date} title={`${d.date}: ${d.count}`}
                className="h-3.5 w-3.5 rounded-sm border border-border/60"
                style={{ background: d.count === 0 ? "transparent" : `rgba(34, 201, 247, ${0.25 + 0.75 * (d.count / max)})` }} />
            ))}
          </div>
        </div>
        <p className="mt-2 text-[11px] text-slate-400">Active on {data.days.filter(d => d.count > 0).length} of the last {data.days.length} days.</p>
      </Card>

      <Card padded={false}>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
          <h3 className="text-sm font-semibold text-white">Everything you did</h3>
          <label className="flex items-center gap-2 text-[11px] text-slate-400">
            <span>Show</span>
            <select id="activity-filter" value={filter} onChange={e => setFilter(e.target.value as ActivityKind | "all")}
              className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-slate-200">
              <option value="all">All</option>
              {KINDS.map(k => <option key={k.kind} value={k.kind}>{k.label}</option>)}
            </select>
          </label>
        </div>
        {groups.length === 0 ? (
          <p className="px-4 py-6 text-sm text-slate-400">Nothing of this type yet.</p>
        ) : groups.map(g => (
          <div key={g.day}>
            <p className="bg-bg/60 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-widest text-slate-400">{g.day}</p>
            <ul>
              {g.items.map(it => {
                const key = `${it.kind}|${it.id}|${it.at}`;
                const isOpen = open === key;
                const expandable = !!it.attempts && it.attempts.length > 1;
                return (
                  <Fragment key={key}>
                    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/50 px-4 py-2.5">
                      <span className="w-16 shrink-0 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{KIND_LABEL[it.kind]}</span>
                      <div className="min-w-0 flex-1">
                        {expandable ? (
                          <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : key)} className="flex items-start gap-1 text-left text-sm text-slate-100">
                            {isOpen ? <ChevronDown aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-300" /> : <ChevronRight aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />}
                            <span dir="auto">{it.title}</span>
                          </button>
                        ) : <p className="text-sm text-slate-100" dir="auto">{it.title}</p>}
                        <p className="text-[11px] text-slate-400">
                          {it.result}{it.minutes ? ` · ${fmtMinutes(it.minutes)}` : ""}
                          {it.blind && <span className="ml-1.5 rounded border border-border px-1 text-[10px] text-slate-400">last try submitted in seconds</span>}
                        </p>
                      </div>
                      {it.href && <Link href={it.href} className="shrink-0 text-[11px] font-semibold text-cyber-300 hover:text-cyber-200">Open</Link>}
                    </li>
                    {isOpen && it.attempts && (
                      <li className="border-t border-border/40 bg-bg/50 px-4 py-2">
                        <ul className="space-y-1">
                          {it.attempts.map((a, i) => (
                            <li key={a.at + i} className="flex flex-wrap items-center gap-x-3 text-[12px]">
                              <span className="w-24 text-slate-400">{fmtDate(a.at)}</span>
                              <span className={cn("w-12 font-mono font-bold tabular-nums", scoreTone(a.score))}>{a.score}%</span>
                              <span className="font-mono text-slate-400 tabular-nums">{Math.floor(a.timeS / 60)}:{String(a.timeS % 60).padStart(2, "0")}</span>
                              {a.blind && <span className="text-[11px] text-slate-400">Submitted in {a.timeS}s, not counted in your averages</span>}
                            </li>
                          ))}
                        </ul>
                      </li>
                    )}
                  </Fragment>
                );
              })}
            </ul>
          </div>
        ))}
      </Card>
    </div>
  );
}
