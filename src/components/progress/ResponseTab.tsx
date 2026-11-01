"use client";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Legend } from "recharts";
import { Timer, Radio, Users, Gauge } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { ProgressPayload, StatBlock } from "@/lib/progress/selfView";
import { fmtDate, fmtMs } from "./format";
import { EmptyState, SectionTitle, Tile } from "./ui";

const sb = (s: StatBlock) => (s.count ? `median ${fmtMs(s.median)} · p90 ${fmtMs(s.p90)} · ${s.count}` : "No data yet");

export function ResponseTab({ data }: { data: ProgressPayload["response"] }) {
  const empty = data.rooms.count === 0 && data.live.source === "none" && data.scenarios.count === 0 && data.edr.count === 0 && data.team.firstAction.count === 0;
  if (empty) {
    return <EmptyState title="No response times yet" body="Answer room questions, file an incident report in the live feed or finish a scenario, and your times will appear here next to how accurate you were." />;
  }
  const chart = data.weekly.map(w => ({
    week: fmtDate(w.start),
    "Decision time (s)": w.roomMedianMs === null ? null : Math.round(w.roomMedianMs / 1000),
    "Right first try (%)": w.roomAccuracy,
    "Live response (min)": w.liveMedianMs === null ? null : Math.round(w.liveMedianMs / 60_000),
  }));
  const hasTrend = data.weekly.some(w => w.roomMedianMs !== null || w.liveMedianMs !== null);
  return (
    <div className="space-y-4">
      {data.live.source !== "none" && (
        <Card>
          <SectionTitle icon={<Radio aria-hidden="true" className="h-4 w-4 text-neon-green" />}
            info="Wall-clock time from the attack's first log. 'To notice' ends when you first open one of its logs; 'investigating' runs until you open the incident report; 'writing' until you submit it. The clock that pauses during a shift is only a helper inside the shift; these are the times that count.">
            Live feed
          </SectionTitle>
          {data.live.source === "sessions" && <p className="mt-1 text-[11px] text-slate-400">From your shift averages. Per-attack times start with your next shift.</p>}
          <div className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Tile label="To notice" value={fmtMs(data.live.notice.median)} sub={sb(data.live.notice)} />
            <Tile label="Investigating" value={fmtMs(data.live.investigate.median)} sub={sb(data.live.investigate)} />
            <Tile label="Writing the report" value={fmtMs(data.live.write.median)} sub={sb(data.live.write)} />
            <Tile label="Total response" value={fmtMs(data.live.total.median)}
              tone={data.live.total.median !== null && data.live.total.median <= data.live.targetMs ? "text-neon-green" : "text-severity-medium"}
              sub={`${data.live.total.withinTarget ?? "–"}% within ${fmtMs(data.live.targetMs)} · p90 ${fmtMs(data.live.total.p90)}`} />
          </div>
          {data.live.bySeverity.length > 1 && (
            <p className="mt-2 text-[11px] text-slate-400">By severity: {data.live.bySeverity.map(s => `${s.severity} ${fmtMs(s.median)} (${s.count})`).join(" · ")}</p>
          )}
        </Card>
      )}

      {data.rooms.count > 0 && (
        <Card>
          <SectionTitle icon={<Timer aria-hidden="true" className="h-4 w-4 text-cyber-300" />}
            info="Time from a question being shown to your first answer, capped at 5 minutes for a tab left open. Fast or slow is split at your own median for that task type.">
            Rooms: decision time next to accuracy
          </SectionTitle>
          <p className="mt-1 text-[12px] text-slate-400">Median {fmtMs(data.rooms.median)} · p90 {fmtMs(data.rooms.p90)} · {data.rooms.accuracy ?? "–"}% right first try
            {data.rooms.source === "telemetry" && " · per-question times start with your next answers"}</p>
          {data.blindCalls.count > 0 && (
            <p className="mt-2 rounded-md border border-severity-medium/30 bg-severity-medium/5 px-3 py-2 text-[12px] text-slate-200">
              {data.blindCalls.count} answer{data.blindCalls.count === 1 ? "" : "s"} came less than 3 seconds after the question opened, and {data.blindCalls.wrong} of them {data.blindCalls.wrong === 1 ? "was" : "were"} wrong. Read the evidence before answering.
            </p>
          )}
          {data.rooms.byType.length > 0 && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[520px] text-[12px]">
                <thead className="text-left text-[10px] uppercase tracking-widest text-slate-400">
                  <tr><th className="py-1.5 pr-2 font-semibold">Task type</th><th className="py-1.5 pr-2 font-semibold">Median</th><th className="py-1.5 pr-2 font-semibold">Right</th><th className="py-1.5 pr-2 font-semibold">Fast + right</th><th className="py-1.5 pr-2 font-semibold">Fast + wrong</th><th className="py-1.5 pr-2 font-semibold">Slow + right</th><th className="py-1.5 font-semibold">Slow + wrong</th></tr>
                </thead>
                <tbody className="tabular-nums">
                  {data.rooms.byType.map(t => (
                    <tr key={t.type} className="border-t border-border/50">
                      <td className="py-1.5 pr-2 text-slate-200">{t.label} <span className="text-slate-500">({t.count})</span></td>
                      <td className="py-1.5 pr-2 font-mono text-slate-300">{fmtMs(t.median)}</td>
                      <td className="py-1.5 pr-2 font-mono text-slate-300">{t.accuracy ?? "–"}%</td>
                      <td className="py-1.5 pr-2 font-mono text-neon-green">{t.fastRight}</td>
                      <td className="py-1.5 pr-2 font-mono text-severity-high">{t.fastWrong}</td>
                      <td className="py-1.5 pr-2 font-mono text-slate-300">{t.slowRight}</td>
                      <td className="py-1.5 font-mono text-slate-400">{t.slowWrong}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(() => {
                const worst = [...data.rooms.byType].filter(t => t.fastRight + t.fastWrong >= 4).sort((a, b) => b.fastWrong / (b.fastRight + b.fastWrong) - a.fastWrong / (a.fastRight + a.fastWrong))[0];
                if (!worst || worst.fastWrong / (worst.fastRight + worst.fastWrong) < 0.5) return null;
                return <p className="mt-2 text-[12px] text-slate-300">Your fast answers on {worst.label.toLowerCase()} tasks are wrong {Math.round((worst.fastWrong / (worst.fastRight + worst.fastWrong)) * 100)}% of the time. Open the evidence before deciding.</p>;
              })()}
            </div>
          )}
        </Card>
      )}

      {hasTrend && (
        <Card>
          <SectionTitle icon={<Gauge aria-hidden="true" className="h-4 w-4 text-neon-purple" />}
            info="The sign of real progress: decision time going down while the share right on the first try holds or rises.">
            Speed and accuracy by week
          </SectionTitle>
          <div className="mt-3 h-56" role="img" aria-label={`Weekly medians: ${data.weekly.map(w => `${fmtDate(w.start)} decision ${fmtMs(w.roomMedianMs)}, ${w.roomAccuracy ?? "no"} percent right`).join("; ")}.`}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chart} margin={{ left: -16, right: 8, top: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" />
                <XAxis dataKey="week" tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis yAxisId="l" tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis yAxisId="r" orientation="right" domain={[0, 100]} tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0d1520", border: "1px solid #1e2a38", borderRadius: 6, fontSize: 12 }} labelStyle={{ color: "#94a3b8" }} />
                <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8" }} />
                <Line yAxisId="l" type="linear" dataKey="Decision time (s)" stroke="#22c9f7" strokeWidth={2} connectNulls dot={{ r: 2 }} />
                <Line yAxisId="r" type="linear" dataKey="Right first try (%)" stroke="#22c55e" strokeWidth={2} connectNulls dot={{ r: 2 }} />
                <Line yAxisId="l" type="linear" dataKey="Live response (min)" stroke="#f59e0b" strokeWidth={2} connectNulls dot={{ r: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <Tile label="Scenarios" value={fmtMs(data.scenarios.median)} sub={data.scenarios.count ? `median time to finish · ${data.scenarios.count} attempts` : "No scenario attempts yet"}
          info="From starting the scenario to submitting the report. Attempts submitted in seconds are left out." />
        <Tile label="EDR cases" value={fmtMs(data.edr.median)} sub={data.edr.count ? `median to a verdict · ${data.edr.accuracy}% correct` : "No EDR practice cases yet"}
          info="From opening a practice case in the EDR console to your verdict." />
        <Tile label="Team: first action" value={fmtMs(data.team.firstAction.median)}
          sub={data.team.slaTotal ? `SLA met ${data.team.slaMet}/${data.team.slaTotal}` : "No team exercises yet"}
          info="From the start of a team shift to your first action. The SLA counts the logs you triaged or escalated against the target for their severity (critical 1 min, high 3, medium 10)." />
      </div>
      {data.team.bySeverity.length > 0 && (
        <Card>
          <SectionTitle icon={<Users aria-hidden="true" className="h-4 w-4 text-pink-400" />}>Team exercises: response by severity</SectionTitle>
          <ul className="mt-2 grid gap-2 sm:grid-cols-3">
            {data.team.bySeverity.map(s => (
              <li key={s.severity} className="rounded-md border border-border bg-bg px-3 py-2 text-[12px]">
                <p className="capitalize text-slate-200">{s.severity}</p>
                <p className={`font-mono text-lg tabular-nums ${s.median !== null && s.median <= s.target ? "text-neon-green" : "text-severity-medium"}`}>{fmtMs(s.median)}</p>
                <p className="text-[11px] text-slate-400">target {fmtMs(s.target)} · {s.count} logs</p>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
