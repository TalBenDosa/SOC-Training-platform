"use client";
import Link from "next/link";
import { ArrowRight, CalendarDays } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { ProgressPayload } from "@/lib/progress/selfView";
import { delta, fmtMs } from "./format";
import { SectionTitle, Tile } from "./ui";

export function OverviewTab({ data }: { data: ProgressPayload }) {
  const { tiles, sentences, next } = data.overview;
  const period = data.periodDays === 7 ? "this week" : `last ${data.periodDays} days`;
  const respDelta = tiles.response.nowMs !== null && tiles.response.prevMs !== null
    ? `${tiles.response.nowMs <= tiles.response.prevMs ? "faster" : "slower"} than before (${fmtMs(tiles.response.prevMs)})` : null;
  return (
    <div className="space-y-4">
      <Card>
        <SectionTitle icon={<CalendarDays aria-hidden="true" className="h-4 w-4 text-cyber-300" />}
          info="Facts from your own activity in this organisation. Topics need at least 5 answered questions before they are rated.">
          {data.periodDays === 7 ? "This week" : `The last ${data.periodDays} days`}
        </SectionTitle>
        <ul className="mt-3 space-y-1.5 text-sm text-slate-200">
          {sentences.map(s => <li key={s} className="leading-relaxed">{s}</li>)}
        </ul>
      </Card>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label={`Done ${period}`} value={tiles.done.now} sub={delta(tiles.done.now, tiles.done.prev) ?? "Rooms, quizzes, scenarios, shifts"}
          info="Completed rooms, quiz and lesson-check attempts, scenario attempts (not counting ones submitted in seconds), live shifts, team exercises and EDR cases." />
        <Tile label="Right first try" value={tiles.firstTry.now === null ? "–" : `${tiles.firstTry.now}%`}
          sub={tiles.firstTry.items ? `${tiles.firstTry.items} questions${delta(tiles.firstTry.now, tiles.firstTry.prev, " pts") ? ` · ${delta(tiles.firstTry.now, tiles.firstTry.prev, " pts")}` : ""}` : "No questions answered yet"}
          info="Share of questions you answered correctly on your first try. Retries show persistence and are counted separately." />
        <Tile label="Missed attacks" value={tiles.missed.now} tone={tiles.missed.now > 0 ? "text-severity-high" : "text-white"}
          sub={delta(tiles.missed.now, tiles.missed.prev) ?? "Live feed and team exercises"}
          info="Real attacks that ended without a report in the live feed, or that you closed as benign or opened and left in a team exercise." />
        <Tile label={tiles.response.label} value={fmtMs(tiles.response.nowMs)}
          sub={[tiles.response.targetMs ? `target ${fmtMs(tiles.response.targetMs)}` : null, respDelta].filter(Boolean).join(" · ") || "Shown next to accuracy, never instead of it"}
          info={tiles.response.targetMs ? "Live feed: from the attack's first log to your passing incident report. The target is 15 minutes." : "Rooms: time from a question being shown to your answer (capped at 5 minutes for a tab left open)."} />
      </div>

      <Card>
        <SectionTitle icon={<ArrowRight aria-hidden="true" className="h-4 w-4 text-neon-green" />}
          info="Picked from your weakest rated topic first, then the mistakes you can review.">Next step</SectionTitle>
        {next.length === 0 ? (
          <p className="mt-2 text-sm text-slate-400">Complete a room or a quiz and your next steps will appear here.</p>
        ) : (
          <ol className="mt-3 space-y-2">
            {next.map((n, i) => (
              <li key={n.href + i} className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-bg px-3 py-2.5">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-cyber-500/40 font-mono text-[11px] text-cyber-300">{i + 1}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-slate-100">{n.label}</p>
                  <p className="text-[11px] text-slate-400">{n.detail}</p>
                </div>
                <Link href={n.href} className="shrink-0 rounded-md border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 hover:bg-cyber-500/20">
                  {n.href.includes("tab=mistakes") ? "Review" : "Start"}
                </Link>
              </li>
            ))}
          </ol>
        )}
      </Card>
    </div>
  );
}
