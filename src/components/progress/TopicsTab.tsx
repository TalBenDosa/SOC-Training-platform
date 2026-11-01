"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowDownRight, ArrowUpRight, Minus, Target, Crosshair } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import type { ProgressPayload, TrendArea } from "@/lib/progress/selfView";
import { LEVEL_STYLE } from "./format";
import { Bar, EmptyState, SectionTitle } from "./ui";

export function TopicsTab({ data }: { data: ProgressPayload["skills"] }) {
  const [open, setOpen] = useState<string | null>(null);
  const any = data.areas.some(a => a.items > 0);
  if (!any) {
    return <EmptyState title="No topics rated yet" body="Each question you answer counts toward one of 12 topics. After 5 questions in a topic you will see how strong you are in it, and where to practise." action={<Link href="/rooms" className="text-xs font-semibold text-cyber-300">Start a room →</Link>} />;
  }
  return (
    <div className="space-y-4">
      <Card>
        <SectionTitle icon={<Target aria-hidden="true" className="h-4 w-4 text-neon-purple" />}
          info="Right on the first try, per topic, across rooms, quizzes, lesson checks and scenario questions. Strong is 80% and up, developing 60 to 79%, weak below 60%. Fewer than 5 questions is not enough to judge. The arrow compares the last 30 days with the 30 before.">
          Topics, weakest first
        </SectionTitle>
        <p className="mt-1 text-[12px] text-slate-400">
          Overall {data.firstTry.accuracy ?? "–"}% right first try ({data.firstTry.firstTryCorrect}/{data.firstTry.items})
          {data.persistence.solvedAfterRetry > 0 && ` · ${data.persistence.solvedAfterRetry} solved after a retry${data.persistence.avgTriesToSolve ? `, ${data.persistence.avgTriesToSolve} tries on average` : ""}`}
        </p>
        <ul className="mt-3 divide-y divide-border/60">
          {data.areas.map(a => <AreaRow key={a.area} a={a} open={open === a.area} onToggle={() => setOpen(open === a.area ? null : a.area)} />)}
        </ul>
      </Card>

      {data.tactics.length > 0 && (
        <Card>
          <SectionTitle icon={<Crosshair aria-hidden="true" className="h-4 w-4 text-cyber-300" />}
            info="Room questions whose event carries a MITRE ATT&CK technique, grouped by the technique's tactic (ATT&CK v19).">
            By MITRE ATT&CK tactic
          </SectionTitle>
          <ul className="mt-3 grid gap-2 sm:grid-cols-2">
            {data.tactics.map(t => (
              <li key={t.tactic} className="rounded-md border border-border bg-bg px-3 py-2">
                <div className="flex items-baseline justify-between gap-2 text-[12px]">
                  <span className="text-slate-200">{t.tactic}</span>
                  <span className="font-mono tabular-nums text-slate-300">{t.firstTryCorrect}/{t.items}</span>
                </div>
                <div className="mt-1.5"><Bar value={t.accuracy} cls={t.accuracy >= 80 ? "bg-neon-green" : t.accuracy >= 60 ? "bg-severity-medium" : "bg-severity-critical"} label={`${t.tactic}: ${t.accuracy}% right first try`} /></div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function AreaRow({ a, open, onToggle }: { a: TrendArea; open: boolean; onToggle: () => void }) {
  const st = LEVEL_STYLE[a.level];
  const t = a.trend;
  const sources = Object.entries(a.sources).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k === "room" ? "room" : k === "quiz" ? "quiz" : k === "lesson" ? "lesson" : "scenario"} question${n === 1 ? "" : "s"}`);
  return (
    <li className="py-2.5">
      <button type="button" aria-expanded={open} onClick={onToggle} className="w-full text-left">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="min-w-0 flex-1 text-sm text-slate-100">{a.label}</span>
          {t && (
            <span className={cn("inline-flex items-center gap-0.5 text-[11px]", t.now > t.prev ? "text-neon-green" : t.now < t.prev ? "text-severity-high" : "text-slate-400")}>
              {t.now > t.prev ? <ArrowUpRight aria-hidden="true" className="h-3.5 w-3.5" /> : t.now < t.prev ? <ArrowDownRight aria-hidden="true" className="h-3.5 w-3.5" /> : <Minus aria-hidden="true" className="h-3.5 w-3.5" />}
              <span>{t.prev}% → {t.now}%</span>
            </span>
          )}
          <span className={cn("rounded border px-1.5 py-0.5 text-[10px] font-semibold", st.cls)}>{st.label}</span>
          <span className="w-16 text-right font-mono text-[12px] tabular-nums text-slate-200">{a.accuracy === null ? "–" : `${a.accuracy}%`}</span>
        </div>
        <div className="mt-1.5"><Bar value={a.accuracy} cls={st.bar} label={`${a.label}: ${a.accuracy ?? 0}% right first try over ${a.items} questions`} /></div>
        <p className="mt-1 text-[11px] text-slate-400">{a.items} question{a.items === 1 ? "" : "s"}{a.items > 0 && a.items < 5 ? `, ${5 - a.items} more to rate this topic` : ""}</p>
      </button>
      {open && (
        <div className="mt-2 rounded-md border border-border bg-bg px-3 py-2.5 text-[12px]">
          <p className="text-slate-300">{sources.length ? `From ${sources.join(", ")}.` : "Nothing answered in this topic yet."}</p>
          <Link href="/progress?tab=mistakes" className="mt-1 inline-block font-semibold text-cyber-300">See your mistakes →</Link>
          {a.practice.length > 0 && (
            <>
              <p className="mt-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">Practise in</p>
              <ul className="mt-1 space-y-1">
                {a.practice.map(p => (
                  <li key={p.kind + p.id} className="flex items-center justify-between gap-2">
                    <span className="text-slate-200">{p.kind === "room" ? "Room" : "Quiz"}: {p.title}</span>
                    <Link href={p.href} className="shrink-0 font-semibold text-cyber-300">Start</Link>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </li>
  );
}
