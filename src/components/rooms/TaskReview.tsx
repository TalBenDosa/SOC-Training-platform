"use client";
/**
 * Read-only rendering of one Room task for Review mode (feedback FB-001).
 *
 * Nothing here submits, grades, awards XP or touches progress — it only shows
 * the task's content plus whatever was captured when the learner genuinely
 * answered it (src/components/rooms/reviewStore.ts): their answer, the correct
 * answer, the explanation. When nothing was captured on this device (a task
 * finished before this existed, or elsewhere) it says so and shows the XP.
 */
import React from "react";
import { CheckCircle2, Flag, FileText, Info, Lightbulb, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import type {
  SanitizedRoomTask as RoomTask,
  SanitizedReadingTask as ReadingTask,
} from "@/lib/rooms/sanitize";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { ReviewRecord, QuestionReview } from "./reviewStore";
import { ReadingBody, ReadOnlyEventCard, ANALYST_VERDICTS } from "./TaskPlayer";

interface TaskReviewProps {
  task: RoomTask;
  record?: ReviewRecord;
  /** Best XP stored for this task (perTaskXp) and the task's max. */
  earnedXp?: number;
  maxXp: number;
  prevLogEvent?: TelemetryEvent;
}

function XpChip({ earned, max }: { earned?: number; max: number }) {
  if (max <= 0) return null;
  const full = (earned ?? 0) >= max;
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-semibold",
      full ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
    )}>
      {full ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Info className="h-3.5 w-3.5" />}
      {earned ?? 0}/{max} XP earned
    </span>
  );
}

function NoDetails() {
  return (
    <p className="flex items-start gap-2 rounded-lg border border-border/60 bg-bg-elevated/30 px-3 py-2 text-xs text-slate-400">
      <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" />
      Your answer for this task wasn&apos;t saved on this device (it was completed earlier or elsewhere), so only the task is shown.
    </p>
  );
}

function Explanation({ text, tone = "neutral" }: { text?: string; tone?: "good" | "bad" | "neutral" }) {
  if (!text) return null;
  return (
    <div className={cn("rounded-lg border p-3 text-sm",
      tone === "good" ? "border-neon-green/30 bg-neon-green/5"
        : tone === "bad" ? "border-severity-high/30 bg-severity-high/5"
        : "border-cyber-500/20 bg-cyber-500/5",
    )}>
      <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Explanation</p>
      <p className="text-slate-300 leading-relaxed">{text}</p>
    </div>
  );
}

/** Options in AUTHORED order (review isn't scored, so no shuffling needed). */
function ReviewOptions({ options, rev }: { options: readonly string[]; rev?: QuestionReview }) {
  return (
    <div className="space-y-2">
      {options.map((label, i) => {
        const isAnswer = rev?.answer === i;
        const isMine = rev?.selected === i;
        const wrongPick = isMine && !isAnswer && rev?.answer !== null && rev?.answer !== undefined;
        return (
          <div
            key={i}
            className={cn(
              "flex items-start gap-2 rounded-lg border px-4 py-2.5 text-sm",
              isAnswer ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                : wrongPick ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                : "border-border/40 bg-bg-elevated/30 text-slate-400",
            )}
          >
            <span className="font-mono font-bold text-xs opacity-60 mt-0.5">{String.fromCharCode(65 + i)}.</span>
            <span className="flex-1">{label}</span>
            {isMine && <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wide opacity-80">Your answer</span>}
            {isAnswer && !isMine && <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wide opacity-80">Correct</span>}
          </div>
        );
      })}
    </div>
  );
}

function ResultLine({ correct }: { correct: boolean }) {
  return correct ? (
    <p className="inline-flex items-center gap-1.5 text-sm font-semibold text-neon-green"><CheckCircle2 className="h-4 w-4" />You answered correctly</p>
  ) : (
    <p className="inline-flex items-center gap-1.5 text-sm font-semibold text-severity-high"><XCircle className="h-4 w-4" />You missed this one — the correct answer is highlighted</p>
  );
}

function ReadingReview({ task, record }: { task: ReadingTask; record?: ReviewRecord }) {
  const cp = task.checkpoint;
  const rev = record?.type === "reading" ? record.checkpoint : undefined;
  return (
    <div className="space-y-7">
      <ReadingBody task={task} />
      {cp && (
        <div className="rounded-lg border border-cyber-500/25 bg-cyber-500/5 p-4 space-y-3">
          <p className="text-sm font-semibold text-white">Quick check</p>
          <p className="text-sm text-slate-200">{cp.question}</p>
          <ReviewOptions options={cp.options} rev={rev} />
          {rev?.explanation && <p className="text-[11px] text-slate-300 leading-relaxed">{rev.explanation}</p>}
        </div>
      )}
    </div>
  );
}

export function TaskReview({ task, record, earnedXp, maxXp, prevLogEvent }: TaskReviewProps) {
  const header = <XpChip earned={earnedXp} max={maxXp} />;

  switch (task.type) {
    case "reading":
      return <ReadingReview task={task} record={record} />;

    case "question": {
      const rev = record?.type === "question" ? record : undefined;
      return (
        <div className="space-y-5">
          {header}
          <p className="text-slate-200 leading-relaxed text-base">{task.question}</p>
          <ReviewOptions options={task.options} rev={rev} />
          {rev ? <><ResultLine correct={rev.correct} /><Explanation text={rev.explanation} tone={rev.correct ? "good" : "bad"} /></> : <NoDetails />}
        </div>
      );
    }

    case "log_analysis": {
      const rev = record?.type === "log_analysis" ? record : undefined;
      return (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            {header}
          </div>
          <p className="text-sm italic text-slate-400 border-l-2 border-cyber-500/40 pl-3">{task.context}</p>
          <ReadOnlyEventCard event={task.event} />
          {!rev && <NoDetails />}
          <div className="space-y-8">
            {task.questions.map((q, i) => {
              const qr = rev?.questions[i];
              return (
                <div key={i} className="space-y-3">
                  <p className="text-sm font-semibold text-white">
                    <span className="text-slate-400 mr-2">Q{i + 1}.</span>{q.question}
                  </p>
                  <ReviewOptions options={q.options} rev={qr} />
                  {qr && <Explanation text={qr.explanation} tone={qr.correct ? "good" : "bad"} />}
                </div>
              );
            })}
          </div>
        </div>
      );
    }

    case "flag": {
      const rev = record?.type === "flag" ? record : undefined;
      return (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-cyber-300">
              <Flag className="h-5 w-5" /> Flag Challenge
            </span>
            {header}
          </div>
          {prevLogEvent && <ReadOnlyEventCard event={prevLogEvent} />}
          <p className="text-slate-200 leading-relaxed whitespace-pre-line">{task.prompt}</p>
          {task.hint && (
            <p className="flex items-start gap-1.5 rounded border border-neon-amber/30 bg-neon-amber/5 px-3 py-2 text-sm text-neon-amber">
              <Lightbulb className="h-3.5 w-3.5 mt-0.5 shrink-0" />{task.hint}
            </p>
          )}
          {rev ? (
            <div className="rounded-lg border border-neon-green/40 bg-neon-green/10 px-4 py-3 text-sm">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1">Your accepted answer</p>
              <p className="font-mono text-neon-green break-all">{rev.value}</p>
            </div>
          ) : <NoDetails />}
        </div>
      );
    }

    case "analyst_choice": {
      const rev = record?.type === "analyst_choice" ? record : undefined;
      return (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            {header}
          </div>
          <div className="rounded-lg border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
            <p className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1">Scenario</p>
            <p className="text-sm text-slate-300 leading-relaxed">{task.scenario}</p>
          </div>
          <ReadOnlyEventCard event={task.event} />
          <div className="grid grid-cols-2 gap-3">
            {ANALYST_VERDICTS.map(v => {
              const isAnswer = rev?.correctVerdict === v.key;
              const isMine = rev?.selected === v.key;
              return (
                <div key={v.key} className={cn(
                  "rounded-lg border px-4 py-3",
                  isAnswer ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                    : isMine ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                    : "border-border/30 bg-bg-elevated/20 text-slate-400",
                )}>
                  <p className="font-semibold text-sm">{v.label}</p>
                  <p className="text-xs opacity-70 mt-0.5">{v.desc}</p>
                  {(isMine || isAnswer) && (
                    <p className="mt-1 text-[10px] font-semibold uppercase tracking-wide opacity-80">
                      {isMine && isAnswer ? "Your verdict — correct" : isMine ? "Your verdict" : "Correct verdict"}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
          {rev ? (
            <>
              <Explanation text={rev.explanation} tone={rev.correct ? "good" : "bad"} />
              {rev.fpTrap && (
                <div className="border-l-2 border-neon-amber/40 pl-3">
                  <p className="text-[11px] uppercase tracking-wider text-neon-amber font-semibold mb-0.5">Common trap</p>
                  <p className="text-xs text-neon-amber/80">{rev.fpTrap}</p>
                </div>
              )}
            </>
          ) : <NoDetails />}
        </div>
      );
    }

    case "matching": {
      const rev = record?.type === "matching" ? record : undefined;
      return (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            {header}
          </div>
          <p className="text-sm text-slate-400">{task.instructions}</p>
          {rev && rev.solution.length > 0 ? (
            <ul className="space-y-2">
              {rev.solution.map(s => {
                const mine = rev.connections[s.id];
                const ok = rev.perPair.find(p => p.id === s.id)?.correct;
                return (
                  <li key={s.id} className={cn("rounded-lg border px-3 py-2.5 text-sm",
                    ok ? "border-neon-green/40 bg-neon-green/5" : "border-severity-high/40 bg-severity-high/5")}>
                    <span className="text-white font-medium">{s.left}</span>
                    <span className="text-slate-500"> → </span>
                    <span className="text-neon-green">{s.right}</span>
                    {!ok && mine && <span className="block mt-0.5 text-[11px] text-severity-high">You matched: {mine}</span>}
                  </li>
                );
              })}
            </ul>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <ul className="space-y-2">{task.left.map(l => <li key={l.id} className="rounded-lg border border-border/40 bg-bg-elevated/30 px-3 py-2 text-slate-300">{l.text}</li>)}</ul>
                <ul className="space-y-2">{task.right.map(r => <li key={r} className="rounded-lg border border-border/40 bg-bg-elevated/30 px-3 py-2 text-slate-400">{r}</li>)}</ul>
              </div>
              <NoDetails />
            </>
          )}
          {rev && <Explanation text={rev.explanation} tone={rev.correct ? "good" : "neutral"} />}
        </div>
      );
    }

    case "ordering": {
      const rev = record?.type === "ordering" ? record : undefined;
      const textOf = (id: string) => task.items.find(it => it.id === id)?.text ?? id;
      return (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            {header}
          </div>
          <p className="text-sm text-slate-400">{task.instructions}</p>
          {rev && rev.correctOrder.length > 0 ? (
            <ol className="space-y-2">
              {rev.correctOrder.map((id, i) => {
                const ok = rev.perSlot.find(s => s.slot === i)?.correct;
                const mine = rev.placed[i];
                return (
                  <li key={id} className={cn("flex items-start gap-3 rounded-lg border px-3 py-2.5 text-sm",
                    ok ? "border-neon-green/40 bg-neon-green/5" : "border-severity-high/40 bg-severity-high/5")}>
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyber-500/20 text-[11px] font-bold text-cyber-300">{i + 1}</span>
                    <span className="flex-1">
                      <span className="text-white">{textOf(id)}</span>
                      {!ok && mine && <span className="block mt-0.5 text-[11px] text-severity-high">You placed: {textOf(mine)}</span>}
                    </span>
                  </li>
                );
              })}
            </ol>
          ) : (
            <>
              <ul className="space-y-2">{task.items.map(it => <li key={it.id} className="rounded-lg border border-border/40 bg-bg-elevated/30 px-3 py-2 text-sm text-slate-300">{it.text}</li>)}</ul>
              <NoDetails />
            </>
          )}
          {rev && <Explanation text={rev.explanation} tone={rev.correct ? "good" : "neutral"} />}
        </div>
      );
    }

    case "query_fill": {
      const rev = record?.type === "query_fill" ? record : undefined;
      const parts = task.template.split(/\{\{([a-zA-Z0-9_]+)\}\}/g);
      return (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            <span className="rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyber-300">{task.language}</span>
            {header}
          </div>
          <p className="text-sm text-slate-400 leading-relaxed">{task.context}</p>
          <div className="rounded-lg border border-border bg-[#080d14] p-4 font-mono text-sm leading-relaxed text-slate-300 whitespace-pre-wrap">
            {parts.map((seg, i) => {
              if (i % 2 === 0) return <span key={i}>{seg}</span>;
              const b = rev?.blanks[seg];
              const mine = rev?.values[seg];
              const shown = b?.correct ? mine : b?.answers[0] ?? mine;
              return (
                <span key={i} className={cn("mx-0.5 rounded border px-1.5 py-0.5",
                  !rev ? "border-cyber-500/40 text-slate-500" : b?.correct ? "border-neon-green/60 text-neon-green" : "border-neon-amber/60 text-neon-amber")}>
                  {shown || task.blanks.find(x => x.id === seg)?.placeholder || "…"}
                </span>
              );
            })}
          </div>
          {rev && task.blanks.filter(b => rev.blanks[b.id] && !rev.blanks[b.id].correct).map(b => (
            <p key={b.id} className="text-xs text-slate-400">
              <span className="font-mono">{b.placeholder ?? b.id}</span>: you wrote <span className="font-mono text-severity-high">{rev.values[b.id] || "—"}</span>, expected <span className="font-mono text-neon-green">{rev.blanks[b.id].answers[0]}</span>
            </p>
          ))}
          {rev ? <Explanation text={rev.explanation} tone={rev.correct ? "good" : "neutral"} /> : <NoDetails />}
        </div>
      );
    }

    case "written_report": {
      const rev = record?.type === "written_report" ? record : undefined;
      return (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <FileText className="h-5 w-5 text-cyber-300" />
            <h2 className="text-xl font-bold text-white">{task.heading}</h2>
            {header}
          </div>
          <p className="text-sm text-slate-400 leading-relaxed">{task.context}</p>
          <p className="text-sm text-white font-medium">{task.prompt}</p>
          <div className="rounded-lg border border-cyber-500/30 bg-cyber-500/5 p-3 space-y-1">
            <p className="text-xs font-semibold uppercase tracking-wider text-cyber-300">A strong answer will</p>
            <ul className="text-xs text-slate-300 space-y-0.5 list-disc list-inside">
              {task.rubricHints.map((hint, i) => <li key={i}>{hint}</li>)}
            </ul>
          </div>
          {rev ? (
            <>
              <div className="rounded-lg border border-border bg-[#080d14] p-4">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Your report</p>
                <p className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-slate-200">{rev.text}</p>
              </div>
              <p className={cn("text-sm font-semibold", rev.correct ? "text-neon-green" : "text-neon-amber")}>
                {rev.score}/100 · {rev.words} words · cited {rev.iocsCited}/{rev.iocsTotal} of the case&apos;s real indicators
              </p>
              <Explanation text={rev.explanation} />
            </>
          ) : <NoDetails />}
        </div>
      );
    }

    default:
      return null;
  }
}
