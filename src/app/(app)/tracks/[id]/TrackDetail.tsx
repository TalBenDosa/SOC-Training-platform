"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, ChevronDown, Presentation, PlayCircle, CheckCircle2, Clock } from "lucide-react";
import { Topbar } from "@/components/nav/Topbar";
import { SlideDeckViewer } from "@/components/lessons/SlideDeckViewer";
import { findTrack } from "@/data/recommendedTracks";
import { useFeatures } from "@/lib/brand/BrandContext";
import { buildTrackView, hoursLabel, type StageView, type StepStatus } from "@/lib/tracks/progress";
import { KIND_LABEL, type ResolvedStep } from "@/lib/tracks/resolve";
import { useLearnerRecords } from "@/lib/tracks/useLearnerRecords";
import { setReadMark } from "@/lib/tracks/readMarks";
import { LevelChip, ProgressBar, KIND_ICON, StatusIcon, STATUS_TEXT } from "@/components/tracks/TrackParts";
import { cn } from "@/lib/utils";

type Step = ResolvedStep & { status: StepStatus };

export function TrackDetail({ trackId }: { trackId: string }) {
  const track = findTrack(trackId)!;
  const features = useFeatures();
  const { records, ready, userId, orgId } = useLearnerRecords();
  const view = useMemo(() => buildTrackView(track, records, f => features[f]), [track, records, features]);
  const [deck, setDeck] = useState<{ src: string; title: string; pages: number } | null>(null);

  // Open the stage the learner is in; the others start folded. Once the learner
  // toggles a stage themselves, their choice wins over the automatic one.
  const currentStageId = view.next?.stage.stage.id ?? null;
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [touched, setTouched] = useState(false);
  useEffect(() => {
    if (!ready || touched) return;
    setOpen(currentStageId ? { [currentStageId]: true } : {});
  }, [ready, currentStageId, touched]);
  const toggle = (id: string) => { setTouched(true); setOpen(o => ({ ...o, [id]: !o[id] })); };

  const remaining = view.stages.reduce((m, s) => m + s.core.filter(x => x.status !== "done").reduce((a, x) => a + x.minutes, 0), 0);

  return (
    <div>
      <Topbar title="Recommended Tracks" subtitle={track.specialty ? `Specialist track · ${track.title}` : `Level ${track.rank} · ${track.title}`} />

      <div className="container mx-auto max-w-[1200px] space-y-6 px-4 py-6 sm:px-6">
        <Link href="/tracks" className="inline-flex items-center gap-1.5 text-[13px] text-slate-400 hover:text-cyber-300">
          <ArrowLeft className="h-4 w-4" aria-hidden /> All tracks
        </Link>

        {/* ── Track header ── */}
        <section className="grid grid-cols-1 gap-6 rounded-xl border border-border-strong bg-bg-panel p-5 sm:p-6 lg:grid-cols-[1fr_300px]">
          <div className="min-w-0 space-y-3">
            <LevelChip level={track.level} rank={track.rank} specialty={track.specialty} />
            <h1 className="text-2xl font-bold text-white text-balance sm:text-3xl">{track.title}</h1>
            <p className="text-[13px] font-medium text-cyber-200">Prepares you for: {track.role}</p>
            <p className="max-w-3xl text-[14px] leading-relaxed text-slate-300">{track.summary}</p>
            <div>
              <h2 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">By the end of this track you can</h2>
              <ul className="space-y-1.5">
                {track.outcomes.map(o => (
                  <li key={o} className="flex gap-2 text-[13px] leading-relaxed text-slate-200">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyber-400" aria-hidden />
                    <span>{o}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <aside className="flex flex-col gap-3 rounded-lg border border-border bg-bg-elevated/60 p-4 lg:self-start">
            <div className="flex items-baseline justify-between">
              <span className="text-[12px] text-slate-400">Your progress</span>
              <span className="text-2xl font-bold tabular-nums text-white">{ready ? `${view.pct}%` : "..."}</span>
            </div>
            <ProgressBar pct={ready ? view.pct : 0} label={`${track.title} progress`} />
            <p className="text-[12px] text-slate-400">
              {ready ? `${view.done} of ${view.total} core steps done` : "Loading your progress"}
              {ready && !view.complete && <> · about {hoursLabel(remaining)} left</>}
            </p>
            {ready && view.next && (
              <StepLink step={view.next.step} className="mt-1 inline-flex items-center justify-center gap-2 rounded-lg bg-cyber-500 px-4 py-2.5 text-[13px] font-semibold text-slate-950 hover:bg-cyber-400">
                {view.started ? "Continue" : "Start the track"} <ArrowRight className="h-4 w-4" aria-hidden />
              </StepLink>
            )}
            {ready && view.next && (
              <p className="text-[12px] leading-snug text-slate-400">
                Next: <span className="text-slate-200">{KIND_LABEL[view.next.step.kind]} · {view.next.step.title}</span>
              </p>
            )}
            {ready && view.complete && (
              <p className="text-[13px] font-semibold text-neon-green">Track complete. Well done.</p>
            )}
            <p className="border-t border-border pt-3 text-[12px] leading-relaxed text-slate-400">
              <span className="font-semibold text-slate-300">Start here if: </span>{track.startHere}
            </p>
          </aside>
        </section>

        {/* ── Stages ── */}
        <section aria-labelledby="stages-h" className="space-y-3">
          <h2 id="stages-h" className="text-sm font-bold uppercase tracking-widest text-slate-300">Stages</h2>
          <ol className="space-y-3">
            {view.stages.map(st => (
              <StageCard
                key={st.stage.id}
                st={st}
                count={view.stages.length}
                current={st.stage.id === currentStageId}
                open={!!open[st.stage.id]}
                onToggle={() => toggle(st.stage.id)}
                onDeck={setDeck}
                onMark={(id, v) => setReadMark({ userId, orgId }, id, v)}
              />
            ))}
          </ol>
        </section>
      </div>

      {deck && <SlideDeckViewer deck={deck} onClose={() => setDeck(null)} />}
    </div>
  );
}

function StageCard({ st, count, current, open, onToggle, onDeck, onMark }: {
  st: StageView;
  count: number;
  current: boolean;
  open: boolean;
  onToggle: () => void;
  onDeck: (d: { src: string; title: string; pages: number }) => void;
  onMark: (lessonId: string, studied: boolean) => void;
}) {
  const panelId = `stage-${st.stage.id}`;
  const deeperDone = st.deeper.filter(s => s.status === "done").length;
  return (
    <li className={cn("rounded-xl border bg-bg-panel", current ? "border-cyber-500/45" : "border-border-strong")}>
      <h3>
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex w-full items-start gap-4 rounded-xl p-4 text-left sm:p-5"
        >
          <span
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-full border text-[13px] font-bold tabular-nums",
              st.complete ? "border-neon-green/50 bg-neon-green/10 text-neon-green"
                : current ? "border-cyber-400/60 bg-cyber-500/15 text-cyber-200"
                : "border-slate-600 text-slate-400",
            )}
            aria-hidden
          >
            {st.complete ? <CheckCircle2 className="h-5 w-5" /> : st.index + 1}
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Stage {st.index + 1} of {count}</span>
              {current && <span className="rounded-full bg-cyber-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyber-200">You are here</span>}
              {st.complete && <span className="text-[11px] font-semibold text-neon-green">Complete</span>}
            </span>
            <span className="mt-1 block text-[16px] font-semibold text-white">{st.stage.title}</span>
            <span className="mt-1 block text-[13px] leading-relaxed text-slate-300">{st.stage.goal}</span>
            <span className="mt-3 flex items-center gap-3">
              <ProgressBar pct={st.total ? (100 * st.done) / st.total : 0} label={`${st.stage.title} progress`} className="max-w-[240px]" />
              <span className="shrink-0 text-[12px] tabular-nums text-slate-400">{st.done}/{st.total} · {hoursLabel(st.minutes)}</span>
            </span>
          </span>
          <ChevronDown className={cn("mt-1 h-5 w-5 shrink-0 text-slate-400 transition-transform", open && "rotate-180")} aria-hidden />
        </button>
      </h3>

      {open && (
        <div id={panelId} className="space-y-4 border-t border-border px-4 pb-5 pt-4 sm:px-5">
          <div>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">Skills you build</p>
            <ul className="flex flex-wrap gap-1.5">
              {st.stage.skills.map(s => (
                <li key={s} className="rounded-md border border-border bg-bg-elevated/60 px-2 py-1 text-[12px] text-slate-200">{s}</li>
              ))}
            </ul>
          </div>

          <ol className="divide-y divide-border/70 overflow-hidden rounded-lg border border-border">
            {st.core.map((s, i) => <StepRow key={s.key} step={s} n={i + 1} onDeck={onDeck} onMark={onMark} />)}
          </ol>

          {st.deeper.length > 0 && (
            <details className="group rounded-lg border border-dashed border-border">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-[13px] font-semibold text-slate-200">
                <span>Go deeper (optional) · {st.deeper.length} more on this topic{deeperDone ? `, ${deeperDone} done` : ""}</span>
                <ChevronDown className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-180" aria-hidden />
              </summary>
              <ol className="divide-y divide-border/70 border-t border-border">
                {st.deeper.map(s => <StepRow key={s.key} step={s} onDeck={onDeck} onMark={onMark} />)}
              </ol>
            </details>
          )}
        </div>
      )}
    </li>
  );
}

function StepRow({ step, n, onDeck, onMark }: {
  step: Step;
  n?: number;
  onDeck: (d: { src: string; title: string; pages: number }) => void;
  onMark: (lessonId: string, studied: boolean) => void;
}) {
  const Icon = KIND_ICON[step.kind];
  const done = step.status === "done";
  return (
    <li className={cn("flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center", done && "bg-neon-green/[0.03]")}>
      <div className="flex min-w-0 flex-1 items-start gap-3">
        {step.kind === "read" ? (
          // Library lessons have no server record: the learner ticks them (reading to the end ticks it too).
          <button
            type="button"
            onClick={() => onMark(step.id, !done)}
            aria-pressed={done}
            aria-label={done ? `Studied: ${step.title}. Select to unmark` : `Mark as studied: ${step.title}`}
            title={done ? "Studied. Select to unmark" : "Mark as studied"}
            className="mt-0.5 shrink-0 rounded-full focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
          >
            <StatusIcon status={step.status} />
          </button>
        ) : (
          <span className="mt-0.5 shrink-0" title={STATUS_TEXT[step.status]}>
            <StatusIcon status={step.status} />
            <span className="sr-only">{STATUS_TEXT[step.status]}</span>
          </span>
        )}
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            {n !== undefined && <span className="tabular-nums text-slate-500">{n}.</span>}
            <Icon className="h-3.5 w-3.5" aria-hidden />
            {KIND_LABEL[step.kind]}
            {step.detail && <span className="font-normal normal-case tracking-normal text-slate-500">· {step.detail}</span>}
          </p>
          <StepLink step={step} className={cn("mt-0.5 block text-[14px] font-medium leading-snug hover:text-cyber-300 hover:underline", done ? "text-slate-300" : "text-white")}>
            {step.title}
          </StepLink>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2 pl-8 sm:pl-0">
        {step.deck && (
          <button
            type="button"
            onClick={() => onDeck({ src: step.deck!.src, title: step.title, pages: step.deck!.pages })}
            className="inline-flex items-center gap-1.5 rounded-md border border-border-strong px-2.5 py-1 text-[12px] text-slate-200 hover:border-cyber-500/50 hover:text-cyber-200"
          >
            <Presentation className="h-3.5 w-3.5" aria-hidden /> Slides
          </button>
        )}
        {step.hasVideo && (
          <span className="inline-flex items-center gap-1 text-[12px] text-slate-400" title="This lesson includes an explainer video">
            <PlayCircle className="h-3.5 w-3.5" aria-hidden /> Video
          </span>
        )}
        <span className="inline-flex items-center gap-1 text-[12px] tabular-nums text-slate-400">
          <Clock className="h-3.5 w-3.5" aria-hidden /> {step.minutes} min
        </span>
      </div>
    </li>
  );
}

/** Links to the step. A live shift opens the dashboard, where the learner picks the company. */
function StepLink({ step, className, children }: {
  step: ResolvedStep;
  className?: string;
  children: React.ReactNode;
}) {
  return <Link href={step.href} className={className}>{children}</Link>;
}
