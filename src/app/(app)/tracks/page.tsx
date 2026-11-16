"use client";

import { useMemo } from "react";
import Link from "next/link";
import { ArrowRight, BookOpen, DoorOpen, ClipboardList, Target, Presentation, Clock, Layers } from "lucide-react";
import { Topbar } from "@/components/nav/Topbar";
import { RECOMMENDED_TRACKS } from "@/data/recommendedTracks";
import { useFeatures } from "@/lib/brand/BrandContext";
import { buildTrackView, recommendedTrack, hoursLabel, type TrackView } from "@/lib/tracks/progress";
import { useLearnerRecords } from "@/lib/tracks/useLearnerRecords";
import { LevelChip, ProgressBar, KIND_ICON } from "@/components/tracks/TrackParts";
import { KIND_LABEL } from "@/lib/tracks/resolve";
import { cn } from "@/lib/utils";

/** The four moves every stage repeats, in this order. */
const METHOD = [
  { icon: BookOpen, title: "Learn", text: "A lesson with its slide deck, and a video where there is one." },
  { icon: DoorOpen, title: "Practise", text: "A Learning Room where you work the same topic on real logs." },
  { icon: ClipboardList, title: "Check", text: "A quiz. 70% or more counts as passed." },
  { icon: Target, title: "Investigate", text: "A scenario or a live SOC shift, start to finish, on your own." },
];

function trackStats(v: TrackView) {
  const core = v.stages.flatMap(s => s.core);
  const count = (k: string) => core.filter(s => s.kind === k).length;
  return {
    stages: v.stages.length,
    hours: hoursLabel(v.minutes),
    rooms: count("room"),
    decks: core.filter(s => s.deck).length,
    investigations: count("scenario") + count("shift"),
  };
}

export default function TracksPage() {
  const features = useFeatures();
  const { records, ready } = useLearnerRecords();
  const views = useMemo(
    () => RECOMMENDED_TRACKS.map(t => buildTrackView(t, records, f => features[f])),
    [records, features],
  );
  const rec = ready ? recommendedTrack(views) : null;

  return (
    <div>
      <Topbar title="Recommended Tracks" subtitle="Our recommended route, from your first day to Tier 3" />

      <div className="container mx-auto max-w-[1400px] space-y-8 px-4 py-6 sm:px-6">
        <section className="max-w-3xl space-y-2">
          <h1 className="text-2xl font-bold text-white text-balance">Grow as an analyst one stage at a time</h1>
          <p className="text-[14px] leading-relaxed text-slate-300">
            Each track gathers the lessons, slide decks, videos, rooms, quizzes, scenarios and live shifts for one level
            into a single ordered route. Every stage teaches one area and ends with real investigation work, so you
            practise each skill right after you learn it.
          </p>
        </section>

        {/* Where to go next: the one action that matters most on this page. */}
        {rec && rec.next && (
          <Link
            href={`/tracks/${rec.track.id}`}
            className="group flex flex-col gap-3 rounded-xl border border-cyber-500/40 bg-cyber-500/[0.07] p-4 transition-colors hover:border-cyber-400/60 hover:bg-cyber-500/10 sm:flex-row sm:items-center"
          >
            <div className="min-w-0 flex-1">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyber-300">
                {rec.started ? "Continue where you left off" : "Recommended start"}
              </p>
              <p className="mt-1 text-[15px] font-semibold text-white">
                {rec.track.title}: Stage {rec.next.stage.index + 1}, {rec.next.stage.stage.title}
              </p>
              <p className="mt-0.5 truncate text-[13px] text-slate-300">
                Next: {KIND_LABEL[rec.next.step.kind]} · {rec.next.step.title}
              </p>
            </div>
            <span className="inline-flex shrink-0 items-center gap-2 self-start rounded-lg bg-cyber-500 px-4 py-2 text-[13px] font-semibold text-slate-950 sm:self-auto">
              {rec.started ? "Continue" : "Start"} <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
            </span>
          </Link>
        )}

        {/* The ladder: Level 1 → 2 → 3. */}
        <section aria-labelledby="ladder-h" className="space-y-3">
          <h2 id="ladder-h" className="text-sm font-bold uppercase tracking-widest text-slate-300">The three tracks</h2>
          <ol className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            {views.map(v => {
              const s = trackStats(v);
              const isRec = rec?.track.id === v.track.id;
              return (
                <li key={v.track.id} className="min-w-0">
                  <Link
                    href={`/tracks/${v.track.id}`}
                    className={cn(
                      "flex h-full flex-col gap-4 rounded-xl border bg-bg-panel p-5 transition-colors hover:border-cyber-500/50",
                      isRec ? "border-cyber-500/40" : "border-border-strong",
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <LevelChip level={v.track.level} rank={v.track.rank} />
                      {v.complete && <span className="text-[11px] font-semibold text-neon-green">Completed</span>}
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-white">{v.track.title}</h3>
                      <p className="mt-1 text-[13px] font-medium text-cyber-200">Prepares you for: {v.track.role}</p>
                    </div>
                    <p className="text-[13px] leading-relaxed text-slate-300">{v.track.summary}</p>
                    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12px] text-slate-400">
                      <Stat icon={Layers} label="Stages" value={s.stages} />
                      <Stat icon={Clock} label="Core time" value={s.hours} />
                      <Stat icon={Presentation} label="Slide decks" value={s.decks} />
                      <Stat icon={KIND_ICON.room} label="Rooms" value={s.rooms} />
                      <Stat icon={KIND_ICON.scenario} label="Investigations" value={s.investigations} />
                    </dl>
                    <p className="text-[12px] leading-relaxed text-slate-400">
                      <span className="font-semibold text-slate-300">Start here if: </span>{v.track.startHere}
                    </p>
                    <div className="mt-auto space-y-1.5">
                      <div className="flex items-baseline justify-between text-[12px]">
                        <span className="text-slate-400">{ready ? `${v.done} of ${v.total} core steps` : "Loading progress"}</span>
                        <span className="font-semibold tabular-nums text-slate-200">{ready ? `${v.pct}%` : ""}</span>
                      </div>
                      <ProgressBar pct={ready ? v.pct : 0} label={`${v.track.title} progress`} />
                    </div>
                  </Link>
                </li>
              );
            })}
          </ol>
        </section>

        <section aria-labelledby="method-h" className="space-y-3">
          <h2 id="method-h" className="text-sm font-bold uppercase tracking-widest text-slate-300">How every stage works</h2>
          <ol className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {METHOD.map((m, i) => (
              <li key={m.title} className="flex gap-3 rounded-lg border border-border bg-bg-elevated/60 p-4">
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-cyber-500/30 bg-cyber-500/10 text-cyber-300">
                  <m.icon className="h-4 w-4" aria-hidden />
                </span>
                <div>
                  <p className="text-[13px] font-semibold text-white">{i + 1}. {m.title}</p>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-slate-400">{m.text}</p>
                </div>
              </li>
            ))}
          </ol>
          <p className="text-[12px] text-slate-400">
            Each stage also has an optional &quot;Go deeper&quot; list for extra practice on the same topic. It never blocks your progress.
          </p>
        </section>
      </div>
    </div>
  );
}

function Stat({ icon: Icon, label, value }: { icon: typeof Clock; label: string; value: string | number }) {
  return (
    <div className="flex items-center gap-1.5">
      <Icon className="h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden />
      <dt className="sr-only">{label}</dt>
      <dd><span className="font-semibold tabular-nums text-slate-200">{value}</span> {label.toLowerCase()}</dd>
    </div>
  );
}
