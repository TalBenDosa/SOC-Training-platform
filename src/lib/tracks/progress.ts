/**
 * Recommended-track progress: a PURE derivation from the learner's existing records
 * (unit-tested in recommendedTracks.test.ts). Nothing new is graded here.
 *
 *   room      room progress completedAt          (entry without it = started)
 *   quiz      best quiz score >= 70%             (the quiz pass mark; lower = started)
 *   scenario  any scenario run
 *   shift     the company is secured on the live SOC Dashboard
 *   lesson    graded Learning Path lesson completed
 *   read      Lesson Library lesson marked as studied (read to the end, or ticked)
 *
 * A stage is complete when every CORE step this environment offers is done;
 * "go deeper" steps are shown with their status but never count.
 */
import type { RecommendedTrack, TrackStage, TrackStep } from "@/data/recommendedTracks";
import type { FeatureKey } from "@/lib/brand/features";
import { resolveSteps, stepKey, type ResolvedStep } from "./resolve";

export const QUIZ_PASS_PCT = 70;

export type StepStatus = "done" | "started" | "todo";

export interface LearnerRecords {
  rooms: Record<string, { completedAt?: string } | undefined>;
  quizzes: Record<string, { score: number } | undefined>;
  scenarios: ReadonlySet<string>;
  shifts: ReadonlySet<string>;
  lessons: ReadonlySet<string>;
  reads: ReadonlySet<string>;
}

export const EMPTY_RECORDS: LearnerRecords = {
  rooms: {}, quizzes: {}, scenarios: new Set(), shifts: new Set(), lessons: new Set(), reads: new Set(),
};

export function stepStatus(step: TrackStep, rec: LearnerRecords): StepStatus {
  switch (step.kind) {
    case "room": {
      const p = rec.rooms[step.id];
      return p?.completedAt ? "done" : p ? "started" : "todo";
    }
    case "quiz": {
      const q = rec.quizzes[step.id];
      return q ? (q.score >= QUIZ_PASS_PCT ? "done" : "started") : "todo";
    }
    case "scenario": return rec.scenarios.has(step.id) ? "done" : "todo";
    case "shift": return rec.shifts.has(step.id) ? "done" : "todo";
    case "lesson": return rec.lessons.has(step.id) ? "done" : "todo";
    case "read": return rec.reads.has(step.id) ? "done" : "todo";
  }
}

export interface StageView {
  stage: TrackStage;
  index: number;
  core: (ResolvedStep & { status: StepStatus })[];
  deeper: (ResolvedStep & { status: StepStatus })[];
  done: number;
  total: number;
  minutes: number;
  complete: boolean;
}

export interface TrackView {
  track: RecommendedTrack;
  stages: StageView[];
  done: number;
  total: number;
  minutes: number;
  /** 0-100, core steps only. */
  pct: number;
  complete: boolean;
  started: boolean;
  /** The first core step not done, in the first incomplete stage. */
  next: { stage: StageView; step: ResolvedStep & { status: StepStatus } } | null;
}

export function buildTrackView(track: RecommendedTrack, rec: LearnerRecords, hasFeature?: (f: FeatureKey) => boolean): TrackView {
  const withStatus = (steps: TrackStep[] | undefined) =>
    resolveSteps(steps, hasFeature).map(s => ({ ...s, status: stepStatus(s, rec) }));

  const stages: StageView[] = track.stages.map((stage, index) => {
    const core = withStatus(stage.steps);
    const deeper = withStatus(stage.deeper);
    const done = core.filter(s => s.status === "done").length;
    return {
      stage, index, core, deeper, done, total: core.length,
      minutes: core.reduce((m, s) => m + s.minutes, 0),
      complete: core.length > 0 && done === core.length,
    };
  }).filter(s => s.total > 0 || s.deeper.length > 0);

  const done = stages.reduce((n, s) => n + s.done, 0);
  const total = stages.reduce((n, s) => n + s.total, 0);
  const started = stages.some(s => [...s.core, ...s.deeper].some(x => x.status !== "todo"));
  let next: TrackView["next"] = null;
  for (const st of stages) {
    const step = st.core.find(s => s.status !== "done");
    if (step) { next = { stage: st, step }; break; }
  }
  return {
    track, stages, done, total,
    minutes: stages.reduce((m, s) => m + s.minutes, 0),
    pct: total ? Math.round((100 * done) / total) : 0,
    complete: total > 0 && done === total,
    started,
    next,
  };
}

/**
 * The track to recommend: the lowest one not complete, unless the learner has already
 * finished more core steps in a higher track (an experienced analyst working in Level 2
 * is not sent back to Level 1). Opening a room is not enough to move them up: only
 * finished steps count.
 */
export function recommendedTrack(views: TrackView[]): TrackView | null {
  const open = [...views].sort((a, b) => a.track.rank - b.track.rank).filter(v => !v.complete);
  if (!open.length) return null;
  return open.reduce((best, v) => (v.done > best.done ? v : best), open[0]);
}

/** Hours, rounded to the half hour, for "about N hours". */
export function hoursLabel(minutes: number): string {
  const h = Math.max(0.5, Math.round((minutes / 60) * 2) / 2);
  return `${h % 1 === 0 ? h.toFixed(0) : h.toFixed(1)} h`;
}

export { stepKey };
