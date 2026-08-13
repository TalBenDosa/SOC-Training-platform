/**
 * Cohort progress along the graded learning path, for the org-admin dashboard.
 *
 * The graded curriculum (ROOMS_META) is a prerequisite DAG, not a linear list,
 * so there is no single "chapter N". The pragmatic, already-available axis is
 * each room's `difficulty`, which we surface as three path STAGES:
 *
 *   beginner     → Foundations
 *   intermediate → SOC Tier 1
 *   advanced     → Advanced
 *
 * Everything here is pure, client-safe (imports ROOMS_META, never rooms.ts), and
 * driven by each student's `completed_room_ids` — which the existing
 * /api/org/analytics endpoint already returns. No backend change.
 *
 * (Refinement later: a richer tiering off category + prerequisite depth. The
 * stage mapping is the one seam to change if that happens.)
 */
import { ROOMS_META } from "@/data/roomsMeta";

export type PathStage = "Foundations" | "SOC Tier 1" | "Advanced";
export const PATH_STAGES: PathStage[] = ["Foundations", "SOC Tier 1", "Advanced"];

const STAGE_BY_DIFFICULTY: Record<RoomDifficulty, PathStage> = {
  beginner: "Foundations",
  intermediate: "SOC Tier 1",
  advanced: "Advanced",
};
type RoomDifficulty = "beginner" | "intermediate" | "advanced";

/** room id → its stage. Also the set of "real" room ids for filtering stale progress. */
const STAGE_OF_ROOM = new Map<string, PathStage>(
  ROOMS_META.map(r => [r.id, STAGE_BY_DIFFICULTY[r.difficulty as RoomDifficulty] ?? "SOC Tier 1"]),
);

export const TOTAL_ROOMS = ROOMS_META.length;

export const STAGE_ROOM_COUNT: Record<PathStage, number> = PATH_STAGES.reduce((acc, stage) => {
  acc[stage] = ROOMS_META.filter(r => STAGE_OF_ROOM.get(r.id) === stage).length;
  return acc;
}, {} as Record<PathStage, number>);

/** How many of a student's completed rooms fall in a given stage. */
export function completedInStage(completedRoomIds: string[], stage: PathStage): number {
  return completedRoomIds.filter(id => STAGE_OF_ROOM.get(id) === stage).length;
}

/** A student's overall path completion (%) — completed real rooms / total rooms. */
export function studentPathPercent(completedRoomIds: string[] | undefined): number {
  if (TOTAL_ROOMS === 0 || !completedRoomIds) return 0;
  const real = completedRoomIds.filter(id => STAGE_OF_ROOM.has(id)).length;
  return Math.round((real / TOTAL_ROOMS) * 100);
}

export interface CohortStageProgress {
  stage: PathStage;
  /** % of this stage's rooms completed, averaged across the cohort. */
  percent: number;
  roomCount: number;
}

/** Cohort coverage per stage: Σ(students' completed in stage) / (stage rooms × students). */
export function cohortPathProgress(students: { completed_room_ids?: string[] }[]): CohortStageProgress[] {
  const n = students.length;
  return PATH_STAGES.map(stage => {
    const denom = STAGE_ROOM_COUNT[stage] * n;
    const sum = denom === 0 ? 0 : students.reduce((s, st) => s + completedInStage(st.completed_room_ids ?? [], stage), 0);
    return { stage, roomCount: STAGE_ROOM_COUNT[stage], percent: denom === 0 ? 0 : Math.round((sum / denom) * 100) };
  });
}
