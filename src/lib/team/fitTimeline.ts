import "server-only";
import { buildTeamTimeline, ORDINARY_PER_ATTACK_ROW } from "./buildTimeline";
import { WORK, withStoryCount, type TeamLoad } from "./load";
import { measureWorkload, type WorkloadPreview } from "./workloadPreview";
import type { VarietyRecord } from "./variety";

/** The Tier-1 load a fitted exercise aims for (the rest of the 80% utilization is the margin). */
export const TIER1_TARGET = 0.9;
const MAX_ROUNDS = 3;

type BuildArgs = Parameters<typeof buildTeamTimeline>;
type Timeline = ReturnType<typeof buildTeamTimeline>;

/** Ordinary telemetry in a built feed: benign pool rows (not the decoys, tickets, MSEL logs or attacks). */
export function ordinaryRows(timeline: Timeline): number {
  return timeline.filter(r => r.channel === "feed").filter(r => {
    const a = (r.answer ?? {}) as { origin?: string; expected_verdict?: string };
    return a.origin === "noise" && a.expected_verdict === "benign";
  }).length;
}

/** The last slot the instructor pinned (1-based; 0 = none): stories up to it are never dropped. */
function lastPinned(slots: BuildArgs[3]): number {
  if (Array.isArray(slots)) return slots.reduce((m: number, id, i) => (id ? i + 1 : m), 0);
  return slots ? 1 : 0;
}

/**
 * Build the exercise, measure the real Tier-1 work, and when it is more than TIER1_TARGET fit it to
 * the team, then build again (Tal, 2026-10-25: the logs at a pace that matches the team's work,
 * availability and size). The load model in load.ts is an estimate; the built timeline also carries
 * ITSM records, MSEL support logs and benign-positive alerts, so the real work is measured, not assumed.
 *
 * Fitting order (Sdema review K1, 2026-11-08: one Tier-1 got a feed that was one ordinary log in
 * fifty, so the feed itself said "attack"):
 *  1. fewer attacks: the standalone pool attacks, then a storyline the instructor did not pin
 *     (a random slot);
 *  2. thinner routine noise, never below ORDINARY_PER_ATTACK_ROW x the attack rows (ordinary
 *     telemetry only; buildTeamTimeline holds the same floor);
 *  3. past that, the load stays over and the lobby says so (a longer shift, fewer storylines, one
 *     more Tier-1): the planned stories and the noise floor are kept.
 */
export function buildFittedTimeline(args: {
  companyId: BuildArgs[0]; difficulty: BuildArgs[1]; seed: BuildArgs[2]; slots: BuildArgs[3];
  load: TeamLoad; stack?: BuildArgs[5]; tenant?: BuildArgs[6]; env?: BuildArgs[7]; opts?: BuildArgs[8];
  roster: { role: string; status?: string }[];
}): { timeline: Timeline; load: TeamLoad; workload: WorkloadPreview; variety: VarietyRecord | null } {
  const first = fitOnce(args, args.seed);
  // 3. An automatic plan (no storyline the admin pinned) whose drawn storyline alone still overloads Tier-1 at the
  //    noise floor: draw another storyline and keep the first that fits, else the lightest. A chosen storyline is
  //    never swapped (a chosen attack always happens).
  const overOf = (w: WorkloadPreview) => (w.tier1.pct ?? 0) > TIER1_TARGET;
  if (!overOf(first.workload) || lastPinned(args.slots) > 0) return first;
  let best = first;
  for (let k = 1; k <= 4; k++) {
    const next = fitOnce(args, `${args.seed}~fit${k}`);
    if ((next.workload.tier1.pct ?? 0) < (best.workload.tier1.pct ?? 0)) best = next;
    if (!overOf(next.workload)) break;
  }
  if (best !== first) args.opts?.onVariety?.(best.variety as VarietyRecord);
  return best;
}

function fitOnce(args: Parameters<typeof buildFittedTimeline>[0], seed: string): { timeline: Timeline; load: TeamLoad; workload: WorkloadPreview; variety: VarietyRecord | null } {
  let load = args.load;
  // What the LAST build drew (variety.ts): the start route stores it for the organization's memory.
  let variety: VarietyRecord | null = null;
  const build = (l: TeamLoad) => buildTeamTimeline(args.companyId, args.difficulty, seed, args.slots, l, args.stack ?? {}, args.tenant ?? null, args.env ?? null,
    { ...(args.opts ?? {}), onVariety: r => { variety = r; } });
  let timeline = build(load);
  let workload = measureWorkload(timeline, load, args.roster);
  const over = () => (workload.tier1.pct ?? 0) > TIER1_TARGET;

  const rebuild = (l: TeamLoad) => { load = l; timeline = build(load); workload = measureWorkload(timeline, load, args.roster); };
  // 1. Fewer attacks: the standalone pool attacks first (load.ts trims them first too), then the
  //    random (unpinned) storylines, never below one storyline.
  while (over() && load.poolAttacks > 0) rebuild({ ...load, poolAttacks: load.poolAttacks - 1 });
  const keep = Math.max(1, lastPinned(args.slots));
  while (over() && load.stories > keep) rebuild({ ...withStoryCount(load, load.stories - 1), poolAttacks: load.poolAttacks });

  // 2. Thinner routine noise, down to the floor.
  for (let round = 0; round < MAX_ROUNDS && over() && load.noiseCount > 0; round++) {
    // Minutes over the target, as routine logs to drop (each one is WORK.READ_SEC_PER_LOG of reading).
    const overMin = ((workload.tier1.pct ?? 0) - TIER1_TARGET) * workload.tier1.capacityMin;
    const floorCut = Math.max(0, ordinaryRows(timeline) - ORDINARY_PER_ATTACK_ROW * workload.attackRows);
    const cut = Math.min(load.noiseCount, floorCut, Math.ceil((overMin * 60) / WORK.READ_SEC_PER_LOG));
    if (cut <= 0) break;
    const rows = Math.max(1, workload.feedRows - cut);
    const meanGap = (load.shiftMin * 60_000 * 0.95) / rows;
    const jitterMs = Math.round(meanGap * 0.25);
    rebuild({ ...load, noiseCount: load.noiseCount - cut, logsPerMin: Math.round((rows / load.shiftMin) * 10) / 10, baseGapMs: Math.round(meanGap - jitterMs / 2), jitterMs });
  }
  return { timeline, load, workload, variety };
}
