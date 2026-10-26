import "server-only";
import { buildTeamTimeline } from "./buildTimeline";
import { WORK, type TeamLoad } from "./load";
import { measureWorkload, type WorkloadPreview } from "./workloadPreview";

/** The Tier-1 load a fitted exercise aims for (the rest of the 80% utilization is the margin). */
export const TIER1_TARGET = 0.9;
const MAX_ROUNDS = 3;

type BuildArgs = Parameters<typeof buildTeamTimeline>;

/**
 * Build the exercise, measure the real Tier-1 work, and when it is more than TIER1_TARGET trim
 * the routine noise (never an attack) and space the feed out to the shift, then build again
 * (Tal, 2026-10-25: the logs at a pace that matches the team's work, availability and size).
 * The load model in load.ts is an estimate; the built timeline also carries ITSM records, MSEL
 * support logs and benign-positive alerts, so the real work is measured, not assumed.
 */
export function buildFittedTimeline(args: {
  companyId: BuildArgs[0]; difficulty: BuildArgs[1]; seed: BuildArgs[2]; slots: BuildArgs[3];
  load: TeamLoad; stack?: BuildArgs[5]; tenant?: BuildArgs[6]; env?: BuildArgs[7]; opts?: BuildArgs[8];
  roster: { role: string; status?: string }[];
}): { timeline: ReturnType<typeof buildTeamTimeline>; load: TeamLoad; workload: WorkloadPreview } {
  let load = args.load;
  const build = (l: TeamLoad) => buildTeamTimeline(args.companyId, args.difficulty, args.seed, args.slots, l, args.stack ?? {}, args.tenant ?? null, args.env ?? null, args.opts ?? {});
  let timeline = build(load);
  let workload = measureWorkload(timeline, load, args.roster);
  for (let round = 0; round < MAX_ROUNDS && (workload.tier1.pct ?? 0) > TIER1_TARGET && load.noiseCount > 0; round++) {
    // Minutes over the target, as routine logs to drop (each one is WORK.READ_SEC_PER_LOG of reading).
    const overMin = ((workload.tier1.pct ?? 0) - TIER1_TARGET) * workload.tier1.capacityMin;
    // Never thin the feed below twice the attack rows: a feed that is mostly the attack gives the
    // answer away. Past that floor the load stays over and the lobby says so (longer shift, fewer storylines).
    const floorCut = Math.max(0, workload.feedRows - 2 * workload.attackRows);
    const cut = Math.min(load.noiseCount, floorCut, Math.ceil((overMin * 60) / WORK.READ_SEC_PER_LOG));
    if (cut <= 0) break;
    const rows = Math.max(1, workload.feedRows - cut);
    const meanGap = (load.shiftMin * 60_000 * 0.95) / rows;
    const jitterMs = Math.round(meanGap * 0.25);
    load = { ...load, noiseCount: load.noiseCount - cut, logsPerMin: Math.round((rows / load.shiftMin) * 10) / 10, baseGapMs: Math.round(meanGap - jitterMs / 2), jitterMs };
    timeline = build(load);
    workload = measureWorkload(timeline, load, args.roster);
  }
  return { timeline, load, workload };
}
