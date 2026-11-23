/**
 * AWS fidelity gate (AWS log review 2026-11-22). Every AWS log a learner can meet must look like a real
 * AWS account's log, and the AWS rows of one story must support the analyst's pivots:
 *   - every attack story, dealt as the Live Feed deals it (instantiateStory -> feedStoryEvents ->
 *     applyStack -> nativize) for the company it is written for;
 *   - every surface the realism collectors build (Live Feed, Scenarios, Team Training, XDR ...).
 * Checks: src/lib/logs/native/testing/awsChecks.ts. Expected: no finding at all.
 */
import { describe, it, expect } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { companyFeedPool, feedCompanyProfile, feedStoryEvents } from "@/app/(app)/dashboard/feedPool";
import { applyStack, nativize } from "./index";
import { makeCtx } from "./ctx";
import { mulberry32, hashSeed } from "@/lib/team/variety";
import { collectAll } from "../realism/collect";
import { checkCloudTrail, checkFlowLine, checkGuardDuty, checkStory, type AwsFinding } from "./testing/awsChecks";

type R = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const SIM = { BENIGN_EVENTS, COMPANY_EVENTS };
const home = (companyId: string) => makeCtx(companyId).tenant.awsRegion;
const report = (fs: AwsFinding[]) => fs.slice(0, 30).map(f => `${f.kind} ${f.where}: ${f.detail}`);

function checkStoryRows(storyId: string, rows: { record: R; sourceId: string; where: string; isAttack?: boolean }[], out: AwsFinding[], homeRegion?: string) {
  const ct = rows.filter(r => r.sourceId === "aws_cloudtrail").map(r => r.record);
  // The story checks follow the attack: noise rows (a pool, a session's ordinary traffic) are unrelated to each other.
  const attackCt = rows.filter(r => r.sourceId === "aws_cloudtrail" && r.isAttack !== false).map(r => r.record);
  for (const r of rows) {
    if (r.sourceId === "aws_cloudtrail") checkCloudTrail(r.record, r.where, out);
    else if (r.sourceId === "aws_guardduty") checkGuardDuty((r.record.detail ?? r.record) as R, r.where, ct, out);
    else if (r.sourceId === "aws_vpcflow") checkFlowLine(typeof r.record === "string" ? r.record : String((r.record as R).message ?? ""), r.where, out);
  }
  checkStory(storyId, attackCt, out, homeRegion);
}

describe("AWS fidelity", () => {
  it("every attack story's AWS rows, as the Live Feed deals them", () => {
    const out: AwsFinding[] = [];
    let n = 0;
    for (const s of ATTACK_STORIES) {
      const companyId = s.companies?.[0] ?? "nexacorp";
      const pool = companyFeedPool(SIM, companyId);
      const edr = feedCompanyProfile(companyId).architecture?.edr;
      const inst = instantiateStory(s, pool, edr, companyId, mulberry32(hashSeed(`aws:${s.id}`)), { seed: "aws-fidelity" });
      const evs = feedStoryEvents(inst.events, companyId).map(e => applyStack(e, companyId, {}));
      const rows = evs.flatMap((e: TelemetryEvent, i) => {
        const log = nativize(e, companyId);
        return log && log.sourceId.startsWith("aws_") ? [{ record: log.record as R, sourceId: log.sourceId, where: `${s.id}#${i}@${e.id}` }] : [];
      });
      n += rows.length;
      checkStoryRows(s.id, rows, out, ["quantumbank", "globallogis"].includes(companyId) ? home(companyId) : undefined);
    }
    for (const [companyId, evs] of Object.entries(COMPANY_EVENTS)) for (const e of evs) {
      const log = nativize(applyStack(e, companyId, {}), companyId);
      if (log?.sourceId === "aws_cloudtrail") { n++; checkCloudTrail(log.record as R, `${companyId}-pool@${e.id}`, out); }
    }
    console.log(`[aws] stories + pools: ${n} AWS rows, ${out.length} findings`);
    expect(report(out)).toEqual([]);
  }, 600_000);

  it("every surface's AWS rows (Live Feed, Scenarios, Team Training, XDR)", () => {
    const out: AwsFinding[] = [];
    const byStory = new Map<string, { record: R; sourceId: string; where: string; isAttack?: boolean }[]>();
    for (const row of collectAll().rows) {
      const sid = row.native?.sourceId;
      if (!sid || !sid.startsWith("aws_")) continue;
      const key = `${row.surface}:${row.storyId ?? row.company ?? "-"}`;
      (byStory.get(key) ?? byStory.set(key, []).get(key)!).push({ record: row.native!.record as R, sourceId: sid, where: `${row.surface}:${row.rowId}`, isAttack: row.isAttack });
    }
    let n = 0;
    for (const [key, rows] of byStory) { n += rows.length; checkStoryRows(key, rows, out); }
    console.log(`[aws] surfaces: ${n} AWS rows in ${byStory.size} cases, ${out.length} findings`);
    expect(report(out)).toEqual([]);
  }, 900_000);
});
