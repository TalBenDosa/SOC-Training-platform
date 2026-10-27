import "server-only";
/**
 * Adds the practice room to every missed attack log of a built report (server side, before the
 * report is cached), so the room list never ships in the live-room bundle.
 */
import { practiceFor } from "../practice";
import type { MissItem, MissedAttack } from "./computeReport";
import type { ServerReport } from "./serverReport";

const enrich = <T extends MissItem | MissedAttack>(items: T[] | undefined) => (items ?? []).map(m => {
  const room = practiceFor(m.technique);
  return room ? { ...m, practice: room } : m;
});

export function withPracticeLinks(r: ServerReport): ServerReport {
  const team = r.team as typeof r.team & { missedAttackLogs?: MissItem[]; missedAttacks?: MissedAttack[]; falseNegatives?: MissItem[] };
  return {
    ...r,
    team: { ...team, missedAttackLogs: enrich(team.missedAttackLogs), missedAttacks: enrich(team.missedAttacks), falseNegatives: enrich(team.falseNegatives) },
    perUser: r.perUser.map(u => ({ ...u, walkedPast: enrich(u.walkedPast), falseNegatives: enrich(u.falseNegatives) })),
  };
}
