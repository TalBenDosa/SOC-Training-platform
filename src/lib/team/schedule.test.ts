// 2026-10-18 review: chosen attacks arrived after the session ended. The timeline now fits the
// instructor's shift length, Attack 1 leads, every planned attack starts in the first half, and the
// instructor can see / bring forward what is still to come.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "./buildTimeline";
import { parseTenant, TENANT_TEMPLATE, type Tenant } from "./tenant";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan } from "./attackPlan";
import { pendingAttacks, releasePlan, shiftElapsedMs, type PendingRow } from "./schedule";
import { storiesForTier } from "@/app/(app)/dashboard/attackStories";
import { teamStoryFilter } from "./buildTimeline";
import { DEFAULT_ENV } from "./environment";

const tenant = parseTenant("acme") as Tenant;
const team = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

describe("timeline fits the shift and leads with the primary incident", () => {
  const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
  const ids = storiesForTier("hard", true).filter(fits).map(s => s.id);
  const slots = [ids[0], ids[1], ids[2]];
  for (const minutes of [20, 30, 45]) for (const seed of ["a", "b", "c", "d"]) {
    it(`${minutes} min · seed ${seed}`, () => {
      const plan = { count: 3, slots, bonus: true };
      const load = loadWithPlan(withShiftMinutes(teamLoad("hard", team), minutes), plan);
      const tl = buildTeamTimeline(TENANT_TEMPLATE, "hard", seed, slots, load, {}, tenant, DEFAULT_ENV, { bonus: true });
      const live = tl.filter(e => e.channel !== "bonus");
      const lastDue = Math.max(...live.filter(e => e.channel === "feed").map(e => e.due_offset_ms));
      expect(lastDue).toBeLessThanOrEqual(minutes * 60_000);
      const firstOf = new Map<string, number>();
      for (const e of live) {
        const a = e.answer as { incident_id?: string; expected_verdict?: string; origin?: string } | undefined;
        if (!a?.incident_id || a.origin !== "story" || !["tp", "escalate"].includes(String(a.expected_verdict))) continue;
        firstOf.set(a.incident_id, Math.min(firstOf.get(a.incident_id) ?? Infinity, e.due_offset_ms));
      }
      const starts = [...firstOf.values()];
      expect(starts.length).toBeGreaterThanOrEqual(2);
      // every planned attack has started by ~the middle of the shift
      for (const s of starts) expect(s).toBeLessThanOrEqual(minutes * 60_000 * 0.55);
      // Attack 1 (the primary incident) is the first to surface
      const primary = [...firstOf.entries()].find(([inc]) => inc.includes(String(slots[0])));
      if (primary) expect(primary[1]).toBe(Math.min(...starts));
    });
  }
});

describe("attack schedule (instructor)", () => {
  const row = (id: string, inc: string, due: number, extra: Partial<PendingRow> = {}, verdict = "tp", origin = "story"): PendingRow =>
    ({ id, channel: "feed", due_offset_ms: due, expected_action: { incident_id: inc, expected_verdict: verdict, origin }, ...extra });
  const rows = [
    row("a1", "story:kerberoasting", 600_000), row("a2", "story:kerberoasting", 660_000), row("a0", "story:kerberoasting", 640_000, {}, "benign"),
    row("b1", "pool:b-bruteforce", 300_000, {}, "tp", "pool_attack"),
    row("c1", "story:oauth", 1e15 + 0, { channel: "bonus" }), row("c2", "story:oauth", 1e15 + 8000, { channel: "bonus" }),
  ];

  it("lists pending attacks soonest first, the bonus last", () => {
    const p = pendingAttacks(rows);
    expect(p.map(x => x.incident)).toEqual(["pool:b-bruteforce", "story:kerberoasting", "story:oauth"]);
    expect(p[1]).toMatchObject({ kind: "planned", firstDueMs: 600_000, rows: 2 });
    expect(p[2].kind).toBe("bonus");
  });

  it("releases the next PLANNED attack first, keeping its spacing and moving its control steps too", () => {
    const plan = releasePlan(rows, 120_000)!;
    expect(plan.incident).toBe("story:kerberoasting");
    const due = Object.fromEntries(plan.updates.map(u => [u.id, u.due_offset_ms]));
    expect(due.a1).toBe(125_000);
    expect(due.a2).toBe(185_000);
    expect(due.a0).toBe(165_000);
    expect(due.b1).toBeUndefined();
  });

  it("releases the held bonus onto the feed at its own pace", () => {
    const plan = releasePlan(rows, 120_000, "story:oauth")!;
    expect(plan.updates).toEqual([{ id: "c1", due_offset_ms: 125_000, channel: "feed" }, { id: "c2", due_offset_ms: 133_000, channel: "feed" }]);
  });

  it("the shift clock excludes pauses and freezes while paused", () => {
    const s = { started_at: "2026-10-18T10:00:00Z", paused_ms: 60_000, paused_at: "2026-10-18T10:10:00Z", status: "paused" };
    expect(shiftElapsedMs(s, Date.parse("2026-10-18T10:20:00Z"))).toBe(9 * 60_000);
    expect(shiftElapsedMs({ ...s, status: "running" }, Date.parse("2026-10-18T10:20:00Z"))).toBe(19 * 60_000);
  });
});
