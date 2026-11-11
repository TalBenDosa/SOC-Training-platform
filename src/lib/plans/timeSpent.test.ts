import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));
const { loadTimeSpent, minutesFor, timeMeasured } = await import("./timeSpent");

type Row = Record<string, unknown>;
/** A tiny stand-in for the Supabase query builder: every filter returns itself, range() resolves. */
function fakeAdmin(tables: Record<string, Row[] | Error>) {
  return {
    from(table: string) {
      const q = {
        select: () => q, eq: () => q, in: () => q, order: () => q,
        range: async () => {
          const t = tables[table];
          if (t instanceof Error) return { data: null, error: { code: "42P01", message: `relation "${table}" does not exist` } };
          return { data: t ?? [], error: null };
        },
      };
      return q;
    },
  } as never;
}

const U = "11111111-0000-4000-8000-000000000001";
const items = [
  { kind: "room", id: "sentinel-fundamentals" },
  { kind: "scenario", id: "spray" },
  { kind: "lesson", id: "soc-analyst--what-is-a-soc" },
  { kind: "quiz", id: "mitre-attack" },
  { kind: "lesson", id: "org-abcd-custom" },
] as const;

describe("time spent per plan item", () => {
  it("sums room telemetry, scenario runs and lesson / quiz beats; custom lessons are not measured", async () => {
    const idx = await loadTimeSpent(fakeAdmin({
      room_progress: [{ user_id: U, room_id: "sentinel-fundamentals", telemetry: [{ decisionLatencyMs: 90_000 }, { decisionLatencyMs: 30_000 }] }],
      scenario_history: [{ user_id: U, slug: "spray", time_taken: 300 }, { user_id: U, slug: "spray", time_taken: 120 }],
      content_time: [{ user_id: U, item_id: "soc-analyst--what-is-a-soc", seconds: 600 }],
    }), { orgId: "org", userIds: [U], items: [...items] });
    // content_time answers both kinds from one fake table: the quiz has no row with its id, so 0.
    expect(minutesFor(idx, U, [...items])).toEqual([2, 7, 10, 0, null]);
  });

  it("before migration 0109, lessons and quizzes come back as not measured, never 0", async () => {
    const idx = await loadTimeSpent(fakeAdmin({ content_time: new Error("missing") }), { orgId: "org", userIds: [U], items: [...items] });
    expect(minutesFor(idx, U, [...items])).toEqual([0, 0, null, null, null]);
    expect(timeMeasured({ kind: "room", id: "x" }, idx)).toBe(true);
  });
});
