// Stage B1: the solo training routes. The server deals the story and keeps its answer; the session row is
// written from the server's record, once.
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ShiftRow } from "@/lib/dashboard/shiftStore";

const user = { id: "11111111-1111-4111-8111-111111111111", orgId: "22222222-2222-4222-8222-222222222222" };
let authed: typeof user | null = user;
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => authed) }));

// A tiny stand-in for the service-role client: records inserts/updates on the two tables the end route writes.
const writes: { table: string; op: string; row: Record<string, unknown> }[] = [];
let closedAlready = false;
const admin = {
  from(table: string) {
    const q = {
      _op: "", _row: {} as Record<string, unknown>,
      insert(row: Record<string, unknown>) { q._op = "insert"; q._row = row; writes.push({ table, op: "insert", row }); return q; },
      update(row: Record<string, unknown>) { q._op = "update"; q._row = row; writes.push({ table, op: "update", row }); return q; },
      eq() { return q; }, is() { return q; },
      select() { return q; },
      single: async () => ({ data: { id: "44444444-4444-4444-8444-444444444444" }, error: null }),
      then(res: (v: unknown) => void) {
        // update(...).eq().is().select("id") → the rows it closed
        res({ data: q._op === "update" && "ended_at" in q._row ? (closedAlready ? [] : [{ id: "x" }]) : null, error: null });
      },
    };
    return q;
  },
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => admin }));

let shift: ShiftRow | null = null;
const insertShift = vi.fn(async () => "55555555-5555-4555-8555-555555555555");
let perHour = 0;
vi.mock("@/lib/dashboard/shiftStore", async (orig) => ({
  ...(await orig<typeof import("@/lib/dashboard/shiftStore")>()),
  loadShift: vi.fn(async () => shift),
  insertShift: (...a: unknown[]) => insertShift(...(a as [])),
  shiftsInLastHour: vi.fn(async () => perHour),
  recentStoryIds: vi.fn(async () => []),
  saveStories: vi.fn(async () => {}),
  orgCompanyFor: vi.fn(async () => null),
}));

const start = (await import("./route")).POST;
const end = (await import("./[id]/end/route")).POST;
const post = (body: unknown) => new Request("https://x/api/dashboard/shift", { method: "POST", body: JSON.stringify(body) });
const SID = "55555555-5555-4555-8555-555555555555";

beforeEach(() => { authed = user; perHour = 0; writes.length = 0; closedAlready = false; insertShift.mockClear(); });

describe("POST /api/dashboard/shift", () => {
  it("a guest gets 401 and no shift", async () => {
    authed = null;
    expect((await start(post({ companyId: "nexacorp", difficulty: "easy" }))).status).toBe(401);
    expect(insertShift).not.toHaveBeenCalled();
  });

  it("rejects a bad level or an unknown company", async () => {
    expect((await start(post({ companyId: "nexacorp", difficulty: "insane" }))).status).toBe(400);
    expect((await start(post({ companyId: "not-a-company", difficulty: "easy" }))).status).toBe(404);
  });

  it("caps trainings per hour", async () => {
    perHour = 30;
    expect((await start(post({ companyId: "nexacorp", difficulty: "easy" }))).status).toBe(429);
  });

  it("deals the story, keeps its answer, returns the story with the shift id", async () => {
    const res = await start(post({ companyId: "medcore", difficulty: "medium" }));
    expect(res.status).toBe(200);
    const body = await res.json() as { shiftId: string; story: { id: string; events: unknown[] } };
    expect(body.shiftId).toBe(SID);
    expect(body.story.events.length).toBeGreaterThan(0);
    const row = (insertShift.mock.calls[0] as unknown as [unknown, { stories: { storyId: string; indicators: string[] }[]; user_id: string }])[1];
    expect(row.user_id).toBe(user.id);
    expect(row.stories[0].storyId).toBe(body.story.id);
    expect(row.stories[0].indicators.length).toBeGreaterThan(0);
  }, 60_000);
});

describe("POST /api/dashboard/shift/[id]/end", () => {
  const params = { params: Promise.resolve({ id: SID }) };
  const past = (ms: number) => new Date(Date.now() - ms).toISOString();
  const base = (): ShiftRow => ({
    id: SID, user_id: user.id, org_id: user.orgId, company_id: "nexacorp", difficulty: "easy", started_at: past(20 * 60_000), ended_at: null, session_id: null,
    stories: [
      { storyId: "a", title: "A", mitre: [], indicators: [], dealtAt: past(19 * 60_000), opensAt: past(17 * 60_000), bestScore: 80, caughtAt: past(10 * 60_000) },
      { storyId: "b", title: "B", mitre: [], indicators: [], dealtAt: past(60_000), opensAt: new Date(Date.now() + 50_000).toISOString(), bestScore: null, caughtAt: null },
    ],
  });
  const endReq = (body: unknown) => new Request(`https://x/api/dashboard/shift/${SID}/end`, { method: "POST", body: JSON.stringify(body) });

  it("writes the session row from the server's counts, not the browser's", async () => {
    shift = base();
    const res = await end(endReq({ eventsOpenedCount: 14, fnCount: 1, avgCatchMs: 400_000, durationMs: 900_000, xpEarned: 99999, attacksCaughtCount: 9 }), params);
    const body = await res.json() as { saved: boolean };
    expect(body.saved).toBe(true);
    const row = writes.find(w => w.table === "dashboard_sessions" && w.op === "insert")!.row;
    expect(row.attacks_caught_count).toBe(1);
    expect(row.attacks_presented_count).toBe(1);     // the second story could not be on screen yet
    expect(row.xp_earned).toBe(120);
    expect(row.detect_rate).toBe(100);
    expect(row.events_opened_count).toBe(14);
  });

  it("a repeated end writes no second row", async () => {
    shift = { ...base(), ended_at: new Date().toISOString(), session_id: "44444444-4444-4444-8444-444444444444" };
    const body = await (await end(endReq({}), params)).json() as { saved: boolean };
    expect(body.saved).toBe(true);
    expect(writes.some(w => w.table === "dashboard_sessions")).toBe(false);
  });

  it("another user's or an unknown training is not found", async () => {
    shift = null;
    expect((await end(endReq({}), params)).status).toBe(404);
  });
});
