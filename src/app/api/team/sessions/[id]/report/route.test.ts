/**
 * QA M5: the end-of-session herd. The report build is single-flight (a waiter that
 * times out answers 503 `building` and the client retries), and a missing XP award
 * runs AFTER the response — the request returns the deterministic numbers at once.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, user, type Op, type Result } from "../../../_testing/fakeAdmin";

const afterQueue: (() => unknown)[] = [];
vi.mock("next/server", async orig => ({ ...(await orig<typeof import("next/server")>()), after: (fn: () => unknown) => { afterQueue.push(fn); } }));
vi.mock("server-only", () => ({}));

const state = {
  user: user() as ReturnType<typeof user> | null,
  loadErr: null as Error | null,
  awarded: null as Record<string, number> | null,
  awardCalls: 0,
};
const REPORT = { team: { version: 4 }, perUser: [{ user_id: "p1" }, { user_id: "p2" }], answers: {} };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => state.user) }));
vi.mock("@/lib/team/awardTeamXp", async orig => {
  const real = await orig<typeof import("@/lib/team/awardTeamXp")>();
  return {
    ...real,
    loadOrBuildReport: vi.fn(async () => { if (state.loadErr) throw state.loadErr; return { report: REPORT, fresh: false }; }),
    awardedTeamXp: vi.fn(async () => state.awarded),
    awardTeamXpOnce: vi.fn(async () => { state.awardCalls++; return { p1: 10, p2: 20 }; }),
    xpFromReport: vi.fn(() => ({ p1: 10, p2: 20 })),
  };
});
const handler = (op: Op): Result => {
  if (op.table === "team_sessions") return { data: { id: "s1", org_id: "org1", status: "ended" } };
  if (op.table === "team_session_members") return { data: { role: "t1" } };
  if (op.table === "profiles") return { data: { xp: 1234 } };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler).client }));

const { GET } = await import("./route");
const { ReportBuildingError } = await import("@/lib/team/awardTeamXp");
const call = () => GET(new Request("https://x"), { params: Promise.resolve({ id: "s1" }) });

beforeEach(() => { state.user = user({ id: "p1", orgRole: "student" }); state.loadErr = null; state.awarded = null; state.awardCalls = 0; afterQueue.length = 0; });

describe("GET /report", () => {
  it("another request is building → 503 { building } with Retry-After (the client retries quietly)", async () => {
    state.loadErr = new ReportBuildingError();
    const res = await call();
    expect(res.status).toBe(503);
    expect(res.headers.get("Retry-After")).toBe("2");
    expect(await res.json()).toMatchObject({ building: true });
  });

  it("a real build failure is still a 500", async () => {
    state.loadErr = new Error("boom");
    expect((await call()).status).toBe(500);
  });

  it("XP not yet awarded: the response carries the deterministic numbers, the award runs after it", async () => {
    const res = await call();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.xp).toEqual({ p1: 10 });          // own card only
    expect(body.myTotalXp).toBeNull();            // the stored total is stale until the award lands
    expect(state.awardCalls).toBe(0);             // nothing on the request path
    expect(afterQueue).toHaveLength(1);
    await afterQueue[0]();
    expect(state.awardCalls).toBe(1);
  });

  it("XP already awarded: no deferred work, the viewer's total comes back", async () => {
    state.awarded = { p1: 10, p2: 20 };
    const body = await (await call()).json();
    expect(afterQueue).toHaveLength(0);
    expect(body.myTotalXp).toBe(1234);
  });
});
