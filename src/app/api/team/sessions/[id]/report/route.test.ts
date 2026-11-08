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
  /** The viewer's seat in this session (null = not seated). */
  mem: { role: "t1" } as { role: string } | null,
};
const REVIEW = { managerId: "m1", managerName: "Noa", score: 80, decisions: [], questions: [], reports: [], timeline: [] };
const REPORT = { team: { version: 4 }, perUser: [{ user_id: "p1" }, { user_id: "p2" }, { user_id: "m1" }], answers: {}, managerReview: REVIEW };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => state.user) }));
vi.mock("@/lib/team/awardTeamXp", async orig => {
  const real = await orig<typeof import("@/lib/team/awardTeamXp")>();
  return {
    ...real,
    loadOrBuildReport: vi.fn(async () => { if (state.loadErr) throw state.loadErr; return { report: REPORT, fresh: false }; }),
    awardedTeamXp: vi.fn(async () => state.awarded),
    awardTeamXpOnce: vi.fn(async () => { state.awardCalls++; return { p1: 10, p2: 20 }; }),
    xpFromReport: vi.fn(() => ({ p1: 10, p2: 20, m1: 30 })),
  };
});
const handler = (op: Op): Result => {
  if (op.table === "team_sessions") return { data: { id: "s1", org_id: "org1", status: "ended" } };
  if (op.table === "team_session_members") return { data: state.mem };
  if (op.table === "profiles") return { data: { xp: 1234 } };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler).client }));

const { GET } = await import("./route");
const { ReportBuildingError } = await import("@/lib/team/awardTeamXp");
const call = () => GET(new Request("https://x"), { params: Promise.resolve({ id: "s1" }) });

beforeEach(() => { state.user = user({ id: "p1", orgRole: "student" }); state.loadErr = null; state.awarded = null; state.awardCalls = 0; state.mem = { role: "t1" }; afterQueue.length = 0; });

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

/**
 * Owner decision 2026-11: only a team admin (org_admin of the session's org, or the
 * platform owner) sees everyone's card and XP. The trainee SOC Manager sees their own
 * card plus team-level numbers like any player; the Command Review is whole only for a
 * team admin and the Manager it is about.
 */
describe("GET /report: who sees what", () => {
  const view = async () => { const res = await call(); return { status: res.status, body: res.status === 200 ? await res.json() : null }; };
  const ids = (b: { perUser: { user_id: string }[] }) => b.perUser.map(u => u.user_id);

  it("an org admin (not seated) sees every card, every XP and the whole Command Review", async () => {
    state.user = user({ id: "adm", orgRole: "org_admin" }); state.mem = null;
    const { status, body } = await view();
    expect(status).toBe(200);
    expect(body.seesAll).toBe(true);
    expect(ids(body)).toEqual(["p1", "p2", "m1"]);
    expect(body.xp).toEqual({ p1: 10, p2: 20, m1: 30 });
    expect(body.managerReview.redacted).toBeUndefined();
    expect(body.managerReview.score).toBe(80);
  });

  it("the platform owner sees everything too", async () => {
    state.user = user({ id: "own", orgId: "other-org", orgRole: null, isPlatformAdmin: true }); state.mem = null;
    const { body } = await view();
    expect(body.seesAll).toBe(true);
    expect(ids(body)).toHaveLength(3);
  });

  it("the trainee SOC Manager sees only their own card and XP, with their own Command Review whole", async () => {
    state.user = user({ id: "m1", orgRole: "student" }); state.mem = { role: "mgr" };
    const { body } = await view();
    expect(body.seesAll).toBe(false);
    expect(ids(body)).toEqual(["m1"]);
    expect(body.xp).toEqual({ m1: 30 });
    expect(body.managerReview.redacted).toBeUndefined();
    expect(body.managerReview.score).toBe(80);
    expect(body.team).toEqual({ version: 4 });          // team-level numbers stay
  });

  it("a Manager seat whose review is about someone else gets it redacted", async () => {
    state.user = user({ id: "m2", orgRole: "student" }); state.mem = { role: "mgr" };
    const { body } = await view();
    expect(body.managerReview.redacted).toBe(true);
  });

  it("the Lead gets the Command Review redacted and only their own card", async () => {
    state.user = user({ id: "p2", orgRole: "student" }); state.mem = { role: "lead" };
    const { body } = await view();
    expect(body.seesAll).toBe(false);
    expect(ids(body)).toEqual(["p2"]);
    expect(body.managerReview.redacted).toBe(true);
    expect(body.managerReview.score).toBeNull();
  });

  it("a player sees their own card, own XP, the redacted review", async () => {
    const { body } = await view();
    expect(body.seesAll).toBe(false);
    expect(ids(body)).toEqual(["p1"]);
    expect(body.xp).toEqual({ p1: 10 });
    expect(body.managerReview.redacted).toBe(true);
  });

  it("an org instructor who is not seated is refused", async () => {
    state.user = user({ id: "ins", orgRole: "instructor" }); state.mem = null;
    expect((await view()).status).toBe(403);
  });

  it("an org instructor seated as t1 has exactly a player's view", async () => {
    state.user = user({ id: "p1", orgRole: "instructor" }); state.mem = { role: "t1" };
    const { body } = await view();
    expect(body.seesAll).toBe(false);
    expect(ids(body)).toEqual(["p1"]);
    expect(body.xp).toEqual({ p1: 10 });
    expect(body.managerReview.redacted).toBe(true);
  });

  it("an org admin of another organization is refused", async () => {
    state.user = user({ id: "adm2", orgId: "org2", orgRole: "org_admin" }); state.mem = null;
    expect((await view()).status).toBe(403);
  });
});
