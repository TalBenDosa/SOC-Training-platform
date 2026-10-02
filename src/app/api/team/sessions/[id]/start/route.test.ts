/**
 * /start: a pinned storyline is re-checked with the builder's predicate (QA M7), a
 * timeline build failure is a clear error that leaves the lobby retryable, and a
 * session with nobody to play it isn't started (QA L7).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, user, type Op, type Result } from "../../../_testing/fakeAdmin";

vi.mock("server-only", () => ({}));
const state = {
  members: [] as { role: string; status: string }[],
  scenario: null as string | null,
  fits: true,
  buildThrows: false,
  transitions: 0,
  seeded: 0,
};
vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgStaff: vi.fn(async () => ({ user: user() })) }));
vi.mock("@/lib/team/buildTimeline", () => ({
  resolveTeamStory: vi.fn((_c: string, _d: string, id: string | null) => (id ? { id, events: [] } : null)),
  teamStoryFilter: vi.fn(() => () => state.fits),
  buildTeamTimeline: vi.fn(() => { if (state.buildThrows) throw new Error("no fitting story"); return [{ due_offset_ms: 0, channel: "feed", body: { id: "e1" }, answer: null }]; }),
}));
vi.mock("@/lib/team/transition", () => ({ teamTransition: vi.fn(async () => { state.transitions++; return { result: { ok: true } }; }) }));
const handler = (op: Op): Result => {
  if (op.table === "team_sessions" && op.action === "select") return { data: { id: "s1", org_id: "org1", status: "lobby", company_id: "nexacorp", difficulty: "medium", seed: "x", scenario_id: state.scenario, config: {} } };
  if (op.table === "team_sessions") return { error: null };
  if (op.table === "team_session_members") return { data: state.members };
  if (op.table === "session_injects") return { count: 0 };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler, name => { if (name === "team_seed_timeline") state.seeded++; return { data: 1 }; }).client }));

const { POST } = await import("./route");
const start = () => POST(new Request("https://x", { method: "POST" }), { params: Promise.resolve({ id: "s1" }) });
const READY = [{ role: "instructor", status: "active" }, { role: "t1", status: "ready" }];

beforeEach(() => { state.members = READY; state.scenario = null; state.fits = true; state.buildThrows = false; state.transitions = 0; state.seeded = 0; });

describe("POST /start", () => {
  it("starts a ready team", async () => {
    const res = await start();
    expect(res.status).toBe(200);
    expect(state.seeded).toBe(1);
    expect(state.transitions).toBe(1);
  });

  it("M7: a pinned storyline that no longer fits the session's products → 409, nothing seeded", async () => {
    state.scenario = "story-x"; state.fits = false;
    const res = await start();
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/pinned storyline/);
    expect(state.seeded).toBe(0);
    expect(state.transitions).toBe(0);
  });

  it("L7: a timeline build failure is a clear 500 and the session stays in the lobby", async () => {
    state.buildThrows = true;
    const res = await start();
    expect(res.status).toBe(500);
    expect((await res.json()).error).toMatch(/nothing was started/);
    expect(state.transitions).toBe(0);
  });

  it("L7: no players (only the instructor / observers / removed members) → 409", async () => {
    state.members = [{ role: "instructor", status: "active" }, { role: "observer", status: "invited" }, { role: "t1", status: "left" }];
    expect((await start()).status).toBe(409);
  });

  it("a removed no-show doesn't block Start", async () => {
    state.members = [...READY, { role: "t2", status: "left" }];
    expect((await start()).status).toBe(200);
  });
});
