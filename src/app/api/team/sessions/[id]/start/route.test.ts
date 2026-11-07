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
  /** The org's earlier sessions the history read returns (newest first), and what /start wrote. */
  past: [] as { id: string; config: unknown; started_at: string }[],
  updates: [] as Record<string, unknown>[],
  history: undefined as unknown,
};
vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgStaff: vi.fn(async () => ({ user: user() })) }));
vi.mock("@/lib/team/buildTimeline", () => ({
  resolveTeamStory: vi.fn((_c: string, _d: string, id: string | null) => (id ? { id, events: [] } : null)),
  teamStoryFilter: vi.fn(() => () => state.fits),
  buildTeamTimeline: vi.fn((...a: unknown[]) => {
    if (state.buildThrows) throw new Error("no fitting story");
    const opts = a[8] as { history?: unknown; onVariety?: (r: unknown) => void } | undefined;
    state.history = opts?.history;
    opts?.onVariety?.({ v: 1, makers: ["travel", "pcap_dev"], decoy: "data_room", twist: "new_account", injects: ["ticket:usb_found"], stories: ["story-a"] });
    return [{ due_offset_ms: 0, channel: "feed", body: { id: "e1" }, answer: null }];
  }),
}));
vi.mock("@/lib/team/transition", () => ({ teamTransition: vi.fn(async () => { state.transitions++; return { result: { ok: true } }; }) }));
const handler = (op: Op): Result => {
  // The history read (the org's started sessions) is the select that filters on started_at.
  if (op.table === "team_sessions" && op.action === "select" && op.filters.some(f => f[0] === "not")) return { data: state.past };
  if (op.table === "team_sessions" && op.action === "select") return { data: { id: "s1", org_id: "org1", status: "lobby", company_id: "nexacorp", difficulty: "medium", seed: "x", scenario_id: state.scenario, config: { shift_min: 30 } } };
  if (op.table === "team_sessions") { if (op.action === "update") state.updates.push(op.payload as Record<string, unknown>); return { error: null }; }
  if (op.table === "team_session_members") return { data: state.members };
  if (op.table === "session_injects") return { count: 0 };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler, name => { if (name === "team_seed_timeline") state.seeded++; return { data: 1 }; }).client }));

const { POST } = await import("./route");
const start = () => POST(new Request("https://x", { method: "POST" }), { params: Promise.resolve({ id: "s1" }) });
const READY = [{ role: "instructor", status: "active" }, { role: "t1", status: "ready" }];

beforeEach(() => { state.members = READY; state.scenario = null; state.fits = true; state.buildThrows = false; state.transitions = 0; state.seeded = 0; state.past = []; state.updates = []; state.history = undefined; });

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
    expect((await res.json()).error).toMatch(/chosen storyline/);
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

  it("memory: reads the org's earlier sessions' variants and stores this session's, staff-only in config", async () => {
    state.past = [
      { id: "s1", config: { variety: { v: 1, makers: ["scan_sentinel"] } }, started_at: "2026-11-07T10:00:00Z" },   // this session (skipped)
      { id: "p1", config: { variety: { v: 1, makers: ["remote_admin"], decoy: "dr_replication", twist: "second_implant", injects: [], stories: ["s-x"] } }, started_at: "2026-11-06T10:00:00Z" },
      { id: "p2", config: { variety: { v: 1, makers: ["travel"], decoy: null, twist: null, injects: [], stories: [] } }, started_at: "2026-11-05T10:00:00Z" },
    ];
    expect((await start()).status).toBe(200);
    expect(state.history).toMatchObject({ makers: { remote_admin: 1, travel: 2 }, decoys: { dr_replication: 1 }, twists: { second_implant: 1 }, stories: { "s-x": 1 } });
    expect((state.history as { makers: Record<string, number> }).makers.scan_sentinel).toBeUndefined();
    const withConfig = state.updates.find(u => u.config);
    expect(withConfig?.config).toMatchObject({ shift_min: 30, variety: { makers: ["travel", "pcap_dev"], decoy: "data_room", twist: "new_account" } });
  });

  it("a removed no-show doesn't block Start", async () => {
    state.members = [...READY, { role: "t2", status: "left" }];
    expect((await start()).status).toBe(200);
  });
});
