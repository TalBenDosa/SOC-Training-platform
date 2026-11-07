/**
 * /end and /pause after 0104: ending is announced two minutes ahead unless staff choose
 * "End now", and nothing pauses the room except a human Pause.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, user, type Op, type Result } from "../../../_testing/fakeAdmin";

vi.mock("server-only", () => ({}));
vi.mock("next/server", async (orig) => ({ ...(await orig<typeof import("next/server")>()), after: vi.fn() }));
const state = { status: "running", who: user() as ReturnType<typeof user>, seat: null as { role: string } | null, calls: [] as string[] };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => state.who) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));
vi.mock("@/lib/team/awardTeamXp", () => ({ awardTeamXpOnce: vi.fn(async () => {}) }));
vi.mock("@/lib/team/membership", () => ({ activeSeat: vi.fn(async () => state.seat) }));
vi.mock("@/lib/team/transition", () => ({
  END_NOTICE_MS: 120_000,
  teamTransition: vi.fn(async (_id: string, to: string, reason: string) => { state.calls.push(`transition:${to}:${reason}`); return { result: { ok: true } }; }),
  teamScheduleEnd: vi.fn(async (_id: string, _by: string, ms: number) => { state.calls.push(`schedule:${ms}`); return { result: { ok: true, ends_at: "2026-11-07T20:02:00.000Z" } }; }),
  teamCancelEnd: vi.fn(async () => { state.calls.push("cancel"); return { result: { ok: true } }; }),
}));
const handler = (op: Op): Result => (op.table === "team_sessions" ? { data: { org_id: "org1", status: state.status } } : { data: null });
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler).client }));

const { POST: END } = await import("./route");
const { POST: PAUSE } = await import("../pause/route");
type Handler = (req: Request, ctx: { params: Promise<{ id: string }> }) => Promise<Response>;
const call = (fn: Handler, body?: unknown) => fn(new Request("https://x", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body), headers: { "Content-Type": "application/json" } } : {}) }), { params: Promise.resolve({ id: "s1" }) });

beforeEach(() => { state.status = "running"; state.who = user(); state.seat = null; state.calls = []; });

describe("POST /end (0104)", () => {
  it("no body: the end is scheduled 2 minutes ahead and the server keeps the time", async () => {
    const res = await call(END);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, mode: "scheduled", ends_at: "2026-11-07T20:02:00.000Z" });
    expect(state.calls).toEqual(["schedule:120000"]);
  });
  it("End now ends at once", async () => {
    expect((await (await call(END, { mode: "now" })).json()).mode).toBe("now");
    expect(state.calls).toEqual(["transition:ended:manual"]);
  });
  it("cancel withdraws a scheduled end", async () => {
    expect((await (await call(END, { mode: "cancel" })).json()).mode).toBe("cancel");
    expect(state.calls).toEqual(["cancel"]);
  });
  it("a lobby that never started ends at once", async () => {
    state.status = "lobby";
    await call(END);
    expect(state.calls).toEqual(["transition:ended:manual"]);
  });
  it("the session's Manager may end; another player may not", async () => {
    state.who = user({ id: "p1", orgRole: "student" }); state.seat = { role: "mgr" };
    expect((await call(END)).status).toBe(200);
    state.seat = { role: "t1" };
    expect((await call(END)).status).toBe(403);
  });
  it("an unknown mode is refused", async () => {
    expect((await call(END, { mode: "later" })).status).toBe(400);
  });
});

describe("POST /pause (0104): only a human pause", () => {
  it("an automatic reason never pauses: noop, no transition", async () => {
    for (const reason of ["coverage", "owner_left"]) {
      const res = await call(PAUSE, { paused: true, reason });
      expect(await res.json()).toMatchObject({ ok: true, noop: true, refused: "automatic_pause_disabled" });
    }
    expect(state.calls).toEqual([]);
  });
  it("staff pause manually", async () => {
    await call(PAUSE, { paused: true });
    expect(state.calls).toEqual(["transition:paused:manual"]);
  });
  it("a Tier-1 cannot pause the room", async () => {
    state.who = user({ id: "p1", orgRole: "student" }); state.seat = { role: "t1" };
    expect((await call(PAUSE, { paused: true, reason: "manual" })).status).toBe(403);
    expect(state.calls).toEqual([]);
  });
});
