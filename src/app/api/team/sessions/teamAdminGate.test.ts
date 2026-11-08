/**
 * Owner decision 2026-11: only an organization admin (or the platform owner) creates and
 * runs a team exercise. These go through the REAL guard (getAuthedUser + requireTeamAdmin,
 * with the org role read from the DB): an org `instructor` gets a 403 on create, start,
 * pause, end, schedule, reassign and seat management; an org admin passes the gate.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, type Op, type Result } from "../_testing/fakeAdmin";

vi.mock("server-only", () => ({}));
vi.mock("react", async (orig) => ({ ...(await orig<typeof import("react")>()), cache: <T,>(f: T) => f }));
vi.mock("next/server", async (orig) => ({ ...(await orig<typeof import("next/server")>()), after: vi.fn() }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const st = {
  orgRole: "instructor",
  platform: false,
  seat: null as { role: string; status: string } | null,
  calls: [] as string[],
};
vi.mock("@/lib/auth/validatedUser", () => ({
  getValidatedAuth: vi.fn(async () => ({ supabase: {}, user: { id: "u1", email: "a@b.c" },
    session: { access_token: `h.${b64({ org_id: "org1", org_name: "College", org_role: st.orgRole, is_platform_admin: st.platform, org_active: true })}.s` } })),
}));
vi.mock("@/lib/team/transition", () => ({
  END_NOTICE_MS: 120_000,
  teamTransition: vi.fn(async () => { st.calls.push("transition"); return { result: { ok: true } }; }),
  teamScheduleEnd: vi.fn(async () => { st.calls.push("schedule"); return { result: { ok: true, ends_at: "2026-11-08T10:02:00.000Z" } }; }),
  teamCancelEnd: vi.fn(async () => { st.calls.push("cancel"); return { result: { ok: true } }; }),
}));
vi.mock("@/lib/team/awardTeamXp", () => ({ awardTeamXpOnce: vi.fn(async () => {}) }));

const handler = (op: Op): Result => {
  if (op.table === "profiles") return { data: { role: "analyst", is_platform_admin: st.platform } };
  if (op.table === "org_members" && op.single) return { data: { role: st.orgRole, status: "active", affiliation_expires_at: null, organizations: { status: "active", expires_at: null } } };
  if (op.table === "team_sessions") return { data: { id: "s1", org_id: "org1", status: "running" } };
  if (op.table === "team_session_members" && op.single) return { data: st.seat };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler).client }));

const { POST: CREATE } = await import("./route");
const { POST: START } = await import("./[id]/start/route");
const { POST: PAUSE } = await import("./[id]/pause/route");
const { POST: END } = await import("./[id]/end/route");
const { POST: SCHEDULE } = await import("./[id]/schedule/route");
const { POST: REASSIGN } = await import("./[id]/reassign/route");
const { POST: ADD_MEMBER, DELETE: REMOVE_MEMBER } = await import("./[id]/members/route");

type Handler = (req: Request, ctx: { params: Promise<{ id: string }> }) => Promise<Response | undefined>;
const post = async (fn: Handler, body: unknown = {}, method = "POST"): Promise<Response> =>
  (await fn(new Request("https://x", { method, body: JSON.stringify(body), headers: { "Content-Type": "application/json" } }), { params: Promise.resolve({ id: "s1" }) }))!;
const U = "11111111-1111-4111-8111-111111111111";

beforeEach(() => { st.orgRole = "instructor"; st.platform = false; st.seat = null; st.calls = []; });

describe("an org instructor cannot run a team exercise (403)", () => {
  it("create", async () => {
    const res = await CREATE(new Request("https://x", { method: "POST", body: JSON.stringify({ company_id: "nexacorp" }) }));
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("Team exercises are run by your organization admin.");
  });
  it("start", async () => { expect((await post(START)).status).toBe(403); });
  it("pause", async () => { expect((await post(PAUSE, { paused: true })).status).toBe(403); expect(st.calls).toEqual([]); });
  it("end, now or scheduled", async () => {
    expect((await post(END, { mode: "now" })).status).toBe(403);
    expect((await post(END)).status).toBe(403);
    expect(st.calls).toEqual([]);
  });
  it("schedule, reassign and seat management", async () => {
    expect((await post(SCHEDULE)).status).toBe(403);
    expect((await post(REASSIGN, { user_id: U, role: "t2" })).status).toBe(403);
    expect((await post(ADD_MEMBER, { user_id: U, role: "t1" })).status).toBe(403);
    expect((await post(REMOVE_MEMBER, { user_id: U }, "DELETE")).status).toBe(403);
  });
  it("an org instructor seated as a player (t1) still cannot end or pause", async () => {
    st.seat = { role: "t1", status: "active" };
    expect((await post(END, { mode: "now" })).status).toBe(403);
    expect((await post(PAUSE, { paused: true })).status).toBe(403);
    expect(st.calls).toEqual([]);
  });
  it("an org instructor holding a legacy instructor seat cannot end it either", async () => {
    st.seat = { role: "instructor", status: "active" };
    expect((await post(END, { mode: "now" })).status).toBe(403);
    expect(st.calls).toEqual([]);
  });
});

describe("an org admin and the platform owner pass the gate", () => {
  it("org admin: create reaches validation, end runs", async () => {
    st.orgRole = "org_admin";
    expect((await CREATE(new Request("https://x", { method: "POST", body: JSON.stringify({ company_id: "nope" }) }))).status).toBe(400);
    expect((await post(END, { mode: "now" })).status).toBe(200);
    expect(st.calls).toEqual(["transition"]);
  });
  it("platform owner with a student org role: create reaches validation", async () => {
    st.orgRole = "student"; st.platform = true;
    expect((await CREATE(new Request("https://x", { method: "POST", body: JSON.stringify({ company_id: "nope" }) }))).status).toBe(400);
  });
});
