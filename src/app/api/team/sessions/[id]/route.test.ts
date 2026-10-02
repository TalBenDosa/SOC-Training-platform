/**
 * QA M1: a removed (`left`) member no longer reads the session (roster, names, meta) —
 * they get 403 { removed } the room turns into "you were removed". Staff see whose
 * access to the organisation expired (`lapsed`) so a wedged ready-check can be fixed.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextResponse } from "next/server";
import { fakeAdmin, user, eqOf, type Op, type Result } from "../../_testing/fakeAdmin";

const state = {
  user: user() as ReturnType<typeof user> | null,
  handler: (_op: Op): Result => ({ data: null }),
};
vi.mock("@/lib/auth/apiGuard", () => ({
  getAuthedUser: vi.fn(async () => state.user),
  requireOrgStaff: vi.fn(async () => (state.user ? { user: state.user } : { error: NextResponse.json({}, { status: 401 }) })),
}));
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(op => state.handler(op)).client }));

const { GET } = await import("./route");
const call = () => GET(new Request("https://x/api/team/sessions/s1"), { params: Promise.resolve({ id: "s1" }) });

const SESSION = { id: "s1", org_id: "org1", status: "lobby", company_id: "nexacorp", difficulty: "medium", seed: "SECRET", scenario_id: "story-x", config: {}, schema_version: 2 };
const MEMBERS = [
  { user_id: "u-staff", role: "instructor", status: "active", ready_at: null },
  { user_id: "p1", role: "t1", status: "ready", ready_at: null },
  { user_id: "p2", role: "t2", status: "invited", ready_at: null },     // affiliation expired
  { user_id: "gone", role: "t1", status: "left", ready_at: null },      // removed
];
const tables = (op: Op): Result => {
  if (op.table === "team_sessions") return { data: SESSION };
  if (op.table === "team_session_members") return { data: MEMBERS };
  if (op.table === "profiles") return { data: [{ id: "p1", handle: "dana", display_name: "Dana" }] };
  if (op.table === "org_members") return { data: [
    { user_id: "u-staff", status: "active", affiliation_expires_at: null },
    { user_id: "p1", status: "active", affiliation_expires_at: new Date(Date.now() + 86_400_000).toISOString() },
    { user_id: "p2", status: "active", affiliation_expires_at: new Date(Date.now() - 86_400_000).toISOString() },
  ] };
  return { data: null };
};

beforeEach(() => { state.user = user(); state.handler = tables; });

describe("GET /api/team/sessions/[id]", () => {
  it("a removed member gets 403 { removed } — no roster, no session meta", async () => {
    state.user = user({ id: "gone", orgRole: "student" });
    const res = await call();
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body).toMatchObject({ removed: true });
    expect(body.roster).toBeUndefined();
    expect(body.session).toBeUndefined();
  });

  it("a stranger still gets the plain 403", async () => {
    state.user = user({ id: "nobody", orgRole: "student" });
    const res = await call();
    expect(res.status).toBe(403);
    expect((await res.json()).removed).toBeUndefined();
  });

  it("an active player reads the room — without the answer key and without anyone's affiliation state", async () => {
    state.user = user({ id: "p1", orgRole: "student" });
    const res = await call();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.session.seed).toBeUndefined();
    expect(body.roster.every((r: { lapsed?: boolean }) => r.lapsed === undefined)).toBe(true);
    expect(body.me).toMatchObject({ id: "p1", role: "t1", is_staff: false });
  });

  it("staff see which invitee's access expired (they can never mark ready)", async () => {
    const body = await (await call()).json();
    const byId = Object.fromEntries(body.roster.map((r: { user_id: string; lapsed?: boolean }) => [r.user_id, r.lapsed]));
    expect(byId).toMatchObject({ p1: false, p2: true });
    expect(byId["u-staff"]).toBeUndefined();   // the instructor row isn't judged
    expect(byId.gone).toBeUndefined();         // nor a removed member
    expect(body.session.seed).toBe("SECRET");
  });

  it("only reads org_members of the session's own org", async () => {
    const seen: Op[] = [];
    state.handler = op => { seen.push(op); return tables(op); };
    await call();
    const om = seen.find(o => o.table === "org_members");
    expect(eqOf(om!, "org_id")).toBe("org1");
  });
});
