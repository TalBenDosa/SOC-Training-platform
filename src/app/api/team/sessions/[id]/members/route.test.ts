/**
 * Roster changes: QA M1 (an invitee whose affiliation expired is not addable; removing
 * a member is the staff's way past a no-show) and QA L1 (a lost race for a single seat
 * or the 60-member cap is a 409 with the reason, never a generic 500).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextResponse } from "next/server";
import { fakeAdmin, user, type Op, type Result } from "../../../_testing/fakeAdmin";
import { rosterConflict, MAX_ROSTER } from "@/lib/team/roster";

const state = {
  user: user() as ReturnType<typeof user> | null,
  handler: (_op: Op): Result => ({ data: null }),
  events: [] as { type: string; payload: unknown }[],
};
vi.mock("@/lib/auth/apiGuard", () => ({
  requireOrgStaff: vi.fn(async () => (state.user ? { user: state.user } : { error: NextResponse.json({}, { status: 401 }) })),
}));
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(op => state.handler(op)).client }));
vi.mock("@/lib/team/appendSystemEvent", () => ({ appendSystemEvent: vi.fn(async (_s: string, type: string, payload: unknown) => { state.events.push({ type, payload }); return { ok: true, seq: 1 }; }) }));
vi.mock("server-only", () => ({}));

const { POST, DELETE } = await import("./route");
const post = async (body: unknown) => (await POST(new Request("https://x/api/team/sessions/s1/members", { method: "POST", body: JSON.stringify(body) }), { params: Promise.resolve({ id: "s1" }) })) as Response;
const del = async (uid: string) => (await DELETE(new Request(`https://x/api/team/sessions/s1/members?user_id=${uid}`, { method: "DELETE" }), { params: Promise.resolve({ id: "s1" }) })) as Response;

const ROSTER = [{ user_id: "u-staff", role: "instructor", status: "active" }, { user_id: "p1", role: "t1", status: "invited" }];
function tables(over: { orgMember?: unknown; insertError?: Result["error"]; roster?: unknown[] } = {}) {
  return (op: Op): Result => {
    if (op.table === "team_sessions") return { data: { id: "s1", org_id: "org1", status: "lobby" } };
    if (op.table === "org_members") return { data: over.orgMember === undefined ? { user_id: "new" } : over.orgMember };
    if (op.table === "team_session_members") {
      if (op.action === "insert") return { error: over.insertError ?? null };
      if (op.action === "update") return { error: null };
      if (op.single) { const uid = op.filters.find(f => f[1] === "user_id")?.[2]; return { data: (over.roster ?? ROSTER).find(r => (r as { user_id: string }).user_id === uid) ?? null }; }
      return { data: over.roster ?? ROSTER };
    }
    return { data: null };
  };
}

beforeEach(() => { state.user = user(); state.handler = tables(); state.events = []; });

describe("POST /members", () => {
  it("adds an active member and announces it", async () => {
    const res = await post({ user_id: "new", role: "t1" });
    expect(res.status).toBe(200);
    expect(state.events.map(e => e.type)).toEqual(["member.added"]);
  });

  it("M1: an invitee whose affiliation expired is refused (the org_members read filters on it)", async () => {
    const seen: Op[] = [];
    const t = tables({ orgMember: null });
    state.handler = op => { seen.push(op); return t(op); };
    const res = await post({ user_id: "lapsed", role: "t1" });
    expect(res.status).toBe(400);
    const om = seen.find(o => o.table === "org_members")!;
    expect(om.filters.some(f => f[0] === "or" && /affiliation_expires_at\.is\.null/.test(f[1]))).toBe(true);
  });

  it("L1: losing the race for a single seat (unique index) is a 409, not a 500", async () => {
    state.handler = tables({ insertError: { code: "23505", message: 'duplicate key value violates unique constraint "team_session_single_seat"' } });
    const res = await post({ user_id: "new", role: "mgr" });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/single-seat/);
  });

  it("L1: the DB roster cap (trigger) is a 409 with the reason", async () => {
    state.handler = tables({ insertError: { code: "P0001", message: "roster_full: a session holds at most 60 members" } });
    const res = await post({ user_id: "new", role: "t1" });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toContain(String(MAX_ROSTER));
  });

  it("any other write error stays a 500", async () => {
    state.handler = tables({ insertError: { code: "08006", message: "connection failure" } });
    expect((await post({ user_id: "new", role: "t1" })).status).toBe(500);
  });
});

describe("DELETE /members (the lobby / instructor Remove button)", () => {
  it("removes a no-show: status → left + member.removed", async () => {
    const seen: Op[] = [];
    const t = tables();
    state.handler = op => { seen.push(op); return t(op); };
    const res = await del("p1");
    expect(res.status).toBe(200);
    expect(seen.find(o => o.action === "update")?.payload).toEqual({ status: "left" });
    expect(state.events.map(e => e.type)).toEqual(["member.removed"]);
  });
  it("never removes the session owner", async () => {
    expect((await del("u-staff")).status).toBe(409);
  });
});

describe("rosterConflict", () => {
  it("maps only roster conflicts", () => {
    expect(rosterConflict(null, "t1")).toBeNull();
    expect(rosterConflict({ code: "23505", message: "team_session_members_pkey" }, "t1")).toMatch(/already on this session/);
    expect(rosterConflict({ code: "42P01", message: "nope" }, "t1")).toBeNull();
  });
});
