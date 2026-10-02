/**
 * POST /api/team/sessions: duplicate invitees are de-duplicated (QA L12), two people
 * on a single seat are refused up front, expired affiliations are filtered (M1), and a
 * pinned storyline is judged on the instantiated story (M7).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, user, type Op, type Result } from "../_testing/fakeAdmin";

vi.mock("server-only", () => ({}));
const state = { fits: true, ops: [] as Op[], rosterError: null as Result["error"] };
vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgStaff: vi.fn(async () => ({ user: user() })), getAuthedUser: vi.fn(async () => user()) }));
vi.mock("@/lib/team/buildTimeline", () => ({
  resolveTeamStory: vi.fn((_c: string, _d: string, id: string | null) => (id === "known" ? { id, events: [] } : null)),
  teamStoryFilter: vi.fn(() => () => state.fits),
}));
const A = "11111111-1111-4111-8111-111111111111", B = "22222222-2222-4222-8222-222222222222";
const handler = (op: Op): Result => {
  state.ops.push(op);
  if (op.table === "org_members") return { data: [{ user_id: A }, { user_id: B }] };
  if (op.table === "team_sessions" && op.action === "insert") return { data: { id: "s-new" } };
  if (op.table === "team_session_members" && op.action === "insert") return { error: state.rosterError };
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => fakeAdmin(handler).client }));

const { POST } = await import("./route");
const create = (body: Record<string, unknown>) => POST(new Request("https://x", { method: "POST", body: JSON.stringify({ company_id: "nexacorp", difficulty: "medium", ...body }) }));
const rosterRows = () => state.ops.find(o => o.table === "team_session_members" && o.action === "insert")?.payload as { user_id: string; role: string }[];

beforeEach(() => { state.fits = true; state.ops = []; state.rosterError = null; });

describe("POST /api/team/sessions", () => {
  it("a named organization: English-only, validated on the server, stored on the template environment", async () => {
    const bad = await create({ tenant_name: "אקמה", invites: [{ user_id: A, role: "t1" }] });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toMatch(/English/);
    expect(state.ops.some(o => o.action === "insert")).toBe(false);
    expect((await create({ tenant_name: "nexacorp" })).status).toBe(400);   // a Live-SOC demo company's name
    const ok = await create({ company_id: "medcore", tenant_name: "Acme-Labs", invites: [{ user_id: A, role: "t1" }] });
    expect(ok.status).toBe(200);
    const row = state.ops.find(o => o.table === "team_sessions" && o.action === "insert")!.payload as { company_id: string; config: { tenant?: { name: string } } };
    expect(row.company_id).toBe("nexacorp");                 // the template, whatever company_id was sent
    expect(row.config.tenant).toEqual({ name: "Acme-Labs" });
  });

  it("L12: a repeated invitee becomes one roster row (the first role wins)", async () => {
    const res = await create({ invites: [{ user_id: A, role: "t1" }, { user_id: A, role: "t2" }, { user_id: B, role: "t2" }] });
    expect(res.status).toBe(200);
    expect(rosterRows().map(r => `${r.user_id}:${r.role}`)).toEqual([expect.stringMatching(/:instructor$/), `${A}:t1`, `${B}:t2`]);
  });

  it("two people on one single seat → 400 before anything is written", async () => {
    const res = await create({ invites: [{ user_id: A, role: "mgr" }, { user_id: B, role: "mgr" }] });
    expect(res.status).toBe(400);
    expect(state.ops.some(o => o.action === "insert")).toBe(false);
  });

  it("M1: invitees are checked against unexpired affiliations", async () => {
    await create({ invites: [{ user_id: A, role: "t1" }] });
    const om = state.ops.find(o => o.table === "org_members")!;
    expect(om.filters.some(f => f[0] === "or" && /affiliation_expires_at\.gt\./.test(f[1]))).toBe(true);
  });

  it("M7: a pinned storyline that doesn't fit (instantiated) → 400", async () => {
    state.fits = false;
    expect((await create({ scenario_id: "known" })).status).toBe(400);
    expect((await create({ scenario_id: "unknown" })).status).toBe(400);
    state.fits = true;
    expect((await create({ scenario_id: "known" })).status).toBe(200);
  });

  it("a roster conflict at insert is a 409 (and the half-made session is deleted)", async () => {
    state.rosterError = { code: "23505", message: 'duplicate key value violates unique constraint "team_session_single_seat"' };
    const res = await create({ invites: [{ user_id: A, role: "t1" }] });
    expect(res.status).toBe(409);
    expect(state.ops.some(o => o.table === "team_sessions" && o.action === "delete")).toBe(true);
  });
});
