/**
 * SEC-02: an existing account gets a role only by accepting an EMAILED invitation
 * while signed in as the address it names — and every other session of the
 * account (a squatter's) is signed out.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const DAY = 86_400_000;
const state = {
  user: { id: "u1", email: "Head@College.ac.il" } as { id: string; email: string } | null,
  invite: null as null | Record<string, unknown>,
  claimed: true,
  attachError: null as null | { message: string },
  updates: [] as Record<string, unknown>[],
  attachArgs: null as null | Record<string, unknown>,
  signOut: [] as [string, string][],
};
vi.mock("@/lib/auth/validatedUser", () => ({
  getValidatedAuth: vi.fn(async () => (state.user ? { user: state.user, session: { access_token: "jwt-of-this-session" } } : null)),
}));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: () => {
      const b: Record<string, unknown> = {};
      let updating: Record<string, unknown> | null = null;
      b.select = () => b; b.eq = () => b;
      b.is = () => b;
      b.maybeSingle = async () => ({ data: state.invite, error: null });
      b.update = (row: Record<string, unknown>) => { updating = row; state.updates.push(row); return b; };
      // update(...).eq(...).is(...).select("id") → claim result; update(...).eq(...) (revert) awaited directly
      const origSelect = b.select;
      b.select = (...a: unknown[]) => (updating ? Promise.resolve({ data: state.claimed ? [{ id: "inv1" }] : [], error: null }) : (origSelect as (...x: unknown[]) => unknown)(...a));
      (b as { then?: unknown }).then = undefined;
      return b;
    },
    rpc: async (_fn: string, args: Record<string, unknown>) => { state.attachArgs = args; return { error: state.attachError }; },
    auth: { admin: { signOut: async (jwt: string, scope: string) => { state.signOut.push([jwt, scope]); return { error: null }; } } },
  }),
}));

const { POST } = await import("./route");
const call = () => POST(new Request("https://x/api/invitations/tok/accept", { method: "POST" }), { params: Promise.resolve({ token: "tok" }) });
const invite = (over: Record<string, unknown> = {}) => ({ id: "inv1", org_id: "org1", email: "head@college.ac.il", role: "org_admin", expires_at: new Date(Date.now() + 5 * DAY).toISOString(), accepted_at: null, ...over });

beforeEach(() => {
  state.user = { id: "u1", email: "Head@College.ac.il" }; state.invite = invite(); state.claimed = true;
  state.attachError = null; state.updates = []; state.attachArgs = null; state.signOut = [];
});

describe("POST /api/invitations/[token]/accept", () => {
  it("grants the invited role to the signed-in owner of the address and signs out every OTHER session", async () => {
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, orgId: "org1", role: "org_admin" });
    expect(state.attachArgs).toMatchObject({ p_org: "org1", p_user: "u1", p_role: "org_admin", p_affiliation_expires: null });
    expect(state.signOut).toEqual([["jwt-of-this-session", "others"]]);
  });

  it("refuses when signed in as a different address (the email check is case-insensitive)", async () => {
    state.user = { id: "u2", email: "someone@else.com" };
    const res = await call();
    expect(res.status).toBe(403);
    expect(state.attachArgs).toBeNull();
    expect(state.updates).toEqual([]);
  });

  it("refuses an invitation without a recipient — a forwardable link proves nothing", async () => {
    state.invite = invite({ email: null });
    expect((await call()).status).toBe(400);
    expect(state.attachArgs).toBeNull();
  });

  it("refuses an expired or already-used invitation, and an unknown token", async () => {
    state.invite = invite({ expires_at: new Date(Date.now() - DAY).toISOString() });
    expect((await call()).status).toBe(410);
    state.invite = invite({ accepted_at: new Date().toISOString() });
    expect((await call()).status).toBe(410);
    state.invite = null;
    expect((await call()).status).toBe(410);
    expect(state.attachArgs).toBeNull();
  });

  it("loses the race cleanly when a parallel request consumed it first", async () => {
    state.claimed = false;
    expect((await call()).status).toBe(410);
    expect(state.attachArgs).toBeNull();
  });

  it("gives the invitation back when the seat limit blocks the attach", async () => {
    state.attachError = { message: "seat_limit_reached" };
    expect((await call()).status).toBe(409);
    expect(state.updates.at(-1)).toEqual({ accepted_at: null });
    expect(state.signOut).toEqual([]);
  });

  it("401 without a session", async () => {
    state.user = null;
    expect((await call()).status).toBe(401);
  });
});
