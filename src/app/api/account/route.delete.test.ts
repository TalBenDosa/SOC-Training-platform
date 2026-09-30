/**
 * P4-02: self-deletion is decided by MEMBERSHIP, never by the active context
 * (profiles.org_id), and a failed read never means "solo → delete now".
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => ({ id: "u1", orgId: null })) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));

const INTERNAL = "d0d0d0d0-0000-4000-8000-000000000000";
type Res = { data: unknown; error: { message: string } | null };
const state = {
  memberships: { data: [] as { org_id: string }[], error: null } as Res,
  profile: { data: { org_id: INTERNAL }, error: null } as Res,
  deleted: false,
  requestOrg: null as string | null,
};

// Minimal chainable stand-in for the service-role client: every filter returns
// the builder; awaiting it (or maybeSingle/single) resolves to the table's result.
function builder(table: string) {
  const b: Record<string, unknown> = {};
  const result = (): Res =>
    table === "org_members" ? state.memberships
    : table === "profiles" ? state.profile
    : { data: null, error: null };
  for (const m of ["select", "eq", "neq", "in", "order", "limit"]) b[m] = () => b;
  b.maybeSingle = async () => result();
  b.single = async () => result();
  b.then = (ok: (r: Res) => unknown) => Promise.resolve(result()).then(ok);
  b.insert = (row: { org_id: string }) => {
    state.requestOrg = row.org_id;
    const ins: Record<string, unknown> = {};
    ins.select = () => ins;
    ins.single = async () => ({ data: { id: "req1", requested_at: "now" }, error: null });
    return ins;
  };
  return b;
}
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: (t: string) => builder(t),
    auth: { admin: { deleteUser: vi.fn(async () => { state.deleted = true; return { error: null }; }) } },
  }),
}));

const { DELETE } = await import("./route");
const call = () => DELETE(new Request("http://x/api/account", { method: "DELETE", body: JSON.stringify({ confirm: "DELETE" }) }));

beforeEach(() => {
  state.memberships = { data: [], error: null };
  state.profile = { data: { org_id: INTERNAL }, error: null };
  state.deleted = false;
  state.requestOrg = null;
});

describe("DELETE /api/account", () => {
  it("a solo learner (no college membership) is erased now", async () => {
    const res = await call();
    expect(res.status).toBe(200);
    expect(state.deleted).toBe(true);
  });

  it("a student removed from college B but still active in A files a request — even though the active context was reset to the root", async () => {
    state.memberships = { data: [{ org_id: "college-a" }], error: null };
    state.profile = { data: { org_id: INTERNAL }, error: null };   // reset by B's removal
    const res = await call();
    expect(res.status).toBe(202);
    expect(state.deleted).toBe(false);
    expect(state.requestOrg).toBe("college-a");
  });

  it("the request goes to the college the student is working in, when enrolled there", async () => {
    state.memberships = { data: [{ org_id: "college-a" }, { org_id: "college-b" }], error: null };
    state.profile = { data: { org_id: "college-b" }, error: null };
    await call();
    expect(state.requestOrg).toBe("college-b");
  });

  it("fails closed when the membership read fails — nothing is deleted", async () => {
    state.memberships = { data: null, error: { message: "timeout" } };
    const res = await call();
    expect(res.status).toBe(503);
    expect(state.deleted).toBe(false);
  });

  it("fails closed when the profile read fails", async () => {
    state.profile = { data: null, error: { message: "timeout" } };
    const res = await call();
    expect(res.status).toBe(503);
    expect(state.deleted).toBe(false);
  });
});
