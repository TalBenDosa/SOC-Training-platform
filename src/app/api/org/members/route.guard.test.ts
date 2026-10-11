// QA phase 7, E-03: a guard whose read fails refuses — on a DB blip an org admin
// must not be able to deactivate / remove a fellow admin or the platform admin.
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgAdmin: vi.fn(async () => ({ user: { id: "admin-1", orgId: "org1" } })) }));
vi.mock("@/lib/auth/revokeSessions", () => ({ revokeUserSessions: vi.fn(async () => true) }));
const st = { failReads: true, deleted: 0 };
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: (table: string) => {
      const q: Record<string, unknown> = {};
      q.select = () => q; q.eq = () => q; q.neq = () => q; q.limit = () => q;
      q.maybeSingle = async () => (st.failReads ? { data: null, error: { message: "pooler saturated" } } : { data: table === "profiles" ? { is_platform_admin: false } : { role: "student" }, error: null });
      q.delete = () => { st.deleted++; return { eq: () => ({ eq: () => ({ select: async () => ({ data: [{ user_id: "x" }], error: null }) }) }) }; };
      q.update = () => ({ eq: () => ({ eq: async () => ({ error: null }) }) });
      return q;
    },
  }),
}));
const { DELETE } = await import("./route");
const del = async (user_id: string) => (await DELETE(new Request("https://x/api/org/members", { method: "DELETE", body: JSON.stringify({ user_id }) })))!;

beforeEach(() => { st.failReads = true; st.deleted = 0; });

describe("DELETE /api/org/members — protected-target guard", () => {
  it("refuses (503) when the protection check can't read, and deletes nothing", async () => {
    const res = await del("platform-admin-or-fellow-admin");
    expect(res.status).toBe(503);
    expect(st.deleted).toBe(0);
  });
  it("proceeds once the check can read and the target is a student", async () => {
    st.failReads = false;
    expect((await del("student-1")).status).toBe(200);
    expect(st.deleted).toBe(1);
  });
});
