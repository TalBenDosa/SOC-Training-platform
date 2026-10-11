/**
 * SEC-04 / SEC-05: the privileged facts behind the API gates come from the DB,
 * not from a JWT that can be up to an hour stale — a removed or demoted member,
 * a revoked platform admin and a college whose licence lapsed are refused at once.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("react", async (orig) => ({ ...(await orig<typeof import("react")>()), cache: <T,>(f: T) => f }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: object) => `h.${b64(claims)}.s`;
const st = {
  claims: { org_id: "org1", org_name: "College", org_role: "org_admin", is_platform_admin: false, org_active: true } as Record<string, unknown>,
  profile: { role: "analyst", is_platform_admin: false } as Record<string, unknown> | null,
  member: { role: "org_admin", status: "active", organizations: { status: "active", expires_at: null } } as Record<string, unknown> | null,
  dbError: false,
};
vi.mock("@/lib/auth/validatedUser", () => ({
  getValidatedAuth: vi.fn(async () => ({ supabase: {}, user: { id: "u1", email: "a@b.c" }, session: { access_token: jwt(st.claims) } })),
}));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: (table: string) => {
      const q: Record<string, unknown> = {};
      q.select = () => q; q.eq = () => q;
      q.maybeSingle = async () => st.dbError ? { data: null, error: { message: "boom" } }
        : { data: table === "profiles" ? st.profile : st.member, error: null };
      return q;
    },
  }),
}));

const { getAuthedUser, requireOrgAdmin, requireOrgStaff, requireSuperAdmin } = await import("./apiGuard");

beforeEach(() => {
  st.claims = { org_id: "org1", org_name: "College", org_role: "org_admin", is_platform_admin: false, org_active: true };
  st.profile = { role: "analyst", is_platform_admin: false };
  st.member = { role: "org_admin", status: "active", organizations: { status: "active", expires_at: null } };
  st.dbError = false;
});

describe("API gates read privilege from the DB", () => {
  it("an active org admin passes", async () => {
    expect("user" in (await requireOrgAdmin())).toBe(true);
    expect(await getAuthedUser()).toMatchObject({ orgId: "org1", orgRole: "org_admin", orgActive: true });
  });

  it("a REMOVED member is refused though the token still says org_admin", async () => {
    st.member = null;
    const g = await requireOrgAdmin();
    expect("error" in g && g.error.status).toBe(403);
    expect(await getAuthedUser()).toMatchObject({ orgId: null, orgRole: null });
  });

  it("a deactivated member is refused", async () => {
    st.member = { ...st.member!, status: "removed" };
    expect("error" in (await requireOrgStaff())).toBe(true);
  });

  it("a DEMOTED admin gets the DB role, not the token's", async () => {
    st.member = { ...st.member!, role: "student" };
    expect("error" in (await requireOrgAdmin())).toBe(true);
    expect((await getAuthedUser())?.orgRole).toBe("student");
  });

  it("a revoked platform-admin flag is refused though the token still carries it", async () => {
    st.claims.is_platform_admin = true;
    st.profile = { role: "analyst", is_platform_admin: false };
    expect("error" in (await requireSuperAdmin())).toBe(true);
    st.profile = { role: "analyst", is_platform_admin: true };
    expect("user" in (await requireSuperAdmin())).toBe(true);
  });

  it.each([
    ["suspended", { status: "suspended", expires_at: null }],
    ["expired by date", { status: "active", expires_at: "2020-01-01T00:00:00Z" }],
  ])("a %s college's staff are refused with the licence message", async (_l, org) => {
    st.member = { ...st.member!, organizations: org };
    const g = await requireOrgStaff();
    expect("error" in g).toBe(true);
    if ("error" in g) { expect(g.error.status).toBe(403); expect((await g.error.json()).error).toMatch(/licence/); }
  });

  it("a DB read error grants nothing (fail closed)", async () => {
    st.dbError = true;
    st.claims.is_platform_admin = true;
    expect("error" in (await requireSuperAdmin())).toBe(true);
    expect("error" in (await requireOrgAdmin())).toBe(true);
  });
});
