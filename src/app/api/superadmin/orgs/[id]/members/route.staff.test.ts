// SEC-02: attaching an existing account by email can never grant a staff role —
// neither from the super-admin console nor from a college admin's roster.
import { describe, it, expect, vi } from "vitest";

const rpc = vi.fn(async () => ({ data: "user-1", error: null }));
vi.mock("@/lib/auth/apiGuard", () => ({
  requireSuperAdmin: vi.fn(async () => ({ user: { id: "tal" } })),
  requireOrgAdmin: vi.fn(async () => ({ user: { id: "admin-1", orgId: "org1" } })),
}));
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => ({ rpc, from: () => ({}) }) }));

const superadmin = await import("./route");
const org = await import("@/app/api/org/members/route");
const req = (body: unknown) => new Request("https://x", { method: "POST", body: JSON.stringify(body) });

describe("attach-by-email never grants a staff role", () => {
  it.each(["org_admin", "instructor"])("super-admin console refuses %s", async role => {
    const res = await superadmin.POST(req({ email: "head@college.ac.il", role }), { params: Promise.resolve({ id: "org1" }) });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/emailed invitation/);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("college admin roster refuses instructor", async () => {
    const res = (await org.POST(req({ email: "t@college.ac.il", role: "instructor" })))!;
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/emailed invitation/);
    expect(rpc).not.toHaveBeenCalled();
  });
});
