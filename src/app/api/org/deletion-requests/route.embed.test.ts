// The /manage deletion queue failed on every load: account_deletion_requests
// references profiles twice (user_id, decided_by), so a bare profiles(...) embed is
// ambiguous (PostgREST PGRST201). The embed must name the user_id foreign key.
import { describe, it, expect, vi } from "vitest";

let selected = "";
vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgAdmin: vi.fn(async () => ({ user: { id: "admin-1", orgId: "org-1" } })) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn() }));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: () => {
      const b: Record<string, unknown> = {};
      b.select = (s: string) => { selected = s; return b; };
      for (const m of ["eq", "order"]) b[m] = () => b;
      b.then = (res: (v: unknown) => unknown) => res({
        data: [{ id: "r1", user_id: "u1", status: "pending", reason: null, requested_at: new Date().toISOString(), profiles: { handle: "dana", display_name: "Dana" } }],
        error: null,
      });
      return b;
    },
  }),
}));

describe("GET /api/org/deletion-requests", () => {
  it("embeds the requester's profile through the user_id foreign key", async () => {
    const { GET } = await import("./route");
    const res = (await GET())!;
    expect(res.status).toBe(200);
    expect(selected).toContain("profiles!account_deletion_requests_user_id_fkey(");
    const { requests } = await res.json();
    expect(requests[0]).toMatchObject({ handle: "dana", display_name: "Dana" });
  });
});
