// SEC-16: a college can't mail more than its daily invitation budget.
import { describe, it, expect, vi, beforeEach } from "vitest";

let sentToday = 0;
const inserted: unknown[] = [];
vi.mock("@/lib/auth/apiGuard", () => ({ requireOrgAdmin: vi.fn(async () => ({ user: { id: "a", orgId: "org1" } })) }));
vi.mock("@/lib/email/sendEmail", () => ({ sendEmailBatch: vi.fn(async (m: unknown[]) => ({ sent: m.map(() => true) })) }));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: () => {
      const q: Record<string, unknown> = {};
      q.select = (_c: string, opts?: { head?: boolean }) => (opts?.head ? { eq: () => ({ gte: async () => ({ count: sentToday, error: null }) }) } : q);
      q.eq = () => q;
      q.maybeSingle = async () => ({ data: { name: "College" }, error: null });
      q.insert = (rows: unknown[]) => { inserted.push(...rows); return { select: async () => ({ data: (rows as { email: string; token: string }[]).map((r, i) => ({ id: `i${i}`, ...r })), error: null }) }; };
      return q;
    },
  }),
}));
const { POST } = await import("./route");
const call = (emails: string[]) => POST(new Request("https://www.hackthesoc.app/api/org/invites", { method: "POST", body: JSON.stringify({ emails }) }));

beforeEach(() => { sentToday = 0; inserted.length = 0; });

describe("org invitation daily budget", () => {
  it("sends while under the budget", async () => {
    sentToday = 10;
    expect((await call(["a@x.com", "b@x.com"])).status).toBe(201);
    expect(inserted).toHaveLength(2);
  });
  it("refuses a batch that would cross the 24-hour budget, saying how many are left", async () => {
    sentToday = 299;
    const res = await call(["a@x.com", "b@x.com"]);
    expect(res.status).toBe(429);
    expect((await res.json()).error).toMatch(/1 left/);
    expect(inserted).toHaveLength(0);
  });
});
