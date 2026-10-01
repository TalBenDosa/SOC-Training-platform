// QA phase 7, E-06: /api/health?deep=1 reports the database, as up/down only.
import { describe, it, expect, vi, beforeEach } from "vitest";

const st = { fail: false };
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: () => {
      const q: Record<string, unknown> = {};
      q.select = () => q; q.limit = () => q;
      q.abortSignal = async () => (st.fail ? { error: { message: "relation secret does not exist" } } : { error: null });
      return q;
    },
  }),
}));
const { GET } = await import("./route");
beforeEach(() => { st.fail = false; vi.spyOn(console, "error").mockImplementation(() => {}); });

describe("GET /api/health", () => {
  it("shallow by default", async () => {
    const res = await GET(new Request("https://x/api/health"));
    expect(res.status).toBe(200);
    expect((await res.json()).db).toBeUndefined();
  });
  it("deep: ok, then 503 without leaking the error", async () => {
    expect((await GET(new Request("https://x/api/health?deep=1"))).status).toBe(200);
    st.fail = true;
    const res = await GET(new Request("https://x/api/health?deep=1"));
    expect(res.status).toBe(503);
    expect(JSON.stringify(await res.json())).not.toMatch(/secret/);
  });
});
