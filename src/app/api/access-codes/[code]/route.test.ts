// QA phase 7: E-16 (double decode → URIError 500, reproduced in production on
// /api/access-codes/%25) and E-11 (a failed read answered {valid:false}, so the
// signup page told the student their code was dead).
import { describe, it, expect, vi, beforeEach } from "vitest";

const st = { fail: false };
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    from: () => {
      const q: Record<string, unknown> = {};
      q.select = () => q; q.eq = () => q; q.gt = () => q;
      q.maybeSingle = async () => (st.fail ? { data: null, error: { message: "pooler" } } : { data: null, error: null });
      return q;
    },
    rpc: async () => ({ data: 0, error: null }),
  }),
}));
const { GET } = await import("./route");
const get = (code: string) => GET(new Request(`https://x/api/access-codes/${code}`), { params: Promise.resolve({ code }) });

beforeEach(() => { st.fail = false; });

describe("GET /api/access-codes/[code]", () => {
  it.each(["%", "%ZZ", "%25"])("a stray %% in the code (%s) is just invalid, not a 500", async code => {
    const res = await get(code);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ valid: false });
  });
  it("a failed read is 503 \"couldn't check\", not {valid:false}", async () => {
    st.fail = true;
    const res = await get("K7MRW3TQ");
    expect(res.status).toBe(503);
  });
  it("an unknown code is still {valid:false}", async () => {
    expect(await (await get("K7MRW3TQ")).json()).toEqual({ valid: false });
  });
});
