// QA phase 7, E-19: the reply is saved BEFORE it is emailed, and a failed send
// puts the save back — so a retry can never email the reporter twice.
import { describe, it, expect, vi, beforeEach } from "vitest";

const st = { log: [] as string[], sendOk: true, updates: [] as Record<string, unknown>[] };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => ({ id: "staff-1", role: "admin", isPlatformAdmin: false })) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));
vi.mock("@/lib/email/sendEmail", () => ({
  sendEmail: vi.fn(async () => { st.log.push("send"); return st.sendOk ? { ok: true } : { ok: false, error: "HTTP 503" }; }),
}));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    auth: { admin: { getUserById: async () => ({ data: { user: { email: "r@x.edu" } }, error: null }) } },
    from: () => {
      const q: Record<string, unknown> = {};
      q.select = () => q; q.eq = () => q;
      q.maybeSingle = async () => ({ data: { id: "f1", user_id: "u1", message: "typo", status: "open", admin_response: null, responded_at: null, responded_by: null }, error: null });
      q.update = (patch: Record<string, unknown>) => { st.updates.push(patch); st.log.push(patch.status === "resolved" ? "save" : "undo"); return { eq: async () => ({ error: null }) }; };
      return q;
    },
  }),
}));
const { POST } = await import("./route");
const reply = () => POST(new Request("https://x/api/feedback/f1/reply", { method: "POST", body: JSON.stringify({ message: "Fixed, thanks!" }) }), { params: Promise.resolve({ id: "f1" }) });

beforeEach(() => { st.log = []; st.updates = []; st.sendOk = true; });

describe("POST /api/feedback/[id]/reply", () => {
  it("saves, then sends", async () => {
    const res = await reply();
    expect(res.status).toBe(200);
    expect(st.log).toEqual(["save", "send"]);
  });
  it("a failed send puts the previous values back and says nothing was saved", async () => {
    st.sendOk = false;
    const res = await reply();
    expect(res.status).toBe(502);
    expect(st.log).toEqual(["save", "send", "undo"]);
    expect(st.updates[1]).toEqual({ admin_response: null, responded_at: null, responded_by: null, status: "open" });
    expect((await res.json()).error).toMatch(/wasn't saved/);
  });
});
