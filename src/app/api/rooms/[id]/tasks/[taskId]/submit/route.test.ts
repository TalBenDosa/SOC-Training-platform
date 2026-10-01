/**
 * QA phase 7, E-04: an attempt is claimed only for an answer that can be graded,
 * and a claimed attempt whose save failed is given back — neither a malformed body
 * nor a server-side save failure may cost the student their first-try XP.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => ({ id: "stu", orgId: "org1" })), canPreviewDrafts: () => false }));
const room = { id: "room-1", tasks: [{ type: "question", id: "q1", question: "?", options: ["a", "b"], answer: 1, explanation: "", xp: 20 }] };
vi.mock("@/lib/rooms/resolve", () => ({ getEffectiveRoom: vi.fn(async () => room) }));

const st = { claims: 0, insertError: null as null | { message: string }, released: [] as Record<string, unknown>[] };
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    rpc: async () => { st.claims++; return { data: st.claims, error: null }; },
    from: (table: string) => {
      if (table === "task_attempts") return { insert: async () => ({ error: st.insertError }) };
      const filter: Record<string, unknown> = {};
      const chain = { eq: (k: string, v: unknown) => { filter[k] = v; return chain; }, then: (r: (x: { error: null }) => void) => { st.released.push(filter); r({ error: null }); } };
      return { update: (row: Record<string, unknown>) => { filter.set = row; return chain; } };
    },
  }),
}));

const { POST } = await import("./route");
const call = (body: unknown) => POST(new Request("https://x/api/rooms/room-1/tasks/q1/submit", { method: "POST", body: JSON.stringify(body) }), { params: Promise.resolve({ id: "room-1", taskId: "q1" }) });

beforeEach(() => { st.claims = 0; st.insertError = null; st.released = []; });

describe("POST /api/rooms/[id]/tasks/[taskId]/submit", () => {
  it("a malformed answer is refused BEFORE an attempt is claimed — the next real answer is still the first try", async () => {
    expect((await call({})).status).toBe(400);
    expect(st.claims).toBe(0);
    const res = await call({ selectedIndex: 1 });
    expect(res.status).toBe(200);
    expect((await res.json()).xpEarned).toBe(20);       // full first-try XP
  });

  it("a failed save gives the claimed attempt back", async () => {
    st.insertError = { message: "db down" };
    expect((await call({ selectedIndex: 1 })).status).toBe(503);
    expect(st.released).toHaveLength(1);
    expect(st.released[0]).toMatchObject({ set: { n: 0 }, user_id: "stu", room_id: "room-1", task_id: "q1", qidx: -1, n: 1 });
  });
});
