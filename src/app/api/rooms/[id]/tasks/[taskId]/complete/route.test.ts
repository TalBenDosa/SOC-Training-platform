// Learner reports (Oct 2026): a room stuck on "Almost there" after the missed
// tasks were answered correctly in a review. The server now passes the room on
// mastery (src/lib/rooms/mastery.ts) while XP keeps its retry reductions.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ROOMS } from "@/data/rooms";
import { ROOM_PASS_THRESHOLD, taskMaxXp } from "@/lib/rooms/xp";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/apiGuard", () => ({
  getAuthedUser: vi.fn(async () => ({ id: "u1", orgId: null, affiliationExpired: false })),
  canPreviewDrafts: () => false,
}));
const room = ROOMS.find(r => r.id === "exchange-online-security")!;
vi.mock("@/lib/rooms/resolve", () => ({ getEffectiveRoom: vi.fn(async () => room) }));

let attempts: { task_id: string; xp_awarded: number; question_index: number | null; correct: boolean }[] = [];
const rpc = vi.fn(async () => ({ data: [{ task_xp: 0, room_xp: 0, room_completed_at: null, newly_completed: false }], error: null }));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({
    rpc,
    from: (t: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "limit", "or", "order"]) b[m] = () => b;
      b.maybeSingle = async () => ({ data: { xp: 0 }, error: null });
      b.then = (res: (v: unknown) => unknown) => res({ data: t === "task_attempts" ? attempts : [], error: null });
      return b;
    },
  }),
}));

const { POST } = await import("./route");
const call = (taskId: string) => POST(new Request("https://x/api", { method: "POST", body: "{}" }), { params: Promise.resolve({ id: room.id, taskId }) });
const threshold = () => (rpc.mock.calls.at(-1) as unknown as [string, { p_pass_threshold: number }])[1].p_pass_threshold;

beforeEach(() => { rpc.mockClear(); attempts = []; });

describe("room completion decides the pass on mastery", () => {
  const graded = room.tasks.filter(t => taskMaxXp(t) > 0);

  it("misses corrected on retries (0 / half XP) → the DB is told the room passes", async () => {
    for (const t of graded) {
      if (t.type === "log_analysis") t.questions.forEach((_, qi) => attempts.push(
        { task_id: t.id, xp_awarded: 0, question_index: qi, correct: false },
        { task_id: t.id, xp_awarded: 0, question_index: qi, correct: true },
      ));
      else attempts.push(
        { task_id: t.id, xp_awarded: 0, question_index: null, correct: false },
        { task_id: t.id, xp_awarded: 0, question_index: null, correct: true },
      );
    }
    const res = await call(graded.at(-1)!.id);
    expect(res.status).toBe(200);
    expect(threshold()).toBe(0);
  });

  it("tasks still wrong → the normal 65% gate stays", async () => {
    for (const t of graded) attempts.push({ task_id: t.id, xp_awarded: 0, question_index: t.type === "log_analysis" ? 0 : null, correct: false });
    await call(graded[0].id);
    expect(threshold()).toBe(ROOM_PASS_THRESHOLD);
  });

  it("the task's XP is still the best XP awarded, not the pass credit", async () => {
    const q = graded.find(t => t.type === "question")!;
    attempts.push({ task_id: q.id, xp_awarded: 0, question_index: null, correct: true });
    await call(q.id);
    expect((rpc.mock.calls.at(-1) as unknown as [string, { p_task_xp: number }])[1].p_task_xp).toBe(0);
  });
});

describe("the response carries the server's pass credit (QA-ROOM-2/12)", () => {
  it("a log-analysis task corrected question by question across runs gets full credit", async () => {
    const la = room.tasks.find(t => t.type === "log_analysis");
    if (!la || la.type !== "log_analysis") throw new Error("expected a log_analysis task");
    // run 1: Q1 right, Q2 wrong. run 2: Q1 wrong, Q2 right. Both were answered correctly once.
    attempts.push(
      { task_id: la.id, xp_awarded: la.questions[0].xp, question_index: 0, correct: true },
      { task_id: la.id, xp_awarded: 0, question_index: 1, correct: true },
    );
    const res = await call(la.id);
    const body = await res.json() as { perTaskCredit: Record<string, number>; passPct: number };
    expect(body.perTaskCredit[la.id]).toBe(la.questions.reduce((s, q) => s + q.xp, 0));
    expect(typeof body.passPct).toBe("number");
  });
});
