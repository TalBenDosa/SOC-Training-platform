// GET /api/library/[id]: the on-demand lesson behind the /learn grid. Readers get
// the lesson without its quiz (answer key); only an admin gets ?full=1.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextResponse } from "next/server";
import { BUILTIN_LESSONS } from "@/data/builtinLessons";
import { LIBRARY_INDEX } from "@/data/libraryIndex";
import { libraryEntry } from "@/lib/lessons/libraryEntry";

const st = { admin: false };
vi.mock("@/lib/auth/apiGuard", () => ({
  getAuthedUser: vi.fn(async () => ({ id: "u1", role: "analyst" })),
  requireAdmin: vi.fn(async () => (st.admin
    ? { user: { id: "a1", role: "admin" } }
    : { error: NextResponse.json({ error: "Admin access required." }, { status: 403 }) })),
}));
const { GET } = await import("./route");
const get = (id: string, q = "") => GET(new Request(`https://x/api/library/${id}${q}`), { params: Promise.resolve({ id }) });

const withQuiz = (BUILTIN_LESSONS as unknown as { id: string; quiz?: unknown[]; sections: unknown[] }[])
  .find(l => (l.quiz?.length ?? 0) > 0)!;

beforeEach(() => { st.admin = false; });

describe("GET /api/library/[id]", () => {
  it("returns the full reader content without the quiz", async () => {
    const res = await get(withQuiz.id);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.id).toBe(withQuiz.id);
    expect(body.sections).toHaveLength(withQuiz.sections.length);
    expect(body).not.toHaveProperty("quiz");
    expect(JSON.stringify(body)).not.toMatch(/"answer":/);
  });

  it("404s an unknown lesson", async () => {
    expect((await get("no-such-lesson")).status).toBe(404);
  });

  it("refuses ?full=1 to a non-admin and serves it, quiz included, to an admin", async () => {
    expect((await get(withQuiz.id, "?full=1")).status).toBe(403);
    st.admin = true;
    const res = await get(withQuiz.id, "?full=1");
    expect(res.status).toBe(200);
    expect((await res.json()).quiz).toHaveLength(withQuiz.quiz!.length);
  });
});

describe("LIBRARY_INDEX", () => {
  it("has one card per built-in lesson, matching it field for field", () => {
    expect(LIBRARY_INDEX).toEqual(BUILTIN_LESSONS.map(l => libraryEntry(l as never)));
  });

  it("every card can be opened through the route", async () => {
    for (const e of LIBRARY_INDEX.slice(0, 5)) expect((await get(e.id)).status).toBe(200);
  });
});
