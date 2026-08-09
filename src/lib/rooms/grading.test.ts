/**
 * Grading tests for the two task types that were graded in the BROWSER until
 * recently — matching and ordering. Both leaked their answer into the page
 * payload by construction (matching through a pair id shared by the left and
 * right item, ordering through `correct_order` plus an `items[]` array that is
 * authored in the correct sequence in 29 of 32 tasks).
 *
 * They now grade here, against shapes the client cannot reverse: matching
 * submits the right-hand TEXT (the client is never told which right item
 * belongs to which left one), ordering submits item ids in placed order.
 *
 * These tests exist because that guarantee is easy to break silently — a future
 * refactor that reintroduces an id on the right-hand item, or that starts
 * trusting a client-sent "correct" flag, would still typecheck and still look
 * fine in the UI.
 */
import { describe, it, expect } from "vitest";
import { gradeTask } from "./grading";
import type { RoomTask } from "@/data/rooms";

const matching: Extract<RoomTask, { type: "matching" }> = {
  type: "matching",
  id: "t-match",
  heading: "h",
  instructions: "i",
  xp: 40,
  explanation: "why",
  pairs: [
    { id: "a", left: "Alpha", right: "First letter" },
    { id: "b", left: "Beta", right: "Second letter" },
    { id: "c", left: "Gamma", right: "Third letter" },
    { id: "d", left: "Delta", right: "Fourth letter" },
  ],
};

const ordering: Extract<RoomTask, { type: "ordering" }> = {
  type: "ordering",
  id: "t-order",
  heading: "h",
  instructions: "i",
  xp: 40,
  explanation: "why",
  items: [
    { id: "one", text: "First" },
    { id: "two", text: "Second" },
    { id: "three", text: "Third" },
    { id: "four", text: "Fourth" },
  ],
  correct_order: ["one", "two", "three", "four"],
};

function ok(r: ReturnType<typeof gradeTask>) {
  if (!r.ok) throw new Error(`expected success, got ${r.error}`);
  return r;
}

describe("gradeTask — matching", () => {
  it("awards full XP when every right-hand text is matched to its own left item", () => {
    const r = ok(gradeTask(matching, {
      connections: { a: "First letter", b: "Second letter", c: "Third letter", d: "Fourth letter" },
    }));
    expect(r.correct).toBe(true);
    expect(r.xpEarned).toBe(40);
    expect(r.reveal.correctCount).toBe(4);
  });

  it("gives proportional partial credit and does not mark the task correct", () => {
    const r = ok(gradeTask(matching, {
      connections: { a: "First letter", b: "Second letter", c: "Fourth letter", d: "Third letter" },
    }));
    expect(r.correct).toBe(false);
    expect(r.reveal.correctCount).toBe(2);
    expect(r.xpEarned).toBe(20); // floor(40 * 2/4)
  });

  it("scores zero when nothing is connected, rather than erroring", () => {
    const r = ok(gradeTask(matching, { connections: {} }));
    expect(r.correct).toBe(false);
    expect(r.xpEarned).toBe(0);
  });

  it("rejects a submission that is not an object", () => {
    const r = gradeTask(matching, { connections: "First letter" });
    expect(r.ok).toBe(false);
  });

  it("does not accept a pair ID in place of the right-hand text", () => {
    // The old client-side check was `connections[p.id] === p.id`. If anything
    // ever reverts to id-equality this passes wrongly — so pin it.
    const r = ok(gradeTask(matching, { connections: { a: "a", b: "b", c: "c", d: "d" } }));
    expect(r.correct).toBe(false);
    expect(r.xpEarned).toBe(0);
  });

  it("only releases the solution as part of the graded response", () => {
    const r = ok(gradeTask(matching, { connections: { a: "First letter" } }));
    expect(r.reveal.solution).toHaveLength(4);
    expect(r.reveal.explanation).toBe("why");
  });
});

describe("gradeTask — ordering", () => {
  it("awards full XP for the exact sequence", () => {
    const r = ok(gradeTask(ordering, { placed: ["one", "two", "three", "four"] }));
    expect(r.correct).toBe(true);
    expect(r.xpEarned).toBe(40);
  });

  it("credits only the slots that actually hold the right item", () => {
    // First two right, last two swapped.
    const r = ok(gradeTask(ordering, { placed: ["one", "two", "four", "three"] }));
    expect(r.correct).toBe(false);
    expect(r.reveal.correctCount).toBe(2);
    expect(r.xpEarned).toBe(20);
  });

  it("scores a fully reversed sequence at zero", () => {
    const r = ok(gradeTask(ordering, { placed: ["four", "three", "two", "one"] }));
    expect(r.reveal.correctCount).toBe(0);
    expect(r.xpEarned).toBe(0);
  });

  it("handles a short or padded array without throwing", () => {
    expect(ok(gradeTask(ordering, { placed: ["one"] })).reveal.correctCount).toBe(1);
    expect(ok(gradeTask(ordering, { placed: ["one", "two", "three", "four", "five"] })).correct).toBe(true);
  });

  it("rejects a submission that is not an array", () => {
    expect(gradeTask(ordering, { placed: "one,two" }).ok).toBe(false);
  });

  it("returns the correct order only in the graded response", () => {
    const r = ok(gradeTask(ordering, { placed: ["two", "one", "three", "four"] }));
    expect(r.reveal.correctOrder).toEqual(["one", "two", "three", "four"]);
  });
});
