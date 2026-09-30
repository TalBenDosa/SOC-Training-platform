import { describe, it, expect } from "vitest";
import { firstAnswerXp, sumFirstAnswerXp, lessonXpFromFirstAnswers } from "./firstAnswers";

describe("firstAnswerXp", () => {
  it("pays full XP when correct on the first graded answer", () => {
    expect(firstAnswerXp(20, true, true)).toBe(20);
  });
  it("pays half (rounded down) when correct now but wrong the first time", () => {
    expect(firstAnswerXp(20, true, false)).toBe(10);
    expect(firstAnswerXp(15, true, false)).toBe(7);
  });
  it("pays nothing when wrong now, whatever the first answer was", () => {
    expect(firstAnswerXp(20, false, true)).toBe(0);
    expect(firstAnswerXp(20, false, false)).toBe(0);
  });
  it("treats no record as a first answer (full credit when correct)", () => {
    expect(firstAnswerXp(20, true, undefined)).toBe(20);
  });
  it("never pays for zero / invalid XP", () => {
    expect(firstAnswerXp(0, true, true)).toBe(0);
    expect(firstAnswerXp(Number.NaN, true, true)).toBe(0);
  });
});

describe("sumFirstAnswerXp", () => {
  it("combines per-question results — harvest-then-resubmit earns half on the missed ones", () => {
    const first = new Map([["q1", true], ["q2", false], ["q3", false]]);
    const items = [
      { questionId: "q1", xp: 10, correct: true },   // known first time → 10
      { questionId: "q2", xp: 10, correct: true },   // learned from the reveal → 5
      { questionId: "q3", xp: 10, correct: false },  // still wrong → 0
    ];
    expect(sumFirstAnswerXp(items, first)).toBe(15);
  });
});

describe("lessonXpFromFirstAnswers", () => {
  it("full XP for a first-try pass (≥ 70% of first answers right)", () => {
    expect(lessonXpFromFirstAnswers(50, [true, true, true, false])).toBe(50);
    expect(lessonXpFromFirstAnswers(50, [true, true, true, true, true, true, true, false, false, false])).toBe(50);
  });
  it("half XP when the pass came only after the key was revealed", () => {
    expect(lessonXpFromFirstAnswers(50, [true, false, false])).toBe(25);
    expect(lessonXpFromFirstAnswers(25, [false])).toBe(12);
  });
  it("full XP when no first answers are on record (pass recorded before 0078)", () => {
    expect(lessonXpFromFirstAnswers(50, [])).toBe(50);
  });
});
