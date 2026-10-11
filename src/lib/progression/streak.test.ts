import { describe, it, expect } from "vitest";
import { computeStreak, collectActivityDates } from "./streak";

const NOW = new Date(2026, 8, 27, 15, 0, 0); // 27 Sep 2026, local time
const day = (offset: number) => new Date(2026, 8, 27 + offset, 12, 0, 0).toISOString();

describe("computeStreak", () => {
  it("counts consecutive days ending today", () => {
    expect(computeStreak([day(0), day(-1), day(-2)], NOW)).toBe(3);
  });
  it("stays alive through the grace day (last activity yesterday)", () => {
    expect(computeStreak([day(-1), day(-2)], NOW)).toBe(2);
  });
  it("is 0 when the last activity was two days ago", () => {
    expect(computeStreak([day(-2), day(-3)], NOW)).toBe(0);
  });
  it("multiple activities on one day count once", () => {
    expect(computeStreak([day(0), day(0), day(-1)], NOW)).toBe(2);
  });
});

describe("collectActivityDates — quizzes and lessons count toward the streak", () => {
  it("a quiz today + a lesson yesterday extend a room streak", () => {
    const dates = collectActivityDates({
      roomDates: [day(-2)],
      quizDates: [day(0)],
      lessonDates: [day(-1)],
    });
    expect(computeStreak(dates, NOW)).toBe(3);
  });
  it("drops unparseable values instead of throwing", () => {
    expect(collectActivityDates({ quizDates: ["not-a-date", day(0)] })).toEqual([day(0)]);
  });
});
