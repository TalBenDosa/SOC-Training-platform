import { describe, it, expect } from "vitest";
import { retryXp, readingXp, taskMaxXp } from "./xp";
import type { RoomTask } from "@/data/rooms";

describe("retryXp", () => {
  it("question / analyst_choice: tries 1–2 keep the XP grading.ts computed, try 3+ pays nothing", () => {
    expect(retryXp("question", 20, 1)).toBe(20);
    expect(retryXp("question", 10, 2)).toBe(10);          // grading.ts already halved it
    expect(retryXp("question", 10, 3)).toBe(0);            // the 2nd wrong try revealed the answer
    expect(retryXp("analyst_choice", 30, 7)).toBe(0);
  });
  it("answer-revealing types pay half after the first try", () => {
    expect(retryXp("matching", 30, 1)).toBe(30);
    expect(retryXp("matching", 30, 2)).toBe(15);
    expect(retryXp("written_report", 25, 5)).toBe(12);
  });
  it("flags reveal nothing and keep full XP on any try", () => {
    expect(retryXp("flag", 40, 9)).toBe(40);
  });
});

describe("taskMaxXp / readingXp", () => {
  it("reading awards engagement XP (content value or 5) and counts 0 toward passing", () => {
    const r = { id: "r", type: "reading", title: "t", content: "c" } as unknown as RoomTask;
    expect(taskMaxXp(r)).toBe(0);
    expect(readingXp(r)).toBe(5);
    expect(readingXp({ ...r, xp: 8 } as unknown as RoomTask)).toBe(8);
  });
  it("log_analysis max = sum of its questions", () => {
    const t = { id: "l", type: "log_analysis", questions: [{ xp: 10 }, { xp: 15 }] } as unknown as RoomTask;
    expect(taskMaxXp(t)).toBe(25);
  });
});
