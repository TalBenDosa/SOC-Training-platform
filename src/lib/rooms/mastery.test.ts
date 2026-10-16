// Learner reports (Oct 2026): "it won't let me pass even when I answer everything
// right, it says 59%". The 65% gate now counts mastery: a task answered correctly
// at any point counts in full, while XP keeps its retry reductions.
import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { ROOM_PASS_THRESHOLD, retryXp, taskMaxXp } from "./xp";
import { roomPassScore, taskPassCredit, type GradedAttempt } from "./mastery";
import { mergeRoomEntry, roomScoreXp } from "./progressMerge";

const room = ROOMS.find(r => r.id === "encoding-encryption-hashing")!;
const graded = room.tasks.filter(t => taskMaxXp(t) > 0);
const att = (task_id: string, correct: boolean, xp: number, question_index: number | null = null): GradedAttempt =>
  ({ task_id, correct, xp_awarded: xp, question_index });

describe("room pass credit (mastery)", () => {
  it("the reported room is graded", () => {
    expect(room).toBeTruthy();
    expect(graded.length).toBeGreaterThan(3);
  });

  it("a first run below the gate, then every miss corrected on a retry → passes, though XP stayed low", () => {
    const attempts: GradedAttempt[] = [];
    let xp = 0;
    graded.forEach((t, i) => {
      const max = taskMaxXp(t);
      if (t.type === "log_analysis") {
        t.questions.forEach((q, qi) => {
          const first = i % 2 === 0;           // half the tasks right first time
          attempts.push(att(t.id, first, first ? q.xp : 0, qi));
          if (!first) attempts.push(att(t.id, true, retryXp(t.type, q.xp, 2), qi));
          xp += first ? q.xp : retryXp(t.type, q.xp, 2);
        });
        return;
      }
      if (i % 2 === 0) { attempts.push(att(t.id, true, max)); xp += max; return; }
      attempts.push(att(t.id, false, 0), att(t.id, false, 0));          // two wrong tries reveal it
      attempts.push(att(t.id, true, retryXp(t.type, max, 3)));          // the correct third try pays 0 or half
      xp += retryXp(t.type, max, 3);
    });
    const { score, max } = roomPassScore(room, attempts);
    expect(xp / max).toBeLessThan(ROOM_PASS_THRESHOLD);   // the old XP-based gate: stuck
    expect(score).toBe(max);                              // every task now answered correctly
    expect(score / max).toBeGreaterThanOrEqual(ROOM_PASS_THRESHOLD);
  });

  it("a task never answered correctly keeps only the XP it earned", () => {
    const t = graded.find(x => x.type === "question")!;
    expect(taskPassCredit(t, [att(t.id, false, 0), att(t.id, false, 0)])).toBe(0);
    expect(taskPassCredit(t, [])).toBe(0);
  });

  it("log analysis credits each question separately", () => {
    const t = graded.find(x => x.type === "log_analysis")!;
    if (t.type !== "log_analysis") throw new Error("expected log_analysis");
    const credit = taskPassCredit(t, [att(t.id, true, 0, 0), att(t.id, false, 0, 1)]);
    expect(credit).toBe(t.questions[0].xp);
  });
});

describe("client gate score uses pass credit", () => {
  it("a corrected retry with 0 XP still counts in full", () => {
    const gradeable = { q1: 40, q2: 60 };
    expect(roomScoreXp({ xpEarned: 40, perTaskXp: { q1: 40, q2: 0 } }, gradeable)).toBe(40);
    expect(roomScoreXp({ xpEarned: 40, perTaskXp: { q1: 40, q2: 0 }, perTaskCredit: { q2: 60 } }, gradeable)).toBe(100);
  });
  it("pass credit merges per task and is never lowered", () => {
    const merged = mergeRoomEntry(
      { completedTaskIds: ["q1"], xpEarned: 0, perTaskXp: { q1: 0 }, perTaskCredit: { q1: 40 } },
      { completedTaskIds: ["q2"], xpEarned: 0, perTaskXp: { q2: 0 }, perTaskCredit: { q1: 0, q2: 60 } },
    );
    expect(merged.perTaskCredit).toEqual({ q1: 40, q2: 60 });
  });
});
