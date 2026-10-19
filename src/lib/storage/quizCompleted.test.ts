// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from "vitest";
import { getQuizProgress, markQuizCompleted } from "./progress";

// Learner report #12: finishing a quiz and going back to the list showed no "Completed"
// badge until a reload, because the cache behind the badge was filled only at sign-in.
describe("markQuizCompleted", () => {
  beforeEach(() => { try { localStorage.clear(); } catch { /* no storage */ } });

  it("marks a just-finished quiz so the list shows its badge without a reload", () => {
    expect(getQuizProgress()["mitre-attack"]).toBeUndefined();
    markQuizCompleted("mitre-attack", 75);
    expect(getQuizProgress()["mitre-attack"]).toEqual({ score: 75 });
  });

  it("keeps the best score across attempts and leaves other quizzes alone", () => {
    markQuizCompleted("mitre-attack", 83.4);
    markQuizCompleted("mitre-attack", 50);
    markQuizCompleted("soc-decision-making", 100);
    expect(getQuizProgress()).toEqual({ "mitre-attack": { score: 83 }, "soc-decision-making": { score: 100 } });
  });

  it("treats a missing score as 0 instead of writing NaN", () => {
    markQuizCompleted("cloud-security-fundamentals", Number.NaN);
    expect(getQuizProgress()["cloud-security-fundamentals"]).toEqual({ score: 0 });
  });
});
