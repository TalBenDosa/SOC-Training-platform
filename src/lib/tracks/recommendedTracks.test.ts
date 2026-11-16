import { describe, it, expect } from "vitest";
import { RECOMMENDED_TRACKS, type TrackStep } from "@/data/recommendedTracks";
import { ROOMS_META } from "@/data/roomsMeta";
import { LIBRARY_INDEX } from "@/data/libraryIndex";
import { QUIZZES_META, SCENARIOS_META } from "@/data/catalogMeta";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import { resolveStep, resolveSteps, stepKey, SHIFT_COMPANY_ORDER } from "./resolve";
import { buildTrackView, recommendedTrack, stepStatus, EMPTY_RECORDS, hoursLabel, type LearnerRecords } from "./progress";

/** Every placement, in route order: track → stage → core, then that stage's deeper. */
function placements() {
  const out: { step: TrackStep; track: number; stage: string; order: number; core: boolean }[] = [];
  let order = 0;
  RECOMMENDED_TRACKS.forEach((t, ti) => t.stages.forEach(st => {
    st.steps.forEach(step => out.push({ step, track: ti, stage: st.id, order: order++, core: true }));
    (st.deeper ?? []).forEach(step => out.push({ step, track: ti, stage: st.id, order: order++, core: false }));
  }));
  return out;
}

describe("recommended tracks: content", () => {
  it("one track per level, in ladder order", () => {
    expect(RECOMMENDED_TRACKS.map(t => t.level)).toEqual(["beginner", "intermediate", "advanced"]);
    expect(RECOMMENDED_TRACKS.map(t => t.rank)).toEqual([1, 2, 3]);
    expect(new Set(RECOMMENDED_TRACKS.map(t => t.id)).size).toBe(RECOMMENDED_TRACKS.length);
  });

  it("every step points at real content", () => {
    const broken = placements().filter(p => !resolveStep(p.step)).map(p => `${p.stage}: ${stepKey(p.step)}`);
    expect(broken).toEqual([]);
  });

  it("no step appears twice anywhere", () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const p of placements()) {
      const k = stepKey(p.step);
      if (seen.has(k)) dupes.push(`${k} in ${seen.get(k)} and ${p.stage}`);
      else seen.set(k, p.stage);
    }
    expect(dupes).toEqual([]);
  });

  it("covers every built-in room, library lesson, graded lesson, quiz and scenario", () => {
    const placed = new Set(placements().map(p => stepKey(p.step)));
    const missing = [
      ...ROOMS_META.map(r => `room:${r.id}`),
      ...LIBRARY_INDEX.map(l => `read:${l.id}`),
      ...LESSON_PATHS.flatMap(p => p.modules.flatMap(m => m.lessons.map(l => `lesson:${p.slug}--${l.slug}`))),
      ...QUIZZES_META.map(q => `quiz:${q.slug}`),
      ...SCENARIOS_META.map(s => `scenario:${s.slug}`),
      ...SHIFT_COMPANY_ORDER.map(c => `shift:${c}`),
    ].filter(k => !placed.has(k));
    expect(missing).toEqual([]);
  });

  it("each room's prerequisites come earlier in the route", () => {
    const at = new Map(placements().filter(p => p.step.kind === "room").map(p => [p.step.id, p]));
    const late: string[] = [];
    for (const r of ROOMS_META) {
      const me = at.get(r.id);
      if (!me) continue;
      for (const pre of r.prerequisites) {
        const p = at.get(pre);
        if (!p || p.order > me.order) late.push(`${r.id} needs ${pre}`);
        // A core room must not depend on an optional room of a later or the same track.
        else if (me.core && !p.core && p.track >= me.track && p.stage !== me.stage) late.push(`${r.id} (core) needs optional ${pre}`);
      }
    }
    expect(late).toEqual([]);
  });

  it("live shifts follow the dashboard's company unlock order", () => {
    const shifts = placements().filter(p => p.step.kind === "shift").map(p => p.step.id);
    expect(shifts).toEqual([...SHIFT_COMPANY_ORDER]);
  });

  it("every stage practises: at least one room, scenario or shift in its core", () => {
    const idle = RECOMMENDED_TRACKS.flatMap(t => t.stages)
      .filter(st => !st.steps.some(s => s.kind === "room" || s.kind === "scenario" || s.kind === "shift"))
      .map(st => st.id);
    expect(idle).toEqual([]);
  });

  it("every stage has a goal and named skills, and ids are unique", () => {
    const stages = RECOMMENDED_TRACKS.flatMap(t => t.stages);
    expect(new Set(stages.map(s => s.id)).size).toBe(stages.length);
    for (const st of stages) {
      expect(st.goal.length, st.id).toBeGreaterThan(40);
      expect(st.skills.length, st.id).toBeGreaterThanOrEqual(3);
      expect(st.steps.length, st.id).toBeGreaterThan(0);
    }
  });

  it("no em dashes in learner-facing track text", () => {
    const text = JSON.stringify(RECOMMENDED_TRACKS.map(t => ({ ...t, stages: t.stages.map(s => ({ ...s, steps: [], deeper: [] })) })));
    expect(text.includes("—")).toBe(false);
  });
});

describe("recommended tracks: progress", () => {
  const track = RECOMMENDED_TRACKS[0];
  const rec = (over: Partial<LearnerRecords>): LearnerRecords => ({ ...EMPTY_RECORDS, ...over });

  it("derives each kind's status from the existing records", () => {
    const r = rec({
      rooms: { "intro-cybersecurity": { completedAt: "2026-11-01" }, "soc-structure": {} },
      quizzes: { "cybersecurity-foundations": { score: 70 }, "security-models-principles": { score: 69 } },
      scenarios: new Set(["phishing-malware-basic"]),
      shifts: new Set(["nexacorp"]),
      lessons: new Set(["soc-analyst--what-is-a-soc"]),
      reads: new Set(["local-lesson-4"]),
    });
    expect(stepStatus({ kind: "room", id: "intro-cybersecurity" }, r)).toBe("done");
    expect(stepStatus({ kind: "room", id: "soc-structure" }, r)).toBe("started");
    expect(stepStatus({ kind: "quiz", id: "cybersecurity-foundations" }, r)).toBe("done");
    expect(stepStatus({ kind: "quiz", id: "security-models-principles" }, r)).toBe("started");
    expect(stepStatus({ kind: "scenario", id: "phishing-malware-basic" }, r)).toBe("done");
    expect(stepStatus({ kind: "shift", id: "nexacorp" }, r)).toBe("done");
    expect(stepStatus({ kind: "lesson", id: "soc-analyst--what-is-a-soc" }, r)).toBe("done");
    expect(stepStatus({ kind: "read", id: "local-lesson-4" }, r)).toBe("done");
    expect(stepStatus({ kind: "read", id: "local-lesson-5" }, r)).toBe("todo");
  });

  it("a new learner starts at the first step of the first track", () => {
    const views = RECOMMENDED_TRACKS.map(t => buildTrackView(t, EMPTY_RECORDS));
    expect(views[0].pct).toBe(0);
    expect(views[0].next?.step.key).toBe(stepKey(track.stages[0].steps[0]));
    expect(recommendedTrack(views)?.track.id).toBe(track.id);
  });

  it("deeper steps never count toward completion", () => {
    const st = track.stages[0];
    const all = rec({
      rooms: Object.fromEntries(st.steps.filter(s => s.kind === "room").map(s => [s.id, { completedAt: "x" }])),
      quizzes: Object.fromEntries(st.steps.filter(s => s.kind === "quiz").map(s => [s.id, { score: 100 }])),
      lessons: new Set(st.steps.filter(s => s.kind === "lesson").map(s => s.id)),
      reads: new Set(st.steps.filter(s => s.kind === "read").map(s => s.id)),
    });
    const v = buildTrackView(track, all);
    expect(v.stages[0].complete).toBe(true);
    expect(v.next?.stage.stage.id).toBe(track.stages[1].id);
  });

  it("steps from a switched-off feature disappear and do not block the stage", () => {
    const noLive = buildTrackView(RECOMMENDED_TRACKS[1], EMPTY_RECORDS, f => f !== "live_soc");
    expect(noLive.stages.some(s => s.stage.id === "t2-capstone")).toBe(false);
    expect(resolveSteps([{ kind: "shift", id: "nexacorp" }], f => f !== "live_soc")).toEqual([]);
  });

  it("a learner working in Level 2 is not sent back to Level 1", () => {
    const r = rec({ rooms: { "windows-event-logs": { completedAt: "x" } } });
    const views = RECOMMENDED_TRACKS.map(t => buildTrackView(t, r));
    expect(recommendedTrack(views)?.track.id).toBe(RECOMMENDED_TRACKS[1].id);
  });

  it("formats hours", () => {
    expect(hoursLabel(20)).toBe("0.5 h");
    expect(hoursLabel(90)).toBe("1.5 h");
    expect(hoursLabel(600)).toBe("10 h");
  });
});
