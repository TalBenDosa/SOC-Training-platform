import { describe, it, expect, vi } from "vitest";

// buildTimeline is server-only in the app; the guard module throws outside a
// react-server bundle, so stub it for the unit test.
vi.mock("server-only", () => ({}));

import { buildTeamTimeline, TEAM_ANSWER_FIELDS } from "./buildTimeline";

const COMBOS: [string, "easy" | "medium" | "hard"][] = [
  ["nexacorp", "easy"], ["nexacorp", "medium"], ["quantumbank", "hard"], ["rocketstack", "medium"], ["medcore", "hard"],
];
const TIER = { easy: "foundation", medium: "core", hard: "advanced" } as const;

describe("buildTeamTimeline — answer key off the wire (audit S4)", () => {
  // Story CHOICE deliberately avoids recently used stories (pickStoryForCompany's
  // anti-repeat memory), so two builds may differ — the timeline is generated once
  // at start and stored, which is what makes every member replay the same incident.
  // The public ids, however, must be a pure function of (seed, position).
  it("opaque ids are a pure function of (seed, position)", () => {
    const feedIds = (seed: string) => buildTeamTimeline("nexacorp", "medium", seed).filter(e => e.channel === "feed").map(e => e.body.id);
    const a = feedIds("seed-1");
    const b = feedIds("seed-1");
    const n = Math.min(a.length, b.length);
    expect(n).toBeGreaterThan(0);
    // feed ids = f(seed, position): the two builds share exactly the ids of the shorter feed
    expect(new Set(a).size).toBe(a.length);
    expect(a.filter(id => b.includes(id)).length).toBe(n);
    const c = buildTeamTimeline("nexacorp", "medium", "seed-2").map(e => e.body.id);
    expect(c.filter(id => a.includes(id)).length).toBe(0);   // a different seed never reuses ids
  });

  it.each(COMBOS)("%s/%s: no public body carries an answer field", (company, diff) => {
    const tl = buildTeamTimeline(company, diff, "s");
    expect(tl.length).toBeGreaterThan(0);
    for (const e of tl) {
      for (const k of TEAM_ANSWER_FIELDS) expect(e.body).not.toHaveProperty(k);
      if (e.channel === "inject") {
        expect(e.body).not.toHaveProperty("expected_response");
        expect(e.body).not.toHaveProperty("linked_objective");
        expect(["update", "ticket", "announcement"]).toContain(e.body.kind);
      }
    }
  });

  it.each(COMBOS)("%s/%s: ids are opaque + unique, and every log has the session tier", (company, diff) => {
    const tl = buildTeamTimeline(company, diff, "s");
    const ids = tl.map(e => String(e.body.id));
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of tl) {
      expect(String(e.body.id)).toMatch(/^[em][0-9a-f]{12}$/);
      if (e.channel === "feed") expect(e.body.tier).toBe(TIER[diff]);
    }
  });

  it("keeps the ground truth in the answer (server-side only)", () => {
    const tl = buildTeamTimeline("nexacorp", "medium", "s");
    const attacks = tl.filter(e => e.channel === "feed" && ["tp", "escalate"].includes(String(e.answer?.expected_verdict)));
    expect(attacks.length).toBeGreaterThan(0);
    expect(attacks.every(e => typeof e.answer?.original_id === "string")).toBe(true);
    const kinds = tl.filter(e => e.channel === "inject").map(e => e.answer?.kind);
    expect(kinds).toEqual(expect.arrayContaining(["twist", "false_lead", "mgmt_pressure", "ticket"]));
    const twist = tl.find(e => e.answer?.kind === "twist");
    expect(twist?.body.kind).toBe("update");
    expect(typeof twist?.answer?.expected_response).toBe("string");
  });

  it("easy shifts have no curveballs and a single-threaded story", () => {
    const tl = buildTeamTimeline("nexacorp", "easy", "s");
    expect(tl.some(e => e.channel === "inject")).toBe(false);
  });
});
