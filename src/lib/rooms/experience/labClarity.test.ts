// Learner feedback (2026-11-24): "very confusing, I did not understand what the lab is for".
// Every lab must say why it exists (`teaches`) and give what to know first (`primer`), for each
// room that has been through the clarity pass (labClarityRooms.ts). Once every room is listed,
// ALL_ROOMS_DONE below flips to true and the rule covers the whole platform.
import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { getRoomExperience, type BriefingLab } from "./index";
import { LAB_CLARITY_ROOMS } from "./labClarityRooms";

const ALL_ROOMS_DONE = false;
const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

const rooms = ROOMS
  .filter(r => ALL_ROOMS_DONE || LAB_CLARITY_ROOMS.has(r.id))
  .map(r => ({ r, exp: getRoomExperience(r.id, r.tasks.map(t => t.id)) }));

describe("lab clarity", () => {
  it("every listed room exists and has an Operation Mode experience", () => {
    const ids = new Set(ROOMS.map(r => r.id));
    expect([...LAB_CLARITY_ROOMS].filter(id => !ids.has(id))).toEqual([]);
    expect(rooms.filter(x => !x.exp).map(x => x.r.id)).toEqual([]);
  });

  it.each(rooms.map(x => [x.r.id, x] as const))("%s: every lab says why it exists and what to know first", (_id, { r, exp }) => {
    const problems: string[] = [];
    for (const t of r.tasks) {
      for (const [i, lab] of ((exp?.briefings ?? {})[t.id] ?? [] as BriefingLab[]).entries()) {
        const at = `${t.id} lab ${i + 1} (${lab.kind} "${lab.title}")`;
        const why = lab.teaches ?? "";
        if (words(why) < 12 || words(why) > 70) problems.push(`${at}: teaches must be 12-70 words (has ${words(why)})`);
        if (why.includes("—")) problems.push(`${at}: em dash in teaches`);
        if (!lab.primer || lab.primer.points.length < 2) problems.push(`${at}: needs a primer with at least 2 points`);
        else if (!lab.primer.example) problems.push(`${at}: primer needs a worked example`);
      }
    }
    expect(problems).toEqual([]);
  });
});
