// Learner feedback (2026-11-24): "very confusing, I did not understand what the lab is for".
// Every lab must say why it exists (`teaches`), give what to know first (`primer`), and carry
// good progressive hints (`hints`; Tal: hints are mandatory, a worked example is optional),
// for each room that has been through the clarity pass (labClarityRooms.ts). Once every room
// is listed, ALL_ROOMS_DONE below flips to true and the rule covers the whole platform.
import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { getRoomExperience, type BriefingLab } from "./index";
import { LAB_CLARITY_ROOMS } from "./labClarityRooms";

const ALL_ROOMS_DONE = false;
const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;
const norm = (s: string) => s.toLowerCase().replace(/[`*_]/g, "").replace(/\s+/g, " ").trim();

/**
 * The answers a lab holds, wherever its kind keeps them: `answer`/`answers`/`culprit`/`target`/
 * `cut`/`correct` strings, at any depth. A hint that quotes one verbatim gives the lab away.
 * Short answers (under 4 characters, like "3" or "no") are too common to police this way.
 */
function answersOf(lab: BriefingLab): string[] {
  const out: string[] = [];
  const KEYS = new Set(["answer", "answers", "culprit", "target", "cut", "correct"]);
  const walk = (v: unknown, key?: string) => {
    if (typeof v === "string") { if (key && KEYS.has(key) && v.trim().length >= 4) out.push(norm(v)); return; }
    if (Array.isArray(v)) { v.forEach(x => walk(x, key)); return; }
    if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) if (k !== "hints") walk(x, k);
  };
  walk(lab);
  return out;
}

const rooms = ROOMS
  .filter(r => ALL_ROOMS_DONE || LAB_CLARITY_ROOMS.has(r.id))
  .map(r => ({ r, exp: getRoomExperience(r.id, r.tasks.map(t => t.id)) }));

describe("lab clarity", () => {
  it("every listed room exists and has an Operation Mode experience", () => {
    const ids = new Set(ROOMS.map(r => r.id));
    expect([...LAB_CLARITY_ROOMS].filter(id => !ids.has(id))).toEqual([]);
    expect(rooms.filter(x => !x.exp).map(x => x.r.id)).toEqual([]);
  });

  it.each(rooms.map(x => [x.r.id, x] as const))("%s: every lab says why it exists, what to know first, and gives good hints", (_id, { r, exp }) => {
    const problems: string[] = [];
    for (const t of r.tasks) {
      for (const [i, lab] of ((exp?.briefings ?? {})[t.id] ?? [] as BriefingLab[]).entries()) {
        const at = `${t.id} lab ${i + 1} (${lab.kind} "${lab.title}")`;
        const why = lab.teaches ?? "";
        if (words(why) < 12 || words(why) > 70) problems.push(`${at}: teaches must be 12-70 words (has ${words(why)})`);
        if (why.includes("—")) problems.push(`${at}: em dash in teaches`);
        if (!lab.primer || lab.primer.points.length < 2) problems.push(`${at}: needs a primer with at least 2 points`);
        const hints = lab.hints ?? [];
        if (hints.length < 2) problems.push(`${at}: needs at least 2 progressive hints (has ${hints.length})`);
        const answers = answersOf(lab);
        for (const [j, h] of hints.entries()) {
          if (words(h) < 6 || words(h) > 50) problems.push(`${at}: hint ${j + 1} must be 6-50 words`);
          if (h.includes("—")) problems.push(`${at}: em dash in hint ${j + 1}`);
          const leaked = answers.find(a => norm(h).includes(a));
          if (leaked) problems.push(`${at}: hint ${j + 1} gives the answer away ("${leaked}")`);
        }
        if (new Set(hints.map(norm)).size !== hints.length) problems.push(`${at}: two hints say the same thing`);
      }
    }
    expect(problems).toEqual([]);
  });
});
