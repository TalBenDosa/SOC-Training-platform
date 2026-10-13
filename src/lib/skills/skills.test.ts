import { describe, it, expect } from "vitest";
import { ROOMS_META } from "@/data/roomsMeta";
import { QUIZZES_META, SCENARIOS_META } from "@/data/catalogMeta";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import { SKILL_AREAS, areaFor } from "./taxonomy";
import { areaOf } from "./contentArea";

const tally = (areas: string[]) => areas.reduce<Record<string, number>>((m, a) => ((m[a] = (m[a] ?? 0) + 1), m), {});

describe("skill taxonomy", () => {
  const roomAreas = ROOMS_META.map(r => areaOf("room", r.id));
  const quizAreas = QUIZZES_META.map(q => areaOf("quiz", q.slug));
  const scenarioAreas = SCENARIOS_META.map(s => areaOf("scenario", s.slug));
  const lessonAreas = LESSON_PATHS.flatMap(p => p.modules.flatMap(m => m.lessons.map(l => areaOf("lesson", `${p.slug}--${l.slug}`))));

  it("every built-in room, quiz, scenario and lesson maps to a known area", () => {
    const known = new Set<string>(SKILL_AREAS.map(a => a.id));
    for (const a of [...roomAreas, ...quizAreas, ...scenarioAreas, ...lessonAreas]) expect(known.has(a)).toBe(true);
  });

  it("no area is left without rooms, and no area swallows the rest", () => {
    const t = tally(roomAreas);
    console.log("[skills] rooms per area", JSON.stringify(t));
    console.log("[skills] lessons per area", JSON.stringify(tally(lessonAreas)));
    console.log("[skills] scenarios per area", JSON.stringify(tally(scenarioAreas)));
    for (const a of SKILL_AREAS) expect(t[a.id] ?? 0, a.id).toBeGreaterThan(0);
    expect(Math.max(...Object.values(t))).toBeLessThan(ROOMS_META.length * 0.35);
  });

  it("every room and quiz category in the corpus is mapped explicitly, not guessed from a title", () => {
    const cats = new Set([...ROOMS_META.map(r => r.category), ...QUIZZES_META.map(q => q.category)]);
    for (const c of cats) expect(areaFor({ category: c }, "__none__" as never), c).not.toBe("__none__");
  });

  it("titles pull phishing and Active Directory content out of broad categories", () => {
    expect(areaFor({ title: "Phishing Email Header Analysis", category: "Threat Detection" })).toBe("email_phishing");
    expect(areaFor({ title: "Kerberoasting and Ticket Attacks", category: "Threat Detection" })).toBe("windows_ad");
    expect(areaFor({ title: "S3 Bucket Exposure", category: "Cloud Security" })).toBe("cloud");
  });
});
