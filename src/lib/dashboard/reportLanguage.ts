/**
 * Incident reports are written in English only (Tal, 2026-11-18). SOC tickets, escalations and
 * handovers are written in English, and the grader reads English. Any letter outside basic Latin
 * (Hebrew, Arabic, Cyrillic, accented Latin...) blocks the report: the form explains why and
 * the grading route refuses it. Digits, punctuation, symbols and IOCs are unaffected.
 * Pure and isomorphic: the form and the route share it.
 */
export const ENGLISH_ONLY_MESSAGE =
  "Write the report in English only. Real SOC tickets and escalations are written in English, and the report is graded in English.";

const NON_ENGLISH_LETTER = /(?![A-Za-z])\p{L}/u;

/** True when the text has no letters outside basic Latin (A-Z, a-z). */
export function isEnglishOnly(text: string): boolean {
  return !NON_ENGLISH_LETTER.test(text);
}

/**
 * Team training (Tal, 2026-11-18): the same rule on every piece of written work a member sends.
 * Team chat (`message.sent`) and the instructor's own injects (`staff.*`) stay free; click
 * telemetry carries no text. Payloads hold ids, not display names, so a Hebrew name never trips it.
 */
export const TEAM_ENGLISH_ONLY_MESSAGE =
  "Write in English only. Real SOC tickets, case notes and escalations are written in English, and your work is graded in English. Team chat can be in any language.";

export const TEAM_FREE_LANGUAGE_TYPES = new Set(["message.sent", "event.opened"]);

/** True when an action payload has written text with non-English letters (any depth, bounded). */
export function payloadHasNonEnglish(type: string, payload: unknown): boolean {
  if (TEAM_FREE_LANGUAGE_TYPES.has(type) || type.startsWith("staff.")) return false;
  const walk = (v: unknown, depth: number): boolean => {
    if (typeof v === "string") return !isEnglishOnly(v);
    if (depth >= 4 || !v || typeof v !== "object") return false;
    return (Array.isArray(v) ? v : Object.values(v)).some(x => walk(x, depth + 1));
  };
  return walk(payload, 0);
}
