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
