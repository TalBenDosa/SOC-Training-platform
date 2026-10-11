// After a host swap, a department word ("the HR workstation …") must still describe
// the host the sentence names.
import { it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory } from "./attackStories";
import { BENIGN_EVENTS } from "./benignEvents";

const ROLE: [RegExp, RegExp][] = [
  [/\bHR (workstation|laptop|machine|PC)\b/i, /-HR-/i],
  [/\bfinance (workstation|laptop|machine|PC)\b/i, /-(FIN|ACC)-/i],
  [/\b(engineering|developer|dev) (workstation|laptop|machine)\b/i, /-(ENG|DEV)-/i],
  [/\bmarketing (workstation|laptop|machine)\b/i, /-MKT-/i],
  [/\bdomain controller\b/i, /DC\d/i],
];
it("role words vs swapped host", () => {
  const out = new Set<string>();
  for (const s of ATTACK_STORIES) for (let k = 0; k < 3; k++) {
    const evs = instantiateStory(s, BENIGN_EVENTS, undefined, "nexacorp").events ?? [];
    for (const e of evs) for (const [word, host] of ROLE) {
      const m = e.description?.match(word);
      if (!m || !e.hostname) continue;
      // the role word should describe a host named in the same sentence
      const hostsInText = (e.description!.match(/\b[A-Z]{2,5}-[A-Z0-9-]{2,}\b/g) ?? []);
      const named = hostsInText.find(h => !host.test(h));
      if (named && hostsInText.every(h => !host.test(h))) out.add(`${s.id}: "${m[0]}" but text names ${hostsInText.join(",")} — ${e.description!.slice(0, 110)}`);
    }
  }
  expect([...out]).toEqual([]);
});
