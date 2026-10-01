// When a story's victim is swapped for a company roster user, the victim's NAME goes
// too — prose ("a converter Tomer uses") and displayName fields must not name a
// different person than the row's user.
import { describe, it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory } from "./attackStories";
import { BENIGN_EVENTS } from "./benignEvents";

describe("story victim swap", () => {
  it("replaces the victim's full and first name wherever the email was replaced", () => {
    const leaks: string[] = [];
    for (const s of ATTACK_STORIES) {
      const counts = new Map<string, number>();
      for (const e of s.events) if (e.user_email && !/^(svc-|ci-|admin@|noreply|system@)/i.test(e.user_email)) counts.set(e.user_email, (counts.get(e.user_email) ?? 0) + 1);
      const victim = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
      if (!victim) continue;
      const surname = victim.split("@")[0].split(/[._]/).pop() ?? "";
      if (!/^[a-z'-]{3,}$/i.test(surname)) continue;
      const re = new RegExp(`\\b([A-Z][a-z]{2,}) (${surname.charAt(0).toUpperCase()}${surname.slice(1)})\\b`);
      const full = s.events.map(e => JSON.stringify([e.description, e.raw, e.user]).match(re)).find(Boolean);
      if (!full) continue;
      for (let k = 0; k < 4; k++) {
        const out = instantiateStory(s, BENIGN_EVENTS, undefined, "nexacorp").events ?? [];
        if (out.some(e => e.user_email === victim)) continue;            // not swapped this time
        const text = JSON.stringify(out.map(e => [e.description, e.raw, e.user]));
        if (text.includes(full[0])) leaks.push(`${s.id}: "${full[0]}" survived the swap`);
      }
    }
    expect([...new Set(leaks)]).toEqual([]);
  });
});
