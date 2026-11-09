/**
 * The solo Live Feed against docs/LOG-REALISM-STANDARD.md, played in code (feedShift.testkit.ts):
 * every built-in company at every difficulty, two seeds each, read the way an analyst reads the feed.
 *  - R8: ordinary traffic is at least twice the attack rows from the moment the attack starts.
 *  - R8: a one-off action (an account change, a mail, a ticket) is never shown twice in a shift, and
 *    recurring telemetry comes back as a fresh record (never a copy with only its time changed).
 *  - R4: a story keeps its order, and a time inside a row that names another story row (an alert's
 *    first activity, a ticket's opened_at) lands on that row's shown time (one monotone map).
 */
import { describe, it, expect } from "vitest";
import { COMPANIES, DIFFICULTIES, nativeOf, playShift, type Shift } from "./feedShift.testkit";
import { RECURRING_TYPES } from "./noiseDeck";

const SEEDS = [1, 2];
const shifts: Shift[] = [];
for (const c of COMPANIES) for (const d of DIFFICULTIES) for (const s of SEEDS) shifts.push(playShift(c, d, s));
const tag = (s: Shift) => `${s.company}/${s.difficulty}/${s.seed} ${s.story.id}`;
const ms = (iso?: string) => Date.parse(iso ?? "");

describe("Live Feed realism (played shifts)", () => {
  it("R8: ordinary rows are at least twice the attack rows once the attack is in the feed", () => {
    const off: string[] = [];
    for (const s of shifts) {
      const atk = s.rows.filter(r => r.kind === "story" && r.attack);
      if (!atk.length) continue;
      const start = Math.min(...atk.map(r => ms(r.event.ts)));
      const ordinary = s.rows.filter(r => (r.kind === "noise" || !r.attack) && ms(r.event.ts) >= start).length;
      if (ordinary < 2 * atk.length) off.push(`${tag(s)}: ${ordinary} ordinary vs ${atk.length} attack rows`);
    }
    expect(off).toEqual([]);
  }, 300_000);

  it("R8: one-off actions appear once per shift; recurring noise is drawn fresh", () => {
    const off: string[] = [];
    for (const s of shifts) {
      const seen = new Map<string, number>();
      const records = new Map<string, number>();
      for (const r of s.rows) {
        if (r.kind !== "noise" || r.mirror) continue;
        const base = r.event.id.replace(/_\d{13}_(q?\d+)$/, "").replace(/_v\d+$/, "");
        if (!RECURRING_TYPES.has(r.event.event_type)) seen.set(base, (seen.get(base) ?? 0) + 1);
        const n = nativeOf(r, s.company);
        // A copy: the whole rendered record again, ids included (only its times differ).
        const flat = JSON.stringify(n?.log.record ?? r.event.raw, (k, v) => (/(time|Time|date|Date|^ts$)/.test(k) || (typeof v === "string" && /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(v)) ? undefined : v));
        records.set(flat, (records.get(flat) ?? 0) + 1);
      }
      for (const [id, n] of seen) if (n > 1) off.push(`${tag(s)}: one-off ${id} shown ${n} times`);
      const worst = Math.max(0, ...records.values());
      if (worst > 1) off.push(`${tag(s)}: one rendered noise record copied ${worst} times`);
    }
    expect(off).toEqual([]);
  }, 300_000);

  it("R4: story rows keep their order and a time naming another story row lands on it", () => {
    const off: string[] = [];
    for (const s of shifts) {
      const st = s.rows.filter(r => r.kind === "story" && !r.mirror).sort((a, b) => a.storyIdx! - b.storyIdx!);
      for (let i = 0; i < st.length; i++) for (let j = i + 1; j < st.length; j++) {
        const ai = ms(st[i].authoredTs), aj = ms(st[j].authoredTs);
        if (ai < aj && ms(st[i].event.ts) > ms(st[j].event.ts)) off.push(`${tag(s)}: row ${st[i].storyIdx} shown after ${st[j].storyIdx}`);
      }
      // authored instant (to the second) -> shown instant of the story row authored then
      const shownAt = new Map<number, number>();
      for (const r of st) { const a = Math.floor(ms(r.authoredTs) / 1000); if (!shownAt.has(a)) shownAt.set(a, Math.floor(ms(r.event.ts) / 1000)); }
      for (const r of st) {
        const authored = s.story.events[r.storyIdx!];
        const own = Math.floor(ms(authored.ts) / 1000);
        for (const [k, v] of Object.entries(authored.raw ?? {})) {
          if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(v)) continue;
          const a = Math.floor(ms(v) / 1000);
          if (a === own || !shownAt.has(a)) continue;
          const got = r.event.raw?.[k];
          if (typeof got !== "string") continue;
          if (Math.abs(Math.floor(ms(got) / 1000) - shownAt.get(a)!) > 1) off.push(`${tag(s)}: row ${r.storyIdx} ${k}=${got}, the row it names was shown at ${new Date(shownAt.get(a)! * 1000).toISOString()}`);
        }
      }
    }
    expect(off).toEqual([]);
  }, 300_000);
});
