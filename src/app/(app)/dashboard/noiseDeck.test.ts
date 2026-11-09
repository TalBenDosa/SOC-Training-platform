/**
 * noiseDeck.ts: the Live Feed's ordinary rows over a long shift on the smallest pools.
 *  - R8: a one-off action is shown once per shift.
 *  - R3: a recurring row shown again for another person names that person everywhere (mail, login,
 *    display name), on their own machine with its own address; never half one person, half another.
 */
import { describe, it, expect } from "vitest";
import { BENIGN_EVENTS } from "./benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { companyFeedPool } from "./feedPool";
import { NoiseDeck, RECURRING_TYPES } from "./noiseDeck";

function lcg(seed: number) { let s = seed; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; }
const SIM = { BENIGN_EVENTS, COMPANY_EVENTS };

describe("NoiseDeck", () => {
  for (const company of ["quantumbank", "globallogis", "rocketstack", "medcore", "nexacorp"]) {
    it(`${company}: 200 draws, one-offs once, variants re-homed whole`, () => {
      const pool = companyFeedPool(SIM, company);
      const byId = new Map(pool.map(e => [e.id, e]));
      const deck = new NoiseDeck(pool, lcg(7));
      const rows = [...deck.backfill(15)];
      for (let i = 0; i < 200; i++) { const e = deck.next(); if (e) rows.push(e); }
      const oneOff = new Map<string, number>();
      const off: string[] = [];
      for (const e of rows) {
        const base = e.id.replace(/_v\d+$/, "");
        if (!RECURRING_TYPES.has(e.event_type)) oneOff.set(base, (oneOff.get(base) ?? 0) + 1);
        if (base === e.id) continue;
        const orig = byId.get(base)!;
        expect(orig).toBeDefined();
        if (orig.user_email === e.user_email) continue;
        const oldLocal = orig.user_email!.split("@")[0];
        const text = JSON.stringify({ ...e, id: undefined });
        if (new RegExp(`(?<![A-Za-z0-9._-])${oldLocal.replace(/\./g, "\\.")}(?![A-Za-z0-9_-])`).test(text)) off.push(`${e.id}: still names ${oldLocal}`);
        if (orig.user?.full_name && e.user?.full_name === orig.user.full_name) off.push(`${e.id}: kept ${orig.user.full_name}`);
        if (orig.hostname && e.hostname === orig.hostname && !/^(srv|svr|prod|db|web|app|sql)[-_]|[-_](dc|fs|srv|sql|db|file|exch|app|web)[-_]?\d*$/i.test(orig.hostname)) off.push(`${e.id}: ${e.user_email} on ${orig.user_email}'s machine ${orig.hostname}`);
      }
      for (const [id, n] of oneOff) if (n > 1) off.push(`one-off ${id} drawn ${n} times`);
      expect(off).toEqual([]);
    });
  }
});
