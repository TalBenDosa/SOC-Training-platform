/**
 * Live Feed (Dashboard) collector.
 *
 * Builds what /dashboard shows for each of the 5 built-in companies with their own products (no
 * stack chosen), by PLAYING the feed the way page.tsx and useLiveEvents.ts run it
 * (src/app/(app)/dashboard/feedShift.testkit.ts, which shares the hook's modules):
 *   - the noise pool: feedPool.ts companyFeedPool (the company's own sources, no real attack, one
 *     host one IP, one account one SID), only what its products can show (fitsStack), labelled for
 *     them (applyStack). Each record is collected once, enriched, with its SIEM mirror when it has one;
 *   - every story the company can be dealt (storiesForCompany easy / medium / hard, solo, honouring
 *     the product locks), played in its own seeded shift: noiseDeck.ts draws the ordinary rows
 *     (one-offs once, recurring telemetry re-homed whole to another person), storyFeed.ts releases the
 *     story (phaseSize bursts, placePhase one monotone map, noiseQuota / noiseTimes), enrichEvent and
 *     siemMirror as the hook calls them;
 *   - rows are rendered with nativeView (a row with no native module shows its legacy raw block).
 * Story rows keep their stable ids (`company:story:event`), pool rows `company:pool:event`, and a
 * noise row the deck re-homed to another person `company:pool:event~person`. One feed per story is
 * recorded for R8: every row of the shift from the story's first attack row on (what is "around the
 * attack").
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { storiesForCompany, instantiateStory, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { applyStack, fitsStack, nativeView, storyHonoursLocks } from "@/lib/logs/native";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { enrichEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import { siemMirror } from "@/app/(app)/dashboard/useLiveEvents";
import { playShift } from "@/app/(app)/dashboard/feedShift.testkit";
import type { Collected, LogRow, Surface } from "../types";
import { seeded } from "../util";

export const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const T0 = Date.parse("2026-11-09T09:00:00.000Z");
const SIM = { BENIGN_EVENTS, COMPANY_EVENTS };

/** page.tsx's noise pool (feedPool.ts): the company's own sources, no real attack, one IP per host, one SID per account. */
export function livePool(id: string): TelemetryEvent[] {
  return companyFeedPool(SIM, id);
}

/** Every story the solo dashboard can deal the company (what pickStoryForCompany accepts), with the first difficulty that deals it. */
export function liveStoryIds(id: string): { id: string; difficulty: "easy" | "medium" | "hard" }[] {
  const pool = livePool(id);
  const edr = feedCompanyProfile(id).architecture?.edr;
  const seen = new Set<string>();
  const out: { id: string; difficulty: "easy" | "medium" | "hard" }[] = [];
  for (const diff of ["easy", "medium", "hard"] as const) {
    for (const s of storiesForCompany(id, diff, true)) {
      if (seen.has(s.id)) continue;
      seen.add(s.id);
      let inst: AttackStory;
      try { inst = instantiateStory(s, pool, edr, id, seeded(`live:${id}:${s.id}`)); } catch { continue; }
      if (!storyHonoursLocks(inst.events, id)) continue;
      out.push({ id: s.id, difficulty: diff });
    }
  }
  return out;
}

/** A row with no native module shows its raw block: grouped by source + vendor, and event code when it has one. */
export const legacySource = (ev: TelemetryEvent) => `legacy:${ev.source}:${ev.vendor ?? "?"}`;
export function legacyType(ev: TelemetryEvent): string {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const code = r["event.code"] ?? r.EventID ?? r["winlog.event_id"] ?? r["data.win.system.eventID"] ?? r.eventName ?? r["event.action"];
  return code !== undefined ? `${ev.event_type}:${String(code)}` : ev.event_type;
}

/** One feed row as the page renders it. */
export function renderRow(surface: Surface, ev: TelemetryEvent, company: string, extra: Partial<LogRow>): LogRow {
  const v = (() => { try { return nativeView(ev, company, {}); } catch { return null; } })();
  const time = Date.parse(ev.ts);
  if (v) {
    return {
      surface, company, rowId: ev.id, source: v.log.sourceId, vendor: v.product, eventType: v.log.kind, time,
      raw: v.log.record, text: v.log.rawLine, severity: ev.severity, ev, native: v.log, ...extra,
    };
  }
  return {
    surface, company, rowId: ev.id, source: legacySource(ev), vendor: ev.vendor, eventType: legacyType(ev), time,
    raw: (ev.raw ?? {}) as Record<string, unknown>, severity: ev.severity, ev, ...extra,
  };
}

const seedOf = (s: string) => { let h = 7; for (let i = 0; i < s.length; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) >>> 0; return (h % 9973) + 1; };
/** A noise row's pool record: the deck's ids are `<pool id>[_v<n>]_<clock>_<i | q<k>>` (backfill rows keep the pool id). */
const poolIdOf = (id: string) => id.replace(/_\d{13}_(q?\d+)$/, "").replace(/_v\d+$/, "");
const isVariant = (id: string) => /_v\d+(_\d{13}_(q?\d+))?$/.test(id);

export function collectLive(out: Collected, companies = COMPANIES): void {
  for (const company of companies) {
    const rnd = seeded(`live-pool:${company}`);
    const pool = livePool(company).filter(e => fitsStack(e, company, {})).map(e => applyStack(e, company, {}));
    // Noise pool: each record once (as the deck first deals it), with its SIEM mirror (false positives are mirrored).
    const poolRows: LogRow[] = [];
    pool.forEach((e, i) => {
      const t = T0 - (pool.length - i) * 45_000 - Math.floor(rnd() * 20_000);
      const ev = { ...enrichEvent(withRebasedTime(e, new Date(t).toISOString()), i), id: `${e.id}` };
      const row = renderRow("live", ev, company, { storyId: `${company}:pool`, isAttack: false, rowId: `${company}:pool:${e.id}` });
      poolRows.push(row);
      const m = siemMirror(ev, 10_000 + i);
      if (m) poolRows.push(renderRow("live", m, company, { storyId: `${company}:pool`, isAttack: false, rowId: `${company}:pool:${e.id}:siem`, meta: { mirrorOf: row.rowId } }));
    });
    out.rows.push(...poolRows);

    const stories = liveStoryIds(company);
    const variants = new Set<string>();
    let storyRows = 0, variantRows = 0, shiftRows = 0;
    for (const { id: storyId, difficulty } of stories) {
      const shift = playShift(company, difficulty, seedOf(`${company}:${storyId}`), storyId);
      const s = shift.story;
      const rows: LogRow[] = [];
      const feed: LogRow[] = [];
      const atkTimes = shift.rows.filter(r => r.kind === "story" && r.attack).map(r => Date.parse(r.event.ts));
      const firstAttack = atkTimes.length ? Math.min(...atkTimes) : Infinity;
      let last: LogRow | undefined;
      for (const r of shift.rows) {
        const time = Date.parse(r.event.ts);
        if (r.kind === "story") {
          const e = s.events[r.storyIdx!];
          const base = { storyId: `${company}:${s.id}`, storyIndex: r.storyIdx, isAttack: r.attack };
          const row = r.mirror
            ? renderRow("live", r.event, company, { ...base, rowId: `${company}:${s.id}:${e.id}:siem`, meta: { mirrorOf: last?.rowId } })
            : renderRow("live", r.event, company, { ...base, authoredTime: Date.parse(r.authoredTs ?? e.ts), rowId: `${company}:${s.id}:${e.id}`, meta: { injected: r.placed, storyTitle: s.title } });
          if (!r.mirror) last = row;
          rows.push(row);
          if (time >= firstAttack) feed.push(row);
          continue;
        }
        // Ordinary rows: in the feed (R8). A record the deck re-homed to another person is a new record, collected once per person.
        const pid = poolIdOf(r.event.id);
        let row: LogRow;
        if (!r.mirror && isVariant(r.event.id)) {
          const key = `${company}:pool:${pid}~${String(r.event.user_email ?? "")}`;
          row = renderRow("live", r.event, company, { storyId: `${company}:pool`, isAttack: false, rowId: key });
          if (!variants.has(key)) { variants.add(key); out.rows.push(row); variantRows++; }
        } else {
          row = {
            surface: "live", company, storyId: `${company}:pool`, rowId: `${company}:pool:${pid}${r.mirror ? ":siem" : ""}`, source: r.event.source, vendor: r.event.vendor,
            eventType: r.event.event_type, time, raw: (r.event.raw ?? {}) as Record<string, unknown>, severity: r.event.severity, isAttack: false,
          };
        }
        if (time >= firstAttack) feed.push(row);
      }
      out.rows.push(...rows);
      storyRows += rows.length;
      shiftRows += shift.rows.length;
      out.feeds.push({ surface: "live", id: `${company}:${s.id}`, company, rows: feed, note: "one played shift, from the first attack row on" });
    }
    out.notes.push(`live ${company}: ${pool.length} noise records, ${stories.length} stories played (${shiftRows} shift rows; ${storyRows} story rows incl. SIEM mirrors; ${variantRows} re-homed noise records)`);
  }
}
