/**
 * Live Feed (Dashboard) collector.
 *
 * Builds what /dashboard shows for each of the 5 built-in companies with their own products (no
 * stack chosen), the way page.tsx and useLiveEvents.ts build it:
 *   - the noise pool: the company's events, only the sources its architecture runs, never a real
 *     attack (companyEventsRaw), one host one IP (normalizeHostIps), only what its products can
 *     show (fitsStack), labelled for them (applyStack);
 *   - every story the company can be dealt (storiesForCompany easy / medium / hard), instantiated
 *     for the company (seeded), kept when it honours the product locks, labelled (applyStack);
 *   - each row re-timed as the feed re-times it (withRebasedTime, story clock "local"), enriched
 *     (enrichEvent), its SIEM mirror added (siemMirror), and rendered with nativeView. A row with no
 *     native module shows its legacy raw block, so that is what is collected.
 * Timing follows the hook's constants (90 s tick, 1-2 noise rows per tick, story phases of 2-3
 * rows 2-4 minutes apart, rows 20-45 s apart inside a phase) with a seeded random, so a run is
 * deterministic. One feed per story is recorded for R8 (noise around the attack).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES, NEXACORP_PROFILE } from "@/lib/sim/companyProfilesMeta";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";
import { storiesForCompany, instantiateStory, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { applyStack, fitsStack, nativeView, storyHonoursLocks } from "@/lib/logs/native";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { enrichEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import { siemMirror, phaseTimes } from "@/app/(app)/dashboard/useLiveEvents";
import { isAttackEvent } from "@/app/(app)/dashboard/groundTruth";
import type { Collected, LogRow, Surface } from "../types";
import { seeded } from "../util";

export const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const T0 = Date.parse("2026-11-09T08:00:00.000Z");

function profile(id: string) {
  return COMPANY_PROFILES.find(c => c.id === id) ?? NEXACORP_PROFILE;
}

/** page.tsx companyEventsRaw + normalizeHostIps. */
export function livePool(id: string): TelemetryEvent[] {
  const base = id === "nexacorp" ? BENIGN_EVENTS : (COMPANY_EVENTS[id] ?? BENIGN_EVENTS);
  const active = new Set(profile(id).architecture?.sources ?? []);
  const malicious = (e: TelemetryEvent) => { const v = String(e.expected_verdict ?? ""); return v === "tp" || v === "escalate"; };
  return normalizeHostIps(base.filter(e => (active.size === 0 || active.has(e.source)) && !malicious(e)));
}

/** Every story the dashboard can deal the company, instantiated for it (deterministic). */
export function liveStories(id: string): AttackStory[] {
  const pool = livePool(id);
  const edr = (profile(id).architecture as { edr?: string } | undefined)?.edr;
  const seen = new Set<string>();
  const out: AttackStory[] = [];
  for (const diff of ["easy", "medium", "hard"] as const) {
    for (const s of storiesForCompany(id, diff, true)) {
      if (seen.has(s.id)) continue;
      seen.add(s.id);
      let inst: AttackStory;
      try { inst = instantiateStory(s, pool, edr, id, seeded(`live:${id}:${s.id}`)); } catch { continue; }
      if (!storyHonoursLocks(inst.events, id)) continue;
      out.push({ ...inst, events: inst.events.map(e => applyStack(e, id, {})) });
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

export function collectLive(out: Collected, companies = COMPANIES): void {
  for (const company of companies) {
    const rnd = seeded(`live-pool:${company}`);
    const pool = livePool(company).filter(e => fitsStack(e, company, {})).map(e => applyStack(e, company, {}));
    // Noise pool: each record once, back-dated like a tick's rows.
    const poolRows: LogRow[] = pool.map((e, i) => {
      const t = T0 - (pool.length - i) * 45_000 - Math.floor(rnd() * 20_000);
      const ev = { ...enrichEvent(withRebasedTime(e, new Date(t).toISOString()), i), id: `${e.id}` };
      return renderRow("live", ev, company, { storyId: `${company}:pool`, isAttack: false, rowId: `${company}:pool:${e.id}` });
    });
    out.rows.push(...poolRows);

    const stories = liveStories(company);
    let storyRows = 0;
    for (const s of stories) {
      const r = seeded(`live-story:${company}:${s.id}`);
      const rows: LogRow[] = [];
      const feed: LogRow[] = [];
      // The shift: the first phase 2-3 minutes in, then a phase every 2-4 minutes.
      let now = T0 + 120_000 + Math.floor(r() * 60_000);
      let cursor = 0;
      let idx = 0;
      const startMs = T0;
      while (cursor < s.events.length) {
        const n = Math.min(s.events.length - cursor, 2 + (r() < 0.5 ? 1 : 0));
        const times = phaseTimes(n, now, r);
        s.events.slice(cursor, cursor + n).forEach((e, i) => {
          const authored = Date.parse(e.ts);
          const re = { ...withRebasedTime(e, new Date(times[i]).toISOString(), { storyClock: "local" }), id: `${s.id}#${cursor + i}` };
          const en = enrichEvent(re, idx++);
          const base = { storyId: `${company}:${s.id}`, storyIndex: cursor + i, authoredTime: authored, isAttack: isAttackEvent(e) };
          const row = renderRow("live", en, company, { ...base, rowId: `${company}:${s.id}:${e.id}`, meta: { injected: re, storyTitle: s.title } });
          rows.push(row);
          const m = siemMirror(en, idx++);
          if (m) rows.push(renderRow("live", m, company, { ...base, rowId: `${company}:${s.id}:${e.id}:siem`, meta: { mirrorOf: row.rowId } }));
        });
        cursor += n;
        if (cursor < s.events.length) now += 120_000 + Math.floor(r() * 120_000);
      }
      // The noise the feed streams over the same window: a tick every 90 s, 1-2 rows each.
      for (let t = startMs + 90_000; t <= now; t += 90_000) {
        const k = 1 + (r() < 0.5 ? 1 : 0);
        for (let j = 0; j < k && poolRows.length; j++) feed.push(poolRows[Math.floor(r() * poolRows.length)]);
      }
      feed.push(...rows);
      out.rows.push(...rows);
      storyRows += rows.length;
      out.feeds.push({ surface: "live", id: `${company}:${s.id}`, company, rows: feed, note: "one shift: noise ticks over the story window" });
    }
    out.notes.push(`live ${company}: ${poolRows.length} noise rows, ${stories.length} stories (${storyRows} story rows incl. SIEM mirrors)`);
  }
}
