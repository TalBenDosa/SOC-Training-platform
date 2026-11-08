/**
 * Sdema review 2026-11-08 (FINDINGS K6, K1, K10): the engine that turns authored stories into the feed.
 *  - K6: a story is squeezed from about 100 authored minutes into about 10 of feed. Every time inside
 *    its rows goes through ONE monotone map, so a field naming another row's time lands on that row:
 *    an alert's ExtendedProperties.*Time and StartTime / EndTime, a ticket's opened_at on every
 *    update, the clocks in a work note.
 *  - K1: ordinary telemetry stays at twice the attack rows; ServiceNow keeps to about 8%.
 *  - K10: the bonus attack is never the same kind as a planned one.
 * Built on the Sdema session config (storyRowsKept.test.ts), several seeds.
 */
import { describe, it, expect } from "vitest";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan, planFromConfig } from "./attackPlan";
import { tenantFromConfig } from "./tenant";
import { envFromConfig } from "./environment";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { storyThemes } from "./storyCategory";
import { ORDINARY_PER_ATTACK_ROW, ITSM_SHARE } from "./buildTimeline";

const CONFIG = {
  env: { industry: "general", platforms: ["azure", "linux"] },
  stack: { edr: "mde", detection_feed: "ms_graph" },
  tenant: { name: "sdemagroup" },
  attacks: { bonus: true, count: 3, slots: ["nexacorp-chain-d", "ai-rag-chatbot-document-injection", "ai-helpdesk-voice-reset"] },
};
const SEEDS = ["sdema-1", "sdema-a", "sdema-b", "129714f9"];
const ROSTER = [{ role: "t1" }, { role: "t2" }, { role: "mgr" }];

type Row = { channel: string; due_offset_ms: number; body: Record<string, unknown>; answer?: Record<string, unknown> };
function build(seed: string): Row[] {
  const plan = planFromConfig(CONFIG);
  const load = loadWithPlan(withShiftMinutes(teamLoad("medium", ROSTER), 30), plan);
  return buildFittedTimeline({
    companyId: "nexacorp", difficulty: "medium", seed, slots: plan.slots, load,
    stack: CONFIG.stack as never, tenant: tenantFromConfig(CONFIG), env: envFromConfig(CONFIG), opts: { bonus: true }, roster: ROSTER,
  }).timeline as Row[];
}
const timelines = new Map(SEEDS.map(s => [s, build(s)]));

const ans = (r: Row) => (r.answer ?? {}) as { origin?: string; incident_id?: string; attack_name?: string; original_id?: string; expected_verdict?: string; bonus?: boolean };
/** An instant in any form the engine writes (a no-zone form is UTC). */
function toMs(v: unknown): number {
  if (typeof v !== "string") return NaN;
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(v)) return Date.parse(v.replace(" ", "T") + "Z");
  return /^\d{4}-\d{2}-\d{2}T/.test(v) ? Date.parse(v) : NaN;
}
const hasMs = (v: string) => /:\d{2}\.\d+/.test(v);
/** The story rows of each incident (planned and bonus), with the authored event each one came from. */
function incidents(tl: Row[]) {
  const out = new Map<string, { row: Row; authored: { ts: string; raw?: Record<string, unknown> } | undefined }[]>();
  for (const r of tl) {
    const a = ans(r);
    if (a.origin !== "story" || !a.incident_id) continue;
    const story = ATTACK_STORIES.find(s => s.title === a.attack_name);
    const id = String(a.original_id ?? "").replace(/__\d+$/, "");
    const authored = story?.events.find(e => e.id === id);
    const k = `${r.channel}|${a.incident_id}`;
    (out.get(k) ?? out.set(k, []).get(k)!).push({ row: r, authored });
  }
  return out;
}

describe("K6: one time map per story", () => {
  for (const seed of SEEDS) {
    it(`seed ${seed}: a time field that names another row equals that row's time`, () => {
      let checked = 0;
      const wrong: string[] = [];
      for (const [inc, rows] of incidents(timelines.get(seed)!)) {
        const byAuthored = new Map<number, number[]>();
        for (const { row, authored } of rows) if (authored) {
          const t = Date.parse(authored.ts);
          (byAuthored.get(t) ?? byAuthored.set(t, []).get(t)!).push(Date.parse(String(row.body.ts)));
        }
        for (const { row, authored } of rows) {
          if (!authored?.raw) continue;
          const raw = (row.body.raw ?? {}) as Record<string, unknown>;
          for (const [k, v] of Object.entries(authored.raw)) {
            const t = toMs(v);
            if (!Number.isFinite(t) || t === Date.parse(authored.ts)) continue;   // a row's own time: covered by its ts
            const shown = byAuthored.get(t);
            if (!shown || !(k in raw)) continue;
            checked++;
            const got = toMs(raw[k]);
            const precise = hasMs(String(v));
            if (!shown.some(s => (precise ? s : Math.floor(s / 1000) * 1000) === got)) wrong.push(`${inc} ${k}=${String(raw[k])} (rows at ${shown.map(s => new Date(s).toISOString()).join(", ")})`);
          }
        }
      }
      expect(wrong).toEqual([]);
      expect(checked).toBeGreaterThan(3);   // the voice-reset alert names three rows, the RAG alert two
    });

    it(`seed ${seed}: one ticket keeps one opened_at`, () => {
      const seen = new Map<string, Set<string>>();
      for (const r of timelines.get(seed)!) {
        const raw = (r.body.raw ?? {}) as Record<string, unknown>;
        const n = raw["servicenow.number"];
        if (typeof n !== "string") continue;
        for (const k of ["servicenow.opened_at", "servicenow.sys_created_on"]) {
          if (typeof raw[k] !== "string") continue;
          const key = `${ans(r).incident_id ?? "-"}|${n}|${k}`;
          (seen.get(key) ?? seen.set(key, new Set()).get(key)!).add(String(raw[k]));
        }
      }
      const multi = [...seen].filter(([, s]) => s.size > 1).map(([k, s]) => `${k}: ${[...s].join(", ")}`);
      expect(multi).toEqual([]);
      expect([...seen.keys()].some(k => k.includes("INC0051764"))).toBe(true);   // the voice-reset ticket and its two updates
    });

    it(`seed ${seed}: a correlation alert's window lies inside its incident and before the alert`, () => {
      const wrong: string[] = [];
      let alerts = 0;
      for (const [inc, rows] of incidents(timelines.get(seed)!)) {
        const first = Math.min(...rows.map(x => Date.parse(String(x.row.body.ts))));
        for (const { row } of rows) {
          const raw = (row.body.raw ?? {}) as Record<string, unknown>;
          const own = Date.parse(String(row.body.ts));
          const start = toMs(raw.StartTime ?? raw["azure.alert.startTimeUtc"]);
          const end = toMs(raw.EndTime ?? raw["azure.alert.endTimeUtc"]);
          if (!Number.isFinite(start)) continue;
          alerts++;
          if (start < first) wrong.push(`${inc}: starts ${new Date(start).toISOString()} before the incident's first row ${new Date(first).toISOString()}`);
          if (start > own) wrong.push(`${inc}: starts after the alert itself`);
          if (Number.isFinite(end) && (end < start || end > own + 1000)) wrong.push(`${inc}: ends ${new Date(end).toISOString()} outside [start, alert]`);
        }
      }
      expect(wrong).toEqual([]);
      expect(alerts).toBeGreaterThan(1);
    });

    it(`seed ${seed}: the clocks in a story's work notes fall inside the story, never after the note`, () => {
      const wrong: string[] = [];
      let clocks = 0;
      for (const [inc, rows] of incidents(timelines.get(seed)!)) {
        const first = Math.min(...rows.map(x => Date.parse(String(x.row.body.ts))));
        for (const { row } of rows) {
          const note = ((row.body.raw ?? {}) as Record<string, unknown>)["servicenow.work_notes"];
          if (typeof note !== "string") continue;
          const own = Date.parse(String(row.body.ts));
          for (const m of note.matchAll(/(?<![\w:.])([01]\d|2[0-3]):([0-5]\d)(?![\w:])/g)) {
            const d = new Date(own);
            let at = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), Number(m[1]), Number(m[2]));
            if (at - own > 12 * 3_600_000) at -= 86_400_000;
            clocks++;
            if (at < Math.floor(first / 60_000) * 60_000 || at > own) wrong.push(`${inc}: "${m[0]}" in a note at ${new Date(own).toISOString()}`);
          }
        }
      }
      expect(wrong).toEqual([]);
      expect(clocks).toBeGreaterThan(0);   // "09:38 ... the 08:31 call recording"
    });
  }
});

describe("K1: the feed is mostly ordinary telemetry", () => {
  for (const seed of SEEDS) {
    it(`seed ${seed}: ordinary rows at twice the attack rows, ServiceNow near ${ITSM_SHARE * 100}%`, () => {
      const feed = timelines.get(seed)!.filter(r => r.channel === "feed");
      const attack = feed.filter(r => ["story", "pool_attack"].includes(String(ans(r).origin))).length;
      const ordinary = feed.filter(r => ans(r).origin === "noise" && ans(r).expected_verdict === "benign").length;
      const itsm = feed.filter(r => ans(r).origin === "itsm").length;
      expect(ordinary).toBeGreaterThanOrEqual(ORDINARY_PER_ATTACK_ROW * attack);
      expect(itsm / feed.length).toBeLessThanOrEqual(ITSM_SHARE + 0.03);
      // Every planned story row is still there (storyRowsKept.test.ts) and the feed keeps to the shift.
      expect(Math.max(...feed.map(r => r.due_offset_ms))).toBeLessThanOrEqual(30 * 60_000);
    });
  }
});

describe("K1: fitting a small team drops attacks it did not plan before it thins the noise", () => {
  it("an automatic plan for one Tier-1: the floor holds and the pinned-nothing storylines give way", () => {
    const roster = [{ role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
    const load = withShiftMinutes(teamLoad("medium", roster), 20);
    const { timeline, load: fitted } = buildFittedTimeline({ companyId: "nexacorp", difficulty: "medium", seed: "fit-small", slots: null, load, roster });
    const feed = (timeline as Row[]).filter(r => r.channel === "feed");
    const attack = feed.filter(r => ["story", "pool_attack"].includes(String(ans(r).origin))).length;
    const ordinary = feed.filter(r => ans(r).origin === "noise" && ans(r).expected_verdict === "benign").length;
    expect(ordinary).toBeGreaterThanOrEqual(ORDINARY_PER_ATTACK_ROW * attack);
    expect(fitted.stories + fitted.poolAttacks).toBeLessThanOrEqual(load.stories + load.poolAttacks);
    expect(fitted.stories).toBeGreaterThanOrEqual(1);
  });
});

describe("K10: the bonus is another kind of attack", () => {
  for (const seed of SEEDS) {
    it(`seed ${seed}: no category of a planned story`, () => {
      const tl = timelines.get(seed)!;
      const titleOf = (r: Row) => ATTACK_STORIES.find(s => s.title === ans(r).attack_name)?.id;
      const planned = new Set(tl.filter(r => r.channel === "feed" && ans(r).origin === "story").map(titleOf).filter((x): x is string => !!x));
      const bonus = new Set(tl.filter(r => r.channel === "bonus" && ans(r).origin === "story").map(titleOf).filter((x): x is string => !!x));
      expect(planned.size).toBe(3);
      expect(bonus.size).toBe(1);
      const plannedThemes = new Set([...planned].flatMap(storyThemes));
      expect([...bonus].flatMap(storyThemes).filter(t => plannedThemes.has(t))).toEqual([]);
    });
  }
  it("an AI voice-clone help-desk reset is also an identity attack", () => {
    expect(storyThemes("ai-helpdesk-voice-reset")).toEqual(["ai", "identity"]);
    expect(storyThemes("helpdesk-mfa-reset")).toEqual(["identity"]);
  });
});
