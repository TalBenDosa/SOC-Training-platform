// R4 (time coherence) and R7 (provable) for the room game labs: every worksheet and every trace.
// The time arithmetic a lab states in its text must be what its own rows show:
//  - every timestamp parses, and a log listing is in time order (oldest-first or newest-first);
//  - a "gap" or "seconds since last" column equals the difference of the times beside it;
//  - every "N minutes later / before / after / apart", "every N seconds" in the text equals the
//    difference between two times the lab shows (or is listed in CLAIM_EXEMPT with the reason);
//  - every worksheet answer in seconds, minutes, hours or days is a difference the rows show, or is
//    worked out from the rows in DERIVED (sums, averages, rates);
//  - a weekday written next to a date is that date's weekday;
//  - a lab that mixes UTC offsets says it works in UTC.
import { describe, it, expect } from "vitest";
import { appendFileSync } from "fs";
import { ROOMS } from "@/data/rooms";
import { getRoomExperience, type BriefingLab } from "./index";

type Worksheet = Extract<BriefingLab, { kind: "worksheet" }>;
type Trace = Extract<BriefingLab, { kind: "trace" }>;
type Lab = (Worksheet | Trace) & { room: string };

const labs: Lab[] = ROOMS.flatMap(room => {
  const exp = getRoomExperience(room.id, room.tasks.map(t => t.id));
  if (!exp) return [];
  return (Object.values(exp.briefings ?? {}).flat() as BriefingLab[])
    .filter((l): l is Worksheet | Trace => l.kind === "worksheet" || l.kind === "trace")
    .map(l => ({ ...l, room: room.id }));
});

// ─── Parsing ────────────────────────────────────────────────────────────────
const MON: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const DOW = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const DAY = 86400;
/** Day number for a month and day in a non-leap year; ordering only. */
const dayOf = (m: number, d: number) => Math.round((Date.UTC(2026, m, d) - Date.UTC(2026, 0, 1)) / 1000);

export interface Stamp { t: number; dated: boolean; secs: boolean; cycle: number; zone: string }

/** A timestamp at the start of a cell, in any of the formats the labs use. */
export function parseStamp(cell: string): Stamp | null {
  const s = cell.trim();
  let m: RegExpMatchArray | null;
  const hms = (h: string, mi: string, se?: string, fr?: string) => +h * 3600 + +mi * 60 + +(se ?? 0) + (fr ? +`0.${fr}` : 0);
  const ok = (h: string, mi: string, se?: string) => +h < 24 && +mi < 60 && +(se ?? 0) < 60;
  // 2026-10-14T09:12:33.123Z, 2026-10-14 09:12 -05:00, 2026-10-14 09:12:33 UTC
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?(?![\d-])/))) {
    if (+m[2] < 1 || +m[2] > 12 || +m[3] < 1 || +m[3] > 31 || (m[4] && !ok(m[4], m[5], m[6]))) return null;
    let off = 0;
    if (m[8] && /^[+-]/.test(m[8])) { const z = m[8].replace(":", ""); off = (z[0] === "-" ? -1 : 1) * (+z.slice(1, 3) * 3600 + +z.slice(3, 5) * 60); }
    return { t: Date.UTC(+m[1], +m[2] - 1, +m[3]) / 1000 + (m[4] ? hms(m[4], m[5], m[6], m[7]) : 0) - off, dated: true, secs: !!m[6], cycle: 0, zone: m[8] ?? "" };
  }
  // RFC 5322 mail date: Thu, 29 Oct 2026 13:46:05 +0530
  if ((m = s.match(/^(?:(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat), )?(\d{1,2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/)) && MON[m[2].toLowerCase()] !== undefined && ok(m[4], m[5], m[6])) {
    const off = (m[7][0] === "-" ? -1 : 1) * (+m[7].slice(1, 3) * 3600 + +m[7].slice(3, 5) * 60);
    return { t: Date.UTC(+m[3], MON[m[2].toLowerCase()], +m[1]) / 1000 + hms(m[4], m[5], m[6]) - off, dated: true, secs: true, cycle: 0, zone: m[7] };
  }
  // 10/14/2026 09:12:33 PM, 11/01/26 01:58
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})(?:[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?(?![\d/])/i))) {
    let h = m[4] ? +m[4] : 0;
    if (m[7]) h = (h % 12) + (/pm/i.test(m[7]) ? 12 : 0);
    const y = m[3].length === 2 ? 2000 + +m[3] : +m[3];
    return { t: Date.UTC(y, +m[1] - 1, +m[2]) / 1000 + (m[4] ? h * 3600 + +m[5] * 60 + +(m[6] ?? 0) : 0), dated: true, secs: !!m[6], cycle: 0, zone: "" };
  }
  // Oct 14 09:12:33, Oct  2 08:00, Dec 31 23:59:40 (syslog: no year)
  if ((m = s.match(/^([A-Z][a-z]{2})\s+(\d{1,2}),?\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?/)) && MON[m[1].toLowerCase()] !== undefined && ok(m[3], m[4], m[5]))
    return { t: dayOf(MON[m[1].toLowerCase()], +m[2]) + hms(m[3], m[4], m[5], m[6]), dated: true, secs: !!m[5], cycle: 365 * DAY, zone: "" };
  // 14 Oct 09:12
  if ((m = s.match(/^(\d{1,2})\s+([A-Z][a-z]{2})\w*\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/)) && MON[m[2].toLowerCase()] !== undefined && ok(m[3], m[4], m[5]))
    return { t: dayOf(MON[m[2].toLowerCase()], +m[1]) + hms(m[3], m[4], m[5]), dated: true, secs: !!m[5], cycle: 365 * DAY, zone: "" };
  // 10-27 02:05, 11/05 02:11:40
  if ((m = s.match(/^(\d{2})[-/](\d{2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/)) && +m[1] >= 1 && +m[1] <= 12 && ok(m[3], m[4], m[5]))
    return { t: dayOf(+m[1] - 1, +m[2]) + hms(m[3], m[4], m[5]), dated: true, secs: !!m[5], cycle: 365 * DAY, zone: "" };
  // Mon 10-19 19:41
  if ((m = s.match(/^(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)[a-z]*\.?,?\s+(\d{2})-(\d{2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/)) && +m[1] >= 1 && +m[1] <= 12 && ok(m[3], m[4], m[5]))
    return { t: dayOf(+m[1] - 1, +m[2]) + hms(m[3], m[4], m[5]), dated: true, secs: !!m[5], cycle: 365 * DAY, zone: "" };
  // Mon 02:54, Thursday 14:22, Sat 19 Sep 01:44 (weekday-led: a week cycle)
  if ((m = s.match(/^(Sun|Mon|Tue|Wed|Thu|Fri|Sat)[a-z]*\.?,?\s+(?:\d{1,2}\s+[A-Z][a-z]{2}\s+)?(\d{1,2}):(\d{2})(?::(\d{2}))?/)) && ok(m[2], m[3], m[4]))
    return { t: ((DOW.indexOf(m[1].toLowerCase()) + 6) % 7) * DAY + hms(m[2], m[3], m[4]), dated: true, secs: !!m[4], cycle: 7 * DAY, zone: "" };
  // 09:12, 09:12:33.123, 9:05 PM, 23:41 UTC
  if ((m = s.match(/^(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(?:\s*(UTC|Z|AM|PM)\b)?(?![\d:])/i))) {
    let h = +m[1];
    if (m[5] && /^(am|pm)$/i.test(m[5])) h = (h % 12) + (/pm/i.test(m[5]) ? 12 : 0);
    if (!ok(String(h), m[2], m[3])) return null;
    return { t: hms(String(h), m[2], m[3], m[4]), dated: false, secs: !!m[3], cycle: DAY, zone: m[5] && /utc|z/i.test(m[5]) ? "UTC" : "" };
  }
  return null;
}

interface Table { name: string; columns: string[]; rows: string[][] }
const tables = (l: Lab): Table[] => l.kind === "worksheet"
  ? [{ name: "", columns: l.columns, rows: l.rows }]
  : l.steps.map(s => ({ name: s.id, columns: s.columns, rows: s.rows }));
const labId = (l: Lab) => `${l.room} / ${l.title}`;

/** Columns that hold ranges, durations or counts rather than points in time. */
const NOT_A_CLOCK = /window|gap|duration|since last|elapsed|age|dwell|delta|Δ|uptime|sla|target|interval|period|retention|lifetime|sleep|jitter/i;
const PLACEHOLDER = /^(#.*|-|–|—|\?|n\/a|none|never|unknown|pending|not (yet|set|seen|logged|recorded)|\(.*\)|.*unknown.*|.*from memory.*|ongoing|open|still open|now|today|yesterday)$/i;

function clockColumns(t: Table): number[] {
  return t.columns.map((c, ci) => ci).filter(ci => {
    if (NOT_A_CLOCK.test(t.columns[ci])) return false;
    const cells = t.rows.map(r => (r[ci] ?? "").trim()).filter(c => c && !PLACEHOLDER.test(c));
    return cells.length > 0 && cells.filter(c => parseStamp(c)).length >= Math.max(1, Math.ceil(cells.length * 0.6));
  });
}

function textsOf(l: Lab): [string, string][] {
  const out: [string, string][] = [["prompt", l.prompt]];
  if (l.kind === "worksheet") {
    out.push(["caption", l.caption]);
    for (const q of l.questions) out.push([`${q.id}.q`, q.q], [`${q.id}.hint`, q.hint], [`${q.id}.why`, q.why]);
  } else {
    out.push(["lead", l.lead]);
    for (const s of l.steps) out.push([`${s.id}.source`, s.source], [`${s.id}.ask`, s.ask], [`${s.id}.why`, s.why], [`${s.id}.learned`, s.learned]);
  }
  return out.filter(([, t]) => !!t);
}

/**
 * The stamps a piece of the lab's text may talk about: table cells, plus every time the lab writes out.
 * A trace step's text talks about its own table and the rows picked so far, so a claim there must hold
 * between those (not between any two rows anywhere that happen to fit). `step` undefined: the whole lab.
 */
function stampsOf(l: Lab, step?: string): Stamp[] {
  const out: Stamp[] = [];
  const tabs = l.kind === "worksheet" || step === undefined ? tables(l)
    : l.steps.map(s => ({ name: s.id, columns: s.columns, rows: s.id === step ? s.rows : [s.rows[s.answer] ?? []] }));
  for (const t of tabs) {
    const cols = clockColumns(tables(l).find(x => x.name === t.name)!);
    for (const ci of cols) for (const r of t.rows) { const p = parseStamp(r[ci] ?? ""); if (p) out.push(p); }
  }
  // A cell can hold a time inside text ("rundll32 at 09:41:33"), and the lab's own text writes times out.
  const framing = [...textsOf(l).map(([, t]) => t), ...tabs.flatMap(t => t.rows.flat())];
  for (const txt of framing) for (const m of (txt ?? "").matchAll(/(?<![\d:.])(\d{1,2}:\d{2}(?::\d{2})?)(?![\d:])/g)) { const p = parseStamp(m[1]); if (p) out.push(p); }
  return out;
}

/** All positive differences between two stamps (time of day only when one side has no date). */
function differences(st: Stamp[]): { d: number; secs: boolean }[] {
  const out: { d: number; secs: boolean }[] = [];
  for (const a of st) for (const b of st) {
    let d = b.t - a.t;
    if (a.dated !== b.dated || (a.cycle === DAY) !== (b.cycle === DAY) || a.cycle === 7 * DAY !== (b.cycle === 7 * DAY)) {
      if (a.cycle !== 0 && b.cycle !== 0 && (a.cycle === DAY || b.cycle === DAY)) d = (((b.t % DAY) - (a.t % DAY)) + DAY) % DAY;
      else continue;
    }
    if (d < 0 && a.cycle === DAY && b.cycle === DAY) d += DAY; // across midnight
    if (d > 0) out.push({ d, secs: a.secs && b.secs });
  }
  return out;
}

// ─── Claims in the text ─────────────────────────────────────────────────────
const WORD: Record<string, number> = { a: 1, an: 1, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, ninety: 90 };
const UNIT: Record<string, number> = { s: 1, sec: 1, secs: 1, second: 1, seconds: 1, min: 60, mins: 60, minute: 60, minutes: 60, h: 3600, hr: 3600, hrs: 3600, hour: 3600, hours: 3600, day: DAY, days: DAY };
const NUM = String.raw`(\d+(?:\.\d+)?|a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|ninety)`;
const UNITS = String.raw`(seconds?|secs?|s|minutes?|mins?|min|hours?|hrs?|h|days?)`;
/** "N minutes later", "N min 18 s before", "every N seconds", "N seconds apart", "a gap of N minutes". */
const CLAIM = new RegExp(String.raw`(about |around |roughly |nearly |almost |some |under |over |just over |just under |more than |less than |close to |~)?\b${NUM}(?: and a half)?[\s-]+${UNITS}(?:,? (?:and )?(\d+)[\s-]*${UNITS})?\b(?=,? (?:later|after|before|earlier|apart|on from|ahead of|behind|between))`, "gi");
const EVERY = new RegExp(String.raw`\b(every|a gap of|gaps? of|interval of)( about| around| roughly)? ${NUM}(?: and a half)?[\s-]+${UNITS}\b`, "gi");

export interface Claim { where: string; text: string; secs: number; approx: boolean; unit: number }

function claimsOf(l: Lab): Claim[] {
  const out: Claim[] = [];
  const num = (s: string) => WORD[s.toLowerCase()] ?? parseFloat(s);
  for (const [where, txt] of textsOf(l)) {
    for (const m of txt.matchAll(CLAIM)) {
      const half = /and a half/.test(m[0]) ? 0.5 : 0;
      const unit = UNIT[m[3].toLowerCase()];
      let secs = (num(m[2]) + half) * unit;
      if (m[4] && m[5]) secs += num(m[4]) * UNIT[m[5].toLowerCase()];
      if (!m[1] && /^(a|an)$/i.test(m[2]) && unit >= 3600) continue; // "an hour later" is a phrase, not a measurement
      out.push({ where, text: m[0], secs, approx: !!m[1] || half > 0, unit: m[4] ? UNIT[m[5].toLowerCase()] : unit });
    }
    for (const m of txt.matchAll(EVERY)) {
      const half = /and a half/.test(m[0]) ? 0.5 : 0;
      const unit = UNIT[m[4].toLowerCase()];
      out.push({ where, text: m[0], secs: (num(m[3]) + half) * unit, approx: !!m[2] || half > 0, unit });
    }
  }
  return out;
}

function claimHolds(c: Claim, diffs: { d: number; secs: boolean }[]): boolean {
  return diffs.some(({ d, secs }) => {
    const base = c.unit === 1 ? (secs ? 1 : 60) : c.unit === 60 ? (secs ? 30 : 60) : c.unit === 3600 ? 15 * 60 : 12 * 3600;
    const tol = c.approx ? Math.max(base, c.secs * 0.2) : base;
    return Math.abs(d - c.secs) <= tol;
  });
}

/**
 * Durations in the text that are not a difference between two shown times, with the reason.
 * Key: `room / lab title / snippet`. A rule threshold, a policy, a schedule or a time outside the rows.
 */
const CLAIM_EXEMPT: Record<string, string> = {
  "bec-investigation / Run the Money Clock / One hour": "The table counts hours since the funds left (D: spotted 240, told 241); checked in DERIVED.",
  "bec-investigation / Run the Money Clock / 241 hours": "Case D's 'Bank told' cell is hour 241; checked in DERIVED.",
};

// ─── Worksheet answers ──────────────────────────────────────────────────────
/** The leading number of a cell: "1,512" 1512, "20 MB an hour" 20, "92%" 92, "-26" -26. */
const n = (s: string | undefined) => parseFloat((s ?? "").replace(/,/g, "").match(/-?\d+(\.\d+)?/)?.[0] ?? "NaN");
const col = (l: Worksheet, name: string) => {
  const i = l.columns.findIndex(c => c.toLowerCase().startsWith(name.toLowerCase()));
  if (i < 0) throw new Error(`${l.title}: no column ${name}`);
  return l.rows.map(r => r[i]);
};
const row = (l: Worksheet, has: string) => {
  const r = l.rows.find(x => x.some(c => c.includes(has)));
  if (!r) throw new Error(`${l.title}: no row with ${has}`);
  return r;
};
const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
const median = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const secs = (s: string) => parseStamp(s)!.t;
const gaps = (cells: string[]) => cells.slice(1).map((c, i) => { const d = secs(c) - secs(cells[i]); return d < 0 ? d + DAY : d; });
/** "sleep 300 seconds, jitter 20%" read from the lab's own prompt. */
const fromText = (txt: string, re: RegExp) => n(txt.match(re)?.[1]);

/**
 * Answers worked out from the rows (sums, means, medians, rates), computed here from the rows themselves,
 * so the accepted answer is proven by the evidence. Key: `room / lab title / question id`.
 */
const DERIVED: Record<string, (l: Worksheet) => number> = {
  "soc-structure / The Metrics Board / mttd": l => sum(l.rows.map(r => secs(r[2]) - secs(r[1]))) / l.rows.length / 3600,
  "soc-structure / The Metrics Board / mttr": l => sum(l.rows.map(r => secs(r[3]) - secs(r[2]))) / l.rows.length / 3600,
  "log-management / Storage Budget / bps": l => n(row(l, "events per second")[1]) * n(row(l, "event size")[1]),
  "log-management / Storage Budget / day": l => n(row(l, "events per second")[1]) * n(row(l, "event size")[1]) * n(row(l, "seconds in a day")[1]) / 1e9,
  "log-management / Storage Budget / comp": l => n(row(l, "events per second")[1]) * n(row(l, "event size")[1]) * n(row(l, "seconds in a day")[1]) / 1e9 * (1 - n(row(l, "compression")[1]) / 100),
  "ioc-analysis / What a Block Really Costs the Crew / q1": l => sum(col(l, "Hours lost").slice(0, 3).map(n)),
  "ioc-analysis / What a Block Really Costs the Crew / q2": l => sum(col(l, "Cost").slice(0, 3).map(n)),
  "ioc-analysis / What a Block Really Costs the Crew / q3": l => col(l, "Hours lost").map(n).filter(h => h <= 8).length,
  "ioc-analysis / What a Block Really Costs the Crew / q4": l => n(row(l, "TTPs")[3]) / n(row(l, "Domain names")[3]),
  // The oldest line needed is 11 hours old: 02:00 to 13:00 UTC, both in the prompt.
  "investigation-methodology / What Disappears First / w1": l => n(row(l, "VPN")[2]) / n(row(l, "VPN")[3]),
  "investigation-methodology / What Disappears First / w2": l => n(row(l, "VPN")[2]) / n(row(l, "VPN")[3]) - ageNeeded(l),
  "investigation-methodology / What Disappears First / w3": l => n(row(l, "Web proxy")[2]) / n(row(l, "Web proxy")[3]) - ageNeeded(l),
  "threat-hunting-fundamentals / Read the Dwell Times Yourself / all": l => median(col(l, "Dwell").map(n)),
  "threat-hunting-fundamentals / Read the Dwell Times Yourself / note": l => col(l, "How it came").filter(c => /ransom note/i.test(c)).length,
  "threat-hunting-fundamentals / Read the Dwell Times Yourself / quiet": l => median(l.rows.filter(r => /outsider/i.test(r[2])).map(r => n(r[3]))),
  "threat-hunting-fundamentals / Read the Gaps Between Requests / band": l => Math.max(...gaps(col(l, "time"))) - Math.min(...gaps(col(l, "time"))),
  "detection-engineering / What Does a Noisy Rule Cost? / one": l => { const r = row(l, "CDZ-0114"); return n(r[2]) * (1 - n(r[3]) / 100); },
  "detection-engineering / What Does a Noisy Rule Cost? / all": l => sum(l.rows.map(r => n(r[2]) * (1 - n(r[3]) / 100))),
  "escalation-procedures / How Long Did Each Page Sit? / missed": l => gaps2(col(l, "Confirmed"), col(l, "Paged")).filter(d => d > 600).length,
  "aws-security / Price the Fleet / count": l => sum(col(l, "Instances").map(n)),
  "aws-security / Price the Fleet / rate": l => sum(l.rows.map(r => n(r[3]) * n(r[4]))),
  "aws-security / Price the Fleet / total": l => sum(l.rows.map(r => n(r[3]) * n(r[4]))) * Math.round((secs("09:05") - secs(col(l, "eventTime")[0].slice(6, 11))) / 3600),
  "edge-case-usecases / What a Lookup Gives Away / rate": l => 60 / median(gaps(col(l, "Time"))),
  "soar-automation / Did the Bot Earn Its Keep? / w1": l => n(l.rows[0][3]) - n(l.rows[1][3]),
  "soar-automation / Did the Bot Earn Its Keep? / w2": l => n(l.rows[1][2]) / n(l.rows[1][1]) * 100,
  "soar-automation / Did the Bot Earn Its Keep? / w3": l => n(l.rows[1][2]) * 15 / 60,
  "tls-encrypted-traffic / The Shape of a Check-In / mean": l => sum(gaps(col(l, "ts"))) / (l.rows.length - 1),
  "tunneling-c2-channels / Work Out the Band / low": l => fromText(l.prompt, /sleep (\d+) seconds/) * (1 - fromText(l.prompt, /jitter (\d+)%/) / 100),
  "tunneling-c2-channels / Work Out the Band / high": l => fromText(l.prompt, /sleep (\d+) seconds/) * (1 + fromText(l.prompt, /jitter (\d+)%/) / 100),
  "tunneling-c2-channels / Work Out the Band / conv": l => fromText(l.prompt, /sleep (\d+) seconds/),
  "tunneling-c2-channels / Work Out the Band / fit": l => { const s = fromText(l.prompt, /sleep (\d+) seconds/), j = fromText(l.prompt, /jitter (\d+)%/) / 100; return gaps(col(l, "Time")).filter(g => g >= s * (1 - j) && g <= s * (1 + j)).length; },
  "incident-report-writing / Which Decision Can Nobody Prove? / days": l => { const r = row(l, "time unknown"); return (Date.UTC(2026, n(r[3].slice(0, 2)) - 1, n(r[3].slice(3, 5))) - Date.UTC(2026, n(r[0].slice(0, 2)) - 1, n(r[0].slice(3, 5)))) / 864e5; },
  "ransomware-full-lifecycle / The Case File, Line by Line / days": l => 0 - n(row(l, "signs in")[0]),
  "ransomware-full-lifecycle / The Case File, Line by Line / inside": l => n(l.rows[l.rows.findIndex(r => /uploaded/i.test(r[2])) - 1][0]),
  "ransomware-full-lifecycle / The Case File, Line by Line / before": l => col(l, "Day").filter(d => n(d) < 0).length,
  "bec-investigation / Run the Money Clock / gap": l => { const r = l.rows.find(x => x[0] === "B")!; return n(r[2]) - n(r[1]); },
  "bec-investigation / Run the Money Clock / late": l => { const r = l.rows.find(x => x[0] === "D")!; if (n(r[2]) - n(r[1]) > 1) return NaN; return n(r[4]); },
  "bec-investigation / Run the Money Clock / before": l => l.rows.filter(r => /never/i.test(r[3]) || n(r[2]) < n(r[3])).length,
  "google-workspace-security / Whose Downloads? / rate": l => { const r = row(l, "731884402196"); return n(r[2]) / n(r[3]); },
  "data-staging-exfiltration-channels / Whose Read Doesn't Fit? / factor": l => { const r = row(l, "d.kalina"); return Math.round(n(r[2]) / n(r[5])); },
};
/** "Tuesday, 13:00 UTC ... from about 02:00 UTC, so the oldest line you need is 11 hours old": the stated age must be the clock difference. */
function ageNeeded(l: Worksheet) {
  const [now, from] = [...l.prompt.matchAll(/(\d{2}:\d{2}) UTC/g)].map(m => secs(m[1]));
  const stated = fromText(l.prompt, /(\d+) hours old/);
  return (now - from) / 3600 === stated ? stated : NaN;
}
/** Confirmed-to-paged gaps, row by row, across midnight. */
function gaps2(a: string[], b: string[]) { return a.map((x, i) => { const d = secs(b[i]) - secs(x); return d < 0 ? d + DAY : d; }); }

/** Worksheet questions answered in a time unit whose answer is not a row-to-row difference. */
const ANSWER_EXEMPT: Record<string, string> = {};

// ─── Tests ──────────────────────────────────────────────────────────────────
/** Tables that are not in time order on purpose, with the reason. Key: `room / lab title / step`. */
const ORDER_EXEMPT: Record<string, string> = {
  "ioc-analysis / The Pivot Board / pdns": "Passive DNS results: one row per record, with first and last seen, not a log.",
  "ioc-analysis / The Pivot Board / rpdns": "Reverse passive DNS results: one row per name.",
  "ioc-analysis / The Pivot Board / rep": "Reputation lookups: one row per address.",
  "ioc-analysis / The Pivot Board / files": "Sandbox results: one row per sample.",
  "escalation-procedures / How Long Did Each Page Sit? / ": "Escalation review: one row per case, in case order.",
  "tunneling-c2-channels / From Gap to Owner / rare": "Destination prevalence: one row per destination.",
  "kerberos-authentication / Who Can Be Downgraded? / ": "Account attributes: one row per account.",
  "memory-disk-forensics / Two Timelines: Read Memory Beside Disk / mft": "MFTECmd output: one row per $MFT entry, in entry order.",
  "memory-disk-forensics / Two Timelines: Read Memory Beside Disk / ram": "windows.filescan / mftscan output: one row per file object, in offset order.",
  "memory-disk-forensics / Three More Witnesses: Prefetch, ShimCache, Amcache / pf": "PECmd output: one row per prefetch file.",
  "memory-disk-forensics / Three More Witnesses: Prefetch, ShimCache, Amcache / shim": "AppCompatCacheParser output: in CacheEntryPosition order, which is the point of ShimCache.",
  "memory-disk-forensics / Three More Witnesses: Prefetch, ShimCache, Amcache / net": "windows.netscan output: in pool offset order, as Volatility prints it.",
  "timestamps-and-timelines / Correct the Skew / ": "Raw times from three skewed clocks: the lab is about putting them in order.",
  "data-staging-exfiltration-channels / Do the Sizes Match? / share": "5145 summarised: one row per account and session, with its first and last read.",
};

/** Set LABTIME_OUT to a file path to get every finding in full while fixing content. */
function verdict(name: string, bad: string[]) {
  if (process.env.LABTIME_OUT && bad.length) appendFileSync(process.env.LABTIME_OUT, `## ${name}\n${bad.join("\n")}\n\n`);
  expect(bad).toEqual([]);
}

describe("lab time coherence (R4, R7)", () => {
  it("finds the labs", () => {
    expect(labs.filter(l => l.kind === "worksheet").length).toBeGreaterThan(140);
    expect(labs.filter(l => l.kind === "trace").length).toBeGreaterThan(45);
  });

  it("every DERIVED answer and every exemption names a lab, question or table that exists", () => {
    const bad: string[] = [];
    const questions = new Set(labs.flatMap(l => l.kind === "worksheet" ? l.questions.map(q => `${labId(l)} / ${q.id}`) : []));
    const tabs = new Set(labs.flatMap(l => tables(l).map(t => `${labId(l)} / ${t.name}`)));
    const titles = new Set(labs.map(labId));
    for (const k of [...Object.keys(DERIVED), ...Object.keys(ANSWER_EXEMPT)]) if (!questions.has(k)) bad.push(`no question ${k}`);
    for (const k of Object.keys(ORDER_EXEMPT)) if (!tabs.has(k)) bad.push(`no table ${k}`);
    for (const k of Object.keys(CLAIM_EXEMPT)) if (![...titles].some(t => k.startsWith(`${t} / `))) bad.push(`no lab ${k}`);
    verdict("every DERIVED answer and every exemption names a lab, question or table that exists", bad);
  });

  it("the parser reads the formats the labs use", () => {
    const t = (s: string) => parseStamp(s)?.t;
    expect(t("2026-09-18 19:05 -05:00")).toBe(t("2026-09-19 00:05 UTC"));
    expect(t("09:47:05")! - t("09:42:05")!).toBe(300);
    expect(t("9:05 PM")).toBe(21 * 3600 + 300);
    expect(parseStamp("25:00")).toBeNull();
    expect(parseStamp("10:61")).toBeNull();
    expect(t("Tue 01:20")! - t("Mon 23:46")!).toBe(94 * 60);
  });

  it("every timestamp in a time column parses", () => {
    const bad: string[] = [];
    for (const l of labs) for (const t of tables(l)) for (const ci of clockColumns(t)) t.rows.forEach((r, ri) => {
      const c = (r[ci] ?? "").trim();
      if (c && !PLACEHOLDER.test(c) && !parseStamp(c)) bad.push(`${labId(l)} / ${t.name}[${t.columns[ci]}] row ${ri}: "${c}"`);
    });
    verdict("every timestamp in a time column parses", bad);
  });

  it("a log listing is in time order, oldest-first or newest-first", () => {
    const bad: string[] = [];
    for (const l of labs) for (const t of tables(l)) {
      const ci = clockColumns(t)[0];
      if (ci === undefined || ORDER_EXEMPT[`${labId(l)} / ${t.name}`]) continue;
      const st = t.rows.map(r => parseStamp(r[ci] ?? "")).filter((s): s is Stamp => !!s);
      if (st.length < 3) continue;
      // A step backwards bigger than half a cycle is the clock wrapping (midnight, a new week, a new year).
      const step = (a: Stamp, b: Stamp) => { let d = b.t - a.t; if (a.cycle && b.cycle === a.cycle && d < -a.cycle / 2) d += a.cycle; return d; };
      const steps = st.slice(1).map((s, i) => step(st[i], s));
      if (!steps.every(d => d >= 0) && !steps.every(d => d <= 0))
        bad.push(`${labId(l)} / ${t.name}[${t.columns[ci]}]: ${t.rows.map(r => r[ci]).join(", ")}`);
    }
    verdict("a log listing is in time order, oldest-first or newest-first", bad);
  });

  it("a gap column equals the difference of the times beside it", () => {
    const bad: string[] = [];
    for (const l of labs) for (const t of tables(l)) {
      const ci = clockColumns(t)[0];
      if (ci === undefined) continue;
      t.columns.forEach((c, gi) => {
        if (!/gap|since last|delta|Δ/i.test(c)) return;
        const unit = /\(min|minutes/i.test(c) ? 60 : /\(h|hours/i.test(c) ? 3600 : 1;
        t.rows.forEach((r, ri) => {
          if (ri === 0) return;
          const v = parseFloat((r[gi] ?? "").replace(/,/g, ""));
          const a = parseStamp(t.rows[ri - 1][ci] ?? ""), b = parseStamp(r[ci] ?? "");
          if (!isFinite(v) || !a || !b) return;
          let d = b.t - a.t; if (d < 0 && a.cycle === DAY) d += DAY;
          if (Math.abs(Math.abs(d) - v * unit) > (unit === 1 ? 0.5 : unit / 2)) bad.push(`${labId(l)} / ${t.name} row ${ri}: ${c} says ${r[gi]}, the times give ${Math.abs(d) / unit}`);
        });
      });
    }
    verdict("a gap column equals the difference of the times beside it", bad);
  });

  it("every duration the text states is a difference between two times the lab shows", () => {
    const bad: string[] = [];
    for (const l of labs) {
      for (const c of claimsOf(l)) {
        const step = l.kind === "trace" && /\.(ask|why|learned)$/.test(c.where) ? c.where.split(".")[0] : undefined;
        const diffs = differences(stampsOf(l, step));
        if (claimHolds(c, diffs) || CLAIM_EXEMPT[`${labId(l)} / ${c.text}`]) continue;
        const near = diffs.map(x => x.d).sort((a, b) => Math.abs(a - c.secs) - Math.abs(b - c.secs))[0];
        bad.push(`${labId(l)} / ${c.where}: "${c.text}" = ${c.secs}s, nearest difference in the lab ${near ?? "none"}s`);
      }
    }
    verdict("every duration the text states is a difference between two times the lab shows", bad);
  });

  it("a worksheet answer in a time unit is a difference the rows show, or is worked out from them", () => {
    const bad: string[] = [];
    for (const l of labs) {
      if (l.kind !== "worksheet") continue;
      const diffs = differences(stampsOf(l));
      for (const q of l.questions) {
        const key = `${labId(l)} / ${q.id}`;
        const v = parseFloat(q.answer[0].replace(/,/g, ""));
        if (DERIVED[key]) {
          const got = DERIVED[key](l);
          if (Math.abs(got - v) > Math.max(0.011, Math.abs(v) * 0.001)) bad.push(`${key}: answer ${v}, the rows give ${got}`);
          continue;
        }
        // "in minutes", "how many hours", "complete minutes": the answer is a duration ("the second row" is not).
        const u = q.q.match(/\b(?:in|how many|many|whole|complete)\s+(?:whole\s+|complete\s+)?(seconds?|minutes?|hours?|days?)\b/i);
        if (!u || !/^-?[\d.,]+$/.test(q.answer[0].trim()) || ANSWER_EXEMPT[key]) continue;
        const unit = UNIT[u[1].toLowerCase()];
        const whole = /\b(whole|complete)\b/i.test(q.q + " " + l.prompt);
        const ok = diffs.some(({ d }) => whole ? Math.floor(d / unit + 1e-9) === v : Math.abs(d - v * unit) <= (unit === 1 ? 0.5 : unit / 2));
        if (!ok) bad.push(`${key}: "${q.q}" answer ${v}: not a difference between two times in the rows, and not in DERIVED`);
      }
    }
    verdict("a worksheet answer in a time unit is a difference the rows show, or is worked out from them", bad);
  });

  it("a weekday written beside a date is that date's weekday", () => {
    const bad: string[] = [];
    const W = "(Sun|Mon|Tue|Wed|Thu|Fri|Sat)[a-z]*";
    const M = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*";
    for (const l of labs) {
      const all = [...textsOf(l).map(([, t]) => t), ...tables(l).map(t => t.rows.map(r => r.join(" | ")).join("\n"))].join("\n");
      const years = [...all.matchAll(/\b(20[12]\d)\b/g)].map(m => +m[1]);
      const year = years.length ? years.sort((a, b) => years.filter(y => y === b).length - years.filter(y => y === a).length)[0] : 2026;
      const check = (w: string, y: number, mo: number, d: number, what: string) => {
        const real = DOW[new Date(Date.UTC(y, mo, d)).getUTCDay()];
        if (real !== w.slice(0, 3).toLowerCase()) bad.push(`${labId(l)}: "${what}" is a ${real}`);
      };
      for (const m of all.matchAll(new RegExp(String.raw`\b${W},? (\d{1,2}) ${M}\b`, "g"))) check(m[1], year, MON[m[3].toLowerCase().slice(0, 3)], +m[2], m[0]);
      for (const m of all.matchAll(new RegExp(String.raw`\b${W},? ${M} (\d{1,2})\b(?!:)`, "g"))) check(m[1], year, MON[m[2].toLowerCase().slice(0, 3)], +m[3], m[0]);
      for (const m of all.matchAll(new RegExp(String.raw`\b(\d{4})-(\d{2})-(\d{2}) \| ${W}\b`, "g"))) check(m[4], +m[1], +m[2] - 1, +m[3], m[0]);
      for (const m of all.matchAll(new RegExp(String.raw`\b${W},? (\d{4})-(\d{2})-(\d{2})\b`, "g"))) check(m[1], +m[2], +m[3] - 1, +m[4], m[0]);
    }
    verdict("a weekday written beside a date is that date's weekday", bad);
  });

  it("a lab that mixes UTC offsets says it works in UTC", () => {
    const bad: string[] = [];
    for (const l of labs) {
      const zones = new Set<string>();
      for (const t of tables(l)) for (const ci of clockColumns(t)) for (const r of t.rows) { const p = parseStamp(r[ci] ?? ""); if (p?.zone) zones.add(p.zone.replace("Z", "UTC")); }
      if (zones.size > 1 && !/\bUTC\b/.test(textsOf(l).map(([, t]) => t).join(" "))) bad.push(`${labId(l)}: ${[...zones].join(", ")}`);
    }
    verdict("a lab that mixes UTC offsets says it works in UTC", bad);
  });
});
