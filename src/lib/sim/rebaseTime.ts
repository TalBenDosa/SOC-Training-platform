/**
 * Raw-timestamp re-timing for the live feed and the team timeline.
 *
 * Static pool events (benignEvents.ts, scenarios.ts, scenario-packs/*) and attack stories hardcode
 * their inner raw timestamps off a FIXED authored date. The feed re-stamps each event's OUTER `ts`
 * to session time. Without also moving the timestamps INSIDE raw{}, an event's displayed time and
 * the timestamp fields inside its own raw log (pps.clickTime, azure…createdDateTime,
 * data.office365.CreationTime, Sysmon UtcTime, a ticket's opened_at, …) drift apart. An analyst
 * builds the incident timeline from the RAW field: it is the evidence, so the two must agree.
 *
 * Two ways to move a row:
 *  - `withRebasedTime(e, newTs)`: every time inside the row moves by the row's own delta. Right for a
 *    self-contained row (noise, a ticket, a decoy) and for the client, which re-bases a whole feed
 *    by one session offset.
 *  - `withMappedTime(e, newTs, map)`: every time inside the row goes through `map`, ONE monotone
 *    function per attack story from authored time to shift time (storyTimeMap). A story is
 *    squeezed from its authored hour or two into a few minutes of feed, so a field that names
 *    ANOTHER row's time (a ticket's opened_at on its later updates, a correlation alert's
 *    StartTime / ExtendedProperties.*Time, a Defender alert's startTimeUtc) must land on that
 *    row's new time, not on "my new time minus the authored gap".
 *
 * ── The contract for log authors (emitters and story data) ─────────────────────────────────────
 * The engine moves, inside raw{} (nested objects and arrays included):
 *  1. any string that is, or contains, a date-time: ISO 8601 with or without a zone
 *     ("2026-09-22T08:48:31.097Z", "2026-09-22T08:56:12", "...+02:00"), the space form
 *     ("2026-09-22 08:34:09", Sysmon UtcTime, ServiceNow opened_at / sys_created_on), or one
 *     embedded in text ("zscalernss-web 2026-09-24 10:26:23"). The format is kept (zone, offset,
 *     precision);
 *  2. RFC 2822 dates with +0000 (mail Received headers) anywhere in a string;
 *  3. a syslog header at the start of a string ("Apr 14 21:40:00 host sshd[1]: ..."), year taken
 *     from the row;
 *  4. epoch seconds / milliseconds (number or digit string, 2015-2035) under a key named in
 *     EPOCH_KEY (timestamp, @timestamp, created_at, rt, eventTime, event_time);
 *  5. bare clock times ("09:38", "08:31:10") ONLY in the free-text keys of CLOCK_TEXT_KEY
 *     (ServiceNow work_notes / comments / close_notes / short_description / description,
 *     incident comment messages, mail subjects). A clock is read as the UTC wall time nearest the
 *     row's own authored ts and written back in UTC, like the raw ISO fields beside it.
 * Authors therefore: write every instant as one of these forms, in UTC unless the product writes an
 * offset; name another row's time with that row's exact authored ts (to the millisecond when the
 * row has milliseconds); keep clocks that are NOT instants (a policy's "Usual Logon Hours
 * 08:00-19:00", a "Query Period" of 00:10:00, a change window, a schtasks /st time) out of the
 * CLOCK_TEXT_KEY fields; and give a correlation alert's StartTime / EndTime the times of the first /
 * last rows it matched. Durations and windows that are not instants are never moved.
 *
 * Standalone (no React) so scripts/validate-runtime-feed can exercise it in CI.
 */

/** Authored epoch ms → new epoch ms. Must be non-decreasing. */
export type TimeMap = (ms: number) => number;

// Full-string forms.
const ISO_TZ_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;
const ISO_LOCAL_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/;
// Sysmon UtcTime / ServiceNow style: "2026-05-10 08:00:00.123" (space, no timezone → treated as UTC).
const SYSMON_UTC_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/;

/** Return true if the string is a timestamp this module knows how to shift. */
export function isTimestampString(s: string): boolean {
  return ISO_TZ_RE.test(s) || ISO_LOCAL_RE.test(s) || SYSMON_UTC_RE.test(s);
}

const p2 = (n: number) => String(n).padStart(2, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

// A date-time anywhere in a string: date, T or space, HH:MM, optional :SS and fraction, optional zone.
const DATETIME_G = /(?<![\d-])(\d{4})-(\d{2})-(\d{2})([T ])(\d{2}):(\d{2})(?::(\d{2})(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?(?![\d:])/g;

function zoneOffsetMin(z: string | undefined): number {
  if (!z || z === "Z") return 0;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(z);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
}

function mapDateTimes(s: string, f: TimeMap): string {
  if (!/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) return s;
  return s.replace(DATETIME_G, (m, y: string, mo: string, d: string, sep: string, hh: string, mi: string, ss: string | undefined, frac: string | undefined, zone: string | undefined) => {
    const [Y, M, D, H, Mi, S] = [y, mo, d, hh, mi, ss ?? "0"].map(Number);
    if (M < 1 || M > 12 || D < 1 || D > 31 || H > 23 || Mi > 59 || S > 59) return m;
    const fracMs = frac ? Math.floor(Number(`0${frac}`) * 1000 + 1e-6) : 0;
    const off = zoneOffsetMin(zone);
    const ms = Date.UTC(Y, M - 1, D, H, Mi, S, fracMs) - off * 60_000;
    if (!Number.isFinite(ms)) return m;
    const out = f(ms);
    if (!Number.isFinite(out) || out === ms) return m;
    const n = new Date(out + off * 60_000);   // wall clock in the original zone
    let r = `${n.getUTCFullYear()}-${p2(n.getUTCMonth() + 1)}-${p2(n.getUTCDate())}${sep}${p2(n.getUTCHours())}:${p2(n.getUTCMinutes())}`;
    if (ss !== undefined) {
      r += `:${p2(n.getUTCSeconds())}`;
      if (frac) {
        const digits = frac.length - 1;
        const msStr = String(n.getUTCMilliseconds()).padStart(3, "0");
        r += "." + (digits <= 3 ? msStr.slice(0, digits) : msStr + frac.slice(4));
      }
    }
    return r + (zone ?? "");
  });
}

// RFC 2822 dates (email Received headers): "Mon, 15 Jun 2026 09:23:14 +0000".
const RFC2822_RE = /\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), )?(\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) \+0000\b/g;
function mapRfc2822(s: string, f: TimeMap): string {
  if (!/\+0000/.test(s)) return s;
  return s.replace(RFC2822_RE, (m, d: string, mon: string, y: string, hh: string, mm: string, ss: string) => {
    const ms = Date.UTC(Number(y), MONTHS.indexOf(mon), Number(d), Number(hh), Number(mm), Number(ss));
    const out = f(ms);
    if (!Number.isFinite(out) || out === ms) return m;
    const n = new Date(out);
    const day = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), /.test(m) ? `${DAYS[n.getUTCDay()]}, ` : "";
    return `${day}${p2(n.getUTCDate())} ${MONTHS[n.getUTCMonth()]} ${n.getUTCFullYear()} ${p2(n.getUTCHours())}:${p2(n.getUTCMinutes())}:${p2(n.getUTCSeconds())} +0000`;
  });
}

// A syslog header at the start of a line: "Apr 14 21:40:00 host ..." / "Apr  4 21:40:00 ...".
const SYSLOG_RE = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( \d|\d{2}) (\d{2}):(\d{2}):(\d{2})(?= )/;
function mapSyslog(s: string, f: TimeMap, anchorMs: number): string {
  if (!Number.isFinite(anchorMs)) return s;
  const m = SYSLOG_RE.exec(s);
  if (!m) return s;
  const ref = new Date(anchorMs);
  let best = NaN;
  for (const y of [ref.getUTCFullYear() - 1, ref.getUTCFullYear(), ref.getUTCFullYear() + 1]) {
    const ms = Date.UTC(y, MONTHS.indexOf(m[1]), Number(m[2].trim()), Number(m[3]), Number(m[4]), Number(m[5]));
    if (!Number.isFinite(best) || Math.abs(ms - anchorMs) < Math.abs(best - anchorMs)) best = ms;
  }
  const out = f(best);
  if (!Number.isFinite(out) || out === best) return s;
  const n = new Date(out);
  const dd = m[2].startsWith(" ") && n.getUTCDate() < 10 ? ` ${n.getUTCDate()}` : p2(n.getUTCDate());
  return `${MONTHS[n.getUTCMonth()]} ${dd} ${p2(n.getUTCHours())}:${p2(n.getUTCMinutes())}:${p2(n.getUTCSeconds())}` + s.slice(m[0].length);
}

/**
 * Keys whose free text names clock times of the incident ("09:38: d.cohen phoned the desk", "at
 * 03:38 UTC"): the clocks move with the row. Matched on the key's last dotted segment (and, for
 * ServiceNow's description, the full key). Part of the author contract above.
 */
export const CLOCK_TEXT_KEY = /(?:^|\.)(?:work_notes|comments|comments_and_work_notes|close_notes|short_description|subject|Subject)$|^servicenow\.description$|(?:^|\.)Comments(?:\.\d+|\[\d+\])?\.message$/;
/** Keys that carry epoch seconds / milliseconds. Part of the author contract above. */
export const EPOCH_KEY = /(?:^|\.)(?:@timestamp|timestamp|created_at|rt|eventTime|event_time)$/;
const EPOCH_S = [1_420_070_400, 2_051_222_400];        // 2015-01-01 .. 2035-01-01
const EPOCH_MS = [EPOCH_S[0] * 1000, EPOCH_S[1] * 1000];

// A wall-clock time in prose ("at 09:45", "At 02:47:10"): not part of a MAC, an IPv6
// address, a version, a longer number, or a date-time (moved as a whole above).
const CLOCK_RE = /(?<![\w:.])(?<!\d{4}-\d{2}-\d{2}[ T])([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?(?!\w|:\w)/g;

/** Clock times in text, read as wall times nearest `anchorMs` (UTC), mapped through `f`, written in `zone`. */
export function mapClockText(text: string, anchorMs: number, f: TimeMap, zone: "utc" | "local" = "utc"): string {
  if (!text || !Number.isFinite(anchorMs)) return text;
  const o = new Date(anchorMs);
  return text.replace(CLOCK_RE, (m, hh: string, mm: string, ss: string | undefined) => {
    let at = Date.UTC(o.getUTCFullYear(), o.getUTCMonth(), o.getUTCDate(), Number(hh), Number(mm), Number(ss ?? 0));
    while (at - anchorMs > 12 * 3_600_000) at -= 86_400_000;   // the mention nearest the event
    while (anchorMs - at > 12 * 3_600_000) at += 86_400_000;
    const out = f(at);
    if (!Number.isFinite(out) || out === at) return m;
    const d = new Date(out);
    const [h, mi, s] = zone === "utc" ? [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()] : [d.getHours(), d.getMinutes(), d.getSeconds()];
    return ss === undefined ? `${p2(h)}:${p2(mi)}` : `${p2(h)}:${p2(mi)}:${p2(s)}`;
  });
}

/**
 * Attack-story prose names its own clock times, authored as the UTC wall time of the
 * event's authored `ts` ("signed in at 09:45"). When the event is re-stamped, those
 * times move by the same delta and are written in `zone`: "local" for the viewer's
 * clock, the one the feed's time column uses, so the row and its text agree.
 */
export function shiftClockText(text: string, origMs: number, deltaMs: number, zone: "utc" | "local" = "local"): string {
  if (!text || !deltaMs || !Number.isFinite(origMs)) return text;
  return mapClockText(text, origMs, ms => ms + deltaMs, zone);
}

export function shiftTimeString(s: string, deltaMs: number): string {
  return mapTimeString(s, ms => ms + deltaMs);
}

/** Every instant in one string value (full or embedded date-time, RFC 2822, syslog header). */
export function mapTimeString(s: string, f: TimeMap, anchorMs = NaN): string {
  return mapSyslog(mapRfc2822(mapDateTimes(s, f), f), f, anchorMs);
}

function mapEpoch(v: number | string, f: TimeMap): number | string {
  const n = typeof v === "number" ? v : /^\d{10}(\d{3})?$/.test(v) ? Number(v) : NaN;
  if (!Number.isFinite(n)) return v;
  const isMs = n >= EPOCH_MS[0] && n <= EPOCH_MS[1];
  const isS = n >= EPOCH_S[0] && n <= EPOCH_S[1];
  if (!isMs && !isS) return v;
  const out = isMs ? f(n) : f(n * 1000) / 1000;
  const r = isMs ? Math.round(out) : Number.isInteger(n) ? Math.floor(out) : Math.round(out * 1000) / 1000;
  return typeof v === "number" ? r : String(r);
}

/** Every instant inside a raw value (recursing objects and arrays), keyed by its dotted path. */
export function mapTimestamps(value: unknown, f: TimeMap, anchorMs = NaN, key = ""): unknown {
  if (typeof value === "string") {
    if (key && EPOCH_KEY.test(key) && /^\d{10}(\d{3})?$/.test(value)) return mapEpoch(value, f);
    const s = mapTimeString(value, f, anchorMs);
    return key && CLOCK_TEXT_KEY.test(key) ? mapClockText(s, anchorMs, f, "utc") : s;
  }
  if (typeof value === "number") return key && EPOCH_KEY.test(key) ? mapEpoch(value, f) : value;
  if (Array.isArray(value)) return value.map(v => mapTimestamps(v, f, anchorMs, key));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = mapTimestamps(v, f, anchorMs, key ? `${key}.${k}` : k);
    return out;
  }
  return value;
}

export function rebaseTimestamps(value: unknown, deltaMs: number, anchorMs = NaN): unknown {
  return mapTimestamps(value, ms => ms + deltaMs, anchorMs);
}

/**
 * Stamp an event's outer `ts` to `newTsIso` and send every time inside its raw{} through `f`
 * (the story's map). A time equal to the row's own authored ts becomes `newTsIso` exactly.
 */
export function withMappedTime<E extends { ts?: string; raw?: Record<string, unknown>; description?: string }>(
  e: E, newTsIso: string, f: TimeMap, opts: { storyClock?: "utc" | "local" } = {},
): E {
  const origMs = e.ts ? Date.parse(e.ts) : NaN;
  const newMs = Date.parse(newTsIso);
  if (!Number.isFinite(origMs) || !Number.isFinite(newMs)) return { ...e, ts: newTsIso };
  const g: TimeMap = ms => (ms === origMs ? newMs : f(ms));
  // Story prose moves with the event (opt-in: a benign row's "at 03:15, scheduled
  // end-of-day job" states a schedule, not the row's own time).
  const description = opts.storyClock && e.description ? mapClockText(e.description, origMs, g, opts.storyClock) : e.description;
  const out = { ...e, ts: newTsIso, ...(description !== e.description ? { description } : {}) };
  if (!e.raw) return out;
  return { ...out, raw: mapTimestamps(e.raw, g, origMs) as Record<string, unknown> };
}

/**
 * Stamp an event's outer `ts` to `newTsIso` AND shift every timestamp inside its
 * raw{} by the same delta, so the raw evidence stays coherent with the displayed
 * time. Use this everywhere the feed re-times a pooled/story event.
 */
export function withRebasedTime<E extends { ts?: string; raw?: Record<string, unknown>; description?: string }>(
  e: E, newTsIso: string, opts: { storyClock?: "utc" | "local" } = {},
): E {
  const origMs = e.ts ? Date.parse(e.ts) : NaN;
  const newMs = Date.parse(newTsIso);
  const delta = Number.isFinite(origMs) && Number.isFinite(newMs) ? newMs - origMs : 0;
  if (delta === 0) return { ...e, ts: newTsIso };
  return withMappedTime(e, newTsIso, ms => ms + delta, opts);
}

/**
 * One monotone map per attack story, from authored time to shift time. `anchors` pairs each
 * story row's authored ts with the time it is shown at. Between two rows a time is interpolated;
 * before the first / after the last it keeps its authored distance (slope 1), so "created 30
 * days ago" stays 30 days ago. Rows sharing an authored ts share the earliest shown time;
 * shown times are made non-decreasing in authored order.
 */
export function storyTimeMap(anchors: { authoredMs: number; shownMs: number }[]): TimeMap {
  const pts = anchors.filter(a => Number.isFinite(a.authoredMs) && Number.isFinite(a.shownMs)).sort((a, b) => a.authoredMs - b.authoredMs || a.shownMs - b.shownMs);
  const xs: number[] = [], ys: number[] = [];
  for (const p of pts) {
    if (xs.length && xs[xs.length - 1] === p.authoredMs) continue;
    xs.push(p.authoredMs);
    ys.push(Math.max(p.shownMs, ys.length ? ys[ys.length - 1] : -Infinity));
  }
  if (xs.length === 0) return ms => ms;
  return ms => {
    if (ms <= xs[0]) return ys[0] + (ms - xs[0]);
    const last = xs.length - 1;
    if (ms >= xs[last]) return ys[last] + (ms - xs[last]);
    let lo = 0, hi = last;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (xs[mid] <= ms) lo = mid; else hi = mid; }
    return Math.round(ys[lo] + ((ms - xs[lo]) * (ys[hi] - ys[lo])) / (xs[hi] - xs[lo]));
  };
}
