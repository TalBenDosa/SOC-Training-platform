/**
 * Raw-timestamp rebasing for the live feed.
 *
 * Static pool events (benignEvents.ts, scenarios.ts, scenario-packs/*) hardcode
 * their inner raw ISO timestamps off a FIXED template base (~May 2026). The feed
 * rebases each event's OUTER `ts` to session time as events stream in. Without
 * also shifting the timestamps INSIDE raw{}, an event's displayed time and the
 * timestamp fields inside its own raw log (pps.clickTime, azure…createdDateTime,
 * data.office365.CreationTime, Sysmon UtcTime, …) drift ~153 days apart. An
 * analyst builds the incident timeline from the RAW field — it is the evidence —
 * so the two must agree. `withRebasedTime` shifts every timestamp string inside
 * raw by the SAME delta applied to the outer ts, preserving each field's intended
 * offset (a click stays == ts; a delivery stays N minutes before it).
 *
 * Standalone (no React) so scripts/validate-runtime-feed can exercise it in CI.
 */

// Full ISO-8601 datetime with a timezone marker: "2026-05-08T10:20:00Z" / "...+02:00".
const ISO_TZ_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;
// Sysmon UtcTime style: "2026-05-10 08:00:00.123" (space, no timezone → treated as UTC).
const SYSMON_UTC_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/;

/** Return true if the string is a timestamp this module knows how to shift. */
export function isTimestampString(s: string): boolean {
  return ISO_TZ_RE.test(s) || SYSMON_UTC_RE.test(s);
}

export function shiftTimeString(s: string, deltaMs: number): string {
  if (ISO_TZ_RE.test(s)) {
    const ms = Date.parse(s);
    if (!Number.isFinite(ms)) return s;
    let out = new Date(ms + deltaMs).toISOString();            // …THH:MM:SS.sssZ
    if (!/\.\d+/.test(s)) out = out.replace(/\.\d{3}Z$/, "Z");  // preserve no-millis form
    return out;
  }
  if (SYSMON_UTC_RE.test(s)) {
    const ms = Date.parse(s.replace(" ", "T") + "Z");
    if (!Number.isFinite(ms)) return s;
    let out = new Date(ms + deltaMs).toISOString().replace("T", " ").replace("Z", "");
    if (!/\.\d+/.test(s)) out = out.replace(/\.\d{3}$/, "");
    return out;
  }
  return s;
}

export function rebaseTimestamps(value: unknown, deltaMs: number): unknown {
  if (typeof value === "string") return shiftTimeString(value, deltaMs);
  if (Array.isArray(value)) return value.map(v => rebaseTimestamps(v, deltaMs));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = rebaseTimestamps(v, deltaMs);
    }
    return out;
  }
  return value;
}

/**
 * Stamp an event's outer `ts` to `newTsIso` AND shift every timestamp inside its
 * raw{} by the same delta, so the raw evidence stays coherent with the displayed
 * time. Use this everywhere the feed re-times a pooled/story event.
 */
export function withRebasedTime<E extends { ts?: string; raw?: Record<string, unknown> }>(
  e: E, newTsIso: string,
): E {
  const origMs = e.ts ? Date.parse(e.ts) : NaN;
  const newMs = Date.parse(newTsIso);
  const delta = Number.isFinite(origMs) && Number.isFinite(newMs) ? newMs - origMs : 0;
  if (delta === 0 || !e.raw) return { ...e, ts: newTsIso };
  return { ...e, ts: newTsIso, raw: rebaseTimestamps(e.raw, delta) as Record<string, unknown> };
}
