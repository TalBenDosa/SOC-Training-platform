/**
 * Free-text SIEM search for the Live Event Feed.
 *
 * Complements (never replaces) the dropdown filters: an event is shown only if
 * it passes the dropdowns AND matches the search query (AND semantics — the
 * dropdown pass lives in EventFeed's `filtered` memo, this file owns the text
 * match).
 *
 * Matching rules
 *  - Case-insensitive SUBSTRING across a flattened event representation:
 *    description + source + hostname + user + src/dst IP + rule id + MITRE +
 *    vendor + event_type + every stringified `raw` value.
 *  - Optional `field:value` tokens (e.g. `source:okta`, `host:FIN-WS-11`) match
 *    a single field instead of the whole blob. Unknown prefixes fall back to a
 *    plain substring, so a stray colon in normal text never breaks the search.
 *  - Multiple whitespace-separated tokens are AND-ed together.
 *
 * Performance: the flattened blob (which stringifies `raw`) is cached per event
 * object in a WeakMap so a re-render never re-stringifies, keeping the feed's
 * filter pass O(n) in the number of events.
 */
import type { LiveEvent } from "./useLiveEvents";

// `field:value` search keys → how to read that one field off an event.
const FIELD_ACCESSORS: Record<string, (ev: LiveEvent) => string | undefined> = {
  source:   (ev) => ev.source,
  host:     (ev) => ev.hostname,
  hostname: (ev) => ev.hostname,
  user:     (ev) => ev.user_email ?? ev.user?.email,
  ip:       (ev) => ev.src_ip,
  src:      (ev) => ev.src_ip,
  dst:      (ev) => ev.dst_ip,
  mitre:    (ev) => ev.mitre_technique,
  tactic:   (ev) => ev.mitre_tactic,
  rule:     (ev) => ev.ruleId,
  vendor:   (ev) => ev.vendor,
  event:    (ev) => ev.event_type,
  severity: (ev) => ev.severity,
};

/** Field keys the `field:value` syntax understands — exported for UI hints. */
export const SEARCH_FIELD_KEYS = Object.keys(FIELD_ACCESSORS);

// Per-event cache of the lowercased flattened blob. Keyed by the event object,
// so it is discarded automatically when the event leaves the feed.
const flatCache = new WeakMap<object, string>();

function flatten(ev: LiveEvent): string {
  const cached = flatCache.get(ev);
  if (cached !== undefined) return cached;
  const parts: (string | undefined)[] = [
    ev.displayDescription, ev.description, ev.source, ev.hostname,
    ev.user_email, ev.user?.email, ev.user?.full_name,
    ev.src_ip, ev.dst_ip, ev.ruleId, ev.mitre_technique, ev.mitre_tactic,
    ev.vendor, ev.event_type,
  ];
  let rawStr = "";
  try { rawStr = JSON.stringify(ev.raw ?? {}); } catch { rawStr = ""; }
  const text = `${parts.filter(Boolean).join(" ")} ${rawStr}`.toLowerCase();
  flatCache.set(ev, text);
  return text;
}

/**
 * True if the event matches the free-text query. An empty/whitespace query
 * matches everything (search is inactive).
 */
export function eventMatchesSearch(ev: LiveEvent, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const tokens = q.split(/\s+/);
  let flat: string | null = null;
  for (const token of tokens) {
    const colon = token.indexOf(":");
    if (colon > 0) {
      const key = token.slice(0, colon);
      const val = token.slice(colon + 1);
      const accessor = FIELD_ACCESSORS[key];
      if (accessor) {
        if (!val) continue; // "source:" with no value yet → ignore this token
        const fieldVal = (accessor(ev) ?? "").toLowerCase();
        if (!fieldVal.includes(val)) return false;
        continue;
      }
      // Unknown prefix (e.g. a timestamp, a "T1071:x" fragment) → plain substring.
    }
    if (flat === null) flat = flatten(ev);
    if (!flat.includes(token)) return false;
  }
  return true;
}
