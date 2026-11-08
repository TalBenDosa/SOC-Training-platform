/**
 * The investigation console is XDR, this platform's own product (owner, 2026-11-08: it must not
 * imitate Microsoft Sentinel). What the console's own analytics raise reads as XDR Analytics, and
 * nothing in an XDR session names Microsoft Sentinel or Azure Sentinel as the console.
 *
 * Source products keep their real names (Microsoft Defender for Endpoint, Entra ID Protection,
 * GuardDuty...): they are the data, not the console. KQL table and column names stay as they are
 * (SecurityAlert, SecurityIncident, SentinelHealth...): they are the data model analysts query.
 * Pure and isomorphic.
 */

/** ProductName of an alert the console's own analytics rules raise. */
export const XDR_PRODUCT = "XDR Analytics";
/** ProviderName of an alert a scheduled analytics rule of the console raises. */
export const XDR_PROVIDER = "XDR Scheduled Alerts";
/** Who the console writes as, in an incident's activity log and ModifiedBy. */
export const XDR_ACTOR = "XDR";

const EXACT: Record<string, string> = {
  "Azure Sentinel": XDR_PRODUCT,
  "Microsoft Sentinel": XDR_PRODUCT,
  "ASI Scheduled Alerts": XDR_PROVIDER,
  "Microsoft Sentinel UEBA": "XDR UEBA",
};

/** A value names the old console only if it holds one of these (cheap test before any regex). */
const MAYBE = /Sentinel|ASI Scheduled/;

/**
 * One string with the console renamed. "SentinelOne" (an EDR vendor) and table names such as
 * SentinelHealth never match: the name must stand alone as a word.
 */
export function xdrText(s: string): string {
  if (!MAYBE.test(s)) return s;
  const exact = EXACT[s];
  if (exact) return exact;
  return s
    .replace(/\b(A|a) (?:Microsoft|Azure) Sentinel\b/g, "$1n XDR")
    .replace(/\b(?:Microsoft|Azure) Sentinel\b/g, "XDR")
    .replace(/\bASI Scheduled Alerts\b/g, XDR_PROVIDER)
    .replace(/\bSentinel(?= (?:raised|raises|rule|fired|flagged|opened|KQL|UEBA|analytics|incident|workspace)\b)/g, "XDR");
}

/**
 * A value (string, array or plain object, nested) with every string passed through xdrText.
 * Copy on write: an unchanged value comes back as the same reference, and the input is never
 * mutated (feed payloads are shared with the rest of the team room).
 */
export function xdrValue<T>(v: T, depth = 0): T {
  if (typeof v === "string") return xdrText(v) as unknown as T;
  // The workspace build runs this over every row on every poll: a value with nothing to rename
  // (nearly all) is only scanned, with no allocation.
  if (!v || typeof v !== "object" || depth > 8 || !mentions(v, depth)) return v;
  if (Array.isArray(v)) {
    let out: unknown[] | null = null;
    for (let i = 0; i < v.length; i++) {
      const x = v[i]; const y = xdrValue(x, depth + 1);
      if (y !== x) { out ??= v.slice(); out[i] = y; }
    }
    return (out ?? v) as unknown as T;
  }
  const o = v as Record<string, unknown>;
  let out: Record<string, unknown> | null = null;
  for (const k in o) {
    if (!Object.prototype.hasOwnProperty.call(o, k)) continue;
    const x = o[k]; const y = xdrValue(x, depth + 1);
    if (y !== x) { out ??= { ...o }; out[k] = y; }
  }
  return (out ?? v) as unknown as T;
}

/** Whether a value (an event payload, a row) holds, at any depth, a string that may name the old console. */
export const mentionsConsole = (v: unknown): boolean => mentions(v, 0);

/** Whether a plain value holds, at any depth, a string that may name the old console. */
function mentions(v: unknown, depth: number): boolean {
  if (typeof v === "string") return MAYBE.test(v);
  if (!v || typeof v !== "object" || depth > 8) return false;
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) if (mentions(v[i], depth + 1)) return true; return false; }
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return false;
  const o = v as Record<string, unknown>;
  for (const k in o) if (Object.prototype.hasOwnProperty.call(o, k) && mentions(o[k], depth + 1)) return true;
  return false;
}
