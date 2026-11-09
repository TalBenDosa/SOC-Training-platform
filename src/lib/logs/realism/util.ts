/**
 * Small pure helpers shared by the realism collectors and checkers.
 */
import type { LogRow } from "./types";

/** Seeded PRNG (mulberry32) so every collector is deterministic. */
export function seeded(seed: string): () => number {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) { h = Math.imul(h ^ seed.charCodeAt(i), 3432918353); h = (h << 13) | (h >>> 19); }
  let a = h >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Leaf [path, value] pairs of a record; array indices become "[]" (schema paths). */
export function leaves(v: unknown, prefix = "", out: [string, unknown][] = []): [string, unknown][] {
  if (Array.isArray(v)) {
    if (v.length === 0) out.push([`${prefix}[]`, "[]"]);
    for (const x of v) leaves(x, `${prefix}[]`, out);
    return out;
  }
  if (v !== null && typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    if (e.length === 0 && prefix) out.push([prefix, "{}"]);
    for (const [k, x] of e) leaves(x, prefix ? `${prefix}.${k}` : k, out);
    return out;
  }
  if (v === undefined) return out;
  out.push([prefix, v]);
  return out;
}

/** Leaf path set of a row's record (string raw: the key=value keys of the line, else empty). */
export function fieldSet(row: LogRow): Set<string> {
  if (typeof row.raw === "string") return new Set(kvKeys(row.raw));
  const s = new Set<string>();
  for (const [p, v] of leaves(row.raw)) if (v !== null && v !== "" && v !== undefined) s.add(p);
  return s;
}

function kvKeys(line: string): string[] {
  return [...line.matchAll(/(?:^|\s|\|)([A-Za-z_][\w.]{0,40})=/g)].map(m => m[1]);
}

/** Every [key, string value] of a row (record leaves, or key=value pairs of a text line). */
export function stringLeaves(row: LogRow): [string, string][] {
  const out: [string, string][] = [];
  if (typeof row.raw === "string") {
    out.push(["", row.raw]);
  } else {
    for (const [p, v] of leaves(row.raw)) if (typeof v === "string" || typeof v === "number") out.push([p, String(v)]);
  }
  return out;
}

export const lastKey = (path: string) => path.replace(/\[\]/g, "").split(".").pop() ?? path;

// ── IPv4 ───────────────────────────────────────────────────────────────────

export function ipToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
export function inCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  const n = Number(bits);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(base) & mask) >>> 0);
}
export const isValidIPv4 = (s: string) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split(".").every(o => Number(o) <= 255 && !(o.length > 1 && o.startsWith("0")));
export const isPrivateIPv4 = (ip: string) => inCidr(ip, "10.0.0.0/8") || inCidr(ip, "172.16.0.0/12") || inCidr(ip, "192.168.0.0/16");
export const DOC_RANGES = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
export const isDocIPv4 = (ip: string) => DOC_RANGES.some(c => inCidr(ip, c));
/** Not routable on the internet (loopback, link-local, CGNAT, multicast, reserved, this-network). */
export const isSpecialIPv4 = (ip: string) =>
  ["0.0.0.0/8", "2.5.0.0/16", "1.3.6.0/24", "1.2.840.0/24", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4", "192.0.0.0/24", "198.18.0.0/15"].some(c => inCidr(ip, c));

/**
 * IPv4 addresses a row really shows as addresses: a leaf whose whole value is an address (or
 * address:port, address/cidr), an address inside a URL, or an address in a field whose name says it
 * holds one. Version strings and OIDs are left alone.
 */
const IP_KEY = /(ip|addr|address|host|src|dst|client|remote|server|peer|source|destination|caller|forwarded|nat|gateway|origin|sender|recipient|target|endpoint|via|from|to)$/i;
const IP_IN_TEXT = /(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d]|\.\d)/g;
export function rowIps(row: LogRow): { key: string; ip: string }[] {
  const out: { key: string; ip: string }[] = [];
  for (const [k, v] of stringLeaves(row)) {
    if (/version|oid|syntax|build|useragent|user_agent/i.test(k)) continue;
    const whole = /^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+|\/\d+)?\s*$/.exec(v);
    if (whole) { if (isValidIPv4(whole[1])) out.push({ key: k, ip: whole[1] }); continue; }
    const keyed = !k || IP_KEY.test(lastKey(k)) || /:\/\//.test(v) || /\b(?:src|dst|ip|from|to|client|remote|addr)\s*[=:]/i.test(v);
    if (!keyed) continue;
    for (const m of v.matchAll(IP_IN_TEXT)) {
      const before = v.slice(Math.max(0, m.index! - 9), m.index!);
      if (/version|ver\s*$|v$|build|\bOS\b/i.test(before)) continue;
      if (isValidIPv4(m[1])) out.push({ key: k, ip: m[1] });
    }
  }
  return out;
}

// ── time ───────────────────────────────────────────────────────────────────

/** An instant in the forms the platform writes (ISO with or without zone, "YYYY-MM-DD HH:MM:SS", epoch ms / s). */
export function parseInstant(v: unknown, key?: string): number {
  const timeKey = key === undefined || /time|date|_at$|^ts$|created|stamp|^rt$|start|^end|^when$/i.test(key.split(".").pop() ?? key);
  if (typeof v === "number") {
    if (!timeKey) return NaN;
    if (v > 1e12 && v < 4e12) return v;
    if (v > 1e9 && v < 4e9) return v * 1000;
    return NaN;
  }
  if (typeof v !== "string") return NaN;
  const s = v.trim();
  if (/^\d{10,13}(\.\d+)?$/.test(s) && !timeKey) return NaN;
  if (/^\d{13}$/.test(s)) return Number(s);
  if (/^\d{10}(\.\d+)?$/.test(s)) return Number(s) * 1000;
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(s);
  if (!m) return NaN;
  const frac = m[3] ? m[3].slice(0, 4) : "";
  const zone = m[4] ? (m[4] === "Z" ? "Z" : m[4].length === 5 ? `${m[4].slice(0, 3)}:${m[4].slice(3)}` : m[4]) : "Z";
  return Date.parse(`${m[1]}T${m[2]}${frac}${zone}`);
}

export const isoOf = (ms: number | undefined) => (ms === undefined || !Number.isFinite(ms) ? "?" : new Date(ms).toISOString());

/** Normalized content of a row for duplicate detection (times, guids, long hex and ids stripped). */
export function contentKey(row: LogRow): string {
  const s = typeof row.raw === "string" ? row.raw : JSON.stringify(row.raw);
  return s
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g, "T")
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "G")
    .replace(/\b[0-9a-f]{16,}\b/gi, "H")
    .replace(/\b\d{9,}\b/g, "N");
}

export const short = (s: string, n = 140) => (s.length > n ? `${s.slice(0, n)}...` : s);
