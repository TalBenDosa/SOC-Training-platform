/**
 * Variation layer (Tal 2026-11-12: "every time an attack is rendered it must not repeat a previous
 * training; the background must change"). Pure, seeded by the caller's rnd, so Team Training replays a
 * session exactly while two sessions differ, and the solo feed differs on every shift.
 *
 * Attacker infrastructure is drawn per render: every documentation address (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24) the attack rows use gets a fresh address of the same range, and the
 * swap is applied to the whole story (every row, every raw value, every text: descriptions, hints,
 * explanations), so the plot stays coherent. A learner who saw 203.0.113.99 last time sees another
 * address this time.
 *
 * Never swapped:
 *  - private and loopback addresses (the company's own hosts are re-homed elsewhere);
 *  - the company's office egress and any address of the company's ordinary noise;
 *  - addresses of a known operator (docOwnerOfIp: a scanner, a cloud provider, a Tor exit), the
 *    authorized third parties a story relies on;
 *  - an address whose place the platform map decides (knownGeoForIp) when no row states its place,
 *    unless the new address maps to the same place: the location an analyst reads never changes.
 */
import type { TelemetryEvent } from "./types";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";
import { docOwnerOfIp } from "./docAddresses";
import { COMPANY_ASSETS } from "./companyProfilesMeta";

const DOC_RE = /(?<![\d.])(?:192\.0\.2|198\.51\.100|203\.0\.113)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d])/g;
const GEO_KEYS = ["source.geo.country_name", "destination.geo.country_name", "GeoLocation.country_name", "data.srccountry",
  "okta.client.geographicalContext.country", "azure.signinlogs.properties.location.countryOrRegion", "httpRequest.country"];

const isAttackRow = (e: TelemetryEvent) => !e.is_baseline && e.expected_verdict !== "fp" && !e.fp_explanation;

/** Every documentation address in a value (deep). */
export const collectDocIps = (v: unknown, out: Set<string>) => collectIps(v, out);
function collectIps(v: unknown, out: Set<string>): void {
  if (typeof v === "string") { for (const m of v.matchAll(DOC_RE)) out.add(m[0]); return; }
  if (Array.isArray(v)) { for (const x of v) collectIps(x, out); return; }
  if (v && typeof v === "object") for (const x of Object.values(v as Record<string, unknown>)) collectIps(x, out);
}

/** Does every row that names this address also state its place (so the map is never consulted)? */
function rowsStatePlace(ip: string, events: TelemetryEvent[]): boolean {
  const rows = events.filter(e => JSON.stringify(e).includes(ip));
  return rows.length > 0 && rows.every(e => !!e.geo?.country || GEO_KEYS.some(k => {
    const v = (e.raw as Record<string, unknown> | undefined)?.[k];
    return typeof v === "string" && v !== "";
  }));
}

const placeKey = (ip: string) => JSON.stringify(knownGeoForIp(ip) ?? null);
const dashed = (ip: string) => ip.replace(/\./g, "-");
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Replace every mapped address (dotted, and the dashed form a PTR name uses) in every string of a value. */
function swapDeep<T>(v: T, map: Map<string, string>, re: RegExp, reDashed: RegExp | null, dashedMap: Map<string, string>): T {
  if (typeof v === "string") {
    let s = v.replace(re, m => map.get(m) ?? m);
    if (reDashed) s = s.replace(reDashed, m => dashedMap.get(m) ?? m);
    return s as T;
  }
  if (Array.isArray(v)) return v.map(x => swapDeep(x, map, re, reDashed, dashedMap)) as T;
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = swapDeep(x, map, re, reDashed, dashedMap);
    return out as T;
  }
  return v;
}

export interface Variation { ips: Record<string, string> }

/**
 * A fresh set of attacker addresses for this render. Returns the story with the swap applied everywhere,
 * and the mapping (for tests and for staff-only session records).
 */
export function varyAttackerInfra<S extends { id: string; events: TelemetryEvent[] }>(
  story: S, companyPool: TelemetryEvent[], companyId: string | undefined, rnd: () => number,
  opts: { reserved?: Iterable<string>; used?: Set<string> } = {},
): { story: S; variation: Variation } {
  const attackIps = new Set<string>();
  for (const e of story.events) if (isAttackRow(e)) collectIps(e, attackIps);
  if (!attackIps.size) return { story, variation: { ips: {} } };

  // Addresses that are not the attacker's: the company's offices, its ordinary noise, known operators.
  const reserved = new Set<string>();
  for (const a of Object.values(COMPANY_ASSETS)) if (a.office?.ip) reserved.add(a.office.ip);
  for (const e of companyPool) collectIps(e, reserved);
  for (const e of story.events) if (!isAttackRow(e)) collectIps(e, reserved);
  // Never handed out (but swapped away from when it is this story's attacker): every address the catalog
  // authors (another storyline's attacker, a partner) and every address this render context already drew
  // (the other storylines of a team session).
  const used = new Set<string>([...reserved, ...(opts.reserved ?? []), ...(opts.used ?? [])]);
  collectIps(story.events, used);

  const map = new Map<string, string>();
  for (const ip of [...attackIps].sort()) {
    if (reserved.has(ip) || docOwnerOfIp(ip) || companyId && COMPANY_ASSETS[companyId]?.office?.ip === ip) continue;
    const net = ip.slice(0, ip.lastIndexOf("."));
    const free = rowsStatePlace(ip, story.events);
    const want = placeKey(ip);
    let pick: string | undefined;
    // Three-digit last octets first, so a new address is never the prefix of another (198.51.100.2 inside
    // 198.51.100.25); two digits only where the place needs it (the low 203.0.113.x hosting bucket).
    for (let t = 0; t < 400 && !pick; t++) {
      const cand = `${net}.${t < 300 ? 100 + Math.floor(rnd() * 155) : 10 + Math.floor(rnd() * 90)}`;
      if (used.has(cand) || docOwnerOfIp(cand)) continue;
      if (!free && placeKey(cand) !== want) continue;
      pick = cand;
    }
    if (!pick) continue;
    used.add(pick);
    opts.used?.add(pick);
    map.set(ip, pick);
  }
  if (!map.size) return { story, variation: { ips: {} } };

  const re = new RegExp(`(?<![\\d.])(?:${[...map.keys()].map(esc).join("|")})(?![\\d])`, "g");
  const dashedMap = new Map([...map].map(([a, b]) => [dashed(a), dashed(b)]));
  const reDashed = new RegExp(`(?<![\\d-])(?:${[...dashedMap.keys()].map(esc).join("|")})(?![\\d])`, "g");
  // The story's own id never changes; everything else (rows, title, hints, explanations) follows the swap.
  const swapped = swapDeep({ ...story, id: "\u0000" } as S, map, re, reDashed, dashedMap);
  return { story: { ...swapped, id: story.id }, variation: { ips: Object.fromEntries(map) } };
}
