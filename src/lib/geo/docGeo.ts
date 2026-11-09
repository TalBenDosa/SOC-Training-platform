/**
 * Places for documentation addresses (R5 + R4/R3 coherence).
 *
 * Attacker and third-party addresses in the scenario packs are documentation addresses
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). The platform's deterministic IP map
 * (@/lib/geo/resolveGeo) puts the whole of 203.0.113.0/24 in Shenzhen, China, so an emitter
 * that is not told where an address is prints China on rows whose story says Amsterdam,
 * Bucharest or Sofia. A pack names where each of its addresses is, and this pass gives
 * every row of that address the story's place: the typed geo, and the raw country, city and
 * coordinate values the emitters derived from the default map.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export interface DocPlace { country: string; iso: string; city?: string; latitude?: number; longitude?: number }

export const PLACES = {
  amsterdam: { country: "Netherlands", iso: "NL", city: "Amsterdam", latitude: 52.37, longitude: 4.9 },
  bucharest: { country: "Romania", iso: "RO", city: "Bucharest", latitude: 44.43, longitude: 26.1 },
  lagos: { country: "Nigeria", iso: "NG", city: "Lagos", latitude: 6.52, longitude: 3.38 },
  frankfurt: { country: "Germany", iso: "DE", city: "Frankfurt am Main", latitude: 50.11, longitude: 8.68 },
  moscow: { country: "Russia", iso: "RU", city: "Moscow", latitude: 55.76, longitude: 37.62 },
  sofia: { country: "Bulgaria", iso: "BG", city: "Sofia", latitude: 42.7, longitude: 23.32 },
  singapore: { country: "Singapore", iso: "SG", city: "Singapore", latitude: 1.35, longitude: 103.82 },
  ashburn: { country: "United States", iso: "US", city: "Ashburn", latitude: 39.04, longitude: -77.49 },
} satisfies Record<string, DocPlace>;

// What the default map writes for 203.0.113.0/24 (see KNOWN_GEO in @/lib/geo/resolveGeo).
const DEFAULT_COUNTRY = new Set(["China", "CN", "CHN"]);
const DEFAULT_CITY = "Shenzhen";
const DEFAULT_LAT = 22.5;
const DEFAULT_LON = 114.1;

function fix(v: unknown, key: string, p: DocPlace): unknown {
  if (typeof v === "string") {
    if (DEFAULT_COUNTRY.has(v)) return v.length <= 3 ? p.iso : p.country;
    if (v === DEFAULT_CITY) return p.city ?? v;
    return v;
  }
  if (typeof v === "number" && /lat/i.test(key) && v === DEFAULT_LAT) return p.latitude ?? v;
  if (typeof v === "number" && /lon/i.test(key) && v === DEFAULT_LON) return p.longitude ?? v;
  if (Array.isArray(v)) return v.map(x => fix(x, key, p));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fix(x, k, p)]));
  return v;
}

/** Give every row of a placed address the story's place (mutates and returns the array). */
export function placeDocAddresses<T extends TelemetryEvent>(events: T[], places: Record<string, DocPlace>): T[] {
  for (const e of events) {
    const ip = (e.src_ip && places[e.src_ip]) ? e.src_ip : (e.dst_ip && places[e.dst_ip]) ? e.dst_ip : undefined;
    if (!ip) continue;
    const p = places[ip];
    if (!e.geo?.country || DEFAULT_COUNTRY.has(e.geo.country)) {
      e.geo = { ...(e.geo ?? {}), country: p.country, ...(p.city ? { city: p.city } : {}),
        ...(p.latitude !== undefined ? { latitude: p.latitude, longitude: p.longitude } : {}) };
    } else if (e.geo.country === p.country || e.geo.country === p.iso) {
      // the row already names the story's country: complete the city and coordinates from the same place
      e.geo = { ...e.geo, city: !e.geo.city || e.geo.city === DEFAULT_CITY ? p.city : e.geo.city,
        latitude: e.geo.latitude ?? p.latitude, longitude: e.geo.longitude ?? p.longitude };
    } else if (e.geo.city === DEFAULT_CITY) {
      e.geo = { ...e.geo, city: p.city };
    }
    if (e.raw) e.raw = fix(e.raw, "", p) as Record<string, unknown>;
  }
  return events;
}
