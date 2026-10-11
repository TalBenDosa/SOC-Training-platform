/**
 * Single source of truth for "where is this IP / event from?".
 *
 * The platform previously answered this in two disconnected places: the live feed
 * enrichment (event.geo → a deterministic IP-prefix map, written to
 * GeoLocation.*) and the threat-intel pivot drawer (which read ONLY
 * source.geo.country_name and otherwise fell back to a country hardcoded PER
 * THREAT CATEGORY). So the same attacker IP could show as, say, Bulgaria in the
 * feed and a category-default country in the pivot — data the analyst is being
 * trained to trust contradicting itself.
 *
 * Both surfaces now resolve geography through this module, so one IP always maps
 * to one country and city. The precedence mirrors the feed's own order: an
 * explicitly-authored geo on the event wins; otherwise a deterministic per-IP
 * lookup keyed on the address prefix (never random, never per-render).
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export interface GeoPoint { country: string; city: string; lat: number; lon: number }

/** Deterministic IP-prefix → location. Prefix match, so an IP always resolves the
 *  same way regardless of which view asks. Shared by the feed enrichment and the
 *  threat-intel drawer. */
export const KNOWN_GEO: Record<string, GeoPoint> = {
  "203.0.113.": { country: "China",       city: "Shenzhen",   lat: 22.5,  lon: 114.1 },
  "91.108.":    { country: "Russia",      city: "Moscow",     lat: 55.7,  lon:  37.6 },
  "185.220.":   { country: "Netherlands", city: "Amsterdam",  lat: 52.3,  lon:   4.9 },
  "45.142.":    { country: "Ukraine",     city: "Kyiv",       lat: 50.4,  lon:  30.5 },
  "62.210.":    { country: "France",      city: "Paris",      lat: 48.8,  lon:   2.3 },
  "52.230.":    { country: "United States", city: "Seattle",  lat: 47.6,  lon: -122.3 },
  "20.190.":    { country: "United States", city: "Redmond",  lat: 47.7,  lon: -122.1 },
  "196.251.":   { country: "Nigeria",     city: "Lagos",      lat:  6.5,  lon:   3.4 },
  "194.26.":    { country: "Russia",      city: "St. Petersburg", lat: 59.9, lon: 30.3 },
  "5.188.":     { country: "Russia",      city: "Moscow",     lat: 55.7,  lon:  37.6 },
  "23.129.":    { country: "United States", city: "Tor Exit — Unknown", lat: 39.0, lon: -77.5 },
  "104.16.":    { country: "United States", city: "San Francisco (Cloudflare)", lat: 37.8, lon: -122.4 },
  "140.82.":    { country: "United States", city: "San Francisco (GitHub)", lat: 37.8, lon: -122.4 },
  "151.101.":   { country: "United States", city: "San Francisco (Fastly)", lat: 37.8, lon: -122.4 },
  "52.216.":    { country: "United States", city: "Ashburn (AWS S3)", lat: 39.0, lon: -77.5 },
  "3.120.":     { country: "Germany",     city: "Frankfurt (AWS)", lat: 50.1, lon: 8.7 },
  "34.107.":    { country: "Germany",     city: "Frankfurt (GCP)", lat: 50.1, lon: 8.7 },
  "178.62.":    { country: "Netherlands", city: "Amsterdam (DigitalOcean)", lat: 52.3, lon: 4.9 },
  "159.89.":    { country: "India",       city: "Bangalore",  lat: 12.9,  lon:  77.6 },
  "168.196.":   { country: "Brazil",      city: "São Paulo",  lat: -23.5, lon: -46.6 },
  "103.75.":    { country: "Hong Kong",   city: "Hong Kong",  lat: 22.3,  lon: 114.2 },
  "80.94.":     { country: "Romania",     city: "Bucharest",  lat: 44.4,  lon:  26.1 },
  "207.154.":   { country: "United Kingdom", city: "London",  lat: 51.5,  lon:  -0.1 },
};

/** Deterministic per-IP location, or null when the prefix isn't known. */
export function knownGeoForIp(ip?: string | null): GeoPoint | null {
  if (!ip) return null;
  const prefix = Object.keys(KNOWN_GEO).find(k => ip.startsWith(k));
  return prefix ? KNOWN_GEO[prefix] : null;
}

// Every raw key across the corpus that a vendor uses to carry an origin COUNTRY,
// in the same precedence the feed applies. Checked in order; first non-empty wins.
const COUNTRY_KEYS = [
  "source.geo.country_name", "destination.geo.country_name",
  "GeoLocation.country_name",
  "data.srccountry",
  "okta.client.geographicalContext.country",
  "azure.signinlogs.properties.location.countryOrRegion",
] as const;

const CITY_KEYS = [
  "source.geo.city_name", "destination.geo.city_name",
  "GeoLocation.city_name",
  "azure.signinlogs.properties.location.city",
  "okta.client.geographicalContext.city",
] as const;

function firstRaw(raw: Record<string, unknown>, keys: readonly string[]): string {
  for (const k of keys) {
    const v = raw[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

/**
 * The country for an event, resolved consistently: authored geo (struct → typed
 * fields → any vendor raw key) first, then a deterministic per-IP fallback.
 * Returns "" only when nothing is known — callers may then apply their own
 * last-resort default.
 */
export function resolveCountry(event: TelemetryEvent): string {
  return (
    event.geo?.country?.trim() ||
    firstRaw(event.raw ?? {}, COUNTRY_KEYS) ||
    knownGeoForIp(event.src_ip)?.country ||
    ""
  );
}

/** The city for an event, resolved with the same precedence as resolveCountry. */
export function resolveCity(event: TelemetryEvent): string {
  return (
    event.geo?.city?.trim() ||
    firstRaw(event.raw ?? {}, CITY_KEYS) ||
    knownGeoForIp(event.src_ip)?.city ||
    ""
  );
}
