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

// ── Attacker domains ──────────────────────────────────────────────────────────

/**
 * Raw keys whose value names a host or URL. A domain is drawn only from these and from the structured fields
 * (dns.query, network.domain, network.url), never from free text or a field name, so a vendor key that
 * looks like a domain (esx.audit.net.firewall) is never one.
 */
const HOST_KEY = /(domain|query|queryname|host|hostname|url|uri|sender|from|server_name|sni|fqdn|remoteurl|referer|referrer|fileorigin|requesturl)$/i;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?\.)+[a-z]{2,12}$/i;
/** TLDs attacker infrastructure favours; a mainstream TLD counts only with a hyphen or a digit in the name. */
const SUSPECT_TLD = new Set(["xyz", "top", "link", "info", "ru", "cc", "site", "online", "biz", "click", "shop", "live", "su", "icu", "buzz", "lol", "example"]);
const COMPANY_TOKEN = /nexacorp|rocketstack|medcore|globallogis|quantumbank/i;
const SUFFIXES = ["24", "eu", "now", "hub", "svc", "pro", "go", "app", "one", "online"];
const PREFIXES = ["my", "get", "go", "secure", "e"];
/** Real services a story names that look like attacker names (a digit, a hyphen): never varied. */
const REAL_DOMAINS = new Set(["office365.com", "microsoft365.com", "7-zip.org", "1password.com", "t-mobile.com", "mercedes-benz.com", "coca-cola.com", "e-boks.dk"]);
/** A brand an attacker name imitates (a lookalike): its words stay first, only a trailing token is added. */
const BRAND = /(docu|sign|putty|office|micro|ms-|msft|outlook|onedrive|sharepoint|teams|azure|windows|win|google|gmail|apple|icloud|adobe|acrobat|zoom|slack|dropbox|paypal|okta|github|chrome|edge|firefox|netfix|netflix|amazon|aws|dhl|fedex|ups|usps|linkedin|wetransfer|anydesk|teamviewer|support|rijksoverheid|overheid|gov|irs|hmrc|bank)/i;

const registered = (host: string) => host.toLowerCase().split(".").slice(-2).join(".");
function hostOf(v: string): string | undefined {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#\s]+)/i.exec(v.trim());
  const h = (m ? m[1] : v.trim().replace(/^.*@/, "")).toLowerCase();
  return DOMAIN_RE.test(h) ? h : undefined;
}
function isAttackerStyle(reg: string): boolean {
  const [name, tld] = reg.split(".");
  if (!name || !tld || COMPANY_TOKEN.test(reg) || REAL_DOMAINS.has(reg)) return false;
  // A mainstream TLD needs a hyphen: a name with only a digit (office365.com) is far more often a real service.
  return SUSPECT_TLD.has(tld) || name.includes("-");
}

/** Domains the attack rows name in a host field. */
function attackDomains(events: TelemetryEvent[]): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => { if (typeof v === "string") { const h = hostOf(v); if (h) out.add(registered(h)); } };
  const walk = (o: unknown) => {
    if (!o || typeof o !== "object") return;
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
      if (typeof v === "string" && HOST_KEY.test(k.split(/[.[\]]/).filter(Boolean).pop() ?? k)) add(v);
      else if (v && typeof v === "object") walk(v);
    }
  };
  for (const e of events) if (isAttackRow(e)) { add(e.dns?.query); add(e.network?.domain); add(e.network?.url); walk(e.raw); }
  return out;
}

/**
 * A new name that keeps what the old one says (the lure's words, the brand it imitates, its TLD): the words
 * are reordered, or a short token is added, or the digits change. `shiptrack-express.info` becomes
 * `express-shiptrack.info` or `shiptrack-express24.info`; `puttysoftware-download.com` stays a PuTTY lookalike.
 */
function mutate(reg: string, rnd: () => number): string {
  const [name, tld] = reg.split(".");
  const parts = name.split("-");
  const r = rnd();
  let next: string;
  // A lookalike keeps the brand it imitates in front: only the digits or a trailing token change.
  if (BRAND.test(name)) {
    next = /\d/.test(name) && r < 0.5 ? name.replace(/\d+/g, d => String(Math.floor(rnd() * 10 ** d.length)).padStart(d.length, "1"))
      : `${name}-${SUFFIXES[Math.floor(rnd() * SUFFIXES.length)]}`;
    return `${next}.${tld}`;
  }
  if (/\d/.test(name) && r < 0.35) next = name.replace(/\d+/g, d => String(Math.floor(rnd() * 10 ** d.length)).padStart(d.length, "1"));
  else if (parts.length >= 2 && r < 0.6) next = [...parts.slice(1), parts[0]].join("-");
  else if (r < 0.8) next = `${name}${rnd() < 0.5 ? "-" : ""}${SUFFIXES[Math.floor(rnd() * SUFFIXES.length)]}`;
  else next = `${PREFIXES[Math.floor(rnd() * PREFIXES.length)]}-${name}`;
  return `${next}.${tld}`;
}

/**
 * Fresh attacker domains for this render, swapped in the whole story. Never: a domain the company's noise or a
 * benign row of the story names, a company's own name, or a mainstream-looking domain (no hyphen, no digit,
 * mainstream TLD: a real service such as proton.me or mega.co).
 */
export function varyAttackerDomains<S extends { id: string; events: TelemetryEvent[] }>(
  story: S, companyPool: TelemetryEvent[], rnd: () => number, opts: { used?: Set<string> } = {},
): { story: S; domains: Record<string, string> } {
  const cands = [...attackDomains(story.events)].filter(isAttackerStyle).sort();
  if (!cands.length) return { story, domains: {} };
  const benignText = (companyPool.concat(story.events.filter(e => !isAttackRow(e)))).map(e => JSON.stringify(e).toLowerCase()).join("\n");
  // A domain inside an encoded command (PowerShell -enc, a base64 blob) cannot follow a text swap: renaming
  // it would leave the decoded command fetching from a host the network logs no longer name.
  const encoded = encodedText(story.events);
  const map = new Map<string, string>();
  for (const reg of cands) {
    if (benignText.includes(reg) || encoded.includes(reg)) continue;
    let pick: string | undefined;
    for (let t = 0; t < 20 && !pick; t++) {
      const c = mutate(reg, rnd);
      if (c !== reg && !opts.used?.has(c) && ![...map.values()].includes(c) && !COMPANY_TOKEN.test(c) && !benignText.includes(c)) pick = c;
    }
    if (!pick) continue;
    opts.used?.add(pick);
    map.set(reg, pick);
  }
  if (!map.size) return { story, domains: {} };
  const re = new RegExp(`(?<![a-z0-9-])(?:${[...map.keys()].map(esc).join("|")})(?![a-z0-9-])`, "gi");
  const swapDomains = <T,>(v: T): T => {
    if (typeof v === "string") return v.replace(re, m => map.get(m.toLowerCase()) ?? m) as T;
    if (Array.isArray(v)) return v.map(swapDomains) as T;
    if (v && typeof v === "object") { const o: Record<string, unknown> = {}; for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = swapDomains(x); return o as T; }
    return v;
  };
  const out = swapDomains({ ...story, id: "\u0000" } as S);
  return { story: { ...out, id: story.id }, domains: Object.fromEntries(map) };
}

/** Every base64 run of the story decoded (UTF-16LE as PowerShell -enc carries it, and plain ASCII), lower case. */
function encodedText(events: TelemetryEvent[]): string {
  const out: string[] = [];
  const blob = JSON.stringify(events);
  for (const m of blob.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)) {
    let bin: string;
    // atob, not Buffer: the browser's live feed instantiates stories too.
    try { bin = atob(m[0].length % 4 ? m[0] + "=".repeat(4 - (m[0].length % 4)) : m[0]); } catch { continue; }
    let wide = "";
    for (let i = 0; i + 1 < bin.length; i += 2) wide += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
    for (const txt of [wide, bin]) if (/^[\x20-\x7e\r\n\t]{8,}$/.test(txt)) out.push(txt.toLowerCase());
  }
  return out.join("\n");
}
