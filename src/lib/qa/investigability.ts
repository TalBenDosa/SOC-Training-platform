/**
 * INVESTIGABILITY — can an analyst detect and work a storyline end to end from its logs?
 * (Tal, 2026-10-02: recognised incidents only, no crypto, every claim backed by a record.)
 *
 * Per storyline, as a session renders it (instantiated on the template organization, labelled
 * for its products, native records):
 *   crypto      — no cryptocurrency incident content anywhere in the story
 *   first-alert — at least one alert / detection row a SOC would really get
 *   claims      — every count the description states ("94 files", "78 failures") is in the record
 *   cmd-domain  — a host a command line fetches from is one the story's network logs show
 *   reuse       — an attacker's public IP is not the attacker in other storylines too
 *
 * Shared by the gate test and by anyone fixing a story: storyProblems(id) lists one story's.
 */
import { ATTACK_STORIES, instantiateStory, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { applyStack, nativeView } from "@/lib/logs/native";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMPANY = "nexacorp";
const POOL = normalizeHostIps(BENIGN_EVENTS);
const EDR = COMPANY_PROFILES.find(c => c.id === COMPANY)?.architecture.edr;

export const CRYPTO_RE = /\b(xmrig|monero|xmr|cryptojack\w*|crypto ?min\w*|coin ?miner\w*|mining pool|stratum\+?\w*|nicehash|minergate|bitcoin|ethereum|crypto(currency)? wallet|wallet address|seed phrase|cryptotracker\w*)\b/i;
const ALERT_TYPES = /alert|detection|quarantine|finding|_blocked|ueba_anomaly|risk_score_change|ids_signature|ids_blocked|waf_block|threat_intel_match|dlp_alert|av_/i;
const COUNT_RE = /\b(\d{1,3}(?:,\d{3})+|\d{2,})\s+(files?|records?|rows?|objects?|items?|messages?|emails?|failures?|failed|attempts?|requests?|queries|hosts?|accounts?|users?|folders?|documents?|downloads?|uploads?|connections?|sessions?|events?|lockouts?|pushes|prompts?)\b/gi;
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)/;
/** Services every story may legitimately show (public resolvers, Microsoft / Google / AWS front doors). */
const SHARED_SERVICES = /^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|9\.9\.9\.9|13\.107\.|20\.190\.|40\.126\.|52\.(9[6-9]|1[01]\d)\.|142\.250\.|172\.217\.)/;

export interface StoryRender { story: AttackStory; events: TelemetryEvent[]; records: unknown[] }

let cache: StoryRender[] | null = null;
export function renderedStories(): StoryRender[] {
  if (cache) return cache;
  cache = ATTACK_STORIES.map(story => {
    const events = (instantiateStory(story, POOL, EDR, COMPANY).events ?? []).map(e => applyStack(e, COMPANY, {}));
    const records = events.map(e => { try { const v = nativeView(e, COMPANY, {}); return v ? { record: v.log.record, rawLine: v.log.rawLine } : e.raw ?? null; } catch { return e.raw ?? null; } });
    return { story, events, records };
  });
  return cache;
}

const isAttackRow = (e: TelemetryEvent) => !e.is_baseline && !["benign", "fp", "false_positive", "informational"].includes(String(e.expected_verdict ?? ""));
const textOf = (e: TelemetryEvent) => [e.description, e.fp_explanation, e.it_verify_message, JSON.stringify(e.raw ?? {}), JSON.stringify(e.process ?? {}), JSON.stringify(e.file ?? {}), JSON.stringify(e.network ?? {})].join(" ");
const hostsIn = (s: string) => [...s.matchAll(/\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)].map(m => m[1].toLowerCase());

/** base64 `-enc` / `-EncodedCommand` payloads decoded (UTF-16LE), so their URLs count as commands. */
function decodedCommands(cmd: string): string {
  const out: string[] = [];
  for (const m of cmd.matchAll(/-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})/gi)) {
    try { out.push(Buffer.from(m[1], "base64").toString("utf16le")); } catch { /* not base64 */ }
  }
  return out.join(" ");
}

/** Attacker public IPs per story (src/dst on attack rows, internal and shared services excluded). */
function attackerIps(r: StoryRender): Set<string> {
  const ips = new Set<string>();
  for (const e of r.events) if (isAttackRow(e)) for (const ip of [e.src_ip, e.dst_ip]) if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !PRIVATE.test(ip) && !SHARED_SERVICES.test(ip)) ips.add(ip);
  return ips;
}

let ipOwners: Map<string, Set<string>> | null = null;
function ipStories(): Map<string, Set<string>> {
  if (ipOwners) return ipOwners;
  ipOwners = new Map();
  for (const r of renderedStories()) for (const ip of attackerIps(r)) (ipOwners.get(ip) ?? ipOwners.set(ip, new Set()).get(ip)!).add(r.story.id);
  return ipOwners;
}

export function storyProblems(r: StoryRender): string[] {
  const p: string[] = [];
  const id = r.story.id;
  // crypto
  for (const e of r.events) { const m = (r.story.title + " " + textOf(e)).match(CRYPTO_RE); if (m) { p.push(`crypto: ${e.id} "${m[0]}"`); break; } }
  // first alert
  if (!r.events.some(e => e.is_detection || ALERT_TYPES.test(e.event_type ?? "") || e.source === "siem" || e.source === "ueba" || e.source === "dlp" || e.source === "av"))
    p.push("first-alert: no alert / detection row — nothing a SOC would be paged on");
  // claims in the description are in the record
  r.events.forEach((e, i) => {
    const rec = JSON.stringify(r.records[i] ?? {}) + JSON.stringify(e.raw ?? {});
    for (const m of (e.description ?? "").matchAll(COUNT_RE)) {
      const n = m[1].replace(/,/g, "");
      if (!rec.includes(n) && !rec.includes(m[1])) p.push(`claims: ${e.id} description says "${m[0]}" but no record field carries ${m[1]}`);
    }
  });
  // command-line fetch hosts appear in the story's network logs
  const netText = r.events.filter(e => ["dns", "firewall", "proxy", "ids", "waf"].includes(e.source) || /net_connection|http_request|dns_query/.test(e.event_type ?? "")).map(e => JSON.stringify([e.description, e.raw, e.network, e.dns])).join(" ").toLowerCase();
  if (netText) for (const e of r.events) {
    const cmd = e.process?.cmdline ?? "";
    for (const h of new Set(hostsIn(cmd + " " + decodedCommands(cmd)))) if (!netText.includes(h)) p.push(`cmd-domain: ${e.id} command fetches from ${h} — no DNS / network row shows it`);
  }
  // attacker infrastructure reused across storylines
  for (const ip of attackerIps(r)) { const owners = ipStories().get(ip); if (owners && owners.size > 2) p.push(`reuse: attacker IP ${ip} also attacks in ${[...owners].filter(x => x !== id).slice(0, 4).join(", ")}`); }
  return p;
}

export function allStoryProblems(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const r of renderedStories()) { const p = storyProblems(r); if (p.length) out[r.story.id] = p; }
  return out;
}
