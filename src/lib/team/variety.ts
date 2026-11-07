/**
 * Exercise variety (owner, 2026-11-07: two exercises in a row both had a PsExec run; "no
 * repetition, vary it every time, never the same parameters"). Isomorphic and pure.
 *
 * Two jobs:
 *  1. MEMORY across exercises. /start stores the variants a session drew (benign-positive alert
 *     makers, the decoy, the twist, the inject variants, the attack storylines) in
 *     team_sessions.config.variety, server side and staff-only like the attack plan. The next
 *     session of the same organization reads the last HISTORY_SESSIONS records and ranks every
 *     catalogue item by how recently it ran: never-seen items first, then the ones seen longest
 *     ago. Nothing here is ever sent to a player.
 *  2. FICTIONAL POOLS for per-run parameters: attacker infrastructure and partner endpoints use
 *     only the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24), never a real
 *     public address, and C2 names are assembled from word parts so two sessions rarely share one.
 */

export const HISTORY_SESSIONS = 5;

/** What one session drew, stored in team_sessions.config.variety (staff-only). */
export interface VarietyRecord {
  v: 1;
  /** Benign-positive alert makers (fpAlerts.ts ids). */
  makers: string[];
  /** The decoy kind behind the false-lead inject (decoys.ts id), or null on easy. */
  decoy: string | null;
  /** The twist kind (twists.ts id), or null on easy / no host to work. */
  twist: string | null;
  /** Inject text variants ("ticket:vishing_mfa", "lead:dr_replication:2", ...). */
  injects: string[];
  /** Attack storylines that ran (planned and bonus). */
  stories: string[];
}

/** For each key: how many sessions ago it last ran (1 = the previous session). */
export interface VarietyHistory {
  makers: Record<string, number>;
  decoys: Record<string, number>;
  twists: Record<string, number>;
  injects: Record<string, number>;
  stories: Record<string, number>;
}

export const emptyHistory = (): VarietyHistory => ({ makers: {}, decoys: {}, twists: {}, injects: {}, stories: {} });

const ID = /^[a-z0-9][a-z0-9_:.-]{0,119}$/i;
const ids = (v: unknown, max = 24): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && ID.test(x)).slice(0, max) : [];
const oneId = (v: unknown): string | null => (typeof v === "string" && ID.test(v) ? v : null);

/** A stored record, re-validated (never trusted as stored). */
export function sanitizeVarietyRecord(x: unknown): VarietyRecord | null {
  if (!x || typeof x !== "object") return null;
  const r = x as Record<string, unknown>;
  return { v: 1, makers: ids(r.makers), decoy: oneId(r.decoy), twist: oneId(r.twist), injects: ids(r.injects), stories: ids(r.stories, 8) };
}

/** The variety record of a session's config, or null. */
export function varietyFromConfig(config: unknown): VarietyRecord | null {
  return sanitizeVarietyRecord((config as { variety?: unknown } | null)?.variety);
}

/**
 * History from the org's previous sessions' configs, NEWEST FIRST (index 0 = the session just
 * before this one). Only the first HISTORY_SESSIONS with a record count.
 */
export function historyFromConfigs(configs: unknown[]): VarietyHistory {
  const h = emptyHistory();
  const recs = configs.map(varietyFromConfig).filter((r): r is VarietyRecord => !!r).slice(0, HISTORY_SESSIONS);
  recs.forEach((r, i) => {
    const ago = i + 1;
    const mark = (m: Record<string, number>, k: string | null) => { if (k && !(k in m)) m[k] = ago; };
    r.makers.forEach(k => mark(h.makers, k));
    mark(h.decoys, r.decoy);
    mark(h.twists, r.twist);
    r.injects.forEach(k => mark(h.injects, k));
    r.stories.forEach(k => mark(h.stories, k));
  });
  return h;
}

// ── Seeded randomness ────────────────────────────────────────────────────────────
export function hashSeed(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
export function mulberry32(a: number): () => number {
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
/** A stream of its own for one label of one session. */
export const streamOf = (seed: string, label: string) => mulberry32(hashSeed(`${seed}:${label}`));
export const pickOf = <T,>(arr: readonly T[], rnd: () => number): T => arr[Math.floor(rnd() * arr.length) % arr.length];
export const intIn = (lo: number, hi: number, rnd: () => number) => lo + Math.floor(rnd() * (hi - lo + 1));
export function shuffled<T>(arr: readonly T[], rnd: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

/**
 * Items in the order a session should try them: never seen in the history first (seeded
 * shuffle), then those seen longest ago, the previous session's last. The catalogue still
 * allows a repeat when nothing fresher fits.
 */
export function rankByHistory<T>(items: readonly T[], key: (t: T) => string, seen: Record<string, number>, rnd: () => number): T[] {
  const tagged = shuffled(items, rnd).map((t, i) => ({ t, i, ago: seen[key(t)] ?? Infinity }));
  return tagged.sort((a, b) => (b.ago - a.ago) || (a.i - b.i)).map(x => x.t);
}

// ── Fictional pools ──────────────────────────────────────────────────────────────
/** RFC 5737 documentation networks: never a real public address. 203.0.113/24 is left out: the geo table maps it to one country. */
const DOC_NETS = ["192.0.2", "198.51.100"] as const;
export function docIp(rnd: () => number, used: Set<string>): string {
  for (let k = 0; k < 400; k++) {
    const ip = `${pickOf(DOC_NETS, rnd)}.${intIn(10, 250, rnd)}`;
    if (!used.has(ip)) { used.add(ip); return ip; }
  }
  const ip = `${DOC_NETS[0]}.${intIn(10, 250, rnd)}`;
  used.add(ip);
  return ip;
}
export const isDocIp = (ip: string) => DOC_NETS.some(n => ip.startsWith(`${n}.`));

const C2_A = ["cdn", "edge", "sync", "telemetry", "update", "static", "assets", "api", "metrics", "content", "media", "cache", "status", "push", "data"];
const C2_B = ["cloud", "delivery", "relay", "node", "gateway", "stream", "hub", "service", "mirror", "portal", "link", "bridge", "track", "beacon", "pulse"];
const C2_C = ["net", "io", "com", "cloud", "app", "live", "site", "online"];
/** A plausible-looking, made-up command-and-control domain. */
export function fakeC2Domain(rnd: () => number, used: Set<string>): string {
  for (let k = 0; k < 50; k++) {
    const a = pickOf(C2_A, rnd), b = pickOf(C2_B.filter(x => x !== a), rnd);
    const d = rnd() < 0.5 ? `${a}-${b}-${intIn(2, 98, rnd)}.${pickOf(C2_C, rnd)}` : `${a}${b}${pickOf(["-svc", "-hq", "-io", "-cdn", ""], rnd)}.${pickOf(C2_C, rnd)}`;
    if (!used.has(d)) { used.add(d); return d; }
  }
  return `${pickOf(C2_A, rnd)}-${intIn(100, 999, rnd)}.net`;
}
