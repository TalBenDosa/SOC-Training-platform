import "server-only";
/**
 * Server-side deterministic timeline for a team session (Phase 0.4). Builds the
 * SAME real telemetry the single-player dashboard uses — the company's benign
 * event pool interleaved with fitting attack stories — into a flat, time-ordered
 * list the start route writes to session_injects. pg_cron then promotes each
 * entry into session_events on time, and Broadcast-from-DB fans it to the team.
 *
 * Generated ONCE at /start and stored in session_injects, so every member replays
 * the identical incident and the AAR reconstructs it exactly from the log. The
 * whole build is a pure function of its inputs: interleaving, cadence, MSEL telemetry
 * AND the attack-story choice (and each story's victim) are drawn from mulberry32
 * streams of the seed, so a seed always replays the same incidents while different
 * sessions still vary. A storyline staff chose (scenario_id) always leads as the
 * primary incident.
 *
 * Answer key (contract 1, 2026-09-27 live-playtest fix round): every feed entry's
 * `answer` carries an explicit expected_verdict (tp | escalate | benign | fp —
 * never missing), an incident_id for every event that belongs to an incident
 * (story steps AND the legitimate control steps inside a story; standalone pool
 * attacks get their own), and supports_inject on logs that back a scripted inject.
 */
import { approvalRefOf, itVerifyApplies } from "@/lib/sim/itVerify";
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { instantiateStory, storiesForCompany, storiesForTier, rehomeEvents, pickInFamilies, familyOf, familyOfId, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { DEFAULT_ENV, envAllowsStory, envHasPlatforms, platformsOfEvent, type TeamEnv } from "./environment";
import { legacyLoad, type TeamLoad } from "./load";
import { COMPANY_PROFILES, COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { mapTimeString, storyTimeMap, withMappedTime, withRebasedTime, type TimeMap } from "@/lib/sim/rebaseTime";
import { normalizeAccountSids, normalizeHostIps } from "@/lib/sim/hostIdentity";
import { applyTenant, type Tenant } from "./tenant";
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { describeEvent } from "@/lib/sim/describeEvent";
import { fpAlerts, type FpOut } from "./fpAlerts";
import { itsmNoise, ticketRecord } from "./itsmNoise";
import { buildDecoy, buildTwist, fwFlavour, pickInjectTexts, type InjectText } from "./msel";
import { emptyHistory, streamOf, type VarietyHistory, type VarietyRecord } from "./variety";
import { webNoise } from "./webNoise";
import { NoiseDeck } from "@/app/(app)/dashboard/noiseDeck";
import { applyStack, fitsStack, stackFor, storyFitsOrg, storyFitsStack, storyHonoursLocks, withCanonicalPids } from "@/lib/logs/native";
import { categoryOf, PRODUCT_LABEL, type Stack } from "@/lib/logs/native/stack";
import { storyThemes, type StoryCategory } from "./storyCategory";

// channel "feed" → promoted as a feed.event (a log); "inject" → a staff.inject
// (an MSEL curveball: management pressure, a help-desk ticket, an announcement).
// `body` is PUBLIC (promoted verbatim to every player); `answer` is the ground
// truth, stored in the staff-only session_injects.expected_action column.
// "bonus" → a held attack story: seeded with due_offset_ms = BONUS_HOLD_MS + its relative offset,
// never promoted until the DB releases it (team_release_bonus) once the team has caught every
// planned attack; released rows become ordinary "feed" rows.
export interface TimelineEntry { due_offset_ms: number; channel: "feed" | "inject" | "bonus"; body: Record<string, unknown>; answer?: Record<string, unknown> }
/** The offset a held bonus row is parked at (far beyond any shift); its real offset is added on release. */
export const BONUS_HOLD_MS = 1_000_000_000_000_000;

/** Share of the visible feed that is ordinary traffic before the first attack row. */
const WARMUP_MIN = 0.10;
/**
 * Logs behind the MSEL injects, added after placement: the twist's two to four rows (a dropped file,
 * its DNS lookup, the firewall row and the EDR row) + the decoy's ticket, earlier batch and two uploads.
 * The most it can be, so the warm-up holds whichever twist is drawn.
 */
const MSEL_SUPPORT_ROWS = 8;
/** Ordinary telemetry (benign pool rows) per attack row in the feed: the floor no load trims below. */
export const ORDINARY_PER_ATTACK_ROW = 2;
/** Share of the feed ServiceNow records may take (approvals that prove a decoy first, unrelated tickets after). */
export const ITSM_SHARE = 0.08;

export type TeamVerdict = "tp" | "escalate" | "benign" | "fp";
/** Where a feed log came from — lets the report / instructor tell story steps from noise. */
export type FeedOrigin = "story" | "pool_attack" | "noise" | "itsm" | "inject_support";

function mostCommonOf(vals: (string | undefined)[]): string | undefined {
  const m = new Map<string, number>();
  for (const v of vals) if (v) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

function hashSeed(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function mulberry32(a: number) {
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function sampleN<T>(arr: T[], n: number, rnd: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a.slice(0, Math.min(n, a.length));
}
/** Rows in authored time order, stable (left as they are when a ts does not parse). */
function byAuthoredTime<T extends { ts?: string }>(evs: T[]): T[] {
  const t = evs.map(e => Date.parse(e.ts ?? ""));
  if (t.some(x => !Number.isFinite(x))) return evs;
  return evs.map((e, i) => ({ e, i })).sort((a, b) => t[a.i] - t[b.i] || a.i - b.i).map(x => x.e);
}

// ── Noise hygiene ────────────────────────────────────────────────────────────
const PERSONAL_MAIL = /@(gmail|googlemail|yahoo|outlook|hotmail|live|proton|protonmail|icloud|gmx)\.(com|me|de|net|ch)\b/i;
const SENSITIVE = /\b(ssn|social security|salary|payroll|passport|credit card|card number|patient|confidential|password|credentials)\b/i;
const ODD_PORTS = new Set([4444, 1337, 31337, 5555, 6666, 6667, 9001, 9050]);
const TOOL_NAMES = /\b(mimikatz|nmap|masscan|rclone|ngrok|procdump|psexec|cobalt ?strike|bloodhound|sharphound|impacket|lazagne|anydesk|teamviewer)\b/i;
/** A row labelled benign that reads as an attack: sensitive data to a personal mailbox, a classic
 *  shell port, an attacker tool by name, or this session's attack infrastructure. */
export function looksLikeAttack(e: TelemetryEvent, attackIps: Set<string> = new Set()): boolean {
  const text = `${e.description ?? ""} ${JSON.stringify(e.raw ?? {})} ${JSON.stringify(e.network ?? {})} ${JSON.stringify(e.process ?? {})}`;
  if (PERSONAL_MAIL.test(text) && SENSITIVE.test(text)) return true;
  const ports = [Number((e as { dst_port?: number }).dst_port), ...[...text.matchAll(/(?:port"?\s*[:=]\s*"?|:)(\d{4,5})\b/gi)].map(m => Number(m[1]))];
  if (ports.some(p => ODD_PORTS.has(p))) return true;
  if (TOOL_NAMES.test(text)) return true;
  return [e.src_ip, e.dst_ip].some(ip => !!ip && attackIps.has(ip));
}
const BLOCKED = /_blocked|waf_block|ids_blocked|email_quarantined|email_blocked|av_quarantine/;
function isBlockedAttempt(e: TelemetryEvent): boolean {
  const action = String(e.raw?.["action"] ?? e.raw?.["data.action"] ?? e.raw?.["event.action"] ?? e.raw?.["pan.action"] ?? "");
  return BLOCKED.test(e.event_type ?? "") || /^(block|blocked|deny|denied|drop|reset-both)$/i.test(action);
}

// ── Answer-key classification ────────────────────────────────────────────────

/**
 * Verdict for an event that belongs to an attack story. The story is the incident,
 * but not every step of it is malicious: the scenario packs ship CONTROL steps (an
 * approved onboarding ticket, the account it legitimately produced, the ordinary
 * site visit before a drive-by) and FP decoys. Those are benign/fp — defaulting
 * every story event to tp punished the analysts who read them correctly.
 */
const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

/**
 * Unrelated tickets a session always shows, so "a ticket" never marks an attack: two, unless the feed
 * already carries two or more tickets that explain no attack (pool approvals, a decoy's ticket), which
 * do that job, and more would push tickets past ITSM_SHARE of a small team's feed (R8).
 */
const unrelatedTicketMin = (benignTickets: number) => (benignTickets >= 2 ? 0 : 2 - benignTickets);
/** Sources whose records are an endpoint's own telemetry. */
const ENDPOINT_SOURCES = new Set<string>(["edr", "sysmon", "av", "windows_security", "linux_audit"]);
/** A ServiceNow record (R8 counts these as the feed's tickets). */
const isTicketRow = (e: TelemetryEvent) => (e.source as string) === "servicenow" || /servicenow/i.test(e.vendor ?? "");

/** Failed sign-in rows a burst is made of (R7 counts the same kinds). */
const AUTH_FAIL = new Set(["auth_failure", "ssh_failed", "vpn_failed", "db_failed", "mfa_denied"]);
/** Story rows authored at most this far apart belong to one run. */
const BURST_GAP_MS = 45_000;
/** A run is a burst when it holds this many failed sign-ins. */
const BURST_MIN_FAILS = 5;

/**
 * R7: a burst stays a burst (as storyFeed.ts does for the solo feed). A band spreads a story's rows
 * over a third of the shift, which stretched a spray of 18 failures in 150 seconds over eight minutes.
 * A run of a story's rows authored at most BURST_GAP_MS apart that holds BURST_MIN_FAILS failed
 * sign-ins keeps its authored spacing from its first row: every row of the run (a firewall row inside
 * the spray too, so the story's time map stays monotone) is shown at the run's start plus its authored
 * offset, never at or past the story's next row. Positions do not change, so nothing else in the
 * timeline moves (the feed is sorted by time afterwards).
 */
function keepAuthBursts(timed: { p: { ev: TelemetryEvent; origin: string; incident?: string; held?: boolean }; at: number }[]): void {
  const byIncident = new Map<string, { k: number; ms: number }[]>();
  timed.forEach((x, k) => {
    if (x.p.origin !== "story" || !x.p.incident) return;
    const ms = Date.parse(x.p.ev.ts);
    if (!Number.isFinite(ms)) return;
    const key = `${x.p.held ? "bonus" : "feed"}|${x.p.incident}`;
    (byIncident.get(key) ?? byIncident.set(key, []).get(key)!).push({ k, ms });
  });
  for (const rows of byIncident.values()) {
    const s = [...rows].sort((a, b) => a.ms - b.ms || a.k - b.k);
    for (let i = 0; i < s.length;) {
      let j = i;
      while (j + 1 < s.length && s[j + 1].ms - s[j].ms <= BURST_GAP_MS) j++;
      const run = s.slice(i, j + 1);
      if (run.length > 1 && run.filter(r => AUTH_FAIL.has(timed[r.k].p.ev.event_type)).length >= BURST_MIN_FAILS) {
        const head = run[0];
        const start = timed[head.k].at;
        const span = run[run.length - 1].ms - head.ms;
        const limit = j + 1 < s.length ? timed[s[j + 1].k].at - 1_000 : Infinity;
        const f = span > 0 ? Math.max(0, Math.min(1, (limit - start) / span)) : 1;
        for (const r of run) timed[r.k].at = start + Math.round((r.ms - head.ms) * f);
      }
      i = j + 1;
    }
  }
}
export function classifyStoryEvent(ev: TelemetryEvent): TeamVerdict {
  if (ev.is_baseline) return "benign";
  // One rule for context rows in every story (expert review P0-6): a user's ordinary internal
  // logon / logoff — no technique, no alert, no explicit verdict — is context, not attack evidence.
  if (!ev.mitre_technique && !ev.is_detection && !ev.expected_verdict && ev.event_type === "auth_success"
    && (!ev.src_ip || PRIVATE_IP.test(ev.src_ip)) && (ev.source === "ad" || ev.source === "windows_security")) return "benign";
  if (ev.expected_verdict === "fp" || ev.fp_explanation || ev.it_verify_result === "confirmed") return "fp";
  if (ev.expected_verdict === "escalate") return "escalate";
  if (ev.expected_verdict === "informational") return "benign";
  return "tp";
}

/**
 * Verdict for an event drawn from a company/benign pool. The pools hide real
 * attacks among the noise (a forwarding rule to an external mailbox, PII to USB, a
 * bulk blob download…); those carry tp/escalate in the data or an "unverified"
 * IT check. An event IT confirmed as authorised is an FP decoy.
 */
export function classifyPoolEvent(ev: TelemetryEvent): TeamVerdict {
  if (ev.expected_verdict === "tp" || ev.expected_verdict === "escalate") return ev.expected_verdict;
  if (ev.expected_verdict === "fp" || ev.fp_explanation || ev.it_verify_result === "confirmed") return "fp";
  if (ev.it_verify_result === "unverified") return "escalate";
  return "benign";
}
const isMalicious = (v: TeamVerdict) => v === "tp" || v === "escalate";

/**
 * Pool attacks that belong together form ONE incident (a spray and its lockouts;
 * one user's MFA-fatigue alerts). Everything else is a standalone incident.
 */
export function poolIncidentKey(ev: TelemetryEvent): string {
  const id = String(ev.id ?? "");
  if (/^mc_(s1_00[4-7]|s1_010|lat_00[1-3]|dns_00[24]|fw_002|o365_002|az_003)$/.test(id)) return "pool:medcore-emr-intrusion";
  if (/^qb_(cs_003|fw_002)$/.test(id)) return "pool:quantumbank-wks012-beacon";
  const bf = id.match(/^(b|mc|gl|qb)_bf_0[1-4]$/);
  if (bf) return `pool:${bf[1]}-bruteforce`;
  if (id === "b_ueba_new_04" || id === "b_ueba_new_06") return "pool:b-lharris-mfa-fatigue";
  return `solo:${id}`;
}
/** A whole kill chain hidden in one pool — too big to drop in beside two live stories. */
const EXCLUDED_POOL_INCIDENTS = new Set(["pool:medcore-emr-intrusion"]);

// ── Description hygiene ──────────────────────────────────────────────────────

const CLOCK = String.raw`\d{1,2}:\d{2}(?::\d{2})?(?:\s?(?:AM|PM|am|pm|UTC|local))?`;
const NUM_WORD = String.raw`(?:\d+|an?|[A-Za-z]+(?:-[a-z]+)?)`;
/**
 * Authored story prose carries its own clock ("At 22:47 …", "Three seconds later …")
 * — but a team shift re-times every log onto the shift clock, so those phrases
 * contradicted the timestamps (playtest P1: "two clocks in every story") and did the
 * correlation for the analyst. Keep the facts, drop the narrated time.
 */
export function scrubClockPhrases(desc: string): string {
  let d = desc;
  const lead = [
    new RegExp(String.raw`^At ${CLOCK},?\s+`),
    new RegExp(String.raw`^${NUM_WORD} (?:seconds?|minutes?|hours?) (?:later,?|after [^,]+,|into [^,]+,)\s*`, "i"),
  ];
  let cutLead = false;
  for (const re of lead) { const n = d.replace(re, ""); if (n !== d) { d = n; cutLead = true; } }
  for (const re of [new RegExp(String.raw`^(?:Between|From) ${CLOCK}(?: (?:and|to|until) ${CLOCK})?,?\s+`)]) {
    const n = d.replace(re, ""); if (n !== d) { d = n; cutLead = true; }
  }
  d = d.replace(new RegExp(String.raw`\s+(?:between|from) ${CLOCK} (?:and|to|until) ${CLOCK}`, "g"), "");
  d = d.replace(new RegExp(String.raw`\bthe ${CLOCK} and ${CLOCK}\b`, "g"), "the two");
  d = d.replace(new RegExp(String.raw`\s+(?:until|by|since|after|before) ${CLOCK}(?=[\s,.;:)—]|$)`, "g"), "");
  d = d.replace(new RegExp(String.raw`,\s*${NUM_WORD} (?:seconds?|minutes?|hours?) (?:after|later|before|old)[^,.—;]*`, "gi"), "");
  d = d.replace(new RegExp(String.raw`\s+at ${CLOCK}(?=[\s,.;:)—]|$)`, "g"), "");
  d = d.replace(/\s{2,}/g, " ").replace(/\s+([,.;])/g, "$1").trim();
  // Re-capitalise only a sentence we cut the front off — "powershell.exe …" stays as written.
  return cutLead && /^[a-z]+ /.test(d) ? d[0].toUpperCase() + d.slice(1) : d;
}

// ── Supporting telemetry for scripted injects / ITSM context ─────────────────

// Firewall / EDR record shapes, decoys, twists and inject texts live in msel.ts (rotated per session).

const TICKET_RE = /\b(CHG-?\d[\d-]*|INC-?\d+|RITM\d+|ONB-\d+|NXC-\d+|NX-\d+|REQ-?\d+)\b/;
/**
 * The IT-verification text (it_verify_*) is a platform answer channel, not a log
 * field, so it never reaches the team (playtest P1: "escalate immediately" in a log).
 * When IT CONFIRMED an admin change, the real-world evidence is the approved ticket
 * — so the team gets that ticket as an ordinary ServiceNow record in the feed, and
 * has to correlate it with the change itself.
 */
export { approvalRefOf };

/** The approval a decoy rests on, as one plain line: the explanation's first clause. */
function approvalSummaryOf(ev: TelemetryEvent): string {
  const first = (ev.fp_explanation ?? "").split(/(?<=\.)\s|\s—\s/)[0].trim().replace(/\.$/, "");
  return first.length > 8 ? first.slice(0, 160) : (ev.description ?? "").replace(/\s+—.*$/, "");
}

function itsmRecordFor(ev: TelemetryEvent, companyId: string): TelemetryEvent | null {
  // A benign-positive alert brings its own ticket (or none): fpAlerts.ts / ticketRecord.
  if (String(ev.id ?? "").startsWith("fpa_")) return null;
  // Scenario review 2026-10-01, fix 5: an FP decoy whose explanation rests on an
  // APPROVAL ("approved … ticket RS-4401") was unanswerable — the approval never
  // appeared in the feed, so the analyst who escalated a USB copy / mail forward
  // (the right call without evidence) was marked wrong. The approval now lands as
  // an ordinary ServiceNow request a few logs before the activity it covers.
  if (ev.it_verify_result !== "confirmed" || !ev.it_verify_message) {
    if (classifyPoolEvent(ev) !== "fp") return null;
    const ref = approvalRefOf(ev.fp_explanation);
    if (!ref) return null;
    const summary = approvalSummaryOf(ev);
    // The same ServiceNow shape as every other ticket (itsmNoise.ts ticketRecord). An approved request
    // item is in Work in Progress (approval "Approved"): "Approved" is not a request-item state.
    return ticketRecord({ table: "sc_req_item", number: ref, state: "Work in Progress", short: summary, ...(ev.user_email ? { requestedFor: ev.user_email } : {}) }, companyId, `itsm_${ev.id}`, ev.ts);
  }
  // A ticket format the IT message uses (CHG / INC / RITM …), else any approval
  // reference it or the explanation cites (e.g. an access request AR-QB-0302).
  const number = ev.it_verify_message.match(TICKET_RE)?.[1] ?? approvalRefOf(ev.it_verify_message) ?? approvalRefOf(ev.fp_explanation);
  if (!number) return null;
  const table = /^INC/.test(number) ? "incident" : /^RITM|^REQ|^ONB/.test(number) ? "sc_req_item" : "change_request";
  const summary = (ev.description ?? "").replace(/\s+—.*$/, "");
  const state = table === "incident" ? "Resolved" : table === "sc_req_item" ? "Work in Progress" : "Implement";
  return ticketRecord({ table, number, state, short: summary, ...(ev.user_email ? { requestedFor: ev.user_email } : {}) }, companyId, `itsm_${ev.id}`, ev.ts);
}

// ── The builder ──────────────────────────────────────────────────────────────

interface Placed { ev: TelemetryEvent; origin: FeedOrigin; verdict: TeamVerdict; incident?: string; supports?: string; held?: boolean; autoContained?: boolean; /** The attack's name, for the report (staff-side answer key only). */ attack?: string;
  /** An ITSM row: the change window in minutes, around `ticketFor`'s time (or the row's own when none). */ window?: [number, number]; ticketFor?: Placed }

/**
 * Variety controls for one build (variety.ts): `history` = how recently each catalogue item ran in
 * this organization's previous sessions; `force` = test hooks; `onVariety` receives what the build
 * drew (the start route stores it, staff-only, for the next session).
 */
export interface VarietyOpts {
  history?: VarietyHistory;
  force?: { makers?: string[]; decoy?: string; twist?: string; miss?: boolean; ticket?: string };
  onVariety?: (r: VarietyRecord) => void;
}

/** Build the ordered, time-stamped feed for a session. */
/**
 * Staff-chosen storyline (team_sessions.scenario_id, exercise-report #18): the
 * attack story the instructor picked in the Session Builder, or null when none was
 * picked / the id isn't a story that fits this company + difficulty (then the
 * timeline falls back to the random pick). Only stories storiesForCompany() would
 * offer are accepted, so a hand-crafted id can't smuggle a K8s escape into a
 * hospital or an advanced chain into an easy session.
 */
export function resolveTeamStory(companyId: string, difficulty: "easy" | "medium" | "hard", storyId: string | null | undefined, env: TeamEnv | null = null, stack: Stack = {}): AttackStory | null {
  if (!storyId) return null;
  const own = teamStoryPool(companyId, difficulty, env, stack).find(s => s.id === storyId);
  if (own) return own;
  // The admin chooses the attacks, and a chosen attack always runs (Tal, 2026-11-12). A plan saved before the
  // engines stopped sharing stories may name one that is now single-player only: it still runs, under the same
  // company / tier / environment fit. The storyline list offers Team Training's own stories only, so no new
  // choice reaches here.
  const legacy = env
    ? storiesForTier(difficulty, difficulty === "hard").filter(s => !s.teamOnly && envAllowsStory(env, s))
    : storiesForCompany(companyId, difficulty, true);
  return legacy.find(s => s.id === storyId) ?? null;
}

/**
 * The stories a session can draw. A Live-SOC company: the ones that fit its architecture
 * (storiesForCompany). A named organization: every story of the difficulty's tier that its
 * environment can carry — the platforms the instructor said it runs, and its industry —
 * whichever demo company it was written for (instantiateStory re-homes it). Hard broadens
 * to core when fewer than 8 advanced stories fit, as the dashboard does.
 */
export function teamStoryPool(companyId: string, difficulty: "easy" | "medium" | "hard", env: TeamEnv | null, stack: Stack = {}): AttackStory[] {
  // Team Training's own stories only: the single-player dashboard and Team Training never share one (Tal, 2026-11-12).
  if (!env) return storiesForCompany(companyId, difficulty, "team");
  const inEnv = (broaden: boolean) => storiesForTier(difficulty, broaden).filter(s => s.teamOnly && envAllowsStory(env, s));
  const pool = inEnv(false);
  if (difficulty === "hard" && pool.filter(teamStoryFilter(companyId, stack, env)).length < 8) return inEnv(true);
  return pool;
}

/**
 * Does a named organization run the product this event's source implies? Baseline sources every SOC
 * has are always allowed; specialised tools only when the instructor selected a matching product
 * (stack) or platform (env) — so the feed never shows a tool the org didn't choose.
 */
const BASELINE_SOURCES = new Set(["edr", "av", "firewall", "ids", "vpn", "o365", "exchange", "sharepoint", "ad", "windows_security", "sysmon", "dns", "siem", "email_gateway", "cloud_azure", "soar"]);
function orgRunsSource(e: TelemetryEvent, env: TeamEnv, stack: Stack, companyId: string): boolean {
  const src = String(e.source);
  const vend = (e.vendor ?? "").toLowerCase();
  // Products that come WITH a choice, never on their own: Defender for Identity is part of the
  // Defender suite (EDR = Microsoft Defender for Endpoint); Claude Enterprise audit logs have no
  // selector. (Sentinel needs the Azure platform: platformsOfEvent.)
  if (/defender for identity/.test(vend)) return stackFor(companyId, stack).edr === "mde";
  if (src === "siem" && /anthropic|claude/.test(vend)) return false;
  if (BASELINE_SOURCES.has(src)) return true;
  switch (src) {
    case "proxy": return stack.proxy !== undefined;
    case "gws": return stack.collab === "google_workspace";
    case "okta": case "mfa": return stack.idp === "okta";
    case "iam": return env.platforms.includes("cyberark");
    case "cloudtrail": return env.platforms.includes("aws");
    case "cloud_gcp": return env.platforms.includes("gcp");
    case "k8s_audit": return env.platforms.includes("k8s");
    case "linux_audit": return env.platforms.includes("linux");
    case "vcs": return env.platforms.includes("github");
    case "virtualization": return env.platforms.includes("vmware");
    // Specialised tools with no selector yet (WAF, DAM, UEBA, NAC, DLP): not shown unless the org opted in — keep them out of a named org's noise.
    case "waf": case "db_monitor": case "ueba": case "nac": case "dlp": case "infra_monitor": case "threat_intel": return false;
    default: return true;
  }
}

/** Sources the session relabels to its chosen product (applyStack): their product is the choice, whatever they were written as. */
const RELABELLED_SOURCES = new Set(["okta", "mfa", "gws", "o365", "exchange", "sharepoint", "edr", "av", "firewall", "ids", "vpn", "dns", "email_gateway"]);

/**
 * An attack step a named organization can show: its platform is one the admin chose, and its
 * product is either relabelled to a chosen one (an Okta-written sign-in in an Entra shop) or
 * comes with a choice: Sentinel and its UEBA with Azure, Purview DLP with Microsoft 365,
 * Defender for Identity with Defender for Endpoint. Anything else the admin never selected
 * (a web proxy, Guardium, a WAF, Claude Enterprise) keeps the story out.
 */
function storyEventChosen(e: TelemetryEvent, env: TeamEnv, stack: Stack, companyId: string): boolean {
  if (!envHasPlatforms(env, [e])) return false;
  const src = String(e.source), vend = (e.vendor ?? "").toLowerCase();
  if (/defender for identity/.test(vend)) return stackFor(companyId, stack).edr === "mde";
  if (src === "ueba") return /sentinel/.test(vend) && env.platforms.includes("azure");
  if (src === "dlp") return /purview/.test(vend) && stackFor(companyId, stack).collab === "m365";
  // A WAF comes with its cloud: the session's WAF product (the template default or the admin's choice)
  // needs that cloud in the environment. An organization that runs neither shows no web-attack WAF row.
  if (categoryOf(e) === "waf") { const waf = stackFor(companyId, stack).waf; return waf === "azure_waf" ? env.platforms.includes("azure") : waf === "aws_waf" ? env.platforms.includes("aws") : false; }
  if (RELABELLED_SOURCES.has(src)) return true;
  return orgRunsSource(e, env, stack, companyId);
}

/** Platforms whose ordinary logs a named organization's template lacks: borrowed (re-homed) from the demo company that runs them. */
function platformNoise(companyId: string, env: TeamEnv, own: TelemetryEvent[]): TelemetryEvent[] {
  const ownHas = new Set(own.flatMap(platformsOfEvent));
  const want = new Set(env.platforms.filter(p => !ownHas.has(p)));
  if (want.size === 0) return [];
  const out: TelemetryEvent[] = [];
  for (const other of Object.keys(COMPANY_EVENTS).sort()) {
    if (other === companyId) continue;
    const pool = COMPANY_EVENTS[other] ?? [];
    const borrowed = pool.filter(e => {
      const ps = platformsOfEvent(e);
      return ps.length > 0 && ps.every(p => want.has(p)) && classifyPoolEvent(e) === "benign" && !e.it_verify_result && !e.fp_explanation && !e.mitre_technique;
    });
    if (borrowed.length) out.push(...rehomeEvents(borrowed, other, companyId, own));
  }
  return out;
}

/** The company pool a story is instantiated against for this stack, and the EDR it is relabelled to. */
function storyBase(companyId: string, stack: Stack, env: TeamEnv | null = null) {
  const ownPool0 = COMPANY_EVENTS[companyId]?.length ? COMPANY_EVENTS[companyId] : undefined;
  let ownPool = ownPool0 ? ownPool0.filter(e => fitsStack(e, companyId, stack)) : ownPool0;
  let basePool = ownPool ?? BENIGN_EVENTS.filter(e => fitsStack(e, companyId, stack));
  // A named organization's feed carries the platforms it runs — and only those. It also only shows
  // the specialised security tools the instructor opted into: a WAF / DAM / UEBA / NAC / SOAR / proxy
  // log for a product the org never selected surprised analysts in the diagnostic. Baseline sources
  // (endpoint, firewall, VPN, identity, mail, DNS, AD, the SIEM) are always present.
  if (env) {
    const own = (ownPool0 ?? BENIGN_EVENTS).filter(e => envHasPlatforms(env, [e]));
    basePool = [...basePool.filter(e => envHasPlatforms(env, [e]) && orgRunsSource(e, env, stack, companyId)), ...platformNoise(companyId, env, own).filter(e => fitsStack(e, companyId, stack))];
    if (ownPool) ownPool = basePool;
  }
  // One host, one IP across the noise (normalizeHostIps) — the story is mapped onto it.
  const companyPool = normalizeHostIps(basePool ?? []);
  const profile = COMPANY_PROFILES.find(c => c.id === companyId);
  const edr = (stack.edr && PRODUCT_LABEL[stack.edr]) || profile?.architecture.edr;
  return { ownPool, companyPool, profile, edr };
}

/**
 * The product rule a session's stories must pass. A named organization (stories from every
 * demo company): a step shown as another product must be one that product really produces,
 * a step kept on its own product follows the company rule (storyFitsOrg). A Live-SOC company
 * with chosen products: every step one they produce (storyFitsStack); with its own: no step
 * written about another vendor's artifacts (storyHonoursLocks).
 */
function sessionFit(companyId: string, stack: Stack, env: TeamEnv | null): (evs: TelemetryEvent[]) => boolean {
  if (env) return evs => storyFitsOrg(evs, companyId, stack);
  if (Object.keys(stack).length > 0) return evs => storyFitsStack(evs, companyId, stack);
  return evs => storyHonoursLocks(evs, companyId);
}

/**
 * Can this story run whole on the session's products? Judged on the INSTANTIATED story
 * (company pool + EDR relabel — the events the feed would really carry), exactly as the
 * timeline's random pick judges it: with a chosen stack every step must be one those
 * products produce; with the company's own, none may be written about another vendor's
 * artifacts. QA M7: the Session Builder's storyline list, POST /sessions and /start all
 * use THIS predicate — they used to check the raw authored events, which could disagree.
 */
export function teamStoryFilter(companyId: string, stack: Stack = {}, env: TeamEnv | null = null): (story: AttackStory) => boolean {
  const { companyPool, edr } = storyBase(companyId, stack, env);
  const fits = sessionFit(companyId, stack, env);
  // A named organization: every log of the attack comes from a product or platform the admin
  // chose (the same rule its noise follows), so what the admin entered is what the feed shows.
  const chosen = (e: TelemetryEvent) => !env || storyEventChosen(e, env, stack, companyId);
  return story => {
    try {
      const evs = instantiateStory(story, companyPool, edr, companyId).events ?? [];
      return evs.length > 0 && evs.every(chosen) && fits(evs);
    } catch { return false; }
  };
}

/**
 * `load` sizes the shift to the team in the room (src/lib/team/load.ts): log pace
 * from the Tier-1 count, attack count from the team size. Omitted → the fixed,
 * difficulty-only load of before (existing seeds replay exactly).
 */
export function buildTeamTimeline(companyId: string, difficulty: "easy" | "medium" | "hard", seed: string, storyId?: string | null | (string | null)[], load: TeamLoad = legacyLoad(difficulty), stack: Stack = {}, tenant: Tenant | null = null, envIn: TeamEnv | null = null, opts: { bonus?: boolean } & VarietyOpts = {}): TimelineEntry[] {
  const history = opts.history ?? emptyHistory();
  const record: VarietyRecord = { v: 1, makers: [], decoy: null, twist: null, injects: [], stories: [] };
  // A named organization always has an environment (the default one when none was stored).
  const env = envIn ?? (tenant ? DEFAULT_ENV : null);
  const rnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}`));
  // Vendor choice (spec §3): only records the session's products — the chosen ones, else
  // the company's own — really produce make the feed, every log is labelled for them (as
  // on the dashboard; unlabelled, a CrowdStrike-authored row rendered as the company's
  // Defender record), and with a chosen stack only stories they can show whole are picked.
  const stacked = Object.keys(stack).length > 0;
  const { ownPool, companyPool, profile, edr } = storyBase(companyId, stack, env);
  const assets = COMPANY_ASSETS[companyId];

  // ── Attack stories: one on easy, two concurrent incidents otherwise ──────────
  interface Story { id: string; incident: string; events: TelemetryEvent[]; name: string }
  // The instructor's attack plan: one slot per concurrent attack — a chosen storyline, or
  // null for a random pick (an older session's single scenario_id is slot 1).
  const slotIds = Array.isArray(storyId) ? storyId : [storyId ?? null];
  const forcedAt = (i: number) => resolveTeamStory(companyId, difficulty, slotIds[i] ?? null, env, stack);
  const pinnedIdsAll = slotIds.filter((x): x is string => !!x);
  const storyFits = teamStoryFilter(companyId, stack, env);
  // Story picks and their victims draw from their own seeded stream: the same seed always
  // replays the same incidents (Math.random here made the warm-up test flaky), and the
  // main `rnd` stream below keeps the draws it had.
  const pickRnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}:story-pick`));
  const storyPool = teamStoryPool(companyId, difficulty, env, stack);
  // How many sessions ago this organization last met each kind of attack.
  const themeAgo = new Map<string, number>();
  for (const [id, n] of Object.entries(history.stories)) for (const t of storyThemes(id)) themeAgo.set(t, Math.min(n, themeAgo.get(t) ?? Infinity));
  const familyAgo = new Map<string, number>();
  for (const [id, n] of Object.entries(history.stories)) familyAgo.set(familyOfId(id), Math.min(n, familyAgo.get(familyOfId(id)) ?? Infinity));
  const pickStory = (accept: (s: AttackStory) => boolean): AttackStory => {
    const fit = storyPool.filter(accept);
    // A named organization never falls back to a story outside what the admin chose: with too few
    // fitting stories a slot repeats a pick (then dropped as a duplicate) rather than leak one.
    const from = fit.length ? fit : env ? storyPool.filter(storyFits) : storyPool;
    // Memory across exercises: a storyline this organization ran in its last sessions waits its turn
    // (the least recently run tier only; with no history every story is in it, so seeds replay as before).
    // A variant waits as long as its family does: the same template with another pretext is still a repeat.
    const ago = (s: AttackStory) => Math.min(history.stories[s.id] ?? Infinity, familyAgo.get(familyOf(s)) ?? Infinity);
    const best = Math.max(...from.map(ago));
    const tier = from.filter(s => ago(s) === best);
    // And the kind of attack rotates (Tal 2026-11-12): inside that tier, the stories whose kinds
    // (storyThemes) this organization met longest ago go first. No history: one tier, seeds replay as before.
    const kindAgo = (s: AttackStory) => Math.min(...storyThemes(s.id).map(t => themeAgo.get(t) ?? Infinity));
    const fresh = Math.max(...tier.map(kindAgo));
    return pickInFamilies(tier.filter(s => kindAgo(s) === fresh), pickRnd);
  };
  // Concurrent incidents hit different people (a team never works two attacks on one victim).
  // Every person on a story's malicious rows is one of its victims (a web story can name several accounts): a second
  // incident that touches any of them is the same victim worked twice.
  const victimsOf = (evs: TelemetryEvent[]) => [...new Set(evs.filter(e => e.user_email && isMalicious(classifyStoryEvent(e))).map(e => e.user_email!))];
  const takenVictims = new Set<string>();
  // The attacker addresses this session's storylines drew (variation.ts): two storylines never share one.
  const storyIps = new Set<string>();
  const storyDomains = new Set<string>();
  // A named organization's incidents are never named after the demo company a story was written for.
  const DEMO_COMPANY = /nexacorp|rocketstack|medcore|globallogis|quantumbank/gi;
  // `themes`: categories the pick must stay out of (the bonus never repeats a planned attack's kind).
  const buildStory = (avoid0: (string | undefined)[] = [], forced?: AttackStory | null, keepOff?: { hosts: Set<string>; users: Set<string> }, themes?: Set<StoryCategory>): Story | null => {
    const avoid = [...avoid0];
    const maxAttempts = stacked || env ? 20 : 6;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Chosen products: only stories they can show whole. The company's own: none
        // written about another vendor's artifacts (PRODUCT_LOCKS). Same predicate the
        // builder / create / start routes use for a pinned storyline (teamStoryFilter).
        const offTheme = (s: AttackStory) => !themes || !storyThemes(s.id).some(t => themes.has(t));
        const story = forced ?? pickStory(s => !avoid.includes(s.id) && storyFits(s) && offTheme(s));
        if (!forced && !offTheme(story)) return null;        // none left outside those themes: the caller decides
        if (!forced && avoid.includes(story.id)) continue;   // server-side there is no anti-repeat memory
        const events0 = instantiateStory(story, companyPool, edr, companyId, pickRnd, { seed, usedIps: storyIps, usedDomains: storyDomains }).events ?? [];
        if (events0.length === 0) return null;
        if ((stacked || env) && !forced && !sessionFit(companyId, stack, env)(events0)) continue;
        const victims = victimsOf(events0);
        // The bonus lands on new ground (expert review P0-4): no host or person the planned attacks touched.
        if (keepOff && !forced && attempt < maxAttempts - 1
          && events0.some(e => (e.hostname && keepOff.hosts.has(e.hostname)) || (e.user_email && keepOff.users.has(e.user_email)))) { avoid.push(story.id); continue; }
        // A random pick tries another story; a chosen one is re-instantiated onto another victim.
        if (victims.some(v => takenVictims.has(v)) && attempt < maxAttempts - 1) { if (!forced) avoid.push(story.id); continue; }
        for (const v of victims) takenVictims.add(v);
        const events = events0.map(e => applyStack(e, companyId, stack));
        const incident0 = events.find(e => e.incident_id)?.incident_id ?? `story:${story.id}`;
        const incident = env ? incident0.replace(DEMO_COMPANY, "org") : incident0;
        return { id: story.id, incident, events, name: story.title };
      } catch { return null; }
    }
    return null;
  };
  // Random slots never draw a storyline the plan pins to another slot.
  const story1 = buildStory(pinnedIdsAll, forcedAt(0));   // slot 1 leads (the primary incident)
  // Further concurrent incidents (load.stories): parallel work for several analysts and
  // a prioritisation call for the Manager. One story keeps a small team single-threaded.
  const story2 = load.stories >= 2 ? buildStory([...pinnedIdsAll, story1?.id], forcedAt(1)) : null;
  const story3 = load.stories >= 3 ? buildStory([...pinnedIdsAll, story1?.id, story2?.id], forcedAt(2)) : null;
  // A story's rows reach the feed in their authored order of time (a few stories list a row out of
  // order): the story's time map (storyTimeMap) is monotone only when the feed order follows the clock.
  const storyPlaced = (s: Story | null): Placed[] => byAuthoredTime(s?.events ?? []).map(ev => ({ ev, origin: "story" as const, verdict: classifyStoryEvent(ev), incident: s!.incident, attack: s!.name }));
  const distinct = (s: Story | null, n: number, others: (Story | null)[]): Story | null =>
    s && others.some(o => o?.incident === s.incident) ? { ...s, incident: `${s.incident}#${n}` } : s;
  const attack1 = storyPlaced(story1);
  const attack2 = storyPlaced(distinct(story2, 2, [story1]));
  const attack3 = storyPlaced(distinct(story3, 3, [story1, story2]));
  // The bonus attack (Tal, 2026-10-03): one more random story, another victim, held back until
  // the team has caught every planned attack — then released into the live feed.
  const planned = [story1, story2, story3].flatMap(st => st?.events ?? []);
  const keepOff = { hosts: new Set(planned.map(e => e.hostname).filter((h): h is string => !!h)), users: new Set(planned.map(e => e.user_email).filter((u): u is string => !!u)) };
  // It is another KIND of attack (Sdema review K10: a help-desk reset twice in one exercise): no category
  // a planned story belongs to (storyThemes), unless no fitting story is left outside them.
  const plannedThemes = new Set([story1, story2, story3].flatMap(st => (st ? storyThemes(st.id) : [])));
  const bonusAvoid = [...pinnedIdsAll, story1?.id, story2?.id, story3?.id];
  const story4 = opts.bonus ? (buildStory(bonusAvoid, null, keepOff, plannedThemes) ?? buildStory(bonusAvoid, null, keepOff)) : null;
  const bonusAttack = storyPlaced(distinct(story4, 4, [story1, story2, story3])).map(p => ({ ...p, held: true }));

  // Identities an incident has touched — their ordinary logins must not sit in the
  // noise labelled benign (playtest: a "benign, informational" VPN+MFA success for an
  // account the team had just contained).
  const compromised = new Set<string>();
  for (const p of [...attack1, ...attack2, ...attack3, ...bonusAttack]) if (isMalicious(p.verdict) && p.ev.user_email) compromised.add(p.ev.user_email);

  // ── Pool: noise + standalone attacks ─────────────────────────────────────────
  const seen = new Set<string>();
  // The company's OWN noise only: the shared pool is NexaCorp's (its hosts, its @nexacorp.com
  // users) — mixed into another tenant's feed it leaked a different company's identities.
  const pool = [...companyPool]
    .filter(e => { const k = String(e.id ?? ""); if (!k) return true; if (seen.has(k)) return false; seen.add(k); return true; });
  const ownIds = new Set(companyPool.map(e => String(e.id ?? "")));

  // Standalone attacks come from the company's OWN pool (never another tenant's identities).
  const groups = new Map<string, TelemetryEvent[]>();
  for (const e of companyPool) {
    if (!isMalicious(classifyPoolEvent(e))) continue;
    const key = poolIncidentKey(e);
    if (EXCLUDED_POOL_INCIDENTS.has(key)) continue;
    groups.set(key, [...(groups.get(key) ?? []), e]);
  }
  const poolAttackN = load.poolAttacks;
  // Standalone attacks on people the stories haven't already hit, when the pool allows.
  const groupKeys = [...groups.keys()].sort();
  const freshKeys = groupKeys.filter(k => !(groups.get(k) ?? []).some(e => e.user_email && takenVictims.has(e.user_email)));
  const chosenGroups = sampleN(freshKeys.length >= poolAttackN ? freshKeys : groupKeys, poolAttackN, rnd);
  // A lone blocked attempt (WAF / IPS / proxy block) is a true positive the controls already stopped;
  // it keeps its own incident (the team confirms it) but is tagged auto_contained so the report does
  // not count it as a missed incident when nobody escalates it (expert review P0-6).
  const poolAttacks: Placed[][] = chosenGroups.map(key => { const g = byAuthoredTime(groups.get(key) ?? []); const lone = g.length === 1 && isBlockedAttempt(g[0]);
    // A standalone attack is named by its first malicious log (it has no storyline title).
    const name = (g.find(e => isMalicious(classifyPoolEvent(e)))?.description ?? "Standalone attack").replace(/\s+/g, " ").slice(0, 90);
    return g.map(ev => ({ ev, origin: "pool_attack" as const, verdict: classifyPoolEvent(ev), incident: key, autoContained: lone, attack: name })); });
  for (const g of poolAttacks) for (const p of g) if (p.ev.user_email) compromised.add(p.ev.user_email);

  // Attack infrastructure of this session: benign noise must never share it (expert review P0-3).
  const attackIps = new Set([...attack1, ...attack2, ...attack3, ...bonusAttack].flatMap(p => [p.ev.src_ip, p.ev.dst_ip]).filter((ip): ip is string => !!ip && !PRIVATE_IP.test(ip)));
  const noiseCandidates = pool.filter(e => {
    const v = classifyPoolEvent(e);
    if (isMalicious(v)) return false;                                      // attacks are never "noise"
    if (v === "benign" && looksLikeAttack(e, attackIps)) return false;     // a "benign" row that reads as an attack would punish the analyst who spots it
    if (!ownIds.has(String(e.id ?? "")) && e.it_verify_result) return false; // another tenant's IT context
    if (e.user_email && compromised.has(e.user_email) && (e.source === "vpn" || /^(auth_|vpn_|mfa_)/.test(e.event_type))) return false;
    return true;
  });
  // Enough continuous noise to span the shift at this team's pace (load.ts), so the
  // DB refill rarely has to recycle logs.
  // Benign-positive alerts (fpAlerts.ts) at the same rate as the attacks' alerts, so a high-severity
  // alert is not an answer: each provable from the evidence in the feed (a ticket, the device, the
  // destination). They count toward the shift's row budget, so the noise sample shrinks by their
  // number and the shift length holds.
  const attackAlerts = [...attack1, ...attack2, ...attack3].filter(p => isMalicious(p.verdict) && isAlertRow(p.ev)).length;
  // Each FP alert comes from a product the session runs: Sentinel analytics only when the
  // organization runs Sentinel (Azure, or a Live-SOC company on Entra / Azure), the EDR / identity
  // alerts only when the chosen product records them. Own stream: the main draws stay as they were.
  const fpN = Math.max(2, Math.min(6, attackAlerts + (rnd() < 0.5 ? 1 : 0)));
  const frnd = streamOf(`${companyId}:${difficulty}:${seed}`, "fp-alerts");
  const resolved = stackFor(companyId, stack);
  const attackHosts = new Set([...attack1, ...attack2, ...attack3, ...bonusAttack, ...poolAttacks.flat()].map(p => p.ev.hostname).filter((h): h is string => !!h));
  const sessionIps = new Set(attackIps);
  // One alert in some medium / hard sessions carries a ticket that does NOT cover it (another host,
  // another scope, a closed window): a ticket nearby is evidence to read, not the answer.
  const miss = difficulty !== "easy" && (opts.force?.miss ?? frnd() < 0.35);
  const fpOut: FpOut[] = fpAlerts(assets, companyId, fpN, frnd, new Date(TEAM_TIME_BASE_MS).toISOString(), {
    siem: env ? env.platforms.includes("azure") : (resolved.cloud === "azure_activity" || resolved.idp === "entra"),
    fits: e => (!env || (storyEventChosen(e, env, stack, companyId) && orgRunsSource(e, env, stack, companyId))) && fitsStack(e, companyId, stack),
    stack: resolved, platforms: env?.platforms ?? [], seen: history.makers, force: opts.force?.makers, miss,
    avoid: { users: new Set([...compromised, ...takenVictims]), hosts: attackHosts, ips: sessionIps },
  });
  record.makers = fpOut.map(f => f.makerId);
  const fpRows = fpOut.flatMap(f => f.rows);
  // Keep the shift at its intended length: the storylines now carry their initial-access and
  // first-alert rows, so the real attack-row count runs over load.ts's estimate (≈10/story, 2/pool).
  // Trim the noise by that overflow and by the FP alerts, so total rows ≈ the planned budget.
  const attackRowsReal = attack1.length + attack2.length + attack3.length + poolAttacks.reduce((n, g) => n + g.length, 0);
  const attackRowsEst = load.stories * 10 + load.poolAttacks * 2;
  // Never below the floor (Sdema review K1: one ordinary log in fifty once the fitter had thinned the
  // noise for a small team, so the feed itself said "attack"): ordinary telemetry (benign pool rows,
  // not the decoys) stays at ORDINARY_PER_ATTACK_ROW times the attack rows, whatever the load asks.
  // (An alert outside its approval is an incident too: it counts as an attack row.)
  const ordinaryFloor = ORDINARY_PER_ATTACK_ROW * (attackRowsReal + fpOut.filter(f => f.verdict === "escalate").length);
  const benignN = Math.max(0, load.noiseCount - fpRows.length - Math.max(0, attackRowsReal - attackRowsEst));
  const shuffled = sampleN(noiseCandidates, noiseCandidates.length, rnd);   // the same draws sampleN(…, benignN) made
  const noise: Placed[] = shuffled.slice(0, benignN).map(ev => ({ ev, origin: "noise" as const, verdict: classifyPoolEvent(ev) }));
  // Ordinary web traffic: web logs that exist only inside a web story name the story. Its own stream,
  // and it takes the place of pool rows, so the shift's length and every other draw stay as they were.
  if (assets && noise.length > 0) {
    const wrnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}:web-noise`));
    const web = webNoise({ assets, storyEvents: planned, avoidIps: attackIps, count: Math.max(6, Math.round(noise.length * 0.14)), rnd: wrnd, ts: new Date(TEAM_TIME_BASE_MS).toISOString() })
      .filter(e => (!env || storyEventChosen(e, env, stack, companyId)) && (!(stacked || !!env) || fitsStack(e, companyId, stack)));
    const slots = sampleN(noise.map((_, i) => i), web.length, wrnd);
    web.slice(0, slots.length).forEach((ev, k) => { noise[slots[k]] = { ev, origin: "noise", verdict: classifyPoolEvent(ev) }; });
  }
  // The sample shrinks as story rows grow, so a platform can drop out of it by chance. A platform the
  // organization runs always shows ordinary traffic: its attack rows must not be the only ones it has.
  for (const p of env?.platforms ?? []) {
    if (noise.some(n => platformsOfEvent(n.ev).includes(p))) continue;
    for (const ev of sampleN(noiseCandidates.filter(e => platformsOfEvent(e).includes(p)), 3, rnd)) {
      noise[Math.floor(rnd() * noise.length) % Math.max(noise.length, 1)] = { ev, origin: "noise", verdict: classifyPoolEvent(ev) };
    }
  }
  // The floor, once web and platform rows have taken their slots: top up with further ordinary pool rows.
  {
    const inFeed = new Set(noise.map(n => n.ev));
    let ordinary = noise.filter(n => n.verdict === "benign").length;
    // R8: tickets stay near ITSM_SHARE of the feed. The tickets a session cannot do without (a story's
    // own ServiceNow rows, the approvals behind decoys and pool rows, the MSEL decoy's ticket and the two
    // unrelated ones) set how much ordinary telemetry has to surround them.
    const attackPlaced = [...attack1, ...attack2, ...attack3, ...poolAttacks.flat()];
    const fixedTickets = [...attackPlaced, ...noise].filter(p => isTicketRow(p.ev)).length + fpRows.filter(isTicketRow).length
      + fpOut.filter(f => f.ticket).length + [...noise, ...attackPlaced].filter(p => itsmRecordFor(p.ev, companyId)).length
      + (difficulty !== "easy" ? 1 : 0) + unrelatedTicketMin(noise.filter(p => isTicketRow(p.ev)).length + fpOut.filter(f => f.ticket).length + (difficulty !== "easy" ? 1 : 0));
    const noiseTicketRows = noise.filter(p => isTicketRow(p.ev)).length;
    const otherRowsNow = attackPlaced.length + fpRows.length + (noise.length - ordinary - noiseTicketRows) + (difficulty !== "easy" ? MSEL_SUPPORT_ROWS : 0) + fixedTickets;
    const ticketFloor = Math.ceil(fixedTickets / ITSM_SHARE) - otherRowsNow;
    // (a pool ticket in the noise is a ticket, not ordinary telemetry)
    const floor = Math.max(ordinaryFloor, ticketFloor + noiseTicketRows);
    // The same record twice is a repeat; a third copy is a tell (R8c). The pool holds a few identical
    // rows (borrowed noise), so the top-up never adds a third of any content.
    const contentOf = (e: TelemetryEvent) => { const { id: _i, ts: _t, ...rest } = e; void _i; void _t; return JSON.stringify(rest); };
    const copies = new Map<string, number>();
    for (const n of noise) { const c = contentOf(n.ev); copies.set(c, (copies.get(c) ?? 0) + 1); }
    const fresh = (e: TelemetryEvent) => { const c = contentOf(e); if ((copies.get(c) ?? 0) >= 2) return false; copies.set(c, (copies.get(c) ?? 0) + 1); return true; };
    for (let k = benignN; k < shuffled.length && ordinary < floor; k++) {
      const ev = shuffled[k];
      if (inFeed.has(ev) || classifyPoolEvent(ev) !== "benign") continue;
      if (k >= benignN && ordinary >= ordinaryFloor && !fresh(ev)) continue;
      noise.push({ ev, origin: "noise", verdict: "benign" }); inFeed.add(ev); ordinary++;
    }
    // A small pool runs out (QuantumBank shows about twenty ordinary rows): recurring telemetry comes
    // back as the same activity by another person of the company on their own machine (noiseDeck.ts,
    // as the solo feed draws it), never as a copy (R8c).
    if (ordinary < floor) {
      const deck = new NoiseDeck(noiseCandidates.filter(e => classifyPoolEvent(e) === "benign"), mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}:noise-variants`)));
      const ids = new Set(noise.map(n => String(n.ev.id ?? "")));
      const perOrigin = new Map<string, number>();
      for (let tries = 0; ordinary < floor && tries < floor * 12; tries++) {
        const ev = deck.next();
        if (!ev) break;
        // An endpoint's own telemetry stays with its records (the EDR console, the workbench and the XDR
        // tables build one process from them): a person moved onto a server's process row is not.
        const vm = /^(.*)_v\d+$/.exec(String(ev.id ?? ""));
        if (vm && (ENDPOINT_SOURCES.has(ev.source) || (ev.hostname && attackHosts.has(ev.hostname)))) continue;
        // Four more instances of one ordinary record at most, each by another person: nine people pulling
        // the same vault password on one server in an hour is a pattern of its own.
        if (vm && (perOrigin.get(vm[1]) ?? 0) >= 4) continue;
        if (inFeed.has(ev) || ids.has(String(ev.id ?? "")) || !fresh(ev)) continue;
        if (vm) perOrigin.set(vm[1], (perOrigin.get(vm[1]) ?? 0) + 1);
        noise.push({ ev, origin: "noise", verdict: "benign" }); inFeed.add(ev); ids.add(String(ev.id ?? "")); ordinary++;
      }
    }
  }
  // Each maker's rows land together (a lockout right after its VPN failures) at a seeded point of the
  // WHOLE feed (placed after the attack bands; spliced into the noise they all fell into the warm-up
  // whenever long storylines left little noise). A ticket that does not cover its alert makes that
  // alert an incident of its own (escalate). Its ticket (if any) is placed later, at a seeded
  // distance before or after it.
  const linkedTickets: { alert: Placed; spec: NonNullable<FpOut["ticket"]> }[] = [];
  const fpGroups: { placed: Placed[]; frac: number }[] = [];
  for (const f of fpOut) {
    const alertEv = f.rows[f.rows.length - 1];
    const placed: Placed[] = f.rows.map(ev => f.verdict === "escalate" && ev === alertEv
      ? { ev, origin: "pool_attack" as const, verdict: "escalate" as const, incident: `solo:${ev.id}`, attack: `Activity outside its approval: ${(ev.description ?? "").slice(0, 70)}` }
      : { ev, origin: "noise" as const, verdict: f.verdict === "escalate" ? "benign" as const : "fp" as const });
    // (an escalate alert never opens the shift: the warm-up stays ordinary traffic)
    const frac = 0.12 + rnd() * 0.84;
    fpGroups.push({ placed, frac: f.verdict === "escalate" ? Math.max(0.3, frac) : frac });
    if (f.ticket) linkedTickets.push({ alert: placed[placed.length - 1], spec: f.ticket });
  }

  const storyCount = attack1.length + attack2.length + attack3.length;
  const poolCount = poolAttacks.reduce((n, g) => n + g.length, 0);
  const total = noise.length + storyCount + poolCount;
  if (total === 0) return [];

  // ── Placement ─────────────────────────────────────────────────────────────────
  // A warm-up of ordinary traffic first, then each story clusters into its own band so it
  // reads as an unfolding attack. The attacks start at staggered, seed-varied points (Tal,
  // 2026-10-03: not all at once, different timing every session). The PRIMARY incident (Attack 1)
  // always surfaces first and every planned attack has started by the middle of the shift
  // (2026-10-18 review: a primary incident due at 30:10 never reached a 21-minute exercise).
  // The warm-up holds on the feed the team SEES: ITSM approvals and the MSEL's supporting logs
  // join after placement and lengthen it, so the floor under every attack row counts them too
  // (placing at 10% of the pre-insert rows let some story mixes open inside the first tenth).
  // ITSM noise (itsmNoise.ts): unrelated tickets, some of them right before attack rows, so "a ticket
  // just fired" marks nothing. Its own stream.
  const trnd = streamOf(`${companyId}:${difficulty}:${seed}`, "itsm");
  const noiseTickets0 = itsmNoise(assets, companyId, assets ? 3 + Math.floor(trnd() * 3) + linkedTickets.length : 0, trnd, new Date(TEAM_TIME_BASE_MS).toISOString(),
    { users: new Set([...compromised, ...takenVictims]), hosts: attackHosts })
    .filter(x => !env || storyEventChosen(x.ev, env, stack, companyId));
  // ServiceNow keeps to about ITSM_SHARE of the feed (Sdema review K1: a quarter of the feed was
  // tickets). The approvals that prove a decoy stay; unrelated tickets fill what is left, never fewer
  // than two, so a ticket is still no tell.
  const evidenceTickets = [...noise, ...attack1, ...attack2, ...attack3, ...poolAttacks.flat()].filter(p => itsmRecordFor(p.ev, companyId)).length + linkedTickets.length;
  const otherRows = total + fpRows.length + (difficulty !== "easy" ? MSEL_SUPPORT_ROWS : 0);
  const itsmBudget = Math.round((ITSM_SHARE * otherRows) / (1 - ITSM_SHARE));
  // A story's own tickets (a help-desk call, a change it abuses) are in the feed already: they count.
  const storyTickets = [...attack1, ...attack2, ...attack3, ...poolAttacks.flat(), ...noise].filter(p => isTicketRow(p.ev)).length + fpRows.filter(isTicketRow).length;
  const benignTickets = noise.filter(p => isTicketRow(p.ev)).length + linkedTickets.length + (difficulty !== "easy" ? 1 : 0);
  const noiseTickets = noiseTickets0.slice(0, Math.max(Math.min(unrelatedTicketMin(benignTickets), noiseTickets0.length), itsmBudget - evidenceTickets - storyTickets));
  const itsmRows = evidenceTickets + noiseTickets.length;
  const lateRows = itsmRows + fpRows.length + (difficulty !== "easy" ? MSEL_SUPPORT_ROWS : 0);
  const leadMin = Math.min(total - 1, Math.ceil(WARMUP_MIN * (total + lateRows)));
  const posToAttack = new Map<number, Placed>();
  // Every attack row first gets the position its band wants; the positions are then handed out
  // together in target order, so overlapping bands INTERLEAVE. (Resolving each band on its own
  // pushed a long story's collisions forward, queueing the next attack behind it: a 62-row
  // ransomware chain held a planned attack back to two thirds of the shift.)
  // A planned attack's opening (its first malicious row) keeps its slot even when the bands around
  // it are dense: it is reserved first, everything else flows around the reservations.
  const anchors = new Set<number>();
  const wanted: { pos: number; seq: number; band: number; ev: Placed }[] = [];
  let bandCount = 0;
  const place = (evs: Placed[], startFrac: number, endFrac: number, anchored = false) => {
    if (evs.length === 0) return;
    const start0 = Math.max(leadMin, Math.floor(total * startFrac));
    const end0 = Math.max(start0, Math.min(total - 1, Math.floor(total * endFrac)));
    const denom = Math.max(1, evs.length - 1);
    // The band's slot is where its first MALICIOUS row surfaces: baseline rows it opens with sit before it.
    const lead = Math.max(0, evs.findIndex(p => isMalicious(p.verdict)));
    const shift = Math.round((lead * (end0 - start0)) / denom);
    const start = Math.max(leadMin, start0 - shift);
    const end = Math.max(start, end0 - shift);
    for (let i = 0; i < evs.length; i++) {
      if (anchored && i <= lead) anchors.add(wanted.length);   // the opening: its baseline rows and the first malicious one
      wanted.push({ pos: Math.min(end, start + Math.round((i * (end - start)) / denom)), seq: wanted.length, band: bandCount, ev: evs[i] });
    }
    bandCount++;
  };
  const assignPositions = () => {
    const taken = new Set<number>();
    const posOf = new Map<number, number>();
    for (const w of wanted) if (anchors.has(w.seq)) {
      let p = w.pos;
      while (taken.has(p) && p < total - 1) p++;
      taken.add(p); posOf.set(w.seq, p);
    }
    const order = wanted.filter(w => !anchors.has(w.seq)).sort((a, b) => a.pos - b.pos || a.seq - b.seq);
    let next = leadMin;
    for (const w of order) {
      let p = Math.max(w.pos, next);
      while (taken.has(p) && p < total - 1) p++;
      if (taken.has(p)) { p = total - 1; while (taken.has(p) && p > 0) p--; }
      taken.add(p); posOf.set(w.seq, p); next = p + 1;
    }
    // Each band keeps its own order: its rows take the band's positions in sequence.
    const byBand = new Map<number, { seq: number; ev: Placed }[]>();
    for (const w of wanted) (byBand.get(w.band) ?? byBand.set(w.band, []).get(w.band)!).push({ seq: w.seq, ev: w.ev });
    for (const rows of byBand.values()) {
      const ps = rows.map(r => posOf.get(r.seq)!).sort((a, b) => a - b);
      rows.forEach((r, i) => posToAttack.set(ps[i], r.ev));
    }
  };
  const warmup = WARMUP_MIN + rnd() * 0.05;
  // Attack 1 leads; the others keep a seeded order behind it.
  const rest = [attack2, attack3].filter(a => a.length > 0);
  if (rest.length === 2 && rnd() < 0.5) rest.reverse();
  const bands = [attack1, ...rest].filter(a => a.length > 0);
  // The last band opens early enough that its first malicious row (after any baseline rows it
  // leads with, and the ITSM / MSEL rows spliced in later) still lands before mid-shift.
  const lastStart = 0.42;
  bands.forEach((evs, k) => {
    const base = bands.length > 1 ? warmup + ((lastStart - warmup) * k) / (bands.length - 1) : warmup;
    // Attack 1 starts right after the warm-up; the later ones jitter a little around their slot.
    const startFrac = k === 0 ? warmup : Math.max(warmup + 0.04, base + (rnd() - 0.5) * 0.06);
    const len = 0.26 + rnd() * 0.12;
    place(evs, startFrac, Math.min(0.94, startFrac + len), true);
  });
  // Standalone pool incidents land at seeded points after the warm-up (a multi-event
  // one spans a few positions), all before the last fifth of the shift.
  for (const g of poolAttacks) {
    const startFrac = warmup + 0.03 + rnd() * (0.8 - warmup);
    place(g, startFrac, Math.min(0.9, startFrac + 0.02 * g.length));
  }
  assignPositions();

  const ordered: Placed[] = [];
  let bi = 0;
  // A dense band (a small team: the fitter cut the noise to a few rows) can be handed positions past
  // the canvas edge. Walk to the last one, never just `total`: rows past the edge used to vanish
  // silently, the voice-clone takeover lost its impact rows (Sdema review, 2026-11-08).
  const lastPos = Math.max(total - 1, ...posToAttack.keys());
  for (let pos = 0; pos <= lastPos; pos++) {
    const atk = posToAttack.get(pos);
    if (atk) ordered.push(atk);
    else if (bi < noise.length) ordered.push(noise[bi++]);
  }
  while (bi < noise.length) ordered.push(noise[bi++]);
  for (const g of fpGroups) ordered.splice(Math.floor(ordered.length * g.frac), 0, ...g.placed);

  // Ticket context (expert review 2026-11-07: an approved ticket right before every FP alert, and never
  // before an attack, was itself the answer). A ticket that explains an alert still lands BEFORE it
  // (the approval exists when the work starts, so the analyst can prove the false positive), but at
  // a seeded distance: long before (a change approved earlier in the day) or just before. Unrelated
  // tickets land everywhere, including just before the opening of attacks, and several makers have
  // no ticket at all. Collect first, splice after (highest position first).
  const itsmInserts: { at: number; p: Placed }[] = [];
  const ticketAt = (i: number) => (trnd() < 0.45 ? Math.max(0, i - 8 - Math.floor(trnd() * 24)) : Math.max(0, i - 1 - Math.floor(trnd() * 3)));
  const indexOf = new Map<Placed, number>(ordered.map((p, i) => [p, i]));
  for (let i = 0; i < ordered.length; i++) {
    const rec = itsmRecordFor(ordered[i].ev, companyId);
    if (rec) itsmInserts.push({ at: ticketAt(i), p: { ev: rec, origin: "itsm", verdict: "benign" } });
  }
  linkedTickets.forEach(({ alert, spec }, k) => {
    const i = indexOf.get(alert);
    if (i === undefined) return;
    itsmInserts.push({ at: ticketAt(i), p: { ev: ticketRecord(spec, companyId, `itsm_fp_${k}`, new Date(TEAM_TIME_BASE_MS).toISOString()), origin: "itsm", verdict: "benign", window: spec.window, ticketFor: alert } });
  });
  // The opening of each planned attack: an unrelated ticket sits right before most of them.
  const openings = [attack1, attack2, attack3].map(a => a.find(p => isMalicious(p.verdict))).map(p => (p ? indexOf.get(p) : undefined)).filter((i): i is number => i !== undefined);
  noiseTickets.forEach(({ ev, window }, k) => {
    const near = k < openings.length && trnd() < 0.75 ? openings[k] : undefined;
    const at = near !== undefined ? Math.max(0, near - 1 - Math.floor(trnd() * 2)) : Math.floor(ordered.length * (0.03 + trnd() * 0.94));
    itsmInserts.push({ at, p: { ev, origin: "itsm", verdict: "benign", window } });
  });
  for (const { at, p } of itsmInserts.sort((a, b) => b.at - a.at)) ordered.splice(at, 0, p);

  // Cadence from the team's load (load.ts): base gap + uniform jitter.
  let t = 2000;
  const timed: { p: Placed; at: number }[] = ordered.map(p => {
    const entry = { p, at: t };
    t += load.baseGapMs + Math.floor(rnd() * load.jitterMs);
    return entry;
  });
  // The shift ends when the instructor said it would: story overflow, ITSM records and FP alerts
  // can run the feed past its budget, so a timeline longer than the shift is compressed onto it
  // (the pace rises slightly; nothing planned falls after the end). The DB refill keeps the feed
  // going if the instructor runs the session longer.
  const shiftMs = load.shiftMin * 60_000;
  const rawSpan = timed.length ? timed[timed.length - 1].at : 0;
  if (rawSpan > shiftMs * 0.95) {
    const k = (shiftMs * 0.95) / rawSpan;
    for (const x of timed) x.at = Math.round(x.at * k);
  }
  // One request seen by the WAF, by the origin web server and by the application behind it is one
  // moment, not rows a feed gap apart: no format shares an id with another, so the time is what ties
  // them. One WAF row is one request: it takes the next origin row of that request, and that origin
  // row the next application row (a WAF row pulling every origin row of the minute put the second
  // request before the first request's application line).
  for (let k = 0, waf = new Map<string, { at: number; n: number }>(), origin = new Map<string, { at: number; n: number }>(); k < timed.length; k++) {
    const e = timed[k].p.ev;
    if (e.source !== "waf" && e.source !== "web_server" && e.source !== "app_log") continue;
    const key = `${e.src_ip}|${e.network?.method}|${e.network?.url}|${e.ts.slice(0, 16)}`;
    const story = timed[k].p.origin === "story";
    const from = !story ? undefined : e.source === "web_server" ? waf : e.source === "app_log" ? origin : undefined;
    const prev = from?.get(key);
    if (prev) { from!.delete(key); timed[k].at = Math.max(prev.at + 1, prev.at + Math.min(700, Math.floor((timed[k].at - prev.at) / 2))); }
    if (e.source === "waf") waf.set(key, { at: timed[k].at, n: k });
    if (e.source === "web_server") origin.set(key, { at: timed[k].at, n: k });
  }
  keepAuthBursts(timed);
  const span = timed.length ? timed[timed.length - 1].at : 0;
  // A change ticket's window, now that times are final: minutes around the alert it covers (or around
  // the record itself). Written relative to the record's own time, since the public row is re-timed
  // by its own offset (toPublicEntry) and every raw timestamp moves with it.
  const atOfPlaced = new Map<Placed, number>(timed.map(x => [x.p, x.at]));
  for (const x of timed) {
    const w = x.p.window;
    if (!w || x.p.ev.raw?.["servicenow.table"] !== "change_request") continue;
    const anchor = (x.p.ticketFor && atOfPlaced.get(x.p.ticketFor)) ?? x.at;
    const iso = (min: number) => new Date(TEAM_TIME_BASE_MS + anchor - x.at + min * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    x.p = { ...x.p, ev: { ...x.p.ev, raw: { ...x.p.ev.raw, "servicenow.start_date": iso(w[0]), "servicenow.end_date": iso(w[1]) } } };
  }

  // ── MSEL — scripted injects timed against the shift ───────────────────────────
  // Each inject is EVALUABLE (expected_response + linked_objective). Skipped on easy.
  // Injects are placed in the window that OPENS at the first attack log and runs to the end of the
  // shift — a "CISO wants a status on the suspicious activity" request can't fire before any attack
  // exists (diagnostic P1). `at(f)` interpolates f across [firstAttack, span].
  // 2026-11-07: every inject text, the decoy's kind and the twist's kind rotate (msel.ts), least
  // recently used first for the organization (variety.ts); their slots jitter a little per session.
  const mselOn = difficulty !== "easy" && span > 0;
  const firstAttackAt = Math.min(span, ...timed.filter(x => isMalicious(x.p.verdict)).map(x => x.at));
  const mselStart = Number.isFinite(firstAttackAt) ? Math.min(firstAttackAt + 30000, span) : 0;
  const at = (f: number) => Math.floor(mselStart + (span - mselStart) * f);
  const vrnd = streamOf(`${companyId}:${difficulty}:${seed}`, "variety-msel");
  const texts = pickInjectTexts(vrnd, history.injects);
  const jit = () => (vrnd() - 0.5) * 0.08;
  const injectBody = (id: string, kind: string, t: InjectText) => ({ id, kind, text: t.text, expected_response: t.expected_response, linked_objective: t.linked_objective, ...(t.expected_decision ? { expected_decision: t.expected_decision } : {}) });
  // Management pressure (CISO / Legal / execs) is no longer scripted on the clock: the SOC-Manager
  // director (src/lib/team/manager) raises it as a decision card when the session makes it true.
  // The decoy and twist texts are filled in below, once their kinds are drawn (or the inject dropped).
  const placeholder: InjectText = { key: "", text: "", expected_response: "", linked_objective: "" };
  const msel: TimelineEntry[] = !mselOn ? [] : [
    { due_offset_ms: at(0.45 + jit()), channel: "inject", body: injectBody("msel_false_lead", "false_lead", placeholder) },
    { due_offset_ms: at(0.55 + jit()), channel: "inject", body: injectBody("msel_2", "ticket", texts.ticket) },
    { due_offset_ms: at(0.68 + jit()), channel: "inject", body: injectBody("msel_twist", "twist", placeholder) },
    { due_offset_ms: at(0.8 + jit()), channel: "inject", body: injectBody("msel_4", "announcement", texts.announcement) },
  ];
  if (mselOn) record.injects.push(texts.ticket.key, texts.announcement.key);
  const dropInject = (id: string) => { const k = msel.findIndex(e => (e.body as { id?: string }).id === id); if (k >= 0) msel.splice(k, 1); };

  // ── Telemetry behind the scripted injects (playtest P1: the twist had no logs and
  // the false lead pointed at firewall logs that didn't exist) ───────────────────
  const support: { p: Placed; at: number }[] = [];
  if (mselOn) {
    // Own RNG stream: inject-support placement depends on the seed alone, not on how
    // many draws the (randomly chosen) stories consumed above.
    const mrnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}:msel-support`));
    const fw = fwFlavour((stack.firewall && PRODUCT_LABEL[stack.firewall]) || profile?.architecture.firewall || "");
    const useSysmon = (profile?.architecture.sources ?? []).includes("sysmon");
    const subnet = assets?.subnet ?? "10.10.20";
    const baseTs = new Date(TEAM_TIME_BASE_MS).toISOString();

    // Twist: something new on the running (primary) attack story's ground.
    const twistInject = msel.find(e => (e.body as { id?: string }).id === "msel_twist");
    const twistAt = twistInject?.due_offset_ms ?? at(0.68);
    // "A host you already worked": prefer hosts whose malicious story logs reached the
    // feed BEFORE the twist lands.
    const seenBefore = new Set(timed.filter(x => x.at < twistAt).map(x => x.p));
    // Candidate = a story with a malicious log on a named host; prefer one already
    // seen before the twist, and the primary story over the second one.
    const hostsOf = (st: Placed[], onlySeen: boolean) => {
      const m = new Map<string, number>();
      for (const p of st) if (p.ev.hostname && isMalicious(p.verdict) && (!onlySeen || seenBefore.has(p))) m.set(p.ev.hostname, (m.get(p.ev.hostname) ?? 0) + 1);
      return m;
    };
    const candidates: [Placed[], boolean][] = [[attack1, true], [attack2, true], [attack1, false], [attack2, false]];
    const found = candidates.find(([st, seen]) => hostsOf(st, seen).size > 0);
    const twistStory = found ? found[0] : (attack1.length ? attack1 : attack2);
    const hostCount = found ? hostsOf(found[0], found[1]) : new Map<string, number>();
    const isInfra = (h: string) => assets ? (h === assets.dc) : false;
    // "A host you already worked" is only true when the team SAW one before the twist.
    // A cloud-only story (account takeover: VPN, Entra, mailbox, SharePoint) has no
    // host at all — the twist then lands on the VICTIM's own device (named in the
    // story's logs), and the inject says so, instead of an unrelated workstation.
    const seenHost = !!found && found[1] && hostCount.size > 0;
    const victim = mostCommonOf(twistStory.filter(x => isMalicious(x.verdict)).map(x => x.ev.user_email));
    const DEVICE_KEYS = ["gp.client_hostname", "device.hostname", "DeviceName", "winlog.computer_name", "data.office365.DeviceProperties.DisplayName"];
    const victimDevice = !seenHost && victim ? twistStory
      .filter(x => x.ev.user_email === victim)
      .flatMap(x => [x.ev.hostname, ...DEVICE_KEYS.map(k => x.ev.raw?.[k])])
      .map(v => (typeof v === "string" ? v.trim() : ""))
      .find(v => v && /^[A-Za-z][A-Za-z0-9-]{2,}$/.test(v) && !/unknown|unregistered/i.test(v)) : undefined;
    const host = (seenHost || hostCount.size ? [...hostCount.entries()].filter(([h]) => !isInfra(h)).sort((a, b) => b[1] - a[1])[0]?.[0] : undefined)
      ?? victimDevice
      ?? [...hostCount.keys()][0]
      ?? assets?.hosts.find(h => /^(WS|LT|LAP|WKS)/i.test(h)) ?? assets?.hosts[0] ?? "WS-UNKNOWN";
    const hostEv = twistStory.find(p => p.ev.hostname === host && p.ev.src_ip && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(p.ev.src_ip));
    const ipDraw = mrnd();   // drawn unconditionally → the stream stays seed-only
    // The host's own address from the story: a row it sent, else a row it received (a published server
    // is the firewall's NAT destination), else a fresh one on the subnet.
    const priv = (ip: unknown): ip is string => typeof ip === "string" && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
    const recvIp = twistStory.map(p => p.ev).find(e => e.hostname === host && priv(e.dst_ip))?.dst_ip
      ?? twistStory.map(p => (p.ev.raw as Record<string, unknown> | undefined)?.["pan.natdst"]).find(priv);
    const hostIp = hostEv?.ev.src_ip ?? recvIp ?? `${subnet}.${60 + Math.floor(ipDraw * 120)}`;
    const hostUser = twistStory.find(p => p.ev.hostname === host && p.ev.user_email)?.ev.user_email ?? (host === victimDevice ? victim : undefined);
    const procEv = [...twistStory].reverse().find(p => p.ev.hostname === host && p.ev.process?.name && isMalicious(p.verdict));
    const incident = twistStory[0]?.incident;
    // The host's OS, from the story's own records of it: a Linux web server or a Mac laptop never
    // gets a rundll32 beacon or a Run key.
    const onHostEvs = [...attack1, ...attack2, ...attack3].filter(p => p.ev.hostname === host).map(p => p.ev);
    const paths = onHostEvs.flatMap(e => [e.process?.path, e.file?.path]).filter((x): x is string => !!x);
    const hostOs: "windows" | "linux" | "mac" = paths.some(x => x.startsWith("/Users/")) || /macbook|mbp/i.test(host) ? "mac"
      : paths.some(x => x.startsWith("/")) || onHostEvs.some(e => e.source === "linux_audit" || e.source === "k8s_audit" || e.source === "web_server") ? "linux" : "windows";
    const usedHosts = new Set<string>([...attackHosts, ...fpOut.map(f => f.host).filter((h): h is string => !!h), host]);
    const usedUsers = new Set<string>([...compromised, ...takenVictims, ...fpOut.map(f => f.person).filter((u): u is string => !!u)]);
    const twist = twistInject ? buildTwist({
      rnd: vrnd, baseTs, assets, stack: resolved, host, hostIp, hostUser, victim, seenHost,
      proc: procEv?.ev.process ? { name: procEv.ev.process.name, pid: procEv.ev.process.pid, path: procEv.ev.process.path, cmdline: procEv.ev.process.cmdline, parent: procEv.ev.process.parent_name } : undefined,
      edr: edr ?? "Microsoft Defender for Endpoint", fw, useSysmon, ips: new Set(sessionIps), domains: new Set(), usedHosts, os: hostOs,
      // What the attack achieved (msel.ts twistGround): a twist needs a cause on its host.
      companyId, story: twistStory.filter(p => isMalicious(p.verdict)).map(p => p.ev),
      // The other incidents' people (their victims, the benign-positive makers' staff), never this story's own.
      avoidUsers: new Set([...usedUsers].filter(u => !twistStory.some(p => p.ev.user_email === u))),
    }, history, opts.force?.twist) : null;
    if (!twist) dropInject("msel_twist");
    else {
      record.twist = twist.kind;
      record.injects.push(twist.inject.key);
      Object.assign(twistInject!.body, { text: twist.inject.text, expected_response: twist.inject.expected_response, linked_objective: twist.inject.linked_objective });
      // Cause before effect (expert review P0-4): the twist fires only after every log the story
      // put on that host (or, for a host-less story, the whole story) has reached the feed: a
      // NEW beacon never appears before the payload it comes from. The inject moves with it.
      const atOf = new Map<Placed, number>(timed.map(x => [x.p, x.at]));
      const onHost = twistStory.filter(p => p.ev.hostname === host);
      const doneAt = Math.max(0, ...(onHost.length ? onHost : twistStory).map(p => atOf.get(p) ?? 0));
      const twistFire = Math.min(Math.floor(span * 0.95), Math.max(twistAt, doneAt + 60000));
      twistInject!.due_offset_ms = twistFire;
      const tw = (k: number) => twistFire + 20000 + k * 45000 + Math.floor(mrnd() * 8000);
      twist.rows.forEach((ev, k) => support.push({ p: { ev, origin: "inject_support", verdict: "tp", incident, supports: "msel_twist" }, at: tw(k) }));
    }

    // False lead: a large upload that is sanctioned business; its kind, reporter, host, destination
    // and volume differ per session, and the host sent a smaller batch the same way earlier.
    const leadInject = msel.find(e => (e.body as { id?: string }).id === "msel_false_lead");
    const decoy = leadInject && assets ? buildDecoy({ assets, companyId, rnd: vrnd, fw, usedUsers, usedHosts, ips: new Set(sessionIps), baseTs }, history, opts.force?.decoy) : null;
    if (!decoy) dropInject("msel_false_lead");
    else {
      record.decoy = decoy.kind;
      record.injects.push(decoy.inject.key);
      Object.assign(leadInject!.body, { text: decoy.inject.text, expected_response: decoy.inject.expected_response, linked_objective: decoy.inject.linked_objective });
      const leadAt = leadInject!.due_offset_ms;
      const when = { baseline: () => Math.max(2000, at(0.02 + mrnd() * 0.2)), before: () => leadAt - 60000 - Math.floor(mrnd() * 90000), after: () => leadAt + 25000 + Math.floor(mrnd() * 40000) };
      decoy.rows.forEach(({ ev, when: w }) => support.push({ p: { ev, origin: "inject_support", verdict: w === "baseline" ? "benign" : "fp", supports: "msel_false_lead" }, at: Math.max(2000, when[w]()) }));
      // Its approval: early in the shift or shortly before the transfers. A change window covers the transfers.
      const tAt = mrnd() < 0.5 ? Math.max(2000, at(0.05 + mrnd() * 0.2)) : Math.max(2000, leadAt - 240000 - Math.floor(mrnd() * 240000));
      const tEv = ticketRecord(decoy.ticket, companyId, "msel_false_lead_itsm", baseTs);
      if (decoy.ticket.window && decoy.ticket.table === "change_request") {
        const iso = (min: number) => new Date(TEAM_TIME_BASE_MS + leadAt - tAt + min * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
        tEv.raw = { ...tEv.raw, "servicenow.start_date": iso(decoy.ticket.window[0]), "servicenow.end_date": iso(decoy.ticket.window[1]) };
      }
      support.push({ p: { ev: tEv, origin: "inject_support", verdict: "benign", supports: "msel_false_lead" }, at: tAt });
    }
  }

  // The held bonus story: its own pace (relative offsets), parked past any shift until released.
  const bonusGap = Math.max(4000, Math.round(load.baseGapMs * 2.5));
  const bonusTimed = bonusAttack.map((p, k) => ({ p, at: BONUS_HOLD_MS + k * bonusGap + Math.floor(rnd() * load.jitterMs) }));

  // Merge the supporting logs into the feed by time. Feed entries come first in the
  // id index space, so ids stay a pure function of (seed, position).
  const merged = [...timed, ...support, ...bonusTimed].sort((a, b) => a.at - b.at);
  // One host, one IP across the WHOLE session — stories, noise, the twist, inject support
  // logs each chose an address their own way; the analyst pivots across all of them.
  // A web row names a workstation only by its address: it moves with that workstation's own rows.
  // R3: one account, one SID across the session (the pool and every story were authored apart).
  const hostEvs = normalizeAccountSids(normalizeHostIps(merged.map(m => m.p.ev)), companyId);
  const movedIps = new Map<string, string>();
  hostEvs.forEach((e, i) => { const was = merged[i].p.ev.src_ip; if (merged[i].p.origin === "story" && was && e.src_ip && was !== e.src_ip && PRIVATE_IP.test(was)) movedIps.set(`${merged[i].p.incident ?? ""}|${was}`, e.src_ip); });
  const sessionEvs = hostEvs.map((e, i) => {
    const to = (e.source === "waf" || e.source === "web_server") && e.src_ip ? movedIps.get(`${merged[i].p.incident ?? ""}|${e.src_ip}`) : undefined;
    return to ? { ...e, src_ip: to, raw: e.raw ? Object.fromEntries(Object.entries(e.raw).map(([k, v]) => [k, v === e.src_ip ? to : v])) : e.raw } : e;
  });
  // One time map per attack story (and per standalone pool incident): authored time → shift time,
  // anchored on the times its rows are shown at. Every time inside the story's rows goes through it
  // (toPublicEntry), so a field naming another row's time lands on that row (K6, Sdema review).
  const shownMs = (m: { p: Placed; at: number }) => TEAM_TIME_BASE_MS + (m.at >= BONUS_HOLD_MS ? m.at - BONUS_HOLD_MS : m.at);
  const groupOf = (p: Placed) => (p.origin === "story" || p.origin === "pool_attack") && p.incident ? `${p.held ? "bonus" : "feed"}|${p.incident}` : undefined;
  const groupRows = new Map<string, { authoredMs: number; shownMs: number }[]>();
  for (const m of merged) {
    const g = groupOf(m.p);
    if (g) (groupRows.get(g) ?? groupRows.set(g, []).get(g)!).push({ authoredMs: Date.parse(m.p.ev.ts), shownMs: shownMs(m) });
  }
  const groupMaps = new Map<string, StoryClock>([...groupRows].map(([g, rows]) => [g, { map: storyTimeMap(rows), firstMs: Math.min(...rows.map(r => r.shownMs)) }]));
  const clocks: (StoryClock | undefined)[] = merged.map(m => { const g = groupOf(m.p); return g ? groupMaps.get(g) : undefined; });
  const feed: TimelineEntry[] = merged.map(({ p, at: due }, i) => {
    // Every log — story, pool, noise, ITSM, inject support — labelled for the session's products.
    const ev = applyStack(sessionEvs[i], companyId, stack);
    const scrub = ev.description && ev.source !== "ueba";
    return {
      due_offset_ms: due,
      channel: p.held ? "bonus" as const : "feed" as const,
      // stamp a stable per-feed id so duplicate pool ids can't collide in the room
      body: {
        ...ev,
        ...(scrub ? { description: scrubClockPhrases(ev.description!) } : {}),
        id: `${ev.id ?? "ev"}__${i}`,
        expected_verdict: p.verdict,
        incident_id: p.incident,
        supports_inject: p.supports,
        feed_origin: p.origin,
        ...(p.attack ? { attack_name: p.attack } : {}),
        ...(p.autoContained ? { auto_contained: true } : {}),
        ...(p.held ? { bonus_attack: true } : {}),
      },
    };
  });

  // Answer key OFF the wire (audit S4/A1): the promoted payload every player
  // receives is the PUBLIC body only; ground truth goes to the staff-only
  // session_injects.expected_action column and is joined back server-side for
  // the after-action report. The same tier is stamped on EVERY log, and ids are
  // opaque and seed-stable.
  const tier = difficulty === "easy" ? "foundation" : difficulty === "hard" ? "advanced" : "core";
  // What this build drew, for the organization's memory (staff-only; never on a public body).
  record.stories = [story1, story2, story3, story4].filter((x): x is Story => !!x).map(x => x.id);
  opts.onVariety?.(record);
  const all = [...feed, ...msel];
  const out = all
    .map((entry, i) => toPublicEntry(entry, i, seed, tier, companyId, clocks[i]))
    .sort((a, b) => a.due_offset_ms - b.due_offset_ms);
  // A named organization (the instructor's own): its people, domain and brand everywhere.
  return tenant ? applyTenant(out, companyId, tenant, seed) : out;
}

// ── What the player sees: the same shape for an attack row and a noise row ──────
// Expert review P0-1/P0-2: 92% of high/critical rows were attacks and attack rows read ~2.3×
// longer, as narrative — the answer was in the badge and the prose. A raw telemetry row now
// carries the level its product logs it at (by event type) and only ALERT rows keep an alert
// severity (attack alerts and false-positive alerts alike); every row's text is the same
// field-built sentence. The authored line and severity go to the answer key for the debrief.
const ALERT_EVENT = /alert|detection|quarantine|finding|ids_signature|ids_blocked|waf_block|threat_intel_match|ioc_hit|^dlp_|^av_|ueba_anomaly|risk_score_change|email_quarantined|email_blocked|nac_quarantine/;
const LOW_EVENT = /auth_failure|vpn_failed|ssh_failed|db_failed|mfa_denied|account_lockout|net_blocked|http_blocked|account_create|account_modify|account_delete|group_modify|role_assignment|cloud_role_change|privilege_escalation|policy_modification|service_install|scheduled_task|privileged_operation|audit_log_cleared|mfa_disabled|k8s_rbac|linux_priv_change/;
export function isAlertRow(e: { is_detection?: boolean; source?: string; event_type?: string }): boolean {
  return !!e.is_detection || ["siem", "ueba", "dlp", "av"].includes(String(e.source)) || ALERT_EVENT.test(String(e.event_type ?? ""));
}
export function productSeverity(e: { is_detection?: boolean; source?: string; event_type?: string; severity?: string }): string {
  if (isAlertRow(e)) return e.severity ?? "medium";
  return LOW_EVENT.test(String(e.event_type ?? "")) ? "low" : "informational";
}

/** Feed fields that reveal the ground truth or the attack story — never sent to players. */
export const TEAM_ANSWER_FIELDS = ["expected_verdict", "fp_explanation", "incident_id", "edr_scope", "is_baseline", "it_verify_result", "it_verify_message", "it_context", "supports_inject", "feed_origin"] as const;
/** Inject kinds that must look identical live (the real kind is the answer). A
 *  management request is not a spoiler — who answers it (the SOC Manager, with a
 *  SITREP) is part of the job — so it gets its own public kind; only the twist and
 *  the false lead stay indistinguishable. */
const PUBLIC_INJECT_KIND: Record<string, string> = { twist: "update", false_lead: "update", mgmt_pressure: "mgmt_request" };

/**
 * Every public feed body is re-timed onto ONE synthetic base (+ its due offset),
 * raw{} timestamps shifted by the same delta. Authored pools carry telltale dates
 * (benign ~May 2026, attack stories ~June 2026), so the date alone marked the attack
 * logs. Clients re-time again to the event's occurred_at for display.
 */
export const TEAM_TIME_BASE_MS = Date.parse("2026-01-01T08:00:00.000Z");

function opaqueId(seed: string, i: number, prefix: string): string {
  const a = hashSeed(`${seed}#${i}`).toString(16).padStart(8, "0");
  const b = hashSeed(`${i}#${seed}#${prefix}`).toString(16).padStart(8, "0").slice(0, 4);
  return `${prefix}${a}${b}`;
}

function strip(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null));
}

/** ATT&CK metadata a reshape leaves in a raw block: on a row no product tags, it is the technique by another name. */
const RAW_TECHNIQUE_KEYS = ["threat.technique.id", "threat.technique.subtechnique.id", "mde.AlertTitle"];

/**
 * The client renders a row's native record from this public body (no incident id, re-timed), so the
 * pid printed beside the record and in its raw block must be derived the same way.
 */
function withPublicPids(ev: Record<string, unknown>, companyId: string): Record<string, unknown> {
  const next = withCanonicalPids(ev as unknown as TelemetryEvent, companyId);
  const { pid, parent_pid } = next.process ?? {};
  if (!next.raw || pid === undefined) return next as unknown as Record<string, unknown>;
  const raw: Record<string, unknown> = { ...next.raw };
  for (const k of ["process.pid", "crowdstrike.RawProcessId"]) if (k in raw) raw[k] = typeof raw[k] === "string" ? String(pid) : pid;
  if (parent_pid !== undefined && "process.parent.pid" in raw) raw["process.parent.pid"] = typeof raw["process.parent.pid"] === "string" ? String(parent_pid) : parent_pid;
  return { ...next, raw } as unknown as Record<string, unknown>;
}

/** Endpoint facts carry a process's start time: it moves with the row, or the authored date marks an attack row. */
function mapEndpointTimes(rest: Record<string, unknown>, f: TimeMap): Record<string, unknown> {
  const t = rest._endpoint as Record<string, { startMs?: number } | undefined> | undefined;
  if (!t) return rest;
  const moved = Object.fromEntries(Object.entries(t).map(([k, v]) =>
    [k, v && typeof v === "object" && typeof v.startMs === "number" ? { ...v, startMs: f(v.startMs) } : v]));
  return { ...rest, _endpoint: moved };
}

/** A story's time map and the time its first row is shown at (toPublicEntry). */
interface StoryClock { map: TimeMap; firstMs: number }
/**
 * An alert's matched-events window. A window the author left to the emitter's default (the alert time
 * minus some minutes) can open before the story's first row once the story is squeezed: it never opens
 * before the incident's first row reaches the feed.
 */
const ALERT_WINDOW_KEY = /(?:^|\.)(?:StartTime|EndTime|startTimeUtc|endTimeUtc|firstActivityDateTime|lastActivityDateTime)$/;
function clampAlertWindow(raw: Record<string, unknown> | undefined, firstMs: number): Record<string, unknown> | undefined {
  if (!raw) return raw;
  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === "string" && ALERT_WINDOW_KEY.test(k)) {
      const n = mapTimeString(v, ms => Math.max(ms, firstMs));
      if (n !== v) changed = true;
      out[k] = n;
    } else out[k] = v;
  }
  return changed ? out : raw;
}

function toPublicEntry(entry: TimelineEntry, i: number, seed: string, tier: string, companyId: string, clock?: StoryClock): TimelineEntry {
  const body = entry.body as Record<string, unknown>;
  if (entry.channel === "inject") {
    const { kind, expected_response, linked_objective, expected_decision, id, ...rest } = body;
    const k = typeof kind === "string" ? kind : "announcement";
    return {
      ...entry,
      body: { ...rest, id: opaqueId(seed, i, "m"), kind: PUBLIC_INJECT_KIND[k] ?? k },
      answer: strip({ kind: k, expected_response, linked_objective, expected_decision, original_id: id }),
    };
  }
  const {
    expected_verdict, fp_explanation, incident_id, edr_scope, is_baseline, it_verify_result, it_verify_message, it_context,
    supports_inject, feed_origin, tier: originalTier, id, bonus_attack, auto_contained, attack_name, ...rest
  } = body;
  // A held bonus row is stamped as if it followed the planned shift; the client re-bases every
  // log onto its release time (occurred_at) anyway.
  const offset = entry.due_offset_ms >= BONUS_HOLD_MS ? entry.due_offset_ms - BONUS_HOLD_MS : entry.due_offset_ms;
  const newTs = new Date(TEAM_TIME_BASE_MS + offset).toISOString();
  const oldMs = typeof rest.ts === "string" ? Date.parse(rest.ts) : NaN;
  // A story row: every time inside it through the story's one map (an alert's window, a ticket's
  // opened_at, a clock in a work note land on the rows they name). Any other row: its own delta.
  const newMs = Date.parse(newTs);
  const f: TimeMap | undefined = !Number.isFinite(oldMs) ? undefined
    : clock ? (ms => (ms === oldMs ? newMs : clock.map(ms))) : (ms => ms + newMs - oldMs);
  const withEndpoint = f ? mapEndpointTimes(rest, f) : rest;
  const moved = (clock ? withMappedTime(withEndpoint as { ts?: string; raw?: Record<string, unknown> }, newTs, clock.map)
    : withRebasedTime(withEndpoint as { ts?: string; raw?: Record<string, unknown> }, newTs)) as Record<string, unknown>;
  const windowed = clock && moved.raw ? { ...moved, raw: clampAlertWindow(moved.raw as Record<string, unknown>, clock.firstMs) } : moved;
  const retimed = withPublicPids(windowed, companyId);
  // QA H1: a technique on a raw log, and empty structured fields, marked attack rows apart
  // from noise for anyone reading the payload — the technique moves to the answer key
  // (the report joins it back), empty structures are dropped.
  const tagged = mitreVisible(retimed as { source?: string; event_type?: string; is_detection?: boolean });
  const { mitre_technique, mitre_tactic, ...untagged } = retimed;
  // is_detection:false exists on authored story rows only, and the raw technique on attack rows only:
  // either one marks a row for anyone reading the payload.
  const rawBlock = retimed.raw as Record<string, unknown> | undefined;
  const rawTechnique = !tagged && rawBlock ? RAW_TECHNIQUE_KEYS.slice(0, 2).map(k => rawBlock[k]).find(Boolean) : undefined;
  const scrubbed = tagged || !rawBlock ? rawBlock : Object.fromEntries(Object.entries(rawBlock).filter(([k]) => !RAW_TECHNIQUE_KEYS.includes(k)));
  const shown0 = Object.fromEntries(Object.entries({ ...(tagged ? retimed : untagged), ...(rawBlock ? { raw: scrubbed } : {}) }).filter(([k, v]) =>
    v !== undefined && v !== null && !(k === "is_detection" && (v as unknown) === false) && !(typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0)));
  const asEvent = { ...retimed, mitre_technique: undefined } as unknown as TelemetryEvent;
  const factual = describeEvent(asEvent, { preferFields: true, fieldsOnly: true });
  // Owner rule (2026-10-06, from the team-training review): the severity a player sees — and so the
  // rule level (3-15) derived from it — must match what the event really is. Collapsing raw attack
  // rows to the product's informational/low level put events that demanded escalation at level 1.
  // The authored severity is shown; productSeverity is only the fallback for rows authored without
  // one. Attack and benign/FP rows of the same severity still render identically (same level band,
  // same field-built description), so the level is evidence to weigh, not the answer.
  const shownSeverity = typeof retimed.severity === "string" && retimed.severity
    ? retimed.severity
    : productSeverity(retimed as { source?: string; event_type?: string; severity?: string; is_detection?: boolean });
  // "Verify with IT" is offered on the same logs as on the dashboard (admin changes, remote-access
  // tools, logs with an authored IT answer); the answer itself stays on the server (it-verify route).
  const itCheck = itVerifyApplies(body as unknown as TelemetryEvent);
  const publicBody = { ...shown0, description: factual, severity: shownSeverity, ...(itCheck ? { it_check: true } : {}) };
  return {
    ...entry,
    body: { ...publicBody, id: opaqueId(seed, i, "e"), tier },
    answer: strip({
      // contract 1: an explicit verdict on every feed log — never missing
      expected_verdict: expected_verdict ?? "benign",
      fp_explanation, incident_id, supports_inject, origin: feed_origin, edr_scope, is_baseline,
      it_verify_result, it_verify_message, it_context, original_id: id, original_tier: originalTier, bonus: bonus_attack, attack_name,
      authored_description: retimed.description, authored_severity: retimed.severity, auto_contained,
      ...(tagged ? {} : { mitre_technique: mitre_technique ?? rawTechnique, mitre_tactic }),
    }),
  };
}
