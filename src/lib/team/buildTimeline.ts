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
 * interleaving/cadence/MSEL telemetry is seeded (mulberry32), but the attack-story
 * CHOICE is random (pickStoryForCompany), so two builds with the same seed may
 * pick different stories — unless staff chose a storyline (scenario_id), which
 * then always leads as the primary incident.
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
import { pickStoryForCompany, instantiateStory, storiesForCompany, storiesForTier, rehomeEvents, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { DEFAULT_ENV, envAllowsStory, envHasPlatforms, platformsOfEvent, type TeamEnv } from "./environment";
import { legacyLoad, type TeamLoad } from "./load";
import { COMPANY_PROFILES, COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";
import { applyTenant, type Tenant } from "./tenant";
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { describeEvent } from "@/lib/sim/describeEvent";
import { fpAlerts } from "./fpAlerts";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { applyStack, fitsStack, storyFitsOrg, storyFitsStack, storyHonoursLocks } from "@/lib/logs/native";
import { PRODUCT_LABEL, type Stack } from "@/lib/logs/native/stack";

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
const pick = <T,>(arr: T[], rnd: () => number): T => arr[Math.floor(rnd() * arr.length) % arr.length];

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

const C2_POOL = [
  { domain: "cdn-edge-metrics.com", ip: "45.61.137.212" },
  { domain: "update-telemetry-cloud.net", ip: "194.87.31.14" },
  { domain: "static-content-sync.io", ip: "91.215.85.140" },
  { domain: "api-cloudsync-status.com", ip: "185.225.74.59" },
  { domain: "img-cdn-delivery.net", ip: "193.42.33.18" },
];
const SAAS_POOL = [
  { domain: "api2.amplitude.com", ip: "54.187.102.33", app: "Amplitude", appId: "amplitude" },
  { domain: "api-eu.mixpanel.com", ip: "35.186.241.51", app: "Mixpanel", appId: "mixpanel" },
  { domain: "heapanalytics.com", ip: "34.120.183.62", app: "Heap", appId: "heap-analytics" },
];

type FwFlavour = "pan" | "forti" | "checkpoint" | "cisco";
function fwFlavour(firewall: string): { flavour: FwFlavour; vendor: string } {
  const f = firewall.toLowerCase();
  if (f.includes("forti")) return { flavour: "forti", vendor: "Fortinet FortiGate" };
  if (f.includes("check point") || f.includes("checkpoint")) return { flavour: "checkpoint", vendor: "Check Point NGFW" };
  if (f.includes("cisco")) return { flavour: "cisco", vendor: "Cisco Firepower" };
  return { flavour: "pan", vendor: "Palo Alto Networks PAN-OS" };
}

interface FwConn { srcIp: string; dstIp: string; domain: string; url: string; category: string; app: string; bytesOut: number; bytesIn: number; sessions?: number }
function firewallRaw(flavour: FwFlavour, c: FwConn): Record<string, unknown> {
  if (flavour === "forti") return {
    "data.type": "utm", "data.subtype": "webfilter", "data.level": "notice", "data.action": "passthrough",
    "data.srcip": c.srcIp, "data.dstip": c.dstIp, "data.dstport": "443", "data.service": "HTTPS",
    "data.hostname": c.domain, "data.url": c.url, "data.catdesc": c.category, "data.app": c.app,
    "data.sentbyte": String(c.bytesOut), "data.rcvdbyte": String(c.bytesIn),
    ...(c.sessions ? { "data.countweb": String(c.sessions) } : {}),
    "firewall.action": "allow", "action_result": "allowed",
  };
  if (flavour === "checkpoint") return {
    "action": "Accept", "layer_name": "Application & URL Filtering", "src": c.srcIp, "dst": c.dstIp,
    "service": "443", "service_id": "https", "proto": "6", "resource": c.url, "app_category": c.category,
    "appi_name": c.app, "bytes_out": String(c.bytesOut), "bytes_in": String(c.bytesIn),
    "ProductName": "URL Filtering", "action_result": "allowed",
  };
  if (flavour === "cisco") return {
    "cisco.ftd.action": "Allow", "cisco.ftd.url": c.url, "cisco.ftd.url_category": c.category,
    "cisco.ftd.application": c.app, "source.ip": c.srcIp, "destination.ip": c.dstIp, "destination.port": "443",
    "network.bytes_out": String(c.bytesOut), "network.bytes_in": String(c.bytesIn), "action_result": "allowed",
  };
  return {
    "url.domain": c.domain, "url.full": c.url, "pan.url.category": c.category, "pan.app": c.app,
    "pan.action": "allow", "pan.rule": "ALLOW-WEB-OUT", "source.ip": c.srcIp, "destination.ip": c.dstIp,
    "destination.port": "443", "pan.bytes_sent": String(c.bytesOut), "pan.bytes_received": String(c.bytesIn),
    ...(c.sessions ? { "pan.repeatcnt": String(c.sessions) } : {}),
    "event.action": "allow", "action_result": "allowed",
  };
}

interface ProcCtx { path: string; cmdline: string; parent: string; account?: string }
function edrConnRaw(edrVendor: string, host: string, proc: string, pid: number, localIp: string, dstIp: string, domain: string, ctx?: ProcCtx): Record<string, unknown> {
  const v = edrVendor.toLowerCase();
  // The process context is the evidence on a LOLBin beacon: rundll32.exe itself is a
  // signed Microsoft binary (its hash looks up clean) — the DLL on its command line,
  // launched from a user-writable folder, is what's malicious.
  const neutral = {
    "process.name": proc, "process.pid": String(pid), "destination.ip": dstIp, "destination.port": "443", "destination.domain": domain, "source.ip": localIp,
    ...(ctx ? { "process.executable": ctx.path, "process.command_line": ctx.cmdline, "process.parent.name": ctx.parent } : {}),
  };
  if (v.includes("crowdstrike") || v.includes("falcon")) return { "crowdstrike.event_simpleName": "NetworkConnectIP4", "crowdstrike.ComputerName": host, "crowdstrike.RemoteAddressIP4": dstIp, "crowdstrike.RemotePort": "443", "crowdstrike.LocalAddressIP4": localIp, ...(ctx ? { "crowdstrike.CommandLine": ctx.cmdline, "crowdstrike.ParentBaseFileName": ctx.parent } : {}), ...neutral };
  if (v.includes("sentinelone")) return { "s1.eventType": "IP Connect", "s1.agent.computerName": host, ...(ctx ? { "s1.src.process.cmdline": ctx.cmdline, "s1.src.process.parent.name": ctx.parent } : {}), ...neutral };
  if (v.includes("sophos")) return { "sophos.event_type": "Network", ...neutral };
  return {
    "ActionType": "ConnectionSuccess", "DeviceName": host.toLowerCase(), "RemoteIP": dstIp, "RemotePort": "443", "RemoteUrl": domain, "LocalIP": localIp,
    "InitiatingProcessFileName": proc, "InitiatingProcessId": String(pid),
    ...(ctx ? {
      "InitiatingProcessFolderPath": ctx.path.replace(/\\[^\\]+$/, ""), "InitiatingProcessCommandLine": ctx.cmdline,
      "InitiatingProcessParentFileName": ctx.parent, ...(ctx.account ? { "InitiatingProcessAccountName": ctx.account } : {}),
    } : {}),
    ...neutral,
  };
}

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
    return serviceNowRecord({
      companyId, id: `itsm_${ev.id}`, ts: ev.ts, table: "sc_req_item", number: ref,
      state: "Approved", shortDescription: summary, severity: "informational",
      extra: { "servicenow.approval": "Approved", ...(ev.user_email ? { "servicenow.requested_for": ev.user_email } : {}) },
      description: `ServiceNow request ${ref} (approved): ${summary}`,
    } as Parameters<typeof serviceNowRecord>[0]);
  }
  // A ticket format the IT message uses (CHG / INC / RITM …), else any approval
  // reference it or the explanation cites (e.g. an access request AR-QB-0302).
  const number = ev.it_verify_message.match(TICKET_RE)?.[1] ?? approvalRefOf(ev.it_verify_message) ?? approvalRefOf(ev.fp_explanation);
  if (!number) return null;
  const table = /^INC/.test(number) ? "incident" : /^RITM|^REQ|^ONB/.test(number) ? "sc_req_item" : "change_request";
  const summary = (ev.description ?? "").replace(/\s+—.*$/, "");
  const rec = serviceNowRecord({
    companyId, id: `itsm_${ev.id}`, ts: ev.ts, table, number,
    state: table === "incident" ? "Resolved" : "Implement", shortDescription: summary, severity: "informational",
    extra: { "servicenow.approval": "Approved", ...(ev.user_email ? { "servicenow.requested_for": ev.user_email } : {}) },
    description: `ServiceNow ${table === "incident" ? "incident" : table === "sc_req_item" ? "request" : "change"} ${number} (approved): ${summary}`,
  } as Parameters<typeof serviceNowRecord>[0]);
  return rec;
}

// ── The builder ──────────────────────────────────────────────────────────────

interface Placed { ev: TelemetryEvent; origin: FeedOrigin; verdict: TeamVerdict; incident?: string; supports?: string; held?: boolean; autoContained?: boolean }

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
  return teamStoryPool(companyId, difficulty, env, stack).find(s => s.id === storyId) ?? null;
}

/**
 * The stories a session can draw. A Live-SOC company: the ones that fit its architecture
 * (storiesForCompany). A named organization: every story of the difficulty's tier that its
 * environment can carry — the platforms the instructor said it runs, and its industry —
 * whichever demo company it was written for (instantiateStory re-homes it). Hard broadens
 * to core when fewer than 8 advanced stories fit, as the dashboard does.
 */
export function teamStoryPool(companyId: string, difficulty: "easy" | "medium" | "hard", env: TeamEnv | null, stack: Stack = {}): AttackStory[] {
  if (!env) return storiesForCompany(companyId, difficulty);
  const inEnv = (broaden: boolean) => storiesForTier(difficulty, broaden).filter(s => envAllowsStory(env, s));
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
function orgRunsSource(e: TelemetryEvent, env: TeamEnv, stack: Stack): boolean {
  const src = String(e.source);
  if (BASELINE_SOURCES.has(src)) return true;
  switch (src) {
    case "proxy": return stack.proxy !== undefined;
    case "gws": return stack.collab === "google_workspace";
    case "okta": case "mfa": return stack.idp === "okta";
    case "iam": return env.platforms.includes("cyberark");
    case "cloudtrail": return env.platforms.includes("aws");
    case "k8s_audit": return env.platforms.includes("k8s");
    case "linux_audit": return env.platforms.includes("linux");
    case "vcs": return env.platforms.includes("github");
    case "virtualization": return env.platforms.includes("vmware");
    // Specialised tools with no selector yet (WAF, DAM, UEBA, NAC, DLP): not shown unless the org opted in — keep them out of a named org's noise.
    case "waf": case "db_monitor": case "ueba": case "nac": case "dlp": case "infra_monitor": return false;
    default: return true;
  }
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
    basePool = [...basePool.filter(e => envHasPlatforms(env, [e]) && orgRunsSource(e, env, stack)), ...platformNoise(companyId, env, own).filter(e => fitsStack(e, companyId, stack))];
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
  return story => {
    try {
      const evs = instantiateStory(story, companyPool, edr, companyId).events ?? [];
      return evs.length > 0 && fits(evs);
    } catch { return false; }
  };
}

/**
 * `load` sizes the shift to the team in the room (src/lib/team/load.ts): log pace
 * from the Tier-1 count, attack count from the team size. Omitted → the fixed,
 * difficulty-only load of before (existing seeds replay exactly).
 */
export function buildTeamTimeline(companyId: string, difficulty: "easy" | "medium" | "hard", seed: string, storyId?: string | null | (string | null)[], load: TeamLoad = legacyLoad(difficulty), stack: Stack = {}, tenant: Tenant | null = null, envIn: TeamEnv | null = null, opts: { bonus?: boolean } = {}): TimelineEntry[] {
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
  interface Story { id: string; incident: string; events: TelemetryEvent[] }
  // The instructor's attack plan: one slot per concurrent attack — a chosen storyline, or
  // null for a random pick (an older session's single scenario_id is slot 1).
  const slotIds = Array.isArray(storyId) ? storyId : [storyId ?? null];
  const forcedAt = (i: number) => resolveTeamStory(companyId, difficulty, slotIds[i] ?? null, env, stack);
  const pinnedIdsAll = slotIds.filter((x): x is string => !!x);
  const storyFits = teamStoryFilter(companyId, stack, env);
  const envPool = env ? teamStoryPool(companyId, difficulty, env, stack) : null;
  const pickStory = (accept: (s: AttackStory) => boolean): AttackStory => {
    if (!envPool) return pickStoryForCompany(companyId, difficulty, accept);
    const fit = envPool.filter(accept);
    const cands = fit.length ? fit : envPool;
    return cands[Math.floor(Math.random() * cands.length)];
  };
  // Concurrent incidents hit different people (a team never works two attacks on one victim).
  const victimOf = (evs: TelemetryEvent[]) => evs.find(e => e.user_email && isMalicious(classifyStoryEvent(e)))?.user_email;
  const takenVictims = new Set<string>();
  // A named organization's incidents are never named after the demo company a story was written for.
  const DEMO_COMPANY = /nexacorp|rocketstack|medcore|globallogis|quantumbank/gi;
  const buildStory = (avoid0: (string | undefined)[] = [], forced?: AttackStory | null, keepOff?: { hosts: Set<string>; users: Set<string> }): Story | null => {
    const avoid = [...avoid0];
    const maxAttempts = stacked || env ? 20 : 6;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Chosen products: only stories they can show whole. The company's own: none
        // written about another vendor's artifacts (PRODUCT_LOCKS). Same predicate the
        // builder / create / start routes use for a pinned storyline (teamStoryFilter).
        const story = forced ?? pickStory(s => !avoid.includes(s.id) && storyFits(s));
        if (!forced && avoid.includes(story.id)) continue;   // server-side there is no anti-repeat memory
        const events0 = instantiateStory(story, companyPool, edr, companyId).events ?? [];
        if (events0.length === 0) return null;
        if ((stacked || env) && !forced && !sessionFit(companyId, stack, env)(events0)) continue;
        const victim = victimOf(events0);
        // The bonus lands on new ground (expert review P0-4): no host or person the planned attacks touched.
        if (keepOff && !forced && attempt < maxAttempts - 1
          && events0.some(e => (e.hostname && keepOff.hosts.has(e.hostname)) || (e.user_email && keepOff.users.has(e.user_email)))) { avoid.push(story.id); continue; }
        // A random pick tries another story; a chosen one is re-instantiated onto another victim.
        if (victim && takenVictims.has(victim) && attempt < maxAttempts - 1) { if (!forced) avoid.push(story.id); continue; }
        if (victim) takenVictims.add(victim);
        const events = events0.map(e => applyStack(e, companyId, stack));
        const incident0 = events.find(e => e.incident_id)?.incident_id ?? `story:${story.id}`;
        const incident = env ? incident0.replace(DEMO_COMPANY, "org") : incident0;
        return { id: story.id, incident, events };
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
  const storyPlaced = (s: Story | null): Placed[] => (s?.events ?? []).map(ev => ({ ev, origin: "story" as const, verdict: classifyStoryEvent(ev), incident: s!.incident }));
  const distinct = (s: Story | null, n: number, others: (Story | null)[]): Story | null =>
    s && others.some(o => o?.incident === s.incident) ? { ...s, incident: `${s.incident}#${n}` } : s;
  const attack1 = storyPlaced(story1);
  const attack2 = storyPlaced(distinct(story2, 2, [story1]));
  const attack3 = storyPlaced(distinct(story3, 3, [story1, story2]));
  // The bonus attack (Tal, 2026-10-03): one more random story, another victim, held back until
  // the team has caught every planned attack — then released into the live feed.
  const planned = [story1, story2, story3].flatMap(st => st?.events ?? []);
  const keepOff = { hosts: new Set(planned.map(e => e.hostname).filter((h): h is string => !!h)), users: new Set(planned.map(e => e.user_email).filter((u): u is string => !!u)) };
  const story4 = opts.bonus ? buildStory([...pinnedIdsAll, story1?.id, story2?.id, story3?.id], null, keepOff) : null;
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
  const poolAttacks: Placed[][] = chosenGroups.map(key => { const g = groups.get(key) ?? []; const lone = g.length === 1 && isBlockedAttempt(g[0]);
    return g.map(ev => ({ ev, origin: "pool_attack" as const, verdict: classifyPoolEvent(ev), incident: key, autoContained: lone })); });
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
  // alert is not an answer — each provable from its approved ticket in the feed. They count toward
  // the shift's row budget, so the noise sample shrinks by their number and the shift length holds.
  const attackAlerts = [...attack1, ...attack2, ...attack3].filter(p => isMalicious(p.verdict) && isAlertRow(p.ev)).length;
  const fpRows = fpAlerts(assets, companyId, Math.max(2, Math.min(6, attackAlerts + (rnd() < 0.5 ? 1 : 0))), rnd, new Date(TEAM_TIME_BASE_MS).toISOString());
  // Keep the shift at its intended length: the storylines now carry their initial-access and
  // first-alert rows, so the real attack-row count runs over load.ts's estimate (≈10/story, 2/pool).
  // Trim the noise by that overflow and by the FP alerts, so total rows ≈ the planned budget.
  const attackRowsReal = attack1.length + attack2.length + attack3.length + poolAttacks.reduce((n, g) => n + g.length, 0);
  const attackRowsEst = load.stories * 10 + load.poolAttacks * 2;
  const benignN = Math.max(0, load.noiseCount - fpRows.length - Math.max(0, attackRowsReal - attackRowsEst));
  const noise: Placed[] = sampleN(noiseCandidates, benignN, rnd).map(ev => ({ ev, origin: "noise" as const, verdict: classifyPoolEvent(ev) }));
  for (const ev of fpRows) noise.splice(Math.floor(noise.length * (0.12 + rnd() * 0.84)), 0, { ev, origin: "noise", verdict: "fp" });

  const storyCount = attack1.length + attack2.length + attack3.length;
  const poolCount = poolAttacks.reduce((n, g) => n + g.length, 0);
  const total = noise.length + storyCount + poolCount;
  if (total === 0) return [];

  // ── Placement ─────────────────────────────────────────────────────────────────
  // A warm-up of ordinary traffic first, then each story clusters into its own band so it
  // reads as an unfolding attack. The attacks start at staggered, seed-varied points (Tal,
  // 2026-10-03: not all at once, different timing every session) and in a seeded order — the
  // primary incident is not always the first to surface.
  const posToAttack = new Map<number, Placed>();
  const place = (evs: Placed[], startFrac: number, endFrac: number) => {
    if (evs.length === 0) return;
    const start = Math.floor(total * startFrac);
    const end = Math.min(total - 1, Math.floor(total * endFrac));
    const denom = Math.max(1, evs.length - 1);
    for (let i = 0; i < evs.length; i++) {
      let pos = Math.min(end, start + Math.round((i * (end - start)) / denom));
      while (posToAttack.has(pos) && pos < total - 1) pos++;
      while (posToAttack.has(pos) && pos > 0) pos--;
      posToAttack.set(pos, evs[i]);
    }
  };
  const warmup = 0.10 + rnd() * 0.08;
  const bands = [attack1, attack2, attack3].filter(a => a.length > 0);
  for (let i = bands.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [bands[i], bands[j]] = [bands[j], bands[i]]; }
  const lastStart = bands.length > 1 ? 0.58 : warmup + 0.22;
  bands.forEach((evs, k) => {
    const base = bands.length > 1 ? warmup + ((lastStart - warmup) * k) / (bands.length - 1) : warmup;
    const startFrac = Math.max(warmup, base + (rnd() - 0.5) * 0.08 + (bands.length > 1 ? 0 : rnd() * 0.22));
    const len = 0.22 + rnd() * 0.14;
    place(evs, startFrac, Math.min(0.96, startFrac + len));
  });
  // Standalone pool incidents land at seeded points after the warm-up (a multi-event
  // one spans a few positions).
  for (const g of poolAttacks) {
    const startFrac = warmup + rnd() * (0.92 - warmup);
    place(g, startFrac, Math.min(0.97, startFrac + 0.02 * g.length));
  }

  const ordered: Placed[] = [];
  let bi = 0;
  for (let pos = 0; pos < total; pos++) {
    const atk = posToAttack.get(pos);
    if (atk) ordered.push(atk);
    else if (bi < noise.length) ordered.push(noise[bi++]);
  }
  while (bi < noise.length) ordered.push(noise[bi++]);

  // Approved-ticket context: an ITSM record lands a few logs before the change it approves.
  // Collect first, splice after (highest position first): splicing while walking the
  // array shifted neighbours and skipped the log just before each confirmed change.
  const itsmInserts: { at: number; rec: TelemetryEvent }[] = [];
  for (let i = 0; i < ordered.length; i++) {
    const rec = itsmRecordFor(ordered[i].ev, companyId);
    if (rec) itsmInserts.push({ at: Math.max(0, i - 1 - Math.floor(rnd() * 3)), rec });
  }
  for (const { at, rec } of itsmInserts.sort((a, b) => b.at - a.at)) ordered.splice(at, 0, { ev: rec, origin: "itsm", verdict: "benign" });

  // Cadence from the team's load (load.ts): base gap + uniform jitter.
  let t = 2000;
  const timed: { p: Placed; at: number }[] = ordered.map(p => {
    const entry = { p, at: t };
    t += load.baseGapMs + Math.floor(rnd() * load.jitterMs);
    return entry;
  });
  const span = timed.length ? timed[timed.length - 1].at : 0;

  // ── MSEL — scripted injects timed against the shift ───────────────────────────
  // Each inject is EVALUABLE (expected_response + linked_objective). Skipped on easy.
  // Injects are placed in the window that OPENS at the first attack log and runs to the end of the
  // shift — a "CISO wants a status on the suspicious activity" request can't fire before any attack
  // exists (diagnostic P1). `at(f)` interpolates f across [firstAttack, span].
  const mselOn = difficulty !== "easy" && span > 0;
  const firstAttackAt = Math.min(span, ...timed.filter(x => isMalicious(x.p.verdict)).map(x => x.at));
  const mselStart = Number.isFinite(firstAttackAt) ? Math.min(firstAttackAt + 30000, span) : 0;
  const at = (f: number) => Math.floor(mselStart + (span - mselStart) * f);
  const msel: TimelineEntry[] = !mselOn ? [] : [
    { due_offset_ms: at(0.30), channel: "inject", body: { id: "msel_1", kind: "mgmt_pressure", text: "CISO wants a status update on the suspicious activity within 15 minutes — is this contained, or spreading?", expected_response: "SOC Manager sends a SITREP: current status, scope so far, and whether it's contained or spreading.", linked_objective: "coordination · SITREP cadence" } },
    { due_offset_ms: at(0.45), channel: "inject", body: { id: "msel_false_lead", kind: "false_lead", text: "Marketing's manager messages the SOC: their newly-approved SaaS analytics tool 'looks like data exfil' in the firewall logs — large outbound transfers to an unfamiliar cloud domain. Is this a real incident?", expected_response: "Recognise it as a sanctioned/benign tool: verify it's on the approved list, confirm the destination is the vendor's, and do NOT over-escalate. A decoy — discrimination, not detection.", linked_objective: "accuracy · discrimination (reject false leads)" } },
    { due_offset_ms: at(0.55), channel: "inject", body: { id: "msel_2", kind: "ticket", text: "A user in Finance says someone from 'IT support' phoned asking them to read back an MFA code to 'verify their account'. How should this be handled?", expected_response: "Tier-1 answers the help-desk ticket: never read back an MFA code, verify the caller through a known channel, and report it as a social-engineering attempt.", expected_decision: "rejected", linked_objective: "accuracy · help-desk handling" } },
    { due_offset_ms: at(0.68), channel: "inject", body: { id: "msel_twist", kind: "twist", text: "EDR update: a host you already worked is now beaconing to a NEW C2 domain — the picture just changed. Re-scope the incident and confirm your containment still holds.", expected_response: "Adapt: re-open/re-scope the case (set a new scope, or re-escalate) rather than treating it as closed — the incident evolved.", linked_objective: "adaptability · re-scope on new evidence" } },
    { due_offset_ms: at(0.62), channel: "inject", body: { id: "msel_3", kind: "mgmt_pressure", text: "Legal is asking whether this is a reportable/notifiable incident — they need your read on scope and data exposure.", expected_response: "SOC Manager sends a SITREP addressing scope and data exposure so Legal can judge notifiability.", linked_objective: "coordination · scope communication" } },
    { due_offset_ms: at(0.78), channel: "inject", body: { id: "msel_4", kind: "announcement", text: "Reminder: log every containment decision with its rationale — this incident will be reviewed after the shift.", expected_response: "Informational — no direct response required; decisions should carry a logged rationale.", linked_objective: "—" } },
    { due_offset_ms: at(0.90), channel: "inject", body: { id: "msel_5", kind: "mgmt_pressure", text: "Exec team wants a one-line bottom line for the leadership channel: what happened, what's the impact, what are we doing about it?", expected_response: "SOC Manager sends a SITREP: what happened, the impact, and the current action.", linked_objective: "coordination · SITREP cadence" } },
  ];

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

    // Twist: a host from the running (primary) attack story beacons to a NEW C2 domain.
    const twistAt = at(0.68);
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
    const ipDraw = mrnd(), pidDraw = mrnd();   // drawn unconditionally → the stream stays seed-only
    const hostIp = hostEv?.ev.src_ip ?? `${subnet}.${60 + Math.floor(ipDraw * 120)}`;
    const hostUser = twistStory.find(p => p.ev.hostname === host && p.ev.user_email)?.ev.user_email ?? (host === victimDevice ? victim : undefined);
    const procEv = [...twistStory].reverse().find(p => p.ev.hostname === host && p.ev.process?.name && isMalicious(p.verdict));
    const proc = procEv?.ev.process?.name ?? "rundll32.exe";
    const pid = procEv?.ev.process?.pid ?? 5000 + Math.floor(pidDraw * 3000);
    const c2 = pick(C2_POOL, mrnd);
    const incident = twistStory[0]?.incident;
    // The beacon's process context (its own seed stream — the draws above stay as they were).
    const dllName = `${["msupd", "wincfg", "cache", "svcmgr"][hashSeed(`${seed}:twist-dll`) % 4]}${(hashSeed(`${seed}:twist-dll#`) % 900) + 100}.dll`;
    const userDir = hostUser ? hostUser.split("@")[0] : "Public";
    const procCtx: ProcCtx = proc.toLowerCase() === "rundll32.exe"
      ? { path: "C:\\Windows\\System32\\rundll32.exe", cmdline: `"C:\\Windows\\System32\\rundll32.exe" C:\\Users\\${userDir}\\AppData\\Local\\Temp\\${dllName},DllRegisterServer`, parent: "explorer.exe", account: hostUser?.split("@")[0] }
      : { path: procEv?.ev.process?.path ?? `C:\\Users\\${userDir}\\AppData\\Local\\Temp\\${proc}`, cmdline: procEv?.ev.process?.cmdline ?? proc, parent: procEv?.ev.process?.parent_name ?? "explorer.exe", account: hostUser?.split("@")[0] };
    // The inject's wording must match where the twist actually landed.
    const twistInject = msel.find(e => (e.body as { id?: string }).id === "msel_twist");
    if (twistInject && !seenHost) {
      const who = victim ? victim.split("@")[0] : null;
      (twistInject.body as { text: string }).text = `EDR update: ${host}${who ? ` — ${who}'s own device —` : ""} has started beaconing to a NEW C2 domain. The compromise may have reached the endpoint: re-scope the incident to include this host and confirm your containment still holds.`;
    }
    // Cause before effect (expert review P0-4): the twist fires only after every log the story
    // put on that host (or, for a host-less story, the whole story) has reached the feed — a
    // NEW beacon never appears before the payload it comes from. The inject moves with it.
    const atOf = new Map<Placed, number>(timed.map(x => [x.p, x.at]));
    const onHost = twistStory.filter(p => p.ev.hostname === host);
    const doneAt = Math.max(0, ...(onHost.length ? onHost : twistStory).map(p => atOf.get(p) ?? 0));
    const twistFire = Math.min(Math.floor(span * 0.95), Math.max(twistAt, doneAt + 60000));
    if (twistInject) twistInject.due_offset_ms = twistFire;
    const tw = (k: number) => twistFire + 20000 + k * 45000 + Math.floor(mrnd() * 8000);
    const twistEvents: TelemetryEvent[] = [
      useSysmon ? {
        id: "msel_twist_dns", ts: baseTs, source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query", severity: "low",
        hostname: host, user_email: hostUser, src_ip: hostIp, dns: { query: c2.domain, query_type: "A", response: c2.ip, rcode: "NOERROR" },
        description: `${host} looked up ${c2.domain}`,
        raw: { "event.code": "22", "winlog.provider_name": "Microsoft-Windows-Sysmon", "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
          "winlog.computer_name": host, "winlog.event_data.QueryName": c2.domain, "winlog.event_data.QueryStatus": "0",
          "winlog.event_data.QueryResults": `::ffff:${c2.ip};`, "winlog.event_data.Image": `C:\\Windows\\System32\\${proc}` },
      } : {
        id: "msel_twist_dns", ts: baseTs, source: "dns", vendor: "Infoblox DNS", event_type: "dns_query", severity: "low",
        hostname: host, src_ip: hostIp, network: { domain: c2.domain }, dns: { query: c2.domain, query_type: "A", response: c2.ip, rcode: "NOERROR" },
        description: `${host} looked up ${c2.domain}`,
        raw: { "dns.question.name": c2.domain, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.answers.data": c2.ip, "dns.answers.ttl": "300", "client.ip": hostIp },
      },
      {
        id: "msel_twist_fw", ts: baseTs, source: "firewall", vendor: fw.vendor, event_type: "net_connection", severity: "medium",
        hostname: host, src_ip: hostIp, dst_ip: c2.ip, dst_port: 443, protocol: "tcp",
        network: { url: `https://${c2.domain}/api/v2/status`, domain: c2.domain, method: "POST", bytes_out: 2140, bytes_in: 612 },
        description: `Outbound HTTPS from ${host} to ${c2.domain}`,
        raw: firewallRaw(fw.flavour, { srcIp: hostIp, dstIp: c2.ip, domain: c2.domain, url: `https://${c2.domain}/api/v2/status`, category: "newly-registered-domain", app: "ssl", bytesOut: 2140, bytesIn: 612, sessions: 14 }),
      },
      {
        id: "msel_twist_edr", ts: baseTs, source: "edr", vendor: edr ?? "Microsoft Defender for Endpoint", event_type: "net_connection", severity: "medium",
        hostname: host, user_email: hostUser, src_ip: hostIp, dst_ip: c2.ip, dst_port: 443, protocol: "tcp",
        process: { name: proc, pid, path: procCtx.path, cmdline: procCtx.cmdline, parent_name: procCtx.parent, ...(hostUser ? { user: hostUser.split("@")[0] } : {}) },
        description: `${proc} on ${host} connected to ${c2.ip}:443`,
        raw: edrConnRaw(edr ?? "", host, proc, pid, hostIp, c2.ip, c2.domain, procCtx),
      },
    ];
    twistEvents.forEach((ev, k) => support.push({ p: { ev, origin: "inject_support", verdict: "tp", incident, supports: "msel_twist" }, at: tw(k) }));

    // False lead: the Marketing SaaS tool's large uploads really are in the firewall
    // log — to the vendor's own ingestion endpoint, behind an approved request.
    const saas = pick(SAAS_POOL, mrnd);
    const mktHosts = (assets?.hosts ?? []).filter(h => /MKT|MARKET/i.test(h));
    const wsHosts = (assets?.hosts ?? []).filter(h => h !== assets?.dc && h !== assets?.fileServer && h !== host);
    const hostDraw = mrnd();
    const mktHost = mktHosts[0] ?? (wsHosts.length ? wsHosts[Math.floor(hostDraw * wsHosts.length)] : host);
    const mktUser = assets?.roster.find(r => /market/i.test(r.title));
    const mktEmail = mktUser && assets ? `${mktUser.name}@${assets.domain}` : undefined;
    const mktIp = `${subnet}.${30 + Math.floor(mrnd() * 20)}`;
    const leadAt = at(0.45);
    const fpWhy = `Sanctioned SaaS: ${saas.app} is Marketing's newly approved analytics tool (see the approved ServiceNow request); the large batched uploads go to the vendor's own ingestion endpoint (${saas.domain}). Expected traffic — not exfiltration.`;
    const bigUp = (bytes: number): FwConn => ({ srcIp: mktIp, dstIp: saas.ip, domain: saas.domain, url: `https://${saas.domain}/batch`, category: "business-and-economy", app: saas.appId, bytesOut: bytes, bytesIn: Math.floor(bytes / 900) });
    const leadEvents: { ev: TelemetryEvent; at: number }[] = [
      {
        at: Math.max(2000, at(0.22)),
        ev: serviceNowRecord({
          companyId, id: "msel_false_lead_itsm", ts: baseTs, table: "sc_req_item", number: `RITM00${93000 + Math.floor(mrnd() * 900)}`,
          state: "Closed Complete", shortDescription: `Software request — ${saas.app} product analytics for Marketing`, severity: "informational",
          extra: { "servicenow.approval": "Approved", "servicenow.approved_by": "IT Security", "servicenow.assignment_group": "Service Desk", ...(mktEmail ? { "servicenow.requested_for": mktEmail } : {}) },
          description: `ServiceNow request approved: ${saas.app} product analytics for Marketing (vendor endpoint ${saas.domain})`,
        } as Parameters<typeof serviceNowRecord>[0]),
      },
      {
        at: leadAt - 60000 - Math.floor(mrnd() * 20000),
        ev: { id: "msel_false_lead_fw1", ts: baseTs, source: "firewall", vendor: fw.vendor, event_type: "net_connection", severity: "medium",
          hostname: mktHost, user_email: mktEmail, src_ip: mktIp, dst_ip: saas.ip, dst_port: 443, protocol: "tcp",
          network: { url: `https://${saas.domain}/batch`, domain: saas.domain, method: "POST", bytes_out: 1_874_310_144 },
          description: `Large outbound HTTPS upload from ${mktHost} to ${saas.domain}`, fp_explanation: fpWhy,
          raw: firewallRaw(fw.flavour, bigUp(1_874_310_144)) },
      },
      {
        at: leadAt + 25000 + Math.floor(mrnd() * 20000),
        ev: { id: "msel_false_lead_fw2", ts: baseTs, source: "firewall", vendor: fw.vendor, event_type: "net_connection", severity: "medium",
          hostname: mktHost, user_email: mktEmail, src_ip: mktIp, dst_ip: saas.ip, dst_port: 443, protocol: "tcp",
          network: { url: `https://${saas.domain}/batch`, domain: saas.domain, method: "POST", bytes_out: 2_311_582_720 },
          description: `Large outbound HTTPS upload from ${mktHost} to ${saas.domain}`, fp_explanation: fpWhy,
          raw: firewallRaw(fw.flavour, bigUp(2_311_582_720)) },
      },
    ];
    leadEvents.forEach(({ ev, at: a }, k) => support.push({ p: { ev, origin: "inject_support", verdict: k === 0 ? "benign" : "fp", supports: "msel_false_lead" }, at: a }));
  }

  // The held bonus story: its own pace (relative offsets), parked past any shift until released.
  const bonusGap = Math.max(4000, Math.round(load.baseGapMs * 2.5));
  const bonusTimed = bonusAttack.map((p, k) => ({ p, at: BONUS_HOLD_MS + k * bonusGap + Math.floor(rnd() * load.jitterMs) }));

  // Merge the supporting logs into the feed by time. Feed entries come first in the
  // id index space, so ids stay a pure function of (seed, position).
  const merged = [...timed, ...support, ...bonusTimed].sort((a, b) => a.at - b.at);
  // One host, one IP across the WHOLE session — stories, noise, the twist, inject support
  // logs each chose an address their own way; the analyst pivots across all of them.
  const sessionEvs = normalizeHostIps(merged.map(m => m.p.ev));
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
  const all = [...feed, ...msel];
  const out = all
    .map((entry, i) => toPublicEntry(entry, i, seed, tier))
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

// RFC 2822 dates (email Received headers) are not ISO, so withRebasedTime leaves
// them on the authored June date — shift them by the same delta as the event.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const RFC2822_RE = /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) \+0000\b/g;
function shiftRfc2822(value: unknown, deltaMs: number): unknown {
  if (typeof value === "string") {
    return value.replace(RFC2822_RE, (_m, d, mon, y, hh, mm, ss) => {
      const ms = Date.UTC(Number(y), MONTHS.indexOf(mon), Number(d), Number(hh), Number(mm), Number(ss)) + deltaMs;
      const n = new Date(ms);
      const p2 = (x: number) => String(x).padStart(2, "0");
      return `${DAYS[n.getUTCDay()]}, ${p2(n.getUTCDate())} ${MONTHS[n.getUTCMonth()]} ${n.getUTCFullYear()} ${p2(n.getUTCHours())}:${p2(n.getUTCMinutes())}:${p2(n.getUTCSeconds())} +0000`;
    });
  }
  if (Array.isArray(value)) return value.map(v => shiftRfc2822(v, deltaMs));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shiftRfc2822(v, deltaMs)]));
  return value;
}

function toPublicEntry(entry: TimelineEntry, i: number, seed: string, tier: string): TimelineEntry {
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
    supports_inject, feed_origin, tier: originalTier, id, bonus_attack, auto_contained, ...rest
  } = body;
  // A held bonus row is stamped as if it followed the planned shift; the client re-bases every
  // log onto its release time (occurred_at) anyway.
  const offset = entry.due_offset_ms >= BONUS_HOLD_MS ? entry.due_offset_ms - BONUS_HOLD_MS : entry.due_offset_ms;
  const newTs = new Date(TEAM_TIME_BASE_MS + offset).toISOString();
  const oldMs = typeof rest.ts === "string" ? Date.parse(rest.ts) : NaN;
  const withMail = Number.isFinite(oldMs) && rest.raw
    ? { ...rest, raw: shiftRfc2822(rest.raw, Date.parse(newTs) - oldMs) as Record<string, unknown> }
    : rest;
  const retimed = withRebasedTime(withMail as { ts?: string; raw?: Record<string, unknown> }, newTs) as Record<string, unknown>;
  // QA H1: a technique on a raw log, and empty structured fields, marked attack rows apart
  // from noise for anyone reading the payload — the technique moves to the answer key
  // (the report joins it back), empty structures are dropped.
  const tagged = mitreVisible(retimed as { source?: string; event_type?: string; is_detection?: boolean });
  const { mitre_technique, mitre_tactic, ...untagged } = retimed;
  const shown0 = Object.fromEntries(Object.entries(tagged ? retimed : untagged).filter(([, v]) =>
    v !== undefined && v !== null && !(typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0)));
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
      it_verify_result, it_verify_message, it_context, original_id: id, original_tier: originalTier, bonus: bonus_attack,
      authored_description: retimed.description, authored_severity: retimed.severity, auto_contained,
      ...(tagged ? {} : { mitre_technique, mitre_tactic }),
    }),
  };
}
