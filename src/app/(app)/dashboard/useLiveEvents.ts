"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { TelemetryEvent } from "@/lib/sim/types";
import { getRuleDescription, WIN_EVENT_VIEWER_DESCRIPTIONS } from "@/lib/sim/ruleDescriptions";
import {
  initWorldState, generateBenignEvent,
  pickPlaybook, startAttack, advanceAttack, attackDue,
} from "@/lib/sim/engine";
import type { WorldState, GeneratedEvent } from "@/lib/sim/engine";
import type { AttackStory } from "./attackStories";
import { appendDashboardSession } from "@/lib/storage/progress";
import { withRebasedTime } from "@/lib/sim/rebaseTime";

export interface ActiveIncident {
  id: string;
  title: string;
  severity: "critical" | "high";
  injectedAt: number;     // Date.now()
  eventIds: string[];     // IDs of the injected attack events
}

/**
 * Teaching payload for the POSITIVE "Learning Moment" debrief shown when an
 * attack completes without being reported. It is never a penalty — just "here's
 * the pattern so you catch it next time".
 */
export interface MissedIncidentDebrief {
  /** What the attack was (the incident / story title). */
  title: string;
  /** MITRE technique ID(s) the attack used. */
  techniques: string[];
  /** One-line "how you could have caught it" tell — the standout signal. */
  tell: string;
}

// ─── Display-enriched event ───────────────────────────────────────────────────

export interface LiveEvent extends TelemetryEvent {
  ruleLevel: number;                                    // 1-10 Wazuh-style
  ruleId: string;                                       // RULE_XXXX
  displayDescription: string;                           // human-readable
}

// ─── Classification helpers ───────────────────────────────────────────────────

// Wazuh-style rule IDs by MITRE technique
const RULE_ID_MAP: Record<string, string> = {
  "T1566.001": "HTS-5715",   // Phishing attachment
  "T1059.001": "HTS-5912",   // PowerShell
  "T1059.003": "HTS-5906",   // cmd.exe
  "T1071.001": "HTS-3128",   // C2 HTTPS
  "T1204.002": "HTS-5720",   // User execution of malicious file
  "T1071.004": "HTS-1002",   // DNS tunneling
  "T1027":     "HTS-1102",   // Obfuscated files
  "T1218.011": "HTS-92300",  // Rundll32 LOLBin
  "T1547.001": "HTS-61116",  // Registry Run key
  "T1003.001": "HTS-61656",  // LSASS dump
  "T1110.003": "HTS-5452",   // Password spray
  "T1078":     "HTS-5501",   // Valid accounts
  "T1567.002": "HTS-9200",   // Exfil to cloud
  "T1486":     "HTS-99201",  // Ransomware encrypt
  "T1490":     "HTS-99202",  // VSS delete
  "T1070.001": "HTS-92511",  // Clear event logs
  "T1569.002": "HTS-92511",  // PsExec service
  "T1021.001": "HTS-5712",   // RDP lateral
  "T1098.005": "HTS-99301",  // OAuth app
  "T1530":     "HTS-99302",  // Cloud storage
  "T1114.002": "HTS-99303",  // Email collection
  "T1552.001": "HTS-99100",  // Credentials in files
  "T1048.003": "HTS-5560",   // Exfil over email
  "T1052.001": "HTS-5570",   // USB exfil
};

// Wazuh-style rule IDs by source + event_type (benign baseline)
const SOURCE_EVENT_RULE: Record<string, string> = {
  "ad:auth_success":        "HTS-18101",
  "ad:auth_failure":        "HTS-18102",
  "edr:process_create":     "HTS-92400",
  "edr:scheduled_task":     "HTS-60105",
  "edr:av_detection":       "HTS-53601",
  "sysmon:process_create":  "HTS-92400",
  "sysmon:file_create":     "HTS-92402",
  "sysmon:net_connection":  "HTS-92403",
  "sysmon:registry_set":    "HTS-92404",
  "dns:dns_query":          "HTS-82001",
  "firewall:net_connection":"HTS-40101",
  "vpn:vpn_login":          "HTS-72201",
  "vpn:vpn_logout":         "HTS-72202",
  "proxy:http_request":     "HTS-31100",
  "o365:email_received":    "HTS-91501",
  "o365:email_sent":        "HTS-91502",
  "o365:sharepoint_access": "HTS-91510",
  "o365:teams_message":     "HTS-91520",
  "cloudtrail:cloud_api_call":"HTS-80200",
};


function calculateRuleLevel(event: TelemetryEvent): number {
  // L-06 — SINGLE SOURCE OF TRUTH: the displayed rule level is derived purely from
  // the event severity, identically for attack and noise. The old function boosted
  // the level from mitre_technique (which ONLY attack events carry) and from
  // process/command content, so attack events uniquely reached levels 7-10 and a 9
  // was unreachable by any noise event — filtering 7-10 and looking for a 9
  // isolated the attack without reading a single log. Tying level to severity, and
  // keeping genuine high-severity NOISE in the pool, closes that leak: an 8 or a 10
  // now appears on real incidents and benign decoys alike.
  return severityBase(event.severity ?? "informational");
}

function severityBase(sev: string): number {
  switch (sev) {
    case "critical":      return 10;
    case "high":          return 8;
    case "medium":        return 5;
    case "low":           return 3;
    case "informational": return 1;
    default:              return 1;
  }
}

// ── L-02: realistic timing (no metronome) ─────────────────────────────────────
// Real telemetry does not arrive on a fixed 60-second grid, and the events of one
// incident do not all land within seconds — each product has its own ingestion
// lag. Before this, baseline events were spaced exactly 60s apart while attack
// events burst 3-4s apart, so "sort by time and take everything off the grid"
// solved any session without reading a log.

// Deterministic irregular cumulative offset (ms) into the past for the k-th
// most-recent backfill event: sums pseudo-random 20-100s gaps so the historical
// feed is never on a fixed 60s grid. k=0 → ~now; larger k → further back.
function jitteredOffset(k: number): number {
  let ms = 0, seed = 0x9e3779b9 >>> 0;
  for (let j = 0; j < k; j++) { seed = Math.imul(seed + j + 1, 2654435761) >>> 0; ms += 20_000 + (seed % 80_000); }
  return ms;
}

// Per-source ingestion delay — the characteristic lag between an action and its
// log landing in the SIEM. Spreads one incident's events across minutes and out of
// strict order, so building the timeline is a genuine skill, not a sort.
function ingestionDelayMs(source: string): number {
  const r = (lo: number, hi: number) => lo + Math.floor(Math.random() * (hi - lo));
  switch (source) {
    case "edr": case "sysmon": case "av":                         return r(5_000, 20_000);
    case "firewall": case "proxy": case "dns": case "ids":
    case "waf": case "vpn": case "nac": case "dhcp":              return r(10_000, 60_000);
    case "siem": case "ueba": case "soar": case "threat_intel":   return r(30_000, 120_000);
    default:                                                      return r(15_000, 60_000);
  }
}

// Raw-timestamp rebasing helpers live in src/lib/sim/rebaseTime.ts (standalone,
// no React) so scripts/validate-runtime-feed can exercise them in CI.

function buildRuleId(event: TelemetryEvent, index: number): string {
  // 1. MITRE technique map
  if (event.mitre_technique && RULE_ID_MAP[event.mitre_technique]) {
    return RULE_ID_MAP[event.mitre_technique];
  }
  // 2. Source + event_type map
  const sourceKey = `${event.source}:${event.event_type}`;
  if (SOURCE_EVENT_RULE[sourceKey]) return SOURCE_EVENT_RULE[sourceKey];
  // 3. Deterministic fallback
  const base = 60000 + (index % 9000);
  return `HTS-${base}`;
}

function buildDescription(event: TelemetryEvent): string {
  // L-05 — the authored description states the CONCLUSION on attack events (names
  // the tool, does the base32/base64 math, gives the domain age, decodes the TXT),
  // which the banner promises the analyst will do themselves. Noise descriptions,
  // by contrast, are factual ("LT-ENG-4400 looked up login.microsoftonline.com").
  // So the authored line is only used for NON-attack events (no mitre_technique);
  // attack events fall through to the factual, observable-derived line below. The
  // interpretation is revealed in the report/debrief, not handed over in the feed.
  // The authored description is a clear, beginner-friendly line — used for NON-attack
  // events (whose authored text is factual). Attack events (mitre_technique present)
  // skip it and fall through to the observable-derived line, so the feed describes
  // rather than explains.
  if (!event.mitre_technique && event.description && event.description.trim().length > 12) {
    return event.description;
  }

  // Otherwise fall back to the exact Event Viewer description text for the code
  const eventCode = event.raw?.["event.code"] as string | undefined;
  if (eventCode && WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode]) {
    return WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode];
  }

  const p    = event.process;
  const n    = event.network;
  const host = event.hostname ? ` on ${event.hostname}` : "";
  const who  = event.user_email ? event.user_email.split("@")[0]
               : event.hostname ?? "System";

  switch (event.event_type) {
    case "process_create":
      return p ? `${p.parent_name || "System"} started ${p.name}${host}` : `New process started${host}`;
    case "file_create":
    case "file_modify":
      return p ? `${p.name} created a file${host}` : `File created${host}`;
    case "file_delete":
      return `File deleted${host}`;
    case "net_connection":
      return `${event.hostname || who} connected to ${n?.domain || event.dst_ip || "external host"}`;
    case "net_blocked":
      return `Connection blocked to ${n?.domain || event.dst_ip || "external host"}`;
    case "dns_query":
      return `${event.hostname || who} looked up ${event.dns?.query || n?.domain || "a domain"}`;
    case "auth_success":
      return `${who} logged in${host}`;
    case "auth_failure":
      return `${who} failed to log in${host}`;
    case "mfa_challenge":
    case "mfa_push_sent":
      return `${who} received a two-factor auth challenge`;
    case "mfa_denied":
      return `${who} rejected an unexpected two-factor push`;
    case "vpn_login":
      return `${who} connected via VPN`;
    case "vpn_logout":
      return `${who} disconnected from VPN`;
    case "vpn_failed":
      return `${who} failed to connect via VPN`;
    case "account_modify":
      return `${who} changed account settings${host}`;
    case "account_create":
      return `New account created for ${who}`;
    case "account_delete":
      return `Account deleted${host}`;
    case "account_lockout":
      return `${who} account was locked out`;
    case "group_modify":
      return `Group membership changed${host}`;
    case "privilege_escalation":
      return `${who} gained elevated privileges${host}`;
    case "cloud_api_call":
    case "cloud_storage_access":
      return `${who} made a cloud API call`;
    case "cloud_role_change":
      return `${who} changed a cloud role`;
    case "av_detection":
    case "av_quarantine":
    case "av_blocked":
    case "edr_alert":
      return `Threat detected on ${event.hostname || "endpoint"}`;
    case "email_received":
      return `${who} received an email`;
    case "email_sent":
      return `${who} sent an email`;
    case "email_blocked":
    case "email_quarantined":
      return `Suspicious email blocked for ${who}`;
    case "sharepoint_access":
    case "sharepoint_download":
      return `${who} accessed a file in SharePoint`;
    case "teams_message":
      return `${who} sent a Teams message`;
    case "scheduled_task":
      return `Scheduled task ran${host}`;
    case "service_install":
      return `New service installed${host}`;
    case "registry_set":
    case "registry_delete":
      return `Registry entry modified${host}`;
    case "dlp_alert":
    case "dlp_block":
      return `Data policy alert for ${who}`;
    case "ids_signature":
    case "ids_blocked":
      return `Intrusion detection alert${host}`;
    case "waf_allow":
      return `Web request to ${n?.domain || "server"}`;
    case "waf_block":
      return `Web attack blocked${host}`;
    case "db_query":
      return `${who} ran a database query`;
    case "db_auth":
      return `${who} logged in to database`;
    case "ueba_anomaly":
    case "risk_score_change":
      return `Unusual behaviour detected for ${who}`;
    case "nac_quarantine":
      return `Device quarantined on network${host}`;
    case "nac_allow":
      return `Device allowed on network${host}`;
    case "http_request":
      return `${who} browsed to ${n?.domain || event.dst_ip || "a website"}`;
    case "http_blocked":
      return `Web request blocked for ${who}`;
    case "mfa_disabled":
      return `MFA removed from account for ${who}`;
    case "policy_modification":
      return `Security policy modified${host}`;
    case "privileged_operation":
      return `Privileged operation performed by ${who}${host}`;
    case "kerberos_tgt":
      return `Kerberos TGT requested for ${who}${host}`;
    case "kerberos_tgs":
      return `Kerberos service ticket requested by ${who}${host}`;
    case "audit_log_cleared":
      return `Security audit log cleared${host}`;
    case "ssh_login":
      return `${who} connected via SSH${host}`;
    case "ssh_failed":
      return `Failed SSH login attempt${host}`;
    case "sudo_command":
      return `${who} ran a privileged command via sudo${host}`;
    case "db_query":
      return `${who} ran a database query`;
    case "db_auth":
      return `${who} logged in to database`;
    case "db_failed":
      return `Failed database login for ${who}`;
    case "k8s_pod_create":
      return `Kubernetes pod created${host}`;
    case "k8s_pod_delete":
      return `Kubernetes pod deleted${host}`;
    case "k8s_exec":
      return `kubectl exec into pod${host}`;
    case "k8s_rbac":
      return `Kubernetes RBAC role binding changed${host}`;
    default:
      return `${event.event_type.replace(/_/g, " ")}${host}`;
  }
}

// ─── Shuffle deck helpers (no-duplicate event rotation) ───────────────────────

/**
 * Extract the pool of regular (non-service) user emails from the event pool.
 * Used to rotate users across deck cycles so the feed never looks repetitive.
 */
function extractDomainUsers(pool: TelemetryEvent[]): string[] {
  const seen = new Set<string>();
  const users: string[] = [];
  for (const e of pool) {
    if (!e.user_email) continue;
    const u = e.user_email;
    // Skip service accounts and generic admin accounts
    if (/^(svc-|ci-|admin@|noreply|system@)/i.test(u)) continue;
    if (!seen.has(u)) { seen.add(u); users.push(u); }
  }
  return users;
}

/**
 * On repeat cycles, swap the event's user_email with a different pool member
 * and update the plain-text description to match. Raw fields are left intact
 * (minor inconsistency tolerated — avoids inadvertently breaking structured fields).
 */
function applyUserVariant(event: TelemetryEvent, cycle: number, users: string[]): TelemetryEvent {
  if (cycle === 0 || users.length <= 1 || !event.user_email) return event;
  // Never mutate once-only training events
  if (isOnceOnly(event)) return event;
  // Skip service accounts
  if (/^(svc-|ci-|admin@|noreply|system@)/i.test(event.user_email)) return event;

  const origIdx = users.indexOf(event.user_email);
  if (origIdx === -1) return event; // unknown user — leave as-is
  const altEmail = users[(origIdx + cycle) % users.length];
  if (altEmail === event.user_email) return event;

  const origName = event.user_email.split("@")[0]; // "t.levy"
  const altName  = altEmail.split("@")[0];          // "r.cohen"

  // Replace username in description (case-sensitive, dot escaped)
  const escapedOrig = origName.replace(".", "\\.");
  const newDesc = event.description?.replace(new RegExp(escapedOrig, "g"), altName);

  return {
    ...event,
    id: `${event.id}_c${cycle}`,
    user_email: altEmail,
    description: newDesc ?? event.description,
  };
}

function shuffleArray<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const isOnceOnly = (e: TelemetryEvent) =>
  !!(e.it_verify_result || e.fp_explanation || e.expected_verdict === "fp");

// ─── Progressive fidelity: stable pseudo-random helpers ───────────────────────
// Deterministic (seeded off event.id) so a given event always renders the same
// noise — no Math.random, which would differ across StrictMode double-invokes.
function stableHash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function stableHex(seed: string, len: number): string {
  let out = "";
  let s = stableHash(seed);
  while (out.length < len) { s = (Math.imul(s, 1103515245) + 12345) >>> 0; out += s.toString(16).padStart(8, "0"); }
  return out.slice(0, len);
}

/**
 * Advanced-tier realism noise. Real production logs carry many always-present,
 * low-signal metadata fields (agent IDs, config builds, logon-session IDs,
 * correlation IDs) that a senior analyst must sift past to find the signal.
 * We add a source-appropriate handful ONLY for advanced-tier story events, so
 * foundation/core logs stay clean for beginners. Every field is neutral
 * metadata — it never states a verdict, preserving the no-hints rule. Each field
 * is namespaced to the event's OWN source (no cross-source contamination).
 */
function injectAdvancedFidelityNoise(raw: Record<string, unknown>, event: TelemetryEvent): void {
  const id = event.id;
  const set = (k: string, v: unknown) => { if (raw[k] === undefined) raw[k] = v; };

  const isSysmonSource = event.source === "sysmon";
  const isWinSecSource = event.source === "ad" || event.source === "windows_security";

  if (isSysmonSource) {
    set("winlog.record_id", String(1_000_000 + (stableHash(id) % 900000)));
    set("winlog.event_data.RuleName", "-");
    set("winlog.event_data.IntegrityLevel", event.process?.integrity === "system" ? "System" : "Medium");
    set("winlog.event_data.LogonId", "0x" + stableHex("logon" + id, 6));
    set("winlog.event_data.TerminalSessionId", "1");
    return;
  }
  if (isWinSecSource) {
    set("winlog.record_id", String(1_000_000 + (stableHash(id) % 900000)));
    set("winlog.event_data.SubjectLogonId", "0x" + stableHex("logon" + id, 6));
    set("winlog.task", "Logon");
    set("winlog.opcode", "Info");
    return;
  }

  const v = (event.vendor ?? "").toLowerCase();
  const src = event.source;
  const isEdr = src === "edr" ||
    ["crowd", "sentinel", "sophos", "defender", "microsoft def", "mde"].some(x => v.includes(x));

  if (isEdr) {
    if (v.includes("crowd")) {
      set("crowdstrike.aid", stableHex("aid" + id, 32));
      set("crowdstrike.cid", stableHex("cid" + id, 32));
      set("crowdstrike.event_platform", "Win");
      set("crowdstrike.ConfigBuild", "1007.3.0018108.1");
    } else {
      set("edr.sensor_id", stableHex("sensor" + id, 32));
      set("edr.org_id", stableHex("org" + id, 16));
      set("edr.agent_version", "7.20.19207");
    }
    return;
  }

  if (["firewall", "vpn", "proxy", "ids", "waf", "nac", "dhcp", "dns"].includes(src)) {
    set("session.id", String((stableHash("sess" + id) % 90_000_000) + 10_000_000));
    set("policy.id", String((stableHash("pol" + id) % 900) + 100));
    set("rule.uuid", `${stableHex(id, 8)}-${stableHex("a" + id, 4)}-${stableHex("b" + id, 4)}`);
    return;
  }

  // Cloud / identity / o365 / okta / DLP — JSON-ingested sources.
  set("correlation.id", `${stableHex("c" + id, 8)}-${stableHex("d" + id, 4)}-4${stableHex("e" + id, 3)}-${stableHex("f" + id, 4)}-${stableHex("g" + id, 12)}`);
  set("request.id", `${stableHex("r" + id, 8)}-${stableHex("h" + id, 4)}-${stableHex("i" + id, 4)}`);
}

export function enrichEvent(event: TelemetryEvent, index: number): LiveEvent {
  const eventCode   = event.raw?.["event.code"]          as string | undefined;
  const o365Op      = event.raw?.["data.office365.Operation"] as string | undefined;

  // ── 1. Compute rule.description ───────────────────────────────────────────
  const ruleDesc = getRuleDescription(event.event_type, event.mitre_technique, eventCode, o365Op);

  // ── 2. Auto-enrich raw with authentic Windows / Sysmon fields ─────────────
  const raw: Record<string, unknown> = { "rule.description": ruleDesc, ...event.raw };

  // Only Windows-native telemetry sources legitimately carry winlog.* fields.
  // Real EDR products (CrowdStrike/SentinelOne/Sophos/Defender-for-Endpoint)
  // report through their OWN schema and must NEVER be stamped with Sysmon /
  // Windows-Security "Event Viewer" fields — doing so is the "EDR wearing
  // Sysmon clothing" realism bug, and it was being applied to every EDR
  // process event system-wide (including the Easy-tier foundation stories).
  const isSysmonSource = event.source === "sysmon";
  const isWinSecSource = event.source === "ad" || event.source === "windows_security";

  // Channel + provider (AD Security events)
  if ((event.source === "ad" || eventCode === "4624" || eventCode === "4625" ||
       eventCode?.startsWith("47") || eventCode?.startsWith("48")) &&
      !raw["winlog.channel"]) {
    raw["winlog.channel"]       = "Security";
    raw["winlog.provider_name"] = "Microsoft-Windows-Security-Auditing";
  }

  // Channel + provider (Sysmon only — NOT EDR products)
  if (isSysmonSource && !raw["winlog.provider_name"]) {
    raw["winlog.provider_name"] = "Microsoft-Windows-Sysmon";
    raw["winlog.channel"]       = "Microsoft-Windows-Sysmon/Operational";
  }

  // Every real Sysmon record carries ProcessGuid + ProcessId + UtcTime — the
  // ProcessGuid is the correlation key that threads Event 1 → 3 → 22 for one
  // process. Curated attack chains set their own (shared) ProcessGuid to make
  // the chain readable as one story; this only fills the gap for events that
  // arrive without one, so a benign Sysmon row isn't obviously thinner than an
  // attack row.
  if (isSysmonSource) {
    if (!raw["winlog.event_data.ProcessGuid"]) {
      raw["winlog.event_data.ProcessGuid"] =
        `{${stableHex("pg" + event.id, 8)}-${stableHex("g1" + event.id, 4)}-${stableHex("g2" + event.id, 4)}-${stableHex("g3" + event.id, 4)}-${stableHex("g4" + event.id, 12)}}`;
    }
    if (!raw["winlog.event_data.ProcessId"]) {
      raw["winlog.event_data.ProcessId"] =
        String(event.process?.pid ?? 1000 + (stableHash("pid" + event.id) % 8000));
    }
    if (!raw["winlog.event_data.UtcTime"] && event.ts) {
      // Sysmon writes UtcTime as "2026-07-17 13:25:23.473"
      raw["winlog.event_data.UtcTime"] = new Date(event.ts).toISOString().replace("T", " ").slice(0, 23);
    }
  }

  // Auth failure (4625) — Status / SubStatus / FailureReason (Windows Security only)
  if (isWinSecSource && event.event_type === "auth_failure" && !raw["winlog.event_data.Status"]) {
    const spray   = event.mitre_technique === "T1110.003";
    // Within auth_failure, detect lockout via description keyword since event_type is already narrowed
    const lockout = event.description?.toLowerCase().includes("lock") ?? false;
    raw["winlog.event_data.Status"]    = "0xC000006D"; // STATUS_LOGON_FAILURE
    // Spray: trying wrong passwords against known accounts → STATUS_WRONG_PASSWORD
    // Unknown user: account doesn't exist → STATUS_NO_SUCH_USER
    raw["winlog.event_data.SubStatus"] = spray ? "0xC000006A"  // STATUS_WRONG_PASSWORD
                                       : lockout ? "0xC0000234" // STATUS_ACCOUNT_LOCKED_OUT
                                       : "0xC000006A";          // default: wrong password
    raw["winlog.event_data.FailureReason"] = spray  ? "%%2312"  // Wrong password
                                           : lockout ? "%%2307"  // Account locked out
                                           : "%%2313";           // Unknown user or bad password
    if (!raw["winlog.event_data.AuthenticationPackageName"]) {
      raw["winlog.event_data.AuthenticationPackageName"] = "NTLM";
      raw["winlog.event_data.LogonProcessName"]          = "NtLmSsp";
    }
    if (event.src_ip && !raw["winlog.event_data.IpAddress"]) {
      raw["winlog.event_data.IpAddress"] = event.src_ip;
      raw["winlog.event_data.IpPort"]    = "54322";
    }
    if (event.hostname && !raw["winlog.event_data.WorkstationName"]) {
      raw["winlog.event_data.WorkstationName"] = event.hostname;
    }
  }

  // Auth success (4624) — KeyLength, SubjectUserSid (Windows Security only;
  // an O365/Okta sign-in is NOT a Windows Security event)
  if (isWinSecSource && event.event_type === "auth_success" && !raw["winlog.event_data.KeyLength"]) {
    raw["winlog.event_data.KeyLength"]      = "0";
    raw["winlog.event_data.SubjectUserSid"] = "S-1-5-18";
    if (!raw["winlog.event_data.LogonType"] && raw["logon.type"]) {
      raw["winlog.event_data.LogonType"] = String(raw["logon.type"]);
    }
    if (!raw["winlog.event_data.AuthenticationPackageName"] && raw["authentication.protocol"]) {
      raw["winlog.event_data.AuthenticationPackageName"] = String(raw["authentication.protocol"]);
    }
    if (event.src_ip && !raw["winlog.event_data.IpAddress"]) {
      raw["winlog.event_data.IpAddress"] = event.src_ip;
      raw["winlog.event_data.IpPort"]    = "0";
    }
  }

  // Account lockout (4740) — Windows Security only (Okta lockouts use okta.*)
  if (isWinSecSource && event.event_type === "account_lockout" && !raw["winlog.event_data.Status"]) {
    raw["winlog.event_data.Status"]        = "0xC0000234"; // STATUS_ACCOUNT_LOCKED_OUT
    raw["winlog.event_data.SubjectUserName"] = "SYSTEM";   // lockout triggered by system
    raw["winlog.event_data.SubjectDomainName"] = "NT AUTHORITY";
    if (event.user_email && !raw["winlog.event_data.TargetUserName"]) {
      raw["winlog.event_data.TargetUserName"]   = event.user_email.split("@")[0];
      raw["winlog.event_data.TargetDomainName"] = (event.user_email.split("@")[1]?.split(".")[0] ?? "DOMAIN").toUpperCase();
    }
    raw["winlog.channel"]       = "Security";
    raw["winlog.provider_name"] = "Microsoft-Windows-Security-Auditing";
  }

  // Sysmon Event 1 process_create — Image, CommandLine, IntegrityLevel.
  // Gated to Sysmon ONLY: EDR products already ship their own native process
  // fields (crowdstrike.*/s1.*/DeviceProcessEvents) and must not be given
  // Sysmon winlog fields.
  if (isSysmonSource && event.process && !raw["winlog.event_data.Image"]) {
    const name = event.process.name ?? "";
    const inSystem32 = ["powershell.exe","cmd.exe","wscript.exe","cscript.exe",
                        "mshta.exe","vssadmin.exe","wevtutil.exe","net.exe",
                        "rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe"].includes(name.toLowerCase());
    raw["winlog.event_data.Image"] = inSystem32
      ? `C:\\Windows\\System32\\${name}`
      : (event.process.path ?? `C:\\Program Files\\${name}`);
    if (event.process.pid)     raw["winlog.event_data.ProcessId"]   = String(event.process.pid);
    if (event.process.cmdline) raw["winlog.event_data.CommandLine"]  = event.process.cmdline;
    raw["winlog.event_data.IntegrityLevel"] = event.process.integrity ?? "Medium";
    raw["winlog.event_data.CurrentDirectory"] = event.user_email
      ? `C:\\Users\\${event.user_email.split("@")[0]}\\`
      : "C:\\Windows\\system32\\";
    if (event.process.parent_name) {
      // explorer.exe lives at C:\Windows\, not System32 — the rest are System32-resident.
      const parent = event.process.parent_name;
      raw["winlog.event_data.ParentImage"] = parent.toLowerCase() === "explorer.exe"
        ? "C:\\Windows\\explorer.exe"
        : `C:\\Windows\\System32\\${parent}`;
      if (event.process.parent_pid) raw["winlog.event_data.ParentProcessId"] = String(event.process.parent_pid);
    }
    if (event.process.hash?.sha256) {
      raw["winlog.event_data.Hashes"] = `SHA256=${event.process.hash.sha256}`;
    }
  }

  // Sysmon Event 3 net_connection — Sysmon only (a firewall net_connection
  // uses pan.*/cp.* fields, not winlog)
  if (isSysmonSource && event.event_type === "net_connection" && event.dst_ip && !raw["winlog.event_data.DestinationIp"]) {
    raw["winlog.event_data.DestinationIp"]   = event.dst_ip;
    raw["winlog.event_data.DestinationPort"] = String(event.dst_port ?? "443");
    raw["winlog.event_data.Protocol"]        = (event.protocol ?? "tcp").toLowerCase();
    raw["winlog.event_data.Initiated"]       = "true";
    if (event.src_ip) raw["winlog.event_data.SourceIp"]   = event.src_ip;
    if (event.process?.name) raw["winlog.event_data.Image"] = event.process.name;
  }

  // DNS query (Sysmon Event 22) — Sysmon only. A Windows-DNS-server event keeps
  // its ECS dns.* namespace and must not gain a Sysmon event.code 22.
  if (isSysmonSource && event.event_type === "dns_query" && event.dns?.query && !raw["winlog.event_data.QueryName"]) {
    if (!raw["event.code"]) raw["event.code"] = "22";
    raw["winlog.event_data.QueryName"]    = event.dns.query;
    raw["winlog.event_data.QueryType"]    = String(event.dns.query_type ?? "1");
    raw["winlog.event_data.QueryResults"] = event.dst_ip ? `${event.dst_ip};` : "::";
    raw["winlog.event_data.QueryStatus"]  = "0"; // SUCCESS / NOERROR
  }

  // File create (Sysmon Event 11) — Sysmon only
  if (isSysmonSource && event.event_type === "file_create" && event.file?.path && !raw["winlog.event_data.TargetFilename"]) {
    raw["winlog.event_data.TargetFilename"] = event.file.path;
  }

  // Registry set (Sysmon Event 13) — Sysmon only
  if (isSysmonSource && event.event_type === "registry_set" && event.registry?.path && !raw["winlog.event_data.TargetObject"]) {
    raw["winlog.event_data.TargetObject"] = event.registry.path;
    if (event.registry.value) raw["winlog.event_data.Details"] = event.registry.value;
    raw["winlog.event_data.EventType"] = "SetValue";
  }

  // ── O365 / Azure AD auto-enrichment ─────────────────────────────────────
  if (event.source === "o365" && !raw["data.office365.Workload"]) {
    const isAzureAD = event.event_type === "auth_success" || event.event_type === "auth_failure"
      || event.event_type === "mfa_challenge" || event.event_type === "mfa_denied"
      || event.event_type === "account_modify" || event.event_type === "account_create"
      || event.event_type === "account_delete" || event.event_type === "group_modify";
    const isExchange = event.event_type === "email_received" || event.event_type === "email_sent";
    const isSharePoint = event.event_type === "sharepoint_access";
    raw["data.office365.Workload"] = isAzureAD ? "AzureActiveDirectory"
      : isExchange ? "Exchange"
      : isSharePoint ? "SharePoint"
      : "AzureActiveDirectory";
    raw["data.office365.RecordType"] = isAzureAD ? "15" : isExchange ? "2" : isSharePoint ? "6" : "15";
    raw["data.office365.Version"]    = "1";
    if (event.user_email) {
      raw["data.office365.UserId"]   = event.user_email;
      raw["data.office365.UserKey"]  = event.user_email;
    }
    if (event.src_ip)    raw["data.office365.ClientIP"] = event.src_ip;
    if (event.ts)        raw["data.office365.CreationTime"] = event.ts;
    raw["data.office365.ResultStatus"] = (event.event_type === "auth_failure" || event.event_type === "mfa_denied")
      ? "Failed" : "Success";
    raw["data.office365.UserType"]      = "0"; // Regular user
    raw["data.office365.OrganizationId"]= "a7b8c9d0-1234-5678-abcd-ef0123456789";
    if (o365Op) raw["data.office365.Operation"] = o365Op;
  }

  // ── Vendor-native field enrichment (Palo Alto / CrowdStrike) ─────────────
  // Central enrichment so every event from these vendors carries the fields a
  // real SIEM ingest would show — without hand-editing dozens of pool events.
  const isPrivateIp = (ip?: string) =>
    !!ip && (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip));

  if (event.source === "firewall" && event.vendor?.includes("Palo Alto") && !raw["panw.panos.type"]) {
    const isThreat = event.severity === "medium" || event.severity === "high" || event.severity === "critical";
    raw["panw.panos.type"]   = isThreat ? "THREAT" : "TRAFFIC";
    raw["panw.panos.action"] = String(raw["event.action"] ?? (event.event_type.includes("block") ? "deny" : "allow"));
    raw["panw.panos.source.zone"]      = isPrivateIp(event.src_ip) ? "trust" : "untrust";
    raw["panw.panos.destination.zone"] = isPrivateIp(event.dst_ip) ? "trust" : "untrust";
    if (raw["rule.name"]) raw["panw.panos.ruleset"] = String(raw["rule.name"]);
  }

  if (event.vendor?.includes("CrowdStrike") && !raw["crowdstrike.aid"]) {
    // Deterministic 32-hex agent id from hostname — same host, same aid, like a real Falcon sensor
    const host = event.hostname ?? "unknown-host";
    let h1 = 5381, h2 = 52711;
    for (let i = 0; i < host.length; i++) {
      h1 = ((h1 << 5) + h1 + host.charCodeAt(i)) >>> 0;
      h2 = ((h2 << 5) ^ h2 ^ host.charCodeAt(i)) >>> 0;
    }
    const hex = (n: number) => n.toString(16).padStart(8, "0");
    raw["crowdstrike.aid"] = `${hex(h1)}${hex(h2)}${hex(h1 ^ h2)}${hex((h1 + h2) >>> 0)}`;
    if (event.hostname && !raw["crowdstrike.ComputerName"]) raw["crowdstrike.ComputerName"] = event.hostname;
  }

  // ── GeoLocation — auto-fill from event.geo struct OR src_ip ─────────────
  const KNOWN_GEO: Record<string, { country: string; city: string; lat: number; lon: number }> = {
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

  if (!raw["GeoLocation.country_name"]) {
    if (event.geo) {
      if (event.geo.country) raw["GeoLocation.country_name"] = event.geo.country;
      if (event.geo.city)    raw["GeoLocation.city_name"]    = event.geo.city;
      if (event.geo.latitude  != null) raw["GeoLocation.location.lat"] = event.geo.latitude;
      if (event.geo.longitude != null) raw["GeoLocation.location.lon"] = event.geo.longitude;
    } else if (event.src_ip) {
      const prefix = Object.keys(KNOWN_GEO).find(k => (event.src_ip as string).startsWith(k));
      if (prefix) {
        const geo = KNOWN_GEO[prefix];
        raw["GeoLocation.country_name"]  = geo.country;
        raw["GeoLocation.city_name"]     = geo.city;
        raw["GeoLocation.location.lat"]  = geo.lat;
        raw["GeoLocation.location.lon"]  = geo.lon;
      }
    }
  }

  return {
    ...event,
    raw,
    ruleLevel: calculateRuleLevel(event),
    ruleId: buildRuleId(event, index),
    displayDescription: buildDescription(event),
  };
}

export interface DashboardSessionRecord {
  type: "dashboard";
  date: string;
  xpEarned: number;
  /**
   * % of presented attacks the student actually caught (via a passing
   * incident report) before the SLA expired. Real signal — derived from
   * attacksCaughtCount/attacksPresentedCount, both driven by markCaught()
   * and incident-open, not by the removed per-event classify() UI.
   */
  detectRate: number;
  /** False-negative count — attacks the SLA timer expired on before the student
   * caught them. Tracked separately from detectRate on purpose (see
   * ANALYST_TELEMETRY_PLAN.md) — over-escalating and missing real attacks are
   * opposite failure modes and averaging them hides both. Optional: records
   * saved before this field lack it. */
  fnCount?: number;
  avgCatchMs: number | null;
  attacksCaughtCount: number;
  attacksPresentedCount: number;
  /** Rows opened this session — a coarse thoroughness signal. Optional: records
   * saved before this field lack it. */
  eventsOpenedCount?: number;
  /** Wall-clock session length in ms (records saved before this field lack it) */
  durationMs?: number;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

interface UseLiveEventsOptions {
  eventPool?: TelemetryEvent[];    // legacy mode: benign background noise
  companyId?: string;              // engine mode: generate events algorithmically
  /** The session's attack story — events injected IN ORDER in small phases */
  story?: AttackStory | null;
  /** Called when the active story's final phase has been injected */
  onStoryComplete?: () => void;
  /** True while the analyst is actively investigating this incident (report modal
   *  open, or the EDR console in play). When true, the "you missed it" verdict is
   *  deferred — a thorough investigation must never auto-fail the analyst. */
  isInvestigating?: () => boolean;
  intervalMs?: number;
  maxVisible?: number;
  /**
   * When false, the feed starts IDLE — no initial events, no streaming — until
   * reset()/resume() is called. The dashboard uses this so nothing runs until
   * the student presses Start Training. Defaults to true (legacy auto-start).
   */
  autoStart?: boolean;
}

export interface LiveEventsApi {
  events: LiveEvent[];
  isStreaming: boolean;
  sessionXp: number;
  newIds: Set<string>;              // IDs of the most recent batch (for fade-in animation)
  activeIncident: ActiveIncident | null;
  dismissIncident: () => void;
  pause: () => void;
  resume: () => void;
  reset: (pool?: TelemetryEvent[], story?: AttackStory | null) => void;
  /** Arm a new attack story mid-session. Optional delayMs overrides the default
   *  8-12 min campaign cooldown (the dashboard uses a shorter gap after a report). */
  startStory: (story: AttackStory, delayMs?: number) => void;
  // Fires when an attack completes uncaught — drives the POSITIVE "Learning
  // Moment" debrief (NOT a fail: no XP loss, no permanent halt). Paired with the
  // missedIncident teaching payload. clearMissedAttack resets both.
  missedAttack: boolean;
  clearMissedAttack: () => void;
  /** Teaching payload for the Learning-Moment debrief (what the attack was, its
   *  MITRE technique(s), and the tell) — null when no debrief is active. */
  missedIncident: MissedIncidentDebrief | null;
  /** Register a real catch — called when the student's incident report passes.
   * Stops the response clock and records catch speed + response time. */
  markCaught: (eventId: string) => void;
  // Response clock — ELAPSED seconds since the attack's first phase (counts UP;
  // pauses while investigating). null when no active attack. Never a deadline.
  attackTimerSeconds: number | null;
  /** Response time (ms) for the most recently handled incident, from attack
   * first-phase injection to catch / passing report. null until one is handled.
   * A coaching metric only — never affects pass/fail or score. */
  lastResponseMs: number | null;
  /** The response-time TARGET in seconds (a coaching benchmark, not a deadline). */
  responseTargetSeconds: number;
  fnCount: number;
  // Phase-1 behavioral telemetry (ANALYST_TELEMETRY_PLAN.md)
  eventsOpenedCount: number;
  recordEventOpened: () => void;
  attacksCaughtCount: number;
  avgCatchMs: number | null;
  endSession: () => DashboardSessionRecord;
  // Attack chain reconstruction (populated after student catches an attack)
  lastAttackChain: LiveEvent[] | null;
  clearLastAttackChain: () => void;
  /** Award bonus XP not tied to a specific event classification (e.g. worksheet, notes grading) */
  addXp: (xp: number) => void;
}

// ─── Learning-Moment debrief builders ─────────────────────────────────────────

/** The standout signal an analyst could have caught the attack by — the highest-
 *  severity event's plain-language description, which reads as the "tell". */
function buildMissedTell(events: TelemetryEvent[]): string {
  const key = events.find(e => e.severity === "critical")
           ?? events.find(e => e.severity === "high")
           ?? events[0];
  const desc = key?.description?.trim();
  if (desc && desc.length > 8) return desc;
  return "an unusual burst of high-severity activity from a single source, out of step with the normal baseline";
}

/** Assemble the positive teaching payload shown when an attack completes uncaught. */
function buildMissedDebrief(title: string, techniques: string[], events: TelemetryEvent[]): MissedIncidentDebrief {
  return {
    title: title || "A multi-stage attack",
    techniques: Array.from(new Set(techniques.filter(Boolean))),
    tell: buildMissedTell(events),
  };
}

// Incident title generator from attack event descriptions
function inferIncidentTitle(events: TelemetryEvent[]): string {
  const highSev = events.find(e => e.severity === "critical" || e.severity === "high");
  if (!highSev) return "Suspicious Activity Detected";
  const desc = highSev.description ?? "";
  // Derive a short title from the description
  if (/cobalt|beacon|c2/i.test(desc))      return "Active C2 Beaconing Detected";
  if (/ransomware|encrypt|locked/i.test(desc)) return "Ransomware Activity Detected";
  if (/lsass|credential|mimikatz|dcsync/i.test(desc)) return "Credential Theft in Progress";
  if (/psexec|lateral|smb|wmi/i.test(desc)) return "Lateral Movement Detected";
  if (/phish|invoice|macro/i.test(desc))   return "Phishing Attack — Active Infection";
  if (/powershell|encoded|base64/i.test(desc)) return "Malicious PowerShell Execution";
  if (/oauth|consent|graph api/i.test(desc)) return "Unauthorized Cloud Access";
  if (/exfil|upload|download.*bulk/i.test(desc)) return "Data Exfiltration Attempt";
  return "High-Severity Incident — Investigate";
}

// Convert GeneratedEvent (engine output) → TelemetryEvent for enrichEvent()
function generatedToTelemetry(g: GeneratedEvent, idx: number): TelemetryEvent {
  return {
    ...g,
    id:  g.id  ?? `eng_${Date.now()}_${idx}`,
    ts:  g.ts  ?? new Date().toISOString(),
    severity: g.severity ?? "informational",
  } as TelemetryEvent;
}

export function useLiveEvents({
  eventPool = [],
  companyId,
  story = null,
  onStoryComplete,
  isInvestigating,
  intervalMs = 40000,
  maxVisible = 100,
  autoStart = true,
}: UseLiveEventsOptions): LiveEventsApi {
  // Engine mode: true when companyId is provided
  const engineMode = Boolean(companyId);
  // Start empty — populated in useEffect so SSR and client render the same HTML (avoids hydration mismatch)
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isStreaming, setIsStreaming]       = useState(autoStart);
  const [sessionXp, setSessionXp]           = useState(0);
  const [newIds, setNewIds]                 = useState<Set<string>>(new Set());
  const [activeIncident, setActiveIncident] = useState<ActiveIncident | null>(null);
  const [missedAttack, setMissedAttack]     = useState(false);
  // Teaching payload for the positive "Learning Moment" debrief (what the attack
  // was), captured when an uncaught attack completes. null when no debrief.
  const [missedIncident, setMissedIncident] = useState<MissedIncidentDebrief | null>(null);

  // SLA countdown + per-skill tracking
  const [attackTimerSeconds,   setAttackTimerSeconds]   = useState<number | null>(null);
  // fnCount = missed-attack count (Phase 1 telemetry — see ANALYST_TELEMETRY_PLAN.md).
  // `missedAttack` stays a one-shot boolean for the existing "you missed it" UI
  // toast; fnCount is the cumulative counter for trend reporting.
  const [fnCount,               setFnCount]              = useState(0);
  const [eventsOpenedCount,     setEventsOpenedCount]    = useState(0);
  const [attacksCaughtCount,    setAttacksCaughtCount]   = useState(0);
  // Real denominator for detectRate: every non-FP incident that ever opened
  // this session, whether it was ultimately caught or missed.
  const [attacksPresentedCount, setAttacksPresentedCount] = useState(0);
  const [avgCatchMs,           setAvgCatchMs]           = useState<number | null>(null);
  // Response time (ms) for the most recently handled incident — from attack
  // first-phase injection to the catch / passing report. Surfaced as a coaching
  // point in the incident report; never affects pass/fail or score.
  const [lastResponseMs,       setLastResponseMs]       = useState<number | null>(null);
  const [lastAttackChain,      setLastAttackChain]      = useState<LiveEvent[] | null>(null);
  /** Incident ids already counted toward attacksCaughtCount — guards markCaught
   * against double-incrementing if it's ever invoked twice for the same incident. */
  const countedIncidentIdsRef = useRef<Set<string>>(new Set());

  const poolRef           = useRef<TelemetryEvent[]>(eventPool);
  const worldStateRef     = useRef<WorldState | null>(
    companyId ? initWorldState(companyId, Date.now() & 0xFFFFFF) : null
  );
  /** Active attack story + injection cursor (events injected in order) */
  const storyRef          = useRef<AttackStory | null>(story);

  /**
   * enrichEvent + progressive fidelity. Log fidelity is a property of the
   * SESSION, not the individual event: when the active story is advanced-tier
   * (a Hard session), EVERY event — benign background noise included — gets
   * production-grade metadata noise. Applying it session-wide (not just to
   * attack events) is deliberate: if only malicious rows were "fuller", field
   * count would leak the answer. Foundation/core sessions stay clean.
   */
  const enrichWithFidelity = useCallback((e: TelemetryEvent, idx: number): LiveEvent => {
    const le = enrichEvent(e, idx);
    if (storyRef.current?.complexity === "advanced" || e.tier === "advanced") {
      injectAdvancedFidelityNoise(le.raw, le);
    }
    return le;
  }, []);
  const storyCursorRef    = useRef(0);
  const onStoryCompleteRef = useRef(onStoryComplete);
  onStoryCompleteRef.current = onStoryComplete;
  // Reassigned every render so the miss-watchdog always reads the CURRENT
  // "is the analyst investigating right now?" closure.
  const isInvestigatingRef = useRef(isInvestigating);
  isInvestigatingRef.current = isInvestigating;
  // The live feed is a low-pressure PRACTICE space. When an attack completes
  // uncaught we DO surface it — as a POSITIVE "Learning Moment" debrief, never a
  // punishment. This watchdog fires it only after a GENEROUSLY long grace (far
  // longer than the old 4-minute trap), never while the analyst is mid-
  // investigation (it re-checks on a ~60s delay instead of interrupting), and
  // never once markCaught has run. It does not fail the shift or claw back XP —
  // page.tsx pauses the feed behind the modal and resumes + arms the next attack
  // when they dismiss it.
  const MISS_DEBRIEF_GRACE_MS = 540_000; // 9 minutes after the attack's final phase
  const missWatchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleDebriefCheck = useCallback((delay: number, debrief: MissedIncidentDebrief) => {
    if (missWatchdogRef.current) clearTimeout(missWatchdogRef.current);
    missWatchdogRef.current = setTimeout(() => {
      missWatchdogRef.current = null;
      if (caughtRef.current) return;                          // caught in time → no debrief
      if (isInvestigatingRef.current?.()) {                   // still working it → wait, never interrupt
        scheduleDebriefCheck(60_000, debrief);
        return;
      }
      // Surface the positive Learning-Moment debrief and pause the feed so the
      // analyst actually reads it. No fail, no XP loss — page.tsx resumes on close.
      setMissedIncident(debrief);
      setMissedAttack(true);
      setIsStreaming(false);
    }, delay);
  }, []);
  const globalIdx         = useRef(15);
  const activeIncidentRef = useRef<ActiveIncident | null>(null);
  const missTimerRef      = useRef<ReturnType<typeof setTimeout> | null>(null);
  const caughtRef         = useRef(false);
  const attackTimerRef    = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** IDs of "once-only" events (IT-verify / FP training) already emitted this session */
  const seenOnceRef        = useRef<Set<string>>(new Set());
  /** Shuffle deck — repeatable events in random order, no duplicates until full cycle */
  const deckRef            = useRef<TelemetryEvent[]>([]);
  const deckPosRef         = useRef(0);
  /** How many times the deck has been fully cycled through — used for user-rotation variants */
  const cycleCountRef      = useRef(0);
  /** Pool of regular user emails extracted from the event pool for rotation */
  const domainUsersRef     = useRef<string[]>([]);
  /** SLA countdown interval + catch speed tracking */
  const slaIntervalRef     = useRef<ReturnType<typeof setInterval> | null>(null);
  const catchSpeedMsRef    = useRef<number[]>([]);
  const attackInjectedAtRef = useRef<number | null>(null);
  /** Session start — reset() restarts it; endSession() reports the duration */
  const sessionStartRef    = useRef(Date.now());

  /** Build (or rebuild) the shuffle deck from the current pool */
  const buildDeck = (pool: TelemetryEvent[]) => {
    const repeatable = pool.filter(e => !isOnceOnly(e));
    deckRef.current  = shuffleArray(repeatable);
    deckPosRef.current = 0;
  };

  /** Pull the next event from the deck — reshuffles when exhausted, applies user-rotation on repeat cycles */
  const nextFromDeck = (): TelemetryEvent | null => {
    if (deckRef.current.length === 0) return null;
    if (deckPosRef.current >= deckRef.current.length) {
      // Reshuffle for next cycle — prevents same last→first adjacency
      deckRef.current = shuffleArray(deckRef.current);
      deckPosRef.current = 0;
      cycleCountRef.current += 1;
    }
    const event = deckRef.current[deckPosRef.current++];
    // On repeat cycles, rotate the acting user so the feed never looks identical
    return cycleCountRef.current > 0
      ? applyUserVariant(event, cycleCountRef.current, domainUsersRef.current)
      : event;
  };

  // ── Populate initial events client-side only (avoids SSR/hydration mismatch) ─
  useEffect(() => {
    // Idle until Start Training: with autoStart=false the feed shows nothing
    // until reset() runs (from handleStartTraining). No logs before the shift.
    if (!autoStart) return;
    const now = Date.now();

    if (engineMode && worldStateRef.current) {
      // ENGINE MODE: generate first 15 events algorithmically
      const world = worldStateRef.current;
      const initial: TelemetryEvent[] = [];
      for (let i = 0; i < 15; i++) {
        const g = generateBenignEvent(world);
        world.simTime += world.rng.range(30_000, 120_000);
        initial.push(generatedToTelemetry(g, i));
      }
      setEvents(
        initial.map((e, i) =>
          enrichWithFidelity(withRebasedTime(e, new Date(now - jitteredOffset(14 - i)).toISOString()), i)
        ).reverse()
      );
      return;
    }

    // LEGACY MODE: shuffle from static pool
    const pool = poolRef.current;
    // Shuffle the whole pool so initial 15 events cover diverse sources, not just the first category in file order
    const shuffled = shuffleArray(pool);
    const initial = shuffled.slice(0, 15);
    initial.forEach(e => { if (isOnceOnly(e)) seenOnceRef.current.add(e.id); });
    const repeatable = shuffled.slice(15).filter(e => !isOnceOnly(e));
    deckRef.current  = shuffleArray(repeatable.length > 0 ? repeatable : pool.filter(e => !isOnceOnly(e)));
    deckPosRef.current = 0;
    domainUsersRef.current = extractDomainUsers(pool);
    setEvents(
      initial.map((e, i) =>
        enrichWithFidelity(withRebasedTime(e, new Date(now - jitteredOffset(14 - i)).toISOString()), i)
      ).reverse()
    );
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // intentionally runs once on mount only

  // ── Normal benign tick ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!isStreaming) return;
    const timer = setInterval(() => {

      // ── ENGINE MODE ────────────────────────────────────────────────────────
      if (engineMode && worldStateRef.current) {
        const world = worldStateRef.current;
        world.simTime = Date.now();

        // Fire next attack phase if due
        if (world.attack && attackDue(world)) {
          const attackEvents = advanceAttack(world);
          // advanceAttack() clears world.attack once every phase has injected —
          // that is the moment the story is genuinely over.
          const storyJustFinished = world.attack === null;
          if (attackEvents && attackEvents.length > 0) {
            const isFP = world.attack?.isFP ?? false;
            const now  = Date.now();
            const raw  = attackEvents.map((g: GeneratedEvent, i: number) => {
              const tele = generatedToTelemetry(g, globalIdx.current + i);
              return {
                ...tele,
                // L-02: spread the incident's events across minutes with a per-source
                // ingestion lag, not a 3-4s burst — building the timeline is now a
                // real correlation exercise, not "take everything within 11 seconds".
                ts: new Date(now + i * (30_000 + Math.floor(Math.random() * 45_000)) + ingestionDelayMs(tele.source)).toISOString(),
                id: `eng_atk_${now}_${i}`,
              };
            });
            globalIdx.current += raw.length;
            const enriched = raw.map(e => enrichWithFidelity(e, globalIdx.current++));
            const batchIds  = new Set(enriched.map(e => e.id));

            if (!isFP) {
              const incident: ActiveIncident = {
                id: `inc_${now}`,
                title: inferIncidentTitle(raw),
                severity: raw.some(e => e.severity === "critical") ? "critical" : "high",
                injectedAt: now,
                eventIds: Array.from(batchIds),
              };
              activeIncidentRef.current = incident;
              caughtRef.current = false;
              attackInjectedAtRef.current = now;
              setAttacksPresentedCount(c => c + 1);
              // Response clock counts UP from 0 — an elapsed timer, not a
              // countdown. It is never a fail at any value; it only measures how
              // long the analyst took so the report can coach on pace.
              setAttackTimerSeconds(0);
              if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
              slaIntervalRef.current = setInterval(() => {
                // Paused while the analyst is working the case (report open / EDR
                // in play) — that time must not count against them. No fail, ever.
                if (isInvestigatingRef.current?.()) return;
                setAttackTimerSeconds(prev => (prev === null ? null : prev + 1));
              }, 1000);
              setActiveIncident(incident);
            }

            setNewIds(batchIds);
            setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
            setTimeout(() => setNewIds(new Set()), 2000);

            // Completed uncaught → schedule the POSITIVE Learning-Moment debrief
            // after a generous grace. Never a fail, never a halt (page.tsx
            // resumes + arms the next attack on dismiss); a passing report before
            // then cancels it via markCaught.
            if (storyJustFinished && !isFP && !caughtRef.current) {
              const inc = activeIncidentRef.current;
              if (inc) {
                const techniques = Array.from(new Set(raw.map(e => e.mitre_technique).filter((m): m is string => !!m)));
                scheduleDebriefCheck(MISS_DEBRIEF_GRACE_MS, buildMissedDebrief(inc.title, techniques, raw));
              }
            }
          }
          return;
        }

        // Generate benign events
        const batchSize = world.rng.range(1, 2);
        const newRaw: TelemetryEvent[] = [];
        for (let i = 0; i < batchSize; i++) {
          const g = generateBenignEvent(world);
          world.simTime += world.rng.range(10_000, 40_000);
          newRaw.push(generatedToTelemetry(g, globalIdx.current + i));
        }
        globalIdx.current += newRaw.length;
        const enriched = newRaw.map(e => enrichWithFidelity(withRebasedTime(e, new Date().toISOString()), globalIdx.current++));
        const batchIds  = new Set(enriched.map(e => e.id));
        setNewIds(batchIds);
        setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
        setTimeout(() => setNewIds(new Set()), 1500);
        return;
      }

      // ── LEGACY MODE (shuffle deck) ─────────────────────────────────────────
      const pool = poolRef.current;
      if (pool.length === 0) return;

      const batchSize = Math.floor(Math.random() * 2) + 1;
      const newRaw: TelemetryEvent[] = [];

      for (let i = 0; i < batchSize; i++) {
        let chosen: TelemetryEvent | null = null;
        if (Math.random() < 0.10) {
          const unsentOnce = pool.filter(e => isOnceOnly(e) && !seenOnceRef.current.has(e.id));
          if (unsentOnce.length > 0) {
            chosen = unsentOnce[Math.floor(Math.random() * unsentOnce.length)];
            seenOnceRef.current.add(chosen.id);
          }
        }
        if (!chosen) chosen = nextFromDeck();
        if (!chosen) chosen = pool[Math.floor(Math.random() * pool.length)];
        newRaw.push({ ...withRebasedTime(chosen, new Date().toISOString()), id: `${chosen.id}_${Date.now()}_${i}` });
      }

      const enriched = newRaw.map(e => enrichWithFidelity(e, globalIdx.current++));
      const batchIds  = new Set(enriched.map(e => e.id));
      setNewIds(batchIds);
      setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
      setTimeout(() => setNewIds(new Set()), 1500);
    }, intervalMs);

    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- interval keyed intentionally; enrichWithFidelity/scheduleDebriefCheck are useCallback-stable and read live values via refs, so recreating the interval on their identity would only churn it
  }, [isStreaming, intervalMs, maxVisible, engineMode]);

  // ── Attack injection — Story Scheduler ───────────────────────────────────────
  // The session story's events are injected IN ORDER in small phases (2-3 events)
  // so the student watches a coherent kill-chain unfold: first phase within
  // ~2-3 minutes, then a new phase every 2-4 minutes until all events appeared.
  const FIRST_PHASE_DELAY = () => 120_000 + Math.floor(Math.random() * 60_000);   // 2-3 min
  const PHASE_GAP         = () => 120_000 + Math.floor(Math.random() * 120_000);  // 2-4 min

  // Response-time TARGET — a coaching benchmark, NOT a deadline. The response
  // clock counts up from 0; if the analyst catches/reports within this many
  // seconds the report notes a good pace, otherwise it gently flags faster
  // triage as an improvement area. Nothing fails or halts at this value.
  const SLA_SECONDS = 900; // 15 minutes — response-time target

  /**
   * Quiet period between the END of one attack campaign and the FIRST phase of
   * the next. Widened from 4-6 to 8-12 minutes: back-to-back campaigns left no
   * room to finish investigating and writing up one incident before the next
   * started competing for attention, which reads as relentless rather than
   * realistic — a real shift has long quiet stretches between incidents.
   */
  const ATTACK_COOLDOWN = () => 480_000 + Math.floor(Math.random() * 240_000); // 8-12 min

  const injectNextPhase = useCallback(() => {
    const s = storyRef.current;
    if (!s) return;
    const cursor = storyCursorRef.current;
    if (cursor >= s.events.length) return;

    const isFirstPhase = cursor === 0;
    const n = Math.min(s.events.length - cursor, 2 + (Math.random() < 0.5 ? 1 : 0)); // 2-3 events
    const now = Date.now();
    const slice = s.events.slice(cursor, cursor + n).map((e, i) => ({
      // L-02: spread over minutes + per-source ingestion delay (was a 4s burst),
      // so the attack no longer stands out as "the only thing off the 60s grid".
      ...withRebasedTime(e, new Date(now + i * (30_000 + Math.floor(Math.random() * 45_000)) + ingestionDelayMs(e.source)).toISOString()),
      id: `atk_${e.id}_${now}_${i}`,
    }));
    storyCursorRef.current = cursor + n;

    const enriched = slice.map(e => enrichWithFidelity(e, globalIdx.current++));
    const batchIds = new Set(enriched.map(e => e.id));

    if (isFirstPhase) {
      // Open the incident: SLA countdown + miss detection fire once per story
      const incident: ActiveIncident = {
        id: `inc_${now}`, title: s.title,
        severity: slice.some(e => e.severity === "critical") ? "critical" : "high",
        injectedAt: now, eventIds: Array.from(batchIds),
      };
      activeIncidentRef.current = incident;
      caughtRef.current = false;
      attackInjectedAtRef.current = now;
      setAttacksPresentedCount(c => c + 1);
      // Response clock starts at 0 and counts UP — an elapsed timer measuring how
      // long the analyst takes to respond. It never fails or halts at any value.
      setAttackTimerSeconds(0);
      if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
      slaIntervalRef.current = setInterval(() => {
        // Pause the response clock while the analyst is working the case — the
        // report is open (they're pulling data into it) or the EDR console is in
        // play. That time must not count against them.
        if (isInvestigatingRef.current?.()) return;
        setAttackTimerSeconds(prev => (prev === null ? null : prev + 1));
      }, 1000);
      setActiveIncident(incident);
    } else if (activeIncidentRef.current) {
      // Later phases extend the same incident (chain board sees the full story)
      activeIncidentRef.current = {
        ...activeIncidentRef.current,
        eventIds: [...activeIncidentRef.current.eventIds, ...batchIds],
      };
      setActiveIncident(activeIncidentRef.current);
    }

    setNewIds(batchIds);
    setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
    setTimeout(() => setNewIds(new Set()), 2000);

    if (storyCursorRef.current >= s.events.length) {
      // Story fully injected. If it was never caught, schedule the POSITIVE
      // Learning-Moment debrief after a generous grace — never a fail, never a
      // permanent halt (page.tsx pauses the feed behind the modal, then resumes
      // and arms the next attack on dismiss). A passing report before the grace
      // elapses cancels it via markCaught.
      if (!caughtRef.current) {
        scheduleDebriefCheck(MISS_DEBRIEF_GRACE_MS, buildMissedDebrief(s.title, s.mitre ?? [], s.events));
      }
      storyRef.current = null;
      onStoryCompleteRef.current?.();
    } else {
      attackTimerRef.current = setTimeout(injectNextPhase, PHASE_GAP());
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [maxVisible]);

  useEffect(() => {
    if (!isStreaming) return;

    if (engineMode && worldStateRef.current) {
      // ENGINE MODE: pick a playbook and arm it; the benign tick fires phases
      const engineDelay = () => Math.floor(Math.random() * 60_000) + 540_000;
      const scheduleEngineAttack = () => {
        const world = worldStateRef.current!;
        startAttack(world, pickPlaybook(world));
        attackTimerRef.current = setTimeout(scheduleEngineAttack, engineDelay());
      };
      attackTimerRef.current = setTimeout(scheduleEngineAttack, engineDelay());
    } else {
      // STORY MODE: arm the first phase of the session story
      attackTimerRef.current = setTimeout(injectNextPhase, FIRST_PHASE_DELAY());
    }

    return () => {
      if (attackTimerRef.current) clearTimeout(attackTimerRef.current);
      if (missTimerRef.current)   clearTimeout(missTimerRef.current);
      if (missWatchdogRef.current) clearTimeout(missWatchdogRef.current);
      if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isStreaming, maxVisible, engineMode, injectNextPhase]);

  /** Arm a new story mid-session (second attack after the first completes) */
  const startStory = useCallback((next: AttackStory, delayMs?: number) => {
    storyRef.current = next;
    storyCursorRef.current = 0;
    if (attackTimerRef.current) clearTimeout(attackTimerRef.current);
    attackTimerRef.current = setTimeout(injectNextPhase, delayMs ?? ATTACK_COOLDOWN());
  }, [injectNextPhase]);

  const pause = useCallback(() => setIsStreaming(false), []);
  const resume = useCallback(() => setIsStreaming(true), []);

  const dismissIncident = useCallback(() => {
    setActiveIncident(null);
    activeIncidentRef.current = null;
  }, []);

  const clearMissedAttack = useCallback(() => { setMissedAttack(false); setMissedIncident(null); }, []);

  const clearLastAttackChain = useCallback(() => setLastAttackChain(null), []);

  const markCaught = useCallback((eventId: string) => {
    const incident = activeIncidentRef.current;
    if (!incident) return;
    if (incident.eventIds.includes(eventId)) {
      caughtRef.current = true;
      if (missTimerRef.current) {
        clearTimeout(missTimerRef.current);
        missTimerRef.current = null;
      }
      // A catch during the post-last-phase grace cancels the "missed" verdict.
      if (missWatchdogRef.current) { clearTimeout(missWatchdogRef.current); missWatchdogRef.current = null; }
      // Record catch speed + response time, then stop the response clock.
      if (attackInjectedAtRef.current !== null) {
        const elapsed = Date.now() - attackInjectedAtRef.current;
        catchSpeedMsRef.current.push(elapsed);
        attackInjectedAtRef.current = null;
        const all = catchSpeedMsRef.current;
        setAvgCatchMs(Math.round(all.reduce((a, b) => a + b, 0) / all.length));
        // This incident's response time — the coaching metric shown in the report.
        setLastResponseMs(elapsed);
      }
      // Count once per incident — guards against a double-call for the same catch.
      if (!countedIncidentIdsRef.current.has(incident.id)) {
        countedIncidentIdsRef.current.add(incident.id);
        setAttacksCaughtCount(c => c + 1);
      }
      if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
      setAttackTimerSeconds(null);
      // Capture the chain events for AttackChainBoard
      setEvents(current => {
        const chainEvents = current.filter(e => incident.eventIds.includes(e.id));
        if (chainEvents.length > 0) setLastAttackChain(chainEvents);
        return current;
      });
    }
  }, []);

  const reset = useCallback((pool?: TelemetryEvent[], newStory?: AttackStory | null) => {
    if (pool) poolRef.current = pool;
    // Clear pending timers
    if (attackTimerRef.current) { clearTimeout(attackTimerRef.current); attackTimerRef.current = null; }
    if (missTimerRef.current)   { clearTimeout(missTimerRef.current);   missTimerRef.current   = null; }
    if (missWatchdogRef.current){ clearTimeout(missWatchdogRef.current);missWatchdogRef.current = null; }
    // Arm the new session story (or keep the current one when omitted)
    if (newStory !== undefined) {
      storyRef.current = newStory;
      storyCursorRef.current = 0;
    }
    if (storyRef.current) {
      attackTimerRef.current = setTimeout(injectNextPhase, 120_000 + Math.floor(Math.random() * 60_000));
    }
    globalIdx.current = 15;
    activeIncidentRef.current = null;
    caughtRef.current = false;
    seenOnceRef.current = new Set(); // reset once-only tracking on company/pool switch
    const src = pool ?? poolRef.current;
    // Rebuild shuffle deck for the new pool (shuffled so initial 15 cover diverse sources)
    const srcShuffled = shuffleArray(src);
    buildDeck(srcShuffled);
    const now = Date.now();
    setEvents(srcShuffled.slice(0, 15).map((e, i) =>
      enrichWithFidelity(withRebasedTime(e, new Date(now - (14 - i) * 60_000).toISOString()), i)
    ).reverse());
    setSessionXp(0);
    setActiveIncident(null);
    setMissedAttack(false);
    setMissedIncident(null);
    setIsStreaming(true);
    setFnCount(0);
    setEventsOpenedCount(0);
    setAttacksCaughtCount(0);
    setAttacksPresentedCount(0);
    setAvgCatchMs(null);
    setLastResponseMs(null);
    setAttackTimerSeconds(null);
    setLastAttackChain(null);
    catchSpeedMsRef.current    = [];
    countedIncidentIdsRef.current = new Set();
    attackInjectedAtRef.current = null;
    sessionStartRef.current    = Date.now();
    if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const endSession = useCallback((): DashboardSessionRecord => {
    const record: DashboardSessionRecord = {
      type: "dashboard",
      date: new Date().toISOString(),
      xpEarned: sessionXp,
      detectRate: attacksPresentedCount > 0 ? Math.round((attacksCaughtCount / attacksPresentedCount) * 100) : 0,
      fnCount,
      avgCatchMs,
      attacksCaughtCount,
      attacksPresentedCount,
      eventsOpenedCount,
      durationMs: Date.now() - sessionStartRef.current,
    };
    // Persist through the storage facade → DB `dashboard_sessions` for signed-in
    // users, localStorage for guests (same "soc_dashboard_sessions" key). Uncapped
    // on purpose: remoteBackend's insert diff needs the array strictly append-only,
    // so a slice cap would silently drop DB inserts past it (persistence-migration
    // Stage 2). The backend is SSR-safe, so no window guard is needed.
    appendDashboardSession(record, Number.MAX_SAFE_INTEGER);
    return record;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionXp, fnCount, attacksCaughtCount, attacksPresentedCount, eventsOpenedCount, avgCatchMs]);

  const addXp = useCallback((xp: number) => {
    if (xp !== 0) setSessionXp(x => Math.max(0, x + xp));
  }, []);

  // Phase-1 telemetry (see ANALYST_TELEMETRY_PLAN.md): a simple running count
  // of distinct rows the student opened this session, before/around reaching
  // their verdict. Session-scoped rather than tightly bound to one incident —
  // per-incident scoping is a Phase 2 refinement.
  const recordEventOpened = useCallback(() => {
    setEventsOpenedCount(c => c + 1);
  }, []);

  return {
    events, isStreaming, sessionXp,
    newIds, activeIncident, dismissIncident, pause, resume, reset, startStory,
    missedAttack, missedIncident, clearMissedAttack, markCaught,
    attackTimerSeconds, lastResponseMs, responseTargetSeconds: SLA_SECONDS,
    fnCount, eventsOpenedCount, recordEventOpened,
    attacksCaughtCount, avgCatchMs, endSession,
    lastAttackChain, clearLastAttackChain, addXp,
  };
}
