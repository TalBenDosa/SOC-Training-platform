/**
 * Display enrichment for live-feed events (rule level / rule id / description,
 * progressive-fidelity noise) and the feed's shuffle/timing helpers.
 *
 * Split out of useLiveEvents.ts (QA phase 6, SEC-01) so the TEAM room can render
 * feed rows without importing the single-player simulation engine — whose attack
 * templates carry expected_verdict / fp_explanation — into its client bundle.
 * Keep this module free of engine / story / storage imports.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { getRuleDescription } from "@/lib/sim/ruleDescriptions";
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { describeEvent } from "@/lib/sim/describeEvent";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

// ─── Display-enriched event ───────────────────────────────────────────────────

export interface LiveEvent extends TelemetryEvent {
  ruleLevel: number;                                    // 3-15 Wazuh-style (see LEVEL_BANDS)
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

// Windows events get a rule per EVENT ID, not per source:event_type — otherwise a network logon, an
// RDP logon, a Kerberos ticket and a GPO change all fire one rule id and "filter by rule / tune this
// rule" becomes unteachable (Tal's diagnostic). Keyed on the real Event ID.
const WINSEC_EVENT_RULE: Record<string, string> = {
  "4624": "HTS-18101", "4625": "HTS-18102", "4634": "HTS-18103", "4647": "HTS-18104", "4648": "HTS-18110",
  "4672": "HTS-18120", "4688": "HTS-18200", "4697": "HTS-18210", "7045": "HTS-18211",
  "4768": "HTS-18300", "4769": "HTS-18301", "4771": "HTS-18302", "4776": "HTS-18303",
  "4720": "HTS-18400", "4722": "HTS-18401", "4724": "HTS-18402", "4725": "HTS-18403", "4726": "HTS-18404",
  "4738": "HTS-18405", "4740": "HTS-18410", "4767": "HTS-18411",
  "4728": "HTS-18420", "4732": "HTS-18421", "4756": "HTS-18422", "4729": "HTS-18423", "4733": "HTS-18424", "4757": "HTS-18425",
  "4662": "HTS-18500", "5136": "HTS-18510", "5140": "HTS-18520", "5145": "HTS-18521",
  "4698": "HTS-18211", "1102": "HTS-18600", "4719": "HTS-18601",
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
  // Owner rule (2026-10-06, after the team-training review): Wazuh's real 0-15 scale, used
  // 3-15 here — nothing a SOC is shown sits below 3. Each severity owns a band; WHICH level in
  // the band is fixed per RULE (source + event type), never per event, so one rule always fires
  // at one level (E-08) and the level still tracks severity identically for attack and noise (L-06).
  const sev = event.severity ?? "informational";
  const [lo, hi] = LEVEL_BANDS[sev] ?? LEVEL_BANDS.informational;
  const ruleKey = `${event.source ?? ""}|${event.event_type ?? ""}`;
  let h = 0; for (const c of ruleKey) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return lo + (h % (hi - lo + 1));
}

/** Rule-level band per severity on the 3-15 scale (Wazuh-style). */
export const LEVEL_BANDS: Record<string, [number, number]> = {
  informational: [3, 4],
  low:           [5, 6],
  medium:        [7, 9],
  high:          [10, 12],
  critical:      [13, 15],
};
/** Display thresholds shared by every view (feed filter, stats, situation board). */
export const LEVEL_MEDIUM_MIN = 7;
export const LEVEL_HIGH_MIN = 10;
/** Severity bucket of a rule level — the inverse of LEVEL_BANDS. */
export function levelBucket(level: number): "critical" | "high" | "medium" | "low" | "informational" {
  return level >= 13 ? "critical" : level >= LEVEL_HIGH_MIN ? "high" : level >= LEVEL_MEDIUM_MIN ? "medium" : level >= 5 ? "low" : "informational";
}

/** Lowest level of a severity's band — for events built without a rule identity. */
export function severityBase(sev: string): number {
  return (LEVEL_BANDS[sev] ?? LEVEL_BANDS.informational)[0];
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
export function jitteredOffset(k: number): number {
  let ms = 0, seed = 0x9e3779b9 >>> 0;
  for (let j = 0; j < k; j++) { seed = Math.imul(seed + j + 1, 2654435761) >>> 0; ms += 20_000 + (seed % 80_000); }
  return ms;
}

// Per-source ingestion delay — the characteristic lag between an action and its
// log landing in the SIEM. Spreads one incident's events across minutes and out of
// strict order, so building the timeline is a genuine skill, not a sort.
export function ingestionDelayMs(source: string): number {
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

export function buildRuleId(event: TelemetryEvent, index: number): string {
  // Pick the base rule that matched (technique → source/event_type → fallback).
  let base: string;
  const eventCode = String(event.raw?.["event.code"] ?? event.raw?.["winlog.event_id"] ?? "");
  const isWinSec = event.source === "ad" || event.source === "windows_security";
  if (event.mitre_technique && RULE_ID_MAP[event.mitre_technique]) {
    base = RULE_ID_MAP[event.mitre_technique];
  } else if (isWinSec && WINSEC_EVENT_RULE[eventCode]) {
    base = WINSEC_EVENT_RULE[eventCode];
  } else {
    const sourceKey = `${event.source}:${event.event_type}`;
    base = SOURCE_EVENT_RULE[sourceKey] ?? `HTS-${60000 + (index % 9000)}`;
  }
  // E-08: a rule's level is a property of the RULE, not the event — one rule id must
  // never fire at two levels, or "filter by rule id" and "how often did this rule
  // fire" return nonsense. But L-06 requires the LEVEL to track severity (so a high
  // level appears on high-severity NOISE too, not only attacks). We reconcile both by
  // making the level part of the rule identity, Wazuh child-rule style: a generic
  // process-creation that matches at high severity is a distinct child rule from the
  // same base at low severity (e.g. HTS-92400.8 vs HTS-92400.1). The level column and
  // the rule id now agree, and the level still isn't attack-exclusive.
  return `${base}.${calculateRuleLevel(event)}`;
}


// ─── Shuffle deck helpers (no-duplicate event rotation) ───────────────────────

/**
 * Extract the pool of regular (non-service) user emails from the event pool.
 * Used to rotate users across deck cycles so the feed never looks repetitive.
 */
export function extractDomainUsers(pool: TelemetryEvent[]): string[] {
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
export function applyUserVariant(event: TelemetryEvent, cycle: number, users: string[]): TelemetryEvent {
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

export function shuffleArray<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export const isOnceOnly = (e: TelemetryEvent) =>
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
export function injectAdvancedFidelityNoise(raw: Record<string, unknown>, event: TelemetryEvent): void {
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
  // A technique-specific rule only where a product would tag the technique (QA H1).
  const tagged = mitreVisible(event) ? event.mitre_technique : undefined;
  const ruleDesc = getRuleDescription(event.event_type, tagged, eventCode, o365Op);

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
    // WorkstationName is the SOURCE workstation. For a network logon (Type 3) from
    // an external IP the origin host is unknown → leave it "-" and record the target
    // host as ComputerName; only stamp the local host for interactive/local logons.
    const logonType = String(raw["winlog.event_data.LogonType"] ?? "");
    if (event.hostname && !raw["winlog.computer_name"]) {
      raw["winlog.computer_name"] = event.hostname;
    }
    if (!raw["winlog.event_data.WorkstationName"]) {
      raw["winlog.event_data.WorkstationName"] = logonType === "3" ? "-" : (event.hostname ?? "-");
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
    // Guard: don't clobber an authored SubjectUserName (e.g. the DC computer account).
    if (!raw["winlog.event_data.SubjectUserName"]) raw["winlog.event_data.SubjectUserName"] = "SYSTEM";
    if (!raw["winlog.event_data.SubjectDomainName"]) raw["winlog.event_data.SubjectDomainName"] = "NT AUTHORITY";
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
    // Inbox-rule / mailbox operations are Exchange admin events, not Azure AD —
    // even though we model them as `account_modify`.
    const op = String(raw["data.office365.Operation"] ?? o365Op ?? "");
    const isExchangeAdminOp = /InboxRule|Mailbox|TransportRule/i.test(op);
    const isAzureAD = !isExchangeAdminOp && (event.event_type === "auth_success" || event.event_type === "auth_failure"
      || event.event_type === "mfa_challenge" || event.event_type === "mfa_denied"
      || event.event_type === "account_modify" || event.event_type === "account_create"
      || event.event_type === "account_delete" || event.event_type === "group_modify");
    const isExchange = isExchangeAdminOp || event.event_type === "email_received" || event.event_type === "email_sent";
    const isSharePoint = event.event_type === "sharepoint_access";
    raw["data.office365.Workload"] = isExchange ? "Exchange"
      : isAzureAD ? "AzureActiveDirectory"
      : isSharePoint ? "SharePoint"
      : "AzureActiveDirectory";
    raw["data.office365.RecordType"] = isExchangeAdminOp ? "1" : isAzureAD ? "15" : isExchange ? "2" : isSharePoint ? "6" : "15";
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

  // One PAN-OS field convention only — flat panw.* (matches the field registry;
  // avoids a second panw.panos.* schema on the same event).
  if (event.source === "firewall" && event.vendor?.includes("Palo Alto") && !raw["panw.type"]) {
    const isThreat = event.severity === "medium" || event.severity === "high" || event.severity === "critical";
    raw["panw.type"] = isThreat ? "THREAT" : "TRAFFIC";
    if (!raw["event.action"]) raw["event.action"] = event.event_type.includes("block") ? "deny" : "allow";
    raw["panw.source_zone"]      = isPrivateIp(event.src_ip) ? "trust" : "untrust";
    raw["panw.destination_zone"] = isPrivateIp(event.dst_ip) ? "trust" : "untrust";
    if (raw["rule.name"] && !raw["panw.rule"]) raw["panw.rule"] = String(raw["rule.name"]);
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
  // The deterministic IP→location map lives in @/lib/geo/resolveGeo so the
  // threat-intel pivot resolves the SAME country/city as the feed (one IP → one
  // place, never a per-view divergence).
  if (!raw["GeoLocation.country_name"]) {
    if (event.geo) {
      if (event.geo.country) raw["GeoLocation.country_name"] = event.geo.country;
      if (event.geo.city)    raw["GeoLocation.city_name"]    = event.geo.city;
      if (event.geo.latitude  != null) raw["GeoLocation.location.lat"] = event.geo.latitude;
      if (event.geo.longitude != null) raw["GeoLocation.location.lon"] = event.geo.longitude;
    } else if (event.src_ip) {
      const geo = knownGeoForIp(event.src_ip);
      if (geo) {
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
    ruleId: buildRuleId(tagged === event.mitre_technique ? event : { ...event, mitre_technique: undefined }, index),
    displayDescription: describeEvent(event),
  };
}
