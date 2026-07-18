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

export interface ActiveIncident {
  id: string;
  title: string;
  severity: "critical" | "high";
  injectedAt: number;     // Date.now()
  eventIds: string[];     // IDs of the injected attack events
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
  "T1566.001": "RULE_5715",   // Phishing attachment
  "T1059.001": "RULE_5912",   // PowerShell
  "T1059.003": "RULE_5906",   // cmd.exe
  "T1071.001": "RULE_3128",   // C2 HTTPS
  "T1204.002": "RULE_5720",   // User execution of malicious file
  "T1071.004": "RULE_1002",   // DNS tunneling
  "T1027":     "RULE_1102",   // Obfuscated files
  "T1218.011": "RULE_92300",  // Rundll32 LOLBin
  "T1547.001": "RULE_61116",  // Registry Run key
  "T1003.001": "RULE_61656",  // LSASS dump
  "T1110.003": "RULE_5452",   // Password spray
  "T1078":     "RULE_5501",   // Valid accounts
  "T1567.002": "RULE_9200",   // Exfil to cloud
  "T1486":     "RULE_99201",  // Ransomware encrypt
  "T1490":     "RULE_99202",  // VSS delete
  "T1070.001": "RULE_92511",  // Clear event logs
  "T1569.002": "RULE_92511",  // PsExec service
  "T1021.001": "RULE_5712",   // RDP lateral
  "T1098.005": "RULE_99301",  // OAuth app
  "T1530":     "RULE_99302",  // Cloud storage
  "T1114.002": "RULE_99303",  // Email collection
  "T1552.001": "RULE_99100",  // Credentials in files
  "T1048.003": "RULE_5560",   // Exfil over email
  "T1052.001": "RULE_5570",   // USB exfil
};

// Wazuh-style rule IDs by source + event_type (benign baseline)
const SOURCE_EVENT_RULE: Record<string, string> = {
  "ad:auth_success":        "RULE_18101",
  "ad:auth_failure":        "RULE_18102",
  "edr:process_create":     "RULE_92400",
  "edr:scheduled_task":     "RULE_60105",
  "edr:av_detection":       "RULE_53601",
  "sysmon:process_create":  "RULE_92400",
  "sysmon:file_create":     "RULE_92402",
  "sysmon:net_connection":  "RULE_92403",
  "sysmon:registry_set":    "RULE_92404",
  "dns:dns_query":          "RULE_82001",
  "firewall:net_connection":"RULE_40101",
  "vpn:vpn_login":          "RULE_72201",
  "vpn:vpn_logout":         "RULE_72202",
  "proxy:http_request":     "RULE_31100",
  "o365:email_received":    "RULE_91501",
  "o365:email_sent":        "RULE_91502",
  "o365:sharepoint_access": "RULE_91510",
  "o365:teams_message":     "RULE_91520",
  "cloudtrail:cloud_api_call":"RULE_80200",
};

// Known-benign domains that should never elevate level
const BENIGN_DOMAINS = new Set([
  "windowsupdate.microsoft.com", "login.microsoftonline.com", "teams.microsoft.com",
  "outlook.office365.com", "s3.amazonaws.com", "api.github.com", "zoom.us",
  "www.bbc.com", "stackoverflow.com", "www.linkedin.com", "app.docusign.com",
  "registry.npmjs.org", "www.googleapis.com",
]);

// Known-safe signed processes
const BENIGN_PROCS = new Set([
  "chrome.exe", "teams.exe", "outlook.exe", "excel.exe", "winword.exe", "word.exe",
  "onedrive.exe", "msmpeng.exe", "wuauclt.exe", "explorer.exe", "svchost.exe",
  "services.exe", "lsass.exe", "csrss.exe", "officeclick2run.exe", "officeclicktorun.exe",
]);

// LOLBins — medium-high suspicion depending on context
const LOLBINS = new Set([
  "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "certutil.exe",
  "bitsadmin.exe", "wmic.exe", "regasm.exe", "installutil.exe",
]);

export interface AnalystNotes {
  whatHappened: string;
  redFlags: string[];
  reportSnippet: string;
}

export function buildAnalystNotes(event: LiveEvent): AnalystNotes {
  const p    = event.process;
  const n    = event.network;
  const f    = event.file;
  const time = event.ts ? new Date(event.ts).toLocaleTimeString("en-GB", { hour12: false }) : "unknown time";
  const host = event.hostname ?? "unknown host";
  const user = event.user_email?.split("@")[0] ?? "unknown user";

  const redFlags: string[] = [];

  // ── Process-based red flags ───────────────────────────────────────────────
  if (p) {
    const name = (p.name ?? "").toLowerCase();
    const cmd  = (p.cmdline ?? "").toLowerCase();
    const parent = (p.parent_name ?? "").toLowerCase();

    if (cmd.includes("-encodedcommand") || cmd.includes(" -enc ")) redFlags.push("⚠ Base64-encoded command (-EncodedCommand)");
    if (cmd.includes("-windowstyle hidden") || cmd.includes("-w hidden"))  redFlags.push("⚠ Hidden window (-WindowStyle Hidden)");
    if (cmd.includes("bypass") && name === "powershell.exe")  redFlags.push("⚠ Execution policy bypass");
    if (cmd.includes("minidump") || cmd.includes("comsvcs"))  redFlags.push("⚠ LSASS memory dump technique");
    if (cmd.includes("delete shadows"))                        redFlags.push("⚠ Volume Shadow Copy deletion");
    if (cmd.includes("net user") && cmd.includes("/add"))      redFlags.push("⚠ New user account being created");

    const officeParents = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
    if (officeParents.includes(parent) && ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"].includes(name)) {
      redFlags.push(`⚠ Office app (${p.parent_name}) spawned ${p.name}`);
    }

    if (LOLBINS.has(name)) redFlags.push(`⚠ LOLBin: ${p.name} used as attack proxy`);
    if (name === "vssadmin.exe") redFlags.push("⚠ Shadow copy tool used");
    if (name === "psexec.exe" || name === "psexesvc.exe") redFlags.push("⚠ PsExec remote execution tool");
  }

  // ── Network-based red flags ───────────────────────────────────────────────
  if (n) {
    const domain = (n.domain ?? "").toLowerCase();
    if (!BENIGN_DOMAINS.has(domain) && domain.length > 0 && event.mitre_technique?.startsWith("T1071")) {
      redFlags.push(`⚠ C2 connection to: ${n.domain}`);
    }
    if (n.bytes_out && n.bytes_out > 5_000_000) redFlags.push(`⚠ Large outbound transfer: ${(n.bytes_out / 1_000_000).toFixed(1)} MB`);
  }

  // ── Auth-based red flags ──────────────────────────────────────────────────
  if (event.event_type === "auth_failure") redFlags.push("⚠ Authentication failure");
  if (event.mitre_technique === "T1110.003") redFlags.push("⚠ Pattern matches password spray attack");
  if (event.mitre_technique === "T1078") redFlags.push("⚠ Login from unusual geography");

  // ── File-based red flags ──────────────────────────────────────────────────
  if (f) {
    const ext = (f.path ?? "").split(".").pop()?.toLowerCase() ?? "";
    if (["exe", "dll", "bat", "ps1", "vbs", "js", "hta"].includes(ext) && f.path?.includes("\\Temp\\")) {
      redFlags.push(`⚠ Executable written to Temp folder: ${f.path?.split("\\").pop()}`);
    }
  }

  // ── Build "What happened here" ────────────────────────────────────────────
  let whatHappened = event.description ?? event.displayDescription ?? "No additional context available.";
  // Keep it to 2 sentences max
  const sentences = whatHappened.split(/(?<=[.!?])\s+/);
  if (sentences.length > 2) whatHappened = sentences.slice(0, 2).join(" ");

  // ── Build report snippet ──────────────────────────────────────────────────
  const mitre = event.mitre_technique ? ` (MITRE ${event.mitre_technique})` : "";
  const severity = (event.severity ?? "informational").toUpperCase();
  const source = (event.source ?? "unknown").toUpperCase();

  let reportSnippet: string;
  if (p && p.name) {
    reportSnippet = `At ${time}, ${p.name}${p.pid ? ` (PID ${p.pid})` : ""} was ${p.parent_name ? `spawned by ${p.parent_name} ` : ""}on host ${host}${event.user_email ? ` (user: ${user})` : ""}. Severity: ${severity}. Source: ${source}${mitre}. ${redFlags.length > 0 ? "Red flags: " + redFlags.map(r => r.replace("⚠ ", "")).join("; ") + "." : "No immediate red flags."}`;
  } else if (n) {
    reportSnippet = `At ${time}, ${source} detected a network event on host ${host}${event.user_email ? ` (user: ${user})` : ""}. Destination: ${n.domain ?? event.dst_ip ?? "unknown"}${event.dst_port ? `:${event.dst_port}` : ""}. Severity: ${severity}${mitre}. ${redFlags.length > 0 ? "Red flags: " + redFlags.map(r => r.replace("⚠ ", "")).join("; ") + "." : "No immediate red flags."}`;
  } else {
    reportSnippet = `At ${time}, ${source} logged a ${event.event_type.replace(/_/g, " ")} event on host ${host}${event.user_email ? ` (user: ${user})` : ""}. Severity: ${severity}${mitre}. ${redFlags.length > 0 ? "Red flags: " + redFlags.map(r => r.replace("⚠ ", "")).join("; ") + "." : "No immediate red flags."}`;
  }

  return { whatHappened, redFlags, reportSnippet };
}

function calculateRuleLevel(event: TelemetryEvent): number {
  const sev    = event.severity ?? "informational";
  const mitre  = event.mitre_technique ?? "";
  const proc   = event.process;
  const net    = event.network;
  const desc   = (event.description ?? "").toLowerCase();
  const raw    = event.raw ?? {} as Record<string, unknown>;

  // ── MITRE technique hard overrides ────────────────────────────────────────
  if (mitre) {
    if (["T1486", "T1490"].includes(mitre))           return 10; // ransomware / VSS
    if (["T1003.001", "T1003"].includes(mitre))       return 10; // LSASS dump
    if (["T1059.001"].includes(mitre))                return 9;  // PowerShell
    if (["T1071.001", "T1071.004"].includes(mitre))   return 9;  // C2 comms
    if (["T1055"].includes(mitre))                    return 9;  // Process injection
    if (["T1566.001"].includes(mitre))                return 8;  // Phishing
    if (["T1204.002"].includes(mitre))                return 8;  // User execution of malicious file
    if (["T1110.003", "T1110"].includes(mitre))       return 8;  // Spray
    if (["T1547.001"].includes(mitre))                return 8;  // Persistence
    if (["T1027", "T1218.011", "T1218.010"].includes(mitre)) return 8;  // Obfuscation/LOLBin
    if (["T1098.005", "T1098.001", "T1114.002", "T1114.001", "T1114.003", "T1530"].includes(mitre)) return 8; // Cloud / mailbox collection / forwarding
    if (["T1137.005"].includes(mitre))                return 8;  // Outlook rule persistence
    if (["T1569.002", "T1021.001", "T1021.002", "T1557.001"].includes(mitre)) return 8;  // Lateral / relay
    if (["T1070.001", "T1070"].includes(mitre))       return 8;  // Log clear
    if (["T1003.006"].includes(mitre))                return 9;  // DCSync
    if (["T1558.003", "T1558.004"].includes(mitre))   return 8;  // Kerberoasting / AS-REP
    if (["T1552.005", "T1552.001", "T1610", "T1611"].includes(mitre)) return 8; // IMDS / container escape / secrets
    if (["T1528", "T1136.003"].includes(mitre))       return 8;  // OAuth token / cloud account
    if (["T1621"].includes(mitre))                    return 7;  // MFA fatigue
    if (["T1078", "T1078.002", "T1078.004"].includes(mitre)) return 7;  // Valid accounts
    if (["T1048.003", "T1052.001", "T1041", "T1567", "T1567.002", "T1580", "T1087.002", "T1087.004", "T1496"].includes(mitre)) return 7; // Exfil / discovery / mining
  }

  // ── Process content analysis ───────────────────────────────────────────────
  if (proc) {
    const name = (proc.name ?? "").toLowerCase();
    const cmd  = (proc.cmdline ?? "").toLowerCase();

    // Critical command indicators
    if (cmd.includes("-encodedcommand") || cmd.includes(" -enc "))  return 10;
    if (cmd.includes("delete shadows"))                             return 10;
    if (cmd.includes("minidump") || cmd.includes("comsvcs"))       return 10;
    if (cmd.includes("cl security") || cmd.includes("cl system"))  return 9;
    if (cmd.includes("-windowstyle hidden") || cmd.includes("-w hidden")) return 9;
    if (cmd.includes("bypass") && name === "powershell.exe")       return 8;
    if (cmd.includes("invoke-mimikatz") || name === "mimikatz.exe") return 10;
    if (name === "psexec.exe" || name === "psexesvc.exe")           return 8;
    if (name === "vssadmin.exe")                                    return 9;
    if (name === "wevtutil.exe" && cmd.includes(" cl "))            return 8;

    // LOLBin usage → medium-high
    if (LOLBINS.has(name)) return Math.max(6, severityBase(sev));

    // Known-safe signed binaries → keep low
    if (BENIGN_PROCS.has(name) && !cmd.includes("bypass")) {
      return Math.min(2, severityBase(sev));
    }
  }

  // ── Network content analysis ──────────────────────────────────────────────
  if (net) {
    const domain = (net.domain ?? "").toLowerCase();
    if (BENIGN_DOMAINS.has(domain)) return 1;
  }

  // ── Event-type baseline (no MITRE / no suspicious content) ───────────────
  // These are the "quiet" defaults, but severity is always a FLOOR: a
  // high-severity event never displays a level that contradicts its severity
  // (e.g. a malicious mail-forward rule must not read as level 2).
  const floor = severityBase(sev);
  switch (event.event_type) {
    case "dns_query":
    case "vpn_logout":
    case "sharepoint_access":
    case "teams_message":
    case "scheduled_task":   return Math.max(1, floor);

    case "auth_failure":     return Math.max(3, floor);   // single failure = low
    case "mfa_denied":       return Math.max(5, floor);
    case "vpn_login":        return Math.max(2, floor);
    case "email_received":   return Math.max(2, floor);
    case "email_sent":       return Math.max(2, floor);
    case "registry_set":     return Math.max(2, floor);
    case "file_create":      return Math.max(2, floor);
  }

  // ── Fallback: severity → level ────────────────────────────────────────────
  return floor;
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
  return `RULE_${base}`;
}

function buildDescription(event: TelemetryEvent): string {
  // Prefer the event's own authored description — these are written as clear,
  // plain sentences for beginners and read far better than the verbose raw
  // Windows Event Viewer text (e.g. "The domain controller attempted to
  // validate the credentials for an account").
  if (event.description && event.description.trim().length > 12) return event.description;

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

  if (event.vendor?.includes("CrowdStrike") && !raw["cs.aid"]) {
    // Deterministic 32-hex agent id from hostname — same host, same aid, like a real Falcon sensor
    const host = event.hostname ?? "unknown-host";
    let h1 = 5381, h2 = 52711;
    for (let i = 0; i < host.length; i++) {
      h1 = ((h1 << 5) + h1 + host.charCodeAt(i)) >>> 0;
      h2 = ((h2 << 5) ^ h2 ^ host.charCodeAt(i)) >>> 0;
    }
    const hex = (n: number) => n.toString(16).padStart(8, "0");
    raw["cs.aid"] = `${hex(h1)}${hex(h2)}${hex(h1 ^ h2)}${hex((h1 + h2) >>> 0)}`;
    if (event.hostname && !raw["cs.ComputerName"]) raw["cs.ComputerName"] = event.hostname;
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
  intervalMs?: number;
  maxVisible?: number;
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
  /** Arm a new attack story mid-session (e.g. a second story after the first completes) */
  startStory: (story: AttackStory) => void;
  // Miss-detection
  missedAttack: boolean;
  clearMissedAttack: () => void;
  /** Register a real catch — called when the student's incident report passes.
   * Stops the SLA countdown, records catch speed, and prevents the miss-timer
   * from later (wrongly) counting this incident as missed. */
  markCaught: (eventId: string) => void;
  // SLA countdown (seconds remaining; null when no active attack)
  attackTimerSeconds: number | null;
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
  intervalMs = 40000,
  maxVisible = 100,
}: UseLiveEventsOptions): LiveEventsApi {
  // Engine mode: true when companyId is provided
  const engineMode = Boolean(companyId);
  // Start empty — populated in useEffect so SSR and client render the same HTML (avoids hydration mismatch)
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isStreaming, setIsStreaming]       = useState(true);
  const [sessionXp, setSessionXp]           = useState(0);
  const [newIds, setNewIds]                 = useState<Set<string>>(new Set());
  const [activeIncident, setActiveIncident] = useState<ActiveIncident | null>(null);
  const [missedAttack, setMissedAttack]     = useState(false);

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
          enrichWithFidelity({ ...e, ts: new Date(now - (14 - i) * 60_000).toISOString() }, i)
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
        enrichWithFidelity({ ...e, ts: new Date(now - (14 - i) * 60_000).toISOString() }, i)
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
          if (attackEvents && attackEvents.length > 0) {
            const isFP = world.attack?.isFP ?? false;
            const now  = Date.now();
            const raw  = attackEvents.map((g: GeneratedEvent, i: number) => ({
              ...generatedToTelemetry(g, globalIdx.current + i),
              ts: new Date(now + i * 4_000).toISOString(),
              id: `eng_atk_${now}_${i}`,
            }));
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
              setAttackTimerSeconds(SLA_SECONDS);
              if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
              slaIntervalRef.current = setInterval(() => {
                setAttackTimerSeconds(prev => {
                  if (prev === null || prev <= 1) {
                    if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
                    return null;
                  }
                  return prev - 1;
                });
              }, 1000);
              setActiveIncident(incident);
              if (missTimerRef.current) clearTimeout(missTimerRef.current);
              missTimerRef.current = setTimeout(() => {
                if (!caughtRef.current) {
                  setMissedAttack(true);
                  setFnCount(c => c + 1);
                  // No XP clawback: losing points for not clicking fast enough on
                  // a timer reads as a trap. The miss is surfaced as a debrief
                  // (see the "you missed one" banner) — a lesson, not a penalty.
                }
                if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
                setAttackTimerSeconds(null);
                missTimerRef.current = null;
              }, SLA_SECONDS * 1000);
            }

            setNewIds(batchIds);
            setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
            setTimeout(() => setNewIds(new Set()), 2000);
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
        const enriched = newRaw.map(e => enrichWithFidelity({ ...e, ts: new Date().toISOString() }, globalIdx.current++));
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
        newRaw.push({ ...chosen, ts: new Date().toISOString(), id: `${chosen.id}_${Date.now()}_${i}` });
      }

      const enriched = newRaw.map(e => enrichWithFidelity(e, globalIdx.current++));
      const batchIds  = new Set(enriched.map(e => e.id));
      setNewIds(batchIds);
      setEvents(prev => [...enriched, ...prev].slice(0, maxVisible));
      setTimeout(() => setNewIds(new Set()), 1500);
    }, intervalMs);

    return () => clearInterval(timer);
  }, [isStreaming, intervalMs, maxVisible, engineMode]);

  // ── Attack injection — Story Scheduler ───────────────────────────────────────
  // The session story's events are injected IN ORDER in small phases (2-3 events)
  // so the student watches a coherent kill-chain unfold: first phase within
  // ~2-3 minutes, then a new phase every 2-4 minutes until all events appeared.
  const FIRST_PHASE_DELAY = () => 120_000 + Math.floor(Math.random() * 60_000);   // 2-3 min
  const PHASE_GAP         = () => 120_000 + Math.floor(Math.random() * 120_000);  // 2-4 min

  // SLA detection window — how long the student has to classify the attack
  // once its first phase appears, before the miss penalty fires. Report
  // writing itself is untimed (the SLA is cleared the moment markCaught()
  // runs, well before the Incident Report modal opens).
  const SLA_SECONDS = 480; // 8 minutes

  const injectNextPhase = useCallback(() => {
    const s = storyRef.current;
    if (!s) return;
    const cursor = storyCursorRef.current;
    if (cursor >= s.events.length) return;

    const isFirstPhase = cursor === 0;
    const n = Math.min(s.events.length - cursor, 2 + (Math.random() < 0.5 ? 1 : 0)); // 2-3 events
    const now = Date.now();
    const slice = s.events.slice(cursor, cursor + n).map((e, i) => ({
      ...e,
      ts: new Date(now + i * 4_000).toISOString(),
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
      setAttackTimerSeconds(SLA_SECONDS);
      if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
      slaIntervalRef.current = setInterval(() => {
        setAttackTimerSeconds(prev => {
          if (prev === null || prev <= 1) { if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; } return null; }
          return prev - 1;
        });
      }, 1000);
      setActiveIncident(incident);
      if (missTimerRef.current) clearTimeout(missTimerRef.current);
      missTimerRef.current = setTimeout(() => {
        if (!caughtRef.current) { setMissedAttack(true); setFnCount(c => c + 1); } // no XP clawback — surfaced as a debrief, not a penalty
        if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
        setAttackTimerSeconds(null);
        missTimerRef.current = null;
      }, SLA_SECONDS * 1000);
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
      // Story fully injected — let the page arm the next one
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
      if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isStreaming, maxVisible, engineMode, injectNextPhase]);

  /** Arm a new story mid-session (second attack after the first completes) */
  const startStory = useCallback((next: AttackStory) => {
    storyRef.current = next;
    storyCursorRef.current = 0;
    if (attackTimerRef.current) clearTimeout(attackTimerRef.current);
    // Cool-down before the next campaign begins
    attackTimerRef.current = setTimeout(injectNextPhase, 240_000 + Math.floor(Math.random() * 120_000));
  }, [injectNextPhase]);

  const pause = useCallback(() => setIsStreaming(false), []);
  const resume = useCallback(() => setIsStreaming(true), []);

  const dismissIncident = useCallback(() => {
    setActiveIncident(null);
    activeIncidentRef.current = null;
  }, []);

  const clearMissedAttack = useCallback(() => setMissedAttack(false), []);

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
      // Record catch speed + stop SLA countdown
      if (attackInjectedAtRef.current !== null) {
        const elapsed = Date.now() - attackInjectedAtRef.current;
        catchSpeedMsRef.current.push(elapsed);
        attackInjectedAtRef.current = null;
        const all = catchSpeedMsRef.current;
        setAvgCatchMs(Math.round(all.reduce((a, b) => a + b, 0) / all.length));
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
      enrichWithFidelity({ ...e, ts: new Date(now - (14 - i) * 60_000).toISOString() }, i)
    ).reverse());
    setSessionXp(0);
    setActiveIncident(null);
    setMissedAttack(false);
    setIsStreaming(true);
    setFnCount(0);
    setEventsOpenedCount(0);
    setAttacksCaughtCount(0);
    setAttacksPresentedCount(0);
    setAvgCatchMs(null);
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
    if (typeof window !== "undefined") {
      const existing = JSON.parse(localStorage.getItem("soc_dashboard_sessions") ?? "[]") as DashboardSessionRecord[];
      localStorage.setItem("soc_dashboard_sessions", JSON.stringify([...existing, record].slice(-50)));
    }
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
    missedAttack, clearMissedAttack, markCaught,
    attackTimerSeconds, fnCount, eventsOpenedCount, recordEventOpened,
    attacksCaughtCount, avgCatchMs, endSession,
    lastAttackChain, clearLastAttackChain, addXp,
  };
}
