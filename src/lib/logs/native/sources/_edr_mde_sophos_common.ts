/**
 * Helpers shared by the `mde` and `sophos` native modules (not a source module itself).
 *
 * - A small MITRE ATT&CK reference (technique id → name + primary tactic) covering every
 *   technique id the EDR corpus uses, so products that print technique NAMES (Defender
 *   `AttackTechniques`, Sophos `mitreAttacks[]`) can be rendered from an authored id.
 * - Local corrections for two edrFacts() misreads (reported, edr-normalize.ts not edited):
 *   doubled image paths and "allowed / not_quarantined" read as quarantined.
 * - IP classification and Windows identity helpers.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";
import type { EdrFacts } from "./edr-normalize";

export const TACTICS: Record<string, { id: string; token: string }> = {
  "Initial Access": { id: "TA0001", token: "InitialAccess" },
  "Execution": { id: "TA0002", token: "Execution" },
  "Persistence": { id: "TA0003", token: "Persistence" },
  "Privilege Escalation": { id: "TA0004", token: "PrivilegeEscalation" },
  "Defense Evasion": { id: "TA0005", token: "DefenseEvasion" },
  "Credential Access": { id: "TA0006", token: "CredentialAccess" },
  "Discovery": { id: "TA0007", token: "Discovery" },
  "Lateral Movement": { id: "TA0008", token: "LateralMovement" },
  "Collection": { id: "TA0009", token: "Collection" },
  "Exfiltration": { id: "TA0010", token: "Exfiltration" },
  "Command and Control": { id: "TA0011", token: "CommandAndControl" },
  "Impact": { id: "TA0040", token: "Impact" },
};

/** Technique id → [sub-technique / technique name, primary tactic] (MITRE ATT&CK Enterprise). */
export const TECHNIQUES: Record<string, [string, string]> = {
  "T1003.001": ["LSASS Memory", "Credential Access"],
  "T1003.002": ["Security Account Manager", "Credential Access"],
  "T1003.003": ["NTDS", "Credential Access"],
  "T1021.001": ["Remote Desktop Protocol", "Lateral Movement"],
  "T1021.002": ["SMB/Windows Admin Shares", "Lateral Movement"],
  "T1021.004": ["SSH", "Lateral Movement"],
  "T1027": ["Obfuscated Files or Information", "Defense Evasion"],
  "T1027.006": ["HTML Smuggling", "Defense Evasion"],
  "T1036.005": ["Match Legitimate Resource Name or Location", "Defense Evasion"],
  "T1039": ["Data from Network Shared Drive", "Collection"],
  "T1041": ["Exfiltration Over C2 Channel", "Exfiltration"],
  "T1048": ["Exfiltration Over Alternative Protocol", "Exfiltration"],
  "T1052.001": ["Exfiltration over USB", "Exfiltration"],
  "T1053.003": ["Cron", "Persistence"],
  "T1053.005": ["Scheduled Task", "Persistence"],
  "T1055.001": ["Dynamic-link Library Injection", "Defense Evasion"],
  "T1056.001": ["Keylogging", "Collection"],
  "T1057": ["Process Discovery", "Discovery"],
  "T1059.001": ["PowerShell", "Execution"],
  "T1059.002": ["AppleScript", "Execution"],
  "T1059.003": ["Windows Command Shell", "Execution"],
  "T1059.004": ["Unix Shell", "Execution"],
  "T1070": ["Indicator Removal", "Defense Evasion"],
  "T1070.001": ["Clear Windows Event Logs", "Defense Evasion"],
  "T1070.004": ["File Deletion", "Defense Evasion"],
  "T1071.004": ["DNS", "Command and Control"],
  "T1074.001": ["Local Data Staging", "Collection"],
  "T1083": ["File and Directory Discovery", "Discovery"],
  "T1087.002": ["Domain Account", "Discovery"],
  "T1105": ["Ingress Tool Transfer", "Command and Control"],
  "T1115": ["Clipboard Data", "Collection"],
  "T1134.001": ["Token Impersonation/Theft", "Privilege Escalation"],
  "T1176": ["Browser Extensions", "Persistence"],
  "T1195.001": ["Compromise Software Dependencies and Development Tools", "Initial Access"],
  "T1195.002": ["Compromise Software Supply Chain", "Initial Access"],
  "T1197": ["BITS Jobs", "Defense Evasion"],
  "T1204.002": ["Malicious File", "Execution"],
  "T1204.004": ["Malicious Copy and Paste", "Execution"],
  "T1218.005": ["Mshta", "Defense Evasion"],
  "T1218.010": ["Regsvr32", "Defense Evasion"],
  "T1218.011": ["Rundll32", "Defense Evasion"],
  "T1219": ["Remote Access Software", "Command and Control"],
  "T1485": ["Data Destruction", "Impact"],
  "T1486": ["Data Encrypted for Impact", "Impact"],
  "T1490": ["Inhibit System Recovery", "Impact"],
  "T1496": ["Resource Hijacking", "Impact"],
  "T1505.003": ["Web Shell", "Persistence"],
  "T1539": ["Steal Web Session Cookie", "Credential Access"],
  "T1547.001": ["Registry Run Keys / Startup Folder", "Persistence"],
  "T1550.002": ["Pass the Hash", "Lateral Movement"],
  "T1552.001": ["Credentials In Files", "Credential Access"],
  "T1552.005": ["Cloud Instance Metadata API", "Credential Access"],
  "T1553.005": ["Mark-of-the-Web Bypass", "Defense Evasion"],
  "T1555.003": ["Credentials from Web Browsers", "Credential Access"],
  "T1557.001": ["LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access"],
  "T1558.004": ["AS-REP Roasting", "Credential Access"],
  "T1560.001": ["Archive via Utility", "Collection"],
  "T1562.001": ["Disable or Modify Tools", "Defense Evasion"],
  "T1565.001": ["Stored Data Manipulation", "Impact"],
  "T1566.001": ["Spearphishing Attachment", "Initial Access"],
  "T1567.002": ["Exfiltration to Cloud Storage", "Exfiltration"],
  "T1611": ["Escape to Host", "Privilege Escalation"],
};

/** Technique name: the table, else the sub-technique part of an authored "Parent: Sub" name. */
export function techniqueName(id?: string, authored?: string): string | undefined {
  if (id && TECHNIQUES[id]) return TECHNIQUES[id][0];
  if (authored) return authored.includes(":") ? authored.split(":").pop()!.trim() : authored;
  return undefined;
}

/** Tactic name of a detection: authored, else the technique's primary tactic. */
export function tacticOf(f: EdrFacts): string | undefined {
  const t = f.detection?.tactic;
  if (t && TACTICS[t]) return t;
  const id = f.detection?.techniqueId;
  if (id && TECHNIQUES[id]) return TECHNIQUES[id][1];
  return t;
}

/** A path whose last two segments repeat ("…\\cmd.exe\\cmd.exe") — an edrFacts misread when
 *  the legacy FolderPath already contained the file name. */
export function fixPath(p?: string): string | undefined {
  if (!p) return p;
  const m = /^(.*)[\\/]([^\\/]+)[\\/]([^\\/]+)$/.exec(p);
  if (m && m[2].toLowerCase() === m[3].toLowerCase()) return `${m[1]}${p.includes("\\") ? "\\" : "/"}${m[2]}`;
  return p;
}
export const baseOf = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
export const dirOf = (p?: string) => (p && /[\\/]/.test(p) ? p.replace(/[\\/][^\\/]+$/, "") : undefined);

/**
 * Remediation actually taken. edrFacts.actionOf() reads `quarantine.status: "not_quarantined"`
 * as "quarantined" (substring match) — corrected here when the legacy fields say the file
 * was allowed / not quarantined.
 */
export function effectiveAction(ev: TelemetryEvent, f: EdrFacts): "killed" | "quarantined" | "blocked" | "detected" {
  const a = f.detection?.action ?? "detected";
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const q = String(r["quarantine.status"] ?? "").toLowerCase();
  const res = String(r["action_result"] ?? "").toLowerCase();
  if (a === "quarantined" && (/^not[_ ]/.test(q) || res === "allowed")) return "detected";
  return a;
}

/** Image identity of a process (name from path, else the first token of the authored command line). */
export function imageName(p: { name?: string; path?: string; cmdline?: string }): string | undefined {
  if (p.name) return p.name;
  const fromPath = baseOf(fixPath(p.path));
  if (fromPath) return fromPath;
  if (p.cmdline) {
    const tok = p.cmdline.trim().match(/^"([^"]+)"|^(\S+)/);
    const t = tok ? (tok[1] ?? tok[2]) : undefined;
    return baseOf(t);
  }
  return undefined;
}

// ── IPs ─────────────────────────────────────────────────────────────────────
const v4 = (ip?: string) => (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip.split(".").map(Number) : null);
export function isPrivate(ip?: string): boolean {
  const o = v4(ip);
  if (!o) return false;
  return o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168);
}
/** Defender LocalIPType / RemoteIPType vocabulary. */
export function ipType(ip?: string): string | null {
  const o = v4(ip);
  if (!o) return ip && ip.includes(":") ? (ip === "::1" ? "Loopback" : "Public") : null;
  if (o[0] === 127) return "Loopback";
  if (isPrivate(ip)) return "Private";
  if (o[0] === 255 && o[1] === 255) return "Broadcast";
  if (o[0] === 169 && o[1] === 254) return "Reserved";
  if (o[0] === 0 || o[0] >= 224) return "Reserved";
  return "Public";
}

// ── Identity ────────────────────────────────────────────────────────────────
const SYSTEM_USERS = new Set(["system", "local service", "network service"]);
export const isSystemUser = (u?: string) => !!u && SYSTEM_USERS.has(u.toLowerCase());
/** Stable domain SID for a user of the company (well-known SID for SYSTEM). */
export function userSid(ctx: NativeCtx, user?: string): string | null {
  if (!user) return null;
  const u = user.toLowerCase();
  if (u === "system") return "S-1-5-18";
  if (u === "local service") return "S-1-5-19";
  if (u === "network service") return "S-1-5-20";
  const dom = [0, 1, 2].map(i => ctx.int(`${ctx.companyId}:domsid:${i}`, 1_000_000_000, 3_999_999_999)).join("-");
  return `S-1-5-21-${dom}-${ctx.int(`${ctx.companyId}:rid:${u}`, 1100, 9999)}`;
}

/** ISO timestamp with N fractional digits (ms from the event, extra digits deterministic). */
export function isoFrac(ms: number, digits: 0 | 3 | 7, ctx: NativeCtx, seed: string): string {
  const iso = new Date(ms).toISOString(); // yyyy-mm-ddThh:mm:ss.mmmZ
  if (digits === 0) return `${iso.slice(0, 19)}Z`;
  if (digits === 3) return iso;
  return `${iso.slice(0, 23)}${String(ctx.int(seed, 0, 9999)).padStart(4, "0")}Z`;
}

/** Hostname-prefix device class used for Defender MachineGroup / Sophos endpoint_type. */
export function isServer(host: string): boolean {
  return /^(srv|dc|sql|web|app|db|fs|file|exch|ad)[-_\d]/i.test(host) || /-dc\d|dc\d\d/i.test(host) || /^SRV/i.test(host);
}
