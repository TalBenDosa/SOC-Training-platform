/**
 * Benign-positive alerts for the team feed (expert review P0-1): the everyday alerts a SOC closes
 * as false positives. Without them every high-severity row was an attack and a Tier-1 could score
 * by badge alone.
 *
 * 2026-11-07 (owner + expert review of two exercises): the same five makers (scan, PsExec, backup,
 * travel, SCCM) ran in both exercises, an approved ticket sat right before every one of them, the
 * scan was raised on a random server with an unrelated address and two decoys landed on one person.
 * Now:
 *  - a CATALOGUE of makers in many kinds (one maker per kind per session), each modelled on what
 *    the real product raises and benign once investigated;
 *  - every parameter (host, person, tool among real equivalents, command-line form, paths, file
 *    names, sizes, counts, cities, addresses) drawn from the session's own stream;
 *  - one asset record per scanner (its host, its address, its ticket's CI agree);
 *  - one person and one host per maker, never an attack victim or an attacked host;
 *  - a ticket is OPTIONAL evidence: some makers are proven by the device, the account or the
 *    destination instead, and the timeline adds unrelated ITSM rows and varies when a ticket
 *    lands (itsmNoise.ts, buildTimeline.ts). A `miss` variant authors a ticket that does NOT cover
 *    the activity (another host, another scope or a window that has closed): that alert is
 *    escalate, not FP.
 *
 * Every alert comes from a product the session runs: EDR detections are authored as Defender for
 * Endpoint and relabelled to the session's EDR (applyStack); identity sign-ins as Entra ID
 * (relabelled to Okta in an Okta shop); SIEM analytics only when the organization runs Sentinel
 * (`siem`); the rest only when the resolved stack has the product (`fits` per maker), and the
 * caller drops anything the chosen product has no record for (fitsStack).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets, RosterUser } from "@/lib/sim/companyProfilesMeta";
import type { Stack } from "@/lib/logs/native/stack";
import { intIn, pickOf, rankByHistory, shuffled, docIp } from "./variety";

/** A ServiceNow record the timeline places near the alert it explains (or fails to explain). */
export interface TicketSpec {
  table: "change_request" | "sc_req_item" | "incident";
  number: string;
  state: string;
  short: string;
  ci?: string;
  assignedTo?: string;
  requestedFor?: string;
  group?: string;
  workNotes?: string;
  /** change_request: the approved window in minutes around the alert's time (start < end). */
  window?: [number, number];
}

export interface FpOut {
  makerId: string;
  kind: string;
  /** The alert row (and any rows that sit with it, e.g. the VPN failures before a lockout). */
  rows: TelemetryEvent[];
  ticket?: TicketSpec;
  /** fp: benign once investigated; escalate: the ticket does not cover it (miss variant). */
  verdict: "fp" | "escalate";
  person?: string;
  host?: string;
}

/** What a session already uses: the makers must not land on these people / hosts. */
export interface FpAvoid { users?: Set<string>; hosts?: Set<string>; ips?: Set<string> }

interface Person { name: string; email: string; host: string; title: string }
interface Ctx {
  assets: CompanyAssets; companyId: string; rnd: () => number; ts: string; n: number;
  stack: Stack; siem: boolean; platforms: Set<string>; miss: boolean;
  person: (re?: RegExp) => Person | null;
  workstation: () => string | null;
  server: () => string | null;
  ips: Set<string>;
  scanner: { host: string; ip: string; product: string; account: string };
}
interface Maker {
  id: string;
  kind: string;
  siemOnly?: boolean;
  /** Can author a ticket that does not cover the activity (the miss variant). */
  canMiss?: boolean;
  fits?: (c: Ctx) => boolean;
  make: (c: Ctx) => FpOut | null;
}

const mail = (a: CompanyAssets, name: string) => `${name}@${a.domain}`;
const isServer = (h: string) => /^(SRV|SVR|DC)-|-SRV-|prod-srv|-DC\d/i.test(h);
const num = (prefix: string, c: Ctx) => `${prefix}00${intIn(30000, 69999, c.rnd)}`;
const hex = (c: Ctx, n: number) => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(c.rnd() * 16)]).join("");
const guid = (c: Ctx) => `${hex(c, 8)}-${hex(c, 4)}-4${hex(c, 3)}-${pickOf(["8", "9", "a", "b"], c.rnd)}${hex(c, 3)}-${hex(c, 12)}`;
const sizeOf = (loMb: number, hiMb: number, c: Ctx) => intIn(loMb, hiMb, c.rnd) * 1_048_576 + intIn(0, 1_048_575, c.rnd);
const ITGROUPS = ["Service Desk", "Windows Server Team", "End User Computing", "Infrastructure Operations", "Identity and Access"];
const IT_RE = /\bit\b|devops|admin|infra|sre|security|systems|network|support/i;
const DEV_RE = /develop|engineer|devops|sre|backend|frontend|quant/i;

/** A Microsoft Sentinel analytics alert (SecurityAlert schema). */
function sentinelAlert(o: { id: string; ts: string; name: string; severity: "high" | "medium"; host?: string; user?: string; ip?: string;
  props: Record<string, string>; fp: string; mitre?: string; mcas?: boolean; tactic?: string }): TelemetryEvent {
  const raw: Record<string, unknown> = { AlertName: o.name, ProductName: o.mcas ? "Microsoft Cloud App Security" : "Azure Sentinel", ProviderName: o.mcas ? "MCAS" : "ASI Scheduled Alerts",
    AlertSeverity: o.severity === "high" ? "High" : "Medium", Status: "New", TimeGenerated: o.ts, "event.action": "alert",
    ...(o.tactic ? { Tactics: o.tactic } : {}), ...(o.host ? { CompromisedEntity: o.host } : {}) };
  if (o.host) raw["Entities.Host.HostName"] = o.host;
  if (o.user) { const [n, d] = o.user.split("@"); raw["Entities.Account.Name"] = n; raw["Entities.Account.UPNSuffix"] = d; }
  if (o.ip) raw["Entities.IP.Address"] = o.ip;
  for (const [k, v] of Object.entries(o.props)) raw[`ExtendedProperties.${k}`] = v;
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: "Microsoft Sentinel", event_type: "risk_score_change", severity: o.severity,
    is_detection: true, expected_verdict: "fp", fp_explanation: o.fp, ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.host ? { hostname: o.host } : {}), ...(o.user ? { user_email: o.user } : {}), ...(o.ip ? { src_ip: o.ip } : {}),
    description: `Sentinel raised "${o.name}"`, raw,
  } as TelemetryEvent;
}

/** An EDR detection, authored as Defender for Endpoint and relabelled to the session's EDR. */
function edrDetection(o: { id: string; ts: string; host: string; userEmail?: string; severity: "high" | "medium" | "low";
  process: NonNullable<TelemetryEvent["process"]>; category: string; description: string; fp: string; mitre: string; extra?: Record<string, unknown> }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "edr", event_type: "process_create", severity: o.severity, vendor: "Microsoft Defender for Endpoint",
    hostname: o.host, ...(o.userEmail ? { user_email: o.userEmail } : {}), is_detection: true,
    expected_verdict: "fp", fp_explanation: o.fp, mitre_technique: o.mitre, description: o.description,
    process: o.process,
    raw: { Category: o.category, action_result: "allowed", "process.name": o.process.name, ...(o.extra ?? {}) },
  } as TelemetryEvent;
}

/**
 * An Entra ID interactive sign-in (the shape the travel alert always used; relabelled in an Okta shop).
 * The alert is Entra ID Protection's, so the sign-in carries the risk detection that raised it, as the
 * real SigninLogs row does (riskLevelDuringSignIn, riskEventTypes_v2, riskState).
 */
function entraSignIn(o: { id: string; ts: string; user: string; ip: string; city: string; country: string; lat: number; lon: number;
  description: string; fp: string; risk: { level: "low" | "medium"; detection: "unfamiliarFeatures" | "anonymizedIPAddress" } }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "o365", event_type: "auth_success", severity: "medium", vendor: "Microsoft Entra ID",
    user_email: o.user, src_ip: o.ip, is_detection: true, expected_verdict: "fp", fp_explanation: o.fp, description: o.description,
    raw: {
      "data.office365.Operation": "UserLoggedIn", "data.office365.Workload": "AzureActiveDirectory",
      "data.office365.AzureActiveDirectoryEventType": "AccountLogon", "data.office365.UserId": o.user,
      "data.office365.ActorIpAddress": o.ip, "data.office365.ClientIP": o.ip, "data.office365.ResultStatus": "Succeeded",
      "GeoLocation.country_name": o.country, "GeoLocation.city_name": o.city, "GeoLocation.location.lat": o.lat, "GeoLocation.location.lon": o.lon,
      "azure.signinlogs.properties.riskLevelDuringSignIn": o.risk.level, "azure.signinlogs.properties.riskEventTypes_v2": [o.risk.detection],
      "azure.signinlogs.properties.riskState": "atRisk",
      action_result: "allowed",
    },
  } as TelemetryEvent;
}

/** escalate instead of FP: the ticket the analyst finds does not cover what happened. */
function asMiss(ev: TelemetryEvent, message: string): void {
  delete ev.fp_explanation;
  ev.expected_verdict = "escalate";
  ev.it_context = { result: "unverified", message };
}

const CITIES: [string, string, number, number][] = [
  ["Munich", "Germany", 48.1351, 11.582], ["Lisbon", "Portugal", 38.7223, -9.1393], ["Warsaw", "Poland", 52.2297, 21.0122],
  ["Madrid", "Spain", 40.4168, -3.7038], ["Copenhagen", "Denmark", 55.6761, 12.5683], ["Dublin", "Ireland", 53.3498, -6.2603],
  ["Milan", "Italy", 45.4642, 9.19], ["Vienna", "Austria", 48.2082, 16.3738], ["Toronto", "Canada", 43.6532, -79.3832],
  ["Singapore", "Singapore", 1.3521, 103.8198], ["Stockholm", "Sweden", 59.3293, 18.0686], ["Prague", "Czechia", 50.0755, 14.4378],
];
const PROXY_NODES: [string, string, string, number, number][] = [
  ["Zscaler", "Frankfurt", "Germany", 50.1109, 8.6821], ["Zscaler", "Amsterdam", "Netherlands", 52.3676, 4.9041],
  ["Netskope", "Paris", "France", 48.8566, 2.3522], ["Netskope", "Zurich", "Switzerland", 47.3769, 8.5417],
];
const RELAY_EGRESS: [string, string, number, number][] = [
  ["Amsterdam", "Netherlands", 52.3676, 4.9041], ["Paris", "France", 48.8566, 2.3522], ["Brussels", "Belgium", 50.8503, 4.3517],
];
const PHONES = ["iPhone 15", "iPhone 16 Pro", "Pixel 9", "Galaxy S24", "Galaxy A55", "iPhone 14"];
/** Mail clients that keep retrying a saved password: the client app and user agent Entra ID records for each. */
const MAIL_CLIENTS: Record<string, { clientApp: string; ua: string }> = {
  "iOS Mail (Exchange ActiveSync)": { clientApp: "Exchange ActiveSync", ua: "iOS/18.1.1 (22B91) dataaccessd/1.0" },
  "Outlook for Android": { clientApp: "Mobile Apps and Desktop clients", ua: "Outlook-Android/2.0" },
  "Samsung Email": { clientApp: "Exchange ActiveSync", ua: "Android-SAMSUNG-SM-S921B/101.50101" },
  "Outlook for Mac": { clientApp: "Mobile Apps and Desktop clients", ua: "MacOutlook/16.90.24101716 (Intelx64 Mac OS X 15.1 (Build 24B83))" },
};

const MAKERS: Maker[] = [
  // ── An authorised vulnerability scan, raised by the SIEM's internal port-scan analytic on the scanner's own asset.
  { id: "scan_sentinel", kind: "scan", siemOnly: true, make: c => {
    const s = c.scanner, t = num("CHG", c);
    const ports = intIn(600, 4200, c.rnd), hosts = intIn(30, 160, c.rnd), mins = pickOf([15, 30, 59], c.rnd);
    const ev = sentinelAlert({ id: `fpa_scan_${c.n}`, ts: c.ts, name: pickOf(["Port scan from an internal host", "Internal host scanning many ports"], c.rnd), severity: "high", host: s.host, ip: s.ip,
      props: { "Distinct Ports": String(ports), "Distinct Hosts": String(hosts), "Query Period": `00:${String(mins).padStart(2, "0")}:00`, "Scanner Account": s.account },
      fp: `Authorised ${s.product} scan from the registered scanner ${s.host} (${s.ip}), the standard change ${t} for the scan window.`, mitre: "T1046", tactic: "Discovery" });
    return { makerId: "scan_sentinel", kind: "scan", verdict: "fp", rows: [ev], host: s.host,
      ticket: { table: "change_request", number: t, state: "Implement", short: `${s.product} authenticated scan of the server and workstation ranges`, ci: s.host, assignedTo: s.account, group: "Security Operations", window: [-intIn(20, 90, c.rnd), intIn(60, 240, c.rnd)] } };
  } },
  // ── The same kind of scan seen by the firewall's threat log (no SIEM needed).
  { id: "scan_firewall", kind: "scan", make: c => {
    const s = c.scanner, t = num("CHG", c);
    const dst = `${c.assets.subnet}.${intIn(2, 230, c.rnd)}`;
    const sig = pickOf([["SCAN-TCP-Port-Scan", "TCP port scan"], ["SCAN-Host-Sweep", "Host sweep"], ["SCAN-UDP-Port-Scan", "UDP port scan"]] as const, c.rnd);
    const ev = {
      id: `fpa_scanfw_${c.n}`, ts: c.ts, source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "ids_signature", severity: "medium", is_detection: true,
      hostname: s.host, src_ip: s.ip, dst_ip: dst, dst_port: pickOf([22, 135, 443, 445, 3389, 8080], c.rnd), expected_verdict: "fp", mitre_technique: "T1046",
      fp_explanation: `${s.host} (${s.ip}) is the registered ${s.product} scanner; its scan window is the standard change ${t}.`,
      description: `${sig[1]} from ${s.ip} toward ${dst}`,
      raw: { "event.action": "ids_alert", "event.outcome": "success", "source.ip": s.ip, "destination.ip": dst, "ids.signature_id": `SID:${intIn(40001, 40099, c.rnd)}`,
        "ids.signature_name": sig[0], "ids.category": "network-scan", "ids.severity": "medium", action_result: "alert", "session.blocked": "false" },
    } as TelemetryEvent;
    return { makerId: "scan_firewall", kind: "scan", verdict: "fp", rows: [ev], host: s.host,
      ticket: { table: "change_request", number: t, state: "Implement", short: `Scheduled ${s.product} discovery scan`, ci: s.host, assignedTo: s.account, group: "Security Operations", window: [-intIn(20, 90, c.rnd), intIn(60, 240, c.rnd)] } };
  } },
  // ── An IT admin runs a command on a server remotely, with one of four real tools: PsExec, PowerShell remoting, WMI or WinRM.
  { id: "remote_admin", kind: "remote_admin", canMiss: true, make: c => {
    const admin = c.person(IT_RE), target = c.server();
    if (!admin || !target) return null;
    const t = num("CHG", c);
    const task = pickOf([
      { what: "install the monthly cumulative update", cmd: `wusa.exe C:\\Patches\\windows11.0-kb50${intIn(30000, 59999, c.rnd)}-x64.msu /quiet /norestart` },
      { what: "restart the print spooler", cmd: "net stop spooler && net start spooler" },
      { what: "export the application event log", cmd: `wevtutil epl Application C:\\Temp\\app-${intIn(100, 999, c.rnd)}.evtx` },
      { what: "refresh group policy", cmd: "gpupdate /force" },
      { what: "update the backup agent", cmd: `msiexec /i \\\\${c.assets.fileServer}\\Deploy\\agent-${intIn(10, 19, c.rnd)}.${intIn(0, 9, c.rnd)}.msi /qn` },
    ], c.rnd);
    const tool = pickOf(["psexec", "psremoting", "wmi", "winrs"] as const, c.rnd);
    const pid = intIn(2000, 9000, c.rnd), ppid = intIn(1000, 9000, c.rnd);
    const proc: NonNullable<TelemetryEvent["process"]> = tool === "psexec"
      ? { name: pickOf(["PsExec.exe", "PsExec64.exe"], c.rnd), pid, parent_name: "cmd.exe", parent_pid: ppid, user: admin.name,
          cmdline: `PsExec64.exe -accepteula \\\\${target} ${pickOf(["-s ", "-h ", ""], c.rnd)}cmd /c "${task.cmd}"` }
      : tool === "psremoting"
        ? { name: "powershell.exe", pid, parent_name: pickOf(["explorer.exe", "WindowsTerminal.exe"], c.rnd), parent_pid: ppid, user: admin.name,
            cmdline: `powershell.exe -NoProfile -Command "Invoke-Command -ComputerName ${target} -ScriptBlock { cmd /c '${task.cmd}' }"` }
        : tool === "wmi"
          ? { name: "WMIC.exe", pid, parent_name: "cmd.exe", parent_pid: ppid, user: admin.name, cmdline: `wmic /node:"${target}" process call create "cmd.exe /c ${task.cmd}"` }
          : { name: "winrs.exe", pid, parent_name: "cmd.exe", parent_pid: ppid, user: admin.name, cmdline: `winrs -r:${target} cmd /c "${task.cmd}"` };
    if (tool === "psexec") proc.cmdline = proc.cmdline!.replace(/^PsExec64\.exe/, proc.name);
    const label = { psexec: "PsExec", psremoting: "PowerShell remoting", wmi: "WMI", winrs: "WinRM (winrs)" }[tool];
    const missHost = c.miss ? c.server() : null;
    const ev = edrDetection({ id: `fpa_remote_${c.n}`, ts: c.ts, host: admin.host, userEmail: admin.email, severity: "high",
      category: "LateralMovement", mitre: tool === "psexec" ? "T1569.002" : tool === "wmi" ? "T1047" : "T1021.006", process: proc,
      description: `${proc.name} on ${admin.host} ran a command on ${target} (${label})`,
      fp: `IT administrator ${admin.name} used ${label} to ${task.what} on ${target} under change ${t}.` });
    if (missHost) asMiss(ev, `IT says change ${t} covers ${missHost} only. Nobody approved remote work on ${target}; ${admin.name} has to explain it.`);
    return { makerId: "remote_admin", kind: "remote_admin", verdict: missHost ? "escalate" : "fp", rows: [ev], person: admin.email, host: admin.host,
      ticket: { table: "change_request", number: t, state: "Implement", short: `${task.what[0].toUpperCase()}${task.what.slice(1)} on ${missHost ?? target}`, ci: missHost ?? target, assignedTo: admin.email, group: pickOf(ITGROUPS, c.rnd), window: [-intIn(15, 60, c.rnd), intIn(45, 180, c.rnd)] } };
  } },
  // ── A management agent runs its script with the execution policy bypassed (Configuration Manager, Intune or PDQ Deploy).
  { id: "mgmt_script", kind: "mgmt_script", make: c => {
    const host = c.workstation();
    if (!host) return null;
    const agent = pickOf([
      { parent: "CcmExec.exe", name: "powershell.exe", cmd: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\${guid(c)}.ps1`, label: "Configuration Manager" },
      { parent: "AgentExecutor.exe", name: "powershell.exe", cmd: `"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -executionPolicy bypass -file "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\${guid(c)}_${guid(c)}.ps1"`, label: "Intune Management Extension" },
      { parent: "PDQDeployRunner-1.exe", name: "cmd.exe", cmd: `cmd.exe /c "C:\\Windows\\AdminArsenal\\PDQDeployRunner\\service-1\\exec\\${pickOf(["Install", "Remediate", "Inventory"], c.rnd)}-${intIn(100, 999, c.rnd)}.bat"`, label: "PDQ Deploy" },
    ], c.rnd);
    const t = num("CHG", c);
    const ev = edrDetection({ id: `fpa_mgmt_${c.n}`, ts: c.ts, host, severity: pickOf(["high", "medium"] as const, c.rnd), category: "SuspiciousScriptExecution", mitre: "T1059.001",
      process: { name: agent.name, pid: intIn(2000, 9000, c.rnd), parent_name: agent.parent, parent_pid: intIn(1000, 4000, c.rnd), user: "SYSTEM", cmdline: agent.cmd },
      description: `${agent.name} launched by ${agent.parent} on ${host} with the execution policy bypassed`,
      fp: `${agent.label} deployment by IT under change ${t}; the script is the package the agent pulled from its own distribution point.`,
      extra: { "process.code_signature.trusted": true } });
    return { makerId: "mgmt_script", kind: "mgmt_script", verdict: "fp", rows: [ev], host,
      ticket: { table: "change_request", number: t, state: pickOf(["Implement", "Scheduled"], c.rnd), short: `${agent.label} deployment wave ${intIn(1, 6, c.rnd)} to workstations`, group: "End User Computing", window: [-intIn(60, 300, c.rnd), intIn(120, 600, c.rnd)] } };
  } },
  // ── Approved business travel: a sign-in from abroad, MFA satisfied.
  { id: "travel", kind: "travel", make: c => {
    const p = c.person();
    if (!p) return null;
    const [city, country, lat, lon] = pickOf(CITIES, c.rnd), ip = docIp(c.rnd, c.ips), t = num("RITM", c);
    const ev = entraSignIn({ id: `fpa_travel_${c.n}`, ts: c.ts, user: p.email, ip, city, country, lat, lon, risk: { level: "medium", detection: "unfamiliarFeatures" },
      description: `${p.email} signed in from ${city}, ${country} (${ip}), first sign-in from this country`,
      fp: `${p.name} is on approved business travel to ${city} (travel request ${t}); the sign-in is from the managed laptop ${p.host} with MFA.` });
    return { makerId: "travel", kind: "travel", verdict: "fp", rows: [ev], person: p.email,
      ticket: { table: "sc_req_item", number: t, state: "Closed Complete", short: `Business travel to ${city}: laptop roaming approved`, requestedFor: p.email, group: "Travel Desk" } };
  } },
  // ── An unfamiliar location that is the company's own web-gateway egress or the user's privacy relay: no ticket, the device proves it.
  { id: "egress_signin", kind: "egress", make: c => {
    const p = c.person();
    if (!p) return null;
    const relay = c.rnd() < 0.5, ip = docIp(c.rnd, c.ips);
    const [vendor, city, country, lat, lon] = relay ? ["iCloud Private Relay", ...pickOf(RELAY_EGRESS, c.rnd)] as [string, string, string, number, number] : pickOf(PROXY_NODES, c.rnd);
    // Apple's relay egress is on the anonymizer lists Identity Protection uses; a gateway node is just a new place.
    const ev = entraSignIn({ id: `fpa_egress_${c.n}`, ts: c.ts, user: p.email, ip, city, country, lat, lon,
      risk: relay ? { level: "medium", detection: "anonymizedIPAddress" } : { level: "low", detection: "unfamiliarFeatures" },
      description: `${p.email} signed in from ${city}, ${country} (${ip}), an unfamiliar location for this account`,
      fp: relay
        ? `${p.name} reads mail on a company-enrolled iPhone with iCloud Private Relay on; Apple's relay egress in ${city} is the address, the device is compliant and MFA was satisfied. Benign, no ticket needed.`
        : `The sign-in left through the company's own ${vendor} egress node in ${city}; the device ${p.host} is managed and MFA was satisfied. Benign, no ticket needed.` });
    return { makerId: "egress_signin", kind: "egress", verdict: "fp", rows: [ev], person: p.email };
  } },
  // ── A new phone: a sign-in from a device the account has never used, right after the help desk re-registered MFA.
  { id: "new_phone", kind: "new_device", make: c => {
    const p = c.person();
    if (!p) return null;
    const phone = pickOf(PHONES, c.rnd), ip = docIp(c.rnd, c.ips), office = c.assets.office;
    const t = num("INC", c);
    const ev = entraSignIn({ id: `fpa_phone_${c.n}`, ts: c.ts, user: p.email, ip, city: office?.city ?? "London", country: office?.country ?? "United Kingdom", lat: 0, lon: 0,
      risk: { level: "low", detection: "unfamiliarFeatures" },
      description: `${p.email} signed in from a device never seen for this account (${phone})`,
      fp: `${p.name} replaced their phone; the help desk re-registered the authenticator under incident ${t} and the first sign-in from the new ${phone} followed. Same city, MFA satisfied.` });
    return { makerId: "new_phone", kind: "new_device", verdict: "fp", rows: [ev], person: p.email,
      ticket: { table: "incident", number: t, state: "Resolved", short: `New phone: re-register the authenticator app for ${p.name}`, requestedFor: p.email, group: "Service Desk",
        workNotes: `Identity verified on a video call against the badge photo. Old device removed, new ${phone} registered.` } };
  } },
  // ── A mail app still holding the old password after a change: repeated failed sign-ins for one account (SIEM analytic).
  { id: "stale_mail_app", kind: "mfa_noise", siemOnly: true, make: c => {
    const p = c.person();
    if (!p) return null;
    const app = pickOf(Object.keys(MAIL_CLIENTS), c.rnd), fails = intIn(14, 60, c.rnd);
    const name = pickOf(["Repeated failed sign-ins for one account", "Many failed sign-ins for one user"], c.rnd), ip = `${c.assets.subnet}.${intIn(100, 199, c.rnd)}`;
    const ev = sentinelAlert({ id: `fpa_stale_${c.n}`, ts: c.ts, name, severity: "medium", user: p.email, ip,
      props: { "Failed sign-ins": String(fails), "ResultType": "50126", "Client app": app, "Distinct IPs": "1", "Query Period": "01:00:00" },
      fp: `${p.name} changed their password this morning; ${app} on their own phone kept retrying the old one over the office Wi-Fi. One source, one known device, no success.`, mitre: "T1110.001", tactic: "CredentialAccess" });
    // The analytic counts sign-in rows: the latest of them reach the feed with it, as SigninLogs holds them.
    const client = MAIL_CLIENTS[app];
    const tries = [0, 1].map(k => ({
      id: `fpa_staleev_${c.n}_${k}`, ts: c.ts, source: "o365", event_type: "auth_failure", severity: "low", vendor: "Microsoft Entra ID",
      user_email: p.email, src_ip: ip, network: { user_agent: client.ua }, expected_verdict: "fp",
      fp_explanation: `${app} on ${p.name}'s own phone retrying the password from before this morning's change.`,
      description: `${p.email} failed to sign in: wrong password`,
      raw: { "data.office365.Operation": "UserLoginFailed", "data.office365.Workload": "AzureActiveDirectory", "data.office365.AzureActiveDirectoryEventType": "AccountLogon",
        "data.office365.UserId": p.email, "data.office365.ActorIpAddress": ip, "data.office365.ClientIP": ip, "data.office365.ResultStatus": "Failed",
        "data.office365.ErrorNumber": "50126", "data.office365.LogonError": "InvalidUserNameOrPassword", "azure.signinlogs.properties.clientAppUsed": client.clientApp, action_result: "blocked" },
    }) as TelemetryEvent);
    return { makerId: "stale_mail_app", kind: "mfa_noise", verdict: "fp", rows: [...tries, ev], person: p.email,
      ticket: c.rnd() < 0.6 ? { table: "incident", number: num("INC", c), state: "In Progress", short: "Phone keeps asking for the password after a reset", requestedFor: p.email, group: "Service Desk" } : undefined };
  } },
  // ── A VPN client with a saved stale password locks the account (the VPN failures, then Security 4740).
  { id: "vpn_lockout", kind: "lockout", fits: c => !!c.stack.onprem_ad && !!c.stack.vpn, make: c => {
    const p = c.person();
    if (!p) return null;
    const ip = docIp(c.rnd, c.ips), dc = c.assets.dc;
    const fail = {
      id: `fpa_vpnfail_${c.n}`, ts: c.ts, source: "vpn", vendor: "Palo Alto Networks PAN-OS", event_type: "vpn_failed", severity: "low", user_email: p.email, src_ip: ip,
      expected_verdict: "fp", description: `${p.name} failed VPN authentication from ${ip}`,
      fp_explanation: `The VPN client on ${p.name}'s laptop still holds the password from before last week's change.`,
      raw: { "pan.event_type": "authentication", "pan.result": "failure", "pan.reason": "Authentication Failed", "pan.auth_method": "LDAP", "pan.gateway": `gp.${c.assets.domain}`, "pan.os": "Windows 11", "source.ip": ip, "event.action_result": "deny" },
    } as TelemetryEvent;
    const lock = {
      id: `fpa_lockout_${c.n}`, ts: c.ts, source: "ad", vendor: "Windows Security", event_type: "account_lockout", severity: "medium", user_email: p.email, hostname: dc,
      is_detection: true, expected_verdict: "fp", mitre_technique: "T1110",
      fp_explanation: `${p.name}'s saved VPN password is stale after a password change (home address ${ip}, their own laptop). No other account failed.`,
      description: `${dc} locked out account ${p.name}`,
      raw: { "winlog.event_id": "4740", "winlog.channel": "Security", "winlog.computer_name": dc, "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserSid": "S-1-5-18", "winlog.event_data.SubjectUserName": `${dc}$`, "winlog.event_data.SubjectDomainName": c.assets.netbios,
        "winlog.event_data.TargetUserName": p.name, "winlog.event_data.TargetDomainName": c.assets.netbios, "winlog.event_data.CallerComputerName": p.host, "event.code": "4740" },
    } as TelemetryEvent;
    return { makerId: "vpn_lockout", kind: "lockout", verdict: "fp", rows: [fail, lock], person: p.email,
      ticket: c.rnd() < 0.5 ? { table: "incident", number: num("INC", c), state: "New", short: "Locked out, cannot connect to the VPN from home", requestedFor: p.email, group: "Service Desk" } : undefined };
  } },
  // ── Payroll DLP: the monthly payroll file with bank details goes to the contracted payroll provider.
  { id: "payroll_dlp", kind: "dlp", fits: c => c.stack.collab === "m365", make: c => {
    const p = c.person(/financ|account|payroll|hr|controller|operations/i) ?? c.person();
    if (!p) return null;
    const provider = pickOf([["Northbeam Payroll", "northbeam-payroll.com"], ["Ledgerline HR", "ledgerline-hr.com"], ["Paycrest Services", "paycrest-services.net"]] as const, c.rnd);
    const month = pickOf(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], c.rnd);
    const files = intIn(1, 4, c.rnd), mb = (intIn(18, 260, c.rnd) / 10).toFixed(1);
    const ev = {
      id: `fpa_dlp_${c.n}`, ts: c.ts, source: "dlp", vendor: "Microsoft Purview", event_type: "dlp_alert", severity: "high", user_email: p.email,
      src_ip: `${c.assets.subnet}.${intIn(20, 199, c.rnd)}`, is_detection: true, expected_verdict: "fp", mitre_technique: "T1048",
      fp_explanation: `${p.name} sends the monthly payroll run to ${provider[0]}, the contracted payroll processor, at its agreed address payroll@${provider[1]}; a data processing agreement covers it.`,
      description: `Purview DLP matched bank account numbers in mail from ${p.email} to an external domain`,
      raw: { "event.action": "DLP_PolicyTriggered", "event.outcome": "success", "user.email": p.email, "policy.name": pickOf(["Financial data: external sharing", "Bank account numbers outbound"], c.rnd),
        "policy.rule": "BankAccountNumbers-External", "policy.action": "NotifyUser", "file.count": String(files), "storage.size": `${mb} MB`,
        "file.name": `Payroll_${month}${files > 1 ? "_part1" : ""}.xlsx`, "email.to.address": `payroll@${provider[1]}`,
        "data.classification": "Bank account number, Personal data", action_result: "notified_not_blocked" },
    } as TelemetryEvent;
    return { makerId: "payroll_dlp", kind: "dlp", verdict: "fp", rows: [ev], person: p.email };
  } },
  // ── The backup job reads many files (SIEM analytic), on the file server, by the backup product's own account.
  { id: "backup_read", kind: "backup", siemOnly: true, make: c => {
    const svc = c.assets.serviceAccounts.find(s => /backup/.test(s)) ?? "svc-backup";
    const product = pickOf([["Veeam Agent", "VeeamAgent.exe"], ["Commvault", "CVD.exe"], ["Veritas NetBackup", "bpbkar32.exe"], ["Azure Backup (MARS)", "cbengine.exe"]] as const, c.rnd);
    const files = intIn(9000, 64000, c.rnd), mins = pickOf([30, 60, 120], c.rnd), t = num("CHG", c);
    const ev = sentinelAlert({ id: `fpa_backup_${c.n}`, ts: c.ts, name: pickOf(["Mass file access by a single account", "Unusual volume of file reads"], c.rnd), severity: "high", host: c.assets.fileServer, user: mail(c.assets, svc),
      props: { "Files Accessed": String(files), "Window": `${mins} minutes`, "Account": svc, "Process": product[1] },
      fp: `${product[0]} job of ${c.assets.fileServer} by ${svc}, the standing change ${t}; the volume matches the share's size.` });
    return { makerId: "backup_read", kind: "backup", verdict: "fp", rows: [ev], host: c.assets.fileServer,
      ticket: c.rnd() < 0.7 ? { table: "change_request", number: t, state: "Implement", short: `${product[0]} schedule for ${c.assets.fileServer} (standard change)`, ci: c.assets.fileServer, assignedTo: mail(c.assets, svc), group: "Infrastructure Operations", window: [-intIn(30, 120, c.rnd), intIn(120, 360, c.rnd)] } : undefined };
  } },
  // ── An authorised penetration test: a credential or AD-recon tool on the testers' own host.
  { id: "redteam_tool", kind: "redteam", canMiss: true, make: c => {
    const host = c.workstation();
    if (!host) return null;
    const firm = pickOf([["Halcyon Assurance", "hal"], ["Northpoint Offensive", "npo"], ["Greyfield Security", "gfs"]] as const, c.rnd);
    const acct = `pt-${firm[1]}${intIn(1, 4, c.rnd)}`, t = num("CHG", c), dir = `C:\\PT\\${firm[1]}-${intIn(10, 99, c.rnd)}`;
    const tool = pickOf([
      { name: "Rubeus.exe", cmd: `${dir}\\Rubeus.exe kerberoast /outfile:${dir}\\hashes.txt`, mitre: "T1558.003", what: "Kerberoasting" },
      { name: "SharpHound.exe", cmd: `${dir}\\SharpHound.exe -c All --zipfilename ${firm[1]}_${intIn(100, 999, c.rnd)}.zip`, mitre: "T1087.002", what: "AD collection" },
      { name: "Certify.exe", cmd: `${dir}\\Certify.exe find /vulnerable`, mitre: "T1649", what: "certificate template enumeration" },
      { name: "Seatbelt.exe", cmd: `${dir}\\Seatbelt.exe -group=user`, mitre: "T1082", what: "host survey" },
    ], c.rnd);
    const missHost = c.miss ? c.workstation() : null;
    const ev = edrDetection({ id: `fpa_redteam_${c.n}`, ts: c.ts, host, userEmail: mail(c.assets, acct), severity: "high", category: "CredentialAccess", mitre: tool.mitre,
      process: { name: tool.name, pid: intIn(2000, 9000, c.rnd), parent_name: "powershell.exe", parent_pid: intIn(1000, 9000, c.rnd), user: acct, cmdline: tool.cmd, path: `${dir}\\${tool.name}` },
      description: `${tool.name} ran on ${host} as ${acct}`,
      fp: `${firm[0]} is running the authorised internal penetration test (change ${t}) from ${host} with the test account ${acct}; ${tool.what} is in the rules of engagement.` });
    if (missHost) asMiss(ev, `The test under ${t} is scoped to ${missHost}. ${host} is not in the rules of engagement, so this run is outside the approval.`);
    return { makerId: "redteam_tool", kind: "redteam", verdict: missHost ? "escalate" : "fp", rows: [ev], host,
      ticket: { table: "change_request", number: t, state: "Implement", short: `Internal penetration test by ${firm[0]}: test host ${missHost ?? host}`, ci: missHost ?? host, requestedFor: mail(c.assets, acct), group: "Security Operations", window: [-intIn(120, 600, c.rnd), intIn(240, 900, c.rnd)] } };
  } },
  // ── A potentially-unwanted-application verdict on an admin's network tool.
  { id: "pua_admin_tool", kind: "pua", make: c => {
    const p = c.person(IT_RE);
    if (!p) return null;
    const tool = pickOf([
      { exe: "advanced_ip_scanner.exe", dir: "C:\\Program Files (x86)\\Advanced IP Scanner", label: "Advanced IP Scanner" },
      { exe: "ipscan.exe", dir: `C:\\Users\\${p.name}\\Downloads`, label: "Angry IP Scanner" },
      { exe: "WNetWatcher.exe", dir: `C:\\Users\\${p.name}\\Tools\\NirSoft`, label: "NirSoft Wireless Network Watcher" },
      { exe: "advanced_port_scanner.exe", dir: "C:\\Program Files (x86)\\Advanced Port Scanner", label: "Advanced Port Scanner" },
    ], c.rnd);
    const path = `${tool.dir}\\${tool.exe}`;
    const ev = edrDetection({ id: `fpa_pua_${c.n}`, ts: c.ts, host: p.host, userEmail: p.email, severity: "medium", category: "UnwantedSoftware", mitre: "T1046",
      process: { name: tool.exe, pid: intIn(2000, 9000, c.rnd), parent_name: "explorer.exe", parent_pid: intIn(1000, 9000, c.rnd), user: p.name, path, cmdline: `"${path}"` },
      description: `Potentially unwanted application ${tool.exe} ran on ${p.host}`,
      fp: `${tool.label} is on IT's approved tool list; ${p.name} used it to find a printer that dropped off the network. The binary is the vendor's signed release.`,
      extra: { "process.code_signature.trusted": true } });
    return { makerId: "pua_admin_tool", kind: "pua", verdict: "fp", rows: [ev], person: p.email, host: p.host,
      ticket: c.rnd() < 0.5 ? { table: "incident", number: num("INC", c), state: "In Progress", short: `Printer on floor ${intIn(1, 6, c.rnd)} not reachable`, requestedFor: p.email, assignedTo: p.email, group: "Service Desk" } : undefined };
  } },
  // ── A developer's packet capture.
  { id: "pcap_dev", kind: "sniffing", make: c => {
    const p = c.person(DEV_RE);
    if (!p) return null;
    const tool = pickOf([
      { name: "dumpcap.exe", parent: "Wireshark.exe", cmd: `"C:\\Program Files\\Wireshark\\dumpcap.exe" -i ${intIn(1, 4, c.rnd)} -w C:\\Users\\${p.name}\\captures\\tls-${intIn(100, 999, c.rnd)}.pcapng` },
      { name: "tshark.exe", parent: "powershell.exe", cmd: `"C:\\Program Files\\Wireshark\\tshark.exe" -i Ethernet -f "port 443" -a duration:${pickOf([60, 120, 300], c.rnd)} -w api-${intIn(100, 999, c.rnd)}.pcapng` },
      { name: "pktmon.exe", parent: "cmd.exe", cmd: `pktmon start --capture --comp nics --pkt-size 0 --file-name C:\\Temp\\pktmon-${intIn(100, 999, c.rnd)}.etl` },
      { name: "netsh.exe", parent: "cmd.exe", cmd: `netsh trace start capture=yes tracefile=C:\\Temp\\trace-${intIn(100, 999, c.rnd)}.etl maxsize=${pickOf([256, 512], c.rnd)}` },
    ], c.rnd);
    const ev = edrDetection({ id: `fpa_pcap_${c.n}`, ts: c.ts, host: p.host, userEmail: p.email, severity: "medium", category: "Discovery", mitre: "T1040",
      process: { name: tool.name, pid: intIn(2000, 9000, c.rnd), parent_name: tool.parent, parent_pid: intIn(1000, 9000, c.rnd), user: p.name, cmdline: tool.cmd },
      description: `Network capture started by ${tool.name} on ${p.host}`,
      fp: `${p.name} is debugging a TLS handshake to the staging API; packet capture on their own laptop is allowed for developers and the capture stays on it.` });
    return { makerId: "pcap_dev", kind: "sniffing", verdict: "fp", rows: [ev], person: p.email, host: p.host };
  } },
  // ── A cloud admin's mass permission change under a ticket (Azure: a SIEM analytic over the Activity log).
  { id: "cloud_perm_azure", kind: "cloud_perm", siemOnly: true, canMiss: true, fits: c => c.platforms.has("azure") || c.stack.cloud === "azure_activity", make: c => {
    const p = c.person(IT_RE);
    if (!p) return null;
    const t = num("CHG", c), n = intIn(12, 48, c.rnd), rg = pickOf(["rg-data-platform", "rg-shared-services", "rg-analytics", "rg-web-prod"], c.rnd);
    const role = pickOf(["Reader", "Storage Blob Data Reader", "Contributor", "Monitoring Reader"], c.rnd);
    const otherRg = c.miss ? pickOf(["rg-finance-prod", "rg-identity", "rg-keyvault-prod"], c.rnd) : null;
    const ev = sentinelAlert({ id: `fpa_azperm_${c.n}`, ts: c.ts, name: "Mass Azure RBAC role assignments by one user", severity: "medium", user: p.email,
      props: { "Role assignments": String(n), "Role": role, "Scope": rg, "Operation": "Microsoft.Authorization/roleAssignments/write" },
      fp: `${p.name} is moving the ${rg} team to group-based access under change ${t}; ${n} ${role} assignments, all inside the approved scope.`, mitre: "T1098", tactic: "Persistence" });
    if (otherRg) asMiss(ev, `Change ${t} approves role changes in ${otherRg}. Nothing approves ${role} grants in ${rg}.`);
    return { makerId: "cloud_perm_azure", kind: "cloud_perm", verdict: otherRg ? "escalate" : "fp", rows: [ev], person: p.email,
      ticket: { table: "change_request", number: t, state: "Implement", short: `Group-based RBAC for ${otherRg ?? rg}`, ci: otherRg ?? rg, assignedTo: p.email, group: "Cloud Platform", window: [-intIn(30, 120, c.rnd), intIn(60, 240, c.rnd)] } };
  } },
  // ── The same on AWS: GuardDuty's anomaly model flags the admin's unusual IAM calls.
  { id: "cloud_perm_aws", kind: "cloud_perm", canMiss: true, fits: c => c.stack.cloud === "aws_cloudtrail", make: c => {
    const p = c.person(IT_RE) ?? c.person(DEV_RE);
    if (!p) return null;
    const t = num("CHG", c), acct = String(intIn(100000000000, 999999999999, c.rnd)), api = pickOf(["AttachRolePolicy", "PutRolePolicy", "PutRolePermissionsBoundary"], c.rnd);
    const count = intIn(8, 40, c.rnd), ip = docIp(c.rnd, c.ips);
    const ev = {
      id: `fpa_awsperm_${c.n}`, ts: c.ts, source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call", severity: "medium", is_detection: true,
      user_email: p.email, src_ip: ip, expected_verdict: "fp", mitre_technique: "T1098",
      fp_explanation: `${p.name} is rolling the new permission boundary onto ${count} workload roles under change ${t}, from the platform team's VPN egress ${ip}.`,
      description: `GuardDuty raised PrivilegeEscalation:IAMUser/AnomalousBehavior for ${p.name}`,
      raw: { "aws.guardduty.type": "PrivilegeEscalation:IAMUser/AnomalousBehavior", "aws.guardduty.severity": "5.0",
        "aws.guardduty.title": `User ${p.name} is anomalously invoking APIs commonly used in Privilege Escalation tactics.`,
        "aws.guardduty.description": `APIs commonly used in Privilege Escalation tactics were invoked by user IAMUser : ${p.name} under unusual circumstances. Such activity is not typically seen from this user.`,
        "aws.guardduty.resource.accessKeyDetails.userName": p.name, "aws.guardduty.service.action.awsApiCallAction.api": api, "aws.guardduty.service.count": count,
        "aws.cloudtrail.awsRegion": pickOf(["eu-central-1", "eu-west-1", "us-east-1"], c.rnd), "aws.cloudtrail.userIdentity.userName": p.name, "cloud.account.id": acct },
    } as TelemetryEvent;
    if (c.miss) asMiss(ev, `Change ${t} ran yesterday evening and is closed. Nothing approves ${api} calls by ${p.name} now.`);
    return { makerId: "cloud_perm_aws", kind: "cloud_perm", verdict: c.miss ? "escalate" : "fp", rows: [ev], person: p.email,
      ticket: { table: "change_request", number: t, state: c.miss ? "Closed" : "Implement", short: "Permission boundary rollout to workload roles", assignedTo: p.email, group: "Cloud Platform",
        window: c.miss ? [-intIn(900, 1200, c.rnd), -intIn(480, 720, c.rnd)] : [-intIn(30, 120, c.rnd), intIn(60, 240, c.rnd)] } };
  } },
  // ── A forwarding rule to an internal delegate while someone is on leave (SIEM analytic over the mailbox audit).
  { id: "delegate_forward", kind: "mail_rule", siemOnly: true, fits: c => c.stack.collab === "m365", make: c => {
    const p = c.person(), d = c.person();
    if (!p || !d) return null;
    const ev = sentinelAlert({ id: `fpa_fwd_${c.n}`, ts: c.ts, name: pickOf(["New inbox rule forwarding mail", "Mail forwarding rule created"], c.rnd), severity: "medium", user: p.email,
      props: { "Operation": "New-InboxRule", "ForwardTo": d.email, "Rule name": pickOf(["Leave cover", "OOO to delegate", "Holiday cover"], c.rnd), "Client": "Outlook" },
      fp: `${p.name} is on leave and forwards to their internal delegate ${d.name}, in the company's own domain, set from Outlook on the managed laptop.`, mitre: "T1114.003", tactic: "Collection" });
    return { makerId: "delegate_forward", kind: "mail_rule", verdict: "fp", rows: [ev], person: p.email };
  } },
  // ── A SharePoint migration download burst (Defender for Cloud Apps policy "Mass download by a single user").
  { id: "mass_download", kind: "mass_download", siemOnly: true, fits: c => c.stack.collab === "m365", make: c => {
    const p = c.person(IT_RE) ?? c.person();
    if (!p) return null;
    const n = intIn(60, 420, c.rnd), site = pickOf(["Projects-Archive", "Operations", "Legacy-Finance", "Policies"], c.rnd), t = num("CHG", c);
    const siteUrl = `https://${c.assets.domain.split(".")[0]}.sharepoint.com/sites/${site}`;
    const ev = sentinelAlert({ id: `fpa_massdl_${c.n}`, ts: c.ts, name: "Mass download by a single user", severity: "medium", user: p.email, mcas: true,
      props: { "Downloads": String(n), "Site": siteUrl, "Window": "1 minute", "Client": "SharePoint Migration Tool" },
      fp: `${p.name} is moving the ${site} site with the SharePoint Migration Tool under change ${t}; the burst is the tool's sync.`, mitre: "T1530", tactic: "Collection" });
    // Defender for Cloud Apps counts the SharePoint audit rows; the latest of them reach the feed with its alert.
    const ip = `${c.assets.subnet}.${intIn(20, 199, c.rnd)}`;
    const downloads = [0, 1].map(k => {
      const file = `${pickOf(["Budget", "Minutes", "Inventory", "Contracts", "Schedule", "Report"], c.rnd)}_${intIn(2019, 2025, c.rnd)}_${intIn(10, 99, c.rnd)}.${pickOf(["xlsx", "docx", "pdf", "pptx"], c.rnd)}`;
      return {
        id: `fpa_massdlev_${c.n}_${k}`, ts: c.ts, source: "o365", event_type: "sharepoint_access", severity: "informational", vendor: "Microsoft 365 Unified Audit Log",
        user_email: p.email, src_ip: ip, expected_verdict: "fp", fp_explanation: `Part of the SharePoint Migration Tool sync of ${site} under change ${t}.`,
        description: `${p.email} downloaded ${file} from SharePoint /sites/${site}`,
        raw: { "data.office365.Operation": "FileDownloaded", "data.office365.Workload": "SharePoint", "data.office365.UserId": p.email, "data.office365.ClientIP": ip,
          "data.office365.SiteUrl": `${siteUrl}/`, "data.office365.SourceFileName": file, "data.office365.ObjectId": `${siteUrl}/Shared Documents/${file}`, action_result: "allowed" },
      } as TelemetryEvent;
    });
    return { makerId: "mass_download", kind: "mass_download", verdict: "fp", rows: [...downloads, ev], person: p.email,
      ticket: { table: "change_request", number: t, state: "Implement", short: `Migrate the SharePoint site ${site}`, ci: site, assignedTo: p.email, group: "Collaboration Services", window: [-intIn(60, 240, c.rnd), intIn(120, 480, c.rnd)] } };
  } },
  // ── A rotated service-account password still cached in a scheduled task on one server (SIEM analytic).
  { id: "stale_service_cred", kind: "svc_cred", siemOnly: true, fits: c => !!c.stack.onprem_ad, make: c => {
    const server = c.server();
    if (!server) return null;
    const svc = pickOf(c.assets.serviceAccounts.filter(s => !/backup|scan/.test(s)).concat(["svc-report"]), c.rnd), fails = intIn(40, 300, c.rnd), t = num("CHG", c);
    const ev = sentinelAlert({ id: `fpa_svccred_${c.n}`, ts: c.ts, name: "Repeated failed logons for one account on one host", severity: "medium", host: server, user: mail(c.assets, svc),
      props: { "Failed logons": String(fails), "Event ID": "4625", "Status": "0xC000006A", "Logon type": "4", "Query Period": "01:00:00" },
      fp: `${svc}'s password was rotated under change ${t}; a scheduled task on ${server} still runs with the old one (logon type 4, batch). One host, one account.`, mitre: "T1110", tactic: "CredentialAccess" });
    // The 4625 events the analytic counts: the latest of them reach the feed with it.
    const logons = [0, 1].map(k => ({
      id: `fpa_svccredev_${c.n}_${k}`, ts: c.ts, source: "ad", vendor: "Windows Security", event_type: "auth_failure", severity: "low",
      hostname: server, user_email: mail(c.assets, svc), expected_verdict: "fp",
      fp_explanation: `The scheduled task on ${server} still runs as ${svc} with the password from before change ${t}.`,
      description: `${server} rejected a batch logon for ${svc}`,
      raw: { "winlog.event_id": "4625", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": server,
        "winlog.event_data.SubjectUserSid": "S-1-5-18", "winlog.event_data.SubjectUserName": `${server}$`, "winlog.event_data.SubjectDomainName": c.assets.netbios,
        "winlog.event_data.TargetUserName": svc, "winlog.event_data.TargetDomainName": c.assets.netbios, "winlog.event_data.LogonType": "4",
        "winlog.event_data.Status": "0xC000006D", "winlog.event_data.SubStatus": "0xC000006A", "winlog.event_data.FailureReason": "%%2313",
        "winlog.event_data.LogonProcessName": "Advapi", "winlog.event_data.AuthenticationPackageName": "Negotiate", "winlog.event_data.WorkstationName": server,
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe", "winlog.event_data.IpAddress": "-", "winlog.event_data.IpPort": "-",
        "event.code": "4625", "event.action": "logon-failed", "event.outcome": "failure", action_result: "blocked" },
    }) as TelemetryEvent);
    return { makerId: "stale_service_cred", kind: "svc_cred", verdict: "fp", rows: [...logons, ev], host: server,
      ticket: { table: "change_request", number: t, state: "Review", short: `Rotate the password of ${svc}`, ci: svc, group: "Identity and Access", window: [-intIn(300, 900, c.rnd), -intIn(60, 240, c.rnd)] } };
  } },
  // ── IT pulls a package from its internal repository with a built-in downloader (certutil, bitsadmin or curl).
  { id: "lolbin_download", kind: "lolbin", make: c => {
    const p = c.person(IT_RE);
    if (!p) return null;
    const repo = `http://${c.assets.fileServer.toLowerCase()}.${c.assets.domain}/repo`;
    const file = pickOf(["printer-driver-x64.zip", "vpn-client-update.msi", "bios-utility.exe", "root-ca-2026.cer"], c.rnd);
    const tool = pickOf([
      { name: "certutil.exe", cmd: `certutil.exe -urlcache -split -f ${repo}/${file} C:\\Temp\\${file}` },
      { name: "bitsadmin.exe", cmd: `bitsadmin /transfer it${intIn(10, 99, c.rnd)} /download /priority normal ${repo}/${file} C:\\Temp\\${file}` },
      { name: "curl.exe", cmd: `curl.exe -o C:\\Temp\\${file} ${repo}/${file}` },
    ], c.rnd);
    const ev = edrDetection({ id: `fpa_lolbin_${c.n}`, ts: c.ts, host: p.host, userEmail: p.email, severity: "medium", category: "SuspiciousDownload", mitre: "T1105",
      process: { name: tool.name, pid: intIn(2000, 9000, c.rnd), parent_name: "cmd.exe", parent_pid: intIn(1000, 9000, c.rnd), user: p.name, cmdline: tool.cmd },
      description: `${tool.name} downloaded a file on ${p.host}`,
      fp: `${p.name} pulled ${file} from IT's own internal repository on ${c.assets.fileServer}; the source is internal and the file is the published package.` });
    return { makerId: "lolbin_download", kind: "lolbin", verdict: "fp", rows: [ev], person: p.email, host: p.host };
  } },
  // ── The help desk's licensed remote-support tool on a user's laptop.
  { id: "remote_support", kind: "remote_support", make: c => {
    const agent = c.person(IT_RE), p = c.person();
    if (!p || !agent) return null;
    const tool = pickOf([
      { name: "TeamViewer.exe", path: "C:\\Program Files\\TeamViewer\\TeamViewer.exe", label: "TeamViewer" },
      { name: "ScreenConnect.ClientService.exe", path: "C:\\Program Files (x86)\\ScreenConnect Client\\ScreenConnect.ClientService.exe", label: "ScreenConnect" },
      { name: "SRService.exe", path: "C:\\Program Files (x86)\\Splashtop\\Splashtop Remote\\Server\\SRService.exe", label: "Splashtop" },
    ], c.rnd);
    const t = num("INC", c);
    const ev = edrDetection({ id: `fpa_rmm_${c.n}`, ts: c.ts, host: p.host, userEmail: p.email, severity: "medium", category: "RemoteAccessSoftware", mitre: "T1219",
      process: { name: tool.name, pid: intIn(2000, 9000, c.rnd), parent_name: "services.exe", parent_pid: intIn(600, 900, c.rnd), user: "SYSTEM", path: tool.path, cmdline: `"${tool.path}"` },
      description: `${tool.label} remote session on ${p.host}`,
      fp: `The service desk's licensed ${tool.label} is the company's remote-support tool; ${agent.name} connected to fix ${p.name}'s Outlook crash under incident ${t}.` });
    return { makerId: "remote_support", kind: "remote_support", verdict: "fp", rows: [ev], person: p.email, host: p.host,
      ticket: { table: "incident", number: t, state: "In Progress", short: "Outlook crashes when opening a shared calendar", requestedFor: p.email, assignedTo: agent.email, group: "Service Desk" } };
  } },
  // ── A freshly compiled, unsigned build run from a developer's workspace (low-prevalence binary).
  { id: "dev_build", kind: "unsigned_build", make: c => {
    const p = c.person(DEV_RE);
    if (!p) return null;
    const app = pickOf(["invoice-sync", "ledger-cli", "route-planner", "report-gen", "api-mock"], c.rnd);
    const path = `C:\\Users\\${p.name}\\source\\repos\\${app}\\bin\\${pickOf(["Debug", "Release"], c.rnd)}\\net8.0\\${app}.exe`;
    const ev = edrDetection({ id: `fpa_build_${c.n}`, ts: c.ts, host: p.host, userEmail: p.email, severity: "medium", category: "LowPrevalenceExecutable", mitre: "T1204.002",
      process: { name: `${app}.exe`, pid: intIn(2000, 9000, c.rnd), parent_name: pickOf(["devenv.exe", "dotnet.exe", "Code.exe"], c.rnd), parent_pid: intIn(1000, 9000, c.rnd), user: p.name, path, cmdline: `"${path}" --env staging` },
      description: `Unsigned, first-seen executable ${app}.exe ran on ${p.host}`,
      fp: `${p.name} built ${app} locally from the team's repository and ran it against staging; an unsigned build seen once is expected on a developer laptop.`,
      extra: { "process.code_signature.exists": false, "file.size": String(sizeOf(1, 9, c)) } });
    return { makerId: "dev_build", kind: "unsigned_build", verdict: "fp", rows: [ev], person: p.email, host: p.host };
  } },
];

/** Every maker's id and kind (the variety tests and the debrief read it). */
export const FP_MAKERS: readonly { id: string; kind: string; siemOnly: boolean; canMiss: boolean }[] = MAKERS.map(m => ({ id: m.id, kind: m.kind, siemOnly: !!m.siemOnly, canMiss: !!m.canMiss }));

const SCAN_PRODUCTS = [
  { product: "Tenable Nessus", host: "NESSUS", account: "svc-nessus" },
  { product: "Qualys scanner appliance", host: "QUALYS", account: "svc-qualys" },
  { product: "Rapid7 InsightVM", host: "R7SCAN", account: "svc-insightvm" },
  { product: "Greenbone OpenVAS", host: "GVM", account: "svc-openvas" },
] as const;

/**
 * Up to `count` benign-positive alerts for a session, seed-stable. `siem`: the organization runs
 * Microsoft Sentinel; `fits`: the session's products have a record for the event; `stack`: the
 * resolved stack (which products exist); `seen`: how recently each maker ran in this org's
 * previous sessions (variety.ts); `avoid`: people, hosts and addresses the attacks use;
 * `force`: test hook (these makers first, in this order); `miss`: author one maker's ticket so
 * that it does not cover the activity (escalate, not FP).
 */
export function fpAlerts(assets: CompanyAssets | undefined, companyId: string, count: number, rnd: () => number, ts: string,
  opts: { siem?: boolean; fits?: (e: TelemetryEvent) => boolean; stack?: Stack; platforms?: string[]; seen?: Record<string, number>;
    avoid?: FpAvoid; force?: string[]; miss?: boolean } = {}): FpOut[] {
  if (!assets || count <= 0) return [];
  const siem = opts.siem ?? true, fits = opts.fits ?? (() => true);
  const avoidUsers = opts.avoid?.users ?? new Set<string>(), avoidHosts = opts.avoid?.hosts ?? new Set<string>();
  const ips = opts.avoid?.ips ?? new Set<string>();
  const usedPeople = new Set<string>(), usedHosts = new Set<string>();
  // People: never an attack victim, never twice in one session (two decoys on one person read as one story).
  const roster: RosterUser[] = shuffled(assets.roster, rnd);
  const seatHost = new Map<string, string>(Object.values(assets.seats ?? {}).flat().map(s => [s.user, s.host]));
  const wsPool = shuffled(assets.hosts.filter(h => h !== assets.dc && h !== assets.fileServer && !isServer(h)), rnd);
  const srvPool = shuffled([assets.fileServer, ...assets.hosts.filter(h => isServer(h) && h !== assets.dc)].filter(Boolean), rnd);
  const freeHost = (pool: string[]) => pool.find(h => !usedHosts.has(h) && !avoidHosts.has(h)) ?? null;
  const take = (h: string | null) => { if (h) usedHosts.add(h); return h; };
  const person = (re?: RegExp): Person | null => {
    for (const r of roster) {
      if (usedPeople.has(r.name) || avoidUsers.has(mail(assets, r.name)) || (re && !re.test(r.title ?? ""))) continue;
      const own = seatHost.get(r.name);
      const host = own && !usedHosts.has(own) && !avoidHosts.has(own) ? own : freeHost(wsPool);
      if (!host) continue;
      usedPeople.add(r.name); usedHosts.add(host);
      return { name: r.name, email: mail(assets, r.name), host, title: r.title ?? "" };
    }
    return null;
  };
  const sp = pickOf(SCAN_PRODUCTS, rnd);
  const prefix = assets.serverPrefix ?? "SRV";
  const scanner = { host: `${prefix}-${sp.host}0${intIn(1, 3, rnd)}`, ip: `${assets.subnet}.${intIn(240, 252, rnd)}`, product: sp.product, account: sp.account };
  const base = { assets, companyId, rnd, ts, stack: opts.stack ?? {}, siem, platforms: new Set(opts.platforms ?? []), ips, scanner,
    person, workstation: () => take(freeHost(wsPool)), server: () => take(freeHost(srvPool)) };

  const eligible = MAKERS.filter(m => (siem || !m.siemOnly) && (!m.fits || m.fits({ ...base, n: 0, miss: false })));
  const ranked = rankByHistory(eligible, m => m.id, opts.seen ?? {}, rnd);
  const forced = (opts.force ?? []).map(id => MAKERS.find(m => m.id === id)).filter((m): m is Maker => !!m);
  const order = forced.length ? [...forced, ...ranked.filter(m => !forced.includes(m))] : ranked;
  const out: FpOut[] = [];
  const kinds = new Set<string>();
  let missLeft = opts.miss ? 1 : 0;
  const seen = opts.seen ?? {};
  // Fresh makers fill the session; one the organization ran in its recent sessions comes back only
  // to reach the minimum of two (a feed with fewer benign-positive alerts is badge-scorable again).
  const MIN = Math.min(2, count);
  for (const pass of [0, 1]) {
    for (const m of order) {
      if (out.length >= (pass === 0 ? count : MIN)) break;
      if (out.some(o => o.makerId === m.id)) continue;
      if (pass === 0 && m.id in seen && !forced.includes(m)) continue;
      if (kinds.has(m.kind) && !forced.includes(m)) continue;
      // A maker that cannot be made here gives its people and hosts back.
      const people = new Set(usedPeople), hostsNow = new Set(usedHosts);
      const r = m.make({ ...base, n: out.length, miss: missLeft > 0 && !!m.canMiss });
      if (!r || !r.rows.every(fits)) {
        usedPeople.clear(); people.forEach(x => usedPeople.add(x));
        usedHosts.clear(); hostsNow.forEach(x => usedHosts.add(x));
        continue;
      }
      if (r.verdict === "escalate") missLeft--;
      kinds.add(m.kind);
      out.push(r);
    }
  }
  return out;
}
