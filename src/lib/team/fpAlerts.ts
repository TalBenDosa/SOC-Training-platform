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
 *
 * 2026-11-08 (Sdema review K2 / K8): every row is built by the emitter the attack stories use
 * (sim/emitters mde / entra / sentinel / windowsSecurity), so a decoy has an attack's columns and is
 * told apart only by its values: an EDR detection is the full DeviceProcessEvents row and then the
 * Defender alert on it; a sign-in carries its device and its MFA step; a Sentinel alert is a full
 * SecurityAlert of the event type the attacks' analytics use (decoyShape.test.ts holds the parity).
 */
import type { TelemetryEvent, EventType } from "@/lib/sim/types";
import type { CompanyAssets, RosterUser } from "@/lib/sim/companyProfilesMeta";
import type { Stack } from "@/lib/logs/native/stack";
import { intIn, pickOf, rankByHistory, shuffled, docIp } from "./variety";
import { mdeProcess, mdeAlert } from "@/lib/sim/emitters/mde";
import { entraSignIn as entraEmit } from "@/lib/sim/emitters/entra";
import { sentinelAlert as sentinelEmit } from "@/lib/sim/emitters/sentinel";
import { winFailedLogon } from "@/lib/sim/emitters/windowsSecurity";
import { makeCtx } from "@/lib/logs/native/ctx";
import { imageHashes } from "@/lib/logs/native/sources/_proc-identity";
import { hashString } from "@/lib/sim/rng";
import { techniqueById, tacticById } from "@/lib/mitre/attack";

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
  /** The caller's own words (the incident's description field). */
  details?: string;
  /** Incident subcategory (an out-of-the-box choice value). */
  subcategory?: string;
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
  /** An account the attacks use (a victim, a sprayed or abused account): never the subject of a decoy. */
  attackUser: (account: string) => boolean;
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

/**
 * A Microsoft Sentinel analytics alert (SecurityAlert), built by the same emitter the stories' alerts use
 * (sim/emitters/sentinel), so a decoy alert and an attack alert carry the same columns: TenantId,
 * SystemAlertId, StartTime / EndTime, Tactics, Techniques, typed Entities. The event type is the one the
 * attack alerts use for the same kind of analytic (behaviour over sign-ins, files or mail: ueba_anomaly;
 * an Azure control-plane analytic: cloud_api_call), never a type only decoys carry.
 */
function sentinelAlert(c: Ctx, o: { id: string; name: string; severity: "high" | "medium"; host?: string; user?: string; ip?: string;
  props: Record<string, string>; fp: string; mitre?: string; mcas?: boolean; tactic?: string; detail?: string; eventType?: EventType }): TelemetryEvent {
  const ev = sentinelEmit({
    id: o.id, ts: c.ts, companyId: c.companyId, host: o.host, user: o.user ?? null, srcIp: o.ip,
    alertName: o.name, severity: o.severity, eventType: o.eventType ?? "ueba_anomaly", mitre: o.mitre, tactic: o.tactic,
    ...(o.detail ? { detail: o.detail } : {}),
    ...(o.mcas ? { productName: "Microsoft Cloud App Security", providerName: "MCAS" } : {}),
    tenantId: makeCtx(c.companyId).tenant.azureTenantId,
    extendedProperties: o.props,
  });
  return { ...ev, is_detection: true, expected_verdict: "fp", fp_explanation: o.fp, description: `Sentinel raised "${o.name}"` } as TelemetryEvent;
}

/** A process an EDR maker shows: its image, command line, parent and the account it runs as. */
interface EdrProcSpec {
  name: string; path?: string; cmdline: string; parent: string; parentPath?: string;
  /** "system": a service / agent process (NT AUTHORITY\SYSTEM); else the person's own account. */
  system?: boolean; integrity?: "Medium" | "High" | "System"; signed?: boolean; sha256?: string;
}
/**
 * An EDR detection as Defender for Endpoint writes it, relabelled to the session's EDR: the process's
 * DeviceProcessEvents row (sim/emitters/mde mdeProcess, every column a story's process row has) and then
 * the alert on it (mdeAlert, with the same process as its evidence). The alert is the maker's last row.
 * The process row is ordinary telemetry (no verdict field of its own): the alert is what the analyst triages.
 */
function edrDetection(c: Ctx, o: { tag: string; host: string; userEmail?: string; severity: "high" | "medium" | "low";
  proc: EdrProcSpec; alertTitle: string; category: string; description: string; fp: string; mitre: string; techniqueName?: string;
  file?: { size?: number } }): TelemetryEvent[] {
  const pid = 4 * intIn(300, 4000, c.rnd), ppid = 4 * intIn(150, 2900, c.rnd);
  const path = o.proc.path ?? `C:\\Windows\\System32\\${o.proc.name}`;
  const sys = !!o.proc.system;
  const user = sys ? null : o.userEmail;
  // A signed vendor binary carries the fleet's own hash for its path (the native renderer derives it, the same on
  // every host); only an unsigned, one-off build gets a hash of its own.
  const sha256 = o.proc.signed === false ? o.proc.sha256 ?? sha256Of(`${c.companyId}:${o.host}:${path.toLowerCase()}`) : undefined;
  const alertSha = sha256 ?? imageHashes(makeCtx(c.companyId), path).sha256;
  const runAs = sys ? "NT AUTHORITY\\SYSTEM" : undefined;
  const parentPath = o.proc.parentPath ?? parentPathOf(o.proc.parent);
  const procEv = mdeProcess({
    id: `fpa_${o.tag}ev_${c.n}_0`, ts: c.ts, companyId: c.companyId, host: o.host, user,
    processName: o.proc.name, processPath: path, cmdline: o.proc.cmdline, parentName: o.proc.parent, pid, parentPid: ppid,
    sha256, signed: o.proc.signed ?? true, integrity: o.proc.integrity ?? (sys ? "System" : "Medium"),
    ...(sys ? { runAsUser: runAs, accountName: "system", accountDomain: "nt authority" } : {}),
    extra: { InitiatingProcessFolderPath: parentPath },
    severity: "low", description: `${o.proc.parent} started ${o.proc.name} on ${o.host}`,
  });
  delete (procEv as Partial<TelemetryEvent>).is_detection;
  const process: NonNullable<TelemetryEvent["process"]> = { ...procEv.process! };
  const alert = mdeAlert({
    id: `fpa_${o.tag}_${c.n}`, ts: c.ts, companyId: c.companyId, host: o.host, user,
    alertTitle: o.alertTitle, category: o.category, detectionSource: "EDR", evidenceRole: "Impacted", mitre: o.mitre,
    ...(o.techniqueName ? { techniqueName: o.techniqueName } : {}),
    // The alert names the file it fired on: a signed tool's fleet build (the hash its process row derives), else its own.
    mdeIncidentId: String(intIn(4000, 9800, c.rnd)), severity: o.severity, sha256: alertSha,
    extra: {
      "process.name": o.proc.name, "process.executable": path, "process.command_line": o.proc.cmdline,
      "process.parent.name": o.proc.parent, "process.hash.sha256": alertSha,
      ...(o.file?.size ? { "file.size": o.file.size } : {}),
      "action_result": "detected",
    },
    description: o.description,
  });
  if (sys) { alert.raw!["AccountName"] = "system"; alert.raw!["AccountDomain"] = "nt authority"; }
  // R2: an EDR alert names its tactic and the parent's command line whatever the verdict (Falcon
  // tactic / tactic_id / objective, parent_details.cmdline): a decoy alert without them was a tell.
  alert.raw!["process.parent.command_line"] = parentCmdOf(o.proc.parent, parentPath);
  const tactic = tacticOf(o.mitre);
  return [procEv, { ...alert, process, src_ip: procEv.src_ip, ...(tactic ? { mitre_tactic: tactic } : {}), expected_verdict: "fp", fp_explanation: o.fp } as TelemetryEvent];
}
const PARENT_PATH: Record<string, string> = {
  "explorer.exe": "C:\\Windows\\explorer.exe", "services.exe": "C:\\Windows\\System32\\services.exe", "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
  "cmd.exe": "C:\\Windows\\System32\\cmd.exe", "powershell.exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "WindowsTerminal.exe": "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe",
  "CcmExec.exe": "C:\\Windows\\CCM\\CcmExec.exe", "AgentExecutor.exe": "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe",
  "PDQDeployRunner-1.exe": "C:\\Windows\\AdminArsenal\\PDQDeployRunner\\service-1\\PDQDeployRunner-1.exe",
  "Wireshark.exe": "C:\\Program Files\\Wireshark\\Wireshark.exe", "devenv.exe": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\Common7\\IDE\\devenv.exe",
  "dotnet.exe": "C:\\Program Files\\dotnet\\dotnet.exe", "Code.exe": "C:\\Program Files\\Microsoft VS Code\\Code.exe",
};
const parentPathOf = (name: string) => PARENT_PATH[name] ?? `C:\\Windows\\System32\\${name}`;
/** The parent's command line as Windows records it: the shell and the service host as they start, an agent with its usual switches. */
const PARENT_CMD: Record<string, string> = {
  "explorer.exe": "C:\\Windows\\Explorer.EXE",
  "services.exe": "C:\\Windows\\system32\\services.exe",
  "svchost.exe": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
  "cmd.exe": "\"C:\\Windows\\system32\\cmd.exe\" ",
  "powershell.exe": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ",
  "CcmExec.exe": "C:\\Windows\\CCM\\CcmExec.exe",
  "AgentExecutor.exe": "\"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe\" -powershell -executionPolicy bypass",
};
const parentCmdOf = (name: string, path: string) => PARENT_CMD[name] ?? (path.includes(" ") ? `"${path}"` : path);
/** The tactic of an ATT&CK technique (the first one it is listed under), by name. */
const tacticOf = (technique: string) => { const t = techniqueById(technique.split(",")[0].trim()); return t ? tacticById(t.tactic)?.name : undefined; };
const sha256Of = (seed: string) => {
  let out = "";
  for (let i = 0; out.length < 64; i++) out += (hashString(`${seed}:${i}`) >>> 0).toString(16).padStart(8, "0");
  return out.slice(0, 64);
};

/** The device a person signs in from, as Entra ID records it (deviceDetail). */
interface SignInDevice { name: string; os: string; browser: string; trustType: "Azure AD joined" | "Hybrid Azure AD joined" | "Azure AD registered"; compliant: boolean; managed: boolean }
/**
 * An Entra ID sign-in (relabelled in an Okta shop), built by the stories' emitter (sim/emitters/entra):
 * the full SigninLogs row with the device (deviceDetail), the authentication steps (authenticationDetails),
 * the Conditional Access result and, for an Identity Protection alert, the risk detection that raised it.
 * The device and the MFA step are what prove or disprove a sign-in, so every decoy sign-in carries them.
 */
function entraSignIn(c: Ctx, o: { id: string; user: string; ip: string; city: string; country: string; lat?: number; lon?: number;
  description: string; fp: string; device: SignInDevice | null; mfa: "push" | "sms" | "token" | null; result?: "success" | "failure";
  errorCode?: string; app?: string; clientApp?: string; ua?: string; risk?: { level: "low" | "medium"; detection: "unfamiliarFeatures" | "anonymizedIPAddress" };
  detection?: boolean; severity?: "low" | "medium" }): TelemetryEvent {
  const ok = (o.result ?? "success") === "success";
  const step = (offsetMs: number) => new Date(Date.parse(c.ts) - offsetMs).toISOString();
  const steps: Record<string, unknown>[] = [{
    authenticationStepDateTime: step(o.mfa ? 18_000 : 0), authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud",
    succeeded: ok, authenticationStepResultDetail: ok ? "Correct password" : "Invalid username or password or Invalid on-premise username or password.",
    authenticationStepRequirement: "Primary authentication",
  }];
  if (ok && o.mfa) steps.push({
    authenticationStepDateTime: step(0),
    authenticationMethod: o.mfa === "token" ? "Previously satisfied" : o.mfa === "sms" ? "Text message" : "Mobile app notification",
    authenticationMethodDetail: o.mfa === "token" ? null : o.mfa === "sms" ? "Phone number" : "Microsoft Authenticator",
    succeeded: true, authenticationStepResultDetail: o.mfa === "token" ? "MFA requirement satisfied by claim in the token" : "MFA successfully completed",
    authenticationStepRequirement: "Multifactor authentication",
  });
  const dev = o.device;
  const app = o.app ?? "Office 365 Exchange Online";
  const geo = o.lat !== undefined ? { lat: o.lat, lon: o.lon! } : CITY_GEO[o.city];
  // deviceDetail.operatingSystem / browser are Entra's parse of the user agent, present with or without a registered device.
  const mobile = /iOS|Android/i.test(o.ua ?? "");
  const ev = entraEmit({
    id: o.id, ts: c.ts, companyId: c.companyId, user: o.user, srcIp: o.ip, result: o.result ?? "success", errorCode: o.errorCode,
    app, appId: APP_ID[app], resource: APP_RESOURCE[app] ?? app, mfa: !!o.mfa && ok, isInteractive: true,
    asn: 64496 + (hashString(`${c.companyId}:asn:${o.ip}`) % 16),
    managed: dev?.managed ?? false, compliant: dev?.compliant ?? false,
    ...(dev ? { deviceId: makeCtx(c.companyId).uuid(`${c.companyId}:entra-device:${dev.name}`), deviceName: dev.name, os: dev.os, browser: dev.browser, trustType: dev.trustType }
      : { os: mobile ? (/iOS/i.test(o.ua ?? "") ? "Ios" : "Android") : "Windows 10", browser: mobile ? "Mobile App" : "Edge 141.0.0" }),
    ...(o.ua ? { userAgent: o.ua } : {}),
    riskLevel: o.risk?.level ?? "none", riskEventTypes: o.risk ? [o.risk.detection] : [], riskDetail: "none",
    conditionalAccess: ok ? "success" : "notApplicable",
    sessionId: makeCtx(c.companyId).uuid(`${o.id}:session`),
    incomingTokenType: "none",
    geo: { city: o.city, country: o.country, ...(geo ? { latitude: geo.lat, longitude: geo.lon } : {}) },
    severity: o.severity ?? (ok ? "medium" : "low"),
    extra: {
      "azure.signinlogs.properties.authenticationDetails": steps,
      ...(o.clientApp ? { "azure.signinlogs.properties.clientAppUsed": o.clientApp } : {}),
    },
    description: o.description,
  });
  return { ...ev, ...(o.detection ? { is_detection: true } : {}), expected_verdict: "fp", fp_explanation: o.fp } as TelemetryEvent;
}

/** First-party application ids Entra ID records (appId) and the resource each one signs in to. */
const APP_ID: Record<string, string> = {
  "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000", "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
  "Office 365 SharePoint Online": "00000003-0000-0ff1-ce00-000000000000",
};
const APP_RESOURCE: Record<string, string> = { "Microsoft Teams": "Microsoft Graph" };
/** Coordinates of the cities a decoy sign-in or an office egress resolves to. */
const CITY_GEO: Record<string, { lat: number; lon: number }> = {
  London: { lat: 51.5074, lon: -0.1278 }, "Tel Aviv": { lat: 32.0853, lon: 34.7818 }, Amsterdam: { lat: 52.3676, lon: 4.9041 },
  "Frankfurt am Main": { lat: 50.1109, lon: 8.6821 }, Zurich: { lat: 47.3769, lon: 8.5417 },
};
/** A Windows browser user agent (Entra parses deviceDetail.operatingSystem / browser from it). */
const EDGE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
const managedLaptop = (host: string, hybrid: boolean): SignInDevice =>
  ({ name: host, os: "Windows 11", browser: "Edge 141.0.0", trustType: hybrid ? "Hybrid Azure AD joined" : "Azure AD joined", compliant: true, managed: true });

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
    const ev = sentinelAlert(c, { id: `fpa_scan_${c.n}`, name: pickOf(["Port scan from an internal host", "Internal host scanning many ports"], c.rnd), severity: "high", host: s.host, ip: s.ip,
      user: mail(c.assets, s.account),
      detail: "One internal source connected to many ports on many hosts inside the query period.",
      props: { "Distinct Ports": String(ports), "Distinct Hosts": String(hosts), "Query Period": `00:${String(mins).padStart(2, "0")}:00`, "Scanner Account": s.account },
      fp: `Authorised ${s.product} scan from the registered scanner ${s.host} (${s.ip}), the standard change ${t} for the scan window.`, mitre: "T1046", tactic: "Discovery" });
    return { makerId: "scan_sentinel", kind: "scan", verdict: "fp", rows: [ev], host: s.host,
      ticket: { table: "change_request", number: t, state: "Implement", short: `${s.product} authenticated scan of the server and workstation ranges`, ci: s.host, assignedTo: s.account, group: "Security Operations", window: [-intIn(20, 90, c.rnd), intIn(60, 240, c.rnd)] } };
  } },
  // ── The same kind of scan seen by the firewall's threat log (no SIEM needed).
  { id: "scan_firewall", kind: "scan", make: c => {
    const s = c.scanner, t = num("CHG", c);
    const dst = `${c.assets.subnet}.${intIn(2, 230, c.rnd)}`;
    const sig = pickOf([["TCP Port Scan", "TCP port scan", "8001"], ["Host Sweep", "Host sweep", "8002"], ["UDP Port Scan", "UDP port scan", "8003"]] as const, c.rnd);
    const ev = {
      id: `fpa_scanfw_${c.n}`, ts: c.ts, source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "ids_signature", severity: "medium", is_detection: true,
      hostname: s.host, src_ip: s.ip, dst_ip: dst, dst_port: pickOf([22, 135, 443, 445, 3389, 8080], c.rnd), expected_verdict: "fp", mitre_technique: "T1046",
      fp_explanation: `${s.host} (${s.ip}) is the registered ${s.product} scanner; its scan window is the standard change ${t}.`,
      description: `${sig[1]} from ${s.ip} toward ${dst}`,
      raw: { "event.action": "ids_alert", "event.outcome": "success", "source.ip": s.ip, "destination.ip": dst, "ids.signature_id": sig[2],
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
    const psx = pickOf(["PsExec.exe", "PsExec64.exe"], c.rnd);
    const proc: EdrProcSpec = tool === "psexec"
      ? { name: psx, path: `C:\\Tools\\SysinternalsSuite\\${psx}`, parent: "cmd.exe", integrity: "High",
          cmdline: `${psx} -accepteula \\\\${target} ${pickOf(["-s ", "-h ", ""], c.rnd)}cmd /c "${task.cmd}"` }
      : tool === "psremoting"
        ? { name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent: pickOf(["explorer.exe", "WindowsTerminal.exe"], c.rnd), integrity: "High",
            cmdline: `powershell.exe -NoProfile -Command "Invoke-Command -ComputerName ${target} -ScriptBlock { cmd /c '${task.cmd}' }"` }
        : tool === "wmi"
          ? { name: "WMIC.exe", path: "C:\\Windows\\System32\\wbem\\WMIC.exe", parent: "cmd.exe", integrity: "High", cmdline: `wmic /node:"${target}" process call create "cmd.exe /c ${task.cmd}"` }
          : { name: "winrs.exe", parent: "cmd.exe", integrity: "High", cmdline: `winrs -r:${target} cmd /c "${task.cmd}"` };
    const label = { psexec: "PsExec", psremoting: "PowerShell remoting", wmi: "WMI", winrs: "WinRM (winrs)" }[tool];
    const missHost = c.miss ? c.server() : null;
    const rows = edrDetection(c, { tag: "remote", host: admin.host, userEmail: admin.email, severity: "high", proc,
      alertTitle: tool === "psremoting" ? "Suspicious PowerShell command line" : tool === "wmi" ? "Suspicious WMI process creation" : "Suspicious remote activity",
      category: tool === "psremoting" || tool === "wmi" ? "Execution" : "LateralMovement", mitre: tool === "psexec" ? "T1569.002" : tool === "wmi" ? "T1047" : "T1021.006",
      description: `${proc.name} on ${admin.host} ran a command on ${target} (${label})`,
      fp: `IT administrator ${admin.name} used ${label} to ${task.what} on ${target} under change ${t}.` });
    const ev = rows[rows.length - 1];
    if (missHost) asMiss(ev, `IT says change ${t} covers ${missHost} only. Nobody approved remote work on ${target}; ${admin.name} has to explain it.`);
    return { makerId: "remote_admin", kind: "remote_admin", verdict: missHost ? "escalate" : "fp", rows, person: admin.email, host: admin.host,
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
    const rows = edrDetection(c, { tag: "mgmt", host, severity: pickOf(["high", "medium"] as const, c.rnd), mitre: agent.name === "cmd.exe" ? "T1059.003" : "T1059.001",
      alertTitle: agent.name === "cmd.exe" ? "Suspicious behavior by cmd.exe was observed" : "Suspicious PowerShell command line", category: "Execution",
      proc: { name: agent.name, path: agent.name === "cmd.exe" ? "C:\\Windows\\System32\\cmd.exe" : "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent: agent.parent, system: true, cmdline: agent.cmd },
      description: `${agent.name} launched by ${agent.parent} on ${host} with the execution policy bypassed`,
      fp: `${agent.label} deployment by IT under change ${t}; the script is the package the agent pulled from its own distribution point.` });
    return { makerId: "mgmt_script", kind: "mgmt_script", verdict: "fp", rows, host,
      ticket: { table: "change_request", number: t, state: pickOf(["Implement", "Scheduled"], c.rnd), short: `${agent.label} deployment wave ${intIn(1, 6, c.rnd)} to workstations`, group: "End User Computing", window: [-intIn(60, 300, c.rnd), intIn(120, 600, c.rnd)] } };
  } },
  // ── Approved business travel: a sign-in from abroad, MFA satisfied.
  { id: "travel", kind: "travel", make: c => {
    const p = c.person();
    if (!p) return null;
    const [city, country, lat, lon] = pickOf(CITIES, c.rnd), ip = docIp(c.rnd, c.ips), t = num("RITM", c);
    const ev = entraSignIn(c, { id: `fpa_travel_${c.n}`, user: p.email, ip, city, country, lat, lon, risk: { level: "medium", detection: "unfamiliarFeatures" }, detection: true,
      device: managedLaptop(p.host, c.rnd() < 0.5), mfa: "push", app: pickOf(["Office 365 Exchange Online", "Microsoft Teams", "Office 365 SharePoint Online"], c.rnd), ua: EDGE_UA,
      description: `${p.email} signed in from ${city}, ${country} (${ip}), first sign-in from this country`,
      fp: `${p.name} is on approved business travel to ${city} (travel request ${t}); the sign-in is from the managed, compliant laptop ${p.host} and passed MFA in the Authenticator app.` });
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
    const ev = entraSignIn(c, { id: `fpa_egress_${c.n}`, user: p.email, ip, city, country, lat, lon, detection: true,
      risk: relay ? { level: "medium", detection: "anonymizedIPAddress" } : { level: "low", detection: "unfamiliarFeatures" },
      device: relay ? { name: "iPhone", os: "Ios 18.1.1", browser: "Mobile Safari", trustType: "Azure AD registered", compliant: true, managed: true } : managedLaptop(p.host, c.rnd() < 0.5),
      mfa: relay ? "token" : "push", ...(relay ? { clientApp: "Mobile Apps and Desktop clients", ua: "Outlook-iOS/2.0" } : { ua: EDGE_UA }),
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
    // The new phone signs in over its mobile carrier in the user's own city.
    const phone = pickOf(PHONES, c.rnd), office = c.assets.office, ip = docIp(c.rnd, c.ips);
    const t = num("INC", c);
    const ios = phone.startsWith("iPhone");
    const ev = entraSignIn(c, { id: `fpa_phone_${c.n}`, user: p.email, ip, city: office?.city ?? "London", country: office?.country ?? "United Kingdom", detection: true,
      risk: { level: "low", detection: "unfamiliarFeatures" }, mfa: "push", clientApp: "Mobile Apps and Desktop clients", ua: ios ? "Outlook-iOS/2.0" : "Outlook-Android/2.0",
      device: { name: phone, os: ios ? "Ios 18.1.1" : "Android 15", browser: ios ? "Mobile Safari" : "Chrome Mobile", trustType: "Azure AD registered", compliant: true, managed: true },
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
    const name = pickOf(["Repeated failed sign-ins for one account", "Many failed sign-ins for one user"], c.rnd), ip = docIp(c.rnd, c.ips);
    const ev = sentinelAlert(c, { id: `fpa_stale_${c.n}`, name, severity: "medium", user: p.email, ip,
      detail: "One account failed to sign in many times in the query period.",
      props: { "Failed sign-ins": String(fails), "ResultType": "50126", "Client app": app, "Distinct IPs": "1", "Query Period": "01:00:00" },
      fp: `${p.name} changed their password this morning; ${app} on their own phone kept retrying the old one from the phone's mobile connection. One source, one known device, no success.`, mitre: "T1110.001", tactic: "CredentialAccess" });
    // The analytic counts sign-in rows: the latest of them reach the feed with it, as SigninLogs holds them.
    const client = MAIL_CLIENTS[app];
    const tries = [0, 1].map(k => {
      const e = entraSignIn(c, { id: `fpa_staleev_${c.n}_${k}`, user: p.email, ip, city: c.assets.office?.city ?? "London", country: c.assets.office?.country ?? "United Kingdom",
        result: "failure", errorCode: "50126", device: null, mfa: null, clientApp: client.clientApp, ua: client.ua, severity: "low",
        description: `${p.email} failed to sign in: wrong password`,
        fp: `${app} on ${p.name}'s own phone retrying the password from before this morning's change.` });
      return { ...e, network: { user_agent: client.ua } } as TelemetryEvent;
    });
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
    const ev = sentinelAlert(c, { id: `fpa_backup_${c.n}`, name: pickOf(["Mass file access by a single account", "Unusual volume of file reads"], c.rnd), severity: "high", host: c.assets.fileServer, user: mail(c.assets, svc),
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
      { name: "Rubeus.exe", cmd: `${dir}\\Rubeus.exe kerberoast /outfile:${dir}\\hashes.txt`, mitre: "T1558.003", what: "Kerberoasting", threat: "HackTool:MSIL/Rubeus", category: "CredentialAccess" },
      { name: "SharpHound.exe", cmd: `${dir}\\SharpHound.exe -c All --zipfilename ${firm[1]}_${intIn(100, 999, c.rnd)}.zip`, mitre: "T1087.002", what: "AD collection", threat: "HackTool:MSIL/SharpHound", category: "Discovery" },
      { name: "Certify.exe", cmd: `${dir}\\Certify.exe find /vulnerable`, mitre: "T1649", what: "certificate template enumeration", threat: "HackTool:MSIL/Certify", category: "CredentialAccess" },
      { name: "Seatbelt.exe", cmd: `${dir}\\Seatbelt.exe -group=user`, mitre: "T1082", what: "host survey", threat: "HackTool:MSIL/Seatbelt", category: "Discovery" },
    ], c.rnd);
    const missHost = c.miss ? c.workstation() : null;
    const rows = edrDetection(c, { tag: "redteam", host, userEmail: mail(c.assets, acct), severity: "high", category: tool.category, mitre: tool.mitre,
      alertTitle: tool.threat,
      proc: { name: tool.name, path: `${dir}\\${tool.name}`, parent: "powershell.exe", cmdline: tool.cmd, signed: false },
      description: `${tool.name} ran on ${host} as ${acct}`,
      fp: `${firm[0]} is running the authorised internal penetration test (change ${t}) from ${host} with the test account ${acct}; ${tool.what} is in the rules of engagement.` });
    const ev = rows[rows.length - 1];
    if (missHost) asMiss(ev, `The test under ${t} is scoped to ${missHost}. ${host} is not in the rules of engagement, so this run is outside the approval.`);
    return { makerId: "redteam_tool", kind: "redteam", verdict: missHost ? "escalate" : "fp", rows, host,
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
    const rows = edrDetection(c, { tag: "pua", host: p.host, userEmail: p.email, severity: "medium", category: "UnwantedSoftware", mitre: "T1046",
      alertTitle: `'${tool.label}' unwanted software was detected`,
      proc: { name: tool.exe, path, parent: "explorer.exe", cmdline: `"${path}"` },
      description: `Potentially unwanted application ${tool.exe} ran on ${p.host}`,
      fp: `${tool.label} is on IT's approved tool list; ${p.name} used it to find a printer that dropped off the network. The binary is the vendor's signed release.` });
    return { makerId: "pua_admin_tool", kind: "pua", verdict: "fp", rows, person: p.email, host: p.host,
      ticket: c.rnd() < 0.5 ? { table: "incident", number: num("INC", c), state: "In Progress", short: `Printer on floor ${intIn(1, 6, c.rnd)} not reachable`, requestedFor: p.email, assignedTo: p.email, group: "Service Desk" } : undefined };
  } },
  // ── A developer's packet capture.
  { id: "pcap_dev", kind: "sniffing", make: c => {
    const p = c.person(DEV_RE);
    if (!p) return null;
    const tool = pickOf([
      { name: "dumpcap.exe", path: "C:\\Program Files\\Wireshark\\dumpcap.exe", parent: "Wireshark.exe", cmd: `"C:\\Program Files\\Wireshark\\dumpcap.exe" -i ${intIn(1, 4, c.rnd)} -w C:\\Users\\${p.name}\\captures\\tls-${intIn(100, 999, c.rnd)}.pcapng` },
      { name: "tshark.exe", path: "C:\\Program Files\\Wireshark\\tshark.exe", parent: "powershell.exe", cmd: `"C:\\Program Files\\Wireshark\\tshark.exe" -i Ethernet -f "port 443" -a duration:${pickOf([60, 120, 300], c.rnd)} -w api-${intIn(100, 999, c.rnd)}.pcapng` },
      { name: "pktmon.exe", path: "C:\\Windows\\System32\\PktMon.exe", parent: "cmd.exe", cmd: `pktmon start --capture --comp nics --pkt-size 0 --file-name C:\\Temp\\pktmon-${intIn(100, 999, c.rnd)}.etl` },
      { name: "netsh.exe", path: "C:\\Windows\\System32\\netsh.exe", parent: "cmd.exe", cmd: `netsh trace start capture=yes tracefile=C:\\Temp\\trace-${intIn(100, 999, c.rnd)}.etl maxsize=${pickOf([256, 512], c.rnd)}` },
    ], c.rnd);
    const rows = edrDetection(c, { tag: "pcap", host: p.host, userEmail: p.email, severity: "medium", category: "Discovery", mitre: "T1040",
      alertTitle: "Suspicious network sniffing activity",
      proc: { name: tool.name, path: tool.path, parent: tool.parent, cmdline: tool.cmd, integrity: "High" },
      description: `Network capture started by ${tool.name} on ${p.host}`,
      fp: `${p.name} is debugging a TLS handshake to the staging API; packet capture on their own laptop is allowed for developers and the capture stays on it.` });
    return { makerId: "pcap_dev", kind: "sniffing", verdict: "fp", rows, person: p.email, host: p.host };
  } },
  // ── A cloud admin's mass permission change under a ticket (Azure: a SIEM analytic over the Activity log).
  { id: "cloud_perm_azure", kind: "cloud_perm", siemOnly: true, canMiss: true, fits: c => c.platforms.has("azure") || c.stack.cloud === "azure_activity", make: c => {
    const p = c.person(IT_RE);
    if (!p) return null;
    const t = num("CHG", c), n = intIn(12, 48, c.rnd), rg = pickOf(["rg-data-platform", "rg-shared-services", "rg-analytics", "rg-web-prod"], c.rnd);
    const role = pickOf(["Reader", "Storage Blob Data Reader", "Contributor", "Monitoring Reader"], c.rnd);
    const otherRg = c.miss ? pickOf(["rg-finance-prod", "rg-identity", "rg-keyvault-prod"], c.rnd) : null;
    const ev = sentinelAlert(c, { id: `fpa_azperm_${c.n}`, name: "Mass Azure RBAC role assignments by one user", severity: "medium", user: p.email, eventType: "cloud_api_call",
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
    const ev = sentinelAlert(c, { id: `fpa_fwd_${c.n}`, name: pickOf(["New inbox rule forwarding mail", "Mail forwarding rule created"], c.rnd), severity: "medium", user: p.email,
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
    const ev = sentinelAlert(c, { id: `fpa_massdl_${c.n}`, name: "Mass download by a single user", severity: "medium", user: p.email, mcas: true,
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
    const svcPool = c.assets.serviceAccounts.filter(s => !/backup|scan/.test(s) && !c.attackUser(s));
    const svc = pickOf(svcPool.length ? svcPool : ["svc-report"], c.rnd), fails = intIn(40, 300, c.rnd), t = num("CHG", c);
    const ev = sentinelAlert(c, { id: `fpa_svccred_${c.n}`, name: "Repeated failed logons for one account on one host", severity: "medium", host: server, user: mail(c.assets, svc),
      props: { "Failed logons": String(fails), "Event ID": "4625", "Status": "0xC000006A", "Logon type": "4", "Query Period": "01:00:00" },
      fp: `${svc}'s password was rotated under change ${t}; a scheduled task on ${server} still runs with the old one (logon type 4, batch). One host, one account.`, mitre: "T1110", tactic: "CredentialAccess" });
    // The 4625 events the analytic counts: the latest of them reach the feed with it.
    const logons = [0, 1].map(k => {
      const e = winFailedLogon({ id: `fpa_svccredev_${c.n}_${k}`, ts: c.ts, companyId: c.companyId, host: server, targetUser: svc, userEmail: mail(c.assets, svc),
        subStatus: "0xC000006A", logonType: 4, authPackage: "Negotiate", workstation: server, severity: "low",
        description: `${server} rejected a batch logon for ${svc}` });
      // A batch logon is requested by the Task Scheduler on the server itself: the machine account is the
      // subject, Advapi the logon process, svchost the caller, and there is no network source.
      const raw = e.raw as Record<string, unknown>;
      Object.assign(raw, {
        "winlog.event_data.SubjectUserSid": "S-1-5-18", "winlog.event_data.SubjectUserName": `${server}$`, "winlog.event_data.SubjectDomainName": c.assets.netbios,
        "winlog.event_data.LogonProcessName": "Advapi  ", "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe",
        "winlog.event_data.IpAddress": "-", "winlog.event_data.IpPort": "-",
      });
      return { ...e, expected_verdict: "fp", fp_explanation: `The scheduled task on ${server} still runs as ${svc} with the password from before change ${t}.` } as TelemetryEvent;
    });
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
    const rows = edrDetection(c, { tag: "lolbin", host: p.host, userEmail: p.email, severity: "medium", category: "CommandAndControl", mitre: "T1105",
      alertTitle: "Suspicious file download",
      proc: { name: tool.name, parent: "cmd.exe", cmdline: tool.cmd },
      description: `${tool.name} downloaded a file on ${p.host}`,
      fp: `${p.name} pulled ${file} from IT's own internal repository on ${c.assets.fileServer}; the source is internal and the file is the published package.` });
    return { makerId: "lolbin_download", kind: "lolbin", verdict: "fp", rows, person: p.email, host: p.host };
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
    const rows = edrDetection(c, { tag: "rmm", host: p.host, userEmail: p.email, severity: "medium", category: "CommandAndControl", mitre: "T1219",
      alertTitle: "Remote access software was started",
      proc: { name: tool.name, path: tool.path, parent: "services.exe", system: true, cmdline: `"${tool.path}"` },
      description: `${tool.label} remote session on ${p.host}`,
      fp: `The service desk's licensed ${tool.label} is the company's remote-support tool; ${agent.name} connected to fix ${p.name}'s Outlook crash under incident ${t}.` });
    return { makerId: "remote_support", kind: "remote_support", verdict: "fp", rows, person: p.email, host: p.host,
      ticket: { table: "incident", number: t, state: "In Progress", short: "Outlook crashes when opening a shared calendar", requestedFor: p.email, assignedTo: agent.email, group: "Service Desk" } };
  } },
  // ── A freshly compiled, unsigned build run from a developer's workspace (low-prevalence binary).
  { id: "dev_build", kind: "unsigned_build", make: c => {
    const p = c.person(DEV_RE);
    if (!p) return null;
    const app = pickOf(["invoice-sync", "ledger-cli", "route-planner", "report-gen", "api-mock"], c.rnd);
    const path = `C:\\Users\\${p.name}\\source\\repos\\${app}\\bin\\${pickOf(["Debug", "Release"], c.rnd)}\\net8.0\\${app}.exe`;
    const parent = pickOf(["devenv.exe", "dotnet.exe", "Code.exe"], c.rnd);
    const rows = edrDetection(c, { tag: "build", host: p.host, userEmail: p.email, severity: "medium", category: "Execution", mitre: "T1204.002",
      alertTitle: "Unsigned low-prevalence executable was run",
      proc: { name: `${app}.exe`, path, parent, cmdline: `"${path}" --env staging`, signed: false }, file: { size: sizeOf(1, 9, c) },
      description: `Unsigned, first-seen executable ${app}.exe ran on ${p.host}`,
      fp: `${p.name} built ${app} locally from the team's repository and ran it against staging; an unsigned build seen once is expected on a developer laptop.` });
    return { makerId: "dev_build", kind: "unsigned_build", verdict: "fp", rows, person: p.email, host: p.host };
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
  const attackUser = (a: string) => avoidUsers.has(a) || avoidUsers.has(mail(assets, a.replace(/@.*$/, "")));
  const base = { assets, companyId, rnd, ts, stack: opts.stack ?? {}, siem, platforms: new Set(opts.platforms ?? []), ips, scanner, attackUser,
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
  // Severity never gives the answer away (realism R8): when no benign-positive alert of the session is high,
  // the last unforced one gives its place to a maker whose alert is (a scanner, an admin's remote tool, a DLP hit).
  const high = (o: FpOut) => o.verdict === "fp" && o.rows.some(e => e.severity === "high" || e.severity === "critical");
  const slot = out.map((o, i) => ({ o, i })).reverse().find(x => !forced.some(f => f.id === x.o.makerId))?.i;
  if (out.length && !out.some(high) && slot !== undefined) {
    for (const m of order) {
      if (out.some(o => o.makerId === m.id) || [...kinds].some(k => k === m.kind && out[slot].kind !== k)) continue;
      const r = m.make({ ...base, n: slot, miss: false });
      if (r && r.rows.every(fits) && high(r)) { out[slot] = r; break; }
    }
  }
  return out;
}
