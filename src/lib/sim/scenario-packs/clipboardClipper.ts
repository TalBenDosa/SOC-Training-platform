/**
 * Scenario pack: "Wrong Wallet — Clipboard Clipper from a Trojanized Utility"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential
 * theft across accounts. A user installs a small "crypto portfolio tracker"
 * utility. Alongside the real (working) tracker, the installer drops a
 * second binary that sits quietly in the background and watches the
 * clipboard. Whenever it sees text matching a cryptocurrency wallet address
 * pattern, it silently replaces it with an attacker-controlled address
 * before the paste happens. This is a real and long-running malware
 * category — commercial "clipper" families have circulated since 2017 and
 * remain common in 2023-2026 bundled with cracked or "free" crypto tools.
 *
 * The teaching point is that the compromise is invisible at the moment it
 * matters. Nothing crashes, nothing pops up, and the only artefact of the
 * theft is that a payment that should have gone to one address went to
 * another — discovered after the money has already moved. The technical
 * story an analyst needs to reconstruct is entirely about persistence and
 * a background process quietly reading and writing the clipboard, not
 * about any single dramatic event.
 *
 * Covers T1115 (Clipboard Data) and T1059.003 (Command and Scripting
 * Interpreter: Windows Command Shell).
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildClipboardClipperScenario(
  scenarioId = "clipboard-clipper-2026",
): ScenarioBundle {
  const B = new Date("2026-05-04T09:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;

  const host = { hostname: "LAP-5528", ip: "10.14.27.19" };
  const victim = { email: "n.peretz@nexacorp.com", name: "Noa Peretz", sam: "n.peretz" };

  const downloadSite = "cryptotracker-lite.io";
  const c2 = "wallet-cfg-sync.net";

  const installerHash = makeSha256("cryptotracker_lite_setup_bundled_clipper_2026");
  const clipperHash   = makeSha256("clipsvc_helper_exe_clipper_binary_2026");
  const cmdHash       = makeSha256("windows_system32_cmd_exe_signed_microsoft");

  // EDR↔scenario integration (Phase 4): one incident, endpoint-primary →
  // edr_scope "edr". Alert-grade rows: the SentinelOne clipboard-hijacker
  // detection that opens the ticket, plus the clipboard-hijack behavioural
  // event (the crux). The rest is pivot-only telemetry in the process tree.
  const INCIDENT = "inc:clc:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The download. A small utility for a real, ordinary need.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_01_download",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Procurement Analyst",
      src_ip: host.ip,
      severity: "low",
      description:
        "LAP-5528 downloaded CryptoTrackerLite_Setup.exe from cryptotracker-lite.io at 09:20, allowed under the category computer-and-internet-info.",
      file: { name: "CryptoTrackerLite_Setup.exe", path: "/download/CryptoTrackerLite_Setup.exe", extension: "exe", size: 9_842_176, sha256: installerHash },
      network: {
        url: `https://${downloadSite}/download/CryptoTrackerLite_Setup.exe`,
        domain: downloadSite,
        method: "GET",
        status: 200,
        bytes_in: 9_842_176,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "104.21.87.203",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${downloadSite}/download/CryptoTrackerLite_Setup.exe`,
        "pan.filename": "CryptoTrackerLite_Setup.exe",
        "pan.filetype": "pe",
        "pan.file_hash": installerHash,
        "pan.direction": "download",
        "pan.session_id": "553012",
        "source.ip": host.ip,
        "url.domain": downloadSite,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. Installation. Unremarkable, user-initiated.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_02_install",
      ts: T(2 * MIN + 10_000),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "CryptoTrackerLite_Setup.exe ran from Downloads at 09:22, started by explorer.exe.",
      process: {
        name: "CryptoTrackerLite_Setup.exe",
        pid: 6214,
        path: "C:\\Users\\n.peretz\\Downloads\\CryptoTrackerLite_Setup.exe",
        parent_name: "explorer.exe",
        parent_pid: 3348,
        cmdline: "\"C:\\Users\\n.peretz\\Downloads\\CryptoTrackerLite_Setup.exe\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "high",
        hash: { sha256: installerHash },
      },
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.threat_level": "none",
        "s1.agent.version": "23.4.1.9",
        "s1.site.name": "Corp-Main",
        "s1.group.name": "Workstations",
        "process.name": "CryptoTrackerLite_Setup.exe",
        "process.pid": "6214",
        "process.executable": "C:\\Users\\n.peretz\\Downloads\\CryptoTrackerLite_Setup.exe",
        "process.command_line": "\"C:\\Users\\n.peretz\\Downloads\\CryptoTrackerLite_Setup.exe\"",
        "process.hash.sha256": installerHash,
        "process.parent.name": "explorer.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 3. A second, unsigned binary — the real tracker installs alongside it.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_03_clipper_written",
      ts: T(2 * MIN + 31_000),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "The installer wrote C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe, unsigned, 512 KB.",
      file: {
        name: "clipsvc_helper.exe",
        path: "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        extension: "exe",
        size: 524_288,
        sha256: clipperHash,
      },
      raw: {
        "s1.event_type": "FILE_CREATION",
        "s1.agent.version": "23.4.1.9",
        "file.name": "clipsvc_helper.exe",
        "file.path": "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        "file.size": "524288",
        "file.hash.sha256": clipperHash,
        "process.name": "CryptoTrackerLite_Setup.exe",
        "process.pid": "6214",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 4. Persistence set via a hidden command shell, not the installer's own
    //    installer routine — a `reg add` from cmd.exe, spawned by the setup
    //    process. This is the T1059.003 event: the interpreter that does it.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_04_persistence_cmd",
      ts: T(2 * MIN + 36_000),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "registry_set",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1059.003",
      mitre_tactic: "Execution",
      description:
        "cmd.exe, spawned by the installer, ran a hidden 'reg add' command adding ClipboardService to the user's Run key, pointing at the AppData binary.",
      process: {
        name: "cmd.exe",
        pid: 6288,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "CryptoTrackerLite_Setup.exe",
        parent_pid: 6214,
        cmdline:
          "cmd.exe /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v ClipboardService /t REG_SZ /d \"C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe\" /f",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "high",
        hash: { sha256: cmdHash },
      },
      registry: {
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        key: "ClipboardService",
        value: "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
      },
      raw: {
        "s1.event_type": "REGISTRY_MODIFICATION",
        "s1.agent.version": "23.4.1.9",
        "process.name": "cmd.exe",
        "process.pid": "6288",
        "process.executable": "C:\\Windows\\System32\\cmd.exe",
        "process.command_line":
          "cmd.exe /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v ClipboardService /t REG_SZ /d \"C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe\" /f",
        "process.hash.sha256": cmdHash,
        "process.code_signature.status": "trusted",
        "process.parent.name": "CryptoTrackerLite_Setup.exe",
        "process.parent.pid": "6214",
        "registry.hive": "HKEY_CURRENT_USER",
        "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry.value": "ClipboardService",
        "registry.data.strings": "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The background process starts.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_05_clipper_start",
      ts: T(2 * MIN + 44_000),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "clipsvc_helper.exe started for the first time, launched by the installer with no visible window.",
      process: {
        name: "clipsvc_helper.exe",
        pid: 6355,
        path: "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        parent_name: "CryptoTrackerLite_Setup.exe",
        parent_pid: 6214,
        cmdline: "clipsvc_helper.exe -silent",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: clipperHash },
      },
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.agent.version": "23.4.1.9",
        "process.name": "clipsvc_helper.exe",
        "process.pid": "6355",
        "process.executable": "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        "process.command_line": "clipsvc_helper.exe -silent",
        "process.hash.sha256": clipperHash,
        "process.code_signature.status": "unsigned",
        "process.parent.name": "CryptoTrackerLite_Setup.exe",
        "process.parent.pid": "6214",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 6. THE EVENT THAT MATTERS — the background process registers as a
    //    clipboard listener and begins reading/rewriting its content.
    //    Discovered two days later, when a vendor reported a payment never
    //    arrived.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_06_clipboard_hijack",
      ts: T(2 * HOUR + 15 * MIN),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "process_access",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1115",
      mitre_tactic: "Collection",
      is_detection: true, // alert-grade: the clipboard-hijack behavioural detection (the crux)
      description:
        "clipsvc_helper.exe registered a clipboard format listener and repeatedly rewrote clipboard content matching cryptocurrency wallet address patterns.",
      process: {
        name: "clipsvc_helper.exe",
        pid: 6355,
        path: "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        parent_name: "CryptoTrackerLite_Setup.exe",
        parent_pid: 6214,
        cmdline: "clipsvc_helper.exe -silent",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: clipperHash },
      },
      raw: {
        "s1.event_type": "Indicators",
        "s1.detection.classification": "Suspicious Activity",
        "s1.detection.classification_source": "Behavioral Engine",
        "s1.indicator.category": "Collection",
        "s1.indicator.name": "Process Monitors and Modifies Clipboard Content",
        "s1.indicator.tactic": "Collection",
        "s1.indicator.technique": "Clipboard Data",
        "s1.indicator.technique_id": "T1115",
        "s1.detection.description":
          "clipsvc_helper.exe called AddClipboardFormatListener and repeatedly invoked GetClipboardData/SetClipboardData in a polling loop, replacing text matching BTC/ETH wallet address regular expressions with a fixed attacker-controlled string.",
        "s1.mitigation_status": "not_mitigated",
        "process.name": "clipsvc_helper.exe",
        "process.pid": "6355",
        "process.executable": "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        "process.hash.sha256": clipperHash,
        "process.code_signature.status": "unsigned",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 7. Its periodic check-in for a fresh substitute-address list.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_07_config_pull",
      ts: T(2 * HOUR + 15 * MIN + 16_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "LAP-5528 requested /w/list.json from wallet-cfg-sync.net, allowed under the category newly-registered-domain.",
      network: { url: `https://${c2}/w/list.json`, domain: c2, method: "GET", status: 200, bytes_in: 612 },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "45.147.230.16",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${c2}/w/list.json`,
        "pan.session_id": "553840",
        "source.ip": host.ip,
        "url.domain": c2,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 8. The detection that opened the ticket — two days later, after a
    //    vendor reported a misdirected payment and the SOC pulled EDR
    //    telemetry for the paying employee's laptop.
    // ---------------------------------------------------------------------
    {
      id: "evt_clc_08_edr_alert",
      ts: T(2 * 24 * HOUR + 3 * HOUR),
      source: "edr",
      vendor: "SentinelOne",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      is_detection: true,    // the SentinelOne malware detection — the alert that opens the ticket
      edr_scope: "edr",      // endpoint-primary → investigated in the EDR console
      description:
        "SentinelOne raised a Critical detection on LAP-5528 for an unsigned AppData process holding a clipboard format listener, and killed it.",
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.threat.name": "Clipboard Hijacker (Generic)",
        "s1.threat.id": "TH-2291-2026",
        "s1.detection.classification": "Malware",
        "s1.detection.classification_source": "Behavioral Engine",
        "s1.mitigation_status": "mitigated",
        "s1.indicator.tactic": "Collection",
        "s1.indicator.technique": "Clipboard Data",
        "s1.indicator.technique_id": "T1115",
        "process.name": "clipsvc_helper.exe",
        "process.pid": "6355",
        "process.executable": "C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe",
        "process.hash.sha256": clipperHash,
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "action_result": "blocked",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: clipperHash,
      first_seen: T(2 * MIN + 31_000),
      last_seen: T(2 * 24 * HOUR + 3 * HOUR),
      reputation: "malicious",
      tags: ["clipper", "unsigned", "appdata", "clipboard-hijack"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(0),
      last_seen: T(2 * MIN + 36_000),
      reputation: "malicious",
      tags: ["bundled-installer", "trojanized"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(2 * HOUR + 15 * MIN + 16_000),
      last_seen: T(2 * HOUR + 15 * MIN + 16_000),
      reputation: "malicious",
      tags: ["c2", "wallet-config-distribution"],
    },
    {
      type: "domain",
      value: downloadSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["freeware-distribution", "trojanized"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(2 * 24 * HOUR + 3 * HOUR),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which event turns this from 'unwanted background software' into an active theft mechanism?",
      hint: "Compare evt_clc_05_clipper_start, which only shows the process launching, with evt_clc_06.",
      kind: "single",
      options: [
        { value: "hijack", label: "evt_clc_06_clipboard_hijack — the process registers a clipboard listener and begins substituting content" },
        { value: "start", label: "evt_clc_05_clipper_start — the process starting at all is the theft" },
        { value: "written", label: "evt_clc_03_clipper_written — writing an unsigned binary to disk is itself the theft" },
        { value: "config_pull", label: "evt_clc_07_config_pull — fetching a domain classified newly-registered-domain is the theft" },
      ],
      answer: "hijack",
      xp: 50,
      explanation:
        "evt_clc_05 only shows a process launching with no window — suspicious, but by itself indistinguishable from a hundred legitimate background helpers. evt_clc_06 is where the behaviour becomes theft: the detection description names the exact APIs (AddClipboardFormatListener, GetClipboardData, SetClipboardData) and states the process is replacing wallet-pattern text with a fixed attacker string. Writing a file (c) is preparation, not action, and fetching a config file (d) is how the substitute address gets updated, not how the theft happens.",
    },
    {
      id: "q2",
      prompt:
        "evt_clc_04 shows cmd.exe running a `reg add` command rather than the installer writing the registry key through its own installer routine. Why does that distinction matter for detection?",
      kind: "single",
      options: [
        { value: "interpreter_signal", label: "A command interpreter carrying out persistence is a distinct, higher-signal event from an installer's own file writes — T1059.003 in its own right" },
        { value: "no_difference", label: "It makes no difference — both methods write the same registry value and are equally invisible" },
        { value: "cmd_malicious", label: "cmd.exe is itself malicious here, since a legitimate installer would never invoke a command interpreter at all" },
        { value: "elevation_proof", label: "Spawning cmd.exe proves the installer escalated its privileges beyond what the user granted at install time" },
      ],
      answer: "interpreter_signal",
      xp: 50,
      explanation:
        "Most legitimate installers write their own Run keys directly through the Windows API as part of the installer framework, not by shelling out to cmd.exe with a `reg add` string. A visible interpreter process with a persistence command on its command line is exactly the kind of event EDR behavioural rules are built to catch, and it is why T1059.003 is tracked as its own technique separate from the resulting registry change. cmd.exe (option c) is not inherently malicious — legitimate installers do sometimes call it — but the combination of a hidden shell out plus a persistence-writing command line is the signal worth alerting on. Nothing in the event supports (d): process.parent.pid shows cmd.exe was launched by the already-elevated setup process, not the reverse.",
    },
    {
      id: "q3",
      prompt:
        "The incident was reported two days after infection, when a vendor said a payment never arrived. What does that gap tell you about detecting this class of malware?",
      hint: "Look at what evt_clc_06 and evt_clc_08 have in common, and how far apart their timestamps are.",
      kind: "single",
      options: [
        { value: "silent_until_business_impact", label: "A clipper produces almost no observable side effects until its outcome — a misdirected payment — surfaces through a business process outside the SOC's normal telemetry" },
        { value: "sensor_offline", label: "The SentinelOne sensor was offline for two days and only resumed logging when the ticket was raised" },
        { value: "detection_disabled", label: "The relevant behavioural indicator was disabled in policy and had to be manually re-enabled" },
        { value: "user_delay", label: "The user waited two days to report it after noticing something was wrong" },
      ],
      answer: "silent_until_business_impact",
      xp: 60,
      explanation:
        "Both evt_clc_06 and evt_clc_08 exist in the log the whole time — evt_clc_06 records the behavioural indicator firing at the two-hour mark, well before the ticket was opened. Nothing here shows the sensor going dark or a policy being disabled; the detection was sitting in the console, unescalated, because nothing about a background clipboard listener trips an urgent alert threshold on its own. That is the actual lesson: this class of malware causes no crash, no ransom note, and no obvious symptom, so the trigger for investigation ends up being a business event — a vendor calling about a missing payment — rather than a security alert being worked promptly.",
    },
    {
      id: "q4",
      prompt:
        "Which remediation step is essential and specific to this malware family, beyond killing the process and removing the Run key?",
      kind: "single",
      options: [
        { value: "verify_recent_transfers", label: "Manually verify every cryptocurrency payment made from this host during the infection window against the intended recipient address" },
        { value: "reset_password", label: "Reset the user's domain password — this is the step that undoes the damage" },
        { value: "reimage_only", label: "Reimage the laptop; once that is done, no further action is needed" },
        { value: "block_domain_only", label: "Block wallet-cfg-sync.net at the firewall; that alone stops any further loss" },
      ],
      answer: "verify_recent_transfers",
      xp: 60,
      explanation:
        "A clipper's damage is done at the moment of a paste, not through an account compromise or a lingering network connection — there is no password to reset that undoes a transaction that already settled on a public blockchain, and blockchain transfers cannot be reversed. The only way to know if money actually moved to the wrong place is to go back through every payment initiated from this host during the infection window and check the destination address the recipient actually received against the one the user intended to send. Reimaging (c) and blocking the domain (d) both stop the malware from running again, which matters, but neither one tells you whether a transfer already happened.",
    },
    {
      id: "q5",
      prompt:
        "Why does clipsvc_helper.exe target clipboard content specifically, rather than, say, keystrokes or files?",
      kind: "single",
      options: [
        { value: "high_value_low_effort", label: "Wallet addresses are long random strings nobody retypes by hand — users always copy-paste them, so intercepting the clipboard reliably catches the one moment that matters" },
        { value: "keylogging_illegal", label: "Keylogging is technically harder to implement than clipboard monitoring" },
        { value: "clipboard_unmonitored", label: "Windows provides no API for reading the clipboard, so clipper malware must use undocumented tricks that are automatically stealthier" },
        { value: "file_access_blocked", label: "EDR products block all file read access by default, forcing malware toward the clipboard as the only remaining option" },
      ],
      answer: "high_value_low_effort",
      xp: 50,
      explanation:
        "Cryptocurrency addresses are 26-42+ character random strings that essentially nobody types from memory — the copy-paste workflow is universal, which makes the clipboard a reliable, narrow chokepoint to intercept. A keylogger would capture far more data (most of it useless) and require far more processing to find a wallet address inside it; clipboard interception gets exactly what it wants, every time, with a simple regex match. Option (b) is not really the driver — keylogging is not meaningfully harder — and options (c) and (d) are both factually wrong: the clipboard APIs (GetClipboardData, SetClipboardData, AddClipboardFormatListener) are fully documented, and EDR products do not block file reads by default.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Wrong Wallet — Clipboard Clipper from a Trojanized Utility",
    threat_actor: "Commodity clipper distributor (bundled crypto-utility)",
    attack_kind: "clipboard_clipper",
    briefing:
      "A vendor reported that a payment from Noa Peretz never arrived. SentinelOne has a Critical detection open on LAP-5528 for an unsigned AppData process holding a clipboard format listener. Work out what was installed, what it changed, and what it may have affected.",
    narrative: `At 09:20 Noa Peretz downloaded CryptoTrackerLite_Setup.exe from cryptotracker-lite.io — a small utility to watch a handful of crypto balances she tracked for vendor payments. She installed it two minutes later; the tracker genuinely works, and she used it that afternoon.

Twenty-one seconds after the real component was written, the same installer wrote a second binary: C:\\Users\\n.peretz\\AppData\\Roaming\\ClipSvc\\clipsvc_helper.exe, 512 KB, unsigned. Five seconds after that, a hidden cmd.exe process — spawned by the installer, not typed by her — ran a 'reg add' command adding ClipboardService to her Run key, pointing at the new binary. Eight seconds later, clipsvc_helper.exe started for the first time with no visible window.

It sat quietly for just over two hours. Then, at 11:35, it registered as a clipboard format listener and began doing exactly what its name never suggested: watching every copy operation, matching the content against BTC and ETH wallet-address patterns, and — when it matched — silently replacing what she had copied with an address of the attacker's choosing before she could paste it. Sixteen seconds later the host fetched a small JSON file from wallet-cfg-sync.net, the kind of periodic check-in a clipper uses to receive an updated substitute-address list.

Nothing crashed. Nothing looked wrong on her screen at any point. Two days later, a vendor called to say a payment had never arrived. That call, not a security alert, is what actually opened this investigation — the SentinelOne detection had been sitting in the console, unescalated, since 11:35 on the day of infection.`,
    learning_objectives: [
      "Recognise clipboard hijacking (T1115) from a behavioural indicator naming the clipboard APIs involved",
      "Identify a command-interpreter persistence step (T1059.003) as distinct from an installer's own file-write behaviour",
      "Understand why this malware class produces almost no observable symptoms before its outcome surfaces",
      "Explain why remediation must include manually verifying transactions, not just removing the malware",
      "Explain why an attacker would target the clipboard specifically for this kind of data",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `CryptoTrackerLite_Setup.exe downloaded from ${downloadSite}` },
      { ts: T(2 * MIN + 10_000), phase: "Execution", action: "User runs the installer (T1204.002)" },
      { ts: T(2 * MIN + 31_000), phase: "Execution", action: "clipsvc_helper.exe written to AppData\\Roaming\\ClipSvc" },
      { ts: T(2 * MIN + 36_000), phase: "Persistence", action: "cmd.exe adds a Run key via `reg add` (T1059.003)" },
      { ts: T(2 * MIN + 44_000), phase: "Execution", action: "clipsvc_helper.exe starts silently" },
      { ts: T(2 * HOUR + 15 * MIN), phase: "Collection", action: "Clipboard format listener registered; wallet addresses substituted in place (T1115)" },
      { ts: T(2 * HOUR + 15 * MIN + 16_000), phase: "Command and Control", action: `Periodic config pull from ${c2}` },
      { ts: T(2 * 24 * HOUR + 3 * HOUR), phase: "Detection", action: "SentinelOne raises a Critical detection and kills the process — two days after infection" },
    ],
    questions,
  };
}
