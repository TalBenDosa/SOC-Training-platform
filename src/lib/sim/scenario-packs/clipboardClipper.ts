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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { clipboardClipperScenarioEvents } from "./clipboardClipper.events";

export function buildClipboardClipperScenario(
  scenarioId = "clipboard-clipper-2026",
): ScenarioBundle {
  const { title, events, T, MIN, HOUR, host, downloadSite, c2, installerHash, clipperHash } = clipboardClipperScenarioEvents();

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
        { value: "hijack", label: "The clipboard format listener registration, followed by repeated rewrites of wallet-pattern text" },
        { value: "start", label: "The first hidden launch of clipsvc_helper.exe by the installer — running a clipper at all is the theft" },
        { value: "written", label: "The unsigned 512 KB clipsvc_helper.exe landing in AppData\\Roaming — dropping the clipper is the theft" },
        { value: "config_pull", label: "The /w/list.json fetch from wallet-cfg-sync.net — pulling the wallet list is the moment funds are taken" },
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
        { value: "interpreter_signal", label: "Shell-driven persistence is a higher-signal event than an installer's own registry writes — T1059.003 in its own right" },
        { value: "no_difference", label: "It makes no difference — both paths write the same ClipboardService Run value, and EDR records them identically" },
        { value: "cmd_malicious", label: "cmd.exe is itself the malicious component here, because a legitimate installer framework has no reason to invoke a shell" },
        { value: "elevation_proof", label: "Spawning cmd.exe shows the installer escalated beyond the privileges the user granted when it was first launched" },
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
        { value: "silent_until_business_impact", label: "A clipper shows almost no side effects until its outcome — a misdirected payment — surfaces in a business process" },
        { value: "sensor_offline", label: "The SentinelOne sensor was offline for two days and only resumed sending telemetry when the ticket was raised" },
        { value: "detection_disabled", label: "The clipboard-listener behavioural indicator was disabled in the SentinelOne policy and had to be re-enabled manually" },
        { value: "user_delay", label: "The user noticed the wrong address on the day but waited two days before reporting it to the service desk" },
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
        { value: "verify_recent_transfers", label: "Check every crypto payment sent from this host during the infection window against the address the user intended" },
        { value: "reset_password", label: "Reset the user's domain password and revoke all sessions, since the clipper ran under that account's security context" },
        { value: "reimage_only", label: "Reimage the laptop from the gold image, which removes the clipper, its Run key and any other dropped files" },
        { value: "block_domain_only", label: "Block wallet-cfg-sync.net at the firewall so the clipper can no longer pull a fresh replacement wallet list" },
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
        { value: "high_value_low_effort", label: "Wallet addresses are long random strings people copy-paste rather than type, so the clipboard is the one chokepoint that matters" },
        { value: "keylogging_illegal", label: "Keylogging is considerably harder to implement than clipboard monitoring and needs a kernel driver on Windows" },
        { value: "clipboard_unmonitored", label: "Windows exposes no documented clipboard API, so clipper malware relies on undocumented calls that EDR cannot hook" },
        { value: "file_access_blocked", label: "EDR products block file read access by default, pushing malware toward the clipboard as the remaining channel" },
      ],
      answer: "high_value_low_effort",
      xp: 50,
      explanation:
        "Cryptocurrency addresses are 26-42+ character random strings that essentially nobody types from memory — the copy-paste workflow is universal, which makes the clipboard a reliable, narrow chokepoint to intercept. A keylogger would capture far more data (most of it useless) and require far more processing to find a wallet address inside it; clipboard interception gets exactly what it wants, every time, with a simple regex match. Option (b) is not really the driver — keylogging is not meaningfully harder — and options (c) and (d) are both factually wrong: the clipboard APIs (GetClipboardData, SetClipboardData, AddClipboardFormatListener) are fully documented, and EDR products do not block file reads by default.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
