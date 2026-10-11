/**
 * Scenario pack: "Invoice.iso — Container-Delivered LNK and LOLBin Chain"
 *
 * FOUNDATION tier. One user, one laptop, no lateral movement, no cross-account
 * credential theft, no cloud pivot. An accounts-payable clerk follows a phishing
 * link to what looks like an overdue invoice and downloads Invoice_84421.iso.
 * Windows tags the ISO with a Mark-of-the-Web zone identifier because it came
 * from the internet, and — since the November 2022 patch for CVE-2022-41091 —
 * that mark now PROPAGATES to the files inside the mounted container. So the
 * shortcut and the bundled update.dat are themselves tagged, and double-clicking
 * the .lnk raises an Open File - Security Warning. The lure still runs because
 * the user clicks "Run anyway" (T1204.002), and because the shortcut doesn't
 * launch an unknown .exe at all: it runs a trusted, signed Windows binary
 * (rundll32.exe) against the bundled data file, and SmartScreen does not re-gate
 * a known Microsoft LOLBin.
 *
 * This is the current container-delivery pattern loader crews use now that the
 * old "MotW doesn't reach files inside an ISO" gap is closed: a container that
 * Windows will mount, a MotW-tagged .lnk the user is socially engineered to run
 * anyway, and a LOLBin (rundll32) chain so nothing unsigned is launched directly.
 * Covers T1566.002 (Phishing: Spearphishing Link), T1204.002 (User Execution:
 * Malicious File), T1218.011 (System Binary Proxy Execution: Rundll32) and
 * T1059.001 (Command and Scripting Interpreter: PowerShell).
 *
 * SOURCE-LIGHT: only `edr` (CrowdStrike Falcon) and `firewall` (Fortinet
 * FortiGate) events.
 *
 * NOTE: `difficulty: "foundation"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { isoContainerSmugglingScenarioEvents } from "./isoContainerSmuggling.events";

export function buildIsoContainerSmugglingScenario(
  scenarioId = "iso-container-smuggling-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, shareSite, c2, isoHash, payloadHash } = isoContainerSmugglingScenarioEvents();
  const sensorId = "e6d92c1804bf47a1a3d0e29fc61b8a72";

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: isoHash,
      first_seen: T(0),
      last_seen: T(4 * MIN + 34_000),
      reputation: "malicious",
      tags: ["iso-container", "motw-tagged", "lnk-lure"],
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
        "Invoice_84421.iso carried a Mark-of-the-Web zone tag (evt_ics_02), and since the Nov-2022 patch (CVE-2022-41091) that mark propagates to the files inside a mounted container. Given that, how did the .lnk still run (evt_ics_04)?",
      hint: "Read evt_ics_04's description and process.name — what did the user do, and what kind of binary did the shortcut actually launch?",
      kind: "single",
      options: [
        { value: "clickthrough_lolbin", label: "The MotW .lnk raised an Open File - Security Warning, the user clicked Run anyway, and the shortcut then ran a trusted signed Windows binary (rundll32) that SmartScreen does not re-gate" },
        { value: "no_propagation", label: "Files inside a mounted ISO still never inherit the container's Mark-of-the-Web, so no warning was ever shown" },
        { value: "trusted_signer", label: "The shortcut itself carried a trusted publisher's Authenticode signature, so SmartScreen waived its reputation check" },
        { value: "smartscreen_off", label: "SmartScreen was switched off by group policy on this laptop, so the download warning did not fire" },
      ],
      answer: "clickthrough_lolbin",
      xp: 60,
      explanation:
        "The old 'MotW doesn't reach files inside an ISO' gap was closed in November 2022 (CVE-2022-41091): a mounted container now propagates the mark to its contents, so update.dat and the .lnk are both tagged and opening the .lnk raises the Open File - Security Warning. Two things let it run anyway. First, the user clicked through the warning (T1204.002) — social engineering, not a technical bypass. Second, the shortcut doesn't launch an unknown .exe at all: evt_ics_04 shows process.name rundll32.exe, a trusted, signed Microsoft binary, run against the bundled update.dat (T1218.011). SmartScreen's app-reputation check gates unknown executables, not a known Windows LOLBin. (b) is the outdated premise this scenario deliberately corrects. (c) invents a signature on the .lnk that isn't in the evidence. (d) assumes a policy state nowhere in the log.",
    },
    {
      id: "q2",
      prompt:
        "cdn-update-relay.net was passed through FortiGate's web filter under category 'Uncategorized' (data.cat: 26). What does that tell you about relying on URL category as a control here?",
      kind: "single",
      options: [
        { value: "gap", label: "New attacker domains often have no category yet, and 'Uncategorized' is commonly set to passthrough, not block" },
        { value: "misconfig", label: "Uncategorized domains belong in the blocked set of any sound baseline, so this is simply a FortiGate misconfiguration" },
        { value: "tls_gap", label: "The request was TLS-encrypted, so without deep inspection the web filter could not see enough to categorise it" },
        { value: "known_good", label: "'Uncategorized' means FortiGuard crawled the domain and found nothing malicious, so it was treated as benign" },
      ],
      answer: "gap",
      xp: 50,
      explanation:
        "FortiGuard's category database can only classify domains it has crawled or received threat-intel on; brand-new attacker infrastructure routinely starts life Uncategorized, and many organisations leave that bucket on passthrough because blocking it wholesale breaks too many legitimate new sites. The log itself proves TLS visibility was fine — full URL, filename, and byte counts are present — so (c) is contradicted by the evidence. (b) assumes a specific policy stance the log doesn't state, and (d) inverts what 'Uncategorized' actually means: it's an absence of classification, not a positive verdict.",
    },
    {
      id: "q3",
      prompt:
        "Which two events, read together, tell you rundll32.exe was abused as a loader for the bundled update.dat rather than doing anything legitimate?",
      kind: "single",
      options: [
        { value: "lnk_and_ps", label: "The .lnk's rundll32 launch (cmdline references D:\\update.dat) and the PowerShell start — rundll32, hosting update.dat, spawned hidden encoded PowerShell one second later" },
        { value: "iso_and_mount", label: "The ISO download and its mount as a new drive letter — the container arrived and was opened before any interpreter ran" },
        { value: "ps_and_fetch", label: "The PowerShell start and the core.dll fetch — the interpreter reached out within two seconds of launch" },
        { value: "fetch_and_write", label: "The core.dll fetch and the AppData write — the payload passed the web filter and was then written to disk" },
      ],
      answer: "lnk_and_ps",
      xp: 60,
      explanation:
        "evt_ics_04 shows rundll32.exe launched with the command line `rundll32.exe D:\\update.dat,Start` — rundll32's legitimate job is to run exported functions of a DLL, and here it is pointed at a data file bundled on the mounted ISO, which is classic LOLBin (T1218.011) abuse. evt_ics_05 confirms what that load did: one second later powershell.exe appears as rundll32's direct child with a hidden window and an encoded command. The pair — the LOLBin hosting update.dat, then the hidden PowerShell it spawned — is what shows rundll32 was the loader, not a normal system task. (c) and (d) are real correlated pairs but describe what PowerShell did once running. (b) shows delivery and mounting, not the loader abuse.",
    },
    {
      id: "q4",
      prompt:
        "Falcon's pattern_disposition_description on evt_ics_08 reads 'Detection, Process Killed'. What is and isn't true about the host's state at that point?",
      kind: "single",
      options: [
        { value: "dll_landed", label: "PowerShell was stopped, but core.dll had already been written to AppData\\Roaming before the kill" },
        { value: "fully_clean", label: "The kill remediated the incident — Falcon removes the files written by a process it terminates" },
        { value: "dll_executed", label: "core.dll had already been loaded by PowerShell and was running in memory when Falcon intervened" },
        { value: "nothing_ran", label: "Nothing reached disk — Falcon blocked the chain before the DLL download could complete its write" },
      ],
      answer: "dll_landed",
      xp: 60,
      explanation:
        "evt_ics_07 is timestamped before evt_ics_08 and shows core.dll already written to disk by powershell.exe. Killing the PowerShell process (evt_ics_08) stopped that process from doing anything further — including loading the DLL it had just fetched — but it does not undo the write that already happened. (b) overstates the outcome: an unsigned DLL is still sitting on the host and needs to be removed and analysed, not assumed gone. (c) isn't supported — nothing in the timeline shows core.dll being executed after it was written; only the write is evidenced. (d) is contradicted directly by evt_ics_07's timestamp, which precedes the kill.",
    },
    {
      id: "q5",
      prompt:
        "You're writing the remediation plan. Which step best addresses how this chain actually ran?",
      kind: "single",
      options: [
        { value: "block_containers", label: "Block or quarantine downloaded container formats (.iso/.img/.vhd/.7z) at the mail and web gateways, so the lure never reaches the desktop as a mountable file" },
        { value: "rely_motw", label: "No change needed — the Nov-2022 Mark-of-the-Web fix already covers this, since the files inside the ISO are now tagged" },
        { value: "disable_lnk", label: "Disable .lnk shortcut execution across the whole organisation through group policy, since the shortcut was the trigger" },
        { value: "revoke_cert", label: "Revoke rundll32.exe's Microsoft code-signing certificate so Windows stops trusting it" },
      ],
      answer: "block_containers",
      xp: 50,
      explanation:
        "The container is what delivered a mountable payload past the gateways — evt_ics_01 shows the .iso logged, not blocked, by a file-filter profile that doesn't treat it as high-risk. Blocking or quarantining downloaded container formats removes the delivery vehicle before a user can mount it. (a=rely_motw) is the trap: the MotW fix did its job (the files were tagged and a warning was shown), but a tagged file plus a user who clicks Run anyway plus a signed LOLBin chain still runs — the tag is a prompt, not a block. (c) would break legitimate shortcut use across the estate for one incident's trigger. (d) is nonsensical — rundll32 is a core Windows binary; you cannot and must not revoke its signature. Detecting rundll32 run against a non-DLL path on a removable/mounted volume is a far better behavioural control than either.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity loader operator (container-delivered LNK)",
    attack_kind: "iso_container_smuggling",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-5528 at 10:09 for a hidden PowerShell process spawned by rundll32 from a mounted ISO volume. The user says she opened what she thought was an overdue invoice from an email this morning. Work out how the file got there and why the Windows security warning on it didn't stop the chain.",
    narrative: `At 10:05 Noa Katz, an accounts-payable clerk, downloaded Invoice_84421.iso from invoice-doc-share.net — 6.8 MB, logged by FortiGate's file-filter profile as log-only because .iso isn't on the list of types that get blocked outright. Six seconds later it landed in her Downloads folder carrying a Zone.Identifier alternate data stream, the ordinary Mark-of-the-Web Windows stamps on anything pulled from the internet.

At 10:09:20 she double-clicked it. Windows' own container-mount handler presented it as a new drive, D:\\, holding two files: Invoice_84421.lnk and update.dat. Since the November 2022 patch Windows propagates the ISO's Mark-of-the-Web to both of them, so opening the shortcut raised the Open File - Security Warning. She clicked Run anyway.

The shortcut did not launch an unknown .exe — that is what SmartScreen reputation-checks. It ran rundll32.exe, a trusted, signed Windows binary, pointed at the bundled data file: 'rundll32.exe D:\\update.dat,Start'. One second later rundll32 — now hosting update.dat — spawned powershell.exe, hidden, with a base64-encoded command. The decoded command downloaded core.dll, 2.4 MB, from cdn-update-relay.net — infrastructure with no connection to invoice-doc-share.net — and wrote it to C:\\Users\\n.katz\\AppData\\Roaming. FortiGate's web filter passed the request through; the domain had no category yet.

Falcon's detection caught up ten seconds after PowerShell started and killed the process before it could load what it had just downloaded. core.dll is still sitting on the host — the kill stopped the process that fetched it, not the file itself.`,
    learning_objectives: [
      "Know that since CVE-2022-41091 (Nov 2022) Mark-of-the-Web propagates to files inside a mounted ISO/IMG — so modern container lures rely on the user clicking through the warning, not on a missing tag",
      "Recognise LOLBin abuse (T1218.011): a .lnk running rundll32.exe against a bundled non-DLL data file on a mounted volume, where SmartScreen does not re-gate the trusted Windows binary",
      "Read a firewall's file-filter and web-category fields to understand why an unusual container type and a fresh domain both slipped through",
      "Correlate a LOLBin's command line with its child process to identify a loader versus a legitimate system task",
      "Distinguish 'the process was killed' from 'the file it wrote is gone' when assessing host state after a detection",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-90_000), phase: "Initial Access", action: `Phishing link opened from webmail → ${shareSite}/invoice/84421 (T1566.002)` },
      { ts: T(0), phase: "Initial Access", action: `Invoice_84421.iso downloaded from ${shareSite}` },
      { ts: T(4 * MIN + 20_000), phase: "Execution", action: "User opens the ISO; Windows mounts it as D:\\, propagating MotW to its files (T1204.002)" },
      { ts: T(4 * MIN + 34_000), phase: "Stealth", action: "User clicks through the MotW warning; .lnk runs rundll32 against D:\\update.dat (T1218.011)" },
      { ts: T(4 * MIN + 35_000), phase: "Execution", action: "rundll32 (hosting update.dat) spawns hidden, encoded PowerShell (T1059.001)" },
      { ts: T(4 * MIN + 37_000), phase: "Command and Control", action: `core.dll fetched from ${c2}, passed through as Uncategorized` },
      { ts: T(4 * MIN + 39_000), phase: "Execution", action: "core.dll written to AppData\\Roaming" },
      { ts: T(4 * MIN + 45_000), phase: "Detection", action: "Falcon kills the PowerShell process — core.dll remains on disk, unloaded" },
    ],
    questions,
  };
}
