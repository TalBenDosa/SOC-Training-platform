/**
 * Scenario pack: "Free PDF Tool — Trojanized Installer with a Keylogger"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement. A user who needs to
 * merge two PDFs before a meeting installs a free converter she found by
 * searching. The installer works — the PDF tool really does merge PDFs — and it
 * also drops a keystroke logger and gives it a Run key.
 *
 * The teaching point is that the application working correctly is not evidence
 * of anything. The user's own account is the one that installed it, from a
 * signed installer with a valid (but recently issued, and unrelated) certificate.
 * Every individual event here is something a normal software installation also
 * does. What separates them is one process reading another process's keyboard
 * input, and a Run key pointing at a binary in AppData.
 *
 * Covers T1056.001 (Input Capture: Keylogging) — a Collection technique the live
 * feed exercises but that no room previously taught.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { trojanizedInstallerKeyloggerScenarioEvents } from "./trojanizedInstallerKeylogger.events";

export function buildTrojanizedInstallerKeyloggerScenario(
  scenarioId = "trojanized-installer-keylogger-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, downloadSite, c2, installerHash, keyloggerHash } = trojanizedInstallerKeyloggerScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: keyloggerHash,
      first_seen: T(2 * MIN + 54_000),
      last_seen: T(41 * MIN),
      reputation: "malicious",
      tags: ["keylogger", "unsigned", "appdata"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(0),
      last_seen: T(2 * MIN + 56_000),
      reputation: "malicious",
      tags: ["trojanized-installer", "signed"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(40 * MIN),
      last_seen: T(40 * MIN),
      reputation: "malicious",
      tags: ["c2", "outbound-post-target"],
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
      last_seen: T(41 * MIN),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The installer was signed with a trusted certificate and the PDF tool it installed genuinely works. What does that tell you about whether this is malicious?",
      hint: "Look at process.code_signature.valid_from in evt_tik_02, and at what else the same installer wrote.",
      kind: "single",
      options: [
        { value: "nothing", label: "Nothing — a valid signature proves who built and signed the file, not that the file or what it installs is safe to run" },
        { value: "benign", label: "It is strong evidence the software is benign; signed installers are vetted before a certificate is issued" },
        { value: "stolen", label: "The certificate must have been stolen from a real vendor, since no legitimate publisher would sign malware" },
        { value: "revoked", label: "The signature is actually invalid — a status of 'trusted' only means Windows was able to parse the certificate" },
      ],
      answer: "nothing",
      xp: 50,
      explanation:
        "Code signing answers one question — which entity signed this binary — and no others. Anyone who can pass a vendor's identity check can buy a certificate, and 'Nordvale Software Solutions OU' issued on 2026-05-29 is a real signer with a certificate that is under a month old. The working PDF tool is part of the same design: users who get what they came for do not uninstall anything. Option (c) is a common and expensive assumption — certificate theft happens, but freshly purchased certificates for purpose-built shell companies are far more common, and the two lead to completely different response actions. Option (d) contradicts the log, which records status 'trusted'.",
    },
    {
      id: "q2",
      prompt:
        "Which single event moves this from 'unwanted software' to 'a security incident'?",
      kind: "single",
      options: [
        { value: "hook", label: "The low-level keyboard hook winupd_helper.exe installed to read input directed at chrome.exe" },
        { value: "runkey", label: "The WindowsUpdateHelper Run-key value giving the AppData binary persistence across reboots and logons" },
        { value: "appdata", label: "The installer writing an unsigned second binary into AppData\\Roaming\\WinUpd alongside the real app" },
        { value: "download", label: "The download of SwiftPDF_Setup.exe from a freeware site, which breaches the software-installation policy" },
      ],
      answer: "hook",
      xp: 60,
      explanation:
        "Adware and legitimate software both write to AppData and both add Run keys — those events (b) and (c) are suspicious context, not proof. A WH_KEYBOARD_LL hook targeting chrome.exe is different in kind: there is no benign reason for a bundled PDF utility to read the keystrokes a user types into her browser. That is capture of credentials and everything else she types. Option (d) is a policy violation, which is a different conversation from a security incident and should not be conflated with one.",
    },
    {
      id: "q3",
      prompt:
        "The user has no local admin rights (Local Admin Rights: false). How did the malware achieve persistence anyway?",
      kind: "single",
      options: [
        { value: "hkcu", label: "It used the HKCU Run key, which any standard user can write to for their own account" },
        { value: "uac", label: "The installer bypassed UAC, which is why it ran at high integrity and could write system autoruns" },
        { value: "service", label: "It installed a per-user Windows service, which does not require administrative rights to register" },
        { value: "task", label: "It created a scheduled task running as SYSTEM, which any standard user is allowed to register" },
      ],
      answer: "hkcu",
      xp: 50,
      explanation:
        "evt_tik_05 records the hive explicitly: HKEY_CURRENT_USER. Every user can write autoruns for their own profile without any elevation, and the entry runs whenever that user logs in — which is all a keylogger targeting one person needs. This is why 'the user isn't an admin' is a much weaker control than it sounds. Options (c) and (d) are simply false about Windows: services and SYSTEM-context scheduled tasks both require administrative rights. Option (b) misreads the evidence — the installer prompted and the user consented, which is ordinary elevation, and in any case the persistence that was actually used needed no elevation at all.",
    },
    {
      id: "q4",
      prompt:
        "You are scoping the response. Which action list matches what the evidence supports?",
      kind: "single",
      options: [
        { value: "full", label: "Isolate the host, remove the Run key and both binaries, and force a password reset for this user across every system" },
        { value: "uninstall", label: "Uninstall SwiftPDF through Programs and Features and close the ticket — the tool is unwanted software, not malware" },
        { value: "block_only", label: "Block stat-collect-eu.com at the perimeter proxy; with the exfil channel cut, the endpoint is unaffected once traffic stops" },
        { value: "monitor", label: "Leave the host running and monitor cache.dat and the POSTs for a few days to measure how much data is collected" },
      ],
      answer: "full",
      xp: 60,
      explanation:
        "A keyboard hook ran for at least thirty-four minutes while the user worked, and evt_tik_08 shows the buffer leaving in 4 KB POSTs every ten minutes. You cannot know what she typed, so you have to assume every credential she entered in that window is compromised — hence the reset, and hence 'across every system', because people reuse passwords. Option (b) treats the PDF tool as the problem when the second binary is; uninstalling SwiftPDF may well leave winupd_helper.exe and its Run key exactly where they are. Option (c) stops exfiltration but leaves collection running and the stolen credentials still valid. Option (d) trades a user's live credentials for investigative curiosity, which is not a trade you get to make.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity infostealer distributor (freeware bundling)",
    attack_kind: "trojanized_installer_keylogger",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-2290 at 10:46: an unsigned binary in AppData holding a low-level keyboard hook. The user installed a free PDF tool this morning. Establish what was installed, what it is doing, and what has left the machine.",
    narrative: `At 10:05 Yael Karni downloaded SwiftPDF_Setup.exe from pdf-tools-free.io. She needed to merge two contracts before an 11:00 meeting, the corporate PDF licence does not cover merging, and the site was categorised shareware-and-freeware, so nothing blocked it.

She ran it at 10:07:30. The installer is signed by "Nordvale Software Solutions OU" with a certificate Windows trusts, issued on 29 May 2026. It installed C:\\Program Files\\SwiftPDF\\SwiftPDF.exe, which is a genuine, working PDF application — she merged her contracts and made her meeting.

Three seconds after writing the real product, the same installer wrote a second binary: C:\\Users\\y.karni\\AppData\\Roaming\\WinUpd\\winupd_helper.exe, 393 KB, unsigned. Two seconds after that it added a value called WindowsUpdateHelper to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing at it. She is not a local administrator, and none of that required her to be.

At 10:09:10 winupd_helper.exe called SetWindowsHookExW to install a WH_KEYBOARD_LL hook against chrome.exe. Over the next thirty-four minutes it appended to cache.dat in its own folder until the file reached 61 KB. From 10:45 the host began POSTing about 4 KB every ten minutes to stat-collect-eu.com/v1/report — a domain the firewall categorises as unknown, and therefore allows.

Falcon detected the hook and raised the alert at 10:46. It did not block anything: pattern_disposition_description is "Detection, No Action". The keylogger was still running when the ticket landed.`,
    learning_objectives: [
      "Explain what a valid code signature does and does not prove about a binary",
      "Recognise Input Capture: Keylogging (T1056.001) from a low-level keyboard hook against another process",
      "Identify HKCU Run-key persistence and explain why it needs no administrative rights",
      "Separate a working application from the payload bundled alongside it in the same installer",
      "Scope credential exposure from the duration a capture mechanism was active, not from what you can see was stolen",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `SwiftPDF_Setup.exe downloaded from ${downloadSite}` },
      { ts: T(2 * MIN + 30_000), phase: "Execution", action: "User runs the signed installer, elevating to high integrity (T1204.002)" },
      { ts: T(2 * MIN + 51_000), phase: "Execution", action: "The genuine PDF application is installed to Program Files" },
      { ts: T(2 * MIN + 54_000), phase: "Execution", action: "An unsigned second binary is written to AppData\\Roaming\\WinUpd" },
      { ts: T(2 * MIN + 56_000), phase: "Persistence", action: "HKCU Run key WindowsUpdateHelper added (T1547.001)" },
      { ts: T(4 * MIN + 10_000), phase: "Collection", action: "WH_KEYBOARD_LL hook installed against chrome.exe (T1056.001)" },
      { ts: T(38 * MIN), phase: "Collection", action: "cache.dat grows to 61 KB in the malware's own directory" },
      { ts: T(40 * MIN), phase: "Exfiltration", action: `4 KB POSTs every ten minutes to ${c2} (T1041)` },
      { ts: T(41 * MIN), phase: "Detection", action: "Falcon raises a Critical detection — detect only, nothing blocked" },
    ],
    questions,
  };
}
