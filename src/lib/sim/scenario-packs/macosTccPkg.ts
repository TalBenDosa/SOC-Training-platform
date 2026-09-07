/**
 * Scenario pack: "macOS TCC Bypass — a Fake Meeting App .pkg Runs a Root Script,
 * Rewrites the Privacy Database and Persists as a LaunchDaemon"
 *
 * INTERMEDIATE tier. Deepens the platform's macOS coverage a second way. Where
 * the stealer scenario was a DMG that phished the login password and harvested
 * Keychain/cookies, this one is a malicious INSTALLER PACKAGE (.pkg) distributed
 * as a fake productivity / meeting app. Double-clicking it runs /usr/sbin/installer,
 * whose preinstall/postinstall shell scripts execute AS ROOT. The postinstall
 * script writes allow-entries directly into the TCC (Transparency, Consent and
 * Control) privacy database, granting the app Full Disk Access and Screen
 * Recording without the user ever seeing a consent prompt — then reads the user's
 * Documents/Desktop/Downloads and drops a LaunchDaemon in /Library/LaunchDaemons
 * so a root helper starts at every boot.
 *
 * Trust and privilege are expressed the macOS way: Developer ID code signing vs
 * ad-hoc signing, notarization, Gatekeeper, the com.apple.quarantine attribute,
 * /usr/sbin/installer, package preinstall/postinstall scripts, the TCC database at
 * ~/Library/Application Support/com.apple.TCC/TCC.db, tccutil, LaunchDaemon plists
 * under /Library/LaunchDaemons and launchctl load.
 *
 * The teaching spine is telling a benign .pkg install from a malicious one when
 * both have the same SHAPE — an installer runs, an app is set up, a launch item is
 * registered. The BENIGN CONTROL (evt 0) is a legitimately-signed, notarized pkg
 * (Zoom): valid Developer ID Installer signature, Gatekeeper passed, a per-user
 * LaunchAgent, and no root script touching the privacy database. The malicious pkg
 * carries a REVOKED Developer ID, its postinstall runs as root, rewrites TCC.db and
 * installs a root LaunchDaemon. The difference is in the signature and what the
 * install scripts do, not the fact that "a pkg installed something."
 *
 * SOURCES (registry vendor keys): crowdstrike-falcon (Falcon supports macOS — the
 * installer/package-script process tree, TCC.db access, LaunchDaemon write, the
 * detection) and microsoft-defender-endpoint (one corroborating cross-platform
 * process event on the root postinstall script).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csFile, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { mdeProcess } from "@/lib/sim/emitters/mde";

export function buildMacosTccPkgScenario(
  scenarioId = "macos-tcc-pkg-2026",
): ScenarioBundle {
  const B = new Date("2026-08-28T14:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const INCIDENT = "inc:mtp:1";

  // The victim endpoint and its user.
  const host = {
    name: "MB-PM-07",
    fqdn: "MB-PM-07.northwind-collab.com",
    ip: "10.44.12.53",
    id: "a1f4e9c2703b48d5a9c6f21e84b70d3f",
    os: "macOS",
    osVersion: "15.3.1",
  };
  const user = {
    sam: "j.okafor",
    email: "j.okafor@northwind-collab.com",
    domain: "northwind-collab",
    full: "Jelani Okafor",
    title: "Product Manager",
  };

  // The malicious package, its bundle, its dropped helper and persistence item.
  const pkgName = "MeetSync-Installer.pkg";
  const pkgPath = "/Users/j.okafor/Downloads/MeetSync-Installer.pkg";
  const bundleId = "com.meetsync.app";
  const tccDb = "/Users/j.okafor/Library/Application Support/com.apple.TCC/TCC.db";
  const daemonPlist = "/Library/LaunchDaemons/com.meetsync.helper.plist";
  const daemonBin = "/Library/Application Support/MeetSync/meetsyncd";

  // The .pkg / Mach-O payload hash — appears on the install, the MDE
  // corroboration and the detection.
  const pkgHash = makeSha256("macos_tcc_pkg_meetsync_postinstall_root_launchdaemon_2026");

  // Falcon sensor identifiers on the MacBook.
  const sensorId = "6d0b93a41f7c4e28b5a2c907e13f8a44";
  const aid = "9c17e5b280d34af6a1b70e2c4f9d3651";

  const cx = "northwind-collab" as const;
  const osx = { "host.os.name": host.os, "host.os.version": host.osVersion };
  const appleSigned = { "process.code_signature.status": "valid", "process.code_signature.subject_name": "Software Signing" };

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL — a legitimately-signed, notarized .pkg install (fp).
    csProcess({
      companyId: cx, id: "mtp_00_benign_notarized_pkg", ts: "2026-08-27T09:15:00.000Z", host: host.name, user: user.email,
      runAsUser: user.sam, processName: "installer", processPath: "/usr/sbin/installer",
      cmdline: "installer -pkg /Users/j.okafor/Downloads/Zoom.pkg -target /", parentName: "Installer", parentPid: 1, pid: 3182,
      severity: "informational", expectedVerdict: "fp",
      fpExplanation: "The control case for the whole scenario. Zoom was installed the day before from a downloaded .pkg — the same 'an installer runs and registers a launch item' shape as the intrusion. What makes it benign is written in the signature and the script behaviour: the package carries a VALID Developer ID Installer signature, it is notarized, and Gatekeeper passed, so macOS let it install cleanly. Its postinstall did nothing unusual — it registered a per-user LaunchAgent under ~/Library/LaunchAgents for auto-update and never ran as root against the privacy database. An analyst who alerts on 'a .pkg installed an app and a launch item' alone will flag this and be wrong; the discriminator is Developer ID + notarization + a benign per-user script, not the install shape.",
      extra: { ...osx, ...appleSigned, "file.name": "Zoom.pkg", "file.path": "/Users/j.okafor/Downloads/Zoom.pkg", "file.signature.status": "valid", "file.signature.subject_name": "Developer ID Installer: Zoom Video Communications, Inc. (BJ4HAAB9B3)", "file.signature.trusted": "true" },
      description: "/usr/sbin/installer installed Zoom.pkg to the system. Falcon recorded a valid Developer ID Installer signature (Zoom Video Communications) and a passed Gatekeeper assessment; the package is notarized. Its postinstall registered a per-user LaunchAgent for the updater and touched no root-owned locations or the TCC database.",
    }),

    // 1. EXECUTION — the malicious .pkg is installed (revoked Developer ID) (T1204.002).
    csProcess({
      companyId: cx, id: "mtp_01_pkg_install", ts: T(0), host: host.name, user: user.email, runAsUser: "root",
      processName: "installer", processPath: "/usr/sbin/installer", cmdline: `installer -pkg ${pkgPath} -target /`,
      parentName: "Installer", parentPid: 1, pid: 4207, sha256: pkgHash,
      mitre: "T1204.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      extra: { ...osx, ...appleSigned, "file.name": pkgName, "file.path": pkgPath, "file.hash.sha256": pkgHash, "file.signature.status": "revoked", "file.signature.subject_name": "Developer ID Installer: Bright Meridian Ltd (7Q9K2M4X8Z)", "file.signature.trusted": "false", "threat.technique.id": "T1204.002", "threat.technique.name": "User Execution: Malicious File", "threat.tactic.name": "Execution", "threat.tactic.id": "TA0002" },
      description: "/usr/sbin/installer installed MeetSync-Installer.pkg (from ~/Downloads) to the system. Falcon recorded the package's Developer ID Installer signature as REVOKED and the file still carrying the com.apple.quarantine attribute; the payload SHA256 is the one seen again in the later events.",
    }),

    // 2. ROOT INSTALL SCRIPT — the package postinstall runs as root (T1059.004).
    csProcess({
      companyId: cx, id: "mtp_02_postinstall_root_shell", ts: T(4 * SEC), host: host.name, user: user.email, runAsUser: "root",
      processName: "sh", processPath: "/bin/sh", cmdline: `/bin/sh /private/tmp/PKInstallSandbox.7fA2/Scripts/${bundleId}.Qk8Lp/postinstall`,
      parentName: "installer", parentPid: 4207, pid: 4221,
      mitre: "T1059.004", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      extra: { ...osx, ...appleSigned, "threat.technique.id": "T1059.004", "threat.technique.name": "Command and Scripting Interpreter: Unix Shell", "threat.tactic.name": "Execution", "threat.tactic.id": "TA0002" },
      description: "The installer executed the package's postinstall script: /bin/sh running from the PKInstallSandbox Scripts directory, spawned by installer and running as root. Package install scripts run with root privilege, so anything this script does inherits it.",
    }),

    // 3. CORROBORATION — Microsoft Defender for Endpoint sees the same root script (T1059.004).
    mdeProcess({
      companyId: cx, id: "mtp_03_mde_postinstall_corroboration", ts: T(5 * SEC), host: host.name,
      processName: "sh", processPath: "/bin/sh", cmdline: `/bin/sh /private/tmp/PKInstallSandbox.7fA2/Scripts/${bundleId}.Qk8Lp/postinstall`,
      parentName: "installer", pid: 4221, parentPid: 4207, runAsUser: "root", accountName: "root", accountDomain: host.name,
      mitre: "T1059.004", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      extra: { "Timestamp": T(5 * SEC), "DeviceId": host.id, "InitiatingProcessFolderPath": "/usr/sbin/installer", "InitiatingProcessCommandLine": `installer -pkg ${pkgPath} -target /`, "InitiatingProcessId": "4207", "InitiatingProcessSHA256": pkgHash, "ReportId": "88301744", "threat.technique.id": "T1059.004", "threat.technique.name": "Command and Scripting Interpreter: Unix Shell", "threat.tactic.name": "Execution", "threat.tactic.id": "TA0002" },
      description: "Defender for Endpoint, also deployed on this Mac, independently recorded the same postinstall /bin/sh child of the installer running under the root account. Its DeviceProcessEvents row ties the shell to the same initiating package payload SHA256.",
    }),

    // 4. TCC MANIPULATION — the root script writes allow-rows into TCC.db (T1548.006).
    csFile({
      companyId: cx, id: "mtp_04_tcc_db_write", ts: T(9 * SEC), host: host.name, user: user.email, action: "file_modify",
      path: tccDb, sha256: null, actorProcess: "sqlite3", actorPath: "/usr/bin/sqlite3", actorPid: 4238,
      actorParentName: "sh", actorParentPid: 4221, actorSigned: "valid", runAsUser: "root",
      mitre: "T1548.006", tactic: "Privilege Escalation", severity: "critical", incidentId: INCIDENT,
      extra: { ...osx, "crowdstrike.CommandLine": `sqlite3 ${tccDb} INSERT OR REPLACE INTO access VALUES('kTCCServiceSystemPolicyAllFiles','${bundleId}',0,2,4,1,NULL,NULL,NULL,'UNUSED',NULL,0,1);`, "process.code_signature.subject_name": "Software Signing", "threat.technique.id": "T1548.006", "threat.technique.name": "Abuse Elevation Control Mechanism: TCC Manipulation", "threat.tactic.name": "Privilege Escalation", "threat.tactic.id": "TA0004" },
      description: "The root postinstall used /usr/bin/sqlite3 to write allow-rows into the user's TCC privacy database at ~/Library/Application Support/com.apple.TCC/TCC.db — one for kTCCServiceSystemPolicyAllFiles (Full Disk Access) and one for kTCCServiceScreenCapture (Screen Recording), keyed to the com.meetsync.app bundle. No macOS consent prompt was shown to the user.",
    }),

    // 5. PERSISTENCE — a root LaunchDaemon is installed and loaded (T1543.004).
    csProcess({
      companyId: cx, id: "mtp_05_launchdaemon_persist", ts: T(15 * SEC), host: host.name, user: user.email, runAsUser: "root",
      processName: "launchctl", processPath: "/bin/launchctl", cmdline: `launchctl load -w ${daemonPlist}`,
      parentName: "sh", parentPid: 4221, pid: 4256,
      mitre: "T1543.004", tactic: "Persistence", severity: "high", incidentId: INCIDENT,
      extra: { ...osx, ...appleSigned, "file.name": "com.meetsync.helper.plist", "file.path": daemonPlist, "file.signature.status": "adhoc", "file.signature.trusted": "false", "threat.technique.id": "T1543.004", "threat.technique.name": "Create or Modify System Process: Launch Daemon", "threat.tactic.name": "Persistence", "threat.tactic.id": "TA0003" },
      description: "The root script wrote a system LaunchDaemon plist at /Library/LaunchDaemons/com.meetsync.helper.plist and ran launchctl load -w on it. The plist's Program points at /Library/Application Support/MeetSync/meetsyncd, an ad-hoc-signed binary that now runs as root; a LaunchDaemon in this directory is started by launchd on every boot, before any user logs in.",
    }),

    // 6. PROTECTED-DATA ACCESS — the root helper reads the user's files via Full Disk Access (T1005).
    csFile({
      companyId: cx, id: "mtp_06_protected_data_read", ts: T(40 * SEC), host: host.name, user: user.email, action: "file_access",
      path: "/Users/j.okafor/Documents/Q3-Roadmap.pdf", sha256: null, actorProcess: "meetsyncd", actorPath: daemonBin, actorPid: 4290,
      actorParentName: "launchd", actorParentPid: 1, actorSha256: pkgHash, actorSigned: "adhoc", runAsUser: "root",
      mitre: "T1005", tactic: "Collection", severity: "critical", incidentId: INCIDENT,
      extra: { ...osx, "threat.technique.id": "T1005", "threat.technique.name": "Data from Local System", "threat.tactic.name": "Collection", "threat.tactic.id": "TA0009" },
      description: "meetsyncd, launched by launchd from /Library/Application Support/MeetSync, read files under the user's ~/Documents and ~/Desktop — including Q3-Roadmap.pdf. These are TCC-protected locations; the reads succeed because the earlier TCC.db write granted the bundle Full Disk Access.",
    }),

    // 7. THE DETECTION — Falcon ties the chain into one macOS TCC-manipulation case.
    {
      ...csAlert({
        companyId: cx, id: "mtp_07_edr_detection", ts: T(1 * MIN), host: host.name, user: user.email, runAsUser: "root",
        threatName: "MacOS_PkgPostinstall_TCCManipulation_LaunchDaemon", mitre: "T1548.006", tactic: "Privilege Escalation",
        technique: "TCC Manipulation", action: "detected", severity: "critical", incidentId: INCIDENT,
        extra: { ...osx, "crowdstrike.IncidentType": "MacOS Privilege Escalation", "crowdstrike.Objective": "Falcon Detection Method", "threat.technique.id": "T1548.006", "threat.technique.name": "Abuse Elevation Control Mechanism: TCC Manipulation", "threat.tactic.name": "Privilege Escalation", "threat.tactic.id": "TA0004" },
        detail: "A package with a revoked Developer ID installer signature ran a root postinstall that wrote to the TCC privacy database and installed a root LaunchDaemon, followed by reads of the user's protected folders.",
        description: "Falcon raised a Critical detection on MB-PM-07: a package with a revoked Developer ID installer signature ran a root postinstall that wrote to the TCC privacy database and installed a root LaunchDaemon, followed by reads of the user's protected folders — a macOS TCC-manipulation and persistence pattern.",
      }),
      edr_scope: "edr",
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.name, // MB-PM-07 — the infected MacBook (own endpoint, not adversary infra)
      first_seen: T(0),
      last_seen: T(1 * MIN),
      reputation: "unknown",
      tags: ["macos", "endpoint", "infected"],
    },
    {
      type: "user",
      value: user.sam, // j.okafor — the user whose protected data was reached
      first_seen: T(0),
      last_seen: T(1 * MIN),
      reputation: "suspicious",
      tags: ["macos-user", "data-owner", "affected"],
    },
    {
      type: "sha256",
      value: pkgHash, // the .pkg / Mach-O payload
      first_seen: T(0),
      last_seen: T(1 * MIN),
      reputation: "malicious",
      tags: ["macos", "installer-package", "revoked-signature"],
    },
  ];

  const killchain = [
    { ts: "2026-08-27T09:15:00.000Z", phase: "Baseline", action: "Zoom.pkg installs cleanly — valid Developer ID Installer, notarized, Gatekeeper passed, per-user LaunchAgent: the clean-install control case" },
    { ts: T(0), phase: "Execution", action: `${pkgName} installed via /usr/sbin/installer — Developer ID Installer signature revoked, com.apple.quarantine set (T1204.002)` },
    { ts: T(4 * SEC), phase: "Execution", action: "Package postinstall runs /bin/sh from the install sandbox as root (T1059.004)" },
    { ts: T(9 * SEC), phase: "Privilege Escalation", action: "sqlite3 writes Full Disk Access + Screen Recording allow-rows into ~/Library/Application Support/com.apple.TCC/TCC.db (T1548.006)" },
    { ts: T(15 * SEC), phase: "Persistence", action: `${daemonPlist} written and launchctl load -w — a root LaunchDaemon that starts at every boot (T1543.004)` },
    { ts: T(40 * SEC), phase: "Collection", action: "meetsyncd reads ~/Documents and ~/Desktop under the granted Full Disk Access (T1005)" },
    { ts: T(1 * MIN), phase: "Detection", action: "Falcon raises the Critical macOS TCC-manipulation / LaunchDaemon detection tying the chain together" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "mtp_q1",
      xp: 55,
      kind: "single",
      prompt:
        "Two .pkg installs appear on MB-PM-07: the Zoom install (mtp_00) and the MeetSync install (mtp_01). Which observation separates the benign install from the malicious one?",
      hint: "Compare the package signature on each, and look at what each install's postinstall script does and under which account.",
      options: [
        { value: "sig_rootscript", label: "Zoom's package signature is valid and notarized and its postinstall stays a per-user helper, while MeetSync's signature is revoked and its postinstall runs as root to alter the privacy database and add a system launch item" },
        { value: "installer_path", label: "Zoom ran from /Applications and MeetSync ran through /usr/sbin/installer, and any app set up by the command-line installer is malicious by definition" },
        { value: "quarantine_flag", label: "MeetSync carried a com.apple.quarantine attribute and Zoom did not, and the presence of that attribute alone proves the download was hostile" },
        { value: "pkg_size", label: "The MeetSync package is far larger than the Zoom package, and any macOS installer above a certain size is a repackaged malicious build" },
      ],
      answer: "sig_rootscript",
      explanation:
        "The discriminator is the signature plus what the install script does, not the fact that a .pkg installed something. Zoom has a valid Developer ID Installer signature and is notarized, and its postinstall only registers a per-user LaunchAgent. MeetSync's Developer ID Installer signature is REVOKED (file.signature.status revoked, trusted false), and its postinstall runs as root — writing allow-rows into TCC.db and installing a root LaunchDaemon. Both packages ran through /usr/sbin/installer, which is normal, so the installer path is not a verdict. Both downloaded files would carry com.apple.quarantine — that is set on anything downloaded, benign or not — so its presence proves nothing. And package size is irrelevant. The real tells are a valid+notarized signature with a benign per-user script on one side, and a revoked signature with a root script that rewrites the privacy database on the other.",
    },
    {
      id: "mtp_q2",
      xp: 60,
      kind: "single",
      prompt:
        "In mtp_04 the root postinstall runs /usr/bin/sqlite3 against ~/Library/Application Support/com.apple.TCC/TCC.db, inserting rows keyed to kTCCServiceSystemPolicyAllFiles and kTCCServiceScreenCapture. What did this achieve?",
      hint: "TCC is the macOS subsystem that gates access to protected resources; think about what an allow-row in its database means and who normally creates it.",
      options: [
        { value: "grant_no_prompt", label: "It granted the app Full Disk Access and Screen Recording by writing the approvals straight into the privacy database, so no macOS consent prompt was ever shown to the user" },
        { value: "repair_perms", label: "It ran a routine disk-permission repair that macOS performs at the end of every package install to fix ownership on the new files" },
        { value: "license_db", label: "It stored the app's license key in a local database so the product could validate its activation offline on future launches" },
        { value: "index_files", label: "It rebuilt the Spotlight metadata index for the user's home folder so the newly installed app could search Documents and Desktop" },
      ],
      answer: "grant_no_prompt",
      explanation:
        "TCC (Transparency, Consent and Control) is the macOS subsystem that gates access to protected resources like the whole disk, Screen Recording, the camera and the user's Documents/Desktop/Downloads. Normally the only way an app gets those is the user clicking Allow on a system consent prompt, and those approvals are stored as rows in TCC.db. Because the postinstall runs as root, it writes the allow-rows itself — kTCCServiceSystemPolicyAllFiles is Full Disk Access, kTCCServiceScreenCapture is Screen Recording — so the app is treated as approved without the user ever consenting. It is not a permission repair (macOS does not rewrite TCC.db as an install step), not a license store (no product-activation data or server is involved), and not a Spotlight reindex (that touches metadata stores, not the privacy database). This grant is what makes the later reads of the user's protected folders succeed.",
    },
    {
      id: "mtp_q3",
      xp: 70,
      kind: "single",
      prompt:
        "Reading mtp_04 (the TCC.db write) together with mtp_05 (the LaunchDaemon) and mtp_06 (the file reads): which statement correctly describes what protected resource was reached and why the foothold survives a reboot?",
      hint: "Distinguish a LaunchDaemon in /Library/LaunchDaemons from a per-user LaunchAgent, and connect the TCC grant to what meetsyncd was then able to read.",
      options: [
        { value: "fda_daemon_boot", label: "The TCC grant gave the app Full Disk Access, so meetsyncd could read the user's Documents and Desktop; because its launch item is a root LaunchDaemon in /Library/LaunchDaemons, launchd restarts it automatically at every boot" },
        { value: "agent_login_only", label: "The item is a per-user LaunchAgent, so it only runs when j.okafor logs in and stops touching protected files the moment the user signs out" },
        { value: "cron_temp", label: "Persistence is a temporary cron entry that expires after the first run, and the file reads were possible only while the installer was still open" },
        { value: "quarantine_relaunch", label: "The com.apple.quarantine attribute is what relaunches the helper after reboot, and Full Disk Access is granted automatically to any notarized installer" },
      ],
      answer: "fda_daemon_boot",
      explanation:
        "The TCC.db write granted kTCCServiceSystemPolicyAllFiles (Full Disk Access), which is exactly why meetsyncd's reads of ~/Documents/Q3-Roadmap.pdf and ~/Desktop succeed in mtp_06 — those are TCC-protected locations a normal app cannot touch. Persistence is a LaunchDaemon: the plist sits in /Library/LaunchDaemons and its program runs as root, and launchd starts every daemon in that directory at boot, before any user logs in — so it survives reboot and does not need the user to sign in. A per-user LaunchAgent (option b) would only start at that user's login and is not what was installed here. There is no cron entry, and quarantine does not relaunch anything — it is just a download marker, and it certainly does not confer Full Disk Access. The combination of a system-wide root LaunchDaemon and a self-granted Full Disk Access is what makes this both persistent and high-impact.",
    },
    {
      id: "mtp_q4",
      xp: 55,
      kind: "single",
      prompt:
        "You need to point to the single event where the actor actually reached the user's protected data. Which one is it?",
      hint: "Separate granting a permission and installing persistence from actually opening a protected file; check which process reads a file under the user's home.",
      options: [
        { value: "data_read", label: "mtp_06 — meetsyncd reading Q3-Roadmap.pdf under ~/Documents, a protected folder reachable only because Full Disk Access was granted" },
        { value: "tcc_write", label: "mtp_04 — the sqlite3 write to TCC.db, which changed a permission setting but did not itself open any of the user's documents" },
        { value: "daemon_load", label: "mtp_05 — the launchctl load of the LaunchDaemon, which established persistence but read none of the user's files" },
        { value: "detect_row", label: "mtp_07 — the Falcon detection record, which is where the collected documents are stored after they are read" },
      ],
      answer: "data_read",
      explanation:
        "mtp_06 is the collection step: meetsyncd opens Q3-Roadmap.pdf under ~/Documents, a TCC-protected location, and that read is the moment the user's data is actually reached (T1005). mtp_04 changed a permission — it wrote the allow-row that made the read possible — but opened no document itself. mtp_05 installed persistence and read none of the user's files. And mtp_07 is a detection record — an alert about the activity, not a place data is read or stored. When you scope what was exposed, the protected-folder read is the event to cite.",
    },
    {
      id: "mtp_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "A root LaunchDaemon is now installed, the TCC privacy database was altered, and root-level code ran on MB-PM-07. Select the TWO actions that match the evidence.",
      hint: "Think about what a root LaunchDaemon and a tampered privacy database mean for trusting the host, and what a root script could have changed beyond what you can see.",
      options: [
        { value: "remove_reset_tcc", label: "Remove the LaunchDaemon plist and the MeetSync support directory, stop the running helper, and reset the tampered TCC entries — treating the Full Disk Access and Screen Recording grants as abused" },
        { value: "isolate_rebuild", label: "Isolate the host and, because unknown root code executed, rebuild it from a known-good image rather than trusting on-host cleanup, and rotate the user's credentials and secrets that were within reach" },
        { value: "delete_pkg_only", label: "Just delete MeetSync-Installer.pkg from the Downloads folder, since removing the installer file also removes the launch item and reverts the TCC changes on its own" },
        { value: "gatekeeper_rescan", label: "Run a Gatekeeper rescan of /Applications, which will re-evaluate the app's signature and automatically remove the daemon and the TCC grants" },
      ],
      answer: ["remove_reset_tcc", "isolate_rebuild"],
      explanation:
        "Because a root LaunchDaemon persists and the privacy database was rewritten, cleanup has to remove the persistence (the plist and the helper's support directory), stop the running daemon, and reset the tampered TCC grants so Full Disk Access and Screen Recording are revoked. In parallel, since UNKNOWN root code executed, you cannot fully trust the host — isolate it, rebuild from a known-good image rather than assuming on-host removal is complete, and rotate the user's credentials and any secrets that were reachable through the granted Full Disk Access. Deleting the .pkg alone does nothing about the already-installed daemon or the TCC rows — those live outside the installer file. And a Gatekeeper rescan does not remove a LaunchDaemon or undo TCC.db edits; Gatekeeper evaluates apps at first launch and has no role in reverting persistence or privacy-database changes a root script already made.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "macOS TCC Bypass — a Fake Meeting App .pkg Runs a Root Script, Rewrites the Privacy Database and Persists as a LaunchDaemon",
    threat_actor: "macOS intrusion operator distributing a trojanized installer package (fake productivity/meeting app)",
    attack_kind: "macos_tcc_bypass",
    briefing:
      "Falcon raised a High alert on MB-PM-07, a product manager's MacBook: minutes after she installed what she thought was a new meeting app, a system installer ran a root script, a background service was registered, and the machine's own privacy database was rewritten. Work out what the installer really did, which protected files it reached, and how it holds on across a reboot.",
    narrative: `MB-PM-07 is a MacBook belonging to Jelani Okafor, a product manager at Northwind Collab. Looking for a lightweight meeting tool, he downloaded and opened MeetSync-Installer.pkg. The day before, the same Mac had cleanly installed Zoom from a notarized, Developer-ID-signed package, and that install is the control case: valid signature, Gatekeeper passed, a per-user LaunchAgent for the updater, and nothing else. The MeetSync package behaved nothing like it.

When Jelani opened the package, /usr/sbin/installer installed it to the system. Falcon recorded the package's Developer ID Installer signature as REVOKED, with the com.apple.quarantine attribute still set — the provenance a careful analyst would stop on. macOS package installs run their preinstall/postinstall scripts as root, and this one used that: the postinstall spawned /bin/sh from the install sandbox as root. Defender for Endpoint, also on the Mac, independently logged the same root shell, tying it to the same payload hash.

The root script then did two things that matter. First it ran /usr/bin/sqlite3 against the user's TCC privacy database at ~/Library/Application Support/com.apple.TCC/TCC.db, inserting allow-rows for kTCCServiceSystemPolicyAllFiles (Full Disk Access) and kTCCServiceScreenCapture (Screen Recording) keyed to com.meetsync.app — so the app was treated as approved for those protected permissions without Jelani ever seeing a consent prompt. Second, it wrote /Library/LaunchDaemons/com.meetsync.helper.plist, pointing at an ad-hoc-signed root helper, and ran launchctl load -w on it: a LaunchDaemon in that directory is started by launchd at every boot, as root, before any user logs in.

launchd started the helper, meetsyncd, which — using the Full Disk Access it had just been granted — read files under ~/Documents and ~/Desktop, including Q3-Roadmap.pdf. Falcon raised the Critical detection a moment later. The exercise is to reconstruct that chain from the endpoint logs and to scope containment for a case where root code ran, the privacy database was altered, and persistence will outlive a reboot.`,
    learning_objectives: [
      "Tell a benign macOS .pkg install from a malicious one using package-signing state (valid Developer ID + notarization + Gatekeeper vs a revoked signature) and what the install scripts do, not the fact that an installer ran",
      "Recognise a package preinstall/postinstall running /bin/sh as root as install-script execution with inherited root privilege (T1059.004)",
      "Read a root write to ~/Library/Application Support/com.apple.TCC/TCC.db that inserts allow-rows for Full Disk Access and Screen Recording as TCC manipulation that grants protected permissions with no consent prompt (T1548.006)",
      "Distinguish a root LaunchDaemon in /Library/LaunchDaemons from a per-user LaunchAgent, and explain why the former survives a reboot and starts before login (T1543.004)",
      "Scope containment for a root-level macOS compromise: remove the LaunchDaemon and reset the tampered TCC grants, isolate and rebuild because unknown root code ran, and rotate reachable credentials",
    ],
    alerts: [], // alerts are attached by the catalogue wiring (withAlerts)
    events,
    iocs,
    killchain,
    questions,
  };
}
