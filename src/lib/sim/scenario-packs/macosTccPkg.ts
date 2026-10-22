/**
 * Scenario pack: "macOS TCC Bypass, a Fake Meeting App .pkg Runs a Root Script,
 * Rewrites the Privacy Database and Persists as a LaunchDaemon"
 *
 * INTERMEDIATE tier. Deepens the platform's macOS coverage a second way. Where
 * the stealer scenario was a DMG that phished the login password and harvested
 * Keychain/cookies, this one is a malicious INSTALLER PACKAGE (.pkg) distributed
 * as a fake productivity / meeting app. The download page tells the user to run an
 * install command in Terminal: `sudo installer -pkg ... -target / -allowUntrusted`.
 * The command-line installer skips Gatekeeper, and -allowUntrusted lets it proceed
 * over a REVOKED Developer ID Installer signature. The package's postinstall script
 * runs as root (installd > package_script_service > /bin/sh), writes allow-entries
 * directly into the TCC (Transparency, Consent and Control) privacy database,
 * granting the app Full Disk Access and Screen Recording without a consent prompt,
 * and drops a LaunchDaemon in /Library/LaunchDaemons so a root helper starts at
 * every boot. The helper then reads the user's Documents/Desktop and calls home.
 *
 * The teaching spine is telling a benign .pkg install from a malicious one when
 * both have the same SHAPE: an installer runs, an app is set up, a script runs as
 * root. The BENIGN CONTROL (mtp_00 series) is Zoom, installed the day before: it
 * came from zoom.us, Gatekeeper accepted a notarized Developer ID Installer
 * signature, Installer.app ran it, and its postinstall touched only /Applications.
 * The malicious package came from a new domain, was installed from Terminal with
 * -allowUntrusted over a revoked signature, and its postinstall edited TCC.db and
 * installed a root LaunchDaemon.
 *
 * SOURCES (several independent views of the one Mac):
 *  - CrowdStrike Falcon (Mac sensor): the process tree, file writes, DNS, the
 *    outbound connection and the detection.
 *  - Microsoft Defender for Endpoint (also on the Mac): file-origin of the package
 *    and an independent record of the root postinstall shell.
 *  - Zscaler Internet Access: the web request that fetched the package.
 *  - macOS Unified Log (`log show --style ndjson`): the system's own record of the
 *    Gatekeeper assessment and of the installer's signature check.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csFile, csAlert, csDns, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { mdeProcess, mdeFile } from "@/lib/sim/emitters/mde";
import { zscalerWeb } from "@/lib/sim/emitters/zscaler";
import { macosUnifiedLog } from "./macosUnifiedLog";

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
    id: "65ea2d20bf4b4bb0472f9396f2c00b64",
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
  const pkgUrl = "https://meetsync-app.com/dl/MeetSync-Installer.pkg";
  const bundleId = "com.meetsync.app";
  const tccDb = "/Users/j.okafor/Library/Application Support/com.apple.TCC/TCC.db";
  const daemonPlist = "/Library/LaunchDaemons/com.meetsync.helper.plist";
  const daemonBin = "/Library/Application Support/MeetSync/meetsyncd";
  const scriptsDir = "/private/tmp/PKInstallSandbox.7fA2Vq/Scripts/com.meetsync.app.pkg.Qk8Lp3";
  const c2Domain = "api.meetsync-app.com";
  const c2Ip = "45.9.148.221";

  // Two different files, two different hashes: the installer package the user
  // downloaded, and the Mach-O helper the package laid down.
  const pkgHash = makeSha256("macos_tcc_pkg_meetsync_installer_package_2026");
  const payloadHash = makeSha256("macos_tcc_pkg_meetsync_helper_machO_meetsyncd_2026");
  // Zoom.pkg, the benign control.
  const zoomPkgHash = makeSha256("macos_tcc_pkg_zoom_pkg_notarized_control");
  // The sqlite3 invocation: named columns (the current `access` table has 17 of them).
  const tccInsert = (service: string) =>
    `INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, flags, last_modified) VALUES ('${service}','${bundleId}',0,2,4,1,'UNUSED',0,CAST(strftime('%s','now') AS INTEGER));`;
  const sqliteCmd = `sqlite3 "${tccDb}" "${tccInsert("kTCCServiceSystemPolicyAllFiles")} ${tccInsert("kTCCServiceScreenCapture")}"`;

  const cx = "northwind-collab" as const;
  const osx = { "host.os.name": host.os, "host.os.version": host.osVersion, "crowdstrike.event_platform": "Mac" };
  const base = { companyId: cx, host: host.name, user: user.email, srcIp: host.ip } as const;
  const apple = { signed: true, signatureSubject: "Software Signing" } as const;
  const pkgScriptSvc = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service";
  const installdPath = "/System/Library/PrivateFrameworks/PackageKit.framework/Resources/installd";
  const installerAppPath = "/System/Library/CoreServices/Installer.app/Contents/MacOS/Installer";

  // One macOS Unified Log record, as `log show --style ndjson` prints it.
  const unifiedLog = (o: { id: string; ts: string; process: string; pid: number; subsystem: string; category: string; message: string; type?: "Default" | "Error" | "Info"; description: string; severity?: TelemetryEvent["severity"]; incident?: string }): TelemetryEvent =>
    macosUnifiedLog({
      id: o.id, ts: o.ts, host: host.name, srcIp: host.ip, incidentId: o.incident, processImagePath: o.process, processId: o.pid,
      subsystem: o.subsystem, category: o.category, eventMessage: o.message, messageType: o.type, severity: o.severity, description: o.description,
    });

  const events: TelemetryEvent[] = [
    // ── BENIGN CONTROL (the day before): Zoom, installed from its own site ──────────
    zscalerWeb({
      ...base, id: "mtp_00a_benign_zoom_download", ts: "2026-08-27T09:14:21.000Z",
      url: "https://zoom.us/client/latest/Zoom.pkg", domain: "zoom.us", category: "Professional Services", appName: "Zoom",
      status: 200, bytesSent: 612, bytesReceived: 118_400_000, userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
      severity: "informational", description: "Zscaler allowed the download of Zoom.pkg from zoom.us.",
    }),
    mdeFile({
      ...base, id: "mtp_00b_benign_zoom_pkg_file", ts: "2026-08-27T09:14:58.000Z", path: "/Users/j.okafor/Downloads/Zoom.pkg",
      sha256: zoomPkgHash, size: 118_400_000, action: "file_create", initiatingProcess: "Safari", severity: "informational",
      extra: { "FolderPath": "/Users/j.okafor/Downloads", "FileOriginReferrerUrl": "https://zoom.us/download", "DeviceId": host.id },
      description: "Defender for Endpoint recorded Zoom.pkg created in Downloads by Safari, with the zoom.us referrer.",
    }),
    unifiedLog({
      id: "mtp_00c_benign_gatekeeper_accept", ts: "2026-08-27T09:15:01.402Z", process: "/usr/libexec/syspolicyd", pid: 612,
      subsystem: "com.apple.syspolicy", category: "gk",
      message: "Assessment of /Users/j.okafor/Downloads/Zoom.pkg: accepted, source=Notarized Developer ID, signer=Developer ID Installer: Zoom Video Communications, Inc. (BJ4HAAB9B3)",
      description: "syspolicyd accepted Zoom.pkg: notarized, valid Developer ID Installer signature.",
    }),
    csProcess({
      ...base, id: "mtp_00_benign_notarized_pkg", ts: "2026-08-27T09:15:03.000Z", runAsUser: user.sam,
      processName: "Installer", processPath: installerAppPath, cmdline: installerAppPath,
      parentName: "launchd", parentPid: 1, pid: 3170, ...apple,
      severity: "informational", expectedVerdict: "fp",
      fpExplanation: "The control case for the whole scenario. Zoom was installed the day before with Installer.app: the same 'a package installs an app and a script runs as root' shape as the intrusion. What makes it benign is the evidence around it. The package came from zoom.us, Gatekeeper accepted a notarized Developer ID Installer signature (syspolicyd), the install ran through the normal Installer app with no override flag, and the postinstall wrote only under /Applications. Package scripts run as root for every package, so root alone proves nothing; the discriminators are origin, signature and what the script touches.",
      extra: { ...osx },
      description: "Installer.app opened Zoom.pkg for the logged-in user.",
    }),
    csProcess({
      ...base, id: "mtp_00d_benign_postinstall", ts: "2026-08-27T09:15:19.000Z", runAsUser: "root",
      processName: "sh", processPath: "/bin/sh", cmdline: "/bin/sh /private/tmp/PKInstallSandbox.3RbQ9w/Scripts/us.zoom.pkg.videomeeting.Pq4Wd1/postinstall",
      parentName: "package_script_service", parentPid: 3182, pid: 3186, ...apple, expectedVerdict: "fp",
      extra: { ...osx },
      description: "Zoom's package postinstall ran as root, as every package script does.",
    }),
    csFile({
      ...base, id: "mtp_00e_benign_zoom_app_written", ts: "2026-08-27T09:15:24.000Z", action: "file_create",
      path: "/Applications/zoom.us.app/Contents/MacOS/zoom.us", actorProcess: "installd", actorPath: installdPath, actorPid: 3178,
      actorParentName: "launchd", actorParentPid: 1, actorSigned: "valid", runAsUser: "root",
      extra: { ...osx }, description: "installd wrote the Zoom application bundle under /Applications.",
    }),

    // ── DELIVERY: the fake meeting app is fetched from a new domain ─────────────────
    zscalerWeb({
      ...base, id: "mtp_00f_zscaler_pkg_download", ts: T(-100 * SEC),
      url: pkgUrl, domain: "meetsync-app.com", category: "Newly Registered and Observed Domains", appName: "General Browsing",
      status: 200, bytesSent: 698, bytesReceived: 48_372_736, userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
      severity: "low", description: "Zscaler allowed the download of MeetSync-Installer.pkg from meetsync-app.com.",
    }),
    mdeFile({
      ...base, id: "mtp_01a_pkg_download_file", ts: T(-80 * SEC), path: pkgPath,
      sha256: pkgHash, size: 48_372_736, action: "file_create", initiatingProcess: "Safari", severity: "low",
      extra: { "FolderPath": "/Users/j.okafor/Downloads", "FileOriginReferrerUrl": "https://meetsync-app.com/", "DeviceId": host.id },
      description: "Defender for Endpoint recorded MeetSync-Installer.pkg created in Downloads by Safari, referrer meetsync-app.com.",
    }),

    // ── EXECUTION: the user pastes the install command into Terminal ───────────────
    csProcess({
      ...base, id: "mtp_01b_terminal", ts: T(-30 * SEC), incidentId: INCIDENT, runAsUser: user.sam,
      processName: "Terminal", processPath: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
      cmdline: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", parentName: "launchd", parentPid: 1, pid: 2840, ...apple,
      extra: { ...osx }, description: "Terminal was opened by the user.",
    }),
    csProcess({
      ...base, id: "mtp_01c_login", ts: T(-29 * SEC), incidentId: INCIDENT, runAsUser: "root",
      processName: "login", processPath: "/usr/bin/login", cmdline: `login -pf ${user.sam}`,
      parentName: "Terminal", parentPid: 2840, pid: 2843, ...apple, extra: { ...osx }, description: "Terminal started a login session.",
    }),
    csProcess({
      ...base, id: "mtp_01d_zsh", ts: T(-29 * SEC + 400), incidentId: INCIDENT, runAsUser: user.sam,
      processName: "zsh", processPath: "/bin/zsh", cmdline: "-zsh", parentName: "login", parentPid: 2843, pid: 2846, ...apple,
      extra: { ...osx }, description: "The login session started the user's shell.",
    }),
    csProcess({
      ...base, id: "mtp_01e_sudo", ts: T(-3 * SEC), incidentId: INCIDENT, runAsUser: "root",
      processName: "sudo", processPath: "/usr/bin/sudo", cmdline: `sudo installer -pkg ${pkgPath} -target / -allowUntrusted`,
      parentName: "zsh", parentPid: 2846, pid: 4198, ...apple, extra: { ...osx }, description: "The shell ran sudo.",
    }),
    csProcess({
      ...base, id: "mtp_01_pkg_install", ts: T(0), runAsUser: "root", incidentId: INCIDENT,
      processName: "installer", processPath: "/usr/sbin/installer", cmdline: `installer -pkg ${pkgPath} -target / -allowUntrusted`,
      parentName: "sudo", parentPid: 4198, pid: 4207, ...apple,
      mitre: "T1204.002", tactic: "Execution", severity: "high",
      extra: { ...osx },
      description: "/usr/sbin/installer was run as root from Terminal against MeetSync-Installer.pkg with -allowUntrusted.",
    }),
    unifiedLog({
      id: "mtp_01f_installer_signature_check", ts: T(1 * SEC + 118), process: "/usr/sbin/installer", pid: 4207,
      subsystem: "com.apple.install", category: "default", type: "Error", severity: "medium",
      message: "Package \"MeetSync-Installer.pkg\": signing certificate \"Developer ID Installer: Bright Meridian Ltd (7Q9K2M4X8Z)\" is revoked; continuing because -allowUntrusted was specified",
      description: "The installer's signature check found a revoked Developer ID Installer certificate and continued because of -allowUntrusted.",
    }),
    csProcess({
      ...base, id: "mtp_01g_installd", ts: T(2 * SEC), incidentId: INCIDENT, runAsUser: "root",
      processName: "installd", processPath: installdPath, cmdline: installdPath, parentName: "launchd", parentPid: 1, pid: 4210, ...apple,
      extra: { ...osx }, description: "launchd started installd to unpack the package payload.",
    }),
    csFile({
      ...base, id: "mtp_01h_helper_written", ts: T(3 * SEC), incidentId: INCIDENT, action: "file_create",
      path: daemonBin, sha256: payloadHash, size: 1_482_240, actorProcess: "installd", actorPath: installdPath, actorPid: 4210,
      actorParentName: "launchd", actorParentPid: 1, actorSigned: "valid", runAsUser: "root",
      severity: "low",
      extra: { ...osx }, description: "installd wrote the Mach-O helper /Library/Application Support/MeetSync/meetsyncd from the package payload.",
    }),

    // ── ROOT INSTALL SCRIPT: the package postinstall runs as root (T1059.004) ──────
    csProcess({
      ...base, id: "mtp_02a_package_script_service", ts: T(3 * SEC + 600), incidentId: INCIDENT, runAsUser: "root",
      processName: "package_script_service", processPath: pkgScriptSvc, cmdline: pkgScriptSvc,
      parentName: "installd", parentPid: 4210, pid: 4214, ...apple,
      extra: { ...osx }, description: "installd started the package script service.",
    }),
    csProcess({
      ...base, id: "mtp_02_postinstall_root_shell", ts: T(4 * SEC), runAsUser: "root", incidentId: INCIDENT,
      processName: "sh", processPath: "/bin/sh", cmdline: `/bin/sh ${scriptsDir}/postinstall`,
      parentName: "package_script_service", parentPid: 4214, pid: 4221, ...apple,
      mitre: "T1059.004", tactic: "Execution", severity: "high",
      extra: { ...osx },
      description: "The package script service ran the postinstall script: /bin/sh from the PKInstallSandbox Scripts directory, as root.",
    }),
    // CORROBORATION, Microsoft Defender for Endpoint sees the same root script.
    mdeProcess({
      ...base, id: "mtp_03_mde_postinstall_corroboration", ts: T(5 * SEC), incidentId: INCIDENT,
      processName: "sh", processPath: "/bin/sh", cmdline: `/bin/sh ${scriptsDir}/postinstall`,
      parentName: "package_script_service", pid: 4221, parentPid: 4214, runAsUser: "root", accountName: "root", accountDomain: host.name,
      mitre: "T1059.004", tactic: "Execution", severity: "high",
      extra: {
        "Timestamp": T(5 * SEC), "DeviceId": host.id, "FolderPath": "/bin",
        "InitiatingProcessFolderPath": pkgScriptSvc, "InitiatingProcessCommandLine": pkgScriptSvc, "InitiatingProcessId": "4214",
        "InitiatingProcessSHA256": makeSha256("macos_package_script_service_apple_system_binary"), "ReportId": "88301744",
      },
      description: "Defender for Endpoint, also deployed on this Mac, independently recorded the same postinstall /bin/sh child of package_script_service running under the root account.",
    }),

    // ── TCC MANIPULATION: the root script writes allow-rows into TCC.db (T1548.006) ─
    csProcess({
      ...base, id: "mtp_04a_sqlite3_exec", ts: T(8 * SEC), runAsUser: "root", incidentId: INCIDENT,
      processName: "sqlite3", processPath: "/usr/bin/sqlite3", cmdline: sqliteCmd,
      parentName: "sh", parentPid: 4221, pid: 4238, ...apple,
      extra: { ...osx }, description: "The postinstall ran sqlite3 against the user's TCC.db with two INSERT statements.",
    }),
    csFile({
      ...base, id: "mtp_04_tcc_db_write", ts: T(9 * SEC), action: "file_modify",
      path: tccDb, sha256: null, actorProcess: "sqlite3", actorPath: "/usr/bin/sqlite3", actorPid: 4238,
      actorParentName: "sh", actorParentPid: 4221, actorSigned: "valid", runAsUser: "root",
      mitre: "T1548.006", tactic: "Privilege Escalation", severity: "critical", incidentId: INCIDENT,
      extra: { ...osx },
      description: "sqlite3 modified the user's TCC privacy database at ~/Library/Application Support/com.apple.TCC/TCC.db: allow-rows for kTCCServiceSystemPolicyAllFiles (Full Disk Access) and kTCCServiceScreenCapture (Screen Recording), keyed to com.meetsync.app. No consent prompt was shown.",
    }),

    // ── PERSISTENCE: a root LaunchDaemon is installed and loaded (T1543.004) ───────
    csFile({
      ...base, id: "mtp_05a_launchdaemon_plist_written", ts: T(13 * SEC), action: "file_create",
      path: daemonPlist, actorProcess: "sh", actorPath: "/bin/sh", actorPid: 4221,
      actorParentName: "package_script_service", actorParentPid: 4214, actorSigned: "valid", runAsUser: "root",
      mitre: "T1543.004", tactic: "Persistence", severity: "high", incidentId: INCIDENT,
      extra: { ...osx }, description: "The postinstall wrote the LaunchDaemon plist /Library/LaunchDaemons/com.meetsync.helper.plist, pointing at meetsyncd.",
    }),
    csProcess({
      ...base, id: "mtp_05_launchdaemon_persist", ts: T(15 * SEC), runAsUser: "root", incidentId: INCIDENT,
      processName: "launchctl", processPath: "/bin/launchctl", cmdline: `launchctl load -w ${daemonPlist}`,
      parentName: "sh", parentPid: 4221, pid: 4256, ...apple,
      mitre: "T1543.004", tactic: "Persistence", severity: "high",
      extra: { ...osx },
      description: "The root script ran launchctl load -w on the new LaunchDaemon plist; launchd starts every daemon in /Library/LaunchDaemons at boot, as root.",
    }),
    csProcess({
      ...base, id: "mtp_05b_helper_start", ts: T(16 * SEC), runAsUser: "root", incidentId: INCIDENT,
      processName: "meetsyncd", processPath: daemonBin, cmdline: daemonBin, sha256: payloadHash,
      parentName: "launchd", parentPid: 1, pid: 4290, signed: false,
      extra: { ...osx },
      description: "launchd started the new LaunchDaemon: meetsyncd, an ad-hoc-signed helper, running as root.",
    }),

    // ── COMMAND AND CONTROL: the helper calls home ─────────────────────────────────
    csDns({
      ...base, id: "mtp_05c_helper_dns", ts: T(17 * SEC), incidentId: INCIDENT, domain: c2Domain, resolvedIp: c2Ip,
      processName: "meetsyncd", processPath: daemonBin, pid: 4290, parentName: "launchd", parentPid: 1, sha256: payloadHash,
      mitre: "T1071.001", tactic: "Command and Control", severity: "medium",
      description: "meetsyncd resolved api.meetsync-app.com.",
    }),
    csNetwork({
      ...base, id: "mtp_05d_helper_connect", ts: T(18 * SEC), incidentId: INCIDENT, remoteIp: c2Ip, remotePort: 443, application: "tls",
      processName: "meetsyncd", processPath: daemonBin, pid: 4290, parentName: "launchd", parentPid: 1, sha256: payloadHash,
      mitre: "T1071.001", tactic: "Command and Control", severity: "medium",
      description: "meetsyncd opened an outbound TLS connection to 45.9.148.221:443.",
    }),

    // ── PROTECTED-DATA ACCESS: the root helper reads the user's files via Full Disk Access (T1005) ─
    csFile({
      ...base, id: "mtp_06_protected_data_read", ts: T(40 * SEC), action: "file_access",
      path: "/Users/j.okafor/Documents/Q3-Roadmap.pdf", sha256: null, actorProcess: "meetsyncd", actorPath: daemonBin, actorPid: 4290,
      actorParentName: "launchd", actorParentPid: 1, actorSha256: payloadHash, actorSigned: "adhoc", runAsUser: "root",
      mitre: "T1005", tactic: "Collection", severity: "critical", incidentId: INCIDENT,
      extra: { ...osx },
      description: "meetsyncd, launched by launchd from /Library/Application Support/MeetSync, opened Q3-Roadmap.pdf under ~/Documents, a TCC-protected location. The read succeeds because the earlier TCC.db write granted the bundle Full Disk Access.",
    }),
    csFile({
      ...base, id: "mtp_06a_protected_data_read_desktop", ts: T(42 * SEC), action: "file_access",
      path: "/Users/j.okafor/Desktop/Customer-Pricing-2026.xlsx", sha256: null, actorProcess: "meetsyncd", actorPath: daemonBin, actorPid: 4290,
      actorParentName: "launchd", actorParentPid: 1, actorSha256: payloadHash, actorSigned: "adhoc", runAsUser: "root",
      mitre: "T1005", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      extra: { ...osx }, description: "meetsyncd opened a second file, this one under ~/Desktop.",
    }),

    // ── THE DETECTION, Falcon ties the chain into one macOS TCC-manipulation case ──
    {
      ...csAlert({
        ...base, id: "mtp_07_edr_detection", ts: T(1 * MIN), runAsUser: "root",
        threatName: "MacOS_PkgPostinstall_TCCManipulation_LaunchDaemon", mitre: "T1548.006", tactic: "Privilege Escalation",
        technique: "TCC Manipulation", action: "detected", severity: "critical", incidentId: INCIDENT,
        processName: "meetsyncd", processPath: daemonBin, cmdline: daemonBin, sha256: payloadHash, pid: 4290,
        parentPath: "/sbin/launchd",
        extra: { ...osx, "crowdstrike.Objective": "Falcon Detection Method" },
        detail: "A package installed with -allowUntrusted over a revoked signature ran a root postinstall that wrote to the TCC privacy database and installed a root LaunchDaemon, followed by reads of the user's protected folders.",
        description: "Falcon raised a Critical detection on MB-PM-07: a package installed with -allowUntrusted over a revoked signature ran a root postinstall that wrote to the TCC privacy database and installed a root LaunchDaemon, followed by reads of the user's protected folders. A macOS TCC-manipulation and persistence pattern.",
      }),
      edr_scope: "edr",
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.name, // MB-PM-07, the infected MacBook (own endpoint, not adversary infra)
      first_seen: T(-100 * SEC),
      last_seen: T(1 * MIN),
      reputation: "unknown",
      tags: ["macos", "endpoint", "infected"],
    },
    {
      type: "user",
      value: user.sam, // j.okafor, the user whose protected data was reached
      first_seen: T(-100 * SEC),
      last_seen: T(1 * MIN),
      reputation: "suspicious",
      tags: ["macos-user", "data-owner", "affected"],
    },
    {
      type: "sha256",
      value: pkgHash, // the downloaded MeetSync-Installer.pkg
      first_seen: T(-80 * SEC),
      last_seen: T(1 * SEC),
      reputation: "malicious",
      tags: ["macos", "installer-package", "revoked-signature"],
    },
    {
      type: "sha256",
      value: payloadHash, // the meetsyncd Mach-O helper the package dropped
      first_seen: T(3 * SEC),
      last_seen: T(1 * MIN),
      reputation: "malicious",
      tags: ["macos", "mach-o", "launchdaemon-payload"],
    },
    {
      type: "domain",
      value: "meetsync-app.com",
      first_seen: T(-100 * SEC),
      last_seen: T(17 * SEC),
      reputation: "malicious",
      tags: ["download-site", "newly-registered", "c2"],
    },
    {
      type: "ip",
      value: c2Ip,
      first_seen: T(17 * SEC),
      last_seen: T(18 * SEC),
      reputation: "malicious",
      tags: ["external", "hosting", "c2"],
    },
  ];

  const killchain = [
    { ts: "2026-08-27T09:15:03.000Z", phase: "Baseline", action: "Zoom.pkg installs cleanly the day before: downloaded from zoom.us, notarized Developer ID Installer signature accepted by Gatekeeper, Installer.app, a postinstall that touches only /Applications. The clean-install control case" },
    { ts: T(-100 * SEC), phase: "Resource Development", action: `${pkgName} is downloaded from the new domain meetsync-app.com through the web proxy` },
    { ts: T(-3 * SEC), phase: "Execution", action: "The user runs sudo installer -pkg ... -target / -allowUntrusted in Terminal; the command-line installer skips Gatekeeper (T1204.002)" },
    { ts: T(1 * SEC), phase: "Stealth", action: "The installer logs the revoked Developer ID Installer signature and continues because of -allowUntrusted" },
    { ts: T(4 * SEC), phase: "Execution", action: "Package postinstall runs /bin/sh from the install sandbox as root, spawned by package_script_service (T1059.004)" },
    { ts: T(8 * SEC), phase: "Privilege Escalation", action: "sqlite3 writes Full Disk Access + Screen Recording allow-rows into ~/Library/Application Support/com.apple.TCC/TCC.db (T1548.006)" },
    { ts: T(15 * SEC), phase: "Persistence", action: `${daemonPlist} written and launchctl load -w; a root LaunchDaemon that starts at every boot (T1543.004)` },
    { ts: T(17 * SEC), phase: "Command and Control", action: "meetsyncd starts under launchd, resolves api.meetsync-app.com and connects out over TLS (T1071.001)" },
    { ts: T(40 * SEC), phase: "Collection", action: "meetsyncd reads ~/Documents and ~/Desktop under the granted Full Disk Access (T1005)" },
    { ts: T(1 * MIN), phase: "Detection", action: "Falcon raises the Critical macOS TCC-manipulation / LaunchDaemon detection tying the chain together" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "mtp_q1",
      xp: 55,
      kind: "single",
      prompt:
        "Two package installs appear on MB-PM-07: Zoom the day before (mtp_00 series) and MeetSync (mtp_01 series). Both ran a postinstall script as root. Which observations separate the benign install from the malicious one?",
      hint: "Compare where each package came from, what the system logged about its signature, and how the installer was started.",
      options: [
        { value: "origin_sig_route", label: "Zoom came from zoom.us with a notarized signature Gatekeeper accepted; MeetSync came from a new domain and was run from Terminal with -allowUntrusted over a revoked certificate" },
        { value: "root_script", label: "Zoom's postinstall ran as the logged-in user while MeetSync's ran as root, and a package script that runs as root is the malicious tell here" },
        { value: "quarantine_flag", label: "MeetSync still carried com.apple.quarantine and Zoom did not, which shows only the MeetSync package was fetched from a hostile source" },
        { value: "pkg_size", label: "The MeetSync package is smaller than Zoom's, the typical footprint of an installer that was repackaged to carry an extra hidden payload" },
      ],
      answer: "origin_sig_route",
      explanation:
        "The discriminators are origin, signature and install route, not the fact that a package installed something. Zoom was fetched from zoom.us (Zscaler, Defender file origin), syspolicyd accepted a notarized Developer ID Installer signature, and Installer.app ran it. MeetSync was fetched from meetsync-app.com, a newly registered domain; the installer was started from Terminal with -allowUntrusted, a flag that exists to continue past a signature the system does not trust, and the installer's own log line says the Developer ID certificate is revoked. Package postinstall scripts run as root for every package, Zoom's included, so root by itself proves nothing (option b). A downloaded file normally carries com.apple.quarantine whether it is benign or not, so that proves nothing either (option c), and package size is irrelevant (option d).",
    },
    {
      id: "mtp_q2",
      xp: 60,
      kind: "single",
      prompt:
        "In mtp_04a the root postinstall runs /usr/bin/sqlite3 against ~/Library/Application Support/com.apple.TCC/TCC.db, inserting rows keyed to kTCCServiceSystemPolicyAllFiles and kTCCServiceScreenCapture (mtp_04 shows the file write). What did this achieve?",
      hint: "TCC is the macOS subsystem that gates access to protected resources; think about what an allow-row in its database means and who normally creates it.",
      options: [
        { value: "grant_no_prompt", label: "It granted Full Disk Access and Screen Recording by writing approvals straight into TCC.db, so no consent prompt was ever shown" },
        { value: "repair_perms", label: "It ran the disk-permission repair that macOS performs at the end of a package install to fix ownership and ACLs on new files" },
        { value: "license_db", label: "It stored the app's licence entitlement in a local SQLite database so activation can be validated offline on future launches" },
        { value: "index_files", label: "It rebuilt the Spotlight metadata index for the user's home folder so the newly installed app could search the Documents and Desktop folders" },
      ],
      answer: "grant_no_prompt",
      explanation:
        "TCC (Transparency, Consent and Control) is the macOS subsystem that gates access to protected resources like the whole disk, Screen Recording, the camera and the user's Documents/Desktop/Downloads. Normally the only way an app gets those is the user clicking Allow on a system consent prompt, and those approvals are stored as rows in TCC.db. The sqlite3 command line in mtp_04a inserts the two allow-rows itself (auth_value 2 is allowed), keyed to com.meetsync.app, so the app is treated as approved without the user ever consenting. It is not a permission repair (macOS does not rewrite TCC.db as an install step), not a license store (no product-activation data or server is involved), and not a Spotlight reindex (that touches metadata stores, not the privacy database). This grant is what makes the later reads of the user's protected folders succeed.",
    },
    {
      id: "mtp_q3",
      xp: 70,
      kind: "single",
      prompt:
        "Reading mtp_04 (the TCC.db write) together with mtp_05 (the LaunchDaemon) and mtp_06 (the file reads): which statement correctly describes what protected resource was reached and why the foothold survives a reboot?",
      hint: "Distinguish a LaunchDaemon in /Library/LaunchDaemons from a per-user LaunchAgent, and connect the TCC grant to what meetsyncd was then able to read.",
      options: [
        { value: "fda_daemon_boot", label: "Full Disk Access let meetsyncd read Documents and Desktop; as a root LaunchDaemon in /Library/LaunchDaemons it starts at every boot" },
        { value: "agent_login_only", label: "It is a per-user LaunchAgent, so it runs only while the user is logged in and loses access to protected files once they sign out" },
        { value: "cron_temp", label: "Persistence is a one-shot cron entry that expires after its first run, and the file reads worked only while the installer window was open" },
        { value: "quarantine_relaunch", label: "The quarantine attribute makes launchd relaunch the helper after reboot, and Full Disk Access comes with any notarized installer" },
      ],
      answer: "fda_daemon_boot",
      explanation:
        "The TCC.db write granted kTCCServiceSystemPolicyAllFiles (Full Disk Access), which is exactly why meetsyncd's reads of ~/Documents/Q3-Roadmap.pdf and ~/Desktop succeed in mtp_06: those are TCC-protected locations a normal app cannot touch. Persistence is a LaunchDaemon: the plist sits in /Library/LaunchDaemons (mtp_05a) and its program runs as root, and launchd starts every daemon in that directory at boot, before any user logs in, so it survives reboot and does not need the user to sign in. A per-user LaunchAgent (option b) would only start at that user's login and is not what was installed here. There is no cron entry, and quarantine does not relaunch anything; it is just a download marker and it certainly does not confer Full Disk Access. The combination of a system-wide root LaunchDaemon and a self-granted Full Disk Access is what makes this both persistent and high-impact.",
    },
    {
      id: "mtp_q4",
      xp: 55,
      kind: "single",
      prompt:
        "You need to point to the single event where the actor actually reached the user's protected data. Which one is it?",
      hint: "Separate granting a permission and installing persistence from actually opening a protected file; check which process reads a file under the user's home.",
      options: [
        { value: "data_read", label: "meetsyncd opening Q3-Roadmap.pdf under ~/Documents, a protected folder it reaches through the Full Disk Access grant" },
        { value: "tcc_write", label: "The sqlite3 write into TCC.db, the step that handed the helper its access to every protected file on the user's disk" },
        { value: "daemon_load", label: "The launchctl load of the root LaunchDaemon, the moment meetsyncd started running with root access to the home folder" },
        { value: "detect_row", label: "The Falcon detection record, which captures the collected documents into the cloud console once they have been read" },
      ],
      answer: "data_read",
      explanation:
        "mtp_06 is the collection step: meetsyncd opens Q3-Roadmap.pdf under ~/Documents, a TCC-protected location, and that read is the moment the user's data is actually reached (T1005); mtp_06a is a second read under ~/Desktop. mtp_04 changed a permission (it wrote the allow-row that made the read possible) but opened no document itself. mtp_05 installed persistence and read none of the user's files. And mtp_07 is a detection record: an alert about the activity, not a place data is read or stored. When you scope what was exposed, the protected-folder reads are the events to cite, together with the callback connection.",
    },
    {
      id: "mtp_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "A root LaunchDaemon is now installed, the TCC privacy database was altered, and root-level code ran on MB-PM-07. Select the TWO actions that match the evidence.",
      hint: "Think about what a root LaunchDaemon and a tampered privacy database mean for trusting the host, and what a root script could have changed beyond what you can see.",
      options: [
        { value: "remove_reset_tcc", label: "Remove the LaunchDaemon plist and the MeetSync support directory, stop the running helper, and reset the tampered TCC entries, treating the Full Disk Access and Screen Recording grants as abused" },
        { value: "isolate_rebuild", label: "Isolate the host and, because unknown root code executed, rebuild it from a known-good image rather than trusting on-host cleanup, and rotate the user's credentials and secrets that were within reach" },
        { value: "delete_pkg_only", label: "Just delete MeetSync-Installer.pkg from the Downloads folder, since removing the installer file also removes the launch item and reverts the TCC changes on its own" },
        { value: "gatekeeper_rescan", label: "Run a Gatekeeper rescan of /Applications, which re-evaluates the app's revoked signature and automatically removes the daemon and the TCC grants it relied on" },
      ],
      answer: ["remove_reset_tcc", "isolate_rebuild"],
      explanation:
        "Because a root LaunchDaemon persists and the privacy database was rewritten, cleanup has to remove the persistence (the plist and the helper's support directory), stop the running daemon, and reset the tampered TCC grants so Full Disk Access and Screen Recording are revoked. In parallel, since UNKNOWN root code executed, you cannot fully trust the host: isolate it, rebuild from a known-good image rather than assuming on-host removal is complete, and rotate the user's credentials and any secrets that were reachable through the granted Full Disk Access. Block meetsync-app.com and the callback address at the proxy and firewall as well. Deleting the .pkg alone does nothing about the already-installed daemon or the TCC rows, which live outside the installer file. And a Gatekeeper rescan does not remove a LaunchDaemon or undo TCC.db edits; Gatekeeper evaluates apps at first launch and has no role in reverting persistence or privacy-database changes a root script already made.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Critical Falcon detection on a product manager's MacBook",
    threat_actor: "macOS intrusion operator distributing a trojanized installer package (fake productivity/meeting app)",
    attack_kind: "macos_tcc_bypass",
    briefing:
      "Falcon raised a Critical detection on MB-PM-07, a product manager's MacBook, a minute after a newly downloaded installer package was run. Work out what the installer did, which protected data it reached and whether it persists.",
    narrative: `MB-PM-07 is a MacBook belonging to Jelani Okafor, a product manager at Northwind Collab. Looking for a lightweight meeting tool, he found meetsync-app.com, a newly registered site, downloaded MeetSync-Installer.pkg through the web proxy, and followed the page's instructions to install it from Terminal: sudo installer -pkg ... -target / -allowUntrusted. The day before, the same Mac had cleanly installed Zoom, and that install is the control case: downloaded from zoom.us, a notarized Developer ID Installer signature that Gatekeeper accepted, Installer.app, and a postinstall that touched only /Applications. The MeetSync package behaved nothing like it.

The command-line installer does not run Gatekeeper, and -allowUntrusted tells it to continue past a signature the system does not trust. The installer's own log line records why that flag mattered: the package's Developer ID Installer certificate was REVOKED. Package install scripts run as root (Zoom's did too), and this one used that: installd laid the payload down, then package_script_service ran the postinstall /bin/sh from the install sandbox as root. Defender for Endpoint, also on the Mac, independently logged the same root shell.

The root script then did two things that matter. First it ran /usr/bin/sqlite3 against the user's TCC privacy database at ~/Library/Application Support/com.apple.TCC/TCC.db, inserting allow-rows for kTCCServiceSystemPolicyAllFiles (Full Disk Access) and kTCCServiceScreenCapture (Screen Recording) keyed to com.meetsync.app, so the app was treated as approved for those protected permissions without Jelani ever seeing a consent prompt. On a fully patched Mac a root process without Full Disk Access should not be able to write that database; here it succeeded, which is itself a finding for the Mac fleet owners (a TCC bypass in the installer path or an over-broad privacy profile). Second, it wrote /Library/LaunchDaemons/com.meetsync.helper.plist, pointing at an ad-hoc-signed root helper, and ran launchctl load -w on it: a LaunchDaemon in that directory is started by launchd at every boot, as root, before any user logs in.

launchd started the helper, meetsyncd, which resolved api.meetsync-app.com, connected out over TLS and, using the Full Disk Access it had just been granted, read files under ~/Documents and ~/Desktop, including Q3-Roadmap.pdf. Falcon raised the Critical detection a moment later. The exercise is to reconstruct that chain from the endpoint, proxy and system logs and to scope containment for a case where root code ran, the privacy database was altered, and persistence will outlive a reboot.`,
    learning_objectives: [
      "Tell a benign macOS .pkg install from a malicious one using download origin, the system's signature assessment (notarized Developer ID accepted vs a revoked certificate), the install route (-allowUntrusted from Terminal) and what the install scripts touch, not the fact that an installer ran as root",
      "Recognise a package preinstall/postinstall running /bin/sh as root under package_script_service as install-script execution with inherited root privilege (T1059.004)",
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
