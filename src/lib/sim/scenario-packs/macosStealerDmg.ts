/**
 * Scenario pack: "macOS Stealer — a 'Cracked' App DMG Harvests Keychain, Cookies and Wallets"
 *
 * INTERMEDIATE tier. Closes the platform's macOS blind spot. A designer on a
 * corporate MacBook downloads a pirated copy of a paid design tool as a disk
 * image (DMG). Inside is an Atomic/AMOS-family infostealer. The user mounts the
 * image and runs the bundled app; because it is only ad-hoc signed (no Developer
 * ID, not notarized) it would normally be stopped by Gatekeeper, so the malware
 * leans on the user to run it anyway. On first run it spawns osascript to present
 * a dialog impersonating macOS and captures the login password in cleartext,
 * then uses `security` to read the login Keychain, reads the Chrome/Safari cookie
 * and saved-password stores and local crypto-wallet files, and uploads a single
 * zip archive to attacker infrastructure over the web proxy.
 *
 * There are NO Windows concepts here. Privilege and trust are expressed the macOS
 * way: Developer ID code signing vs ad-hoc signing, notarization, Gatekeeper
 * assessment, the com.apple.quarantine extended attribute, /Volumes mount points,
 * osascript/AppleScript, /usr/bin/security and login.keychain-db, and the
 * ~/Library/Application Support/... paths where browsers and wallets keep secrets.
 *
 * The teaching spine is telling a benign "DMG install" from a malicious one when
 * both have the same SHAPE — mount an image, run an app. The BENIGN CONTROL (evt
 * 0) is a legitimately-signed, notarized install (Rectangle.app): valid Developer
 * ID signature, Gatekeeper assessment passed, and it never touches osascript,
 * the Keychain, or the network. The malicious install carries an ad-hoc signature
 * and, within seconds, phishes the password and reads every credential store on
 * the box. The difference is in the signature and the behaviour, not the fact
 * that "an app was installed from a disk image".
 *
 * SOURCES (registry vendor keys): crowdstrike-falcon (Falcon supports macOS —
 * process tree, osascript, file access, code-signature state, the detection),
 * zscaler-internet-access (the DMG download session and the exfil upload),
 * microsoft-defender-endpoint (one corroborating cross-platform process event).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildMacosStealerDmgScenario(
  scenarioId = "macos-stealer-dmg-2026",
): ScenarioBundle {
  const B = new Date("2026-08-24T20:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const INCIDENT = "inc:msd:1";

  // The victim endpoint and its user.
  const host = {
    name: "MB-CR-14",
    fqdn: "MB-CR-14.meridianstudios.com",
    ip: "10.50.4.61",
    id: "d7c1a4f0e2b94a3c8f5e61a02c9b7d34",
    os: "macOS",
    osVersion: "14.6.1",
  };
  const user = {
    sam: "a.fontaine",
    email: "a.fontaine@meridianstudios.com",
    domain: "meridianstudios",
    full: "Adrien Fontaine",
    title: "Senior Graphic Designer",
  };

  // Attacker infrastructure.
  const dlDomain = "pixelforge-crack.top";                                  // where the DMG came from
  const dlUrl = "https://pixelforge-crack.top/dl/PixelForge_Pro_v7.dmg";    // the download URL
  const dlServerIp = "185.234.72.19";                                       // the download host (not itself an IOC of interest)
  const exfilDomain = "gate-collect.top";                                   // the upload endpoint
  const exfilIp = "45.147.230.88";                                          // the upload host

  // The stealer's Mach-O / DMG payload hash — appears on the download, the
  // execution, and the credential-access reads.
  const stealerHash = makeSha256("macos_stealer_dmg_pixelforge_amos_machO_2026");

  // Falcon sensor identifiers on the MacBook.
  const sensorId = "8b2e5c17a9d0426f81c3e7449af61b0d";
  const aid = "3f9a7c2140b64e8db5c19a03f77e2c6a";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a legitimately-signed, notarized DMG install.
    //    Same shape as the attack (mount an image, run an app), opposite
    //    verdict: valid Developer ID, Gatekeeper passed, no osascript, no
    //    Keychain, no network. This is what a clean DMG install looks like.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_00_benign_notarized_install",
      ts: "2026-08-23T16:20:00Z",
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      user_email: user.email,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "The control case for the whole scenario. Rectangle.app was installed from a downloaded disk image the day before — the same 'mount a DMG, run an app' shape as the intrusion. What makes it benign is written in the signature and the behaviour: the binary carries a valid Developer ID Application signature, it is notarized, and the Gatekeeper assessment passed, so macOS let it run without the user having to override anything. It also does nothing a stealer does — no osascript password prompt, no read of login.keychain-db, no browser cookie access, no outbound upload. An analyst who alerts on 'an app ran from a disk image' alone will flag this and be wrong; the discriminator is Developer ID + notarization + quiet behaviour, not the install shape.",
      description:
        "Rectangle.app launched from /Applications after a disk-image install. Falcon recorded a valid Developer ID Application signature and a passed Gatekeeper assessment; the com.apple.quarantine attribute was cleared because the app is notarized. No child processes, credential-store reads, or network activity followed.",
      process: {
        name: "Rectangle",
        pid: 2871,
        path: "/Applications/Rectangle.app/Contents/MacOS/Rectangle",
        parent_name: "launchd",
        parent_pid: 1,
        cmdline: "/Applications/Rectangle.app/Contents/MacOS/Rectangle",
        user: user.sam,
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "Rectangle",
        "crowdstrike.FilePath": "/Applications/Rectangle.app/Contents/MacOS/",
        "crowdstrike.ParentProcessName": "launchd",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "Rectangle",
        "process.executable": "/Applications/Rectangle.app/Contents/MacOS/Rectangle",
        "process.code_signature.status": "valid",
        "process.code_signature.subject_name": "Developer ID Application: Knollsoft LLC (XSYZ3E2CY6)",
        "file.name": "Rectangle",
        "file.path": "/Applications/Rectangle.app",
        "file.signature.status": "valid",
        "file.signature.subject_name": "Developer ID Application: Knollsoft LLC (XSYZ3E2CY6)",
        "file.signature.trusted": "true",
        "host.name": host.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": user.sam,
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. DELIVERY — the DMG download session, seen at the web proxy.
    //    Zscaler logs the GET that pulled PixelForge_Pro_v7.dmg from the
    //    pirate-app domain, and hashes the payload (T1204.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_01_dmg_download",
      ts: T(0),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: host.name,
      user_email: user.email,
      src_ip: host.ip,
      dst_ip: dlServerIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "Zscaler logged a.fontaine downloading PixelForge_Pro_v7.dmg (30 MB) from pixelforge-crack.top over HTTPS. The site is categorised Malware and the payload hash matches what later runs on the host.",
      raw: {
        "url.full": dlUrl,
        "url.domain": dlDomain,
        "url.path": "/dl/PixelForge_Pro_v7.dmg",
        "url.category": "Malware",
        "http.request.method": "GET",
        "http.response.status_code": "200",
        "http.user_agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "destination.domain": dlDomain,
        "destination.ip": dlServerIp,
        "destination.port": "443",
        "source.ip": host.ip,
        "source.user.name": user.sam,
        "user.name": user.sam,
        "network.bytes": "31457280",
        "network.protocol": "https",
        "network.transport": "tcp",
        "threat.file.hash.sha256": stealerHash,
        "threat.category": "Malware",
        "threat.name": "OSX/InfoStealer",
        "threat.technique.id": "T1204.002",
        "threat.technique.name": "User Execution: Malicious File",
        "threat.tactic.name": "Execution",
        "threat.tactic.id": "TA0002",
        "action": "allowed",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. EXECUTION — the DMG is mounted and the app runs from /Volumes.
    //    Ad-hoc signature (no Developer ID), the payload hash matches the
    //    download. The com.apple.quarantine attribute is present (T1204.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_02_dmg_mount_run",
      ts: T(3 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      user_email: user.email,
      severity: "high",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "The disk image mounted at /Volumes/PixelForge Pro and its app launched from that mount point. Falcon recorded the binary as ad-hoc signed (no Developer ID, not notarized) and still carrying the com.apple.quarantine attribute; its SHA256 matches the downloaded DMG payload.",
      process: {
        name: "PixelForge Pro",
        pid: 4102,
        path: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        parent_name: "launchd",
        parent_pid: 1,
        cmdline: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        user: user.sam,
        hash: { sha256: stealerHash },
      },
      file: {
        name: "PixelForge Pro.app",
        path: "/Volumes/PixelForge Pro/PixelForge Pro.app",
        sha256: stealerHash,
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "PixelForge Pro",
        "crowdstrike.FilePath": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/",
        "crowdstrike.CommandLine": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "crowdstrike.ParentProcessName": "launchd",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "PixelForge Pro",
        "process.executable": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "process.hash.sha256": stealerHash,
        "process.code_signature.status": "adhoc",
        "process.code_signature.subject_name": "-",
        "file.name": "PixelForge Pro.app",
        "file.path": "/Volumes/PixelForge Pro/PixelForge Pro.app",
        "file.hash.sha256": stealerHash,
        "file.signature.status": "unsigned",
        "file.signature.trusted": "false",
        "host.name": host.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": user.sam,
        "threat.technique.id": "T1204.002",
        "threat.technique.name": "User Execution: Malicious File",
        "threat.tactic.name": "Execution",
        "threat.tactic.id": "TA0002",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE FAKE PASSWORD PROMPT — osascript display dialog (AppleScript).
    //    The app spawns /usr/bin/osascript to impersonate macOS and capture
    //    the login password in cleartext (T1059.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_03_osascript_password_prompt",
      ts: T(3 * MIN + 8 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      user_email: user.email,
      severity: "high",
      mitre_technique: "T1059.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "The PixelForge Pro binary spawned /usr/bin/osascript running a `display dialog ... with hidden answer` AppleScript — a prompt styled to look like a macOS system request, asking the user to type their login password to 'finish installation'.",
      process: {
        name: "osascript",
        pid: 4118,
        path: "/usr/bin/osascript",
        parent_name: "PixelForge Pro",
        parent_pid: 4102,
        cmdline:
          "osascript -e display dialog \"PixelForge Pro needs your password to finish installation.\" default answer \"\" with hidden answer with icon caution buttons {\"OK\"} default button \"OK\"",
        user: user.sam,
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "osascript",
        "crowdstrike.FilePath": "/usr/bin/",
        "crowdstrike.CommandLine":
          "osascript -e display dialog \"PixelForge Pro needs your password to finish installation.\" default answer \"\" with hidden answer with icon caution buttons {\"OK\"} default button \"OK\"",
        "crowdstrike.ParentProcessName": "PixelForge Pro",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "osascript",
        "process.executable": "/usr/bin/osascript",
        "process.parent.name": "PixelForge Pro",
        "process.parent.pid": "4102",
        "process.code_signature.status": "valid",
        "process.code_signature.subject_name": "Software Signing",
        "host.name": host.name,
        "host.os.name": host.os,
        "user.name": user.sam,
        "threat.technique.id": "T1059.002",
        "threat.technique.name": "Command and Scripting Interpreter: AppleScript",
        "threat.tactic.name": "Execution",
        "threat.tactic.id": "TA0002",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. CORROBORATION — Microsoft Defender for Endpoint sees the same run.
    //    Cross-platform sensor also on the Mac; native Advanced Hunting
    //    DeviceProcessEvents schema confirms the osascript child (T1059.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_04_mde_osascript_corroboration",
      ts: T(3 * MIN + 9 * SEC),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.name,
      user_email: user.email,
      severity: "high",
      mitre_technique: "T1059.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "Defender for Endpoint, also deployed on this Mac, independently recorded the same osascript child of PixelForge Pro. Its DeviceProcessEvents row ties the osascript process to the same initiating binary and payload SHA256.",
      raw: {
        "Timestamp": T(3 * MIN + 9 * SEC),
        "DeviceName": host.name,
        "DeviceId": host.id,
        "ActionType": "ProcessCreated",
        "FileName": "osascript",
        "FolderPath": "/usr/bin/osascript",
        "ProcessCommandLine":
          "osascript -e display dialog \"PixelForge Pro needs your password to finish installation.\" default answer \"\" with hidden answer",
        "ProcessId": "4118",
        "InitiatingProcessFileName": "PixelForge Pro",
        "InitiatingProcessFolderPath":
          "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "InitiatingProcessCommandLine":
          "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "InitiatingProcessId": "4102",
        "InitiatingProcessSHA256": stealerHash,
        "AccountName": user.sam,
        "AccountDomain": user.domain,
        "ReportId": "70418822",
        "threat.technique.id": "T1059.002",
        "threat.technique.name": "Command and Scripting Interpreter: AppleScript",
        "threat.tactic.name": "Execution",
        "threat.tactic.id": "TA0002",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. KEYCHAIN THEFT — /usr/bin/security reads login.keychain-db.
    //    With the captured password the stealer unlocks and reads the login
    //    Keychain and pulls the Chrome Safe Storage key (T1555.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_05_keychain_access",
      ts: T(3 * MIN + 40 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_access",
      hostname: host.name,
      user_email: user.email,
      severity: "critical",
      mitre_technique: "T1555.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "The payload invoked /usr/bin/security to read ~/Library/Keychains/login.keychain-db and extract the Chrome Safe Storage key. Falcon recorded the security process, spawned by PixelForge Pro, opening the login Keychain file.",
      process: {
        name: "security",
        pid: 4131,
        path: "/usr/bin/security",
        parent_name: "PixelForge Pro",
        parent_pid: 4102,
        cmdline: "security 2>&1 >/dev/null find-generic-password -wa Chrome",
        user: user.sam,
      },
      file: {
        name: "login.keychain-db",
        path: "/Users/a.fontaine/Library/Keychains/login.keychain-db",
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "login.keychain-db",
        "crowdstrike.FilePath": "/Users/a.fontaine/Library/Keychains/",
        "crowdstrike.CommandLine": "security 2>&1 >/dev/null find-generic-password -wa Chrome",
        "crowdstrike.ParentProcessName": "PixelForge Pro",
        "crowdstrike.OperationType": "FileOpenInfo",
        "process.name": "security",
        "process.executable": "/usr/bin/security",
        "process.parent.name": "PixelForge Pro",
        "process.parent.pid": "4102",
        "file.name": "login.keychain-db",
        "file.path": "/Users/a.fontaine/Library/Keychains/login.keychain-db",
        "host.name": host.name,
        "host.os.name": host.os,
        "user.name": user.sam,
        "threat.technique.id": "T1555.001",
        "threat.technique.name": "Credentials from Password Stores: Keychain",
        "threat.tactic.name": "Credential Access",
        "threat.tactic.id": "TA0006",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. BROWSER SESSION + PASSWORD THEFT — Chrome Cookies and Login Data.
    //    The payload reads the browser cookie store and saved-login database
    //    (T1539 — steal web session cookies).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_06_browser_cookie_theft",
      ts: T(3 * MIN + 55 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_access",
      hostname: host.name,
      user_email: user.email,
      severity: "critical",
      mitre_technique: "T1539",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "The payload read ~/Library/Application Support/Google/Chrome/Default/Cookies and the matching Login Data database, and the equivalent Safari stores. These hold live web session cookies and saved passwords.",
      process: {
        name: "PixelForge Pro",
        pid: 4102,
        path: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        parent_name: "launchd",
        parent_pid: 1,
        cmdline: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        user: user.sam,
        hash: { sha256: stealerHash },
      },
      file: {
        name: "Cookies",
        path: "/Users/a.fontaine/Library/Application Support/Google/Chrome/Default/Cookies",
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "Cookies",
        "crowdstrike.FilePath": "/Users/a.fontaine/Library/Application Support/Google/Chrome/Default/",
        "crowdstrike.OperationType": "FileOpenInfo",
        "process.name": "PixelForge Pro",
        "process.executable": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "process.hash.sha256": stealerHash,
        "file.name": "Cookies",
        "file.path": "/Users/a.fontaine/Library/Application Support/Google/Chrome/Default/Cookies",
        "host.name": host.name,
        "host.os.name": host.os,
        "user.name": user.sam,
        "threat.technique.id": "T1539",
        "threat.technique.name": "Steal Web Session Cookie",
        "threat.tactic.name": "Credential Access",
        "threat.tactic.id": "TA0006",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. WALLET THEFT — local crypto-wallet files read (T1552.001).
    //    Exodus / Electrum wallet files under ~/Library/Application Support.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_07_wallet_file_theft",
      ts: T(4 * MIN + 10 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_access",
      hostname: host.name,
      user_email: user.email,
      severity: "critical",
      mitre_technique: "T1552.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "The payload read local cryptocurrency-wallet files, including ~/Library/Application Support/Exodus/exodus.wallet and Electrum wallet data — files that store wallet seeds and keys on disk.",
      process: {
        name: "PixelForge Pro",
        pid: 4102,
        path: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        parent_name: "launchd",
        parent_pid: 1,
        cmdline: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        user: user.sam,
        hash: { sha256: stealerHash },
      },
      file: {
        name: "exodus.wallet",
        path: "/Users/a.fontaine/Library/Application Support/Exodus/exodus.wallet",
      },
      raw: {
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "exodus.wallet",
        "crowdstrike.FilePath": "/Users/a.fontaine/Library/Application Support/Exodus/",
        "crowdstrike.OperationType": "FileOpenInfo",
        "process.name": "PixelForge Pro",
        "process.executable": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        "process.hash.sha256": stealerHash,
        "file.name": "exodus.wallet",
        "file.path": "/Users/a.fontaine/Library/Application Support/Exodus/exodus.wallet",
        "host.name": host.name,
        "host.os.name": host.os,
        "user.name": user.sam,
        "threat.technique.id": "T1552.001",
        "threat.technique.name": "Unsecured Credentials: Credentials In Files",
        "threat.tactic.name": "Credential Access",
        "threat.tactic.id": "TA0006",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. EXFILTRATION — the collected data leaves the host as one zip upload.
    //    Zscaler logs an outbound POST to the attacker endpoint (T1567.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_08_exfil_upload",
      ts: T(4 * MIN + 30 * SEC),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: host.name,
      user_email: user.email,
      src_ip: host.ip,
      dst_ip: exfilIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      description:
        "Zscaler logged an outbound POST from MB-CR-14 uploading an ~8 MB archive to gate-collect.top (45.147.230.88), sent with a curl user-agent moments after the credential-store reads.",
      raw: {
        "url.full": "https://gate-collect.top/api/upload",
        "url.domain": exfilDomain,
        "url.path": "/api/upload",
        "url.category": "Malware",
        "http.request.method": "POST",
        "http.response.status_code": "200",
        "http.user_agent": "curl/8.4.0",
        "destination.domain": exfilDomain,
        "destination.ip": exfilIp,
        "destination.port": "443",
        "source.ip": host.ip,
        "source.user.name": user.sam,
        "user.name": user.sam,
        "network.bytes": "8734096",
        "network.protocol": "https",
        "network.transport": "tcp",
        "threat.technique.id": "T1567.002",
        "threat.technique.name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "threat.tactic.name": "Exfiltration",
        "threat.tactic.id": "TA0010",
        "action": "allowed",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. THE DETECTION — Falcon raises the alert-grade detection tying the
    //    osascript prompt, the Keychain read and the exfil into one case.
    //    is_detection + edr_scope "hybrid" (host artifacts + a proxy facet).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "msd_09_edr_detection",
      ts: T(5 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.name,
      user_email: user.email,
      severity: "critical",
      mitre_technique: "T1555.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      is_detection: true,   // the Falcon detection that opened the incident
      edr_scope: "hybrid",  // host artifacts (osascript, Keychain, wallet reads) + the proxy-observed upload — pivot into EDR for MB-CR-14
      description:
        "Falcon raised a Critical detection on MB-CR-14: an ad-hoc-signed app from a mounted disk image spawned osascript to prompt for the password, then read the login Keychain, browser cookie stores and wallet files and uploaded an archive — a macOS credential-stealer pattern.",
      process: {
        name: "PixelForge Pro",
        pid: 4102,
        path: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        parent_name: "launchd",
        parent_pid: 1,
        cmdline: "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/PixelForge Pro",
        user: user.sam,
        hash: { sha256: stealerHash },
      },
      raw: {
        "crowdstrike.DetectName": "MacOS_Infostealer_OsascriptCredentialAccess",
        "crowdstrike.Tactic": "Credential Access",
        "crowdstrike.Technique": "Keychain",
        "crowdstrike.Objective": "Falcon Detection Method",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.IncidentType": "MacOS Credential Theft",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": aid,
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": user.sam,
        "crowdstrike.FileName": "PixelForge Pro",
        "crowdstrike.FilePath": "/Volumes/PixelForge Pro/PixelForge Pro.app/Contents/MacOS/",
        "process.hash.sha256": stealerHash,
        "host.name": host.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": user.sam,
        "threat.technique.id": "T1555.001",
        "threat.technique.name": "Credentials from Password Stores: Keychain",
        "threat.tactic.name": "Credential Access",
        "threat.tactic.id": "TA0006",
        "event.outcome": "success",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.name, // MB-CR-14 — the infected MacBook
      first_seen: T(0),
      last_seen: T(5 * MIN),
      // "unknown", not "malicious": this is the organisation's own endpoint —
      // the victim, not adversary infrastructure.
      reputation: "unknown",
      tags: ["macos", "endpoint", "infected"],
    },
    {
      type: "user",
      value: user.sam, // a.fontaine — the user whose credentials were read
      first_seen: T(0),
      last_seen: T(5 * MIN),
      reputation: "suspicious",
      tags: ["macos-user", "credential-owner", "affected"],
    },
    {
      type: "sha256",
      value: stealerHash, // the DMG / Mach-O payload
      first_seen: T(0),
      last_seen: T(5 * MIN),
      reputation: "malicious",
      tags: ["macos", "disk-image-payload", "adhoc-signed"],
    },
    {
      type: "url",
      value: dlUrl, // the DMG download URL
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["download-source", "pirated-app"],
    },
    {
      type: "domain",
      value: dlDomain, // pixelforge-crack.top — where the DMG came from
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["download-source", "warez"],
    },
    {
      type: "domain",
      value: exfilDomain, // gate-collect.top — the upload endpoint
      first_seen: T(4 * MIN + 30 * SEC),
      last_seen: T(4 * MIN + 30 * SEC),
      reputation: "malicious",
      tags: ["upload-destination", "external"],
    },
    {
      type: "ip",
      value: exfilIp, // 45.147.230.88 — the upload host
      first_seen: T(4 * MIN + 30 * SEC),
      last_seen: T(4 * MIN + 30 * SEC),
      reputation: "malicious",
      tags: ["upload-destination", "external"],
    },
  ];

  const killchain = [
    { ts: "2026-08-23T16:20:00Z", phase: "Baseline", action: `Notarized ${"Rectangle.app"} installs from a signed DMG — valid Developer ID, Gatekeeper passed: the clean-install control case` },
    { ts: T(0), phase: "Delivery", action: `PixelForge_Pro_v7.dmg downloaded from ${dlDomain} (categorised Malware) (T1204.002)` },
    { ts: T(3 * MIN), phase: "Execution", action: "DMG mounted at /Volumes/PixelForge Pro; ad-hoc-signed app runs with com.apple.quarantine set (T1204.002)" },
    { ts: T(3 * MIN + 8 * SEC), phase: "Execution", action: "osascript display dialog impersonates macOS and captures the login password (T1059.002)" },
    { ts: T(3 * MIN + 40 * SEC), phase: "Credential Access", action: "/usr/bin/security reads login.keychain-db and the Chrome Safe Storage key (T1555.001)" },
    { ts: T(3 * MIN + 55 * SEC), phase: "Credential Access", action: "Chrome/Safari Cookies and Login Data read — session cookies and saved passwords (T1539)" },
    { ts: T(4 * MIN + 10 * SEC), phase: "Credential Access", action: "Local crypto-wallet files (exodus.wallet, Electrum) read from ~/Library/Application Support (T1552.001)" },
    { ts: T(4 * MIN + 30 * SEC), phase: "Exfiltration", action: `~8 MB archive POSTed to ${exfilDomain} (${exfilIp}) (T1567.002)` },
    { ts: T(5 * MIN), phase: "Detection", action: "Falcon raises the Critical macOS credential-theft detection tying the chain together" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "msd_q1",
      xp: 55,
      kind: "single",
      prompt:
        "Two disk-image app installs appear on MB-CR-14: the Rectangle install (msd_00) and the PixelForge Pro install (msd_02). Which observation separates the benign install from the malicious one?",
      hint: "Compare the code-signature fields on each, and look at what each app does in the seconds after it launches.",
      options: [
        { value: "sig_behaviour", label: "Rectangle carries a valid Developer ID signature and cleared Gatekeeper, while PixelForge Pro is ad-hoc signed and immediately spawns osascript to prompt for the password" },
        { value: "volumes_path", label: "Rectangle ran from /Applications while PixelForge Pro ran from /Volumes, and any app that executes from a mounted image is malicious by definition" },
        { value: "quarantine_flag", label: "PixelForge Pro carried a com.apple.quarantine attribute and Rectangle did not, and the presence of that flag alone proves the download was hostile" },
        { value: "binary_size", label: "Rectangle is a much smaller binary than PixelForge Pro, and any macOS app package larger than 30 MB is a repackaged cracked build" },
      ],
      answer: "sig_behaviour",
      explanation:
        "The discriminator is the signature plus the behaviour, not the install shape. Rectangle has a valid Developer ID Application signature and is notarized, so Gatekeeper let it run and it then did nothing unusual. PixelForge Pro is only ad-hoc signed (subject '-', file.signature.status unsigned) and within seconds spawns osascript to phish the password and starts reading credential stores. Running from /Volumes is normal for the first launch right after mounting a DMG, so it is not by itself a verdict. Both downloaded apps would carry com.apple.quarantine — that is set on anything downloaded, benign or not — so its presence proves nothing. And binary size is irrelevant. The real tells are Developer ID + notarization on one side and ad-hoc signing + credential-theft behaviour on the other.",
    },
    {
      id: "msd_q2",
      xp: 60,
      kind: "single",
      prompt:
        "In msd_03 the PixelForge Pro binary spawns /usr/bin/osascript running `display dialog ... with hidden answer`. What is this step doing?",
      hint: "osascript runs AppleScript; think about what a dialog with a hidden-answer field asks the user to type, and who normally asks for it.",
      options: [
        { value: "phish_password", label: "Running AppleScript to show a prompt impersonating macOS and capture the user's login password in cleartext" },
        { value: "license_check", label: "Invoking a signed Apple utility to validate the application's license key against the vendor's activation server" },
        { value: "launchd_task", label: "Using AppleScript to register a background update job with launchd, which is standard behaviour for app installers" },
        { value: "system_update", label: "Rendering the built-in macOS software-update prompt, which osascript displays on the operating system's behalf" },
      ],
      answer: "phish_password",
      explanation:
        "osascript executes AppleScript, and `display dialog ... with hidden answer` renders a password box. A stealer uses it to throw up a prompt dressed as a macOS system request so the user types their login password into the malware — the classic macOS way to defeat the fact that a normal app cannot read that password. It is not a license check (no vendor server is contacted, and osascript is not a licensing tool), it is not registering a launchd job (that would call launchctl, not display a dialog), and it is not the real software-update prompt (macOS updates are driven by softwareupdate/SoftwareUpdate, never by an app's own osascript). The captured password is what next unlocks the login Keychain in msd_05.",
    },
    {
      id: "msd_q3",
      xp: 65,
      kind: "single",
      prompt:
        "msd_05 shows /usr/bin/security reading ~/Library/Keychains/login.keychain-db, and msd_06 and msd_07 read the Chrome Cookies file and a crypto-wallet file. Taken together, what is the actor collecting?",
      hint: "Look at what each of those three files stores, and what a class of macOS malware is built to take.",
      options: [
        { value: "credential_loot", label: "Stored secrets — the login Keychain, browser session cookies and saved logins, and wallet files — the loot of a macOS infostealer" },
        { value: "crash_logs", label: "Diagnostic and crash logs the installer bundles so it can send a support report back to the software developer" },
        { value: "import_settings", label: "Configuration files the app reads once at first launch to import the user's existing browser bookmarks and themes" },
        { value: "integrity_cache", label: "System integrity data that macOS caches and that any notarized application is entitled to read when it starts up" },
      ],
      answer: "credential_loot",
      explanation:
        "The login Keychain holds saved passwords and tokens, the Chrome Cookies file holds live web session cookies, the Login Data database holds saved browser passwords, and wallet files hold cryptocurrency seeds and keys. Reading all of them in sequence is exactly the collection stage of a macOS infostealer. They are not crash logs (login.keychain-db and exodus.wallet are secret stores, not diagnostics), not a bookmark import (that would touch Bookmarks, not Cookies, the Keychain and wallets), and not any 'integrity cache' a notarized app is entitled to — reading another process's Keychain and cookie store is precisely what apps are NOT allowed to do without the user's password, which is why the osascript prompt came first.",
    },
    {
      id: "msd_q4",
      xp: 55,
      kind: "single",
      prompt:
        "You need to identify the point where data actually left MB-CR-14, and where it went. Which event shows it?",
      hint: "Separate an inbound download and a local file read from an outbound send; check the HTTP method and direction.",
      options: [
        { value: "exfil_post", label: "msd_08 — a POST from the host uploads an ~8 MB archive to gate-collect.top (45.147.230.88) over the web proxy" },
        { value: "dmg_get", label: "msd_01 — the GET that pulled PixelForge_Pro_v7.dmg from pixelforge-crack.top down onto the host" },
        { value: "keychain_read", label: "msd_05 — the security command reading the login keychain from the user's own home directory" },
        { value: "detect_row", label: "msd_09 — the Falcon detection record, which is where the collected archive is stored after the upload" },
      ],
      answer: "exfil_post",
      explanation:
        "msd_08 is an outbound POST uploading an ~8 MB archive to gate-collect.top (45.147.230.88) — data leaving the host, and the two exfil IOCs (the domain and the IP) come from it. msd_01 is the opposite direction: a GET that pulled the DMG onto the host. msd_05 is a local read that never touches the network. And msd_09 is a Falcon detection record — an alert about the activity, not a place data is sent or stored. The upload is the event to cite when you scope what was lost.",
    },
    {
      id: "msd_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "The login Keychain, the browser cookie and saved-password stores, and wallet files were all read and then uploaded off MB-CR-14. Select the TWO actions that match the evidence.",
      hint: "Think about what a stolen session cookie or Keychain entry lets an attacker do even after the Mac is cleaned, and what the two malicious domains and the IP are for.",
      options: [
        { value: "reset_revoke", label: "Treat every credential on the host as compromised: force password resets and revoke active web sessions and tokens across the user's services" },
        { value: "isolate_block", label: "Isolate MB-CR-14, remove the PixelForge Pro app and its mounted image, and block the download and upload domains and the exfil IP" },
        { value: "rotate_one", label: "Only rotate the single Chrome password, since session cookies expire on their own and the Keychain stays encrypted at rest regardless" },
        { value: "gatekeeper_rescan", label: "Skip re-imaging and just run a Gatekeeper rescan of /Applications, which will quarantine the app and close out the incident on its own" },
      ],
      answer: ["reset_revoke", "isolate_block"],
      explanation:
        "Because the Keychain, cookies and saved passwords were exfiltrated, the credentials themselves are compromised — a stolen session cookie lets an attacker resume a logged-in session without the password, so containment must reset passwords AND revoke live sessions/tokens across the user's services, not just remove the malware. In parallel, isolate the host, remove the app and its mounted image, and block the download domain, the upload domain and the exfil IP so the same infrastructure cannot be reached again. Rotating only the Chrome password ignores everything else that was taken and wrongly assumes cookies are harmless. And a Gatekeeper rescan does nothing here — the app ran from /Volumes, not /Applications, and the credentials are already gone, so a rescan neither recovers them nor addresses the stolen sessions.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "macOS Stealer — a 'Cracked' App DMG Harvests Keychain, Cookies and Wallets",
    threat_actor: "Commodity macOS infostealer operator (Atomic/AMOS-family), distributing via pirated-app disk images",
    attack_kind: "macos_infostealer",
    briefing:
      "Falcon raised a High alert on MB-CR-14, a designer's MacBook: shortly after the user installed an app from a downloaded disk image, a system tool prompted for the macOS password and the machine opened an outbound upload to an unfamiliar host. The user says the app was a free copy of a paid design tool. Work out what ran, what it touched, and what left the machine.",
    narrative: `MB-CR-14 is a MacBook belonging to Adrien Fontaine, a senior designer at Meridian Studios. Wanting a paid design tool for free, he searched for a "cracked" copy and downloaded PixelForge_Pro_v7.dmg from pixelforge-crack.top — a site the web proxy categorises as Malware. The day before, the same Mac had cleanly installed Rectangle.app from a notarized, Developer-ID-signed disk image, and that install is the control case: valid signature, Gatekeeper passed, no further activity. The cracked DMG behaved nothing like it.

When Adrien mounted the image and opened the app, Falcon recorded a binary running from /Volumes/PixelForge Pro that was only ad-hoc signed — no Developer ID, not notarized — and still carrying the com.apple.quarantine attribute. A legitimate app of that provenance would be stopped by Gatekeeper; a stealer's whole opening move is to get the user past that. Within seconds the app spawned /usr/bin/osascript running a "display dialog ... with hidden answer" AppleScript: a prompt dressed as a macOS system request, asking for the login password to "finish installation". Adrien typed it in.

With the password captured, the payload used /usr/bin/security to read ~/Library/Keychains/login.keychain-db and pull the Chrome Safe Storage key, then read the Chrome and Safari Cookies and Login Data stores — live web session cookies and saved passwords — and local cryptocurrency-wallet files including exodus.wallet under ~/Library/Application Support. Defender for Endpoint, also on the Mac, independently logged the same osascript child, tying it to the same payload hash. The collected material was zipped and, at 20:09, POSTed as a single ~8 MB archive to gate-collect.top (45.147.230.88) over the proxy. Falcon raised the Critical detection a moment later. The exercise is to reconstruct that chain from the logs and to scope containment for a case where the credentials themselves — not just the Mac — are what was lost.`,
    learning_objectives: [
      "Tell a benign macOS DMG install from a malicious one using code-signing state (Developer ID + notarization + Gatekeeper vs ad-hoc/unsigned) and post-launch behaviour, not the fact that an app ran from a disk image",
      "Recognise an osascript `display dialog ... with hidden answer` spawned by an app as an AppleScript prompt phishing the login password (T1059.002)",
      "Read /usr/bin/security against login.keychain-db, and reads of the browser Cookies/Login Data stores and wallet files, as macOS credential theft (T1555.001 / T1539 / T1552.001)",
      "Trace macOS exfiltration at the web proxy — an outbound upload to attacker infrastructure — and extract the download and upload IOCs (domains, IP, payload hash, URL)",
      "Scope containment for a credential-stealer: because the Keychain, cookies and saved passwords were taken, reset passwords and revoke live sessions/tokens, not just clean the host",
    ],
    alerts: [], // alerts are attached by the catalogue wiring (withAlerts)
    events,
    iocs,
    killchain,
    questions,
  };
}
