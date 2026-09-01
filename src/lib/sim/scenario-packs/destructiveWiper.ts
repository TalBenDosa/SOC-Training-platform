/**
 * Scenario pack: "Destructive Wiper — an Endpoint Bricked, and No Way to Pay for It Back"
 *
 * ADVANCED tier. A destructive WIPER, not ransomware. On VNT-WKS-27 a single
 * SYSTEM process (cl64.exe) loads a validly-signed third-party storage driver to
 * gain kernel-mode raw access to the physical disk, deletes the Volume Shadow
 * Copies, turns off Windows boot recovery, clears the Security event log, and
 * then overwrites the Master Boot Record / partition structures and user files
 * with junk. The machine goes unbootable within seconds.
 *
 * The teaching spine is that this looks ransomware-adjacent — mass file writes,
 * shadow-copy deletion, boot tampering — but there is NO recovery or extortion
 * path: no encryption to a key, no ransom note that a key could ever unlock, no
 * C2 fetching a decryptor. The sectors and files are simply destroyed. The
 * objective is denial/destruction, not a payout, and that changes the entire
 * response: you cannot decrypt or negotiate your way out, only rebuild.
 *
 * The BENIGN CONTROL (event 0) is a legitimately change-ticketed secure-wipe: IT
 * running signed Sysinternals sdelete against a machine being decommissioned in a
 * maintenance window — the same "a disk is being overwritten" shape, opposite
 * verdict. The discriminator is who ran it, under what authorisation, and whether
 * it also destroyed backups and cleared logs — not the fact that a disk was wiped.
 *
 * SOURCES (registry vendor keys): crowdstrike-falcon (the destructive process
 * tree, the raw-disk write, and the detection), sysmon (process creation, the
 * signed-but-abused driver load — Event 6 — and a file overwrite — Event 11),
 * microsoft-defender-endpoint (one corroborating DeviceProcessEvents record).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildDestructiveWiperScenario(
  scenarioId = "destructive-wiper-2026",
): ScenarioBundle {
  const B = new Date("2026-08-29T03:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const INCIDENT = "inc:dw:1";

  // The bricked endpoint.
  const host = {
    name: "VNT-WKS-27",
    fqdn: "VNT-WKS-27.vantageindustrial.com",
    ip: "10.60.8.27",
    id: "c4a9f10e2b7d43c1985e60a1f2c8b7d3",
    os: "Windows",
    osVersion: "10.0.19045",
  };

  // The host wiped legitimately the day before — the benign control.
  const decommHost = { name: "VNT-WKS-19", fqdn: "VNT-WKS-19.vantageindustrial.com" };

  // The compromised privileged account used to push and launch the payload as a
  // remote service across the fleet. The wiper itself runs as SYSTEM.
  const deployAdmin = { sam: "a.novak", email: "a.novak@vantageindustrial.com", full: "Adam Novak" };

  // The wiper binary, and the signed third-party driver it abuses for raw disk
  // I/O. Both appear literally in the events below.
  const wiperHash = makeSha256("destructive_wiper_2026_cl64_payload_binary");
  const driverHash = makeSha256("destructive_wiper_2026_epmntdrv_signed_partition_driver");

  const sensorId = "a1f7c3e290b64d58b2c419e037f8a6c1";
  const aid = "6b2d9c4715a04e83b9f1c60a28e7d54f";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — an authorised, change-ticketed secure wipe.
    //    IT running signed Sysinternals sdelete against a decommissioned host
    //    inside a maintenance window. Same "the disk is being overwritten"
    //    shape as the attack, opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_00_benign_secure_wipe",
      ts: "2026-08-28T21:30:00Z",
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: decommHost.name,
      user_email: "it.deploy@vantageindustrial.com",
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "The control case for the whole scenario. Under change ticket CHG-20418, the IT decommissioning team ran signed Sysinternals sdelete to securely erase VNT-WKS-19 before it left the estate — the same 'a disk is being overwritten' shape as the intrusion. What makes it benign is written in the authorisation and the surrounding behaviour: a signed Microsoft-published tool, run by a named IT account, at high integrity, inside a maintenance window, on a host slated for disposal. It does NOT delete this host's shadow copies to block recovery, does NOT disable boot recovery, and does NOT clear the Security log. An analyst who alerts on 'a disk got wiped' alone will flag this and be wrong; the discriminator is who ran it, under what ticket, and whether backups and logs were destroyed alongside — not the wipe itself.",
      description:
        "sdelete64.exe (signed Sysinternals, Microsoft-published) ran on VNT-WKS-19 under the it.deploy account at high integrity, overwriting the drive of a host being decommissioned under change ticket CHG-20418. No shadow-copy deletion, boot-config change, or log clearing followed.",
      process: {
        name: "sdelete64.exe",
        pid: 5120,
        path: "C:\\Tools\\Sysinternals\\sdelete64.exe",
        parent_name: "cmd.exe",
        parent_pid: 4880,
        cmdline: "sdelete64.exe -p 3 -c -z C:",
        user: "VANTAGE\\it.deploy",
        integrity: "high",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.ComputerName": decommHost.name,
        "crowdstrike.UserName": "VANTAGE\\it.deploy",
        "crowdstrike.FileName": "sdelete64.exe",
        "crowdstrike.FilePath": "C:\\Tools\\Sysinternals\\",
        "crowdstrike.CommandLine": "sdelete64.exe -p 3 -c -z C:",
        "crowdstrike.ParentProcessName": "cmd.exe",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "sdelete64.exe",
        "process.executable": "C:\\Tools\\Sysinternals\\sdelete64.exe",
        "process.command_line": "sdelete64.exe -p 3 -c -z C:",
        "process.parent.name": "cmd.exe",
        "process.integrity_level": "High",
        "process.code_signature.status": "valid",
        "process.code_signature.subject_name": "Microsoft Corporation",
        "file.name": "sdelete64.exe",
        "file.path": "C:\\Tools\\Sysinternals\\sdelete64.exe",
        "file.signature.status": "valid",
        "file.signature.subject_name": "Microsoft Corporation",
        "file.signature.trusted": "true",
        "host.name": decommHost.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": "it.deploy",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE WIPER EXECUTES — cl64.exe runs as SYSTEM, launched by the SCM
    //    (services.exe) after being pushed as a remote service. Unsigned,
    //    dropped in C:\Users\Public (T1485 Data Destruction).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_01_wiper_exec",
      ts: T(0),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1485",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Falcon recorded services.exe on VNT-WKS-27 spawning an unsigned binary, C:\\Users\\Public\\cl64.exe, as NT AUTHORITY\\SYSTEM at 03:12 — a payload started by the Service Control Manager immediately before a burst of destructive activity.",
      process: {
        name: "cl64.exe",
        pid: 6620,
        path: "C:\\Users\\Public\\cl64.exe",
        parent_name: "services.exe",
        parent_pid: 720,
        cmdline: "C:\\Users\\Public\\cl64.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: wiperHash },
      },
      file: {
        name: "cl64.exe",
        path: "C:\\Users\\Public\\cl64.exe",
        sha256: wiperHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.FileName": "cl64.exe",
        "crowdstrike.FilePath": "C:\\Users\\Public\\",
        "crowdstrike.CommandLine": "C:\\Users\\Public\\cl64.exe",
        "crowdstrike.ParentProcessName": "services.exe",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "cl64.exe",
        "process.executable": "C:\\Users\\Public\\cl64.exe",
        "process.command_line": "C:\\Users\\Public\\cl64.exe",
        "process.parent.name": "services.exe",
        "process.integrity_level": "System",
        "process.hash.sha256": wiperHash,
        "file.name": "cl64.exe",
        "file.path": "C:\\Users\\Public\\cl64.exe",
        "file.hash.sha256": wiperHash,
        "file.signature.status": "unsigned",
        "file.signature.trusted": "false",
        "host.name": host.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": "SYSTEM",
        "threat.technique.id": "T1485",
        "threat.technique.name": "Data Destruction",
        "threat.tactic.name": "Impact",
        "threat.tactic.id": "TA0040",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE ABUSED DRIVER — Sysmon Event 6 (DriverLoad). A validly-signed
    //    third-party partition-management driver (epmntdrv.sys) is loaded to
    //    obtain kernel-mode raw disk access (T1543.003).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_02_driver_load",
      ts: T(4 * SEC),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "service_install",
      hostname: host.name,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1543.003",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      description:
        "Sysmon Event 6 recorded the kernel driver epmntdrv.sys loading on VNT-WKS-27 seconds after cl64.exe started. The driver is validly signed by a third-party storage-tool vendor; it is loaded to reach the physical disk from kernel mode.",
      file: {
        name: "epmntdrv.sys",
        path: "C:\\Windows\\System32\\drivers\\epmntdrv.sys",
        sha256: driverHash,
      },
      raw: {
        "winlog.event_id": "6",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": host.fqdn,
        "winlog.event_data.ImageLoaded": "C:\\Windows\\System32\\drivers\\epmntdrv.sys",
        "winlog.event_data.Hashes": `SHA256=${driverHash}`,
        "winlog.event_data.Signed": "true",
        "winlog.event_data.Signature": "CHENGDU YIWO Tech Development Co., Ltd.",
        "winlog.event_data.SignatureStatus": "Valid",
        "file.hash.sha256": driverHash,
        "host.name": host.name,
        "event.code": "6",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. SHADOW COPIES DELETED — Sysmon Event 1. cl64.exe spawns vssadmin to
    //    remove the Volume Shadow Copies (T1490 Inhibit System Recovery).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_03_vssadmin_delete",
      ts: T(20 * SEC),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1490",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Sysmon Event 1 shows cl64.exe spawning vssadmin.exe with 'delete shadows /all /quiet' as SYSTEM on VNT-WKS-27 — the on-disk restore points being removed.",
      process: {
        name: "vssadmin.exe",
        pid: 6712,
        path: "C:\\Windows\\System32\\vssadmin.exe",
        parent_name: "cl64.exe",
        parent_pid: 6620,
        cmdline: "vssadmin.exe delete shadows /all /quiet",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": host.fqdn,
        "winlog.event_data.Image": "C:\\Windows\\System32\\vssadmin.exe",
        "winlog.event_data.OriginalFileName": "VSSADMIN.EXE",
        "winlog.event_data.CommandLine": "vssadmin.exe delete shadows /all /quiet",
        "winlog.event_data.CurrentDirectory": "C:\\Windows\\System32\\",
        "winlog.event_data.ParentImage": "C:\\Users\\Public\\cl64.exe",
        "winlog.event_data.ParentCommandLine": "C:\\Users\\Public\\cl64.exe",
        "winlog.event_data.ProcessId": "6712",
        "winlog.event_data.ParentProcessId": "6620",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "host.name": host.name,
        "event.code": "1",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. CORROBORATION — Microsoft Defender for Endpoint sees the same run.
    //    DeviceProcessEvents ties the vssadmin shadow-deletion to the same
    //    initiating payload SHA256 (T1490).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_08_mde_corroboration",
      ts: T(21 * SEC),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1490",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Defender for Endpoint, also on VNT-WKS-27, independently recorded the vssadmin shadow deletion. Its DeviceProcessEvents row ties the vssadmin child to the same initiating cl64.exe binary and payload SHA256 as Falcon saw.",
      raw: {
        "Timestamp": T(21 * SEC),
        "DeviceName": host.name,
        "DeviceId": host.id,
        "ActionType": "ProcessCreated",
        "FileName": "vssadmin.exe",
        "FolderPath": "C:\\Windows\\System32\\vssadmin.exe",
        "ProcessCommandLine": "vssadmin.exe delete shadows /all /quiet",
        "ProcessId": "6712",
        "InitiatingProcessFileName": "cl64.exe",
        "InitiatingProcessFolderPath": "C:\\Users\\Public\\cl64.exe",
        "InitiatingProcessCommandLine": "C:\\Users\\Public\\cl64.exe",
        "InitiatingProcessId": "6620",
        "InitiatingProcessSHA256": wiperHash,
        "AccountName": "system",
        "AccountDomain": "nt authority",
        "ReportId": "51830744",
        "threat.technique.id": "T1490",
        "threat.technique.name": "Inhibit System Recovery",
        "threat.tactic.name": "Impact",
        "threat.tactic.id": "TA0040",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. BOOT RECOVERY DISABLED — Sysmon Event 1. bcdedit turns off Windows
    //    recovery so the machine cannot self-heal (T1490).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_04_bcdedit_norecovery",
      ts: T(35 * SEC),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1490",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Sysmon Event 1 shows cl64.exe spawning bcdedit.exe to set recoveryenabled to no and ignore boot failures on VNT-WKS-27 — the Windows recovery environment being switched off.",
      process: {
        name: "bcdedit.exe",
        pid: 6744,
        path: "C:\\Windows\\System32\\bcdedit.exe",
        parent_name: "cl64.exe",
        parent_pid: 6620,
        cmdline: "bcdedit.exe /set {default} recoveryenabled no",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": host.fqdn,
        "winlog.event_data.Image": "C:\\Windows\\System32\\bcdedit.exe",
        "winlog.event_data.OriginalFileName": "bcdedit.exe",
        "winlog.event_data.CommandLine": "bcdedit.exe /set {default} recoveryenabled no",
        "winlog.event_data.CurrentDirectory": "C:\\Windows\\System32\\",
        "winlog.event_data.ParentImage": "C:\\Users\\Public\\cl64.exe",
        "winlog.event_data.ParentCommandLine": "C:\\Users\\Public\\cl64.exe",
        "winlog.event_data.ProcessId": "6744",
        "winlog.event_data.ParentProcessId": "6620",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "host.name": host.name,
        "event.code": "1",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. EVENT LOG CLEARED — Falcon process_create. wevtutil clears the
    //    Security log to erase the trail (T1070.001 Clear Windows Event Logs).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_05_wevtutil_clear",
      ts: T(50 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.name,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1070.001",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "Falcon recorded cl64.exe spawning wevtutil.exe with 'cl Security' as SYSTEM on VNT-WKS-27 — the Security event log being emptied.",
      process: {
        name: "wevtutil.exe",
        pid: 6790,
        path: "C:\\Windows\\System32\\wevtutil.exe",
        parent_name: "cl64.exe",
        parent_pid: 6620,
        cmdline: "wevtutil.exe cl Security",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.FileName": "wevtutil.exe",
        "crowdstrike.FilePath": "C:\\Windows\\System32\\",
        "crowdstrike.CommandLine": "wevtutil.exe cl Security",
        "crowdstrike.ParentProcessName": "cl64.exe",
        "crowdstrike.OperationType": "ProcessRollup2",
        "process.name": "wevtutil.exe",
        "process.executable": "C:\\Windows\\System32\\wevtutil.exe",
        "process.command_line": "wevtutil.exe cl Security",
        "process.parent.name": "cl64.exe",
        "process.integrity_level": "System",
        "host.name": host.name,
        "host.os.name": host.os,
        "threat.technique.id": "T1070.001",
        "threat.technique.name": "Clear Windows Event Logs",
        "threat.tactic.name": "Defense Evasion",
        "threat.tactic.id": "TA0005",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE DISK STRUCTURE WIPE — Falcon file_modify. Through the loaded
    //    driver, cl64.exe writes over the raw physical disk (\\.\PhysicalDrive0
    //    / \Device\Harddisk0), destroying the MBR and partition table
    //    (T1561.002 Disk Structure Wipe).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_06_raw_disk_write",
      ts: T(70 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_modify",
      hostname: host.name,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1561.002",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Falcon recorded cl64.exe issuing raw writes to \\\\.\\PhysicalDrive0 (\\Device\\Harddisk0\\DR0) on VNT-WKS-27 — the master boot record and partition table region of the physical disk being overwritten directly, not through the file system.",
      process: {
        name: "cl64.exe",
        pid: 6620,
        path: "C:\\Users\\Public\\cl64.exe",
        parent_name: "services.exe",
        parent_pid: 720,
        cmdline: "C:\\Users\\Public\\cl64.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: wiperHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "RawDiskAccess",
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.FileName": "cl64.exe",
        "crowdstrike.FilePath": "C:\\Users\\Public\\",
        "crowdstrike.CommandLine": "C:\\Users\\Public\\cl64.exe",
        "crowdstrike.OperationType": "DiskWrite",
        "crowdstrike.TargetDevice": "\\\\.\\PhysicalDrive0",
        "crowdstrike.VolumeDevice": "\\Device\\Harddisk0\\DR0",
        "process.name": "cl64.exe",
        "process.executable": "C:\\Users\\Public\\cl64.exe",
        "process.hash.sha256": wiperHash,
        "process.integrity_level": "System",
        "host.name": host.name,
        "host.os.name": host.os,
        "threat.technique.id": "T1561.002",
        "threat.technique.name": "Disk Wipe: Disk Structure Wipe",
        "threat.tactic.name": "Impact",
        "threat.tactic.id": "TA0040",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. FILE CONTENT WIPE — Sysmon Event 11 (FileCreate). cl64.exe overwrites
    //    user documents with junk (T1561.001 Disk Content Wipe).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_07_file_overwrite",
      ts: T(80 * SEC),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "file_modify",
      hostname: host.name,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1561.001",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Sysmon Event 11 shows cl64.exe writing over user files on VNT-WKS-27, including C:\\Users\\m.reyes\\Documents\\Q3-forecast.xlsx — the file contents being replaced with junk rather than encrypted.",
      process: {
        name: "cl64.exe",
        pid: 6620,
        path: "C:\\Users\\Public\\cl64.exe",
        parent_name: "services.exe",
        parent_pid: 720,
        cmdline: "C:\\Users\\Public\\cl64.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: wiperHash },
      },
      file: {
        name: "Q3-forecast.xlsx",
        path: "C:\\Users\\m.reyes\\Documents\\Q3-forecast.xlsx",
      },
      raw: {
        "winlog.event_id": "11",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": host.fqdn,
        "winlog.event_data.Image": "C:\\Users\\Public\\cl64.exe",
        "winlog.event_data.TargetFilename": "C:\\Users\\m.reyes\\Documents\\Q3-forecast.xlsx",
        "winlog.event_data.CreationUtcTime": "2026-08-29 03:13:20.114",
        "winlog.event_data.ProcessId": "6620",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "host.name": host.name,
        "event.code": "11",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. THE DETECTION — Falcon raises the Critical destructive-attack
    //    detection, and attributes the deploying account. is_detection +
    //    edr_scope "edr" (endpoint-only; there is no control-plane facet).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "dw_09_edr_detection",
      ts: T(2 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.name,
      user_email: deployAdmin.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1485",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "edr",
      description:
        "Falcon raised a Critical detection on VNT-WKS-27: a SYSTEM binary loaded a signed disk driver, deleted the shadow copies, disabled boot recovery, cleared the Security log, and wrote over the raw disk and user files. The remote service that launched it was created under the a.novak account.",
      process: {
        name: "cl64.exe",
        pid: 6620,
        path: "C:\\Users\\Public\\cl64.exe",
        parent_name: "services.exe",
        parent_pid: 720,
        cmdline: "C:\\Users\\Public\\cl64.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: wiperHash },
      },
      raw: {
        "crowdstrike.DetectName": "WindowsWiper_DestructiveDiskWrite",
        "crowdstrike.Tactic": "Impact",
        "crowdstrike.Technique": "Data Destruction",
        "crowdstrike.Objective": "Falcon Detection Method",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.IncidentType": "Destructive Attack",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": aid,
        "crowdstrike.ComputerName": host.name,
        "crowdstrike.UserName": `VANTAGE\\${deployAdmin.sam}`,
        "crowdstrike.FileName": "cl64.exe",
        "crowdstrike.FilePath": "C:\\Users\\Public\\",
        "process.hash.sha256": wiperHash,
        "host.name": host.name,
        "host.os.name": host.os,
        "host.os.version": host.osVersion,
        "user.name": deployAdmin.sam,
        "threat.technique.id": "T1485",
        "threat.technique.name": "Data Destruction",
        "threat.tactic.name": "Impact",
        "threat.tactic.id": "TA0040",
        "event.outcome": "success",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.name, // VNT-WKS-27 — the bricked endpoint
      first_seen: T(0),
      last_seen: T(2 * MIN),
      // "unknown", not "malicious": this is the organisation's own endpoint —
      // the victim, not adversary infrastructure.
      reputation: "unknown",
      tags: ["endpoint", "bricked", "affected"],
    },
    {
      type: "user",
      value: deployAdmin.sam, // a.novak — the compromised deployment account
      first_seen: T(0),
      last_seen: T(2 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "deployment", "privileged"],
    },
    {
      type: "sha256",
      value: wiperHash, // cl64.exe — the wiper payload
      first_seen: T(0),
      last_seen: T(2 * MIN),
      reputation: "malicious",
      tags: ["payload", "destructive", "unsigned"],
    },
    {
      type: "sha256",
      value: driverHash, // epmntdrv.sys — the signed driver abused for raw disk access
      first_seen: T(4 * SEC),
      last_seen: T(4 * SEC),
      reputation: "malicious",
      tags: ["kernel-driver", "signed", "raw-disk-access"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "dw_q1",
      xp: 60,
      kind: "single",
      prompt:
        "Reconstruct the process tree on VNT-WKS-27. A single SYSTEM process, cl64.exe, spawns vssadmin 'delete shadows /all /quiet', bcdedit 'recoveryenabled no', and wevtutil 'cl Security', and writes to \\\\.\\PhysicalDrive0. Which description best fits the sequence?",
      hint: "Group the four child actions by what each one destroys, and note that no files are being encrypted anywhere.",
      options: [
        { value: "coordinated_wipe", label: "One SYSTEM binary overwrote the raw disk and user files with junk while removing the on-disk restore points, switching off boot recovery, and emptying the event log" },
        { value: "ransomware_note", label: "A ransomware payload encrypting the files on the host and dropping a note in each affected directory before reaching its key server" },
        { value: "backup_maintenance", label: "A backup agent taking scheduled volume snapshots and pruning older restore points as part of a routine nightly maintenance job" },
        { value: "disk_repair", label: "A disk-defragmentation and check-disk pass reorganising sectors, which accounts for the heavy write activity and the reboot that followed" },
      ],
      answer: "coordinated_wipe",
      explanation:
        "Read together, the four children are a demolition, not housekeeping: vssadmin removes the shadow copies, bcdedit switches off the Windows recovery environment, wevtutil empties the Security log, and the raw write to \\\\.\\PhysicalDrive0 destroys the boot structures — with a parallel overwrite of user files. Nothing here encrypts data. It is not ransomware (there is no encryption and no note — see the next question), not a backup agent (a backup does not clear the event log or write over the raw disk), and not a defrag/chkdsk pass (those do not delete shadow copies, disable recovery, or wipe logs). This is coordinated destruction whose whole point is to make the machine unrecoverable.",
    },
    {
      id: "dw_q2",
      xp: 70,
      kind: "single",
      prompt:
        "VNT-WKS-27 is now unbootable and its files are gibberish. It looks ransomware-adjacent — mass writes, shadow-copy deletion, boot tampering. Why is this a wiper rather than recoverable ransomware?",
      hint: "Ask what a victim would need in order to get their data back, and whether anything in the evidence could ever provide it.",
      options: [
        { value: "no_recovery_path", label: "Nothing encrypts data to a key or leaves a note demanding payment — sectors and files are overwritten with junk and the backups and boot config are gone, so no key could ever restore them; the aim is denial" },
        { value: "note_pending", label: "It is ransomware whose note has simply not been written yet; the wiping stage always runs first and the extortion message appears a few minutes afterwards" },
        { value: "reversible", label: "It is recoverable: deleting shadow copies is undone with 'vssadmin resize', and the boot record is rebuilt with 'bootrec /fixmbr', so the host comes straight back" },
        { value: "decryptor_c2", label: "It is ransomware whose decryptor is pulled from its command-and-control server once the operator has confirmed the victim's payment on the portal" },
      ],
      answer: "no_recovery_path",
      explanation:
        "The defining difference is the recovery path. Ransomware encrypts data reversibly and monetises the key: there is a ransom note, and paying (in principle) yields a decryptor. Here there is no encryption, no note, and no C2 to fetch a decryptor — the disk sectors and files are overwritten with junk and the shadow copies and boot config are destroyed, so there is literally no key or secret that could put the data back. 'Note pending' is wrong: no note is coming because none is part of the design. 'Reversible' is wrong: once the raw sectors are overwritten, vssadmin resize and bootrec /fixmbr have nothing to rebuild from. And there is no decryptor to fetch. The objective is destruction/denial, which is exactly why the response cannot be 'wait for or pay the demand'.",
    },
    {
      id: "dw_q3",
      xp: 65,
      kind: "single",
      prompt:
        "Sysmon Event 6 shows epmntdrv.sys — a validly-signed third-party storage driver — loading on VNT-WKS-27 moments after cl64.exe started. What role does loading that driver serve?",
      hint: "A normal user-mode program cannot freely write over the physical disk. Think about what a kernel driver grants that user mode does not.",
      options: [
        { value: "kernel_raw_access", label: "It gives the payload kernel-mode raw access to \\\\.\\PhysicalDrive0, letting it overwrite the boot record and partition table directly, beneath the file system and its permissions" },
        { value: "vendor_update", label: "It is a routine signed driver update pushed by the storage vendor, unrelated to the process that happened to start immediately before it" },
        { value: "edr_minifilter", label: "It installs the endpoint agent's own mini-filter driver so the security tool can inspect the disk writes the process is making" },
        { value: "encrypted_container", label: "It mounts an encrypted container as a virtual disk, which is where the operator stages the collected files before exfiltrating them" },
      ],
      answer: "kernel_raw_access",
      explanation:
        "A user-mode process cannot freely scribble over the raw physical disk — the file system and its permissions are in the way. Loading a signed driver that exposes low-level disk I/O gives the malware kernel-mode raw access to \\\\.\\PhysicalDrive0, so it can overwrite the master boot record and partition structures directly. Abusing a legitimately-signed third-party driver this way is a hallmark of real wipers (HermeticWiper leaned on exactly this kind of signed partition-management driver). It is not a coincidental vendor update (the timing and the raw writes that follow make that clear), not the EDR's own mini-filter, and not an encrypted container — there is no exfiltration here, only destruction.",
    },
    {
      id: "dw_q4",
      xp: 60,
      kind: "single",
      prompt:
        "The night before, VNT-WKS-19 logged sdelete64.exe overwriting its drive (dw_00). Why is that event benign while the VNT-WKS-27 activity is an incident, when both are 'a disk being overwritten'?",
      hint: "Compare the tool and its signer, the account and its authorisation, and whether backups and logs were destroyed alongside the wipe.",
      options: [
        { value: "authorised_scoped", label: "The sdelete run is a signed Sysinternals tool a named IT account ran against a host being decommissioned under a change ticket, and it never removed shadow copies, disabled recovery, or cleared the log" },
        { value: "no_difference", label: "There is no real difference in intent; both are disk wipes, so VNT-WKS-19 should be raised as a second destructive incident belonging to the same campaign" },
        { value: "sdelete_harmless", label: "sdelete only clears free space and cannot affect real data, so overwriting a live drive with it is always harmless no matter which account runs it" },
        { value: "integrity_rule", label: "The VNT-WKS-19 run was at high integrity rather than SYSTEM, and any wipe below SYSTEM is by definition an authorised administrative action" },
      ],
      answer: "authorised_scoped",
      explanation:
        "Same shape, opposite verdict — and the discriminator is authorisation and surrounding behaviour, not the wipe. On VNT-WKS-19 a signed, Microsoft-published Sysinternals tool was run by a named IT account, under change ticket CHG-20418, against a host being decommissioned in a maintenance window — and it did nothing else: no shadow-copy deletion, no boot-recovery change, no log clearing. VNT-WKS-27 is an unsigned SYSTEM binary that chained all of those recovery-inhibiting and log-clearing steps with no ticket behind it. 'No difference in intent' ignores the ticket and the context. 'sdelete is harmless' is false — sdelete absolutely can destroy real data. And the integrity level is not the test: plenty of legitimate admin actions run as SYSTEM, and plenty of malicious ones do not.",
    },
    {
      id: "dw_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "There is no decryptor and no ransom demand, and the host is destroyed. Select the TWO response actions that fit a destructive-attack case.",
      hint: "One action is about getting the business back; the other is about stopping the same thing happening to the next host. Neither involves the (non-existent) attacker portal.",
      options: [
        { value: "image_and_rebuild", label: "Preserve forensic disk images of the affected hosts, then rebuild the machines from known-good offline or immutable backups rather than attempting an in-place repair" },
        { value: "reset_and_hunt", label: "Reset the compromised deployment account's credentials and hunt across the fleet for the remote mechanism that pushed and launched the binary as SYSTEM" },
        { value: "pay_operator", label: "Hold off on rebuilding and open a channel to the operator, since paying the demand is the quickest route to a working decryption key for the files" },
        { value: "chkdsk_recover", label: "Reboot each bricked endpoint and run 'chkdsk /r', which repairs the overwritten boot record and brings back the junked files automatically" },
      ],
      answer: ["image_and_rebuild", "reset_and_hunt"],
      explanation:
        "Because the data is destroyed, not encrypted, recovery means rebuild, not decrypt: image the affected hosts for forensics, then restore from offline or immutable backups that the wiper could not reach. In parallel, close the door on the next host — reset the compromised a.novak account and hunt the fleet for the remote service-creation mechanism that pushed and launched cl64.exe as SYSTEM, since a wiper is rarely aimed at one machine. Paying the operator is meaningless here: there is no key and no portal, so there is nothing to buy back. And chkdsk /r cannot help — once the raw sectors and the MBR are overwritten with junk there is nothing for it to repair or recover.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Destructive Wiper — an Endpoint Bricked, and No Way to Pay for It Back",
    threat_actor: "Destructive intrusion operator (data-destruction objective, wiper deployed via a compromised admin)",
    attack_kind: "destructive_attack",
    briefing:
      "Falcon fired a Critical detection on VNT-WKS-27 at 03:12, and the Service Desk is fielding calls that several machines rebooted and now show \"No operating system found.\" The host went dark seconds after the alert. Telemetry shows a process running as SYSTEM that spawned a burst of built-in Windows tools, heavy disk writes, and an emptied Security log. Reconstruct what executed and classify it.",
    narrative: `VNT-WKS-27 is a workstation at Vantage Industrial. At 03:12 the Service Control Manager launched an unsigned binary, C:\\Users\\Public\\cl64.exe, as NT AUTHORITY\\SYSTEM — a payload pushed to the host as a remote service under the compromised administrator account a.novak, and, from the Service Desk calls, to a number of other machines at the same time.

Within seconds cl64.exe loaded a validly-signed third-party storage driver, epmntdrv.sys, to obtain kernel-mode raw access to the physical disk. It then worked through a short, deliberate sequence: vssadmin deleted the Volume Shadow Copies, bcdedit set recoveryenabled to no, and wevtutil cleared the Security event log. With the on-disk restore points gone, boot recovery disabled, and the trail wiped, it wrote junk directly over \\\\.\\PhysicalDrive0 — destroying the master boot record and partition table — and overwrote user files such as Q3-forecast.xlsx with garbage. The machine was unbootable moments later.

The night before, the same estate had cleanly and legitimately wiped VNT-WKS-19: signed Sysinternals sdelete, run by the IT decommissioning account under change ticket CHG-20418, in a maintenance window, on a host being disposed of. That is the control case — the same 'a disk is being overwritten' shape, but authorised, scoped, and unaccompanied by any destruction of backups or logs.

This is where the exercise bites. Everything about VNT-WKS-27 rhymes with ransomware — mass writes, shadow-copy deletion, boot tampering — but there is no encryption to a key, no ransom note, and no command-and-control to hand back a decryptor. The data is not locked; it is gone. Defender for Endpoint independently logged the vssadmin shadow deletion against the same cl64.exe payload hash, and Falcon raised the Critical destructive-attack detection at 03:14. The job is to recognise a wiper for what it is — destruction, not extortion — and to scope a response that rebuilds rather than waits for a key that will never come.`,
    learning_objectives: [
      "Read a destructive process tree (a signed-driver load, vssadmin 'delete shadows', bcdedit 'recoveryenabled no', wevtutil 'cl', a raw \\\\.\\PhysicalDrive0 write, file overwrites) and recognise coordinated data destruction plus recovery inhibition",
      "Distinguish a wiper from ransomware by the ABSENCE of an encryption key, a ransom note, and a C2 decryptor path — the objective is denial/destruction, not extortion, so the data is gone rather than locked",
      "Recognise abuse of a validly-signed third-party kernel driver loaded to reach \\\\.\\PhysicalDrive0 from kernel mode as the mechanism for overwriting disk structures beneath the file system",
      "Separate an authorised, change-ticketed secure-wipe/decommission (signed Sysinternals tool, named IT account, maintenance window) from a malicious wipe that also destroys backups and clears logs",
      "Scope response for a destructive attack: preserve forensic images, rebuild from offline/immutable backups, reset the compromised deployment account, and hunt the fleet for the delivery mechanism — do not expect a decryptor",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Impact", action: `Unsigned cl64.exe launched as SYSTEM by the SCM on ${host.name} (T1485)` },
      { ts: T(4 * SEC), phase: "Privilege Escalation", action: "Signed driver epmntdrv.sys loaded for kernel-mode raw disk access (T1543.003)" },
      { ts: T(20 * SEC), phase: "Impact", action: "vssadmin delete shadows /all /quiet — Volume Shadow Copies removed (T1490)" },
      { ts: T(35 * SEC), phase: "Impact", action: "bcdedit /set {default} recoveryenabled no — boot recovery disabled (T1490)" },
      { ts: T(50 * SEC), phase: "Defense Evasion", action: "wevtutil cl Security — Security event log cleared (T1070.001)" },
      { ts: T(70 * SEC), phase: "Impact", action: "Raw write to \\\\.\\PhysicalDrive0 — MBR and partition table destroyed (T1561.002)" },
      { ts: T(80 * SEC), phase: "Impact", action: "User files overwritten with junk (T1561.001)" },
      { ts: T(2 * MIN), phase: "Detection", action: "Falcon raises the Critical destructive-attack detection; deploying account a.novak attributed" },
    ],
    questions,
  };
}
