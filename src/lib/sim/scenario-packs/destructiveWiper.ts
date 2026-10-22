/**
 * Scenario pack: "Destructive Wiper, an Endpoint Bricked, and No Way to Pay for It Back"
 *
 * ADVANCED tier. A destructive WIPER, not ransomware. On VNT-WKS-27 a single
 * SYSTEM process (cl64.exe) loads a validly-signed third-party storage driver to
 * gain kernel-mode raw access to the physical disk, deletes the Volume Shadow
 * Copies, turns off Windows boot recovery, clears the Security event log, and
 * then overwrites the Master Boot Record / partition structures and user files
 * with junk. The machine goes unbootable within seconds.
 *
 * The teaching spine is that this looks ransomware-adjacent, mass file writes,
 * shadow-copy deletion, boot tampering, but there is NO recovery or extortion
 * path: no encryption to a key, no ransom note that a key could ever unlock, no
 * C2 fetching a decryptor. The sectors and files are simply destroyed. The
 * objective is denial/destruction, not a payout, and that changes the entire
 * response: you cannot decrypt or negotiate your way out, only rebuild.
 *
 * The BENIGN CONTROL (event 0) is a legitimately change-ticketed secure-wipe: IT
 * running signed Sysinternals sdelete against a machine being decommissioned in a
 * maintenance window, the same "a disk is being overwritten" shape, opposite
 * verdict. The discriminator is who ran it, under what authorisation, and whether
 * it also destroyed backups and cleared logs, not the fact that a disk was wiped.
 *
 * SOURCES (registry vendor keys): crowdstrike-falcon (the destructive process
 * tree, the raw-disk IOA, the deployment server's commands and the detection),
 * sysmon (process creation, the signed-but-abused driver load, Event 6, and the
 * file overwrites, Event 11), microsoft-defender-endpoint (one corroborating
 * DeviceProcessEvents record), windows-security (the logons, the C$ write and the
 * 7045 service creations), fortigate-ssl-vpn (the compromised account's VPN
 * login) and servicenow-itsm (the change ticket behind the benign control).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { fgVpn } from "@/lib/sim/emitters/fortigate";
import { sysmonProcess, sysmonFile, sysmonDriver } from "@/lib/sim/emitters/sysmon";
import { mdeProcess } from "@/lib/sim/emitters/mde";
import { winLogon, winServiceInstall, winDetailedShareAccess, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";

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
    osVersion: "10.0.22631",
  };

  // The host wiped legitimately the day before, the benign control.
  const decommHost = { name: "VNT-WKS-19", fqdn: "VNT-WKS-19.vantageindustrial.com" };

  // The compromised privileged account used to push and launch the payload as a
  // remote service across the fleet. The wiper itself runs as SYSTEM.
  const deployAdmin = { sam: "a.novak", email: "a.novak@vantageindustrial.com", full: "Adam Novak" };
  const deployAdminSid = domainSidFor("vantageindustrial", deployAdmin.sam);
  // The host the operator pushed the payload from (the deployment server a.novak's
  // credentials were used on).
  const deploySrc = { name: "VNT-DEPLOY-01", ip: "10.60.1.40", fqdn: "VNT-DEPLOY-01.vantageindustrial.com" };
  // The VPN address the compromised account came in from, and the tunnel address it was handed.
  const vpnSrcIp = "196.251.33.74";
  const vpnTunnelIp = "10.60.250.17";
  const adminCtx = { user: deployAdmin.email, runAsUser: `VANTAGE\\${deployAdmin.sam}` };
  const fleetHosts = [
    { name: "VNT-WKS-31", ip: "10.60.8.31", pid: 4412, t0: 1 * SEC, svc: -7 * SEC, rec: "52734" },
    { name: "VNT-WKS-33", ip: "10.60.8.33", pid: 5236, t0: 3 * SEC, svc: -5 * SEC, rec: "52738" },
  ];

  // The wiper binary, and the signed third-party driver it abuses for raw disk
  // I/O. Both appear literally in the events below.
  const wiperHash = makeSha256("destructive_wiper_2026_cl64_payload_binary");
  const driverHash = makeSha256("destructive_wiper_2026_epmntdrv_signed_partition_driver");

  const sensorId = "16c868848556ddbef116670ca7936a19";
  const aid = "6b2d9c4715a04e83b9f1c60a28e7d54f";

  const cx = "vantageindustrial" as const;
  const cl64Path = "C:\\Users\\Public\\cl64.exe";
  const osExtra = { "host.os.name": host.os, "host.os.version": host.osVersion };

  const events: TelemetryEvent[] = [
    // 0c. The change ticket behind the benign control (opened and approved the day before).
    {
      ...serviceNowRecord({
        id: "dw_00c_change_ticket", ts: "2026-08-28T20:40:00.000Z", table: "change_request", number: "CHG0020418", state: "Implement",
        shortDescription: "Decommission VNT-WKS-19: secure erase of user data before disposal", callerId: "it.deploy@vantageindustrial.com",
        extra: {
          "servicenow.type": "Standard", "servicenow.approval": "approved", "servicenow.approved_by": "k.lund", "servicenow.assigned_to": "it.deploy",
          "servicenow.cmdb_ci": decommHost.name, "servicenow.planned_start_date": "2026-08-28 21:00:00", "servicenow.planned_end_date": "2026-08-28 23:00:00", "servicenow.risk": "Low",
        },
        severity: "informational",
        description: "Change CHG0020418 (Standard, approved by k.lund): secure erase of VNT-WKS-19 before disposal, assigned to it.deploy, window 21:00 to 23:00 on 28 Aug.",
      }),
      it_context: { result: "confirmed", message: "CHG0020418 is an approved standard change: VNT-WKS-19 is being decommissioned and its user data securely erased by IT Deployment (it.deploy) between 21:00 and 23:00." },
    },

    // 0. BENIGN CONTROL, an authorised, change-ticketed secure wipe (signed sdelete).
    csProcess({
      companyId: cx, id: "dw_00_benign_secure_wipe", ts: "2026-08-28T21:30:00.000Z", host: decommHost.name,
      user: "it.deploy@vantageindustrial.com", processName: "sdelete64.exe", processPath: "C:\\Tools\\Sysinternals\\sdelete64.exe",
      cmdline: "sdelete64.exe -p 3 -s -q C:\\Users", parentName: "cmd.exe", parentPid: 4880, pid: 5120,
      signed: true, signatureSubject: "Microsoft Corporation", integrity: "high", severity: "informational",
      expectedVerdict: "fp",
      fpExplanation: "The control case for the whole scenario. Under change ticket CHG0020418, the IT decommissioning team ran signed Sysinternals sdelete to securely erase the user profiles on VNT-WKS-19 before it left the estate: the same 'data is being destroyed' shape as the intrusion. What makes it benign is written in the authorisation and the surrounding behaviour: a signed Microsoft-published tool, run by a named IT account, at high integrity, inside the approved change window, on a host slated for disposal. It does NOT delete this host's shadow copies to block recovery, does NOT disable boot recovery, and does NOT clear the Security log. An analyst who alerts on 'data got wiped' alone will flag this and be wrong; the discriminator is who ran it, under what ticket, and whether backups and logs were destroyed alongside, not the wipe itself.",
      extra: { ...osExtra, "file.code_signature.exists": true, "file.code_signature.subject_name": "Microsoft Corporation", "file.code_signature.trusted": true },
      description: "sdelete64.exe (signed Sysinternals, Microsoft-published) ran on VNT-WKS-19 under the it.deploy account at high integrity, securely deleting C:\\Users on a host being decommissioned under change ticket CHG0020418. No shadow-copy deletion, boot-config change, or log clearing followed.",
    }),

    // 0v. THE COMPROMISE: a.novak's VPN login from an address in Nigeria, 31 minutes before the push.
    fgVpn({
      companyId: cx, id: "dw_00v_vpn_login", ts: T(-31 * MIN), host: "VNT-FW-01", user: deployAdmin.email,
      remoteIp: vpnSrcIp, assignedIp: vpnTunnelIp, severity: "medium", incidentId: INCIDENT,
      mitre: "T1133", tactic: "Initial Access",
      description: "FortiGate SSL-VPN tunnel established for a.novak from 196.251.33.74 (Lagos) at 02:41, tunnel address 10.60.250.17.",
    }),

    // 0w. THE DEPLOYMENT SERVER: the same account opens an RDP session on VNT-DEPLOY-01 from the tunnel address.
    winLogon({
      companyId: cx, id: "dw_00w_deploy_rdp_logon", ts: T(-80 * SEC), host: deploySrc.name, fqdn: deploySrc.fqdn,
      logSource: "windows_security", targetUser: deployAdmin.sam, targetSid: deployAdminSid, userEmail: deployAdmin.email,
      srcIp: vpnTunnelIp, workstation: "WIN-9QK4M2", logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ", recordId: "2290418",
      mitre: "T1021.001", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "VNT-DEPLOY-01 logged a 4624 type 10 (RemoteInteractive) logon for a.novak from the VPN tunnel address 10.60.250.17 at 03:10:40.",
    }),
    csProcess({
      companyId: cx, id: "dw_00x_deploy_cmd", ts: T(-75 * SEC), host: deploySrc.name, srcIp: deploySrc.ip, ...adminCtx,
      processName: "cmd.exe", cmdline: "cmd.exe", parentName: "explorer.exe", parentPid: 3912, pid: 5208, severity: "medium", incidentId: INCIDENT,
      extra: { ...osExtra },
      description: "cmd.exe started in a.novak's RDP session on VNT-DEPLOY-01.",
    }),

    // 0a. DELIVERY: a.novak's network logon to VNT-WKS-27 from the deployment server.
    //     (Forwarded to the SIEM before the wiper later cleared the local Security log.)
    winLogon({
      companyId: cx, id: "dw_00a_admin_network_logon", ts: T(-50 * SEC), host: host.name, fqdn: host.fqdn,
      logSource: "windows_security", targetUser: deployAdmin.sam, targetSid: deployAdminSid, userEmail: deployAdmin.email,
      srcIp: deploySrc.ip, workstation: deploySrc.name, logonType: 3, authPackage: "Kerberos", recordId: "1184207",
      mitre: "T1021.002", tactic: "Lateral Movement", severity: "medium", incidentId: INCIDENT,
      description: "VNT-WKS-27 logged a 4624 type 3 (network) logon for a.novak from the deployment server VNT-DEPLOY-01 at 03:11, less than a minute before the destructive activity began.",
    }),

    // 0a2. The payload copied to the target's C$ from the deployment server (cmd.exe /c copy), then the share write on the target (5145).
    csProcess({
      companyId: cx, id: "dw_00y_deploy_copy", ts: T(-44 * SEC), host: deploySrc.name, srcIp: deploySrc.ip, ...adminCtx,
      processName: "cmd.exe", cmdline: `cmd.exe /c copy D:\\Tools\\cl64.exe \\\\${host.name}\\C$\\Users\\Public\\cl64.exe`, parentName: "cmd.exe", parentPid: 5208, pid: 5284,
      mitre: "T1570", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      extra: { ...osExtra },
      description: "cmd.exe on VNT-DEPLOY-01 copied D:\\Tools\\cl64.exe to the C$ share of VNT-WKS-27.",
    }),
    winDetailedShareAccess({
      companyId: cx, id: "dw_00z_c_share_write", ts: T(-40 * SEC), host: host.name, fqdn: host.fqdn, logSource: "windows_security",
      targetUser: deployAdmin.sam, targetSid: deployAdminSid, userEmail: deployAdmin.email, srcIp: deploySrc.ip,
      shareName: "\\\\*\\C$", shareLocalPath: "\\??\\C:\\", relativeTargetName: "Users\\Public\\cl64.exe", accessMask: "0x2", accessList: "%%4417",
      recordId: "1184211", mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "VNT-WKS-27 logged a 5145: a.novak from 10.60.1.40 wrote Users\\Public\\cl64.exe to the C$ share.",
    }),
    csProcess({
      companyId: cx, id: "dw_00z2_sc_create", ts: T(-14 * SEC), host: deploySrc.name, srcIp: deploySrc.ip, ...adminCtx,
      processName: "sc.exe", cmdline: `sc.exe \\\\${host.name} create cl64svc binPath= C:\\Users\\Public\\cl64.exe start= demand`, parentName: "cmd.exe", parentPid: 5208, pid: 5312,
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      extra: { ...osExtra },
      description: "sc.exe on VNT-DEPLOY-01 created the service cl64svc on VNT-WKS-27 pointing at C:\\Users\\Public\\cl64.exe.",
    }),

    // 0b. DELIVERY: the remote service that will launch the payload as SYSTEM (System-log 7045).
    winServiceInstall({
      companyId: cx, id: "dw_00b_remote_service_install", ts: T(-8 * SEC), host: host.name, fqdn: host.fqdn,
      logSource: "windows_security", targetUser: deployAdmin.sam, userEmail: deployAdmin.email, installerSid: deployAdminSid,
      serviceName: "cl64svc", imagePath: cl64Path, accountName: "LocalSystem",
      serviceType: "user mode service", startType: "demand start", recordId: "52731",
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description: "The Service Control Manager on VNT-WKS-27 logged 7045: a new demand-start service, cl64svc, with ImagePath C:\\Users\\Public\\cl64.exe running as LocalSystem, created in a.novak's session (the UserID is a.novak's SID).",
    }),

    // 0d. The same push reaches two more machines (7045 on each), and the service is started.
    ...fleetHosts.map(h => winServiceInstall({
      companyId: cx, id: `dw_00d_${h.name.toLowerCase().replace("-", "_").replace("-", "_")}_service_install`, ts: T(h.svc), host: h.name, fqdn: `${h.name}.vantageindustrial.com`,
      logSource: "windows_security", targetUser: deployAdmin.sam, userEmail: deployAdmin.email, installerSid: deployAdminSid,
      serviceName: "cl64svc", imagePath: cl64Path, accountName: "LocalSystem", serviceType: "user mode service", startType: "demand start", recordId: h.rec,
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description: `${h.name} logged 7045: demand-start service cl64svc with ImagePath C:\\Users\\Public\\cl64.exe running as LocalSystem, created in a.novak's session.`,
    })),
    csProcess({
      companyId: cx, id: "dw_00z3_sc_start", ts: T(-3 * SEC), host: deploySrc.name, srcIp: deploySrc.ip, ...adminCtx,
      processName: "sc.exe", cmdline: `sc.exe \\\\${host.name} start cl64svc`, parentName: "cmd.exe", parentPid: 5208, pid: 5340,
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      extra: { ...osExtra },
      description: "sc.exe on VNT-DEPLOY-01 started the service cl64svc on VNT-WKS-27.",
    }),

    // 1. THE WIPER EXECUTES, cl64.exe as SYSTEM, launched by the SCM (services.exe).
    csProcess({
      companyId: cx, id: "dw_01_wiper_exec", ts: T(0), host: host.name, srcIp: host.ip, user: null,
      processName: "cl64.exe", processPath: cl64Path, cmdline: cl64Path, parentName: "services.exe", parentPid: 720, pid: 6620,
      sha256: wiperHash, signed: false, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1485", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
      extra: { ...osExtra, "file.name": "cl64.exe", "file.hash.sha256": wiperHash, "file.code_signature.exists": false, "file.code_signature.trusted": false, "threat.technique.id": "T1485", "threat.technique.name": "Data Destruction", "threat.tactic.name": "Impact", "threat.tactic.id": "TA0040" },
      description: "Falcon recorded services.exe on VNT-WKS-27 spawning an unsigned binary, C:\\Users\\Public\\cl64.exe, as NT AUTHORITY\\SYSTEM at 03:12, a payload started by the Service Control Manager immediately before a burst of destructive activity.",
    }),

    // 1b. The same payload starts on the two other machines the service was pushed to.
    ...fleetHosts.map(h => csProcess({
      companyId: cx, id: `dw_01b_${h.name.toLowerCase().replace("-", "_").replace("-", "_")}_wiper_exec`, ts: T(h.t0), host: h.name, srcIp: h.ip, user: null,
      processName: "cl64.exe", processPath: cl64Path, cmdline: cl64Path, parentName: "services.exe", parentPid: 720, pid: h.pid,
      sha256: wiperHash, signed: false, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1485", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
      extra: { ...osExtra, "file.name": "cl64.exe", "file.hash.sha256": wiperHash, "file.code_signature.exists": false, "file.code_signature.trusted": false, "threat.technique.id": "T1485", "threat.technique.name": "Data Destruction", "threat.tactic.name": "Impact", "threat.tactic.id": "TA0040" },
      description: `Falcon recorded services.exe on ${h.name} starting the unsigned C:\\Users\\Public\\cl64.exe as NT AUTHORITY\\SYSTEM.`,
    })),

    // 1c. The driver is registered as a kernel-mode service by cl64.exe before it loads (System-log 7045).
    winServiceInstall({
      companyId: cx, id: "dw_01c_driver_service_install", ts: T(3 * SEC), host: host.name, fqdn: host.fqdn,
      logSource: "windows_security", targetUser: "SYSTEM", userEmail: null, installerSid: "S-1-5-18",
      serviceName: "epmntdrv", imagePath: "\\SystemRoot\\System32\\drivers\\epmntdrv.sys", accountName: "",
      serviceType: "kernel mode driver", startType: "demand start", recordId: "52732",
      mitre: "T1543.003", tactic: "Privilege Escalation", severity: "high", incidentId: INCIDENT,
      description: "The Service Control Manager on VNT-WKS-27 logged 7045: a new demand-start kernel-mode driver service, epmntdrv, with ImagePath \\SystemRoot\\System32\\drivers\\epmntdrv.sys.",
    }),

    // 2. THE ABUSED DRIVER, Sysmon Event 6 (DriverLoad), a signed 3rd-party partition driver.
    sysmonDriver({
      companyId: cx, id: "dw_02_driver_load", ts: T(4 * SEC), host: host.name, srcIp: host.ip, user: null,
      image: "C:\\Windows\\System32\\drivers\\epmntdrv.sys", sha256: driverHash, signed: true,
      signature: "CHENGDU YIWO Tech Development Co., Ltd.", signatureStatus: "Valid", eventType: "service_install",
      mitre: "T1543.003", tactic: "Privilege Escalation", severity: "high", incidentId: INCIDENT,
      description: "Sysmon Event 6 recorded the kernel driver epmntdrv.sys loading on VNT-WKS-27 seconds after cl64.exe started. The driver is validly signed by a third-party storage-tool vendor; it is loaded to reach the physical disk from kernel mode.",
    }),

    // 3. SHADOW COPIES DELETED, Sysmon Event 1, cl64 spawns vssadmin (T1490).
    sysmonProcess({
      companyId: cx, id: "dw_03_vssadmin_delete", ts: T(20 * SEC), host: host.name, srcIp: host.ip, user: null,
      processName: "vssadmin.exe", processPath: "C:\\Windows\\System32\\vssadmin.exe", cmdline: "vssadmin.exe delete shadows /all /quiet",
      parentName: "cl64.exe", parentPath: cl64Path, parentCmdline: cl64Path, pid: 6712, parentPid: 6620,
      integrity: "System", originalFileName: "VSSADMIN.EXE", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1490", tactic: "Impact", severity: "high", incidentId: INCIDENT,
      description: "Sysmon Event 1 shows cl64.exe spawning vssadmin.exe with 'delete shadows /all /quiet' as SYSTEM on VNT-WKS-27, the on-disk restore points being removed.",
    }),

    // 4. CORROBORATION, Microsoft Defender for Endpoint sees the same vssadmin run (T1490).
    mdeProcess({
      companyId: cx, id: "dw_08_mde_corroboration", ts: T(21 * SEC), host: host.name, srcIp: host.ip, user: null,
      processName: "vssadmin.exe", processPath: "C:\\Windows\\System32\\vssadmin.exe", cmdline: "vssadmin.exe delete shadows /all /quiet",
      parentName: "cl64.exe", pid: 6712, parentPid: 6620, runAsUser: "NT AUTHORITY\\SYSTEM", accountName: "system", accountDomain: "nt authority",
      mitre: "T1490", tactic: "Impact", severity: "high", incidentId: INCIDENT,
      extra: { "Timestamp": T(21 * SEC), "DeviceId": host.id, "InitiatingProcessFolderPath": cl64Path, "InitiatingProcessCommandLine": cl64Path, "InitiatingProcessId": "6620", "InitiatingProcessSHA256": wiperHash, "ReportId": "51830744", "threat.technique.id": "T1490", "threat.technique.name": "Inhibit System Recovery", "threat.tactic.name": "Impact", "threat.tactic.id": "TA0040" },
      description: "Defender for Endpoint, also on VNT-WKS-27, independently recorded the vssadmin shadow deletion. Its DeviceProcessEvents row ties the vssadmin child to the same initiating cl64.exe binary and payload SHA256 as Falcon saw.",
    }),

    // 5. BOOT RECOVERY DISABLED, Sysmon Event 1, bcdedit (T1490).
    sysmonProcess({
      companyId: cx, id: "dw_04_bcdedit_norecovery", ts: T(35 * SEC), host: host.name, srcIp: host.ip, user: null,
      processName: "bcdedit.exe", processPath: "C:\\Windows\\System32\\bcdedit.exe", cmdline: "bcdedit.exe /set {default} recoveryenabled no",
      parentName: "cl64.exe", parentPath: cl64Path, parentCmdline: cl64Path, pid: 6744, parentPid: 6620,
      integrity: "System", originalFileName: "bcdedit.exe", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1490", tactic: "Impact", severity: "high", incidentId: INCIDENT,
      description: "Sysmon Event 1 shows cl64.exe spawning bcdedit.exe to set recoveryenabled to no and ignore boot failures on VNT-WKS-27, the Windows recovery environment being switched off.",
    }),

    // 6. EVENT LOG CLEARED, Falcon process_create, wevtutil (T1685.005).
    csProcess({
      companyId: cx, id: "dw_05_wevtutil_clear", ts: T(50 * SEC), host: host.name, srcIp: host.ip, user: null,
      processName: "wevtutil.exe", processPath: "C:\\Windows\\System32\\wevtutil.exe", cmdline: "wevtutil.exe cl Security",
      parentName: "cl64.exe", parentPid: 6620, pid: 6790, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1685.005", tactic: "Defense Impairment", severity: "high", incidentId: INCIDENT,
      extra: { ...osExtra, "threat.technique.id": "T1685", "threat.technique.subtechnique.id": "T1685.005", "threat.technique.name": "Clear Windows Event Logs", "threat.tactic.name": "Defense Impairment", "threat.tactic.id": "TA0112" },
      description: "Falcon recorded cl64.exe spawning wevtutil.exe with 'cl Security' as SYSTEM on VNT-WKS-27, the Security event log being emptied.",
    }),

    // 7. THE DISK STRUCTURE WIPE: a behavioural IOA summary (precursor, not the ticket-opener) for the raw write
    //    to \\.\PhysicalDrive0 (T1561.002). The sensor does not log disk writes as telemetry, it detects them.
    csAlert({
      companyId: cx, id: "dw_06_raw_disk_write", ts: T(70 * SEC), host: host.name, srcIp: host.ip, user: null, runAsUser: "NT AUTHORITY\\SYSTEM",
      threatName: "RawDiskWrite_MbrOverwrite", mitre: "T1561.002", tactic: "Impact", technique: "Disk Wipe: Disk Structure Wipe",
      action: "detected", severity: "critical", incidentId: INCIDENT, isDetection: false,
      cmdline: cl64Path, sha256: wiperHash, pid: 6620,
      parentPath: "C:\\Windows\\System32\\services.exe", processTree: "services.exe > cl64.exe",
      extra: { ...osExtra, "crowdstrike.TargetFileName": "\\Device\\Harddisk0\\DR0", "threat.technique.id": "T1561", "threat.technique.subtechnique.id": "T1561.002", "threat.technique.name": "Disk Wipe: Disk Structure Wipe", "threat.tactic.name": "Impact", "threat.tactic.id": "TA0040" },
      description: "Falcon recorded cl64.exe issuing raw writes to \\\\.\\PhysicalDrive0 (\\Device\\Harddisk0\\DR0) on VNT-WKS-27: the master boot record and partition table region of the physical disk being overwritten directly, not through the file system.",
    }),

    // 8. FILE CONTENT WIPE: Sysmon Event 11, cl64.exe overwrites user and business files (T1561.001).
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07_file_overwrite", ts: T(80 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\Users\\m.reyes\\Documents\\Q3-forecast.xlsx", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\Users\\m.reyes\\Documents\\Q3-forecast.xlsx on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07b_file_overwrite", ts: T(81 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\Users\\m.reyes\\Documents\\Customer-pricing-2026.xlsx", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\Users\\m.reyes\\Documents\\Customer-pricing-2026.xlsx on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07c_file_overwrite", ts: T(82 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\Users\\m.reyes\\Desktop\\Plant-maintenance-schedule.docx", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\Users\\m.reyes\\Desktop\\Plant-maintenance-schedule.docx on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07d_file_overwrite", ts: T(84 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\Users\\a.novak\\Documents\\Network-diagram-v7.vsdx", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\Users\\a.novak\\Documents\\Network-diagram-v7.vsdx on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07e_file_overwrite", ts: T(86 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\Users\\Public\\Documents\\Supplier-contracts.pdf", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\Users\\Public\\Documents\\Supplier-contracts.pdf on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },
    {
      ...sysmonFile({
        companyId: cx, id: "dw_07f_file_overwrite", ts: T(88 * SEC), host: host.name, srcIp: host.ip, user: null,
        processName: "cl64.exe", processPath: cl64Path, pid: 6620,
        path: "C:\\ProgramData\\Vantage\\ERP\\export\\orders-2026.csv", sha256: null,
        mitre: "T1561.001", tactic: "Impact", severity: "critical", incidentId: INCIDENT,
        description: "Sysmon Event 11 shows cl64.exe writing over C:\\ProgramData\\Vantage\\ERP\\export\\orders-2026.csv on VNT-WKS-27: the file contents being replaced with junk rather than encrypted.",
      }),
      process: { name: "cl64.exe", pid: 6620, path: cl64Path, parent_name: "services.exe", parent_pid: 720, user: "NT AUTHORITY\\SYSTEM", hash: { sha256: wiperHash } },
    },

    // 9. THE DETECTION, Falcon Critical destructive-attack detection, attributes the deploy account.
    {
      ...csAlert({
        companyId: cx, id: "dw_09_edr_detection", ts: T(2 * MIN), host: host.name, srcIp: host.ip, user: null, runAsUser: "NT AUTHORITY\\SYSTEM",
        threatName: "WindowsWiper_DestructiveDiskWrite", mitre: "T1485", tactic: "Impact", technique: "Data Destruction",
        action: "detected", processTree: "services.exe > cl64.exe", severity: "critical", incidentId: INCIDENT,
        detail: "A SYSTEM binary loaded a signed disk driver, deleted the shadow copies, disabled boot recovery, cleared the Security log, and wrote over the raw disk and user files. The remote service that launched it was created under the a.novak account.",
        description: "Falcon raised a Critical detection on VNT-WKS-27: a SYSTEM binary loaded a signed disk driver, deleted the shadow copies, disabled boot recovery, cleared the Security log, and wrote over the raw disk and user files. The remote service that launched it was created under the a.novak account.",
      }),
      edr_scope: "edr",
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.name, // VNT-WKS-27, the bricked endpoint
      first_seen: T(0),
      last_seen: T(2 * MIN),
      // "unknown", not "malicious": this is the organisation's own endpoint -
      // the victim, not adversary infrastructure.
      reputation: "unknown",
      tags: ["endpoint", "affected"],
    },
    {
      type: "user",
      value: deployAdmin.sam, // a.novak: the compromised deployment account
      first_seen: T(-31 * MIN),
      last_seen: T(-3 * SEC),
      reputation: "suspicious",
      tags: ["deployment", "privileged"],
    },
    {
      type: "sha256",
      value: wiperHash, // cl64.exe, the wiper payload
      first_seen: T(0),
      last_seen: T(2 * MIN),
      reputation: "malicious",
      tags: ["payload", "unsigned"],
    },
    {
      type: "host",
      value: deploySrc.name, // VNT-DEPLOY-01, where a.novak's session pushed the payload from
      first_seen: T(-80 * SEC),
      last_seen: T(-3 * SEC),
      reputation: "suspicious",
      tags: ["deployment-server"],
    },
    {
      type: "ip",
      value: vpnSrcIp, // the VPN source address of the a.novak login
      first_seen: T(-31 * MIN),
      last_seen: T(-31 * MIN),
      reputation: "malicious",
      tags: ["external", "vpn-source"],
    },
    {
      type: "host",
      value: "VNT-WKS-31", // second machine the service was pushed to
      first_seen: T(-7 * SEC),
      last_seen: T(1 * SEC),
      reputation: "unknown",
      tags: ["affected"],
    },
    {
      type: "host",
      value: "VNT-WKS-33", // third machine the service was pushed to
      first_seen: T(-5 * SEC),
      last_seen: T(3 * SEC),
      reputation: "unknown",
      tags: ["affected"],
    },
    {
      type: "sha256",
      value: driverHash, // epmntdrv.sys, the signed driver abused for raw disk access
      first_seen: T(4 * SEC),
      last_seen: T(4 * SEC),
      reputation: "malicious",
      tags: ["kernel-driver", "signed"],
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
        { value: "coordinated_wipe", label: "A single SYSTEM binary junking the raw disk and user files while deleting restore points, disabling boot recovery and clearing the log" },
        { value: "ransomware_note", label: "A ransomware payload encrypting the files on the host and dropping a note in each affected directory before contacting its key server" },
        { value: "backup_maintenance", label: "A backup agent taking scheduled volume snapshots and pruning older restore points and logs as part of a routine nightly maintenance job" },
        { value: "disk_repair", label: "A disk-defragmentation and check-disk pass reorganising sectors, which accounts for the heavy write activity and the reboot that followed" },
      ],
      answer: "coordinated_wipe",
      explanation:
        "Read together, the four children are a demolition, not housekeeping: vssadmin removes the shadow copies, bcdedit switches off the Windows recovery environment, wevtutil empties the Security log, and the raw write to \\\\.\\PhysicalDrive0 destroys the boot structures, with a parallel overwrite of user files. Nothing here encrypts data. It is not ransomware (there is no encryption and no note, see the next question), not a backup agent (a backup does not clear the event log or write over the raw disk), and not a defrag/chkdsk pass (those do not delete shadow copies, disable recovery, or wipe logs). This is coordinated destruction whose whole point is to make the machine unrecoverable.",
    },
    {
      id: "dw_q2",
      xp: 70,
      kind: "single",
      prompt:
        "VNT-WKS-27 is now unbootable and its files are gibberish. It looks ransomware-adjacent, mass writes, shadow-copy deletion, boot tampering. Why is this a wiper rather than recoverable ransomware?",
      hint: "Ask what a victim would need in order to get their data back, and whether anything in the evidence could ever provide it.",
      options: [
        { value: "no_recovery_path", label: "No encryption and no note, sectors and files are overwritten with junk and backups and boot config destroyed, so no key could restore them" },
        { value: "note_pending", label: "It is ransomware whose note has not been written yet; in this family the wiping stage runs first and the extortion message follows minutes later" },
        { value: "reversible", label: "It is recoverable: deleting shadow copies is undone with 'vssadmin resize', and the boot record is rebuilt with 'bootrec /fixmbr', so the host comes straight back" },
        { value: "decryptor_c2", label: "It is ransomware whose decryptor is pulled from its command-and-control server once the operator has confirmed the victim's payment on the portal" },
      ],
      answer: "no_recovery_path",
      explanation:
        "The defining difference is the recovery path. Ransomware encrypts data reversibly and monetises the key: there is a ransom note, and paying (in principle) yields a decryptor. Here there is no encryption, no note, and no C2 to fetch a decryptor, the disk sectors and files are overwritten with junk and the shadow copies and boot config are destroyed, so there is literally no key or secret that could put the data back. 'Note pending' is wrong: no note is coming because none is part of the design. 'Reversible' is wrong: once the raw sectors are overwritten, vssadmin resize and bootrec /fixmbr have nothing to rebuild from. And there is no decryptor to fetch. The objective is destruction/denial, which is exactly why the response cannot be 'wait for or pay the demand'.",
    },
    {
      id: "dw_q3",
      xp: 65,
      kind: "single",
      prompt:
        "Sysmon Event 6 shows epmntdrv.sys, a validly-signed third-party storage driver, loading on VNT-WKS-27 moments after cl64.exe started. What role does loading that driver serve?",
      hint: "A normal user-mode program cannot freely write over the physical disk. Think about what a kernel driver grants that user mode does not.",
      options: [
        { value: "kernel_raw_access", label: "It gives the payload kernel-mode raw access to \\\\.\\PhysicalDrive0, so it can overwrite the boot record and partition table directly" },
        { value: "vendor_update", label: "It is a routine signed driver update pushed by the storage vendor, unrelated to the process that happened to start immediately before it" },
        { value: "edr_minifilter", label: "It installs the endpoint agent's own mini-filter driver so the security tool can inspect the raw disk writes the process is making" },
        { value: "encrypted_container", label: "It mounts an encrypted container as a virtual disk, which is where the operator stages the collected files before exfiltrating them" },
      ],
      answer: "kernel_raw_access",
      explanation:
        "A user-mode process cannot freely scribble over the raw physical disk, the file system and its permissions are in the way. Loading a signed driver that exposes low-level disk I/O gives the malware kernel-mode raw access to \\\\.\\PhysicalDrive0, so it can overwrite the master boot record and partition structures directly. Abusing a legitimately-signed third-party driver this way is a hallmark of real wipers (HermeticWiper leaned on exactly this kind of signed partition-management driver). It is not a coincidental vendor update (the timing and the raw writes that follow make that clear), not the EDR's own mini-filter, and not an encrypted container, there is no exfiltration here, only destruction.",
    },
    {
      id: "dw_q4",
      xp: 60,
      kind: "single",
      prompt:
        "The night before, VNT-WKS-19 logged sdelete64.exe securely deleting C:\\Users (dw_00), with change ticket CHG0020418 visible in the change record. Why is that event benign while the VNT-WKS-27 activity is an incident, when both are 'a disk being overwritten'?",
      hint: "Compare the tool and its signer, the account and its authorisation, and whether backups and logs were destroyed alongside the wipe.",
      options: [
        { value: "authorised_scoped", label: "sdelete is a signed Sysinternals tool a named IT account ran on a host being decommissioned under an approved change, with no shadow, boot or log tampering" },
        { value: "no_difference", label: "There is no real difference in intent; both are disk wipes, so VNT-WKS-19 should be raised as a second destructive incident belonging to the same campaign" },
        { value: "sdelete_harmless", label: "sdelete only clears free space and cannot affect live data, so running it against a drive is harmless whichever account launches it" },
        { value: "integrity_rule", label: "The VNT-WKS-19 run was at high integrity rather than SYSTEM, and a wipe running below SYSTEM integrity is the mark of an authorised admin action" },
      ],
      answer: "authorised_scoped",
      explanation:
        "Same shape, opposite verdict, and the discriminator is authorisation and surrounding behaviour, not the wipe. On VNT-WKS-19 a signed, Microsoft-published Sysinternals tool was run by a named IT account, under the approved change CHG0020418 (visible in the change record and confirmed by IT), against a host being decommissioned in its change window, and it did nothing else: no shadow-copy deletion, no boot-recovery change, no log clearing. VNT-WKS-27 is an unsigned SYSTEM binary that chained all of those recovery-inhibiting and log-clearing steps with no ticket behind it. 'No difference in intent' ignores the ticket and the context. 'sdelete is harmless' is false: run with -s against C:\\Users, sdelete irreversibly destroys the files, which is exactly what the change authorised. And the integrity level is not the test: plenty of legitimate admin actions run as SYSTEM, and plenty of malicious ones do not.",
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
        "Because the data is destroyed, not encrypted, recovery means rebuild, not decrypt: image the affected hosts for forensics, then restore from offline or immutable backups that the wiper could not reach. In parallel, close the door on the next host, reset the compromised a.novak account and hunt the fleet for the remote service-creation mechanism that pushed and launched cl64.exe as SYSTEM: the same cl64svc service was created on VNT-WKS-31 and VNT-WKS-33 within seconds of VNT-WKS-27, and the deployment server VNT-DEPLOY-01 is where a.novak's VPN-fed session ran sc.exe. Paying the operator is meaningless here: there is no key and no portal, so there is nothing to buy back. And chkdsk /r cannot help, once the raw sectors and the MBR are overwritten with junk there is nothing for it to repair or recover.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Critical detection and unbootable machines at Vantage Industrial",
    threat_actor: "Destructive intrusion operator (data-destruction objective, wiper deployed via a compromised admin)",
    attack_kind: "destructive_attack",
    briefing:
      "Falcon raised a Critical detection on VNT-WKS-27 at 03:14, and the Service Desk reports that several machines have rebooted to \"No operating system found\". Establish what executed, how it got there, and how far it spread.",
    narrative: `VNT-WKS-27 is a workstation at Vantage Industrial. The chain started at 02:41, when the FortiGate SSL-VPN logged a tunnel for the administrator account a.novak from 196.251.33.74 in Lagos. At 03:10:40 that account opened an RDP session on the deployment server VNT-DEPLOY-01 from the tunnel address, copied D:\\Tools\\cl64.exe to the C$ share of VNT-WKS-27, and used sc.exe to create and start a service for it; the same service, cl64svc, was created on VNT-WKS-31 and VNT-WKS-33 within seconds. At 03:12 the Service Control Manager launched the unsigned binary C:\\Users\\Public\\cl64.exe on VNT-WKS-27 as NT AUTHORITY\\SYSTEM.

Within seconds cl64.exe registered and loaded a validly-signed third-party storage driver, epmntdrv.sys, to obtain kernel-mode raw access to the physical disk. It then worked through a short, deliberate sequence: vssadmin deleted the Volume Shadow Copies, bcdedit set recoveryenabled to no, and wevtutil cleared the Security event log. With the on-disk restore points gone, boot recovery disabled, and the trail wiped, it wrote junk directly over \\\\.\\PhysicalDrive0, destroying the master boot record and partition table, and overwrote user and business files such as Q3-forecast.xlsx with garbage. The machine was unbootable moments later.

The night before, the same estate had cleanly and legitimately wiped VNT-WKS-19: signed Sysinternals sdelete, run by the IT decommissioning account under the approved change CHG0020418 (visible in the change record), in its change window, on a host being disposed of. That is the control case, the same 'a disk is being overwritten' shape, but authorised, scoped, and unaccompanied by any destruction of backups or logs.

This is where the exercise bites. Everything about VNT-WKS-27 rhymes with ransomware, mass writes, shadow-copy deletion, boot tampering, but there is no encryption to a key, no ransom note, and no command-and-control to hand back a decryptor. The data is not locked; it is gone. Defender for Endpoint independently logged the vssadmin shadow deletion against the same cl64.exe payload hash, and Falcon raised the Critical destructive-attack detection at 03:14. The job is to recognise a wiper for what it is, destruction, not extortion, and to scope a response that rebuilds rather than waits for a key that will never come.`,
    learning_objectives: [
      "Read a destructive process tree (a signed-driver load, vssadmin 'delete shadows', bcdedit 'recoveryenabled no', wevtutil 'cl', a raw \\\\.\\PhysicalDrive0 write, file overwrites) and recognise coordinated data destruction plus recovery inhibition",
      "Distinguish a wiper from ransomware by the ABSENCE of an encryption key, a ransom note, and a C2 decryptor path, the objective is denial/destruction, not extortion, so the data is gone rather than locked",
      "Recognise abuse of a validly-signed third-party kernel driver loaded to reach \\\\.\\PhysicalDrive0 from kernel mode as the mechanism for overwriting disk structures beneath the file system",
      "Separate an authorised, change-ticketed secure-wipe/decommission (signed Sysinternals tool, named IT account, maintenance window) from a malicious wipe that also destroys backups and clears logs",
      "Scope response for a destructive attack: preserve forensic images, rebuild from offline/immutable backups, reset the compromised deployment account, and hunt the fleet for the delivery mechanism, do not expect a decryptor",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-31 * MIN), phase: "Initial Access", action: `a.novak authenticates to the FortiGate SSL-VPN from ${vpnSrcIp} (T1133)` },
      { ts: T(-80 * SEC), phase: "Lateral Movement", action: `a.novak opens an RDP session on ${deploySrc.name} from the tunnel address ${vpnTunnelIp} (T1021.001)` },
      { ts: T(-50 * SEC), phase: "Lateral Movement", action: `a.novak network logon (4624 type 3) to ${host.name} from ${deploySrc.name} (T1021.002)` },
      { ts: T(-44 * SEC), phase: "Lateral Movement", action: `cl64.exe copied from ${deploySrc.name} to the C$ share of ${host.name} (T1570)` },
      { ts: T(-14 * SEC), phase: "Execution", action: `sc.exe on ${deploySrc.name} creates cl64svc on ${host.name} (T1569.002)` },
      { ts: T(-8 * SEC), phase: "Execution", action: "Remote service cl64svc created for C:\\Users\\Public\\cl64.exe as LocalSystem (7045, T1569.002); the same service appears on VNT-WKS-31 and VNT-WKS-33" },
      { ts: T(0), phase: "Impact", action: `Unsigned cl64.exe launched as SYSTEM by the SCM on ${host.name} (T1485)` },
      { ts: T(3 * SEC), phase: "Privilege Escalation", action: "Driver service epmntdrv created (7045) and signed driver epmntdrv.sys loaded for kernel-mode raw disk access (T1543.003)" },
      { ts: T(20 * SEC), phase: "Impact", action: "vssadmin delete shadows /all /quiet: Volume Shadow Copies removed (T1490)" },
      { ts: T(35 * SEC), phase: "Impact", action: "bcdedit /set {default} recoveryenabled no: boot recovery disabled (T1490)" },
      { ts: T(50 * SEC), phase: "Defense Impairment", action: "wevtutil cl Security: Security event log cleared (T1685.005, formerly T1070.001)" },
      { ts: T(70 * SEC), phase: "Impact", action: "Raw write to \\\\.\\PhysicalDrive0: MBR and partition table destroyed (T1561.002)" },
      { ts: T(80 * SEC), phase: "Impact", action: "User and business files overwritten with junk (T1561.001)" },
      { ts: T(2 * MIN), phase: "Detection", action: "Falcon raises the Critical destructive-attack detection" },
    ],
    questions,
  };
}
