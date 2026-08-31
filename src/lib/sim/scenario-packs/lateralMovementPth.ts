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

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the legitimate way to reach SRV-FILE-03.
    //    A prior-day 4624: same event ID, same LogonType 3, but Kerberos,
    //    from the user's own workstation, in business hours. This is what a
    //    normal network logon to the file server looks like.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_00_benign_logon",
      ts: "2026-08-26T13:12:04Z",
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: fileSrv.hostname,
      user_email: benign.email,
      src_ip: benignWs.ip,
      severity: "informational",
      fp_explanation:
        "Legitimate Type-3 network logon to the file server: Kerberos (the in-domain default), from the user's OWN workstation FIN-WS-22, at 13:12 on a business day. Same 4624 / LogonType 3 as the attack — the difference is the authentication package, the source host, and the hour.",
      description:
        "A 4624 network logon for m.rossi on SRV-FILE-03 at 13:12 the previous afternoon, LogonType 3 over Kerberos, from her own workstation FIN-WS-22.",
      authentication: { method: "Kerberos", result: "success", logon_type: 3 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5540912",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": benignSid,
        "winlog.event_data.TargetUserName": benign.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x5A11C02",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": benignWs.hostname,
        "winlog.event_data.IpAddress": benignWs.ip,
        "winlog.event_data.IpPort": "50142",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": benignWs.ip,
        "user.name": benign.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE SOURCE OF THE HASH — LSASS access on the foothold FIN-WS-11.
    //    Sysmon Event 10: a masquerading process opens lsass.exe with the
    //    access rights a credential dumper needs (0x1410). This is where the
    //    NTLM hash the operator is about to replay came from (T1003.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_01_lsass_access",
      ts: T(0),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_access",
      hostname: foothold.hostname,
      src_ip: foothold.ip,
      severity: "high",
      mitre_technique: "T1003.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "On the foothold host FIN-WS-11 a process running from C:\\Windows\\Temp opened lsass.exe with GrantedAccess 0x1410 at 02:00 — the read/query rights a credential dumper uses to lift hashes from memory.",
      process: {
        name: "svchost.exe",
        pid: 6624,
        path: "C:\\Windows\\Temp\\svchost.exe",
        cmdline: "C:\\Windows\\Temp\\svchost.exe",
        user: `NEXACORP\\${admin.sam}`,
      },
      raw: {
        // Sysmon Event 10 — ProcessAccess
        "winlog.event_id": "10",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": foothold.fqdn,
        "winlog.event_data.SourceImage": "C:\\Windows\\Temp\\svchost.exe",
        "winlog.event_data.SourceProcessId": "6624",
        "winlog.event_data.TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "winlog.event_data.TargetProcessId": "712",
        "winlog.event_data.GrantedAccess": "0x1410",
        "winlog.event_data.CallTrace":
          "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|C:\\Windows\\System32\\KERNELBASE.dll+2a1ee|UNKNOWN(0000000abc120000)",
        "winlog.event_data.User": `NEXACORP\\${admin.sam}`,
        "host.name": foothold.hostname,
        "host.ip": foothold.ip,
        "event.code": "10",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE PASS-THE-HASH LANDING — a 4624 on SRV-FILE-03 that looks ordinary.
    //    Type 3, NTLM, from FIN-WS-11's IP and workstation name, off-hours.
    //    No password was ever typed; the hash alone authenticated (T1550.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_02_pth_logon",
      ts: T(4 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: foothold.ip,
      severity: "high",
      mitre_technique: "T1550.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "A 4624 network logon for s.kessler arrived on SRV-FILE-03 at 02:04, LogonType 3 over NTLM, from FIN-WS-11 (10.20.6.41) — a finance workstation reaching a file server as an infrastructure admin, at night.",
      authentication: { method: "NTLM", result: "success", logon_type: 3 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5551338",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": admin.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x6C41F70",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.WorkstationName": foothold.hostname,
        "winlog.event_data.LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "winlog.event_data.IpAddress": foothold.ip,
        "winlog.event_data.IpPort": "49277",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": foothold.ip,
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. 4672 — the logon carried admin privileges. Confirms the replayed
    //    hash belongs to a highly-privileged account, not an ordinary user.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_03_special_privs",
      ts: T(4 * MIN + 6 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privilege_escalation",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: foothold.ip,
      severity: "medium",
      mitre_technique: "T1078",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      description:
        "A 4672 on SRV-FILE-03 assigned SeDebugPrivilege, SeTcbPrivilege and SeBackupPrivilege to the s.kessler logon session — this NTLM network logon is running with local-administrator rights.",
      raw: {
        // Windows Security Event 4672 — Special privileges assigned to new logon
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5551339",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x6C41F70",
        "winlog.event_data.PrivilegeList":
          "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeTcbPrivilege",
        "event.code": "4672",
        "event.action": "logged-in-special",
        "event.outcome": "success",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. 5140 — the ADMIN$ administrative share is opened. This is the SMB
    //    channel PsExec-style remote execution rides on (T1021.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_04_admin_share",
      ts: T(4 * MIN + 22 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "file_access",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: foothold.ip,
      severity: "high",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "SRV-FILE-03 logged a 5140 connection to the ADMIN$ administrative share under the s.kessler session from 10.20.6.41 — the hidden share used to stage and launch remote code, not a normal file access.",
      raw: {
        // Windows Security Event 5140 — A network share object was accessed
        "winlog.event_id": "5140",
        "winlog.channel": "Security",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5551361",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x6C41F70",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.IpAddress": foothold.ip,
        "winlog.event_data.IpPort": "49277",
        "winlog.event_data.ShareName": "\\\\*\\ADMIN$",
        "winlog.event_data.ShareLocalPath": "\\??\\C:\\Windows",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.AccessList": "%%4416",
        "event.code": "5140",
        "event.action": "share-accessed",
        "event.outcome": "success",
        "source.ip": foothold.ip,
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. 7045 — a service is installed remotely on SRV-FILE-03. Auto-start,
    //    binary dropped into C:\Windows, running as LocalSystem. This is the
    //    PsExec / remote-service-creation pattern (T1569.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_05_service_install",
      ts: T(5 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "service_install",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: foothold.ip,
      severity: "high",
      mitre_technique: "T1569.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "A 7045 on SRV-FILE-03 recorded a new auto-start service, WinSvcUpdate, whose binary C:\\Windows\\svcupd64.exe runs as LocalSystem — a service created over the ADMIN$ session moments after the NTLM logon.",
      raw: {
        // Windows Security / System Event 7045 — A new service was installed
        "winlog.event_id": "7045",
        "winlog.channel": "System",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Service Control Manager",
        "winlog.record_id": "884012",
        "winlog.event_data.AccountName": "LocalSystem",
        "winlog.event_data.ServiceName": "WinSvcUpdate",
        "winlog.event_data.ImagePath": "C:\\Windows\\svcupd64.exe",
        "winlog.event_data.ServiceType": "user mode service",
        "winlog.event_data.StartType": "auto start",
        "event.code": "7045",
        "event.action": "service-installed",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. Sysmon Event 1 — the service binary executes: services.exe (the SCM)
    //    spawns C:\Windows\svcupd64.exe. Unsigned, from an unusual location.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_06_service_exec",
      ts: T(5 * MIN + 9 * SEC),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: fileSrv.ip,
      severity: "high",
      mitre_technique: "T1569.002",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "Sysmon recorded services.exe on SRV-FILE-03 spawning C:\\Windows\\svcupd64.exe as LocalSystem — the installed service starting, an unsigned binary launched by the Service Control Manager.",
      process: {
        name: "svcupd64.exe",
        pid: 8104,
        path: "C:\\Windows\\svcupd64.exe",
        parent_name: "services.exe",
        parent_pid: 720,
        cmdline: "C:\\Windows\\svcupd64.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: svcBinaryHash },
      },
      raw: {
        // Sysmon Event 1 — ProcessCreate
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.event_data.Image": "C:\\Windows\\svcupd64.exe",
        "winlog.event_data.OriginalFileName": "svcupd64.exe",
        "winlog.event_data.CommandLine": "C:\\Windows\\svcupd64.exe",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\services.exe",
        "winlog.event_data.ParentProcessId": "720",
        "winlog.event_data.ProcessId": "8104",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "winlog.event_data.Hashes": `SHA256=${svcBinaryHash}`,
        "winlog.event_data.Signed": "false",
        "host.name": fileSrv.hostname,
        "host.ip": fileSrv.ip,
        "process.name": "svcupd64.exe",
        "process.hash.sha256": svcBinaryHash,
        "event.code": "1",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. 4688 — the payload spawns an encoded PowerShell child. Windows
    //    Security process creation, showing the service binary is a launcher.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_07_payload_powershell",
      ts: T(5 * MIN + 12 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "process_create",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: fileSrv.ip,
      severity: "high",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "A 4688 on SRV-FILE-03 shows svcupd64.exe spawning an encoded, hidden-window PowerShell as SYSTEM — the remotely-installed service acting as a loader.",
      process: {
        name: "powershell.exe",
        pid: 8260,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "svcupd64.exe",
        parent_pid: 8104,
        cmdline: "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        // Windows Security Event 4688 — A new process has been created
        "winlog.event_id": "4688",
        "winlog.channel": "Security",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5551402",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "SRV-FILE-03$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.NewProcessId": "0x2044",
        "winlog.event_data.NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.CommandLine": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        "winlog.event_data.ParentProcessName": "C:\\Windows\\svcupd64.exe",
        "winlog.event_data.TokenElevationType": "%%1936",
        "winlog.event_data.MandatoryLabel": "S-1-16-16384",
        "event.code": "4688",
        "event.action": "created-process",
        "event.outcome": "success",
        "user.name": "SRV-FILE-03$",
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. Sysmon Event 3 — the payload reaches toward the DC over SMB (445).
    //    The second hop being set up: SRV-FILE-03 → DC-NEXA-01.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_08_smb_to_dc",
      ts: T(6 * MIN),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "net_connection",
      hostname: fileSrv.hostname,
      src_ip: fileSrv.ip,
      dst_ip: dc.ip,
      dst_port: 445,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "Sysmon recorded powershell.exe on SRV-FILE-03 opening an outbound TCP/445 (SMB) connection to DC-NEXA-01 (10.20.5.10) — the operator pivoting from the file server toward a Domain Controller.",
      raw: {
        // Sysmon Event 3 — NetworkConnect
        "winlog.event_id": "3",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": fileSrv.fqdn,
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ProcessId": "8260",
        "winlog.event_data.Protocol": "tcp",
        "winlog.event_data.Initiated": "true",
        "winlog.event_data.SourceIp": fileSrv.ip,
        "winlog.event_data.SourceHostname": fileSrv.fqdn,
        "winlog.event_data.SourcePort": "51993",
        "winlog.event_data.DestinationIp": dc.ip,
        "winlog.event_data.DestinationHostname": dc.fqdn,
        "winlog.event_data.DestinationPort": "445",
        "winlog.event_data.DestinationPortName": "microsoft-ds",
        "host.name": fileSrv.hostname,
        "host.ip": fileSrv.ip,
        "destination.ip": dc.ip,
        "destination.port": "445",
        "event.code": "3",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. CrowdStrike Falcon detection on SRV-FILE-03 — alert-grade. Ties the
    //    NTLM network logon, the remote service, and the DC-bound SMB into one
    //    pass-the-hash detection. is_detection + edr_scope "hybrid".
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_09_edr_detection",
      ts: T(6 * MIN + 40 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: fileSrv.ip,
      severity: "critical",
      mitre_technique: "T1550.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      is_detection: true,   // the Falcon detection that opened the incident
      edr_scope: "hybrid",  // host artifacts (remote service, PS loader) + the AD NTLM logon that delivered the operator — pivot to EDR for SRV-FILE-03
      description:
        "Falcon raised a Critical detection on SRV-FILE-03: an NTLM network logon for a privileged account from a workstation, followed by a remotely-installed service and an encoded PowerShell reaching a Domain Controller — a pass-the-hash lateral-movement pattern.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "PassTheHashRemoteServiceExecution",
        "crowdstrike.detection.tactic": "Lateral Movement",
        "crowdstrike.detection.technique": "Use Alternate Authentication Material: Pass the Hash",
        "crowdstrike.detection.technique_id": "T1550.002",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.process_tree": "services.exe > svcupd64.exe > powershell.exe",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.sensor.id": sensorId,
        "host.name": fileSrv.hostname,
        "host.ip": fileSrv.ip,
        "user.name": `NEXACORP\\${admin.sam}`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 10. THE SECOND HOP — a 4624 on the DC, same account, same hash, now
    //     from SRV-FILE-03. NTLM Type-3 again (T1550.002 / T1021.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_10_dc_logon",
      ts: T(8 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: dc.hostname,
      user_email: admin.email,
      src_ip: fileSrv.ip,
      severity: "critical",
      mitre_technique: "T1550.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "A 4624 network logon for s.kessler landed on DC-NEXA-01 at 02:08, LogonType 3 over NTLM, this time sourced from SRV-FILE-03 (10.20.7.28) — the same replayed hash reaching a Domain Controller one hop on.",
      authentication: { method: "NTLM", result: "success", logon_type: 3 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "9920551",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": admin.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x8B03D19",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.WorkstationName": fileSrv.hostname,
        "winlog.event_data.IpAddress": fileSrv.ip,
        "winlog.event_data.IpPort": "52140",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": fileSrv.ip,
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 11. Microsoft Sentinel correlation (fed by Defender for Identity) — the
    //     alert that opened the ticket, tying the chain across all three hosts.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_lm_11_sentinel_correlation",
      ts: T(9 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: fileSrv.hostname,
      user_email: admin.email,
      src_ip: foothold.ip,
      severity: "critical",
      mitre_technique: "T1550.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "Sentinel raised a correlation alert, enriched by Defender for Identity, for s.kessler: NTLM authentications traversing FIN-WS-11 → SRV-FILE-03 → DC-NEXA-01 in nine minutes off-hours, with the account's normal logon pattern attached for comparison.",
      raw: {
        "AlertName": "LateralMovement_PassTheHash_MultiHop",
        "alert.rule.id": "SEN-IDENT-0342",
        "alert.severity": "High",
        "target.user.name": `NEXACORP\\${admin.sam}`,
        "user.full_name": "Sofia Kessler",
        "user.department": "IT Infrastructure",
        "user.title": admin.title,
        "user.group.name": ["Domain Users", "Server Operators", "Backup Operators"],
        "host.name": fileSrv.hostname,
        "threat.technique.id": "T1550.002",
        "threat.technique.name": "Use Alternate Authentication Material: Pass the Hash",
        "threat.tactic.name": "Lateral Movement",
        "ExtendedProperties.DefenderForIdentity Detection": "Suspected identity theft (pass-the-hash)",
        "ExtendedProperties.Authentication Package": "NTLM",
        "ExtendedProperties.Hosts In Path": ["FIN-WS-11", "SRV-FILE-03", "DC-NEXA-01"],
        "ExtendedProperties.Window Start": T(4 * MIN),
        "ExtendedProperties.Window End": T(8 * MIN),
        "ExtendedProperties.Usual Logon Hours": "08:00-19:00",
        "ExtendedProperties.Usual Auth Protocol": "Kerberos",
        "ExtendedProperties.Source Addresses In Window": [foothold.ip, fileSrv.ip],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
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
        { value: "privs", label: "evt_lm_03_special_privs — the 4672 assigning admin privileges on SRV-FILE-03" },
        { value: "service", label: "evt_lm_05_service_install — the 7045 remote service creation" },
        { value: "sentinel", label: "evt_lm_11_sentinel_correlation — the Sentinel alert that named the technique" },
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
        { value: "block_ip", label: "Block 10.20.6.41 at the firewall — cutting the source address stops the lateral movement" },
        { value: "reset_mfa", label: "Reset s.kessler's MFA and require MFA on the next logon; that neutralises the pass-the-hash" },
        { value: "reimage_fileserver", label: "Reimage SRV-FILE-03 only — the file server is where the service ran, so removing it ends the incident" },
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
