/**
 * Scenario pack: "SYSTEM in Twelve Seconds — Token Impersonation on an IIS Host"
 *
 * INTERMEDIATE tier. A web-application service account, svc-web, is already
 * compromised (the initial foothold — a webshell in the IIS worker process — is
 * out of scope for this ticket). svc-web is not a local administrator and never
 * needs to be. But like most IIS application-pool identities it is granted
 * SeImpersonatePrivilege, and that single privilege is the whole game: it lets
 * the account impersonate any security token it can get a handle to, including
 * the token of a SYSTEM service.
 *
 * The attacker drops a PrintSpoofer/potato-style tool, coerces the Print Spooler
 * service (spoolsv.exe, running as SYSTEM) into connecting to an attacker-owned
 * named pipe, impersonates the SYSTEM token that connection yields, and launches
 * a shell as NT AUTHORITY\SYSTEM. From SYSTEM it exports the local SAM hive to
 * dump the built-in Administrator's password hash.
 *
 * The pedagogy: every loud, obviously-bad event here (the SYSTEM shell, the SAM
 * export) is downstream. The event that MADE it all possible is quiet and looks
 * like routine housekeeping — the 4672 that says svc-web logged on holding
 * SeImpersonatePrivilege. A strong analyst reads the precondition, not just the
 * payload, and the whole chain is reconstructable from the telemetry: the
 * privilege assignment (4672), the tool launch (Sysmon 1), the spooler coercion
 * (Sysmon 18 named pipe), the token handle (Sysmon 10, GrantedAccess 0x1410),
 * the sensitive-privilege use (4673), the SYSTEM process (4688, full token), and
 * the credential dump (MDE). Nothing in the raw states the verdict.
 *
 * NOTE: `difficulty: "intermediate"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field). This pack
 * is NOT registered here — the catalogue wiring does that.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256, makeMd5 } from "@/lib/sim/iocs";

export function buildWindowsPrivescTokenScenario(
  scenarioId = "windows-privesc-token-2026",
): ScenarioBundle {
  const B = new Date("2026-08-14T02:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const SEC = 1_000;
  const MIN = 60_000;

  // The public-facing IIS host. NexaCorp's product marketing site + a couple of
  // internal web apps share this application server.
  const host = { hostname: "WEB-APP-04", fqdn: "WEB-APP-04.nexacorp.com", ip: "10.30.5.40" };

  // The IIS application-pool identity. Runs w3wp.exe. Not a local admin. Holds
  // SeImpersonatePrivilege because every IIS service account does — that is the
  // crux of the whole incident.
  const svc = { sam: "svc-web", domain: "NEXACORP" };
  const svcSid = "S-1-5-21-3421479547-3897544621-1789562108-5107";
  const svcLogonId = "0x8F41C2";

  // The dropped token-impersonation tool (PrintSpoofer/potato family). Signed by
  // nobody; sitting in a world-writable temp directory it has no business in.
  const toolPath = "C:\\Windows\\Temp\\spf.exe";
  const toolSha256 = makeSha256("printspoofer_token_impersonation_tool_webapp04_nexacorp");
  const toolMd5 = makeMd5("printspoofer_token_impersonation_tool_webapp04_nexacorp");
  const toolImphash = makeMd5("printspoofer_imphash_webapp04");

  // The SAM hive the SYSTEM shell exports to steal the local Administrator hash.
  const samDumpPath = "C:\\Windows\\Temp\\sam.save";

  // One incident. Everything below is host-observable on WEB-APP-04 — Windows
  // Security + Sysmon + the MDE detection — so this is an EDR-scope investigation:
  // there is a real process tree to walk from w3wp.exe down to the SYSTEM shell.
  const INCIDENT = "inc:wpe:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Routine baseline — the IIS app-pool identity logs on as a service.
    //    LogonType 5. Hundreds of these a week; entirely normal on its own.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_01_service_logon",
      ts: T(0),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: host.hostname,
      severity: "informational",
      mitre_technique: "T1078.003",
      mitre_tactic: "Persistence",
      description:
        "A 4624 LogonType 5 on WEB-APP-04 for the service account NEXACORP\\svc-web — the IIS application pool starting under its assigned identity.",
      authentication: { method: "Negotiate", result: "success", logon_type: 5 },
      raw: {
        // Windows Security Event 4624 — An account was successfully logged on
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": host.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5540911",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WEB-APP-04$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": svcSid,
        "winlog.event_data.TargetUserName": svc.sam,
        "winlog.event_data.TargetDomainName": svc.domain,
        "winlog.event_data.TargetLogonId": svcLogonId,
        "winlog.event_data.LogonType": "5",
        "winlog.event_data.LogonProcessName": "Advapi  ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "winlog.event_data.ProcessId": "0x2f4",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\services.exe",
        "winlog.event_data.IpAddress": "-",
        "winlog.event_data.IpPort": "-",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 2. THE PRECONDITION — 4672 records the privileges that logon holds.
    //    SeImpersonatePrivilege is in the list. This is the entire reason the
    //    rest of the chain is possible, and it looks like boilerplate.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_02_special_privs",
      ts: T(1 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privileged_operation",
      hostname: host.hostname,
      severity: "low",
      mitre_technique: "T1078.003",
      mitre_tactic: "Privilege Escalation",
      description:
        "A 4672 on WEB-APP-04 for the svc-web logon session (0x8F41C2), enumerating the special privileges assigned to it at logon.",
      raw: {
        // Windows Security Event 4672 — Special privileges assigned to new logon
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": host.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5540912",
        "winlog.event_data.SubjectUserSid": svcSid,
        "winlog.event_data.SubjectUserName": svc.sam,
        "winlog.event_data.SubjectDomainName": svc.domain,
        "winlog.event_data.SubjectLogonId": svcLogonId,
        // The privilege that PrintSpoofer/potato attacks require. Present here on
        // a NON-admin service account — exactly the dangerous-but-common grant.
        "winlog.event_data.PrivilegeList":
          "SeAssignPrimaryTokenPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeCreateGlobalPrivilege\n\t\t\tSeChangeNotifyPrivilege\n\t\t\tSeIncreaseWorkingSetPrivilege",
        "event.code": "4672",
        "event.action": "special-privileges-assigned",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 3. The webshell speaks — the IIS worker spawns a shell. Parent is w3wp.exe.
    //    A web app should never launch cmd.exe. This is the foothold surfacing.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_03_w3wp_spawns_cmd",
      ts: T(3 * MIN),
      source: "sysmon",
      vendor: "Sysmon",
      event_type: "process_create",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1505.003",
      mitre_tactic: "Persistence",
      description:
        "Sysmon Event 1 on WEB-APP-04: the IIS worker w3wp.exe spawned cmd.exe under the svc-web identity.",
      process: {
        name: "cmd.exe",
        pid: 7724,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "w3wp.exe",
        parent_pid: 4188,
        cmdline: "cmd.exe /c whoami /priv",
        user: "NEXACORP\\svc-web",
        integrity: "high",
      },
      raw: {
        // Sysmon Event ID 1 — Process creation
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.record_id": "9912044",
        "winlog.event_data.RuleName": "technique_id=T1505.003,technique_name=Web Shell",
        "winlog.event_data.UtcTime": "2026-08-14 02:17:00.114",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-1f10-64dc-2e01-000000005e00}",
        "winlog.event_data.ProcessId": "7724",
        "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.CommandLine": "cmd.exe /c whoami /priv",
        "winlog.event_data.CurrentDirectory": "C:\\Windows\\System32\\inetsrv\\",
        "winlog.event_data.User": "NEXACORP\\svc-web",
        "winlog.event_data.LogonId": svcLogonId,
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.ParentProcessGuid": "{a1b2c3d4-0c40-64dc-1a01-000000005e00}",
        "winlog.event_data.ParentProcessId": "4188",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        "winlog.event_data.ParentCommandLine": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"NexaWebAppPool\"",
        "winlog.event_data.ParentUser": "NEXACORP\\svc-web",
        "event.code": "1",
        "event.action": "process-created",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 4. The tool is dropped and run. Sysmon 1 carries the hashes — the one
    //    citable file IOC of the incident. Signed by nobody, in C:\Windows\Temp.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_04_tool_launch",
      ts: T(3 * MIN + 40 * SEC),
      source: "sysmon",
      vendor: "Sysmon",
      event_type: "process_create",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1068",
      mitre_tactic: "Privilege Escalation",
      description:
        "Sysmon Event 1: cmd.exe launched C:\\Windows\\Temp\\spf.exe. The binary is unsigned and its SHA256 is recorded in the event.",
      process: {
        name: "spf.exe",
        pid: 7810,
        path: toolPath,
        parent_name: "cmd.exe",
        parent_pid: 7724,
        cmdline: "spf.exe -i -c cmd.exe",
        user: "NEXACORP\\svc-web",
        integrity: "high",
        hash: { sha256: toolSha256, md5: toolMd5 },
      },
      raw: {
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.record_id": "9912051",
        "winlog.event_data.RuleName": "-",
        "winlog.event_data.UtcTime": "2026-08-14 02:17:40.502",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-1f28-64dc-3001-000000005e00}",
        "winlog.event_data.ProcessId": "7810",
        "winlog.event_data.Image": toolPath,
        "winlog.event_data.FileVersion": "-",
        "winlog.event_data.Product": "-",
        "winlog.event_data.Company": "-",
        "winlog.event_data.OriginalFileName": "-",
        "winlog.event_data.CommandLine": "spf.exe -i -c cmd.exe",
        "winlog.event_data.CurrentDirectory": "C:\\Windows\\Temp\\",
        "winlog.event_data.User": "NEXACORP\\svc-web",
        "winlog.event_data.LogonId": svcLogonId,
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.Hashes": `SHA256=${toolSha256},MD5=${toolMd5},IMPHASH=${toolImphash}`,
        "winlog.event_data.ParentProcessGuid": "{a1b2c3d4-1f10-64dc-2e01-000000005e00}",
        "winlog.event_data.ParentProcessId": "7724",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.ParentCommandLine": "cmd.exe /c whoami /priv",
        "winlog.event_data.ParentUser": "NEXACORP\\svc-web",
        "event.code": "1",
        "event.action": "process-created",
        "event.outcome": "success",
        "process.name": "spf.exe",
        "process.executable": toolPath,
        "process.command_line": "spf.exe -i -c cmd.exe",
        "process.hash.sha256": toolSha256,
        "process.code_signature.status": "not signed",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The coercion — the Print Spooler (SYSTEM) connects to the attacker's
    //    named pipe. Sysmon Event 18: Image is spoolsv.exe, PipeName \spoolss.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_05_pipe_connect",
      ts: T(3 * MIN + 44 * SEC),
      source: "sysmon",
      vendor: "Sysmon",
      event_type: "process_access",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1134.001",
      mitre_tactic: "Privilege Escalation",
      description:
        "Sysmon Event 18 (Pipe Connected) on WEB-APP-04: spoolsv.exe connected to the named pipe \\spoolss — the Print Spooler being coerced toward an attacker-controlled endpoint.",
      raw: {
        // Sysmon Event ID 18 — Pipe Connected
        "winlog.event_id": "18",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.record_id": "9912066",
        "winlog.event_data.RuleName": "-",
        "winlog.event_data.UtcTime": "2026-08-14 02:17:44.881",
        "winlog.event_data.EventType": "ConnectPipe",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-0b90-64dc-0d00-000000005e00}",
        "winlog.event_data.ProcessId": "1996",
        "winlog.event_data.PipeName": "\\spoolss",
        "winlog.event_data.Image": "C:\\Windows\\System32\\spoolsv.exe",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "event.code": "18",
        "event.action": "pipe-connected",
        "event.outcome": "success",
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The token handle — spf.exe opens spoolsv.exe with GrantedAccess 0x1410,
    //    enough to read/duplicate the process token. Sysmon Event 10.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_06_process_access",
      ts: T(3 * MIN + 45 * SEC),
      source: "sysmon",
      vendor: "Sysmon",
      event_type: "process_access",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1134.001",
      mitre_tactic: "Privilege Escalation",
      description:
        "Sysmon Event 10 (ProcessAccess): C:\\Windows\\Temp\\spf.exe opened a handle to spoolsv.exe with GrantedAccess 0x1410.",
      process: {
        name: "spf.exe",
        pid: 7810,
        path: toolPath,
        user: "NEXACORP\\svc-web",
        integrity: "high",
      },
      raw: {
        // Sysmon Event ID 10 — Process accessed
        "winlog.event_id": "10",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.record_id": "9912071",
        "winlog.event_data.RuleName": "technique_id=T1134,technique_name=Access Token Manipulation",
        "winlog.event_data.UtcTime": "2026-08-14 02:17:45.203",
        "winlog.event_data.SourceProcessGUID": "{a1b2c3d4-1f28-64dc-3001-000000005e00}",
        "winlog.event_data.SourceProcessId": "7810",
        "winlog.event_data.SourceThreadId": "8140",
        "winlog.event_data.SourceImage": toolPath,
        "winlog.event_data.TargetProcessGUID": "{a1b2c3d4-0b90-64dc-0d00-000000005e00}",
        "winlog.event_data.TargetProcessId": "1996",
        "winlog.event_data.TargetImage": "C:\\Windows\\System32\\spoolsv.exe",
        "winlog.event_data.GrantedAccess": "0x1410",
        "winlog.event_data.CallTrace":
          "C:\\Windows\\SYSTEM32\\ntdll.dll+9d2b4|C:\\Windows\\System32\\KERNELBASE.dll+2d51e|C:\\Windows\\Temp\\spf.exe+3a17",
        "winlog.event_data.SourceUser": "NEXACORP\\svc-web",
        "winlog.event_data.TargetUser": "NT AUTHORITY\\SYSTEM",
        "event.code": "10",
        "event.action": "process-accessed",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 7. The privilege is exercised — 4673 records SeImpersonatePrivilege being
    //    used by spf.exe. This is the impersonation call itself.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_07_sensitive_priv_use",
      ts: T(3 * MIN + 45 * SEC + 400),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privileged_operation",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1134.001",
      mitre_tactic: "Privilege Escalation",
      description:
        "A 4673 on WEB-APP-04 recording sensitive-privilege use: SeImpersonatePrivilege exercised by the process C:\\Windows\\Temp\\spf.exe under the svc-web session.",
      raw: {
        // Windows Security Event 4673 — A privileged service was called
        "winlog.event_id": "4673",
        "winlog.channel": "Security",
        "winlog.computer_name": host.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5541190",
        "winlog.event_data.SubjectUserSid": svcSid,
        "winlog.event_data.SubjectUserName": svc.sam,
        "winlog.event_data.SubjectDomainName": svc.domain,
        "winlog.event_data.SubjectLogonId": svcLogonId,
        "winlog.event_data.ObjectServer": "Security",
        "winlog.event_data.Service": "-",
        "winlog.event_data.PrivilegeList": "SeImpersonatePrivilege",
        "winlog.event_data.ProcessId": "0x1e82",
        "winlog.event_data.ProcessName": toolPath,
        "event.code": "4673",
        "event.action": "sensitive-privilege-use",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": svc.sam,
        "user.domain": svc.domain,
      },
    },

    // ---------------------------------------------------------------------
    // 8. ESCALATION SUCCEEDS — 4688 for a cmd.exe now owned by SYSTEM, spawned
    //    by spf.exe, with a FULL token (TokenElevationType %%1937). svc-web is
    //    gone; this process is NT AUTHORITY\SYSTEM.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_08_system_shell",
      ts: T(3 * MIN + 46 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privilege_escalation",
      hostname: host.hostname,
      severity: "critical",
      mitre_technique: "T1134.002",
      mitre_tactic: "Privilege Escalation",
      description:
        "A 4688 on WEB-APP-04: spf.exe created cmd.exe running as NT AUTHORITY\\SYSTEM (SID S-1-5-18) with TokenElevationType %%1937 (full token).",
      process: {
        name: "cmd.exe",
        pid: 7864,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "spf.exe",
        parent_pid: 7810,
        cmdline: "cmd.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        // Windows Security Event 4688 — A new process has been created
        "winlog.event_id": "4688",
        "winlog.channel": "Security",
        "winlog.computer_name": host.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5541204",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WEB-APP-04$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.NewProcessId": "0x1eb8",
        "winlog.event_data.NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.TokenElevationType": "%%1937",
        "winlog.event_data.MandatoryLabel": "S-1-16-16384",
        "winlog.event_data.ProcessId": "0x1e82",
        "winlog.event_data.CommandLine": "cmd.exe",
        "winlog.event_data.CreatorProcessName": toolPath,
        "winlog.event_data.TargetUserSid": "S-1-5-18",
        "winlog.event_data.TargetLogonId": "0x3E7",
        "event.code": "4688",
        "event.action": "process-created",
        "event.outcome": "success",
        "host.name": host.hostname,
        "user.name": "SYSTEM",
        "user.domain": "NT AUTHORITY",
      },
    },

    // ---------------------------------------------------------------------
    // 9. THE PAYOFF — from SYSTEM, reg.exe exports the SAM hive. MDE raises the
    //    detection. This is the alert-grade event; the rest surfaces in the tree.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_09_sam_dump",
      ts: T(4 * MIN + 30 * SEC),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      severity: "critical",
      mitre_technique: "T1003.002",
      mitre_tactic: "Credential Access",
      is_detection: true, // alert-grade: SYSTEM-context export of the SAM hive — the crux the SOC actually receives
      edr_scope: "edr",   // fully host-observable → investigated in the EDR console (walkable process tree)
      description:
        "Microsoft Defender for Endpoint raised a detection on WEB-APP-04: reg.exe, launched by the SYSTEM cmd.exe, exported the SAM registry hive to C:\\Windows\\Temp\\sam.save.",
      process: {
        name: "reg.exe",
        pid: 7902,
        path: "C:\\Windows\\System32\\reg.exe",
        parent_name: "cmd.exe",
        parent_pid: 7864,
        cmdline: "reg save hklm\\sam C:\\Windows\\Temp\\sam.save",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      raw: {
        // MDE Advanced Hunting — DeviceProcessEvents projection
        "Timestamp": "2026-08-14T02:18:30.7742100Z",
        "DeviceId": "b91c4de2a7f0451c9d3e6f2a1b8c0d4e5f6a7b8c",
        "DeviceName": "web-app-04.nexacorp.com",
        "ActionType": "ProcessCreated",
        "FileName": "reg.exe",
        "FolderPath": "C:\\Windows\\System32\\reg.exe",
        "ProcessCommandLine": "reg  save hklm\\sam C:\\Windows\\Temp\\sam.save",
        "ProcessId": "7902",
        "ProcessIntegrityLevel": "System",
        "ProcessTokenElevation": "TokenElevationTypeDefault",
        "SHA256": makeSha256("windows_system32_reg_exe_signed_microsoft"),
        "AccountName": "system",
        "AccountDomain": "nt authority",
        "AccountSid": "S-1-5-18",
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessCommandLine": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessId": "7864",
        "InitiatingProcessParentFileName": "spf.exe",
        "InitiatingProcessParentId": "7810",
        "InitiatingProcessIntegrityLevel": "System",
        "InitiatingProcessTokenElevation": "TokenElevationTypeFull",
        "InitiatingProcessAccountName": "system",
        "InitiatingProcessAccountDomain": "nt authority",
        "InitiatingProcessSHA256": makeSha256("windows_system32_cmd_exe_signed_microsoft"),
        "ReportId": "84421907",
        "mde.AlertTitle": "Sensitive registry hive (SAM) exported by a SYSTEM process",
        "mde.Category": "CredentialAccess",
        "mde.DetectionSource": "EDR",
        "mde.DeviceName": "web-app-04.nexacorp.com",
        "mde.IncidentId": "39714",
        "mde.InitiatingProcessFileName": "cmd.exe",
        "mde.InitiatingProcessCommandLine": "cmd.exe",
        "event.code": "1",
        "event.action": "process-created",
        "event.outcome": "success",
        "threat.tactic.name": "Credential Access",
        "threat.technique.id": "T1003.002",
        "threat.technique.name": "OS Credential Dumping: Security Account Manager",
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 10. The correlation that opened the ticket — Sentinel ties the rare
    //     privilege elevation on svc-web to the SYSTEM process and SAM export,
    //     with the account's baseline attached.
    // ---------------------------------------------------------------------
    {
      id: "evt_wpe_10_sentinel_corr",
      ts: T(6 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      severity: "high",
      mitre_technique: "T1134.001",
      mitre_tactic: "Privilege Escalation",
      description:
        "Microsoft Sentinel raised a High incident correlating a rare privilege elevation and an unusual process execution on WEB-APP-04 for NEXACORP\\svc-web, with the service account's baseline attached.",
      raw: {
        "AlertName": "PrivilegeEscalation_TokenImpersonation_ServiceToSYSTEM",
        "AlertSeverity": "High",
        "TimeGenerated": T(6 * MIN),
        "RarePrivilegeElevation": "true",
        "UnusualProcessExecution": "true",
        "alert.rule.id": "SEN-PRIVESC-0042",
        "target.user.name": "NEXACORP\\svc-web",
        "user.full_name": "IIS Application Pool — NexaWebAppPool",
        "user.department": "IT — Web Platform",
        "user.title": "Service Account (IIS App Pool Identity)",
        "host.name": host.hostname,
        "threat.tactic.name": "Privilege Escalation",
        "threat.technique.id": "T1134.001",
        "threat.technique.name": "Access Token Manipulation: Token Impersonation/Theft",
        "ExtendedProperties.Window Start": T(0),
        "ExtendedProperties.Window End": T(4 * MIN + 30 * SEC),
        "ExtendedProperties.Baseline Processes (Prior 30d)": "w3wp.exe, inetinfo.exe, wmiprvse.exe",
        "ExtendedProperties.Observed Privilege": "SeImpersonatePrivilege",
        "ExtendedProperties.SYSTEM Process Observed": "cmd.exe (parent spf.exe)",
        "ExtendedProperties.Local Admin Priv On Host": "false",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      // The organisation's own IIS host — the victim asset, not adversary
      // infrastructure. Reputation "unknown", never "malicious": tagging your own
      // estate hostile is how a blocklist ends up blocking production.
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(6 * MIN),
      reputation: "unknown",
      tags: ["iis", "internet-facing", "web-app", "compromised-host"],
    },
    {
      type: "user",
      value: svc.sam,
      first_seen: T(0),
      last_seen: T(6 * MIN),
      reputation: "suspicious",
      tags: ["service-account", "iis-app-pool", "seimpersonate", "compromised"],
    },
    {
      type: "sha256",
      value: toolSha256,
      first_seen: T(3 * MIN + 40 * SEC),
      last_seen: T(3 * MIN + 45 * SEC),
      reputation: "malicious",
      tags: ["printspoofer", "potato", "token-impersonation", "T1134.001"],
    },
    {
      type: "md5",
      value: toolMd5,
      first_seen: T(3 * MIN + 40 * SEC),
      last_seen: T(3 * MIN + 40 * SEC),
      reputation: "malicious",
      tags: ["printspoofer", "potato", "privesc-tool"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "svc-web is not a local administrator, yet it ended the incident holding a SYSTEM shell. Which single event establishes the PRECONDITION that made that escalation technically possible?",
      hint: "The escalation abuses one specific Windows privilege. Which event enumerates it on the svc-web logon session?",
      kind: "single",
      options: [
        { value: "special_privs", label: "evt_wpe_02_special_privs — the 4672 listing SeImpersonatePrivilege on the svc-web session" },
        { value: "service_logon", label: "evt_wpe_01_service_logon — the 4624 LogonType 5 service logon for svc-web" },
        { value: "pipe", label: "evt_wpe_05_pipe_connect — spoolsv.exe connecting to the \\spoolss named pipe" },
        { value: "system_shell", label: "evt_wpe_08_system_shell — the 4688 for cmd.exe running as SYSTEM" },
      ],
      answer: "special_privs",
      xp: 50,
      explanation:
        "PrintSpoofer/potato attacks do not need administrator rights — they need SeImpersonatePrivilege, the right to impersonate a security token the process can get a handle to. evt_wpe_02_special_privs is the 4672 that records that privilege on the svc-web logon session (0x8F41C2), and it is present precisely because svc-web is an IIS application-pool identity, which Windows grants SeImpersonatePrivilege by default. Without that grant the entire token-theft chain is impossible. The 4624 (a) only shows the account logged on; the named pipe (c) and the SYSTEM shell (d) are steps that the privilege in (b) enabled, not the precondition itself. Reading the precondition, not just the payload, is the whole point: a service account with SeImpersonate is a privilege-escalation waiting to happen.",
    },
    {
      id: "q2",
      prompt:
        "Read evt_wpe_05_pipe_connect and evt_wpe_06_process_access together. What technique do they show, and what does the GrantedAccess value 0x1410 represent?",
      kind: "single",
      options: [
        { value: "token_theft", label: "Token impersonation/theft: the SYSTEM spooler was coerced onto an attacker pipe, then spf.exe opened a handle to it (0x1410) to duplicate its token" },
        { value: "lsass_dump", label: "An LSASS memory dump: spf.exe read lsass.exe's memory to extract plaintext credentials" },
        { value: "kerberoast", label: "Kerberoasting: spf.exe requested a service ticket over the named pipe and cracked it offline" },
        { value: "dll_injection", label: "DLL injection: spf.exe wrote a malicious DLL into spoolsv.exe and forced it to load" },
      ],
      answer: "token_theft",
      xp: 60,
      explanation:
        "This is the mechanism of the whole potato/PrintSpoofer family (T1134.001). The attacker gets a SYSTEM service — here the Print Spooler, spoolsv.exe — to authenticate to a named pipe the attacker controls (evt_wpe_05, spoolsv.exe running as SYSTEM connecting to \\spoolss). The tool then impersonates that connection and opens a handle to the SYSTEM process to duplicate its token: evt_wpe_06 shows spf.exe (source) accessing spoolsv.exe (target) with GrantedAccess 0x1410, the access mask that grants enough rights to read and duplicate the process token. It is not an LSASS dump — the target is spoolsv.exe, not lsass.exe, and nothing reads process memory for credentials here. Kerberoasting and DLL injection are unrelated techniques with entirely different telemetry.",
    },
    {
      id: "q3",
      prompt:
        "Which single event is the proof that privilege escalation actually SUCCEEDED — the moment svc-web's context became SYSTEM — rather than merely being attempted?",
      hint: "One event shows a privilege being used; another shows a process that is already owned by SYSTEM.",
      kind: "single",
      options: [
        { value: "system_shell", label: "evt_wpe_08_system_shell — a 4688 for cmd.exe owned by S-1-5-18 with TokenElevationType %%1937" },
        { value: "priv_use", label: "evt_wpe_07_sensitive_priv_use — the 4673 recording SeImpersonatePrivilege being exercised" },
        { value: "proc_access", label: "evt_wpe_06_process_access — the Sysmon 10 handle to spoolsv.exe" },
        { value: "sentinel", label: "evt_wpe_10_sentinel_corr — the Sentinel correlation that opened the ticket" },
      ],
      answer: "system_shell",
      xp: 60,
      explanation:
        "evt_wpe_07 (4673) and evt_wpe_06 (Sysmon 10) show the privilege being used and the token handle being opened — these are the attempt in progress, still running under the svc-web session. The success is evt_wpe_08: a 4688 whose new process, cmd.exe, is owned by SubjectUserSid / TargetUserSid S-1-5-18 (NT AUTHORITY\\SYSTEM) with TokenElevationType %%1937, the code for a full elevated token. That is the first event where the executing context is SYSTEM rather than svc-web — the escalation has landed. The Sentinel alert (d) is the SOC finding out after the fact, six minutes later; it is detection, not the compromise event.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the incident report. Select EVERY statement that is directly supported by the events in front of you.",
      kind: "multi",
      options: [
        { value: "held_priv", label: "svc-web held SeImpersonatePrivilege before the escalation began" },
        { value: "coerced_spooler", label: "The Print Spooler (spoolsv.exe, SYSTEM) was coerced onto an attacker-controlled named pipe and its token was accessed" },
        { value: "ran_as_system", label: "A process executed as NT AUTHORITY\\SYSTEM on WEB-APP-04" },
        { value: "sam_export", label: "The SYSTEM context was used to export the local SAM hive" },
        { value: "lateral_dc", label: "The attacker used the SYSTEM token to move laterally to a domain controller" },
      ],
      answer: ["held_priv", "coerced_spooler", "ran_as_system", "sam_export"],
      xp: 70,
      explanation:
        "Four statements are evidenced end to end. 'Held the privilege' is the 4672 (evt_wpe_02). 'Coerced the spooler' is the pair evt_wpe_05 (spoolsv.exe → \\spoolss pipe) and evt_wpe_06 (spf.exe opening spoolsv.exe, GrantedAccess 0x1410). 'Ran as SYSTEM' is the 4688 (evt_wpe_08, cmd.exe owned by S-1-5-18, full token). 'Exported the SAM hive' is the MDE detection (evt_wpe_09, reg save hklm\\sam to C:\\Windows\\Temp\\sam.save, initiated by the SYSTEM cmd.exe). The false statement is lateral movement to a domain controller: there is no authentication, network, or process event on any DC in this telemetry — the entire chain is local to WEB-APP-04. Reporting a DC compromise you cannot see is exactly the kind of unsupported claim that derails a response; svc-web is a local service account with no admin rights on the host (the Sentinel context records Local Admin Priv On Host = false), and the SAM dump gives the attacker LOCAL hashes, not domain ones.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "SYSTEM in Twelve Seconds — Token Impersonation on an IIS Host",
    threat_actor: "Post-exploitation operator on a compromised web-app service account",
    attack_kind: "windows_privilege_escalation",
    briefing:
      "Microsoft Sentinel raised a High incident at 02:20 for the service account NEXACORP\\svc-web on the IIS host WEB-APP-04: a rare privilege elevation and an unusual process execution within a six-minute window. The web-app foothold is already being handled by another team. Your job: determine whether svc-web escalated its privileges on this host, how far it got, and what it reached.",
    narrative: `svc-web is the identity NexaCorp's public web application pool runs under on WEB-APP-04. It is deliberately a low-privilege account — not a local administrator, no domain rights beyond a plain user. What it does have, because every IIS application-pool identity has it, is SeImpersonatePrivilege: the right to impersonate a security token the process can obtain a handle to. On a healthy host that privilege never matters. On a host where the web application has already been compromised, it is the entire attack surface.

At 02:14 the app pool logged on as it does hundreds of times a week — a 4624 LogonType 5, followed by the 4672 that quietly enumerates SeImpersonatePrivilege on the new session. Three minutes later the foothold surfaced: the IIS worker w3wp.exe spawned cmd.exe, then dropped and ran C:\\Windows\\Temp\\spf.exe, an unsigned PrintSpoofer/potato-style tool.

What followed took about twelve seconds. spf.exe coerced the Print Spooler service — spoolsv.exe, running as SYSTEM — into connecting to a named pipe it controlled (\\spoolss), then opened a handle to spoolsv.exe with GrantedAccess 0x1410 and duplicated its SYSTEM token. Windows logged the impersonation as a 4673 sensitive-privilege use citing SeImpersonatePrivilege and spf.exe. Then spf.exe launched cmd.exe with that stolen token: a 4688 whose new process is owned by S-1-5-18, NT AUTHORITY\\SYSTEM, with a full elevated token. svc-web had become SYSTEM without ever being an administrator.

From SYSTEM the operator went straight for credentials: reg.exe, launched by the SYSTEM cmd.exe, exported the local SAM hive to C:\\Windows\\Temp\\sam.save — the built-in Administrator's password hash, now the attacker's. Microsoft Defender for Endpoint raised the detection on that export. Sentinel correlated the rare privilege elevation to the SYSTEM process two minutes later and opened this ticket.

Everything is local to WEB-APP-04. No domain controller, no other host, no network hop appears anywhere in the telemetry. The escalation is real and complete; the blast radius is this one machine and the local secrets on it — which is exactly what the report has to say, no more and no less.`,
    learning_objectives: [
      "Recognise SeImpersonatePrivilege on a 4672 as the precondition for potato/PrintSpoofer escalation, and understand why IIS/service accounts carry it",
      "Reconstruct a named-pipe token-impersonation chain from Sysmon (Event 18 pipe, Event 10 ProcessAccess GrantedAccess 0x1410) and Windows Security (4673) telemetry",
      "Distinguish an escalation ATTEMPT (4673 privilege use, Sysmon 10 handle) from escalation SUCCESS (4688 with a SYSTEM-owned process and TokenElevationType %%1937)",
      "Read TokenElevationType and the SubjectUserSid S-1-5-18 on a 4688 to prove a process is executing as SYSTEM",
      "Scope the impact to what the evidence supports — a local SAM dump on one host — and resist inferring domain-wide compromise the telemetry does not show",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Persistence", action: `4624 LogonType 5 — the IIS app pool logs on as ${svc.domain}\\${svc.sam} on ${host.hostname}` },
      { ts: T(1 * SEC), phase: "Privilege Escalation", action: "4672 — the svc-web session is assigned SeImpersonatePrivilege (the precondition)" },
      { ts: T(3 * MIN), phase: "Execution", action: "Sysmon 1 — w3wp.exe spawns cmd.exe under svc-web (webshell surfacing)" },
      { ts: T(3 * MIN + 40 * SEC), phase: "Privilege Escalation", action: "Sysmon 1 — unsigned C:\\Windows\\Temp\\spf.exe launched (PrintSpoofer/potato tool)" },
      { ts: T(3 * MIN + 44 * SEC), phase: "Privilege Escalation", action: "Sysmon 18 — spoolsv.exe (SYSTEM) coerced onto the \\spoolss named pipe" },
      { ts: T(3 * MIN + 45 * SEC), phase: "Privilege Escalation", action: "Sysmon 10 — spf.exe opens spoolsv.exe with GrantedAccess 0x1410 to duplicate its token" },
      { ts: T(3 * MIN + 45 * SEC + 400), phase: "Privilege Escalation", action: "4673 — SeImpersonatePrivilege exercised by spf.exe" },
      { ts: T(3 * MIN + 46 * SEC), phase: "Privilege Escalation", action: "4688 — cmd.exe created as NT AUTHORITY\\SYSTEM (TokenElevationType %%1937) — escalation succeeds" },
      { ts: T(4 * MIN + 30 * SEC), phase: "Credential Access", action: "MDE detection — reg save hklm\\sam to C:\\Windows\\Temp\\sam.save from the SYSTEM shell" },
      { ts: T(6 * MIN), phase: "Detection", action: "Sentinel correlates the rare privilege elevation and opens the incident" },
    ],
    questions,
  };
}
