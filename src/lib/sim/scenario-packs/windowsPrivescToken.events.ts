/**
 * Events-only half of the ./windowsPrivescToken.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./windowsPrivescToken.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256, makeMd5 } from "@/lib/sim/iocs";
import { winLogon, winSpecialPrivileges, winSensitivePrivUse, winProcessCreate } from "@/lib/sim/emitters/windowsSecurity";
import { sysmonProcess, sysmonFile, sysmonPipe } from "@/lib/sim/emitters/sysmon";
import { sysmonPipeCreated } from "@/lib/sim/emitters/scenarioExtras";
import { mdeProcess } from "@/lib/sim/emitters/mde";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of the windowsPrivescToken scenario: the events and the story title, no answer key. */
export function windowsPrivescTokenScenarioEvents() {
  const title = "Rare privilege alert for an IIS service account";
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
  const svc = { sam: "svc-web", domain: "NEXACORP", email: "svc-web@nexacorp.com" };
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
  const sysDumpPath = "C:\\Windows\\Temp\\sys.save";

  // One incident. Everything below is host-observable on WEB-APP-04 — Windows
  // Security + Sysmon + the MDE detection — so this is an EDR-scope investigation:
  // there is a real process tree to walk from w3wp.exe down to the SYSTEM shell.
  const INCIDENT = "inc:wpe:1";

  const cxN = "nexacorp" as const;
  const regSha = makeSha256("windows_system32_reg_exe_signed_microsoft");
  const cmdSha = makeSha256("windows_system32_cmd_exe_signed_microsoft");

  // One pid per process across every source (the Sysmon / 4688 / 4673 / MDE rows all name these).
  const PID = { w3wp: 4188, cmd: 7724, spf: 7810, spoolsv: 1996, systemCmd: 7864, reg: 7902, regSys: 7940 };
  const W3WP = "C:\\Windows\\System32\\inetsrv\\w3wp.exe";
  const SPOOLSV = "C:\\Windows\\System32\\spoolsv.exe";
  // PrintSpoofer builds its pipe from the computer name: \\.\pipe\<computer>\pipe\spoolss
  const pipeName = `\\${host.hostname}\\pipe\\spoolss`;
  const svcAcct = `${svc.domain}\\${svc.sam}`;

  const events: TelemetryEvent[] = [
    // 1. Routine baseline — the IIS app-pool identity logs on as a service (Type 5).
    winLogon({
      companyId: cxN, id: "evt_wpe_01_service_logon", ts: T(0), host: host.hostname, fqdn: host.fqdn,
      targetUser: svc.sam, targetSid: svcSid, subjectUser: "WEB-APP-04$", subjectSid: "S-1-5-18",
      logonType: 5, authPackage: "Negotiate", logonProcess: "Advapi  ", logonId: svcLogonId, workstation: "-",
      processName: "C:\\Windows\\System32\\services.exe", recordId: "5540911", severity: "informational",
      incidentId: INCIDENT,
      description: "A 4624 LogonType 5 on WEB-APP-04 for the service account NEXACORP\\svc-web — the IIS application pool starting under its assigned identity.",
    }),

    // 2. THE PRECONDITION — 4672 enumerates SeImpersonatePrivilege on the svc-web session.
    winSpecialPrivileges({
      companyId: cxN, id: "evt_wpe_02_special_privs", ts: T(1 * SEC), host: host.hostname, fqdn: host.fqdn,
      targetUser: svc.sam, targetSid: svcSid, logonId: svcLogonId, eventType: "privileged_operation", eventAction: "special-privileges-assigned",
      privilegeList: "SeAssignPrimaryTokenPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeImpersonatePrivilege",
      recordId: "5540912", severity: "low", incidentId: INCIDENT,
      description: "A 4672 on WEB-APP-04 for the svc-web logon session (0x8F41C2), enumerating the special privileges assigned to it at logon.",
    }),

    // 3. The webshell speaks — w3wp.exe spawns cmd.exe (Sysmon 1).
    sysmonProcess({
      companyId: cxN, id: "evt_wpe_03_w3wp_spawns_cmd", ts: T(3 * MIN), host: host.hostname, user: svc.email,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c whoami /priv", sha256: cmdSha,
      parentName: "w3wp.exe", parentPath: W3WP, parentCmdline: "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"NexaWebAppPool\"",
      pid: PID.cmd, parentPid: PID.w3wp, integrity: "High", processGuid: "{a1b2c3d4-1f10-64dc-2e01-000000005e00}", parentGuid: "{a1b2c3d4-0c40-64dc-1a01-000000005e00}",
      ruleName: "technique_id=T1505.003,technique_name=Web Shell", incidentId: INCIDENT, mitre: "T1505.003", tactic: "Persistence", severity: "high",
      description: "Sysmon Event 1 on WEB-APP-04: the IIS worker w3wp.exe spawned cmd.exe under the svc-web identity.",
    }),

    // 3a. The tool lands in C:\Windows\Temp (Sysmon 11, written by the worker process).
    {
      ...sysmonFile({
        companyId: cxN, id: "evt_wpe_03a_tool_written", ts: T(3 * MIN + 30 * SEC), host: host.hostname, user: svc.email,
        processName: "w3wp.exe", processPath: W3WP, pid: PID.w3wp, processGuid: "{a1b2c3d4-0c40-64dc-1a01-000000005e00}",
        path: toolPath, sha256: toolSha256, fileSize: 27_136, incidentId: INCIDENT, severity: "high", mitre: "T1105", tactic: "Command and Control",
        description: "Sysmon Event 11: w3wp.exe created C:\\Windows\\Temp\\spf.exe, 27 KB, thirty seconds after the web shell first ran a command.",
      }),
      process: { name: "w3wp.exe", pid: PID.w3wp, path: W3WP, user: svcAcct, integrity: "high" as const },
    },

    // 4. The tool is run (Sysmon 1, hashes recorded).
    sysmonProcess({
      companyId: cxN, id: "evt_wpe_04_tool_launch", ts: T(3 * MIN + 40 * SEC), host: host.hostname, user: svc.email,
      processName: "spf.exe", processPath: toolPath, cmdline: "spf.exe -i -c cmd.exe",
      parentName: "cmd.exe", parentPath: "C:\\Windows\\System32\\cmd.exe", parentCmdline: "cmd.exe /c whoami /priv",
      pid: PID.spf, parentPid: PID.cmd, sha256: toolSha256, md5: toolMd5, imphash: toolImphash, signed: false, integrity: "High",
      originalFileName: "-", processGuid: "{a1b2c3d4-1f28-64dc-3001-000000005e00}", parentGuid: "{a1b2c3d4-1f10-64dc-2e01-000000005e00}", ruleName: "-",
      incidentId: INCIDENT, mitre: "T1068", tactic: "Privilege Escalation", severity: "high",
      description: "Sysmon Event 1: cmd.exe launched C:\\Windows\\Temp\\spf.exe. The binary is unsigned and its SHA256 is recorded in the event.",
    }),

    // 5a. The tool creates the pipe the spooler will be coerced into connecting to (Sysmon 17).
    sysmonPipeCreated({
      companyId: cxN, id: "evt_wpe_05a_pipe_create", ts: T(3 * MIN + 43 * SEC), host: host.hostname, userEmail: svc.email, runAsUser: svcAcct,
      image: toolPath, pid: PID.spf, processGuid: "{a1b2c3d4-1f28-64dc-3001-000000005e00}", pipeName,
      incidentId: INCIDENT, mitre: "T1134.001", tactic: "Privilege Escalation", severity: "high",
      description: "Sysmon Event 17 (Pipe Created) on WEB-APP-04: C:\\Windows\\Temp\\spf.exe created the named pipe \\WEB-APP-04\\pipe\\spoolss.",
    }),

    // 5. The coercion — spoolsv.exe (SYSTEM) connects to that pipe (Sysmon 18).
    {
      ...sysmonPipe({
        companyId: cxN, id: "evt_wpe_05_pipe_connect", ts: T(3 * MIN + 44 * SEC), host: host.hostname, user: null,
        image: SPOOLSV, pid: PID.spoolsv, pipeName, runAsUser: "NT AUTHORITY\\SYSTEM",
        incidentId: INCIDENT, mitre: "T1134.001", tactic: "Privilege Escalation", severity: "high",
        description: "Sysmon Event 18 (Pipe Connected) on WEB-APP-04: spoolsv.exe connected to the named pipe \\WEB-APP-04\\pipe\\spoolss, the Print Spooler being coerced onto a pipe the attacker created.",
      }),
      event_type: "file_access" as const,
      process: { name: "spoolsv.exe", pid: PID.spoolsv, path: SPOOLSV, user: "NT AUTHORITY\\SYSTEM", integrity: "system" as const },
      file: { name: "spoolss", path: `\\\\.\\pipe${pipeName}` },
    },

    // 7. The privilege is exercised — 4673 SeImpersonatePrivilege by spf.exe.
    winSensitivePrivUse({
      companyId: cxN, id: "evt_wpe_07_sensitive_priv_use", ts: T(3 * MIN + 45 * SEC + 400), host: host.hostname, fqdn: host.fqdn,
      targetUser: svc.sam, targetSid: svcSid, logonId: svcLogonId, privilegeUsed: "SeImpersonatePrivilege",
      processName: toolPath, processId: `0x${PID.spf.toString(16)}`, recordId: "5541190", incidentId: INCIDENT, mitre: "T1134.001", tactic: "Privilege Escalation", severity: "high",
      description: "A 4673 on WEB-APP-04 recording sensitive-privilege use: SeImpersonatePrivilege exercised by the process C:\\Windows\\Temp\\spf.exe under the svc-web session.",
    }),

    // 8. ESCALATION SUCCEEDS — 4688: svc-web (through spf.exe) creates a cmd.exe whose token is SYSTEM's.
    (() => {
      const e = winProcessCreate({
        companyId: cxN, id: "evt_wpe_08_system_shell", ts: T(3 * MIN + 46 * SEC), host: host.hostname, fqdn: host.fqdn,
        targetUser: svc.sam, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe", parentPath: toolPath,
        pid: PID.systemCmd, subjectUser: svc.sam, subjectSid: svcSid, runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system",
        tokenElevation: "%%1936", eventType: "privilege_escalation", recordId: "5541204", incidentId: INCIDENT, mitre: "T1134.002", tactic: "Privilege Escalation", severity: "critical",
        description: "A 4688 on WEB-APP-04: spf.exe, running as svc-web, created cmd.exe whose token belongs to NT AUTHORITY\\SYSTEM (S-1-5-18).",
      });
      // The creator is the svc-web session and spf.exe; the new process runs under the SYSTEM logon session.
      Object.assign(e.raw, {
        "winlog.event_data.SubjectLogonId": svcLogonId,
        "winlog.event_data.ProcessId": `0x${PID.spf.toString(16)}`,
        "winlog.event_data.TargetUserSid": "S-1-5-18",
        "winlog.event_data.TargetLogonId": "0x3E7",
      });
      e.process = { ...e.process!, parent_pid: PID.spf };
      return e;
    })(),

    // 9. THE PAYOFF — reg.exe exports the SAM and SYSTEM hives; MDE raises the detection.
    {
      ...mdeProcess({
        companyId: cxN, id: "evt_wpe_09_sam_dump", ts: T(4 * MIN + 30 * SEC), host: host.hostname, user: null,
        processName: "reg.exe", processPath: "C:\\Windows\\System32\\reg.exe", cmdline: `reg  save hklm\\sam ${samDumpPath}`,
        parentName: "cmd.exe", pid: PID.reg, parentPid: PID.systemCmd, sha256: regSha, integrity: "System", isDetection: true,
        runAsUser: "NT AUTHORITY\\SYSTEM", accountName: "system", accountDomain: "nt authority",
        incidentId: INCIDENT, mitre: "T1003.002", tactic: "Credential Access", severity: "critical",
        extra: {
          "Timestamp": "2026-08-14T02:18:30.7742100Z",
          "DeviceId": "b91c4de2a7f0451c9d3e6f2a1b8c0d4e5f6a7b8c",
          "ProcessIntegrityLevel": "System",
          "ProcessTokenElevation": "TokenElevationTypeDefault",
          "AccountSid": "S-1-5-18",
          "InitiatingProcessCommandLine": "cmd.exe",
          "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
          "InitiatingProcessParentFileName": "spf.exe",
          "InitiatingProcessParentId": String(PID.spf),
          "InitiatingProcessIntegrityLevel": "System",
          "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
          "InitiatingProcessAccountName": "system",
          "InitiatingProcessAccountDomain": "nt authority",
          "InitiatingProcessSHA256": cmdSha,
          "ReportId": "84421907",
          "mde.AlertTitle": "Sensitive registry hive (SAM) exported by a SYSTEM process",
          "mde.Category": "CredentialAccess",
          "mde.DetectionSource": "EDR",
          "mde.DeviceName": "web-app-04.nexacorp.com",
          "mde.IncidentId": "39714",
          "mde.InitiatingProcessFileName": "cmd.exe",
          "mde.InitiatingProcessCommandLine": "cmd.exe",
          "threat.tactic.name": "Credential Access",
          "threat.technique.id": "T1003",
          "threat.technique.subtechnique.id": "T1003.002",
          "threat.technique.name": "OS Credential Dumping: Security Account Manager",
        },
        description: "Microsoft Defender for Endpoint raised a detection on WEB-APP-04: reg.exe, launched by the SYSTEM cmd.exe, exported the SAM registry hive to C:\\Windows\\Temp\\sam.save.",
      }),
      edr_scope: "edr",
    },
    // 9a. The SYSTEM hive follows — a SAM hive alone cannot be decrypted offline.
    mdeProcess({
      companyId: cxN, id: "evt_wpe_09a_system_hive", ts: T(4 * MIN + 38 * SEC), host: host.hostname, user: null,
      processName: "reg.exe", processPath: "C:\\Windows\\System32\\reg.exe", cmdline: `reg  save hklm\\system ${sysDumpPath}`,
      parentName: "cmd.exe", pid: PID.regSys, parentPid: PID.systemCmd, sha256: regSha, integrity: "System",
      runAsUser: "NT AUTHORITY\\SYSTEM", accountName: "system", accountDomain: "nt authority", signed: true,
      incidentId: INCIDENT, mitre: "T1003.002", tactic: "Credential Access", severity: "high",
      description: "Eight seconds after the SAM export the same SYSTEM cmd.exe ran reg.exe again, saving the SYSTEM hive to C:\\Windows\\Temp\\sys.save.",
    }),

    // 10. The Sentinel correlation that opened the ticket.
    sentinelAlert({
      companyId: cxN, id: "evt_wpe_10_sentinel_corr", ts: T(6 * MIN), host: host.hostname, srcIp: host.ip, user: svc.email,
      alertName: "PrivilegeEscalation_TokenImpersonation_ServiceToSYSTEM", ruleId: "SEN-PRIVESC-0042",
      severity: "high", eventType: "ueba_anomaly", fullName: "IIS Application Pool, NexaWebAppPool", department: "IT, Web Platform",
      title: "Service Account (IIS App Pool Identity)",
      incidentId: INCIDENT, mitre: "T1134.001", tactic: "Privilege Escalation",
      extendedProperties: {
        "Window Start": T(0),
        "Window End": T(4 * MIN + 30 * SEC),
        "Baseline Processes (Prior 30d)": "w3wp.exe, inetinfo.exe, wmiprvse.exe",
        "Observed Privilege": "SeImpersonatePrivilege",
        "SYSTEM Process Observed": "cmd.exe (parent spf.exe)",
        "Local Admin Priv On Host": "false",
      },
      description: "Microsoft Sentinel raised a High incident correlating a rare privilege elevation and an unusual process execution on WEB-APP-04 for NEXACORP\\svc-web, with the service account's baseline attached.",
    }),
  ];

  // The host's own address on every endpoint-sensor row (the EDR console header reads it from the host's process telemetry).
  for (const e of events) if (e.hostname === host.hostname && (e.source === "sysmon" || e.source === "edr")) e.src_ip = host.ip;

  return { title, events, B, T, SEC, MIN, host, svc, svcSid, svcLogonId, toolPath, toolSha256, toolMd5, toolImphash, samDumpPath, INCIDENT, cxN, regSha, cmdSha, pipeName };
}
