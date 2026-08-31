/**
 * Scenario pack: "Fix My Internet — Scheduled-Task Persistence from a
 * Downloaded Script"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential
 * theft across accounts. A user runs a PowerShell "network fix" script she
 * found linked from a forum post. The script itself does very little that
 * looks alarming — it drops one binary — but it also registers a Scheduled
 * Task that relaunches that binary at every logon, forever, until someone
 * finds and removes it.
 *
 * The teaching point is persistence as a technique in its own right,
 * independent of whatever the payload turns out to do. The single most
 * important fact in this whole scenario is one command line —
 * `schtasks /create ... /sc onlogon` — and the single most important piece
 * of evidence that the persistence actually works is the same binary
 * launching again, hours later, with a different parent process, at the
 * next interactive logon.
 *
 * Telemetry here is Sysmon-native: Event ID 1 (process creation),
 * Event ID 11 (file creation) and Event ID 22 (DNS query), exactly as
 * Sysmon logs them, with no Windows Security Event Log fields mixed in.
 *
 * Covers T1053.005 (Scheduled Task/Job: Scheduled Task) and
 * T1059.001 (Command and Scripting Interpreter: PowerShell).
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildScheduledTaskPersistenceScenario(
  scenarioId = "scheduled-task-persistence-2026",
): ScenarioBundle {
  const B = new Date("2026-04-13T08:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;

  const host = { hostname: "WS-7742", ip: "10.14.9.201" };
  const victim = { email: "s.attia@nexacorp.com", name: "Shani Attia", sam: "s.attia" };

  const downloadSite = "netfix-tools-download.com";
  const c2 = "svc-heartbeat-relay.net";

  const scriptHash    = makeSha256("speedboost_netfix_ps1_downloader_2026");
  const payloadHash   = makeSha256("netfix_agent_exe_persistence_payload_2026");
  const powershellHash = makeSha256("windows_powershell_v1_signed_microsoft");
  const schtasksHash  = makeSha256("windows_system32_schtasks_exe_signed_microsoft");

  // Sysmon ProcessGuid values — one per process creation instant, threaded
  // through ParentProcessGuid so the Event ID 11/22 records (which carry no
  // parent field of their own) and the SIEM's "join on ParentProcessGuid"
  // query in evt_stp_08 are backed by telemetry that actually contains that
  // field, not just by matching PIDs.
  const explorerGuid   = "{a53f7d10-eac9-6600-0000-0010b4e50300}"; // explorer.exe, pre-existing
  const powershellGuid = "{a53f7d10-eaec-6600-0000-0010e6210400}"; // evt_stp_02, PID 5124
  const schtasksGuid   = "{a53f7d10-eaf1-6600-0000-0010128b0400}"; // evt_stp_04, PID 5188
  const netfixGuid1    = "{a53f7d10-eafd-6600-0000-0010b3f60400}"; // first run, PID 5240
  const svchostGuid    = "{a53f7d05-2a1b-6600-0000-0010f4c20100}"; // Schedule service host, pre-existing
  const netfixGuid2    = "{a53f7d29-4763-6600-0000-0010a9d90800}"; // relaunch at logon, PID 2016

  // EDR↔scenario integration (Phase 4): one incident. Endpoint-primary (Sysmon
  // host telemetry) → edr_scope "edr". The firewall beacon and the SIEM
  // correlation are transport and detection evidence; the schtasks.exe
  // registration is the alert-grade EDR behavioural detection carrying the crux.
  const INCIDENT = "inc:stp:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The download. A forum-linked "fix" for a common, believable
    //    complaint.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_01_download",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "HR Coordinator",
      src_ip: host.ip,
      severity: "low",
      mitre_technique: "T1189", // Drive-by Compromise — web-delivered malicious script from a forum-linked "fix" (matches the killchain's "Initial Access" phase)
      mitre_tactic: "Initial Access",
      description:
        "WS-7742 downloaded SpeedBoost_NetFix.ps1 from netfix-tools-download.com at 08:05, allowed under the category computer-and-internet-info.",
      file: { name: "SpeedBoost_NetFix.ps1", path: "/scripts/SpeedBoost_NetFix.ps1", extension: "ps1", size: 4_216, sha256: scriptHash },
      network: {
        url: `https://${downloadSite}/scripts/SpeedBoost_NetFix.ps1`,
        domain: downloadSite,
        method: "GET",
        status: 200,
        bytes_in: 4_216,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "172.67.140.55",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "computer-and-internet-info",
        "pan.url": `${downloadSite}/scripts/SpeedBoost_NetFix.ps1`,
        "pan.filename": "SpeedBoost_NetFix.ps1",
        "pan.filetype": "script",
        "pan.file_hash": scriptHash,
        "pan.direction": "download",
        "pan.session_id": "618204",
        "source.ip": host.ip,
        "url.domain": downloadSite,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The user runs it. Sysmon Event ID 1.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_02_script_run",
      ts: T(3 * MIN + 18_000),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      description:
        "At 08:08:18 explorer.exe started powershell.exe with an execution-policy bypass, running the downloaded script directly from Downloads.",
      process: {
        name: "powershell.exe",
        pid: 5124,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "explorer.exe",
        parent_pid: 3116,
        cmdline:
          "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: powershellHash },
      },
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(3 * MIN + 18_000),
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.CommandLine":
          "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1\"",
        "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
        "winlog.event_data.ParentCommandLine": "C:\\Windows\\Explorer.EXE",
        "winlog.event_data.Hashes": `SHA256=${powershellHash}`,
        "winlog.event_data.User": `NEXACORP\\${victim.sam}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.ProcessId": "5124",
        "winlog.event_data.ParentProcessId": "3116",
        "winlog.event_data.ProcessGuid": powershellGuid,
        "winlog.event_data.ParentProcessGuid": explorerGuid,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 3. The script drops its payload. Sysmon Event ID 11.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_03_payload_written",
      ts: T(3 * MIN + 24_000),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "Six seconds later the script wrote C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe, unsigned.",
      file: {
        name: "netfix_agent.exe",
        path: "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        extension: "exe",
        size: 318_976,
        sha256: payloadHash,
      },
      raw: {
        "event.code": "11",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(3 * MIN + 24_000),
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.TargetFilename": "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        "winlog.event_data.CreationUtcTime": T(3 * MIN + 24_000),
        "winlog.event_data.Hashes": `SHA256=${payloadHash}`,
        "winlog.event_data.ProcessId": "5124",
        "winlog.event_data.ProcessGuid": powershellGuid,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 4. THE EVENT THAT MATTERS — the script registers persistence.
    //    Sysmon Event ID 1, schtasks.exe.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_04_scheduled_task",
      ts: T(3 * MIN + 29_000),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "scheduled_task",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1053.005",
      mitre_tactic: "Persistence",
      is_detection: true, // alert-grade: the EDR behavioural crux — schtasks.exe registering the logon-triggered persistence (T1053.005)
      edr_scope: "edr",   // endpoint-primary persistence incident → investigated in the EDR console
      description:
        "Five seconds later powershell.exe spawned schtasks.exe, registering a task named NetFixOptimizer to run the AppData binary at every logon, at the highest available run level.",
      process: {
        name: "schtasks.exe",
        pid: 5188,
        path: "C:\\Windows\\System32\\schtasks.exe",
        parent_name: "powershell.exe",
        parent_pid: 5124,
        cmdline:
          "schtasks.exe /create /tn \"NetFixOptimizer\" /tr \"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\" /sc onlogon /rl highest /f",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: schtasksHash },
      },
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(3 * MIN + 29_000),
        "winlog.event_data.Image": "C:\\Windows\\System32\\schtasks.exe",
        "winlog.event_data.CommandLine":
          "schtasks.exe /create /tn \"NetFixOptimizer\" /tr \"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\" /sc onlogon /rl highest /f",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ParentCommandLine":
          "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1\"",
        "winlog.event_data.Hashes": `SHA256=${schtasksHash}`,
        "winlog.event_data.User": `NEXACORP\\${victim.sam}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.ProcessId": "5188",
        "winlog.event_data.ParentProcessId": "5124",
        "winlog.event_data.ProcessGuid": schtasksGuid,
        "winlog.event_data.ParentProcessGuid": powershellGuid,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 4b. The script launches the binary it just wrote and registered a task
    //     for — this is what actually creates the process that later makes
    //     the DNS query in evt_stp_05, so Sysmon logs it as Event ID 1 first.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_04b_payload_exec",
      ts: T(3 * MIN + 33_000),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "Four seconds after registering the scheduled task, the same PowerShell session launched netfix_agent.exe directly, once, to run immediately rather than waiting for the next logon.",
      process: {
        name: "netfix_agent.exe",
        pid: 5240,
        path: "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        parent_name: "powershell.exe",
        parent_pid: 5124,
        cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: payloadHash },
      },
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(3 * MIN + 33_000),
        "winlog.event_data.Image": "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        "winlog.event_data.CommandLine": "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ParentCommandLine":
          "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1\"",
        "winlog.event_data.Hashes": `SHA256=${payloadHash}`,
        "winlog.event_data.User": `NEXACORP\\${victim.sam}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.ProcessId": "5240",
        "winlog.event_data.ParentProcessId": "5124",
        "winlog.event_data.ProcessGuid": netfixGuid1,
        "winlog.event_data.ParentProcessGuid": powershellGuid,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The dropped binary resolves its call-home domain. Sysmon Event 22.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_05_dns_query",
      ts: T(3 * MIN + 41_000),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "dns_query",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      dns: { query: c2, query_type: "A", rcode: "0" },
      description:
        "netfix_agent.exe resolved svc-heartbeat-relay.net eight seconds after launching.",
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(3 * MIN + 41_000),
        "winlog.event_data.Image": "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        "winlog.event_data.QueryName": c2,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": "type:  1 46.246.90.12;",
        "winlog.event_data.ProcessId": "5240",
        "winlog.event_data.ProcessGuid": netfixGuid1,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The first-run check-in.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_06_beacon",
      ts: T(3 * MIN + 44_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      description:
        "netfix_agent.exe opened a TCP/443 session to svc-heartbeat-relay.net, allowed under the category newly-registered-domain.",
      network: { domain: c2, bytes_out: 1_204, bytes_in: 388 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "46.246.90.12",
        "pan.dport": "443",
        "pan.proto": "tcp",
        "pan.app": "ssl",
        "pan.category": "newly-registered-domain",
        "pan.session_id": "618317",
        "pan.bytes_sent": "1204",
        "pan.bytes_received": "388",
        "source.ip": host.ip,
        "url.domain": c2,
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 7. Hours later, at the next interactive logon, Task Scheduler proves
    //    the persistence works — a different parent, the same binary.
    // ---------------------------------------------------------------------
    {
      id: "evt_stp_07_relaunch_at_logon",
      ts: T(21 * HOUR + 6 * MIN),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1053.005",
      mitre_tactic: "Persistence",
      description:
        "At 05:11 the next morning, netfix_agent.exe launched again — this time as a child of svchost.exe (Task Scheduler), not powershell.exe, matching the NetFixOptimizer trigger.",
      process: {
        name: "netfix_agent.exe",
        pid: 2016,
        path: "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        parent_name: "svchost.exe",
        parent_pid: 1148,
        cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: payloadHash },
      },
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": host.hostname,
        "winlog.event_data.UtcTime": T(21 * HOUR + 6 * MIN),
        "winlog.event_data.Image": "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe",
        "winlog.event_data.CommandLine": "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "winlog.event_data.ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
        "winlog.event_data.Hashes": `SHA256=${payloadHash}`,
        "winlog.event_data.ProcessGuid": netfixGuid2,
        "winlog.event_data.ParentProcessGuid": svchostGuid,
        "winlog.event_data.User": `NEXACORP\\${victim.sam}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.ProcessId": "2016",
        "winlog.event_data.ParentProcessId": "1148",
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 8. The correlation rule that opened the ticket, built entirely on the
    //    Sysmon telemetry above.
    // ---------------------------------------------------------------------
    {
      // Vendor changed from "Microsoft Sysmon" — Sysmon is a passive ETW
      // logger with no detection/correlation capability of its own and no
      // "detection" namespace. This is a Sentinel analytics-rule alert built
      // on top of the Sysmon feed, so the raw fields now match the SIEM
      // correlation-alert pattern used elsewhere in this platform rather
      // than an invented Sysmon field namespace.
      id: "evt_stp_08_detection",
      ts: T(21 * HOUR + 9 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1053.005",
      description:
        "A SIEM detection rule built on the Sysmon feed fired on WS-7742: a script-spawned PowerShell process registered a Scheduled Task, and the task's target binary was observed launching from svchost.exe at the following logon.",
      raw: {
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "AlertName": "ScheduledTaskPersistence_ScriptSpawnedPowerShell",
        "alert.description":
          "schtasks.exe was spawned by powershell.exe, itself running a script downloaded minutes earlier, and registered a logon-triggered task. The task's target binary later executed as a child of svchost.exe (Schedule service), confirming the persistence mechanism is active.",
        "alert.severity": "High",
        "alert.rule.id": "SEN-PERSIST-0088",
        "ExtendedProperties.Query": "SysmonEvent1 | join SysmonEvent1 on ParentProcessGuid",
        "ExtendedProperties.Trigger Process": "schtasks.exe (parent powershell.exe)",
        "ExtendedProperties.Trigger ProcessGuid": schtasksGuid,
        "ExtendedProperties.Relaunch Process": "netfix_agent.exe (parent svchost.exe)",
        "ExtendedProperties.Relaunch ParentProcessGuid": svchostGuid,
        "host.hostname": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: payloadHash,
      first_seen: T(3 * MIN + 24_000),
      last_seen: T(21 * HOUR + 6 * MIN),
      reputation: "malicious",
      tags: ["persistence-payload", "unsigned", "appdata"],
    },
    {
      type: "sha256",
      value: scriptHash,
      first_seen: T(0),
      last_seen: T(3 * MIN + 18_000),
      reputation: "malicious",
      tags: ["powershell-downloader", "forum-distributed"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(3 * MIN + 41_000),
      last_seen: T(3 * MIN + 44_000),
      reputation: "malicious",
      tags: ["c2", "newly-registered", "beacon"],
    },
    {
      type: "domain",
      value: downloadSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["script-distribution", "forum-linked"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(21 * HOUR + 9 * MIN),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which single event is the point where this stops being 'a script ran' and becomes 'a persistent foothold exists on this host'?",
      hint: "A payload that only ran once and was never seen again would still be a problem, but not this kind of problem. What changes that?",
      kind: "single",
      options: [
        { value: "scheduled_task", label: "evt_stp_04_scheduled_task — schtasks.exe registers NetFixOptimizer to run the payload at every logon" },
        { value: "payload_written", label: "evt_stp_03_payload_written — the payload existing on disk is what makes this persistent" },
        { value: "script_run", label: "evt_stp_02_script_run — running the downloaded script is the persistence" },
        { value: "beacon", label: "evt_stp_06_beacon — the outbound connection is what establishes persistence" },
      ],
      answer: "scheduled_task",
      xp: 50,
      explanation:
        "A file sitting on disk (b) is not persistence by itself — nothing makes it run again once the current session ends, and if the process that started it is killed, it is simply gone. Running the script once (c) is execution, not persistence — the same is true of every one-off command a user has ever typed. The connection out (d) is a symptom of the payload running, not the mechanism that gets it running again. evt_stp_04 is the actual mechanism: /sc onlogon means Windows itself will relaunch the target binary at every future logon, with no further action from the attacker required. That is what 'persistent' means.",
    },
    {
      id: "q2",
      prompt:
        "evt_stp_07 shows netfix_agent.exe launching again, roughly 21 hours after evt_stp_04, this time as a child of svchost.exe rather than powershell.exe. Why does that specific detail matter to an investigator?",
      kind: "single",
      options: [
        { value: "confirms_task_fired", label: "It confirms the task fired: the parent is svchost.exe hosting the Schedule service, exactly what Windows uses to launch scheduled tasks" },
        { value: "different_malware", label: "It means a second, unrelated piece of malware is now also running on the host alongside the first" },
        { value: "process_injection", label: "It proves netfix_agent.exe injected its code into svchost.exe specifically to hide from detection" },
        { value: "irrelevant_detail", label: "The parent process is an incidental detail and adds nothing beyond what evt_stp_04 already showed" },
      ],
      answer: "confirms_task_fired",
      xp: 60,
      explanation:
        "winlog.event_data.ParentCommandLine in evt_stp_07 reads 'svchost.exe -k netsvcs -p -s Schedule' — that is literally the Windows Task Scheduler service process. Seeing the exact same binary and hash (payloadHash) launch again with that specific parent, at a plausible next-logon time, is direct proof that the persistence mechanism registered in evt_stp_04 is not just configured but working. Without this event, an analyst would only have the registration command and would have to assume it succeeded. Nothing here indicates injection (c) — the file.hash.sha256 matches the original binary exactly, and there is no second unrelated payload (b); it is the same file, launched by the mechanism set up hours earlier.",
    },
    {
      id: "q3",
      prompt:
        "This scenario uses only Sysmon Event IDs 1, 11 and 22 — no Windows Security Event Log (channel Security, Event ID 4698) appears anywhere. What does that tell you about how the scheduled task creation was actually detected?",
      kind: "single",
      options: [
        { value: "process_not_task_log", label: "It was detected from the process that created the task (schtasks.exe and its command line), not from a dedicated 'task created' audit event" },
        { value: "task_didnt_register", label: "Since no 4698 event exists, the task was never actually registered with Task Scheduler" },
        { value: "sysmon_broken", label: "Sysmon should have generated an event for the task creation and failed to" },
        { value: "not_detectable", label: "Without Security auditing enabled, scheduled task persistence cannot be detected at all" },
      ],
      answer: "process_not_task_log",
      xp: 60,
      explanation:
        "Sysmon does not have a scheduled-task-specific event type — what it logs is the process that ran schtasks.exe, with its full command line, which is exactly evt_stp_04. That single event contains everything needed to know a task was created, its name, and its target: no dedicated audit log is required, and this is in fact the standard way Sysmon-based detection content catches T1053.005 in practice. Event ID 4698 is a genuinely different, Windows Security Event Log record that requires separate audit policy configuration — its absence here doesn't mean the task wasn't created (evt_stp_07 proves it was) or that Sysmon is malfunctioning; it means this particular telemetry pipeline relies on process-creation visibility instead.",
    },
    {
      id: "q4",
      prompt:
        "The connection in evt_stp_06 was allowed, not blocked, and the DNS query in evt_stp_05 resolved without any restriction. Given that, what should the response plan for this host include?",
      kind: "single",
      options: [
        { value: "remove_task_and_binary", label: "Delete the NetFixOptimizer scheduled task and the netfix_agent.exe binary, then verify no task remains before considering the host clean" },
        { value: "block_domain_sufficient", label: "Block svc-heartbeat-relay.net at the firewall; once the C2 can't be reached, the host is effectively contained" },
        { value: "kill_process_sufficient", label: "Kill the current netfix_agent.exe process; since it isn't running as SYSTEM, it poses no further risk" },
        { value: "wait_for_next_alert", label: "No action needed yet — wait to see if the correlation rule fires again before responding" },
      ],
      answer: "remove_task_and_binary",
      xp: 60,
      explanation:
        "Blocking the domain (b) or killing the running process (c) both address the current symptom while leaving the actual mechanism — the NetFixOptimizer task — fully intact. The task will simply relaunch the binary at the next logon, and if the operators simply update their DNS or the payload's embedded domain, the block becomes stale. The only response that matches the evidence is removing both the task registration and the file it points to, then explicitly checking Task Scheduler to confirm nothing remains — exactly the check evt_stp_07 shows was missing the first time, since the task fired again 21 hours after it was created and nobody had removed it yet.",
    },
    {
      id: "q5",
      prompt:
        "Which detail distinguishes this scheduled task from a normal, IT-managed scheduled task an analyst might see on any given day?",
      kind: "single",
      options: [
        { value: "chain_of_custody", label: "The full chain: a forum-downloaded script spawned the process that registered the task, targeting a binary the same script had just written to AppData" },
        { value: "onlogon_trigger", label: "Its use of an onlogon trigger, a scheduling option that only malicious tasks are ever configured with" },
        { value: "rl_highest", label: "Its request for /rl highest, a run level that only administrator accounts are ever able to specify" },
        { value: "task_name", label: "The task name NetFixOptimizer, which is itself a well-known malicious string flagged by threat intel" },
      ],
      answer: "chain_of_custody",
      xp: 50,
      explanation:
        "IT-managed scheduled tasks are created by known deployment tools, run from Program Files or a management agent's install path, and register cleanly through documented change processes — none of that context exists here. What makes this task suspicious is not any single argument on its command line (onlogon triggers and /rl highest are both used constantly by entirely legitimate software) but the full provenance: a script fetched from a site with no relationship to the organisation, run interactively by an end user, spawning the exact process that registered the task, pointed at a binary written to the user's own AppData folder seconds earlier. The task name itself is meaningless — attackers can and do name tasks anything that sounds boring.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Fix My Internet — Scheduled-Task Persistence from a Downloaded Script",
    threat_actor: "Commodity persistence-loader distributor (forum-linked script)",
    attack_kind: "scheduled_task_persistence",
    briefing:
      "A SIEM correlation rule fired on WS-7742 overnight: a binary written by a PowerShell script the previous morning relaunched at logon as a child of the Task Scheduler service. Work out how it got persistence and what it does when it runs.",
    narrative: `At 08:05 Shani Attia downloaded SpeedBoost_NetFix.ps1 from netfix-tools-download.com, a script linked from a forum thread promising to fix a slow home-office VPN connection. She ran it just over three minutes later: powershell.exe -ExecutionPolicy Bypass -File, launched directly by explorer.exe.

Six seconds in, the script wrote C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe. Five seconds after that, it spawned schtasks.exe with a single, decisive command: register a task called NetFixOptimizer to run that binary at every logon, at the highest available privilege level, no confirmation required. Twelve seconds later, netfix_agent.exe resolved svc-heartbeat-relay.net and opened a TCP/443 session to it — the first check-in.

Nothing about that first run looked catastrophic. It was one script, one dropped file, one outbound connection that the firewall allowed under a category nobody blocks by default.

The evidence that this mattered arrived 21 hours later. At 05:11 the next morning, netfix_agent.exe started again — same file, same hash, but this time launched by svchost.exe running the Schedule service, not by anything the user did. The scheduled task had fired exactly as it was built to. A SIEM detection rule built on the Sysmon feed connected the two events three minutes later: a script-spawned PowerShell process registering a task, and that task's target binary actually executing at the next logon, on a host where nobody had removed anything in between.`,
    learning_objectives: [
      "Identify Scheduled Task/Job persistence (T1053.005) from a schtasks.exe command line, independent of what the payload itself does",
      "Recognise PowerShell script execution (T1059.001) launched by explorer.exe from a downloaded file",
      "Use a changed parent process (svchost.exe running the Schedule service) as direct proof a persistence mechanism is active",
      "Understand how Sysmon Event IDs 1, 11 and 22 alone can detect T1053.005 without a dedicated Windows Security 4698 event",
      "Build a remediation plan that removes the persistence mechanism itself, not just the currently running process",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `SpeedBoost_NetFix.ps1 downloaded from ${downloadSite}` },
      { ts: T(3 * MIN + 18_000), phase: "Execution", action: "explorer.exe launches powershell.exe running the downloaded script (T1059.001)" },
      { ts: T(3 * MIN + 24_000), phase: "Execution", action: "netfix_agent.exe written to AppData\\Local\\NetFixSvc" },
      { ts: T(3 * MIN + 29_000), phase: "Persistence", action: "schtasks.exe registers NetFixOptimizer to run at every logon (T1053.005)" },
      { ts: T(3 * MIN + 33_000), phase: "Execution", action: "powershell.exe launches netfix_agent.exe directly for an immediate first run" },
      { ts: T(3 * MIN + 41_000), phase: "Command and Control", action: `netfix_agent.exe resolves ${c2}` },
      { ts: T(3 * MIN + 44_000), phase: "Command and Control", action: "First outbound check-in, allowed as newly-registered-domain (T1071.001)" },
      { ts: T(21 * HOUR + 6 * MIN), phase: "Persistence", action: "netfix_agent.exe relaunches at logon as a child of svchost.exe — the task firing (T1053.005)" },
      { ts: T(21 * HOUR + 9 * MIN), phase: "Detection", action: "SIEM correlation rule fires on the Sysmon telemetry" },
    ],
    questions,
  };
}
