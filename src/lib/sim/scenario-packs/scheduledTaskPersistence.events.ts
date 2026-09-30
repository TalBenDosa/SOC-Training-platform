/**
 * Events-only half of the ./scheduledTaskPersistence.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./scheduledTaskPersistence.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { sysmonProcess, sysmonFile, sysmonDns } from "@/lib/sim/emitters/sysmon";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildScheduledTaskPersistenceScenario`: the events and the story title, no answer key. */
export function scheduledTaskPersistenceScenarioEvents() {
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

  const cx = { companyId: "nexacorp" as const, host: host.hostname, user: victim.email, srcIp: host.ip };
  const PW = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const PWCMD = "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1\"";
  const AGENT = "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe";

  const events: TelemetryEvent[] = [
    // 1. The download — a forum-linked "fix".
    panWeb({
      ...cx, id: "evt_stp_01_download", ts: T(0), url: `https://${downloadSite}/scripts/SpeedBoost_NetFix.ps1`,
      domain: downloadSite, method: "GET", action: "alert", category: "computer-and-internet-info",
      dstIp: "172.67.140.55", status: 200, bytesIn: 4_216, userTitle: "HR Coordinator",
      file: { name: "SpeedBoost_NetFix.ps1", path: "/scripts/SpeedBoost_NetFix.ps1", sha256: scriptHash, size: 4_216 },
      fileType: "script", mitre: "T1189", tactic: "Initial Access", severity: "low",
      description:
        "WS-7742 downloaded SpeedBoost_NetFix.ps1 from netfix-tools-download.com at 08:05, allowed under the category computer-and-internet-info.",
    }),

    // 2. The user runs it (Sysmon 1).
    sysmonProcess({
      ...cx, id: "evt_stp_02_script_run", ts: T(3 * MIN + 18_000), processName: "powershell.exe", processPath: PW,
      cmdline: PWCMD, parentName: "explorer.exe", parentPath: "C:\\Windows\\explorer.exe", parentCmdline: "C:\\Windows\\Explorer.EXE",
      pid: 5124, parentPid: 3116, sha256: powershellHash, integrity: "Medium",
      processGuid: powershellGuid, parentGuid: explorerGuid, mitre: "T1059.001", tactic: "Execution", severity: "high",
      description:
        "At 08:08:18 explorer.exe started powershell.exe with an execution-policy bypass, running the downloaded script directly from Downloads.",
    }),

    // 3. The script drops its payload (Sysmon 11).
    sysmonFile({
      ...cx, id: "evt_stp_03_payload_written", ts: T(3 * MIN + 24_000), processName: "powershell.exe", processPath: PW,
      pid: 5124, processGuid: powershellGuid, path: AGENT, sha256: payloadHash, fileSize: 318_976, severity: "medium",
      description: "Six seconds later the script wrote C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe, unsigned.",
    }),

    // 4. THE EVENT THAT MATTERS — persistence registered (Sysmon 1, schtasks.exe).
    {
      ...sysmonProcess({
        ...cx, id: "evt_stp_04_scheduled_task", ts: T(3 * MIN + 29_000), processName: "schtasks.exe", processPath: "C:\\Windows\\System32\\schtasks.exe",
        cmdline: "schtasks.exe /create /tn \"NetFixOptimizer\" /tr \"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\" /sc onlogon /rl highest /f",
        parentName: "powershell.exe", parentPath: PW, parentCmdline: PWCMD, pid: 5188, parentPid: 5124,
        sha256: schtasksHash, integrity: "Medium", processGuid: schtasksGuid, parentGuid: powershellGuid,
        eventType: "scheduled_task", isDetection: true, mitre: "T1053.005", tactic: "Persistence", severity: "high",
        description:
          "Five seconds later powershell.exe spawned schtasks.exe, registering a task named NetFixOptimizer to run the AppData binary at every logon, at the highest available run level.",
      }),
      edr_scope: "edr",
    },

    // 4b. The script launches the binary directly for an immediate first run (Sysmon 1).
    sysmonProcess({
      ...cx, id: "evt_stp_04b_payload_exec", ts: T(3 * MIN + 33_000), processName: "netfix_agent.exe", processPath: AGENT,
      cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"", parentName: "powershell.exe", parentPath: PW,
      parentCmdline: PWCMD, pid: 5240, parentPid: 5124, sha256: payloadHash, integrity: "Medium",
      processGuid: netfixGuid1, parentGuid: powershellGuid, severity: "high",
      description:
        "Four seconds after registering the scheduled task, the same PowerShell session launched netfix_agent.exe directly, once, to run immediately rather than waiting for the next logon.",
    }),

    // 5. The binary resolves its call-home domain (Sysmon 22).
    sysmonDns({
      ...cx, id: "evt_stp_05_dns_query", ts: T(3 * MIN + 41_000), processName: "netfix_agent.exe", processPath: AGENT,
      pid: 5240, processGuid: netfixGuid1, domain: c2, resolvedIp: "46.246.90.12", severity: "medium",
      description: "netfix_agent.exe resolved svc-heartbeat-relay.net eight seconds after launching.",
    }),

    // 6. The first-run check-in.
    panConnection({
      ...cx, id: "evt_stp_06_beacon", ts: T(3 * MIN + 44_000), domain: c2, dstIp: "46.246.90.12", remotePort: 443,
      app: "ssl", transport: "tcp", action: "allow", end: true, bytesOut: 1_204, bytesIn: 388,
      category: "newly-registered-domain", mitre: "T1071.001", tactic: "Command and Control", severity: "high",
      description:
        "netfix_agent.exe opened a TCP/443 session to svc-heartbeat-relay.net, allowed under the category newly-registered-domain.",
    }),

    // 7. Relaunch at logon — the task firing (Sysmon 1, parent svchost.exe).
    sysmonProcess({
      ...cx, id: "evt_stp_07_relaunch_at_logon", ts: T(21 * HOUR + 6 * MIN), processName: "netfix_agent.exe", processPath: AGENT,
      cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"", parentName: "svchost.exe",
      parentPath: "C:\\Windows\\System32\\svchost.exe", parentCmdline: "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
      pid: 2016, parentPid: 1148, sha256: payloadHash, integrity: "Medium", processGuid: netfixGuid2, parentGuid: svchostGuid,
      mitre: "T1053.005", tactic: "Persistence", severity: "high",
      description:
        "At 05:11 the next morning, netfix_agent.exe launched again — this time as a child of svchost.exe (Task Scheduler), not powershell.exe, matching the NetFixOptimizer trigger.",
    }),

    // 8. The SIEM correlation that opened the ticket.
    sentinelAlert({
      ...cx, id: "evt_stp_08_detection", ts: T(21 * HOUR + 9 * MIN), alertName: "ScheduledTaskPersistence_ScriptSpawnedPowerShell",
      ruleId: "SEN-PERSIST-0088", severity: "critical", eventType: "ueba_anomaly", mitre: "T1053.005",
      detail:
        "schtasks.exe was spawned by powershell.exe, itself running a script downloaded minutes earlier, and registered a logon-triggered task. The task's target binary later executed as a child of svchost.exe (Schedule service), confirming the persistence mechanism is active.",
      extendedProperties: {
        "Query": "SysmonEvent1 | join SysmonEvent1 on ParentProcessGuid",
        "Trigger Process": "schtasks.exe (parent powershell.exe)",
        "Trigger ProcessGuid": schtasksGuid,
        "Relaunch Process": "netfix_agent.exe (parent svchost.exe)",
        "Relaunch ParentProcessGuid": svchostGuid,
      },
      description:
        "A SIEM detection rule built on the Sysmon feed fired on WS-7742: a script-spawned PowerShell process registered a Scheduled Task, and the task's target binary was observed launching from svchost.exe at the following logon.",
    }),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Fix My Internet — Scheduled-Task Persistence from a Downloaded Script", events, T, MIN, HOUR, host, downloadSite, c2, scriptHash, payloadHash };
}
