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
import { sysmonProcess, sysmonFile, sysmonDns, sysmonNetwork } from "@/lib/sim/emitters/sysmon";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { winLogon, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";
import { winTaskCreated } from "@/lib/sim/emitters/scenarioExtras";

/** Telemetry half of `buildScheduledTaskPersistenceScenario`: the events and the story title, no answer key. */
export function scheduledTaskPersistenceScenarioEvents() {
  const B = new Date("2026-04-13T08:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;
  /** Offset (ms) of the task's daily trigger on day 2: 07:50:00, 23h45m after the first download. */
  const D2 = 23 * HOUR + 45 * MIN;

  const host = { hostname: "WS-7742", ip: "10.14.9.201" };
  const victim = { email: "s.attia@nexacorp.com", name: "Shani Attia", sam: "s.attia" };

  const downloadSite = "netfix-tools-download.com";
  const siteIp = "172.67.140.55";
  const c2 = "svc-heartbeat-relay.net";
  const c2Ip = "46.246.90.12";

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
  const chromeGuid     = "{a53f7d10-eabb-6600-0000-0010c7e10300}"; // chrome.exe, pre-existing
  const powershellGuid = "{a53f7d10-eaec-6600-0000-0010e6210400}"; // evt_stp_02, PID 5124
  const schtasksGuid   = "{a53f7d10-eaf1-6600-0000-0010128b0400}"; // evt_stp_04, PID 5188
  const netfixGuid1    = "{a53f7d10-eafd-6600-0000-0010b3f60400}"; // first run, PID 5240
  const svchostGuid    = "{a53f7d05-2a1b-6600-0000-0010f4c20100}"; // Schedule service host, pre-existing
  const netfixGuid2    = "{a53f7d29-4763-6600-0000-0010a9d90800}"; // second run (task trigger), PID 2016

  // Two EDR cases for the one host: the day-1 delivery and registration, and the day-2
  // task firing. The two netfix_agent.exe instances are different processes (different
  // pid, ProcessGuid and logon session), so they cannot share one case identity.
  const INCIDENT = "inc:stp:1";
  const INCIDENT2 = "inc:stp:2";

  const cx = { companyId: "nexacorp" as const, host: host.hostname, user: victim.email, srcIp: host.ip };
  const PW = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const SCRIPT = "C:\\Users\\s.attia\\Downloads\\SpeedBoost_NetFix.ps1";
  // What Explorer's "Run with PowerShell" verb starts: it relaxes the policy for the process only.
  const PWCMD = `"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -Command "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & '${SCRIPT}'"`;
  const AGENT = "C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe";
  const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

  const day1Logon = { guid: "{a53f7d10-e9f0-6600-0000-0020c41a0400}", id: "0x1F4A2C" };
  const day2Logon = { guid: "{a53f7d29-4701-6600-0000-0020e8360800}", id: "0x3B91E7" };
  const userSid = domainSidFor("nexacorp", victim.sam);

  // The task as schtasks.exe /create /sc daily /st 07:50 stores it (Security 4698 TaskContent).
  const taskXml =
    `<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n` +
    `  <RegistrationInfo>\n    <Date>2026-04-13T08:08:29.4126518</Date>\n    <Author>NEXACORP\\s.attia</Author>\n    <URI>\\NetFixOptimizer</URI>\n  </RegistrationInfo>\n` +
    `  <Principals>\n    <Principal id="Author">\n      <UserId>${userSid}</UserId>\n      <LogonType>InteractiveToken</LogonType>\n    </Principal>\n  </Principals>\n` +
    `  <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n    <AllowHardTerminate>true</AllowHardTerminate>\n    <StartWhenAvailable>false</StartWhenAvailable>\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n    <AllowStartOnDemand>true</AllowStartOnDemand>\n    <Enabled>true</Enabled>\n    <Hidden>false</Hidden>\n    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\n    <Priority>7</Priority>\n  </Settings>\n` +
    `  <Triggers>\n    <CalendarTrigger>\n      <StartBoundary>2026-04-13T07:50:00</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n    </CalendarTrigger>\n  </Triggers>\n` +
    `  <Actions Context="Author">\n    <Exec>\n      <Command>${AGENT}</Command>\n    </Exec>\n  </Actions>\n</Task>`;

  /** Sysmon 3 carries the connecting process only in its EventData; the EDR console attaches it through the process node. */
  const withProc = (e: TelemetryEvent, name: string, pid: number, path: string, parent?: { name: string; pid: number }): TelemetryEvent => ({
    ...e, process: { name, pid, path, ...(parent ? { parent_name: parent.name, parent_pid: parent.pid } : {}), user: "NEXACORP\\s.attia", integrity: "medium" },
  });

  const events: TelemetryEvent[] = [
    // 0a. The browser resolves the site the forum post pointed at (Sysmon 22, chrome.exe).
    sysmonDns({
      ...cx, id: "evt_stp_00a_dns_site", ts: T(-2_000), processName: "chrome.exe", processPath: CHROME, pid: 7316,
      processGuid: chromeGuid, domain: downloadSite, resolvedIp: siteIp, severity: "low",
      description: "chrome.exe on WS-7742 resolved netfix-tools-download.com two seconds before the first firewall record for it.",
    }),

    // 0b. URL-filtering record for the page that served the script.
    panWeb({
      ...cx, id: "evt_stp_00b_url", ts: T(-1_000), url: `https://${downloadSite}/scripts/SpeedBoost_NetFix.ps1`,
      domain: downloadSite, method: "GET", action: "alert", category: "computer-and-internet-info",
      dstIp: siteIp, status: 200, userAgent: UA, userTitle: "HR Coordinator", severity: "low",
      description: "URL-filtering record for the request to netfix-tools-download.com/scripts/SpeedBoost_NetFix.ps1, allowed under computer-and-internet-info.",
    }),

    // 1. The download — a forum-linked "fix".
    panWeb({
      ...cx, id: "evt_stp_01_download", ts: T(0), url: `https://${downloadSite}/scripts/SpeedBoost_NetFix.ps1`,
      domain: downloadSite, method: "GET", action: "alert", category: "computer-and-internet-info",
      dstIp: siteIp, status: 200, bytesIn: 4_216, userTitle: "HR Coordinator",
      file: { name: "SpeedBoost_NetFix.ps1", path: "/scripts/SpeedBoost_NetFix.ps1", sha256: scriptHash, size: 4_216 },
      fileType: "script", mitre: "T1189", tactic: "Initial Access", severity: "low",
      description:
        "WS-7742 downloaded SpeedBoost_NetFix.ps1 from netfix-tools-download.com at 08:05, allowed under the category computer-and-internet-info.",
    }),

    // 1b. The browser saves it into Downloads (Sysmon 11, chrome.exe).
    {
      ...sysmonFile({
        ...cx, id: "evt_stp_01b_script_saved", ts: T(3_000), processName: "chrome.exe", processPath: CHROME, pid: 7316,
        processGuid: chromeGuid, path: SCRIPT, sha256: scriptHash, fileSize: 4_216, severity: "low",
        description: "chrome.exe wrote SpeedBoost_NetFix.ps1 into C:\\Users\\s.attia\\Downloads three seconds after the firewall record.",
      }),
      process: { name: "chrome.exe", pid: 7316, path: CHROME, parent_name: "explorer.exe", parent_pid: 3116, user: "NEXACORP\\s.attia", integrity: "medium" },
    },

    // 2. The user runs it (Sysmon 1).
    sysmonProcess({
      ...cx, id: "evt_stp_02_script_run", ts: T(3 * MIN + 18_000), processName: "powershell.exe", processPath: PW,
      cmdline: PWCMD, parentName: "explorer.exe", parentPath: "C:\\Windows\\explorer.exe", parentCmdline: "C:\\Windows\\Explorer.EXE",
      pid: 5124, parentPid: 3116, sha256: powershellHash, integrity: "Medium",
      processGuid: powershellGuid, parentGuid: explorerGuid, mitre: "T1059.001", tactic: "Execution", severity: "high",
      description:
        "At 08:08:18 explorer.exe started powershell.exe through the Run with PowerShell verb, with a process-scope execution-policy bypass, running the downloaded script from Downloads.",
    }),

    // 2a. The script connects to the same site for its second file (Sysmon 3).
    withProc(sysmonNetwork({
      ...cx, id: "evt_stp_02a_net_site", ts: T(3 * MIN + 20_000), processName: "powershell.exe", processPath: PW, pid: 5124,
      remoteIp: siteIp, remotePort: 443, remoteHost: downloadSite, severity: "medium",
      description: "powershell.exe opened a TCP/443 connection to netfix-tools-download.com two seconds after the script started.",
    }), "powershell.exe", 5124, PW, { name: "explorer.exe", pid: 3116 }),

    // 2b. The script fetches its payload binary — the origin of netfix_agent.exe.
    panWeb({
      ...cx, id: "evt_stp_02b_payload_download", ts: T(3 * MIN + 21_000), url: `https://${downloadSite}/agent/netfix_agent.exe`,
      domain: downloadSite, method: "GET", action: "alert", category: "computer-and-internet-info",
      dstIp: siteIp, status: 200, bytesIn: 318_976, userAgent: "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.4391",
      file: { name: "netfix_agent.exe", path: "/agent/netfix_agent.exe", sha256: payloadHash, size: 318_976 },
      fileType: "pe", mitre: "T1105", tactic: "Command and Control", severity: "medium",
      description:
        "Three seconds after the script started, WS-7742 fetched netfix_agent.exe from netfix-tools-download.com — the binary the script then wrote to disk.",
    }),

    // 3. The script drops its payload (Sysmon 11).
    {
      ...sysmonFile({
        ...cx, id: "evt_stp_03_payload_written", ts: T(3 * MIN + 24_000), processName: "powershell.exe", processPath: PW,
        pid: 5124, processGuid: powershellGuid, path: AGENT, sha256: payloadHash, fileSize: 318_976, severity: "medium",
        description: "Six seconds later the script wrote C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe, unsigned.",
      }),
      process: { name: "powershell.exe", pid: 5124, path: PW, parent_name: "explorer.exe", parent_pid: 3116, cmdline: PWCMD, user: "NEXACORP\\s.attia", integrity: "medium" },
    },

    // 4. THE EVENT THAT MATTERS — persistence registered (Sysmon 1, schtasks.exe).
    {
      ...sysmonProcess({
        ...cx, id: "evt_stp_04_scheduled_task", ts: T(3 * MIN + 29_000), processName: "schtasks.exe", processPath: "C:\\Windows\\System32\\schtasks.exe",
        cmdline: "schtasks.exe /create /tn \"NetFixOptimizer\" /tr \"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\" /sc daily /st 07:50 /f",
        parentName: "powershell.exe", parentPath: PW, parentCmdline: PWCMD, pid: 5188, parentPid: 5124,
        sha256: schtasksHash, integrity: "Medium", processGuid: schtasksGuid, parentGuid: powershellGuid,
        eventType: "scheduled_task", isDetection: true, mitre: "T1053.005", tactic: "Persistence", severity: "high",
        description:
          "Five seconds later powershell.exe spawned schtasks.exe, registering a per-user task named NetFixOptimizer to run the AppData binary every day at 07:50 (no elevation — the user is not a local admin).",
      }),
      edr_scope: "edr",
    },

    // 4a. The same registration in the Security log (4698).
    winTaskCreated({
      id: "evt_stp_04a_task_audit", ts: T(3 * MIN + 29_500), companyId: "nexacorp", host: host.hostname, user: victim.sam,
      userEmail: victim.email, userSid, subjectLogonId: day1Logon.id, taskName: "\\NetFixOptimizer", taskContent: taskXml,
      severity: "medium", mitre: "T1053.005", tactic: "Persistence",
      description: "Security 4698 on WS-7742: a scheduled task named \\NetFixOptimizer was created by s.attia, with a daily trigger and the AppData binary as its action.",
    }),

    // 4b. The script launches the binary directly for an immediate first run (Sysmon 1).
    sysmonProcess({
      ...cx, id: "evt_stp_04b_payload_exec", ts: T(3 * MIN + 33_000), processName: "netfix_agent.exe", processPath: AGENT,
      cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"", parentName: "powershell.exe", parentPath: PW,
      parentCmdline: PWCMD, pid: 5240, parentPid: 5124, sha256: payloadHash, integrity: "Medium",
      processGuid: netfixGuid1, parentGuid: powershellGuid, severity: "high",
      description:
        "Four seconds after registering the scheduled task, the same PowerShell session launched netfix_agent.exe directly, once, to run immediately rather than waiting for the next trigger.",
    }),

    // 5. The binary resolves its call-home domain (Sysmon 22).
    sysmonDns({
      ...cx, id: "evt_stp_05_dns_query", ts: T(3 * MIN + 41_000), processName: "netfix_agent.exe", processPath: AGENT,
      pid: 5240, processGuid: netfixGuid1, domain: c2, resolvedIp: c2Ip, severity: "medium",
      description: "netfix_agent.exe resolved svc-heartbeat-relay.net eight seconds after launching.",
    }),

    // 5b. The first outbound connection of the binary (Sysmon 3).
    withProc(sysmonNetwork({
      ...cx, id: "evt_stp_05b_net_c2", ts: T(3 * MIN + 42_000), processName: "netfix_agent.exe", processPath: AGENT, pid: 5240,
      remoteIp: c2Ip, remotePort: 443, remoteHost: c2, severity: "high",
      description: "netfix_agent.exe opened a TCP/443 connection to 46.246.90.12 one second after the DNS answer.",
    }), "netfix_agent.exe", 5240, AGENT, { name: "powershell.exe", pid: 5124 }),

    // 6. The first-run check-in.
    panConnection({
      ...cx, id: "evt_stp_06_beacon", ts: T(3 * MIN + 44_000), domain: c2, dstIp: c2Ip, remotePort: 443,
      app: "ssl", transport: "tcp", action: "allow", end: true, bytesOut: 1_204, bytesIn: 388, elapsedSec: 2,
      category: "newly-registered-domain", mitre: "T1071.001", tactic: "Command and Control", severity: "high",
      description:
        "netfix_agent.exe opened a TCP/443 session to svc-heartbeat-relay.net, allowed under the category newly-registered-domain.",
    }),

    // ── Day 2 ────────────────────────────────────────────────────────────────────────
    // 6b. The user signs in at the start of the working day (Security 4624, interactive).
    winLogon({
      id: "evt_stp_06b_next_day_logon", ts: T(D2 - 230_000), companyId: "nexacorp", host: host.hostname, targetUser: victim.sam,
      userEmail: victim.email, targetSid: userSid, logSource: "windows_security", logonType: 2, authPackage: "Negotiate",
      logonProcess: "User32 ", workstation: host.hostname, logonId: day2Logon.id, processName: "C:\\Windows\\System32\\winlogon.exe",
      subjectSid: "S-1-5-18", subjectUser: `${host.hostname}$`, severity: "informational",
      description: "4624 on WS-7742: s.attia signed in interactively at 07:46, four minutes before the 07:50 trigger time.",
    }),

    // 7. The task's trigger time arrives — the Schedule service starts the binary (Sysmon 1, parent svchost.exe).
    sysmonProcess({
      ...cx, id: "evt_stp_07_relaunch_at_trigger", ts: T(D2 + 2_000), processName: "netfix_agent.exe", processPath: AGENT,
      cmdline: "\"C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe\"", parentName: "svchost.exe",
      parentPath: "C:\\Windows\\System32\\svchost.exe", parentCmdline: "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
      pid: 2016, parentPid: 1148, sha256: payloadHash, integrity: "Medium", processGuid: netfixGuid2, parentGuid: svchostGuid,
      mitre: "T1053.005", tactic: "Persistence", severity: "high",
      description:
        "At 07:50:02 the next morning, netfix_agent.exe launched again — this time as a child of svchost.exe (Task Scheduler), not powershell.exe, at the 07:50 time the NetFixOptimizer trigger names.",
    }),

    // 7a. What it does when it runs: the same check-in (Sysmon 22, 3 and the firewall session).
    sysmonDns({
      ...cx, id: "evt_stp_07a_dns_query", ts: T(D2 + 9_000), processName: "netfix_agent.exe", processPath: AGENT,
      pid: 2016, processGuid: netfixGuid2, domain: c2, resolvedIp: c2Ip, severity: "medium",
      description: "The relaunched netfix_agent.exe resolved svc-heartbeat-relay.net seven seconds after starting.",
    }),
    withProc(sysmonNetwork({
      ...cx, id: "evt_stp_07b_net_c2", ts: T(D2 + 11_000), processName: "netfix_agent.exe", processPath: AGENT, pid: 2016,
      remoteIp: c2Ip, remotePort: 443, remoteHost: c2, severity: "high",
      description: "The relaunched netfix_agent.exe opened a TCP/443 connection to 46.246.90.12.",
    }), "netfix_agent.exe", 2016, AGENT, { name: "svchost.exe", pid: 1148 }),
    panConnection({
      ...cx, id: "evt_stp_07c_beacon", ts: T(D2 + 13_000), domain: c2, dstIp: c2Ip, remotePort: 443,
      app: "ssl", transport: "tcp", action: "allow", end: true, bytesOut: 1_212, bytesIn: 396, elapsedSec: 2,
      category: "newly-registered-domain", mitre: "T1071.001", tactic: "Command and Control", severity: "high",
      description: "A second TCP/443 session to svc-heartbeat-relay.net with the same size pattern as the day-1 check-in.",
    }),

    // 8. The SIEM correlation that opened the ticket.
    sentinelAlert({
      ...cx, id: "evt_stp_08_detection", ts: T(D2 + 6 * MIN), alertName: "ScheduledTaskPersistence_ScriptSpawnedPowerShell",
      ruleId: "SEN-PERSIST-0088", severity: "critical", eventType: "ueba_anomaly", mitre: "T1053.005", tactic: "Persistence",
      detail:
        "schtasks.exe was spawned by powershell.exe, itself running a script downloaded minutes earlier, and registered a daily task. The task's target binary later executed as a child of svchost.exe (Schedule service) at the trigger time.",
      extendedProperties: {
        "Query": "SysmonEvent1 | join SysmonEvent1 on ParentProcessGuid",
        "Trigger Process": "schtasks.exe (parent powershell.exe)",
        "Trigger ProcessGuid": schtasksGuid,
        "Relaunch Process": "netfix_agent.exe (parent svchost.exe)",
        "Relaunch ParentProcessGuid": svchostGuid,
      },
      description:
        "A SIEM detection rule built on the Sysmon feed fired on WS-7742: a script-spawned PowerShell process registered a Scheduled Task, and the task's target binary was observed launching from svchost.exe at the trigger time the next morning.",
    }),
  ];

  // Day-1 events are one incident; the day-2 task firing is a second one (a new process
  // instance in a new logon session, so it gets its own case on the same host).
  for (const e of events) e.incident_id = Date.parse(e.ts) >= B + D2 - 240_000 ? INCIDENT2 : INCIDENT;

  // Sysmon Event 1 carries the session's LogonGuid/LogonId. Day-1 runs share the
  // user's first interactive session; the next-morning launch is a NEW logon session
  // (the 4624 above), so it carries a different LogonGuid/LogonId.
  for (const e of events) {
    if (e.source !== "sysmon" || e.event_type === "dns_query") continue;
    const l = e.incident_id === INCIDENT2 ? day2Logon : day1Logon;
    if (e.raw) { e.raw["winlog.event_data.LogonGuid"] = l.guid; e.raw["winlog.event_data.LogonId"] = l.id; }
  }

  return { title: "SIEM alert on an HR coordinator's laptop", events, T, MIN, HOUR, D2, host, downloadSite, c2, c2Ip, scriptHash, payloadHash };
}
