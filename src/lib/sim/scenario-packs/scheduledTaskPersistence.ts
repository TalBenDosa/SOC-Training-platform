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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { scheduledTaskPersistenceScenarioEvents } from "./scheduledTaskPersistence.events";

export function buildScheduledTaskPersistenceScenario(
  scenarioId = "scheduled-task-persistence-2026",
): ScenarioBundle {
  const { title, events, T, MIN, HOUR, host, downloadSite, c2, scriptHash, payloadHash } = scheduledTaskPersistenceScenarioEvents();

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
        { value: "scheduled_task", label: "schtasks.exe, spawned by the script, registering NetFixOptimizer to relaunch the dropped binary at every logon" },
        { value: "payload_written", label: "The script writing netfix_agent.exe into AppData\\Local\\NetFixSvc, since a binary stored in the user profile survives a reboot" },
        { value: "script_run", label: "explorer.exe launching powershell.exe with -ExecutionPolicy Bypass, since the policy bypass keeps the script active across sessions" },
        { value: "beacon", label: "netfix_agent.exe opening its TCP/443 session to svc-heartbeat-relay.net, since the C2 channel is what keeps the attacker on the host" },
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
        { value: "confirms_task_fired", label: "It confirms the task fired: svchost.exe hosting the Schedule service is exactly the process Windows uses to launch scheduled tasks" },
        { value: "different_malware", label: "It means a second, unrelated implant is now running alongside the first, since the relaunch comes from a different parent under a different PID" },
        { value: "process_injection", label: "It proves netfix_agent.exe injected itself into svchost.exe to borrow a trusted Windows process and hide its activity from endpoint detection" },
        { value: "irrelevant_detail", label: "The parent process is incidental — the schtasks.exe registration already proved the task works, so the relaunch adds nothing new" },
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
        { value: "process_not_task_log", label: "It was caught from the process that created the task — schtasks.exe and its full command line — rather than from a dedicated 'task created' audit record" },
        { value: "task_didnt_register", label: "Because no 4698 event exists, the task was never actually registered with Task Scheduler — the schtasks.exe command must have failed silently" },
        { value: "sysmon_broken", label: "Sysmon has a dedicated task-creation event that should have fired for NetFixOptimizer, so the sensor configuration dropped it and needs fixing" },
        { value: "not_detectable", label: "Without Security auditing enabled, scheduled-task persistence is invisible to the SIEM, so this alert must have come from the firewall beacon alone" },
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
        { value: "block_domain_sufficient", label: "Block svc-heartbeat-relay.net at the firewall; once the C2 can't be reached the implant is inert and the host is effectively contained" },
        { value: "kill_process_sufficient", label: "Kill the running netfix_agent.exe process; it runs at Medium integrity rather than SYSTEM, so once the process is gone it cannot act again" },
        { value: "wait_for_next_alert", label: "Hold off on remediation and let the correlation rule fire again, so the next relaunch is captured with full telemetry before the host is touched" },
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
        { value: "onlogon_trigger", label: "Its onlogon trigger — IT-managed tasks run on fixed daily or weekly schedules, so a task keyed to user logon is the signature of malicious persistence" },
        { value: "rl_highest", label: "Its /rl highest run level — IT deployment tools register tasks as SYSTEM, so a user-context task asking for top privileges marks it as malicious" },
        { value: "task_name", label: "The task name NetFixOptimizer, which appears as a known-malicious persistence string in threat-intel feeds and is enough by itself to classify the task" },
      ],
      answer: "chain_of_custody",
      xp: 50,
      explanation:
        "IT-managed scheduled tasks are created by known deployment tools, run from Program Files or a management agent's install path, and register cleanly through documented change processes — none of that context exists here. What makes this task suspicious is not any single argument on its command line (onlogon triggers and /rl highest are both used constantly by entirely legitimate software) but the full provenance: a script fetched from a site with no relationship to the organisation, run interactively by an end user, spawning the exact process that registered the task, pointed at a binary written to the user's own AppData folder seconds earlier. The task name itself is meaningless — attackers can and do name tasks anything that sounds boring.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
