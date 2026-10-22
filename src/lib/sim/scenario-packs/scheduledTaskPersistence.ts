/**
 * Scenario pack: "SIEM alert on an HR coordinator's laptop"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential
 * theft across accounts. A user runs a PowerShell "network fix" script she
 * found linked from a forum post. The script itself does very little that
 * looks alarming — it drops one binary — but it also registers a Scheduled
 * Task that starts that binary every day at 07:50, forever, until someone
 * finds and removes it.
 *
 * The teaching point is persistence as a technique in its own right,
 * independent of whatever the payload turns out to do. The single most
 * important fact in this whole scenario is one command line —
 * `schtasks /create ... /sc daily /st 07:50` — and the single most important
 * piece of evidence that the persistence actually works is the same binary
 * launching again, a day later, with a different parent process, at the
 * trigger time.
 *
 * Telemetry: Sysmon (Event IDs 1, 3, 11 and 22), PAN-OS URL/file/traffic
 * records, Windows Security 4698 (task registered) and 4624 (next-day logon),
 * and a Sentinel correlation alert; each in its own source's format.
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
  const { title, events, T, MIN, D2, host, downloadSite, c2, c2Ip, scriptHash, payloadHash } = scheduledTaskPersistenceScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: payloadHash,
      first_seen: T(3 * MIN + 21_000),
      last_seen: T(D2 + 2_000),
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
      last_seen: T(D2 + 13_000),
      reputation: "malicious",
      tags: ["c2", "newly-registered", "beacon"],
    },
    {
      type: "ip",
      value: c2Ip,
      first_seen: T(3 * MIN + 41_000),
      last_seen: T(D2 + 13_000),
      reputation: "malicious",
      tags: ["c2", "external"],
    },
    {
      type: "domain",
      value: downloadSite,
      first_seen: T(-2_000),
      last_seen: T(3 * MIN + 21_000),
      reputation: "malicious",
      tags: ["script-distribution", "forum-linked"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(D2 + 6 * MIN),
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
        { value: "scheduled_task", label: "schtasks.exe, spawned by the script, registering NetFixOptimizer to start the dropped binary every day at 07:50" },
        { value: "payload_written", label: "The script writing netfix_agent.exe into AppData\\Local\\NetFixSvc, since a binary stored in the user profile survives a reboot" },
        { value: "script_run", label: "explorer.exe launching powershell.exe with a process-scope policy bypass, since the bypass keeps the script active across sessions" },
        { value: "beacon", label: "netfix_agent.exe opening its TCP/443 session to svc-heartbeat-relay.net, since the C2 channel is what keeps the attacker on the host" },
      ],
      answer: "scheduled_task",
      xp: 50,
      explanation:
        "A file sitting on disk (b) is not persistence by itself, nothing makes it run again once the current session ends, and if the process that started it is killed, it is simply gone. Running the script once (c) is execution, not persistence, the same is true of every one-off command a user has ever typed, and the Set-ExecutionPolicy -Scope Process change dies with that PowerShell process. The connection out (d) is a symptom of the payload running, not the mechanism that gets it running again. evt_stp_04 is the actual mechanism: /sc daily /st 07:50 means Windows itself will start the target binary every morning, with no further action from the attacker required. That is what 'persistent' means.",
    },
    {
      id: "q2",
      prompt:
        "evt_stp_07 shows netfix_agent.exe launching again, roughly 24 hours after evt_stp_04, this time as a child of svchost.exe rather than powershell.exe. Why does that specific detail matter to an investigator?",
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
        "ParentCommandLine in evt_stp_07 reads 'svchost.exe -k netsvcs -p -s Schedule', that is literally the Windows Task Scheduler service process. Seeing the same binary (the Hashes field matches the file written at 08:08:24 yesterday) launch again with that specific parent, at 07:50:02, the minute the task's daily trigger names, is direct proof that the persistence mechanism registered in evt_stp_04 is not just configured but working. Without this event, an analyst would only have the registration command and would have to assume it succeeded. Nothing here indicates injection (c), svchost.exe is the parent of the new process, not its host, and there is no second unrelated payload (b); it is the same file, launched by the mechanism set up a day earlier.",
    },
    {
      id: "q3",
      prompt:
        "Two records describe the task: Security 4698 and the Sysmon schtasks.exe event. Which record shows the task actually RAN, and why does the registration alone not prove that?",
      kind: "single",
      options: [
        { value: "launch_by_scheduler", label: "The 07:50 Sysmon process event with svchost.exe (Schedule) as parent; registration only proves a task exists, a launch shows the trigger fired" },
        { value: "audit_proves_run", label: "The 4698 record; Windows writes it when a task executes, so its TaskContent shows that the trigger fired and the action ran" },
        { value: "create_runs_task", label: "The schtasks.exe command line; the /create switch starts the task at once, so the registration event is also the first execution" },
        { value: "any_connection", label: "The 08:08 firewall session; any outbound connection after the task was registered proves that the task itself ran" },
      ],
      answer: "launch_by_scheduler",
      xp: 60,
      explanation:
        "Security 4698 is written when a task is created or changed. Its TaskContent holds the definition (here a CalendarTrigger with a one-day interval and an Exec action pointing at the AppData binary), so it corroborates the Sysmon command line, but it says nothing about execution (b). /create (c) only registers; it does not start the task. The first run at 08:08:33 was started directly by PowerShell (evt_stp_04b), so the connection that followed (d) has nothing to do with the task. Only the launch at 07:50:02 the next morning, with the Schedule service host as parent, proves the trigger fired and the persistence works.",
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
        "Blocking the domain (b) or killing the running process (c) both address the current symptom while leaving the actual mechanism, the NetFixOptimizer task, fully intact. The task will simply start the binary again at the next 07:50 trigger, and if the operators simply update their DNS or the payload's embedded domain, the block becomes stale. The only response that matches the evidence is removing both the task registration and the file it points to, then explicitly checking Task Scheduler to confirm nothing remains, exactly the check evt_stp_07 shows was missing the first time, since the task fired again 24 hours after it was created and nobody had removed it yet.",
    },
    {
      id: "q5",
      prompt:
        "Which detail distinguishes this scheduled task from a normal, IT-managed scheduled task an analyst might see on any given day?",
      kind: "single",
      options: [
        { value: "chain_of_custody", label: "The full chain: a forum-downloaded script spawned the process that registered the task, targeting a binary the same script had just written to AppData" },
        { value: "daily_trigger", label: "Its daily trigger, IT-managed tasks only run on event triggers such as logon or startup, so a time-based task is the signature of malicious persistence" },
        { value: "task_path", label: "Its target — a binary in the user's own AppData\\Local, where IT deployment tools never install, rather than Program Files or a managed agent path" },
        { value: "task_name", label: "The task name NetFixOptimizer, which appears as a known-malicious persistence string in threat-intel feeds and is enough by itself to classify the task" },
      ],
      answer: "chain_of_custody",
      xp: 50,
      explanation:
        "IT-managed scheduled tasks are created by known deployment tools, run from Program Files or a management agent's install path, and register cleanly through documented change processes, none of that context exists here. What makes this task suspicious is not any single argument on its command line (daily triggers and AppData targets both appear in some legitimate per-user software too) but the full provenance: a script fetched from a site with no relationship to the organisation, run interactively by an end user, spawning the exact process that registered the task, pointed at a binary written to the user's own AppData folder seconds earlier. The task name itself is meaningless, attackers can and do name tasks anything that sounds boring; and this is a plain per-user task (no elevation), which is exactly what a non-admin end user can register with a time trigger.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity persistence-loader distributor (forum-linked script)",
    attack_kind: "scheduled_task_persistence",
    briefing:
      "The SIEM rule ScheduledTaskPersistence_ScriptSpawnedPowerShell fired on WS-7742, the laptop of Shani Attia (HR coordinator), at 07:56 this morning. The alert points at an unsigned binary under her AppData folder that was started at 07:50. Work out how it got onto the machine, what started it, and what it does when it runs.",
    narrative: `At 08:05 Shani Attia downloaded SpeedBoost_NetFix.ps1 from netfix-tools-download.com, a script linked from a forum thread promising to fix a slow home-office VPN connection. Chrome resolved the site two seconds earlier and saved the file into Downloads. She ran it just over three minutes later through Explorer's Run with PowerShell verb, which starts powershell.exe with a process-scope execution-policy bypass.

Two seconds in, the script connected to the same site and fetched netfix_agent.exe, and six seconds in it wrote it to C:\\Users\\s.attia\\AppData\\Local\\NetFixSvc\\netfix_agent.exe. Five seconds after that, it spawned schtasks.exe with a single, decisive command: register a per-user task called NetFixOptimizer to run that binary every day at 07:50. Security 4698 recorded the same registration, trigger and action included. No elevation was needed: a standard user can register a time-triggered task that runs only in her own context. Four seconds later the script launched netfix_agent.exe once by hand, and eight seconds after that the binary resolved svc-heartbeat-relay.net and opened a TCP/443 session to it, the first check-in.

Nothing about that first run looked catastrophic. It was one script, one dropped file, one outbound connection that the firewall allowed under a category nobody blocks by default.

The evidence that this mattered arrived the next morning. Shani signed in at 07:46 (a new logon session), and at 07:50:02 netfix_agent.exe started again: same file, same hash, but this time launched by svchost.exe running the Schedule service, not by anything the user did. It resolved the same domain, connected to the same address and sent a session of the same size. A SIEM detection rule built on the Sysmon feed connected the two events six minutes later: a script-spawned PowerShell process registering a task, and that task's target binary executing at the trigger time, on a host where nobody had removed anything in between.`,
    learning_objectives: [
      "Identify Scheduled Task/Job persistence (T1053.005) from a schtasks.exe command line, independent of what the payload itself does",
      "Recognise PowerShell script execution (T1059.001) launched by explorer.exe from a downloaded file",
      "Use a changed parent process (svchost.exe running the Schedule service) as direct proof a persistence mechanism is active",
      "Tell task registration (Security 4698 and the schtasks.exe command line) apart from task execution (a launch by the Schedule service)",
      "Build a remediation plan that removes the persistence mechanism itself, not just the currently running process",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `SpeedBoost_NetFix.ps1 downloaded from ${downloadSite}, saved by chrome.exe into Downloads` },
      { ts: T(3 * MIN + 18_000), phase: "Execution", action: "explorer.exe launches powershell.exe running the downloaded script (T1059.001)" },
      { ts: T(3 * MIN + 21_000), phase: "Command and Control", action: `netfix_agent.exe fetched from ${downloadSite} (T1105)` },
      { ts: T(3 * MIN + 24_000), phase: "Execution", action: "netfix_agent.exe written to AppData\\Local\\NetFixSvc" },
      { ts: T(3 * MIN + 29_000), phase: "Persistence", action: "schtasks.exe registers a per-user NetFixOptimizer task to run every day at 07:50 (T1053.005); Security 4698 records it" },
      { ts: T(3 * MIN + 33_000), phase: "Execution", action: "powershell.exe launches netfix_agent.exe directly for an immediate first run" },
      { ts: T(3 * MIN + 41_000), phase: "Command and Control", action: `netfix_agent.exe resolves ${c2}` },
      { ts: T(3 * MIN + 44_000), phase: "Command and Control", action: "First outbound check-in, allowed as newly-registered-domain (T1071.001)" },
      { ts: T(D2 + 2_000), phase: "Persistence", action: "Next morning (new logon session): netfix_agent.exe relaunches at 07:50 as a child of svchost.exe, the task firing (T1053.005)" },
      { ts: T(D2 + 13_000), phase: "Command and Control", action: "The relaunched binary repeats the DNS lookup and the same-sized TCP/443 check-in" },
      { ts: T(D2 + 6 * MIN), phase: "Detection", action: "SIEM correlation rule fires on the Sysmon telemetry" },
    ],
    questions,
  };
}
