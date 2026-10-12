import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { windowsPrivescTokenScenarioEvents } from "./windowsPrivescToken.events";
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


export function buildWindowsPrivescTokenScenario(
  scenarioId = "windows-privesc-token-2026",
): ScenarioBundle {
  const { title, events, T, SEC, MIN, host, svc, toolSha256, toolMd5, INCIDENT } = windowsPrivescTokenScenarioEvents();

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
        { value: "special_privs", label: "The 4672 special-logon record listing SeImpersonatePrivilege on the svc-web session" },
        { value: "service_logon", label: "The 4624 LogonType 5 service logon that started the IIS app pool under the svc-web identity" },
        { value: "pipe", label: "The Sysmon 18 record of the SYSTEM spooler connecting to the attacker-controlled \\spoolss pipe" },
        { value: "system_shell", label: "The 4688 showing spf.exe creating cmd.exe as NT AUTHORITY\\SYSTEM with a full elevated token" },
      ],
      answer: "special_privs",
      xp: 50,
      explanation:
        "PrintSpoofer/potato attacks do not need administrator rights — they need SeImpersonatePrivilege, the right to impersonate a security token the process can get a handle to. evt_wpe_02_special_privs is the 4672 that records that privilege on the svc-web logon session (0x8F41C2), and it is present precisely because svc-web is an IIS application-pool identity, which Windows grants SeImpersonatePrivilege by default. Without that grant the entire token-theft chain is impossible. The 4624 (b) only shows the account logged on; the named pipe (c) and the SYSTEM shell (d) are steps that the privilege in (a) enabled, not the precondition itself. Reading the precondition, not just the payload, is the whole point: a service account with SeImpersonate is a privilege-escalation waiting to happen.",
    },
    {
      id: "q2",
      prompt:
        "Read evt_wpe_05_pipe_connect and evt_wpe_06_process_access together. What technique do they show, and what does the GrantedAccess value 0x1410 represent?",
      kind: "single",
      options: [
        { value: "token_theft", label: "Token impersonation: the SYSTEM spooler was coerced onto an attacker pipe, then spf.exe opened a handle to it (0x1410) to duplicate its token" },
        { value: "lsass_dump", label: "An LSASS memory dump: spf.exe opened lsass.exe with read access and pulled plaintext credentials and NTLM hashes out of its memory" },
        { value: "kerberoast", label: "Kerberoasting: spf.exe requested a service ticket for svc-web over the named pipe and took the encrypted ticket away to crack offline" },
        { value: "dll_injection", label: "DLL injection: spf.exe wrote a malicious DLL path into spoolsv.exe's memory (0x1410) and forced the spooler to load it with a remote thread" },
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
        { value: "system_shell", label: "The 4688 in which spf.exe creates cmd.exe owned by S-1-5-18 with TokenElevationType %%1937" },
        { value: "priv_use", label: "The 4673 recording SeImpersonatePrivilege being exercised by spf.exe under the svc-web session" },
        { value: "proc_access", label: "The Sysmon 10 record of spf.exe opening a handle to spoolsv.exe with GrantedAccess 0x1410" },
        { value: "sentinel", label: "The Sentinel High incident correlating a rare privilege elevation on WEB-APP-04 that opened the ticket" },
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
    title,
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
