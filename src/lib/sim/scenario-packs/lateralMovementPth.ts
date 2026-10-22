import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { lateralMovementPthScenarioEvents } from "./lateralMovementPth.events";
/**
 * Scenario pack: "Night-time privileged logons for an infrastructure admin"
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


export function buildLateralMovementPthScenario(
  scenarioId = "lateral-movement-pth-2026",
): ScenarioBundle {
  const { title, events, T, MIN, SEC, foothold, fileSrv, dc, admin, benign, svcBinaryHash, dumperHash } = lateralMovementPthScenarioEvents();

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
    {
      type: "sha256",
      value: dumperHash, // the unsigned svchost.exe in C:\Windows\Temp that read LSASS
      first_seen: T(-20 * SEC),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["credential-dumper", "masquerading", "temp-dir"],
    },
    {
      type: "domain",
      value: "cdn-winupdate.net", // where the SYSTEM PowerShell on the file server fetched its script
      first_seen: T(5 * MIN + 13 * SEC),
      last_seen: T(5 * MIN + 17 * SEC),
      reputation: "malicious",
      tags: ["payload-host", "lookalike-update-domain"],
    },
    {
      type: "ip",
      value: "185.174.137.26",
      first_seen: T(5 * MIN + 13 * SEC),
      last_seen: T(5 * MIN + 17 * SEC),
      reputation: "malicious",
      tags: ["payload-host", "external"],
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
        { value: "ntlm_ws_hour", label: "NTLM instead of Kerberos, from FIN-WS-11 — a finance workstation, not an admin host — landing at 02:04, off-hours" },
        { value: "logontype", label: "The attack logon is LogonType 3 while the benign one is LogonType 10, which is what marks the attack as remote" },
        { value: "targetuser", label: "The TargetUserName is a service account — pass-the-hash replays machine or service hashes rather than named user accounts" },
        { value: "impersonation", label: "ImpersonationLevel differs: the attack logon requested delegation, while the benign logon only allowed impersonation of the caller" },
      ],
      answer: "ntlm_ws_hour",
      xp: 60,
      explanation:
        "A 4624 / LogonType 3 is the single most common line in a file server's Security log, the event code proves nothing on its own. The tells are in the other fields, read against a baseline. NTLM (AuthenticationPackageName=NTLM, LogonProcessName=NtLmSsp) in a domain that authenticates with Kerberos by default is the classic pass-the-hash signature, because a replayed hash drives NTLM, not Kerberos. The source WorkstationName/IpAddress is FIN-WS-11, a finance clerk's workstation with no reason to administer a server, and the time is 02:04. The benign control is the same 4624/Type-3 but Kerberos, from the user's own workstation, at 13:12. (b) is wrong: both are LogonType 3. (c) is false, the abused account here is a named admin, s.kessler. (d) is refuted by the records: ImpersonationLevel is %%1833 (Impersonation) on both logons.",
    },
    {
      id: "q2",
      prompt:
        "The operator authenticated to SRV-FILE-03 without ever typing s.kessler's password. Which event explains WHERE the material that let them do that came from?",
      kind: "single",
      options: [
        { value: "lsass", label: "The LSASS access on FIN-WS-11 — a masqueraded svchost opening lsass.exe with GrantedAccess 0x1410, dumping the hash" },
        { value: "privs", label: "The 4672 on SRV-FILE-03 — the special-privileges grant that issued the new session its administrative credential material" },
        { value: "service", label: "The 7045 on SRV-FILE-03 — the WinSvcUpdate service created over ADMIN$, whose SYSTEM context let the operator read the hash" },
        { value: "sentinel", label: "The Sentinel correlation fed by Defender for Identity — the record that captured s.kessler's hash as it was replayed" },
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
        { value: "service_exec", label: "Service Execution (T1569.002) — the PsExec pattern: drop a binary over ADMIN$, register it as a service, let the SCM run it" },
        { value: "scheduled", label: "Scheduled Task execution (T1053.005) — the service entry is how an at/schtasks job surfaces once registered remotely" },
        { value: "wmi", label: "WMI event subscription (T1546.003) — a 7045 is the artefact Windows writes when an __EventConsumer is registered" },
        { value: "legit_patch", label: "A routine software deployment — an auto-start WinSvcUpdate service installed by an admin account is ordinary patch-tool behaviour" },
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
        { value: "reset_isolate_hunt", label: "Reset s.kessler's password to invalidate the hash, isolate FIN-WS-11 and SRV-FILE-03, and hunt on DC-NEXA-01 as exposed tier-0" },
        { value: "block_ip", label: "Block 10.20.6.41 at the firewall — cutting off the foothold workstation stops the hash being replayed and closes the incident" },
        { value: "reset_mfa", label: "Reset s.kessler's MFA and require it on her next logon — MFA blocks credential replay, so that step neutralises the hash" },
        { value: "reimage_fileserver", label: "Reimage SRV-FILE-03 — the remote service and PowerShell loader both ran there, so wiping it removes the operator's foothold" },
      ],
      answer: "reset_isolate_hunt",
      xp: 65,
      explanation:
        "An NTLM hash is derived from the password, so a password reset changes the hash and is what actually invalidates a pass-the-hash — but only if you also assume everywhere the hash already went. Here it reached a Domain Controller, so containment has to reset the credential, isolate the foothold and the file server, and hunt on DC-NEXA-01 for follow-on actions (further logons, DCSync attempts, new accounts) while treating tier-0 exposure as live. (b) fails because 10.20.6.41 is an internal workstation the operator borrowed; blocking it does nothing about the hash already replayed onward and would disrupt a legitimate host. (c) fails because pass-the-hash is an NTLM replay that never touches an interactive logon prompt — MFA is simply not in that authentication path. (d) ignores both the credential theft on FIN-WS-11 and the second hop to the DC.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Hands-on-keyboard intrusion operator (post-foothold, credential-replay)",
    attack_kind: "lateral_movement",
    briefing:
      "Microsoft Sentinel raised a High alert at 02:09 for the infrastructure admin s.kessler: privileged authentications for her account across several hosts inside nine minutes, in the middle of the night. Work out how the account was used, where the credential came from, and how far it reached before you contain it.",
    narrative: `The operator already had a foothold on FIN-WS-11, a finance clerk's workstation. The afternoon before, s.kessler, an infrastructure administrator, had remoted into it over Remote Desktop to fix it (a 4624 LogonType 10 from her admin workstation), which left her credentials cached in memory. At 01:59 PowerShell wrote an unsigned svchost.exe into C:\\Windows\\Temp and started it as SYSTEM; at 02:00 that process opened lsass.exe with GrantedAccess 0x1410 and lifted the NTLM hash.

At 02:04 that hash was replayed. A 4624 network logon for s.kessler landed on the file server SRV-FILE-03, LogonType 3, but over NTLM, from FIN-WS-11's address, at night; the domain controller logged the matching 4776 credential validation for a logon coming from FIN-WS-11. No password was ever typed; the hash alone authenticated. It looks like any of the hundred ordinary share connections the server logs each day, and that is exactly why pass-the-hash slips past a tired analyst. A 4672 confirmed the logon carried local-administrator privileges, and a 5140 and a 5145 showed the operator opening the ADMIN$ administrative share and writing svcupd64.exe into it.

Over that SMB session the operator created a service remotely: a 7045 recorded WinSvcUpdate, an auto-start service whose binary C:\\Windows\\svcupd64.exe runs as LocalSystem. services.exe launched it, and it spawned an encoded PowerShell that resolved cdn-winupdate.net and fetched a script from it, the PsExec remote-execution pattern, giving SYSTEM on the file server. At 02:06 that PowerShell reached out over TCP/445 to the Domain Controller DC-NEXA-01, and at 02:08 the same replayed hash produced another 4776 and NTLM 4624 on the DC itself, with a 4672 and a 5145 on the svcctl pipe: the first step of creating a service there.

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
      { ts: "2026-08-26T16:20:11.000Z", phase: "Credential Access", action: `${admin.sam} remotes into ${foothold.hostname} over RDP (4624 type 10), leaving her credentials cached` },
      { ts: T(-20 * SEC), phase: "Resource Development", action: "An unsigned svchost.exe is written to C:\\Windows\\Temp and started as SYSTEM on the foothold workstation" },
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
