/**
 * Learning Rooms — Batch 24
 *
 * The interactive counterpart to three attack-type theory lessons written in
 * a parallel workstream (credential attacks, lateral movement, web attacks).
 * Each room here is deliberately practice-heavy: at most two reading tasks,
 * everything else is the student deciding something from real telemetry.
 *
 * - credential-attacks-practice — distinguishing brute forcing (T1110.001),
 *   password spraying (T1110.003), credential stuffing (T1110.004) and
 *   credential dumping (T1003) from the shape of 4625 data, not the label.
 * - lateral-movement-practice   — reconstructing a movement chain across
 *   three hosts from scattered, independently-incomplete evidence, and the
 *   privilege realism that makes ADMIN$/service-install evidence meaningful.
 * - web-attacks-practice        — reading IIS status codes as outcome not
 *   intent, and correlating a WAF record with a web-server record for the
 *   same request to recover true client-IP attribution.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// ROOM 1: credential-attacks-practice
// =============================================================================

const bruteForceEvent: TelemetryEvent = {
  id: "evt-cred-la1-001",
  ts: "2026-06-02T02:41:18.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "high",
  hostname: "DC01.vantree.local",
  src_ip: "154.16.88.203",
  mitre_technique: "T1110.001",
  mitre_tactic: "Credential Access",
  authentication: { method: "NTLM", result: "Failure", logon_type: 3 },
  description:
    "DC01 recorded a failed network logon against account d.solano; this is one of a run of similarly-shaped failures against the same account in the preceding six minutes.",
  raw: {
    "event.code": "4625",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC01.vantree.local",
    "winlog.event_data.TargetUserName": "d.solano",
    "winlog.event_data.TargetDomainName": "VANTREE",
    "winlog.event_data.WorkstationName": "RDS-GATEWAY02",
    "winlog.event_data.IpAddress": "154.16.88.203",
    "winlog.event_data.IpPort": "0",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.FailureReason": "%%2313",
    "winlog.event_data.LogonProcessName": "NtLmSsp ",
    "winlog.event_data.AuthenticationPackageName": "NTLM",
    "winlog.event_id": 4625,
  },
};

const sprayEvent: TelemetryEvent = {
  id: "evt-cred-la2-001",
  ts: "2026-06-05T14:07:52.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "high",
  hostname: "DC01.vantree.local",
  src_ip: "185.220.101.47",
  mitre_technique: "T1110.003",
  mitre_tactic: "Credential Access",
  authentication: { method: "NTLM", result: "Failure", logon_type: 3 },
  description:
    "DC01 recorded a failed network logon against account k.mensah; this is one of 142 distinct accounts that recorded similarly low attempt counts from the same source IP within a 20-minute window.",
  raw: {
    "event.code": "4625",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC01.vantree.local",
    "winlog.event_data.TargetUserName": "k.mensah",
    "winlog.event_data.TargetDomainName": "VANTREE",
    "winlog.event_data.WorkstationName": "-",
    "winlog.event_data.IpAddress": "185.220.101.47",
    "winlog.event_data.IpPort": "0",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.FailureReason": "%%2313",
    "winlog.event_data.LogonProcessName": "NtLmSsp ",
    "winlog.event_data.AuthenticationPackageName": "NTLM",
    "winlog.event_id": 4625,
  },
};

const rotationEvent: TelemetryEvent = {
  id: "evt-cred-ac1-001",
  ts: "2026-06-08T09:14:02.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "medium",
  hostname: "APP-RPT03.vantree.local",
  src_ip: "10.20.4.18",
  authentication: { method: "Kerberos", result: "Failure", logon_type: 5 },
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-55210 rotated svc_reportgen's password in the credential vault at 09:11. App servers pull the new credential on their next service restart; APP-RPT03 through APP-RPT08 had not yet restarted their reporting service at the time of this event.",
  description:
    "APP-RPT03 recorded a failed service logon for account svc_reportgen; five other internal application servers recorded similarly-shaped failures for the same account within the same eight-minute window.",
  raw: {
    "event.code": "4625",
    "winlog.channel": "Security",
    "winlog.computer_name": "APP-RPT03.vantree.local",
    "winlog.event_data.TargetUserName": "svc_reportgen",
    "winlog.event_data.TargetDomainName": "VANTREE",
    "winlog.event_data.WorkstationName": "APP-RPT03",
    "winlog.event_data.IpAddress": "10.20.4.18",
    "winlog.event_data.IpPort": "0",
    "winlog.event_data.LogonType": "5",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.FailureReason": "%%2313",
    "winlog.event_data.LogonProcessName": "Advapi  ",
    "winlog.event_data.AuthenticationPackageName": "Negotiate",
    "winlog.event_id": 4625,
  },
};

const credentialAttacksRoom: Room = {
  id: "credential-attacks-practice",
  title: "Credential Attacks in the Logs",
  description:
    "The theory lesson taught you what brute forcing, password spraying, credential stuffing, and credential dumping are. This room makes you tell them apart from the raw authentication telemetry alone — no labels, no detection-rule names, just TargetUserName, IpAddress, LogonType, and Status/SubStatus fields deciding which attack you're actually looking at, plus the trap that catches analysts who escalate every repeated-failure pattern without checking its shape first.",
  difficulty: "intermediate",
  category: "Threat Detection",
  estimatedMinutes: 55,
  xp: 370,
  icon: "🎯",
  prerequisites: ["auth-identity-monitoring"],
  tasks: [
    {
      type: "reading",
      id: "cred-r1",
      heading: "Four Attacks, One Symptom: Repeated Failed Logons",
      content:
        `Every credential attack an analyst investigates eventually produces the same raw material: a cluster of failed sign-in attempts sitting in the authentication logs, right next to the millions of ordinary ones. The theory lesson that came before this room named four distinct techniques behind those clusters. What it could not teach is the skill this room is entirely built around: telling them apart from the log fields alone, because in a real queue nobody hands you a label that says 'this is a password spray' — you have to read the shape of the data and decide for yourself.\n\n` +
        `**The four shapes, briefly**\n\n` +
        `T1110.001, brute forcing, is trying many passwords against one account — like standing at a single lock trying key after key until one turns, or the lock breaks first. T1110.003, password spraying, inverts that: try one or two common passwords against as many accounts as possible, deliberately spreading the attempts thin enough that no single account ever crosses a lockout threshold — a burglar trying the single most common key against every door on the street rather than picking one lock properly. T1110.004, credential stuffing, doesn't guess at all: it replays username-and-password pairs already stolen from some other breach, betting (correctly, often enough to be worth it) that people reuse passwords across services — the burglar isn't guessing keys, they're trying a keyring stolen from a locksmith who serviced a different building down the road. T1003, OS credential dumping, is a different category of attack entirely: it doesn't touch the authentication endpoint at all. It reads credential material directly out of a process's memory (classically lsass.exe on Windows) or a credential store on disk, so there is no failed-logon burst to find — the burglar just stole the master key file from the building manager's office and never touched a single door.\n\n` +
        `**Why the detection rule's name is not the answer**\n\n` +
        `A SIEM rule literally titled 'Password Spray Detected' can fire on a burst of failures that is really an ordinary brute-force attempt against one forgotten service account, and a rule titled 'Brute Force Detected' can just as easily fire on the single representative event a real spray produces once you drill into it. The rule name reflects what its author intended to catch, not what necessarily happened. What actually distinguishes the four techniques is answerable from three questions, asked of the aggregate, not any single log line: how many distinct accounts were targeted? How many attempts landed against each one? And did the activity touch an authentication endpoint at all, or did it touch a process or a file instead? Get those three answers and the technique nearly names itself — brute force is few accounts, many attempts each; spraying is many accounts, few attempts each; stuffing is many accounts, usually one attempt each, sourced from many different IPs, with an unusually high success rate for how little effort went into each guess; and dumping shows up nowhere in this list at all, because it never generates an authentication attempt in the first place.\n\n` +
        `The next reading takes the specific Windows event most of this room lives in — Event ID 4625, a failed logon — and shows you exactly which fields carry the answer to those three questions, and which fields are decoration.`,
      codeExample:
        "FOUR CREDENTIAL ATTACKS, AT A GLANCE\n" +
        "=======================================================\n" +
        "T1110.001 Brute Force         Few accounts, MANY attempts each\n" +
        "T1110.003 Password Spraying   MANY accounts, few attempts each\n" +
        "T1110.004 Credential Stuffing MANY accounts, ~1 attempt each,\n" +
        "                              many source IPs, unusually high\n" +
        "                              success rate for the attempt count\n" +
        "T1003     Credential Dumping   NO authentication attempt at all --\n" +
        "                              memory/disk read, not a logon event\n" +
        "=======================================================\n\n" +
        "THE THREE QUESTIONS THAT ACTUALLY DISCRIMINATE\n" +
        "=======================================================\n" +
        "1. How many DISTINCT accounts were targeted?\n" +
        "2. How many attempts landed against EACH one?\n" +
        "3. Did this touch an auth endpoint, or a process/file instead?\n" +
        "=======================================================",
    },
    {
      type: "reading",
      id: "cred-r2",
      heading: "Reading a 4625: The Fields That Actually Distinguish an Attack",
      content:
        `Windows Event ID 4625 is logged every time an interactive, network, service, or remote logon attempt fails, and it is the single event this room leans on most. Learn its fields once and you can answer all three of Reading 1's questions from a raw log without waiting for anyone's dashboard to do the aggregation for you.\n\n` +
        `**The fields that matter**\n\n` +
        `TargetUserName is the account the attempt was made against — this is your grouping key for question one (how many distinct values of this field appear together?). IpAddress and WorkstationName identify where the attempt came from; a single unchanging IpAddress across a burst tells you one actor is behind it, which matters for questions two and three alike. LogonType tells you what kind of session was attempted (3 is a network logon, the type by far most common in both brute-force and spray activity, since it requires no interactive session and is cheap to script at volume). Status and SubStatus, read together, are the outcome: Status 0xC000006D is the generic 'logon failure' Windows returns for a bad username/password pair, and SubStatus narrows it further — 0xC000006A means the account exists and the password was wrong, 0xC0000064 means the username itself does not exist at all (a strong tell that whoever is attempting this is guessing usernames, not just passwords), 0xC0000234 means the account is now locked out, and 0xC0000071 means the password has expired. FailureReason carries a Windows event-code placeholder (commonly %%2313, 'Unknown user name or bad password') that mirrors the SubStatus without adding new information.\n\n` +
        `**One event is one data point, not a verdict**\n\n` +
        `A single 4625 tells you almost nothing on its own — plenty of legitimate activity produces one. What answers Reading 1's three questions is the AGGREGATE your SIEM builds by grouping many of these events along two different axes. Group by TargetUserName and count attempts: a huge count against one value is the brute-force shape. Group by source (IpAddress, or WorkstationName if IP rotates) and count DISTINCT values of TargetUserName touched: a huge distinct-account count from one source, each with only a handful of attempts, is the spray shape. This is the exact discrimination this room's two log-analysis exercises are built to test — and it is worth internalizing now, because 'raw count of 4625 events' alone, without knowing which axis it was grouped on, tells you nothing about which of the two attacks you are looking at.\n\n` +
        `**What doesn't fit this pattern at all**\n\n` +
        `Credential stuffing shows the same TargetUserName/IpAddress fields, but the source axis looks different: attempts arrive from many different, often geographically scattered IpAddress values rather than one steady source, frequently with only a single attempt per account — because the attacker already has a real password for that account from a prior breach and isn't guessing at all. Credential dumping, as covered in Reading 1, will never appear in a 4625 aggregate in the first place; if you go looking for it in authentication logs you are looking in the wrong log source entirely — that story lives in process-access telemetry on the host where memory was read, not here.`,
      codeExample:
        "4625 STATUS / SUBSTATUS -- WHAT EACH ONE MEANS\n" +
        "=======================================================\n" +
        "Status 0xC000006D        Generic logon failure (bad user/pass pair)\n" +
        "  SubStatus 0xC000006A    Account exists, WRONG PASSWORD\n" +
        "  SubStatus 0xC0000064    Account does NOT EXIST (username guess)\n" +
        "  SubStatus 0xC0000234    Account is LOCKED OUT\n" +
        "  SubStatus 0xC0000071    Password EXPIRED\n" +
        "=======================================================\n\n" +
        "THE TWO AGGREGATION AXES\n" +
        "=======================================================\n" +
        "Group by TargetUserName, count attempts\n" +
        "  -> huge count on ONE account        = BRUTE FORCE shape\n\n" +
        "Group by source, count DISTINCT TargetUserName values\n" +
        "  -> huge distinct-account count,\n" +
        "     few attempts each, ONE source    = SPRAY shape\n\n" +
        "Group by TargetUserName, ~1 attempt each,\n" +
        "  sourced from MANY DIFFERENT IPs      = STUFFING shape\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "cred-q1",
      question:
        "A 4625 burst against the same account shows SubStatus 0xC000006A for its first 30 attempts, then switches to 0xC0000234 for every attempt after that. What changed?",
      options: [
        "The attacker switched from guessing passwords to guessing usernames",
        "The account's lockout policy was triggered — the account is now locked out, so further attempts fail for a different reason than a wrong password",
        "The password was guessed correctly on attempt 31, and 0xC0000234 confirms a successful logon",
        "0xC0000234 means the source IP was blocked by a firewall rule, unrelated to the account itself",
      ],
      answer: 1,
      explanation:
        "0xC0000234 is specifically the account-locked-out substatus, not a username-guessing indicator, a success indicator, or a firewall signal — it only ever appears once the account's lockout threshold has actually been crossed, which is exactly why it appears only after attempt 30 rather than from the start. A genuine success would produce a 4624, not a further 4625; 0xC0000064 (not 0xC0000234) is the username-does-not-exist substatus; and this field describes the target account's own state, not the network layer.",
      xp: 20,
    },
    {
      type: "matching",
      id: "cred-m1",
      heading: "Match Each Credential Attack to Its Distinguishing Log Signature",
      instructions: "Match each technique to the pattern that actually separates it from the other three in the aggregate.",
      pairs: [
        { id: "bruteforce", left: "Brute forcing a single account (T1110.001)", right: "One TargetUserName value, a large attempt count, usually one steady source IpAddress" },
        { id: "spray", left: "Password spraying (T1110.003)", right: "Many distinct TargetUserName values from one source, only 1-3 attempts against each — deliberately staying under the lockout threshold per account" },
        { id: "stuffing", left: "Credential stuffing (T1110.004)", right: "Many distinct TargetUserName values, ~1 attempt each, sourced from many different IpAddress values, with a higher success rate than the attempt count alone would predict" },
        { id: "dumping", left: "Credential dumping (T1003)", right: "No 4625/4624 burst anywhere at all — instead a process (commonly lsass.exe) is opened with an access level consistent with reading credential material directly from memory" },
      ],
      explanation:
        "Each pairing comes from the two aggregation axes in Reading 2: brute force groups tightly on one TargetUserName; spraying groups tightly on one source but spreads across many TargetUserName values, each safely under lockout; stuffing looks like spraying's account breadth but loses the single-source pattern and gains an anomalously high success rate, because the passwords being tried are real, not guessed; and dumping never touches the authentication log at all, which is itself the tell that you are looking at the wrong log source if you go hunting for it in 4625 data.",
      xp: 40,
    },
    {
      type: "log_analysis",
      id: "cred-la1",
      heading: "A Burst Against One Account",
      context:
        "Vantree's SIEM flagged unusual 4625 volume overnight. In the six minutes before this representative record, DC01 logged 47 failed logon attempts against a single account, all from the same source IP and workstation name, with no other accounts appearing in the same burst.",
      event: bruteForceEvent,
      questions: [
        {
          question:
            "TargetUserName is 'd.solano' on every one of the 47 failures described above, IpAddress and WorkstationName are identical across all of them, and SubStatus is 0xC000006A (wrong password) throughout. Which of the two aggregation axes from Reading 2 does this match, and what technique does that indicate?",
          options: [
            "Grouped tightly on source with many distinct accounts touched — this is password spraying (T1110.003)",
            "Grouped tightly on one TargetUserName value with a large attempt count from a single source — this is brute forcing (T1110.001)",
            "Grouped on many distinct source IPs against one account — this is credential stuffing (T1110.004)",
            "No authentication events would be generated by this technique at all — this must be credential dumping (T1003)",
          ],
          answer: 1,
          explanation:
            "This is exactly the brute-force shape from Reading 2: one TargetUserName value (d.solano) absorbing a large attempt count from one steady source. Password spraying would show many distinct accounts, not one; credential stuffing would show many source IPs rather than one steady one; and credential dumping would produce no 4625 burst at all, since it never touches the authentication endpoint.",
          xp: 25,
        },
        {
          question:
            "SubStatus stays 0xC000006A (wrong password) for all 47 attempts rather than ever switching to 0xC0000234. What does that specifically tell you, and why might it matter for how urgently this needs a response?",
          options: [
            "It proves the account was never actually at risk, since the password was never guessed",
            "The account's lockout threshold has not yet been crossed despite 47 attempts — meaning either the account has an unusually high lockout threshold (or a policy exemption), or the threshold simply hasn't been reached yet and the attack is still live and could still succeed",
            "0xC0000234 only appears for administrator accounts, so this confirms d.solano is a standard user",
            "SubStatus has no relationship to the account lockout policy at all",
          ],
          answer: 1,
          explanation:
            "SubStatus 0xC000006A means the password was wrong on that specific attempt; the fact that it never flips to 0xC0000234 (locked out) after 47 tries is itself informative — either d.solano's account is exempt from the org's normal lockout policy (worth checking) or the threshold simply hasn't been reached yet, meaning the attack is still actively running and could still land a correct guess. It says nothing about whether the account is privileged, and it certainly doesn't mean the account was never at risk.",
          xp: 25,
        },
        {
          question: "What is the correct next step?",
          options: [
            "No action needed — 4625 events are routine and this volume is within normal limits",
            "Block or rate-limit the source IP, check whether d.solano's account has an unnecessary lockout exemption, confirm no 4624 success followed this burst from the same source, and reach out to d.solano to confirm whether this was them locked out of a forgotten credential",
            "Immediately disable NTLM domain-wide, since NtLmSsp appears in the LogonProcessName field",
            "Escalate as a confirmed password spray and begin resetting every account in the domain",
          ],
          answer: 1,
          explanation:
            "The response should match the finding: contain the source, check and correct why lockout never triggered, confirm no success snuck through, and rule out the mundane explanation (d.solano genuinely forgot a changed password) before treating it as hostile. Disabling NTLM domain-wide is disproportionate to one account's burst, and this is brute forcing against one account, not a spray, so a domain-wide reset is the wrong response for what was actually observed.",
          xp: 30,
        },
      ],
    },
    {
      type: "log_analysis",
      id: "cred-la2",
      heading: "Low-and-Slow Across Many Accounts",
      context:
        "A separate SIEM correlation flagged a different pattern the same week: 142 distinct accounts each recorded 2-3 failed 4625 attempts, all from the single source IP 185.220.101.47, spread across a 20-minute window. The highest per-account attempt count observed anywhere in the burst was 3 — one below Vantree's 4-attempt lockout policy. Review the representative record below, for one of the 142 targeted accounts.",
      event: sprayEvent,
      questions: [
        {
          question:
            "TargetUserName here is k.mensah, one of 142 distinct accounts touched from the same 185.220.101.47 in 20 minutes, with a maximum of 3 attempts against any single account. How does this differ from the shape you read in Log Analysis 1, and what does it indicate?",
          options: [
            "It's the same shape as Log Analysis 1, just against a different account — this is brute forcing (T1110.001)",
            "It's the inverse shape: one steady source spread thin across many distinct accounts, each safely under the lockout threshold — this is password spraying (T1110.003)",
            "142 distinct accounts from one IP with only 2-3 attempts each cannot be attributed to any of the four techniques from Reading 1",
            "This must be credential dumping, since so many accounts are affected at once",
          ],
          answer: 1,
          explanation:
            "Log Analysis 1 was one account absorbing many attempts (brute forcing); this is the mirror image — one source spread thin across 142 distinct accounts, each individually staying under Vantree's 4-attempt lockout policy, exactly the spray shape from Reading 2. It fits T1110.003 precisely; it's not unattributable, and credential dumping would never produce a 4625 burst at all, regardless of account count.",
          xp: 25,
        },
        {
          question:
            "The maximum attempt count against any single account was 3 — one below the 4-attempt lockout policy. Why does that specific number matter, rather than being incidental?",
          options: [
            "It's a coincidence and has no bearing on whether this is a spray",
            "Staying just under the lockout threshold on every single account is deliberate — it lets the attacker try a common password against the entire account population without ever triggering a lockout or a lockout-based alert, which is the entire point of spraying instead of brute forcing",
            "It proves the source IP has already been blocked by the domain's account lockout policy",
            "3 attempts is required by NTLM before a 4625 event is generated at all",
          ],
          answer: 1,
          explanation:
            "Staying one attempt below the lockout threshold, consistently, across 142 different accounts, is not incidental — it's the defining discipline of a password spray, deliberately trading depth (many guesses against one account) for breadth (a few guesses against many accounts) specifically to avoid triggering lockout-based alerting. Lockout policy doesn't block source IPs, and NTLM doesn't require any minimum attempt count before logging a 4625 — a single failed attempt logs one immediately.",
          xp: 25,
        },
        {
          question: "What is the correct response, given this is a spray rather than a brute-force burst?",
          options: [
            "Reset only k.mensah's password, since that's the account shown in this record",
            "Block/rate-limit 185.220.101.47 at the perimeter, search specifically for any 4624 SUCCESS from that same source (a spray's entire goal is finding the one account with a weak or reused password), and treat any account with a matching success as compromised regardless of how few attempts it took",
            "No action needed — none of the 142 accounts were locked out, so no harm occurred",
            "Force an immediate domain-wide password reset for all 25,000 Vantree accounts as the only sufficient response",
          ],
          answer: 1,
          explanation:
            "The critical next step for any spray is checking whether it worked — a single 4624 success from that same source IP, even against an account that only saw 2 or 3 attempts, means the spray found its target and that account needs to be treated as compromised immediately. Fixing only k.mensah's account ignores the other 141 targets; 'no accounts locked out' is the attack working as designed, not evidence of no harm; and a full domain-wide reset is a massive overreaction compared to the targeted response an actual finding calls for.",
          xp: 30,
        },
      ],
    },
    {
      type: "question",
      id: "cred-q2",
      question:
        "Two separate SIEM findings land on your queue on the same day. Finding A: 60 failed 4625 attempts against one account, sourced from one IP, over 90 minutes. Finding B: 8 failed 4625 attempts total, but spread across 6 different accounts (1-2 attempts each) from one IP over 5 minutes. Which is more likely a password spray, and why?",
      options: [
        "Finding A, because it has the higher total attempt count",
        "Finding B, because it distributes a small number of attempts across multiple distinct accounts from one source rather than concentrating them on one account — total volume is not the discriminator, account breadth is",
        "Neither — sprays always involve at least 50 accounts to qualify",
        "Both are equally likely to be either technique, since source IP is the only field that matters",
      ],
      answer: 1,
      explanation:
        "Total attempt count is a trap here: Finding A's 60 attempts against ONE account is the brute-force shape, while Finding B's much smaller total of 8 attempts, spread across SIX distinct accounts, matches the spray shape even at low volume — breadth across accounts, not raw count, is what the shape actually depends on. There's no fixed account-count threshold that defines a spray, and TargetUserName distribution matters just as much as source IP.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "cred-ac1",
      heading: "Verdict: A Service Account Failing After a Password Rotation",
      scenario:
        "A detection rule tuned for repeated 4625 activity fired on account svc_reportgen. Review the event below alongside the change record attached to it.",
      event: rotationEvent,
      correct_verdict: "false_positive",
      explanation:
        "The detection rule fired on repeated 4625 volume against one account, which superficially resembles Log Analysis 1's brute-force shape — but the source axis tells a different story: these failures came from six of Vantree's own internal application servers (APP-RPT03 through APP-RPT08), not one external actor, all within minutes of a confirmed, ticketed password rotation. This is the ordinary lag between a credential vault rotating a service account's password and every consumer of that credential picking up the new value on its next restart — expected, self-resolving noise, not an attack.",
      fp_trap:
        "It's tempting to pattern-match this straight to Log Analysis 1: same account, repeated 0xC000006A failures, tuned rule fired. But Log Analysis 1's defining shape was one TargetUserName from ONE steady source; this finding is one TargetUserName from MULTIPLE internal, known application hosts, clustered tightly around a documented change window — a shape neither brute forcing nor spraying actually produces, because an attacker has no reason to distribute failed attempts against a single account across six of your own app servers. Skipping the it_verify_result and reflexively escalating any repeated-failure pattern against one account, without checking source diversity and timing against your own change calendar, is exactly the over-alerting failure mode that burns analyst time chasing a service restart.",
      xp: 30,
    },
    {
      type: "ordering",
      id: "cred-o1",
      heading: "Order the Spray-to-Compromise Chain",
      instructions: "Arrange these events in the order they occur when a password spray actually succeeds.",
      items: [
        { id: "failures", text: "Low-volume failed logon attempts (1-3 each) appear against dozens of distinct accounts from one source IP, none reaching the lockout threshold" },
        { id: "success", text: "One targeted account records a successful 4624 logon from that same source IP" },
        { id: "session", text: "A new interactive session under that account is established from a second, previously unseen source" },
        { id: "recon", text: "The compromised account is used to enumerate group memberships and file shares it has never accessed before" },
        { id: "access", text: "The account authenticates to a sensitive file server it has no prior 90-day access history with" },
      ],
      correct_order: ["failures", "success", "session", "recon", "access"],
      explanation:
        "This is the full arc a successful spray follows: the failure sweep is the attacker searching for one weak or reused password across many accounts; the single 4624 success is the moment the spray finds its target; the follow-on session from a different source is the attacker actually logging in as that account to operate; and the recon and sensitive-access steps are what a compromised account gets used for once the attacker has it — exactly why Log Analysis 2's response called for hunting a 4624 success from the spray's source IP rather than stopping at 'no accounts were locked out.'",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "cred-qf1",
      heading: "Write It Yourself: Detect a Password Spray in KQL",
      language: "kql",
      context:
        "Using the pattern confirmed in Log Analysis 2 — one source, many distinct targeted accounts, low attempts each — write the KQL a detection engineer would deploy to catch a spray, where raw failure COUNT alone would miss it.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TimeGenerated > ago({{window}})\n| summarize DistinctAccounts = dcount({{accountfield}}), TotalFailures = count() by IpAddress\n| where DistinctAccounts > {{threshold}}",
      blanks: [
        { id: "eventid", answers: ["4625"], placeholder: "failed logon Event ID" },
        { id: "window", answers: ["30m", "1h", "20m", "60m"], placeholder: "aggregation window" },
        { id: "accountfield", answers: ["TargetAccount", "Account", "TargetUserName"], placeholder: "field holding the targeted account name" },
        { id: "threshold", answers: ["10", "15", "20", "25", "30"], placeholder: "minimum distinct-account count to consider suspicious" },
      ],
      explanation:
        "This mirrors the discrimination from Reading 2 and Log Analysis 2: filtering to 4625 and counting distinct targeted accounts per source is what actually catches a spray, because TotalFailures alone (a low number, by design) would never trip a volume-based alert tuned for brute forcing — the whole point of spraying is staying under exactly that kind of threshold on any single account, so the detection has to key on account BREADTH, not attempt count.",
      xp: 35,
    },
    {
      type: "flag",
      id: "cred-f1",
      prompt:
        "Look at Log Analysis 2, the password spray. Exactly how many distinct accounts were targeted from source IP 185.220.101.47 in the 20-minute window described in the task's context? Enter the exact number.",
      answer: "142",
      hint: "It's stated in the opening context of Log Analysis 2, and referenced again in Question 1's explanation.",
      xp: 25,
    },
  ],
};

// =============================================================================
// ROOM 2: lateral-movement-practice
// =============================================================================

const kestrelLogonEvent: TelemetryEvent = {
  id: "evt-lat-la1-001",
  ts: "2026-07-02T02:19:44.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_success",
  severity: "medium",
  hostname: "SRV-FIL02.kestrel.local",
  src_ip: "10.60.14.22",
  mitre_technique: "T1021.002",
  mitre_tactic: "Lateral Movement",
  authentication: { method: "NTLM", result: "Success", logon_type: 3 },
  description: "SRV-FIL02 recorded a successful network logon for account sysmgr_svc, originating from WKS-SALES14.",
  raw: {
    "event.code": "4624",
    "winlog.channel": "Security",
    "winlog.computer_name": "SRV-FIL02.kestrel.local",
    "winlog.event_data.TargetUserName": "sysmgr_svc",
    "winlog.event_data.TargetDomainName": "KESTREL",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.LogonProcessName": "NtLmSsp ",
    "winlog.event_data.AuthenticationPackageName": "NTLM",
    "winlog.event_data.WorkstationName": "WKS-SALES14",
    "winlog.event_data.IpAddress": "10.60.14.22",
    "winlog.event_data.IpPort": "51330",
    "winlog.event_id": 4624,
  },
};

const kestrelServiceEvent: TelemetryEvent = {
  id: "evt-lat-la2-001",
  ts: "2026-07-02T02:20:11.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "service_install",
  severity: "high",
  hostname: "SRV-FIL02.kestrel.local",
  mitre_technique: "T1569.002",
  mitre_tactic: "Execution",
  description: "SRV-FIL02's System log recorded a new service being installed and started, 27 seconds after the network logon reviewed in Log Analysis 1.",
  raw: {
    "event.code": "7045",
    "winlog.channel": "System",
    "winlog.computer_name": "SRV-FIL02.kestrel.local",
    "winlog.event_data.ServiceName": "PSEXESVC",
    "winlog.event_data.ImagePath": "%SystemRoot%\\PSEXESVC.exe",
    "winlog.event_data.ServiceType": "user mode service",
    "winlog.event_data.StartType": "demand start",
    "winlog.event_data.AccountName": "LocalSystem",
    "winlog.event_id": 7045,
  },
};

const jumpHostEvent: TelemetryEvent = {
  id: "evt-lat-ac1-001",
  ts: "2026-07-03T11:20:09.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "service_install",
  severity: "low",
  hostname: "SRV-APP11.kestrel.local",
  src_ip: "10.60.1.9",
  it_verify_result: "confirmed",
  it_verify_message:
    "JMP-ITSUPPORT01 is the documented IT administrative jump host. Change ticket CHG-61840 covers a scheduled monitoring-agent redeployment to SRV-APP11 during this window.",
  authentication: { method: "NTLM", result: "Success", logon_type: 3 },
  description: "SRV-APP11 recorded a network logon from JMP-ITSUPPORT01 as sysmgr_svc, followed by a new service installation matching the deployment tool's expected footprint.",
  raw: {
    "event.code": "7045",
    "winlog.channel": "System",
    "winlog.computer_name": "SRV-APP11.kestrel.local",
    "winlog.event_data.ServiceName": "KestrelMonitorAgent",
    "winlog.event_data.ImagePath": "C:\\ProgramData\\KestrelIT\\monitor_agent.exe",
    "winlog.event_data.ServiceType": "user mode service",
    "winlog.event_data.StartType": "auto start",
    "winlog.event_data.AccountName": "LocalSystem",
    "winlog.event_id": 7045,
  },
};

const lateralMovementRoom: Room = {
  id: "lateral-movement-practice",
  title: "Tracing Lateral Movement",
  description:
    "Windows Protocols & Lateral Movement taught you the wire-level mechanics — SMB, Kerberos, NTLM, DCERPC. This room hands you the scattered evidence a real intrusion leaves across three hosts and asks you to reconstruct it: decide whether a network logon is admin tooling or an intrusion, connect a service installation back to the session that caused it, and order a multi-host movement chain by what the timestamps actually say.",
  difficulty: "advanced",
  category: "Threat Detection",
  estimatedMinutes: 65,
  xp: 370,
  icon: "🧵",
  prerequisites: ["windows-protocols-lateral"],
  tasks: [
    {
      type: "reading",
      id: "lat-r1",
      heading: "What One Host's Logs Can and Can't Tell You",
      content:
        `A single compromised host never shows you an intrusion — it shows you one link in a chain, and the chain is only visible once you pull evidence from every host it touched and lay the timestamps side by side. That reconstruction skill, not any single log field, is what separates an analyst who can confirm lateral movement from one who can only confirm that something odd happened somewhere.\n\n` +
        `**Why one host's view is always incomplete**\n\n` +
        `When an attacker moves from host A to host B, host A's logs show the outbound side — a process reaching out, a session being initiated — while host B's logs show the inbound side: an authentication event, then whatever the attacker did once inside. Neither host, on its own, tells the full story. Host B in particular cannot tell you where its visitor's credentials actually came from; a network logon (LogonType 3, authenticated via NTLM's NtLmSsp mechanism) looks identical whether it originated from a legitimate remote-administration tool running on an approved jump host, or from an attacker who stole those exact credentials on a completely different, already-compromised machine ten minutes earlier. Settling which one you're looking at requires evidence that doesn't live in that one 4624 record at all — the source host's own history, a change ticket, or what happens immediately afterward.\n\n` +
        `**The chain you'll reconstruct in this room**\n\n` +
        `A realistic movement chain looks like this: a workstation is compromised first (through phishing, an exposed service, or stolen credentials); from there, the attacker authenticates outward to a first server, using the stolen account's genuine privileges to write to an administrative share and install a service; that new service becomes their execution point on the first server, from which they pivot again — often within minutes — to a second server, repeating the pattern. Each hop leaves its own, independently incomplete set of artefacts, and SIEM ingestion delay means those artefacts frequently do not arrive in your queue in the order they actually happened. Reconstructing the true order, from timestamps rather than arrival order or which alert fired loudest, is exactly what this room's ordering exercise will ask you to do.\n\n` +
        `**Reading this room's evidence**\n\n` +
        `Throughout this room, you'll be handed individual, independently-real log records — a 4624, a 7045, a process event — the same way a real investigation hands them to you: one host, one log source, one moment at a time. Nothing in any single record will tell you 'this is the second hop of an attack.' That conclusion only exists once you've placed each record next to the others by host, account, and time, exactly the discipline the rest of this room drills.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant WKS as WKS-SALES14 (compromised workstation)\n" +
        "  participant FIL as SRV-FIL02 (hop 1)\n" +
        "  participant APP as SRV-APP09 (hop 2)\n" +
        "  Note over WKS: Attacker obtains sysmgr_svc's credentials\n" +
        "  WKS->>FIL: NTLM network logon (LogonType 3, NtlmSsp)\n" +
        "  WKS->>FIL: ADMIN$ write + IPC$/svcctl service install\n" +
        "  Note over FIL: New service runs as the attacker's execution point\n" +
        "  FIL->>APP: Outbound connection, then NTLM network logon\n" +
        "  FIL->>APP: ADMIN$ write + IPC$/svcctl service install\n" +
        "  Note over APP: Each hop's logs are independently incomplete -- only reconstructing all three together shows the chain",
      diagramCaption: "A two-hop lateral movement chain across three hosts",
    },
    {
      type: "reading",
      id: "lat-r2",
      heading: "Privilege Realism: What ADMIN$ and a New Service Actually Prove",
      content:
        `Every log-analysis task in this room hinges on one fact that's easy to state and easy to forget under pressure: writing to the ADMIN$ share and creating a new Windows service through the Service Control Manager both require local administrator rights on the TARGET host, specifically. Not domain admin. Not administrator anywhere else in the environment. Local admin, on that one machine, at the moment the action happened.\n\n` +
        `**Why this matters more than it sounds like it should**\n\n` +
        `It's tempting to treat 'this account installed a service remotely' as proof of a powerful, domain-wide compromise. It isn't, automatically. Local administrator rights on a specific server can come from many places that have nothing to do with Domain Admins membership: a GPO Restricted Groups policy that grants a helpdesk or support-tooling service account local admin across every workstation and server in scope (common, and often broader than anyone remembers authorizing); a one-off addition to a single server's local Administrators group that was never cleaned up after a project ended; or, yes, genuine compromise of a Domain Admin account. The service installation you're looking at proves the acting account held local admin on that specific target — it does not, by itself, tell you why, or whether that grant was ever meant to be used from where it was just used.\n\n` +
        `**What this means for reading the room's evidence**\n\n` +
        `When you see a service successfully installed via ADMIN$/svcctl in this room's log-analysis tasks, you already know one thing for certain without needing it stated anywhere: the acting account held local admin on that target host at that moment — the action could not have succeeded otherwise. What you don't automatically know is whether that account's use, from that source, at that time, was authorized. Those are two separate questions, and conflating them is a common analyst error in both directions: dismissing a legitimate privilege as suspicious just because it's broad, or dismissing a suspicious USE of a legitimate privilege as fine just because the account technically had the right to do it. This room's log-analysis and analyst-choice tasks are built specifically to make you hold both facts at once — the account really can do this, and that still doesn't answer whether this specific instance should have happened.\n\n` +
        `**The check that actually answers the second question**\n\n` +
        `Since the privilege itself won't tell you, the discriminator has to come from elsewhere: does the source host have any history of being used for administration (a jump host, a management console) or is this its first appearance in that role? Is there a change ticket or an open support session covering this timeframe? Is the timing consistent with the account's normal operating pattern (business hours, a known maintenance window) or a clear outlier? None of these live in the 4624 or the 7045 — they live in context you have to go get, which is exactly the 'one extra piece of evidence' this room's first log-analysis task asks you to name.`,
      codeExample:
        "WHAT ADMIN$/SVCCTL SUCCESS PROVES -- AND DOESN'T\n" +
        "=======================================================\n" +
        "PROVES:   the acting account held LOCAL ADMIN on the\n" +
        "          TARGET host, at that moment -- the action\n" +
        "          could not have succeeded otherwise\n\n" +
        "DOES NOT PROVE:\n" +
        "  - Domain Admin membership (local admin can be granted\n" +
        "    narrowly, e.g. via GPO Restricted Groups, with zero\n" +
        "    domain-wide privilege attached)\n" +
        "  - that THIS USE, from THIS SOURCE, at THIS TIME, was\n" +
        "    authorized -- that's a separate question entirely\n" +
        "=======================================================\n\n" +
        "WHERE THE SECOND ANSWER ACTUALLY LIVES\n" +
        "=======================================================\n" +
        "- Source host's history: designated jump host, or first\n" +
        "  appearance in an administrative role?\n" +
        "- A change ticket or open support session for this window?\n" +
        "- Timing: matches the account's normal pattern, or an\n" +
        "  outlier (off-hours, unfamiliar source)?\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "lat-q1",
      question:
        "An analyst argues that because an account successfully installed a service via ADMIN$/svcctl on SRV-FIL02, that account must be a member of Domain Admins. What's wrong with that reasoning?",
      options: [
        "Nothing — Domain Admin membership is the only way to write to ADMIN$ or create a service anywhere in a domain",
        "The action only proves local administrator rights on SRV-FIL02 specifically; that can be granted narrowly (for example via a GPO Restricted Groups policy scoping a support account's admin rights to certain hosts) with no Domain Admin membership involved at all",
        "ADMIN$ access actually requires no privilege whatsoever — any authenticated user can write to it",
        "Service creation requires SeDebugPrivilege, which only Domain Admins hold",
      ],
      answer: 1,
      explanation:
        "Local administrator rights on one specific host, however that account came to hold them, is all that's required — and all that the action proves. Domain Admins is one way to get local admin everywhere, but far from the only way, and it's common for a single service or support account to hold local admin narrowly across just the hosts a GPO scopes it to. ADMIN$ definitely requires privilege, and SeDebugPrivilege is unrelated to service creation — it's the privilege behind reading another process's memory, covered in the privilege-escalation room.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "lat-la1",
      heading: "Admin Tooling or Intrusion? A Network Logon From an Unusual Source",
      context:
        "SRV-FIL02 is a general-purpose file server. sysmgr_svc is a support-tooling account with local administrator rights on most Kestrel workstations and servers, granted through a GPO Restricted Groups policy. Kestrel's asset inventory shows WKS-SALES14 as a standard sales-team workstation with no record, in the prior 90 days, of being a source for any administrative logon to SRV-FIL02.",
      event: kestrelLogonEvent,
      questions: [
        {
          question:
            "TargetUserName is sysmgr_svc, LogonType is 3, and LogonProcessName is 'NtLmSsp ' — an NTLM network logon. Given that sysmgr_svc genuinely holds local admin rights broadly, does this event by itself prove an intrusion?",
          options: [
            "Yes — NTLM network logons by an admin-capable account are always malicious",
            "No — this exact mechanism (an NTLM network logon by an account with legitimate local admin rights) is also precisely how normal remote administration and support tooling works; the event alone doesn't distinguish the two",
            "Yes, because LogonType 3 is exclusive to attacker tooling and is never used by legitimate remote administration",
            "No, because sysmgr_svc is a service account and service accounts cannot be compromised",
          ],
          answer: 1,
          explanation:
            "Reading 2's point applies directly: the mechanism sysmgr_svc just used is identical whether a legitimate support session or an attacker with stolen credentials triggered it. LogonType 3 is the standard, extremely common network-logon type used constantly by legitimate remote administration, not an attacker-exclusive signal, and service accounts are compromised routinely — their credentials are just as stealable as any user's.",
          xp: 25,
        },
        {
          question: "What one additional piece of evidence would most efficiently settle whether this is legitimate administration or an intrusion?",
          options: [
            "Whether WKS-SALES14 has any history of being used as a source for administrative logons to servers like SRV-FIL02, and whether an open change ticket or support session covers this timeframe",
            "Re-confirming that LogonType is exactly 3, since that value alone is the deciding factor",
            "Nothing further is needed — the presence of NtLmSsp in LogonProcessName already settles it",
            "Whether SRV-FIL02 has ever been rebooted in the past year",
          ],
          answer: 0,
          explanation:
            "This is Reading 2's answer: the privilege itself won't tell you whether this specific use was authorized, so the discriminator has to come from the source host's history and any documented change — a designated jump host or an open ticket points toward legitimate administration, while a source with no such history, like WKS-SALES14 here, points toward compromise. Re-checking LogonType or LogonProcessName adds nothing new, and SRV-FIL02's reboot history is unrelated.",
          xp: 25,
        },
        {
          question: "WKS-SALES14 has no history of admin-source activity toward SRV-FIL02, and no change ticket exists for this timeframe. What should the analyst do?",
          options: [
            "Close as benign, since sysmgr_svc genuinely holds the local admin rights that made this succeed",
            "Treat this as a likely intrusion using sysmgr_svc's credentials: investigate WKS-SALES14 as the probable point of compromise, and continue tracing what sysmgr_svc did next on SRV-FIL02",
            "Disable sysmgr_svc's local admin rights domain-wide immediately, without further investigation",
            "Take no action until a full 90-day audit of every account's logon history is complete",
          ],
          answer: 1,
          explanation:
            "Holding the right to do something is not the same as this specific use being authorized (Reading 2's core distinction) — with no source history and no ticket, the reasonable read is that sysmgr_svc's credentials are being used from a host that was never meant to originate this kind of session, meaning WKS-SALES14 itself is the more likely actual point of compromise and needs its own investigation, while tracing forward what happened on SRV-FIL02 next. Revoking rights domain-wide is heavy before confirming anything, and waiting for a full audit abandons an active lead.",
          xp: 30,
        },
      ],
    },
    {
      type: "log_analysis",
      id: "lat-la2",
      heading: "Connecting the Service Install to the Session That Caused It",
      context:
        "Compare this record's host and timestamp against the network logon you reviewed in Log Analysis 1 (SRV-FIL02, 02:19:44, sysmgr_svc from WKS-SALES14).",
      event: kestrelServiceEvent,
      questions: [
        {
          question:
            "This event's computer_name is SRV-FIL02 and its timestamp is 02:20:11 — 27 seconds after the 4624 logon from Log Analysis 1 on the same host. What does connecting these two records tell you that neither one tells you alone?",
          options: [
            "Nothing new — a service installation and a network logon on the same host are unrelated by default",
            "Together they show the NTLM session from WKS-SALES14 wasn't just a connection attempt — it was followed, within half a minute, by a real new service being created and started on SRV-FIL02, consistent with the ADMIN$/IPC$/svcctl mechanism from Reading 2",
            "The 27-second gap proves this service installation is unrelated to sysmgr_svc's session, since real attacks happen instantly",
            "This event alone proves domain-wide compromise, without needing Log Analysis 1 at all",
          ],
          answer: 1,
          explanation:
            "Neither record alone tells the full story — Reading 1's whole point — but placed together, a network logon immediately followed by a new service on the same host is exactly the observable signature of the ADMIN$-write-then-svcctl-install mechanism from Reading 2, whether performed by legitimate tooling or an attacker. A 27-second gap is well within how quickly this mechanism actually executes, and this single service record says nothing about domain-wide scope on its own.",
          xp: 25,
        },
        {
          question: "ServiceName is 'PSEXESVC' and ImagePath is its literal, unmodified default value. Why is it common to see a tool's real default name here rather than something disguised?",
          options: [
            "PSEXESVC cannot be renamed under any circumstances, so this is the only name that could ever appear",
            "Operators frequently don't bother renaming default tooling, especially when moving quickly — which cuts both ways: instantly recognizable to an analyst who knows the default, but easy to miss if you don't already know what PSEXESVC.exe's presence typically means",
            "The default name proves this specific installation was legitimate, since attackers always rename their tools",
            "The ImagePath field doesn't actually exist on a 7045 event, so this value is unreliable",
          ],
          answer: 1,
          explanation:
            "PsExec's service name and path can be customized, but plenty of real intrusions simply don't bother — which is exactly why recognizing PSEXESVC.exe's default footprint is worth memorizing rather than assuming disguise. Seeing the literal default proves nothing about legitimacy either way, since both legitimate admins and attackers use PsExec constantly, often without renaming it, and ImagePath is a genuine, standard field on 7045.",
          xp: 25,
        },
        {
          question:
            "Given that this service installation required local admin on SRV-FIL02, and sysmgr_svc genuinely holds that right, what does the successful installation add to your understanding beyond what Reading 2 already told you to expect?",
          options: [
            "It changes nothing — the privilege question was already settled by Reading 2, and this event doesn't affect the authorization question at all",
            "It proves, on its own, that sysmgr_svc's use here was authorized, since the action succeeded",
            "It proves sysmgr_svc must actually be a Domain Admin account",
            "It proves WKS-SALES14 is a legitimate jump host, since the downstream action worked",
          ],
          answer: 0,
          explanation:
            "This is the distinction Reading 2 built toward: a successful ADMIN$/svcctl action confirms the privilege existed (which you already knew from sysmgr_svc's known GPO-granted rights) but adds nothing to the separate question of whether this specific use, from this specific source, was authorized — that answer still depends on WKS-SALES14's history and the absence of a change ticket, established in Log Analysis 1, not on this event succeeding.",
          xp: 30,
        },
      ],
    },
    {
      type: "question",
      id: "lat-q2",
      question:
        "Two records show byte-for-byte identical ADMIN$/IPC$-then-7045 mechanics on two different hosts. One is later confirmed to be an intrusion; the other, reviewed next, turns out to be legitimate. Since the technical mechanism was identical in both, what actually made the difference?",
      options: [
        "Nothing could actually differ — if the mechanism is identical, both cases must have the same verdict",
        "Context outside the mechanism itself: the source host's known role and history, whether a change ticket or support session covers the activity, and whether the timing matches normal administrative patterns",
        "The ServiceName field, since malicious services always use a different name than legitimate ones",
        "The LogonType value, since intrusions always use a different LogonType than legitimate remote administration",
      ],
      answer: 1,
      explanation:
        "This is the throughline of Reading 2 and Log Analysis 1/2: the mechanism is identical for legitimate remote administration and for an attacker using stolen but genuinely privileged credentials, so the verdict has to come from context that lives outside that mechanism — source host history, tickets, and timing. ServiceName and LogonType don't reliably differ between the two cases at all, since both legitimate tooling and attackers commonly use the same defaults and the same LogonType 3.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "lat-ac1",
      heading: "Verdict: The Same Mechanism From the Designated Jump Host",
      scenario:
        "A detection rule fired on IPC$/svcctl access followed by a new service installation, this time on SRV-APP11, originating from JMP-ITSUPPORT01. IT records confirm JMP-ITSUPPORT01 is Kestrel's designated administrative jump host, and the access occurred at 11:20 AM on a weekday, matching an open change ticket for a scheduled agent redeployment.",
      event: jumpHostEvent,
      correct_verdict: "false_positive",
      explanation:
        "The mechanism is identical to Log Analysis 1/2 — an NTLM network logon by sysmgr_svc followed by a new service — which is exactly why context, not the mechanism, decides this verdict. Here, the source is the documented jump host (not an unexplained workstation like WKS-SALES14), the timing matches business hours and an open, specific change ticket, and the installed service (KestrelMonitorAgent, running from a known internal deployment path) matches the ticket's stated purpose rather than a generic remote-execution tool's default footprint.",
      fp_trap:
        "IPC$/svcctl access followed by a 7045 is precisely the pattern this room just taught you to treat seriously — and reflexively escalating every instance of it, without checking source and ticket, would flag Kestrel's own routine administration constantly. The differentiators are exactly the ones Reading 2 named: a verified jump host instead of an unexplained peer host, a specific matching change ticket instead of no record at all, and an installed service that identifies itself as a known internal tool instead of a generic default like PSEXESVC. Skipping that check and escalating purely on 'ADMIN$ + svcctl + 7045' is the same over-alerting failure the credential-attacks room warns about with RC4 tickets — a real signal, checked without its context, becomes noise.",
      xp: 30,
    },
    {
      type: "matching",
      id: "lat-m1",
      heading: "Match Each Movement Technique to the Artefact It Leaves",
      instructions: "Match each lateral-movement technique to the log artefact that actually reveals it.",
      pairs: [
        { id: "smb", left: "SMB / administrative shares (ADMIN$, IPC$)", right: "IPC$/svcctl access on the target, followed by a new-service Event ID 7045 with a ServiceName and ImagePath" },
        { id: "rdp", left: "RDP (Remote Desktop Protocol)", right: "A 4624 logon with LogonType 10, plus a full interactive graphical session — not a named-pipe or RPC artefact at all" },
        { id: "wmi", left: "WMI-based remote execution", right: "A connection to TCP/135 then a dynamic high port, and a new process on the target with WmiPrvSE.exe as its parent — no new-service artefact" },
        { id: "winrm", left: "WinRM / PowerShell Remoting", right: "An HTTP or HTTPS session on TCP 5985/5986, with any spawned process showing wsmprovhost.exe as its parent" },
      ],
      explanation:
        "Each technique's artefact follows directly from its transport: SMB-based execution leaves the IPC$/svcctl-then-7045 chain this room's log-analysis tasks are built on; RDP leaves an entirely different, session-based artefact (LogonType 10) with no named pipe involved; WMI rides DCOM/RPC and specifically avoids leaving a service artefact, which is exactly why its detection leans on process-creation telemetry (WmiPrvSE.exe as parent) instead; and WinRM's distinct HTTP-based transport shows up as a TCP 5985/5986 session with wsmprovhost.exe fingerprinting any process it spawns.",
      xp: 40,
    },
    {
      type: "ordering",
      id: "lat-o1",
      heading: "Reconstruct the Chain Across Three Hosts, By Timestamp",
      instructions: "Your SIEM received these six records out of arrival order because of an ingestion delay on one host's log forwarder. Arrange them by their actual timestamps, not by when they reached your queue.",
      items: [
        { id: "wks-logon", text: "WKS-SALES14, 02:14 — sysmgr_svc's credentials are used to establish a session on this workstation, a host with no prior record of initiating administrative activity" },
        { id: "fil-4624", text: "SRV-FIL02, 02:19 — a network logon (LogonType 3, NtLmSsp) from WKS-SALES14 authenticates as sysmgr_svc" },
        { id: "fil-7045", text: "SRV-FIL02, 02:20 — a new service is registered and started, 27 seconds after the network logon above" },
        { id: "fil-outbound", text: "SRV-FIL02, 02:31 — the newly-installed service's process opens an outbound connection toward SRV-APP09" },
        { id: "app-4624", text: "SRV-APP09, 02:32 — a network logon (LogonType 3) from SRV-FIL02 authenticates as sysmgr_svc, followed by its own ADMIN$/service-install sequence" },
        { id: "app-lsass", text: "SRV-APP09, 02:41 — a process consistent with credential-access tooling briefly accesses lsass.exe" },
      ],
      correct_order: ["wks-logon", "fil-4624", "fil-7045", "fil-outbound", "app-4624", "app-lsass"],
      explanation:
        "Laid out by timestamp rather than arrival order, the chain reads exactly as Reading 1 described: the workstation compromise comes first, then the first hop's logon-then-service-install pair (the same two records from Log Analysis 1 and 2), then the pivot outbound from that new foothold, then the second hop repeating the identical logon-then-install pattern, and finally credential-access activity on the second server — the natural next step once an attacker has a new foothold worth harvesting more credentials from. Ordering these by which alert fired first in your queue instead would have put the second hop's evidence ahead of the first hop's, exactly the trap this exercise is built to catch.",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "lat-qf1",
      heading: "Write It Yourself: Correlate a Network Logon With a Following Service Install",
      language: "kql",
      context: "Using the pattern confirmed in Log Analysis 1 and 2 — an NTLM network logon immediately followed by a new service on the same host — write the KQL that flags this sequence for any account not on an approved admin-source allowlist.",
      template:
        "SecurityEvent\n| where EventID == {{logonid}} and LogonProcessName == \"{{logonproc}}\"\n| project Computer, Account = TargetUserName, LogonTime = TimeGenerated\n| join kind=inner (\n    SecurityEvent\n    | where EventID == {{svcid}}\n    | project Computer, InstallTime = TimeGenerated\n) on Computer\n| where InstallTime - LogonTime between (0min .. {{window}})",
      blanks: [
        { id: "logonid", answers: ["4624"], placeholder: "successful network logon Event ID" },
        { id: "logonproc", answers: ["NtLmSsp", "NtLmSsp "], placeholder: "LogonProcessName value for an NTLM network logon" },
        { id: "svcid", answers: ["7045"], placeholder: "new service installed Event ID" },
        { id: "window", answers: ["2min", "5min", "1min", "3min"], placeholder: "how tight the logon-to-install gap should be to count" },
      ],
      explanation:
        "This operationalizes exactly the correlation you did by hand in Log Analysis 1 and 2: join a network logon on one host to a service installation on the SAME host within a tight window, which turns a byte-for-byte-identical mechanism (Reading 2's central point) into a detection that still needs the same context check — an admin-source allowlist — to separate SRV-APP11's legitimate deployment from WKS-SALES14's unexplained one.",
      xp: 35,
    },
    {
      type: "flag",
      id: "lat-f1",
      prompt: "Look at Log Analysis 2, the service installation on SRV-FIL02. What is the exact value of the ServiceName field recorded in the raw log? Enter it exactly as shown.",
      answer: "PSEXESVC",
      hint: "It's in the raw block's winlog.event_data.ServiceName field — the same real, unmodified default name Reading 2's codeExample warned you to recognize.",
      xp: 25,
    },
  ],
};

// =============================================================================
// ROOM 3: web-attacks-practice
// =============================================================================

const orbitlineInjectionEvent: TelemetryEvent = {
  id: "evt-web-la1-001",
  ts: "2026-06-09T03:12:41.900Z",
  source: "siem",
  vendor: "Microsoft Sentinel",
  event_type: "http_request",
  severity: "high",
  hostname: "WEB-ORB03.orbitline.local",
  mitre_technique: "T1190",
  mitre_tactic: "Initial Access",
  network: {
    url: "https://www.orbitline.com/search.aspx",
    domain: "www.orbitline.com",
    method: "GET",
    status: 200,
    bytes_out: 48231,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  },
  description:
    "IIS access log (W3CIISLog) for www.orbitline.com. This is the third and final sc-status 200 inside a two-minute, 40-request burst against /search.aspx, in which the other 37 requests returned sc-status 500.",
  raw: {
    TimeGenerated: "2026-06-09T03:12:41.900Z",
    Computer: "WEB-ORB03.orbitline.local",
    sSiteName: "ORBITLINEWEB",
    sComputerName: "WEB-ORB03",
    sIP: "10.12.4.30",
    csMethod: "GET",
    csUriStem: "/search.aspx",
    csUriQuery: "q=widget%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
    csUserName: "-",
    cIP: "10.12.4.9",
    csHost: "www.orbitline.com",
    csUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    csReferer: "-",
    scStatus: "200",
    scSubStatus: "0",
    scWin32Status: "0",
    scBytes: "48231",
    csBytes: "612",
    TimeTaken: "812",
    csVersion: "HTTP/1.1",
    Type: "W3CIISLog",
  },
};

const orbitlineCorrelationEvent: TelemetryEvent = {
  id: "evt-web-la2-001",
  ts: "2026-06-09T03:12:40.900Z",
  source: "siem",
  vendor: "Microsoft Sentinel",
  event_type: "http_request",
  severity: "high",
  hostname: "WEB-ORB03.orbitline.local",
  mitre_technique: "T1190",
  mitre_tactic: "Initial Access",
  description:
    "SIEM correlation search joining the AWS WAF record and the IIS access-log record for the same request reviewed in Log Analysis 1 (same URI, same one-second window).",
  raw: {
    waf: {
      formatVersion: 1,
      timestamp: 1749438760900,
      webaclId: "arn:aws:wafv2:us-east-1:481923004471:regional/webacl/orbitline-prod/6e2a19f0-88b1-4d2e-9a7c-3f0512ee4c81",
      terminatingRuleId: "NONE",
      terminatingRuleType: "REGULAR",
      action: "ALLOW",
      httpSourceName: "ALB",
      httpSourceId: "app/orbitline-prod-alb/8f2c471a9b3d5e02",
      "httpRequest.clientIp": "91.203.44.187",
      "httpRequest.country": "RO",
      "httpRequest.httpMethod": "GET",
      "httpRequest.uri": "/search.aspx",
      "httpRequest.args": "q=widget%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
      "httpRequest.httpVersion": "HTTP/1.1",
      "httpRequest.requestId": "1-67e1a2f3-4c8d716b0e29fa5817b3c964",
    },
    iis: {
      TimeGenerated: "2026-06-09T03:12:41.900Z",
      Computer: "WEB-ORB03.orbitline.local",
      sSiteName: "ORBITLINEWEB",
      sIP: "10.12.4.30",
      csMethod: "GET",
      csUriStem: "/search.aspx",
      csUriQuery: "q=widget%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
      cIP: "10.12.4.9",
      csHost: "www.orbitline.com",
      scStatus: "200",
      scBytes: "48231",
      Type: "W3CIISLog",
    },
  },
};

const orbitlineScanEvent: TelemetryEvent = {
  id: "evt-web-ac1-001",
  ts: "2026-06-14T10:02:07.000Z",
  source: "waf",
  vendor: "AWS WAF",
  event_type: "waf_block",
  severity: "low",
  hostname: "WEB-ORB03.orbitline.local",
  src_ip: "64.39.106.190",
  it_verify_result: "confirmed",
  it_verify_message: "Change record CHG-70119 authorizes Orbitline's quarterly external PCI ASV scan from the Qualys cloud scanner range, window 09:00-12:00 UTC on 14 Jun.",
  network: { url: "https://www.orbitline.com/products/detail.aspx", domain: "www.orbitline.com", method: "GET", status: 403, user_agent: "Qualys-Scanner/9.5" },
  description:
    "AWS WAF blocked a SQL injection payload from 64.39.106.190. Representative of a sustained burst from this single address across many parameters and endpoints, all carrying the same self-identifying User-Agent.",
  raw: {
    formatVersion: 1,
    timestamp: 1749895327000,
    webaclId: "arn:aws:wafv2:us-east-1:481923004471:regional/webacl/orbitline-prod/6e2a19f0-88b1-4d2e-9a7c-3f0512ee4c81",
    terminatingRuleId: "AWS-AWSManagedRulesSQLiRuleSet",
    terminatingRuleType: "MANAGED_RULE_GROUP",
    action: "BLOCK",
    httpSourceName: "ALB",
    httpSourceId: "app/orbitline-prod-alb/8f2c471a9b3d5e02",
    "httpRequest.clientIp": "64.39.106.190",
    "httpRequest.country": "US",
    "httpRequest.httpMethod": "GET",
    "httpRequest.uri": "/products/detail.aspx",
    "httpRequest.args": "id=4471%20OR%201%3D1--",
    "httpRequest.httpVersion": "HTTP/1.1",
    "httpRequest.requestId": "1-6869c50f-2f19c4b76d0e5a3819bb4c72",
    "httpRequest.headers[0].name": "Host",
    "httpRequest.headers[0].value": "www.orbitline.com",
    "httpRequest.headers[1].name": "User-Agent",
    "httpRequest.headers[1].value": "Qualys-Scanner/9.5",
  },
};

const webAttacksRoom: Room = {
  id: "web-attacks-practice",
  title: "Reading a Web Attack in the Logs",
  description:
    "The theory lesson explained SQL injection, path traversal, and web shells. This room hands you the actual access-log lines, WAF records, and process telemetry a real web attack leaves, and asks you to do the two things that matter on the job: decide whether an injection attempt actually worked from status codes and response size alone, and pull the true client IP out of a WAF record because your web server's own log only ever shows the load balancer.",
  difficulty: "advanced",
  category: "Application Security",
  estimatedMinutes: 55,
  xp: 330,
  icon: "🐚",
  prerequisites: ["networking-protocols"],
  tasks: [
    {
      type: "reading",
      id: "web-r1",
      heading: "Reading an IIS Access Log: Status Codes and What 'Worked' Actually Means",
      content:
        `An IIS access log line looks dense the first time you see one, but almost everything in it exists to answer one question: what did the client ask for, and what did the server actually do about it? Learn the handful of fields that carry that answer and a wall of a hundred nearly-identical-looking lines stops being noise and starts being a story with a beginning, middle, and the one line that matters.\n\n` +
        `**The fields that carry the story**\n\n` +
        `cs-uri-stem is the path being requested (/search.aspx); cs-uri-query is everything after the question mark — and for a web application attack, this is very often where the payload itself lives, since query parameters are exactly what SQL injection, path traversal, and command injection attempts try to smuggle malicious input through. c-ip is the address IIS believes it's talking to (with an important caveat covered in the next reading). cs(User-Agent) identifies the client software, or claims to — it's trivially spoofable, but a consistent, honest-looking value across an entire burst is itself informative. sc-status is the HTTP status code the server actually returned, and it is the single most important field for judging outcome, not intent.\n\n` +
        `**Status codes as outcome, not as intent**\n\n` +
        `A 4xx status (404 Not Found, 403 Forbidden) means the server understood the request and refused or couldn't fulfill it — content discovery sweeps and blocked injection attempts both live here. A 5xx status, especially 500 Internal Server Error, means the application itself broke while trying to process the request — and for a SQL injection attempt specifically, a 500 very often means the malformed SQL syntax the attacker sent caused the database driver to throw an unhandled exception, which the application couldn't recover from. That's a critical, counter-intuitive point: a 500 in the middle of an injection attempt is usually a FAILED attempt, not a successful one — the payload broke the query before it could return anything useful. A 200 OK, by contrast, means the request was processed successfully end to end. In the middle of a calibration burst against a search endpoint, a lone 200 sitting among dozens of 500s is not the boring result — it's the one attempt whose SQL syntax was valid enough to actually execute.\n\n` +
        `**The field most analysts skip past: response size**\n\n` +
        `sc-bytes (the size of the response body) is easy to ignore, but for exactly this scenario it's often the field that turns a hunch into a finding. A search endpoint that normally returns a few kilobytes for a real search term returning tens of kilobytes for a query-string payload containing UNION SELECT is a strong sign the injected query executed and returned far more data than a normal search result ever would — a classic signature of a successful UNION-based extraction. Reading a wall of access-log lines well means scanning past the sea of matching 500s and 403s for the outlier: a 200, especially paired with an outlier response size, sitting inside a burst that otherwise looks like nothing but failure.\n\n` +
        `**One line is one request, not a verdict**\n\n` +
        `As with the authentication logs elsewhere on this platform, a single access-log line rarely proves anything on its own — a normal user occasionally gets a 500 from an unrelated bug, and a single 200 among many requests could be entirely unrelated traffic that happened to land in the same window. What actually builds a finding is the same discipline as always: look at the line in the context of the burst it belongs to, and let the status code and response size — not the query string alone — tell you whether an attempt worked.`,
      codeExample:
        "HTTP STATUS CODES -- READ AS OUTCOME, NOT INTENT\n" +
        "=======================================================\n" +
        "2xx   Request processed successfully end to end\n" +
        "      -- for an injection attempt, this can mean it EXECUTED\n" +
        "3xx   Redirect -- rarely relevant to injection analysis\n" +
        "4xx   Client error -- server refused/couldn't fulfill it\n" +
        "      (404 not found, 403 forbidden -- WAF blocks live here)\n" +
        "5xx   Server error -- the APPLICATION broke processing it\n" +
        "      -- for SQLi, usually means malformed syntax crashed\n" +
        "         the query parser BEFORE anything was returned\n" +
        "=======================================================\n\n" +
        "WHY A 500-HEAVY BURST WITH A FEW 200s IS THE PATTERN\n" +
        "=======================================================\n" +
        "37 x 500   Malformed injection syntax -- parser crashed,\n" +
        "           attacker calibrating, nothing returned\n" +
        " 3 x 200   Syntactically valid payload -- query EXECUTED\n" +
        "           -- check sc-bytes against this endpoint's normal\n" +
        "              response size before assuming it's benign\n" +
        "=======================================================",
    },
    {
      type: "reading",
      id: "web-r2",
      heading: "Why You Need Both the WAF Record and the Web-Server Record for the Same Request",
      content:
        `Modern web applications almost never sit directly on the internet. A request from a real client typically passes through a WAF (Web Application Firewall), then a load balancer, before it ever reaches the web server itself — and each hop in that path can rewrite what the NEXT hop believes about who's actually asking.\n\n` +
        `**Where the true client IP actually lives**\n\n` +
        `A WAF, sitting closest to the internet-facing edge, is usually the last point in the chain that ever sees the real client's raw TCP connection — its own log's client-IP field (for example AWS WAF's httpRequest.clientIp) reflects the actual internet-facing source. Everything downstream of the WAF, though, sees a re-established connection: the load balancer opens its OWN connection to the web server, using its own address, and unless the environment is specifically configured to forward and log the original client's address (via an X-Forwarded-For header the web server is set up to capture), the web server's own access log will show the load balancer's internal IP in its client-IP field — every single time, for every single request, regardless of who actually sent it.\n\n` +
        `**What this means for attribution**\n\n` +
        `If you only ever pull the web server's own access log, every request — legitimate and malicious alike — appears to originate from the same handful of internal load-balancer addresses. Trying to build a block list, or even just answer 'who sent this,' from that field alone is not just incomplete, it's actively misleading: you'd be looking at your own infrastructure's address, not the attacker's. The WAF record for the exact same request is the only place the real source survives, which is why confirming attribution always means pulling both records — matched by the request's URI, method, and a timestamp close enough to be the same event — and reading the WAF's client-IP field as authoritative for 'who,' while the web server's record remains authoritative for exactly what request the application itself processed and how it responded.\n\n` +
        `**Matching two records that don't share an ID**\n\n` +
        `Different vendors' logs almost never share a common request identifier you can join on directly. In practice, matching a WAF record to its corresponding web-server record means lining up the URI and query string, the HTTP method, and a timestamp within a second or two of each other — close enough, combined, to be confident they describe the same request, even though neither log was designed with the other in mind. This is exactly the correlation exercise the next log-analysis task in this room asks you to perform by hand.`,
      diagram:
        "flowchart LR\n" +
        "  C[Client: true source IP] --> W[WAF: sees the real client IP]\n" +
        "  W --> L[Load Balancer: opens its OWN connection]\n" +
        "  L --> S[Web Server / IIS: logs the LB's IP as c-ip]\n" +
        "  W -.->|httpRequest.clientIp = true attacker IP| N1[Recorded only at the WAF]\n" +
        "  S -.->|c-ip = the load balancer's own address| N2[Same value for every request, regardless of source]",
      diagramCaption: "Where the true client IP survives — and where it doesn't",
    },
    {
      type: "question",
      id: "web-q1",
      question:
        "An access log shows a burst of 40 requests to /search.aspx?q=... from one source in two minutes: 37 return sc-status 500, and 3 return sc-status 200. What do the three 200 responses most likely represent, relative to the 37 failures?",
      options: [
        "Nothing different — 500 and 200 both indicate the request was blocked, just with different wording",
        "Syntactically valid injection payloads that actually executed against the application, unlike the 37 failures where malformed SQL syntax crashed the query parser before returning anything",
        "The 3 requests with status 200 are certainly unrelated legitimate traffic that coincidentally landed inside the attack burst",
        "A 500 status always means the server successfully blocked the attack, making the 37 failures the more serious finding",
      ],
      answer: 1,
      explanation:
        "500 means the server-side application broke processing the request — for injection attempts, that's usually the query parser choking on malformed syntax, a failed attempt, not a block. The three 200 responses inside the same burst, from the same source, in the same short window, are far more consistent with payloads that were syntactically valid and executed than with unrelated coincidental traffic, and a 500 is not evidence of successful blocking; it's an application error.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "web-la1",
      heading: "One 200 Among a Wall of 500s",
      context:
        "Orbitline's WAF logged 40 requests to /search.aspx from 91.203.44.187 within a two-minute window: 37 returned sc-status 500, and 3 returned sc-status 200. This endpoint's normal response for a real search term is roughly 2,000-3,000 bytes. Review the record below — the third and final 200 in that burst.",
      event: orbitlineInjectionEvent,
      questions: [
        {
          question:
            "scStatus here is 200 and scBytes is 48,231 — against a baseline of roughly 2,000-3,000 bytes for a normal search result on this endpoint. Combined with the fact that 37 of the 40 requests in this burst returned 500, what does this specific record most likely represent?",
          options: [
            "A normal search that happened to return a large result set",
            "The one payload in the burst whose SQL syntax was valid enough to execute, returning far more data than a real search ever would — consistent with a successful UNION-based extraction, unlike the 37 failed attempts that crashed the query parser",
            "Evidence that the WAF successfully blocked this specific request, since it returned a non-error status",
            "A caching artifact, since scBytes reflects the size of a cached response, not the actual query result",
          ],
          answer: 1,
          explanation:
            "A response roughly 16-24x this endpoint's normal size, on the one successful status code inside a burst where everything else failed, is the signature of a UNION-based injection that actually executed and pulled back extra columns/rows — not a coincidentally large legitimate search, not a block (200 means the request went through, not that it was stopped), and scBytes reflects the actual response size sent to the client, not a caching layer's own bookkeeping.",
          xp: 25,
        },
        {
          question: "csUriQuery contains a UNION SELECT payload targeting a users table. Does the presence of that payload text, by itself, prove the injection succeeded?",
          options: [
            "Yes — the payload text appearing in the log is sufficient proof on its own",
            "No — the payload only shows what was attempted; scStatus and scBytes are what confirm whether it actually executed and returned data, which is exactly why this record needs to be read for outcome, not just for the query string",
            "No — csUriQuery is never actually logged for GET requests, so this field can't be trusted",
            "Yes, but only because the User-Agent string in this record is unusually suspicious",
          ],
          answer: 1,
          explanation:
            "This is Reading 1's central point: the query string tells you intent, not outcome. Plenty of the 37 failed attempts in this same burst almost certainly carried similarly aggressive-looking payload text and still crashed on syntax — the codes and size are what separate the one that worked from the 37 that didn't. csUriQuery is a completely standard field for GET requests with query parameters, and the User-Agent here is an ordinary browser string, not itself suspicious.",
          xp: 25,
        },
        {
          question: "What is the appropriate next step given this finding?",
          options: [
            "Close this as one more blocked injection attempt, consistent with the other 37 requests in the burst",
            "Treat this as a confirmed, successful SQL injection rather than just an attempt: pull the database's own query/audit log for this timeframe to determine what was actually read, and move to contain the source",
            "No further action is needed since the WAF already logged the request",
            "Reset every user's password site-wide as the only appropriate response to a database query",
          ],
          answer: 1,
          explanation:
            "The evidence points to actual data exposure, not just an attempted-and-failed request like the other 37 — that calls for pulling the database's own audit trail to scope exactly what the query returned, not treating this record the same as the failures around it. This record being logged is not the same as it being handled, and a site-wide password reset is disconnected from what this specific finding (a users-table read) actually calls for until the database audit confirms scope.",
          xp: 30,
        },
      ],
    },
    {
      type: "log_analysis",
      id: "web-la2",
      heading: "Correlating the WAF Record With the Web-Server Record",
      context:
        "The IIS record you reviewed in Log Analysis 1 shows cIP as 10.12.4.9 for the successful injection — Orbitline's internal Application Load Balancer, not a real client. Pull the AWS WAF record for the same request, matched by URI and a one-second-apart timestamp, to find out who actually sent it.",
      event: orbitlineCorrelationEvent,
      questions: [
        {
          question: "waf.httpRequest.clientIp shows 91.203.44.187, but iis.cIP for the same request shows 10.12.4.9. Which one is the true originating client, and why do they differ?",
          options: [
            "91.203.44.187 is the true client — the WAF sees the raw internet-facing connection, while 10.12.4.9 is the internal Application Load Balancer's own address, which is what IIS sees because the request reaches it already re-proxied",
            "10.12.4.9 is the true client, since the web server is always closer to the source than a WAF",
            "They're both equally valid representations of the same external address, just recorded in different formats",
            "This is a logging error — a single request can only ever have one recorded IP, so one of these two fields must be wrong",
          ],
          answer: 0,
          explanation:
            "This is Reading 2's core mechanism: the WAF is the last hop that sees the real client's raw connection, while everything downstream (the load balancer, then IIS) sees a re-established connection using the load balancer's own address — that's not a logging error, it's simply how a proxied architecture works, and it's exactly why 10.12.4.9 is not, and never will be, the real client for any request through this path.",
          xp: 25,
        },
        {
          question: "If an analyst tried to build a source-IP block list purely from IIS's own cIP field across many requests, what would go wrong?",
          options: [
            "Nothing — cIP reliably reflects the true external source for every request",
            "Every request proxied through the same load balancer shows the identical internal address (10.12.4.9) regardless of which external client actually sent it, making cIP useless for attribution on its own — this is exactly why the WAF record has to be pulled for the same request",
            "cIP only appears on requests that were blocked, so it can't be used for a block list of allowed traffic",
            "cIP rotates randomly on every request, making it impossible to build any list from it at all",
          ],
          answer: 1,
          explanation:
            "Reading 2's central warning: because every request passes through the same load balancer, IIS's cIP field shows the same internal address across the board — legitimate and malicious traffic alike — which makes it structurally incapable of supporting source attribution by itself, regardless of how many requests you pull. It's not restricted to blocked requests, and it doesn't rotate randomly; it's simply, consistently, the load balancer's own fixed address.",
          xp: 25,
        },
        {
          question: "Both records now confirm 91.203.44.187 as the true source of the successful injection from Log Analysis 1. What should the analyst do with this IP specifically?",
          options: [
            "Add a block/deny rule for it at the web server's own configuration, since that's where the request was ultimately processed",
            "Add a targeted block/deny rule for it at the WAF (the only point in the chain that actually sees this address), and search WAF logs broadly for this same clientIp across the full incident window to scope its other activity",
            "Take no further action, since the injection has already been logged",
            "Block the internal load balancer address 10.12.4.9 instead, since that's the IP IIS itself recorded",
          ],
          answer: 1,
          explanation:
            "Since the web server never sees the real client address at all, blocking has to happen at the WAF — the only point in the chain capable of matching on 91.203.44.187 in the first place — and the same clientIp field should be searched across the broader window to find any other requests this actor made, not just the one already confirmed. Blocking 10.12.4.9 would block Orbitline's own load balancer, cutting off all legitimate traffic through it.",
          xp: 30,
        },
      ],
    },
    {
      type: "question",
      id: "web-q2",
      question:
        "Two WAF-blocked bursts against the same endpoint look identical in payload shape — the same SQLi payload catalogue, similar volume. One turns out to be an authorized vulnerability scan; the other is a real attacker's calibration probing. What most reliably tells them apart?",
      options: [
        "Nothing can reliably tell them apart — payload shape is the only signal available",
        "A stable, non-rotating source IP with a self-identifying User-Agent and a matching change record on the scan side, versus a source that rotates across a range, an ordinary browser or scripting User-Agent, and no corresponding change record on the attack side",
        "The scan will always use a lower HTTP status code than a real attack",
        "Authorized scans never trigger a WAF's managed rule sets, so any WAF block is automatically a real attack",
      ],
      answer: 1,
      explanation:
        "Payload shape alone is exactly what makes these look identical — the real discriminators: a scanner is typically one stable, unchanging source IP, often with a self-identifying User-Agent (many scanning tools announce themselves), backed by a documented change record covering the window; a real attacker's probing more often rotates source addresses, uses generic or scripted User-Agents, and has no matching authorization on file. HTTP status codes don't reliably differ between the two, and authorized scans absolutely do trigger WAF rules — that's the point of running them.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "web-ac1",
      heading: "Verdict: A Scheduled Vulnerability Scan Firing the Same Signatures",
      scenario: "AWS WAF blocked a sustained burst of SQL injection payloads against multiple Orbitline endpoints from a single source. Review the record below alongside the associated change record.",
      event: orbitlineScanEvent,
      correct_verdict: "false_positive",
      explanation:
        "Every payload here matches the same managed SQLi signature set a real attack would trigger — which is exactly why the discriminators from Reading 2 and Question 2 matter: 64.39.106.190 is a single, stable source inside the documented Qualys scanner range, the User-Agent self-identifies as the scanning tool rather than disguising itself, a confirmed change record covers this exact window, and — critically — nothing in this burst resembles Log Analysis 1's pattern (a 200 with an anomalous response size); every request here was BLOCKed at the WAF, meaning none of it ever reached the application or the database.",
      fp_trap:
        "It's tempting to escalate any SQLi-signature WAF block as a potential attack, since that's the exact rule category behind Log Analysis 1's real finding. But the discriminators are context, not payload shape: a source IP that never rotates, a User-Agent that announces itself as scanning tooling instead of disguising it, a change record confirming authorization, and — the most important check — no downstream success at all, since every request in this burst was blocked, unlike Log Analysis 1's lone 200 that got through. Escalating every blocked SQLi signature without checking source stability, the User-Agent, and whether anything actually reached the database is exactly the over-alerting trap that buries a real finding like Log Analysis 1's under routine scanning noise.",
      xp: 30,
    },
    {
      type: "ordering",
      id: "web-o1",
      heading: "Order the Web Shell Attack Chain",
      instructions: "Arrange these events in the order a web shell compromise actually unfolds, from first probe to code execution.",
      items: [
        { id: "probe", text: "AWS WAF blocks a burst of malformed injection payloads against /search.aspx from a single external IP — the attacker calibrating what the application's SQL parser will accept" },
        { id: "success", text: "One request in that same burst returns sc-status 200 with a response body far larger than this endpoint's normal size — the payload that actually executed" },
        { id: "oversize-post", text: "A POST request to an upload-capable endpoint, from the same external IP, is allowed through the WAF after exceeding its body-inspection size limit" },
        { id: "file-write", text: "IIS's own worker process, w3wp.exe, is observed writing a new file, checkout-widget.min.aspx, into the site's assets directory" },
        { id: "shell-exec", text: "w3wp.exe spawns cmd.exe — a process a web worker should never parent" },
      ],
      correct_order: ["probe", "success", "oversize-post", "file-write", "shell-exec"],
      explanation:
        "This is the full arc from Reading 1 and Log Analysis 1/2 through to code execution: the WAF-blocked burst is the attacker calibrating their injection against the application's parser; the lone 200 with an oversized response is the moment one payload actually executed, most likely disclosing enough to enable the next stage; the oversized POST getting past the WAF's inspection limit is how a malicious file upload can slip through even a well-configured WAF; the file write by w3wp.exe itself (not an administrator, not a deployment tool) is the web shell landing on disk; and w3wp.exe parenting cmd.exe is that shell finally being used to execute commands.",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "web-qf1",
      heading: "Write It Yourself: Find a Web Worker Process Spawning a Shell",
      language: "kql",
      context: "Using the pattern from the last step of the attack chain you just ordered — w3wp.exe should never be the parent of a command interpreter — write the KQL a detection engineer would deploy against endpoint process telemetry to catch it.",
      template:
        "DeviceProcessEvents\n| where InitiatingProcessFileName =~ \"{{parent}}\"\n| where FileName in~ (\"{{child1}}\", \"{{child2}}\", \"{{child3}}\")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName",
      blanks: [
        { id: "parent", answers: ["w3wp.exe"], placeholder: "the IIS worker process" },
        { id: "child1", answers: ["cmd.exe", "powershell.exe"], placeholder: "a command interpreter a web worker should never spawn" },
        { id: "child2", answers: ["powershell.exe", "cmd.exe"], placeholder: "a second shell to watch for" },
        { id: "child3", answers: ["cscript.exe", "wscript.exe"], placeholder: "a scripting host to watch for" },
      ],
      explanation:
        "A web worker process spawning any command interpreter or scripting host — not just cmd.exe — is never expected in normal IIS operation, exactly the pattern the final item in this room's ordering task showed you. Filtering DeviceProcessEvents on InitiatingProcessFileName = w3wp.exe against a short list of shell/script hosts is a far more targeted detection than trying to catch the web shell's file write itself, since file names and paths are trivial for an attacker to vary while the parent-child relationship is not.",
      xp: 35,
    },
    {
      type: "flag",
      id: "web-f1",
      prompt: "Look at the ordering task's attack chain (Task o1). What is the exact filename of the web shell that w3wp.exe wrote into the site's assets directory? Enter it exactly as shown, including the extension.",
      answer: "checkout-widget.min.aspx",
      hint: "It's named to blend in with the site's other minified JavaScript assets — check the ordering item describing the file write, right before w3wp.exe spawns cmd.exe.",
      xp: 25,
    },
  ],
};

export const roomsBatch24 = [credentialAttacksRoom, lateralMovementRoom, webAttacksRoom];
