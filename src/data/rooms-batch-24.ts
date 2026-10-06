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
import { KQL_PRIMER } from "@/data/kqlPrimer";
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
      checkpoint: {
        question: "Why does credential dumping (T1003) never appear in a 4625 failed-logon burst?",
        options: [
          "Credential dumping requires the target account to have a registered SPN, so the resulting activity is logged as Event ID 4769 (Kerberos service ticket request), not 4625 -- a common mix-up with Kerberoasting",
          "It reads credential material directly from process memory or a disk-based store, so it never touches an authentication endpoint at all",
          "It only works against accounts with Kerberos pre-authentication disabled, so any resulting activity would surface as a 4768 AS-REQ, not a 4625",
          "Dumping tools authenticate using the harvested hash immediately afterward, and that Pass-the-Hash logon always succeeds, so the only event generated is a 4624, never a 4625",
        ],
        answer: 1,
        explanation:
          "Credential dumping is a different category entirely -- it reads credentials directly out of memory (classically lsass.exe) or a disk-based store, so there is no logon attempt at all to generate a 4625, successful or failed.",
      },
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
        "Status 0xC0000234        Account is LOCKED OUT (SubStatus 0x0)\n" +
        "Status 0xC000006E        Account restriction (valid creds, but...)\n" +
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
        "A 4625 burst against the same account shows SubStatus 0xC000006A (under Status 0xC000006D) for its first 30 attempts; every attempt after that instead logs Status 0xC0000234. What changed?",
      options: [
        "The attacker switched from guessing passwords to enumerating usernames, and the DC now reports the targeted names as nonexistent",
        "The account crossed its lockout threshold, so the DC now rejects further attempts because of account state rather than a wrong password",
        "The password was correct on attempt 31, but a logon restriction on the account (such as logon hours) made the DC refuse the session",
        "The DC began throttling the source host after repeated failures, so the new code describes the client rather than the targeted account",
      ],
      answer: 1,
      explanation:
        "0xC0000234 is specifically the account-locked-out status code (logged in the Status field, with SubStatus 0x0), not a username-guessing indicator, a success indicator, or a firewall signal — it only ever appears once the account's lockout threshold has actually been crossed, which is exactly why it appears only after attempt 30 rather than from the start. A genuine success would produce a 4624, not a further 4625; 0xC0000064 (not 0xC0000234) is the username-does-not-exist substatus; and this field describes the target account's own state, not the network layer.",
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
            "SubStatus stays 0xC000006A (wrong password) for all 47 attempts, and the Status never switches to 0xC0000234 (locked out). What does that specifically tell you, and why might it matter for how urgently this needs a response?",
          options: [
            "It proves the account was never actually at risk, since Windows automatically disables the TargetUserName field once 30 consecutive failures accumulate, which is why no lockout code ever appears in this burst",
            "The account's lockout threshold has not yet been crossed despite 47 attempts — meaning either the account has an unusually high lockout threshold (or a policy exemption), or the threshold simply hasn't been reached yet and the attack is still live and could still succeed",
            "0xC0000234 only appears for accounts protected by Credential Guard, so this confirms d.solano's account has virtualization-based security enabled rather than a standard lockout policy",
            "SubStatus values only describe the authentication package used (NTLM vs Kerberos), not the account's lockout state, so 0xC000006A persisting for 47 attempts is expected regardless of any lockout policy",
          ],
          answer: 1,
          explanation:
            "SubStatus 0xC000006A means the password was wrong on that specific attempt; the fact that the event never flips to Status 0xC0000234 (locked out) after 47 tries is itself informative — either d.solano's account is exempt from the org's normal lockout policy (worth checking) or the threshold simply hasn't been reached yet, meaning the attack is still actively running and could still land a correct guess. It says nothing about whether the account is privileged, and it certainly doesn't mean the account was never at risk.",
          xp: 25,
        },
        {
          question: "What is the correct next step?",
          options: [
            "No action needed — 47 failed attempts against a single account falls within Vantree's documented baseline for helpdesk-assisted password resets, so this is expected noise rather than a finding",
            "Block or rate-limit the source IP, check whether d.solano's account has an unnecessary lockout exemption, confirm no 4624 success followed this burst from the same source, and reach out to d.solano to confirm whether this was them locked out of a forgotten credential",
            "Immediately disable NTLM domain-wide, since NtLmSsp appearing in LogonProcessName means the credential material itself has already been compromised and cannot be trusted going forward",
            "Escalate as a confirmed password spray and begin resetting every account in the domain, since any burst of 4625 failures against a single TargetUserName value indicates the account population as a whole is under attack",
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
            "It's a coincidence and has no bearing on whether this is a spray — Windows caps how many 4625 events any single source IP can generate against a given account within a 20-minute window, which independently produces a ceiling of about 3",
            "Staying just under the lockout threshold on every single account is deliberate — it lets the attacker try a common password against the entire account population without ever triggering a lockout or a lockout-based alert, which is the entire point of spraying instead of brute forcing",
            "It proves the source IP has already been blocked by the domain's account lockout policy, which is why every account topped out at exactly 3 attempts before further traffic from 185.220.101.47 was silently dropped",
            "3 attempts is required by NTLM before a 4625 event is generated at all, so the first two failures against each account were simply never logged, and 3 is the earliest possible count that could ever appear",
          ],
          answer: 1,
          explanation:
            "Staying one attempt below the lockout threshold, consistently, across 142 different accounts, is not incidental — it's the defining discipline of a password spray, deliberately trading depth (many guesses against one account) for breadth (a few guesses against many accounts) specifically to avoid triggering lockout-based alerting. Lockout policy doesn't block source IPs, and NTLM doesn't require any minimum attempt count before logging a 4625 — a single failed attempt logs one immediately.",
          xp: 25,
        },
        {
          question: "What is the correct response, given this is a spray rather than a brute-force burst?",
          options: [
            "Reset only k.mensah's password, since that's the account shown in this record, and treat the other 141 accounts referenced in the SIEM correlation as a separate matter for whichever analyst happens to pick up that ticket next",
            "Block/rate-limit 185.220.101.47 at the perimeter, search specifically for any 4624 SUCCESS from that same source (a spray's entire goal is finding the one account with a weak or reused password), and treat any account with a matching success as compromised regardless of how few attempts it took",
            "No action needed — none of the 142 accounts were locked out, which under Vantree's policy means the attempted logons were rejected before ever being evaluated, so nothing about this burst could have succeeded",
            "Force an immediate domain-wide password reset for all 25,000 Vantree accounts as the only sufficient response, since a spray targeting 142 of them proves the attacker already holds valid credentials for the remaining accounts too",
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
        "Finding A, because 60 failures in 90 minutes is a sustained volume, and high total volume is what separates a spray from a short brute-force burst",
        "Finding B, because it spreads a few attempts across several accounts from one source; account breadth, not total volume, is the discriminator",
        "Finding A, because a slow, steady pace against one account is how a spray stays under the lockout threshold, whereas Finding B's fast burst is brute force",
        "Neither, because T1110.003 requires attempts across at least ten distinct accounts, and Finding B only touches six",
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
      context: KQL_PRIMER +
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
  description: "SRV-APP11 recorded a network logon from JMP-ITSUPPORT01 as sysmgr_svc at 11:20 on a weekday, followed by a new service installation.",
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
        `A realistic movement chain looks like this: a workstation is compromised first (through phishing, an exposed service, or stolen credentials); from there, the attacker authenticates outward to a first server, using the stolen account's genuine privileges to write to an administrative share and install a service; that new service becomes their execution point on the first server, from which they pivot again — often within minutes — to a second server, repeating the pattern. Each hop leaves its own, independently incomplete set of artefacts, and SIEM ingestion delay means those artefacts frequently do not arrive in your queue in the order they actually happened. Reconstructing the true order, from timestamps rather than arrival order or which alert fired loudest, is exactly what this room's ordering exercise will ask you to do. Timestamps need care too: one host's forwarder may stamp events in UTC while another sends local time with an offset, so convert every timestamp to UTC before comparing records across hosts.\n\n` +
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
      checkpoint: {
        question:
          "Per Reading 1, why can host B's logs never tell you, on their own, whether a network logon came from a legitimate admin tool or an attacker with stolen credentials?",
        options: [
          "An NTLM network logon omits the source workstation name and IP address, so host B has no record of where the session came from",
          "An NTLM network logon (LogonType 3) looks the same from an approved jump host as from an attacker holding stolen but valid credentials",
          "Approved admin tooling authenticates with Kerberos, so only a Kerberos logon on host B could be cleared without any outside evidence",
          "Host B records the inbound logon but not the actions that follow it, so what the visitor did next must come from host A's logs",
        ],
        answer: 1,
        explanation:
          "The mechanism is the same either way — host B's own 4624 can't distinguish source legitimacy; that answer has to come from the source host's history, a change ticket, or what happens immediately afterward. The 4624 does carry WorkstationName and IpAddress for an NTLM network logon, so host B knows where the session came from — just not whether that source should have been using the account. Legitimate tooling uses NTLM too (it depends on how the target is addressed), so a Kerberos logon would be no more self-clearing. And host B logs what happens after the logon (the service install in this room is a target-side record), so the follow-on actions do not have to come from host A.",
      },
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
        "Nothing is wrong: service creation over svcctl requires Domain Admins, the only group nested by default into every member server's local Administrators",
        "It proves only local administrator rights on SRV-FIL02, which can be granted narrowly, for example by a GPO scoping a support account to specific hosts",
        "ADMIN$ is writable by any authenticated domain user by default, so the install shows only that the account authenticated, not that it holds privilege",
        "The install needed SeDebugPrivilege, which local Administrators membership does not grant on its own, so the account must hold a higher domain-level role",
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
            "Yes — in a Kerberos domain, remote administration authenticates by Kerberos, so an NTLM network logon by an admin-capable account points to stolen credentials",
            "No — an NTLM network logon by an account with genuine local admin is also what routine remote administration looks like; this record alone can't separate the two",
            "Yes — sysmgr_svc is a service-type account, and a 4624 network logon by a service-type account is itself misuse, whatever host it originates from",
            "No — LogonType 3 records only a file-share connection, so without a LogonType 10 session there is no remote execution on SRV-FIL02 to investigate",
          ],
          answer: 1,
          explanation:
            "Reading 2's point applies directly: the mechanism sysmgr_svc just used is identical whether a legitimate support session or an attacker with stolen credentials triggered it. NTLM is not an intrusion marker — legitimate tools fall back to it routinely (for example when a target is addressed by IP), so the authentication package can't carry the verdict. sysmgr_svc is a support-tooling account whose whole job is network logons to the hosts it administers, so a 4624 from it is expected, not misuse in itself. And LogonType 3 is exactly the logon behind SMB/ADMIN$/svcctl remote execution (PsExec-style), so its presence does not rule execution out — LogonType 10 is RDP, a different technique.",
          xp: 25,
        },
        {
          question: "What one additional piece of evidence would most efficiently settle whether this is legitimate administration or an intrusion?",
          options: [
            "Whether WKS-SALES14 has a history as an admin source toward servers like SRV-FIL02, and whether a change ticket or support session covers this window",
            "Whether the GPO Restricted Groups policy actually scopes sysmgr_svc to SRV-FIL02, since that grant decides whether this logon was authorized",
            "Whether SRV-FIL02 logged 4625 failures for sysmgr_svc just before this success, since use of stolen credentials starts with failed guesses",
            "Whether the logon negotiated NTLM rather than Kerberos, since sanctioned tooling here would use Kerberos and NTLM suggests a pass-the-hash replay",
          ],
          answer: 0,
          explanation:
            "This is Reading 2's answer: the privilege itself won't tell you whether this specific use was authorized, so the discriminator has to come from the source host's history and any documented change — a designated jump host or an open ticket points toward legitimate administration, while a source with no such history, like WKS-SALES14 here, points toward compromise. Checking the GPO scope only re-confirms the privilege (the right to do it), which is exactly the question Reading 2 separates from authorization. Looking for preceding 4625s assumes guessing — an attacker holding valid stolen credentials logs on successfully the first time. And NTLM versus Kerberos is already visible in this record and does not distinguish legitimate tooling from misuse.",
          xp: 25,
        },
        {
          question: "WKS-SALES14 has no history of admin-source activity toward SRV-FIL02, and no change ticket exists for this timeframe. What should the analyst do?",
          options: [
            "Close as authorized: sysmgr_svc holds GPO-granted local admin on SRV-FIL02, and a successful logon shows the access was within its rights",
            "Treat it as likely credential misuse: investigate WKS-SALES14 as the probable compromise and trace what sysmgr_svc did next on SRV-FIL02",
            "Reset sysmgr_svc's password and close the case, since rotating the credential removes the attacker's access without any further tracing",
            "Escalate SRV-FIL02 for reimaging as the origin of the intrusion, since the session was recorded on that host and the activity started there",
          ],
          answer: 1,
          explanation:
            "Holding the right to do something is not the same as this specific use being authorized (Reading 2's core distinction) — with no source history and no ticket, the reasonable read is that sysmgr_svc's credentials are being used from a host that was never meant to originate this kind of session, so WKS-SALES14 is the likely point of compromise and needs its own investigation, while you trace forward what happened on SRV-FIL02. Closing because the account holds local admin repeats the privilege-equals-authorization error. Resetting the password and closing is containment without scoping: it leaves the compromised workstation and anything already done on SRV-FIL02 unexamined. And SRV-FIL02 is the target of this logon, not its origin — the 4624 records WKS-SALES14 as the source.",
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
            "That the service was started locally on SRV-FIL02, since a 7045 carries no source host or account, so it can't be tied to any network session",
            "That the session from WKS-SALES14 went beyond a connection: within half a minute a new service was created and started, matching ADMIN$/svcctl",
            "That PSEXESVC ran on WKS-SALES14, since a remotely created service executes on the workstation that requested it, not on the target",
            "That sysmgr_svc holds Domain Admin, since a remote service install right after a network logon needs domain-level rights on a member server",
          ],
          answer: 1,
          explanation:
            "Neither record alone tells the full story — Reading 1's whole point — but placed together, a network logon immediately followed by a new service on the same host is exactly the observable signature of the ADMIN$-write-then-svcctl-install mechanism from Reading 2, whether performed by legitimate tooling or an attacker. It's true the 7045 has no source fields, but that is precisely why you correlate by host, account context and time instead of concluding the install was local. The service runs where it was registered — computer_name is SRV-FIL02, not the workstation. And the install proves local admin on SRV-FIL02 only, not Domain Admin membership.",
          xp: 25,
        },
        {
          question: "ServiceName is 'PSEXESVC' and ImagePath is its literal, unmodified default value. Why is it common to see a tool's real default name here rather than something disguised?",
          options: [
            "PsExec offers no switch to change the service it registers, so every PsExec session, legitimate or not, leaves a service named PSEXESVC",
            "Operators often skip renaming default tools when moving fast — easy to spot if you know the default, easy to miss if you don't know it",
            "A default tool name points to sanctioned IT use, since attackers rename their tooling to evade detection before they deploy it on a target",
            "The Service Control Manager derives ServiceName from the binary's file name, so the installer had no chance to choose a different name",
          ],
          answer: 1,
          explanation:
            "PsExec's service name and path can be customized, but plenty of real intrusions simply don't bother — which is exactly why recognizing PSEXESVC.exe's default footprint is worth memorizing rather than assuming disguise. PsExec does support a custom service name, and ServiceName is whatever the creating program passes to the Service Control Manager, not something derived from the file name — so neither of the 'no choice' explanations holds. And the literal default proves nothing about legitimacy, since legitimate admins and attackers both use PsExec constantly, often without renaming it.",
          xp: 25,
        },
        {
          question:
            "This installation required local admin on SRV-FIL02, and sysmgr_svc genuinely holds that right. What does the install's success add to the AUTHORIZATION question — whether this use of sysmgr_svc, from WKS-SALES14, should have happened?",
          options: [
            "Nothing: success confirms a privilege you already knew of; authorization still rests on the source's history and the missing ticket",
            "It settles it as authorized, because Windows refuses an svcctl install from any account not permitted to administer SRV-FIL02",
            "It shows WKS-SALES14 is an approved admin source, because the GPO grant only lets sysmgr_svc install services from listed hosts",
            "It settles it as misuse, because a sanctioned support session would push an internal agent rather than PsExec's default service",
          ],
          answer: 0,
          explanation:
            "This is the distinction Reading 2 built toward: a successful ADMIN$/svcctl action confirms the privilege existed (which you already knew from sysmgr_svc's GPO-granted rights) but adds nothing to the separate question of whether this specific use, from this specific source, was authorized — that still depends on WKS-SALES14's history and the absence of a change ticket, from Log Analysis 1. (It does add evidence that execution happened — the first question here — just not evidence about authorization.) Windows checks permission, not authorization, so success cannot settle it as authorized. A Restricted Groups grant scopes which TARGET hosts the account administers, not which sources it may connect from. And legitimate admins use PsExec under its default name too, so the tool choice cannot settle it as misuse.",
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
        "The authentication package: intrusions fall back to NTLM, while legitimate remote administration inside the domain authenticates through Kerberos tickets",
        "Context outside the mechanism: the source host's role and history, whether a change ticket covers it, and whether the timing fits normal admin patterns",
        "The ServiceName field: malicious services use randomly generated or obfuscated names, while legitimate deployment tools register a fixed, predictable name",
        "The LogonType value: intrusions authenticate with LogonType 10 (RemoteInteractive), while legitimate remote administration uses LogonType 3 (Network)",
      ],
      answer: 1,
      explanation:
        "This is the throughline of Reading 2 and Log Analysis 1/2: the mechanism is identical for legitimate remote administration and for an attacker using stolen but genuinely privileged credentials, so the verdict has to come from context that lives outside that mechanism — source host history, tickets, and timing. ServiceName, LogonType and the authentication package don't reliably differ between the two cases at all, since both legitimate tooling and attackers commonly use the same defaults, the same LogonType 3, and NTLM or Kerberos depending only on how the target was addressed.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "lat-ac1",
      heading: "Verdict: The Same Mechanism From the Designated Jump Host",
      scenario:
        "A detection rule fired on IPC$/svcctl access followed by a new service installation, this time on SRV-APP11, originating from JMP-ITSUPPORT01 and again using sysmgr_svc — the same account as the SRV-FIL02 chain. Review the record, its source and timing, and the IT verification note attached to it, then decide.",
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
      instructions: "Your SIEM received these six records out of arrival order, and Kestrel's forwarders don't stamp time the same way: SRV-FIL02 sends UTC, while WKS-SALES14 and SRV-APP09 send local time with an offset. Arrange the records in the order they actually happened.",
      items: [
        { id: "wks-logon", text: "WKS-SALES14, 05:14 local (UTC+03:00) — sysmgr_svc's credentials are used to open a session on this sales workstation, which has never initiated administrative activity before" },
        { id: "fil-4624", text: "SRV-FIL02, 02:19:44 UTC — a network logon (LogonType 3, NtLmSsp) from WKS-SALES14 authenticates as sysmgr_svc" },
        { id: "fil-7045", text: "SRV-FIL02, 02:20:11 UTC — a new service, PSEXESVC, is registered and started through svcctl" },
        { id: "fil-outbound", text: "SRV-FIL02, 02:31 UTC — the PSEXESVC process opens an outbound connection toward SRV-APP09" },
        { id: "app-4624", text: "SRV-APP09, 05:32 local (UTC+03:00) — a network logon (LogonType 3) from SRV-FIL02 authenticates as sysmgr_svc, followed by its own ADMIN$/service-install sequence" },
        { id: "app-lsass", text: "SRV-APP09, 05:41 local (UTC+03:00) — a process launched by the newly installed service briefly opens lsass.exe with memory-read access" },
      ],
      correct_order: ["wks-logon", "fil-4624", "fil-7045", "fil-outbound", "app-4624", "app-lsass"],
      explanation:
        "Normalized to UTC (subtract three hours from the local stamps: 05:14 → 02:14, 05:32 → 02:32, 05:41 → 02:41), the chain reads exactly as Reading 1 described, and causality agrees at every step: the credentials are in use on the workstation first, then the first hop's logon-then-service-install pair (the same two records from Log Analysis 1 and 2 — the service can only be installed through an authenticated session), then the pivot outbound from that new service, then the second hop repeating the logon-then-install pattern, and finally credential access by a process the second hop's service launched. Sorting the raw clock values instead would have put all three SRV-FIL02 records ahead of the workstation compromise that made them possible — the mixed-time-zone trap this exercise is built to catch.",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "lat-qf1",
      heading: "Write It Yourself: Correlate a Network Logon With a Following Service Install",
      language: "kql",
      context: KQL_PRIMER + "**For this query you also need:** `let` names a value for reuse (here, a list of approved admin-source IPs); `x in (list)` is true when x is in the list and `x !in (list)` when it is not (`in~` / `!in~` ignore case); `join kind=inner (...) on Computer` keeps only rows whose Computer appears on both sides; and a time gap is written as a timespan literal such as `2min` or `90s`, tested with `between (0min .. 2min)`.\n\nUsing the pattern confirmed in Log Analysis 1 and 2 — an NTLM network logon immediately followed by a new service on the same host — write the KQL that flags this sequence whenever the logon came from a source NOT on the approved admin-source allowlist (JMP-ITSUPPORT01 is 10.60.1.9). Keep the logon-to-install window between one and five minutes. Note that Windows writes LogonProcessName for NTLM with a trailing space, which is why the template matches it with `has` rather than `==`.",
      template:
        "let AdminSources = dynamic([\"10.60.1.9\"]);\nSecurityEvent\n| where EventID == {{logonid}} and LogonType == {{logontype}} and LogonProcessName has \"{{logonproc}}\"\n| where IpAddress {{allowop}} (AdminSources)\n| project Computer, Account = TargetUserName, SourceIp = IpAddress, LogonTime = TimeGenerated\n| join kind=inner (\n    Event\n    | where EventLog == \"System\" and EventID == {{svcid}}\n    | project Computer, InstallTime = TimeGenerated\n) on Computer\n| where InstallTime - LogonTime between (0min .. {{window}})",
      blanks: [
        { id: "logonid", answers: ["4624"], placeholder: "successful logon Event ID" },
        { id: "logontype", answers: ["3"], placeholder: "LogonType number for a network logon" },
        { id: "logonproc", answers: ["NtLmSsp"], placeholder: "LogonProcessName value for an NTLM network logon" },
        { id: "allowop", answers: ["!in", "!in~"], placeholder: "operator: source NOT in the allowlist" },
        { id: "svcid", answers: ["7045"], placeholder: "new service installed Event ID (System log)" },
        {
          id: "window",
          answers: [
            "1min", "2min", "3min", "4min", "5min",
            "1m", "2m", "3m", "4m", "5m",
            "1minute", "2minutes", "3minutes", "4minutes", "5minutes",
            "60s", "90s", "120s", "180s", "240s", "300s",
            "60sec", "90sec", "120sec", "180sec", "240sec", "300sec",
          ],
          placeholder: "max logon-to-install gap (1-5 minutes)",
        },
      ],
      explanation:
        "This operationalizes exactly the correlation you did by hand in Log Analysis 1 and 2: join a network logon (4624, LogonType 3, NTLM) on one host to a service installation on the SAME host within a tight window, and drop sources on the admin allowlist with `!in` — the same context check Reading 2 calls for, which is what separates SRV-APP11's deployment from the jump host (10.60.1.9, filtered out) from WKS-SALES14's unexplained session (kept). Using `in` instead would invert the rule and alert only on the sanctioned jump host. Note the two different tables: the 4624 logon lives in the Security log (Sentinel's SecurityEvent table), but 7045 is written by the Service Control Manager to the System log, which Sentinel stores in the Event table — querying SecurityEvent for 7045 returns nothing. (The Security-log equivalent of a service install is Event ID 4697, which requires 'Audit Security System Extension' to be enabled.) Any window from one to five minutes catches the 27-second gap seen on SRV-FIL02 while staying tight enough to avoid joining unrelated logons.",
      xp: 35,
    },
    {
      type: "flag",
      id: "lat-f1",
      // Pin the logon record: the service record itself carries no source fields,
      // so the student has to pivot to the session that caused the install.
      event: kestrelLogonEvent,
      prompt: "The firewall team wants to isolate the machine that opened the session which installed PSEXESVC on SRV-FIL02, but their console accepts IP addresses only. Using the record shown, enter that machine's IP address.",
      answer: "10.60.14.22",
      hint: "The 7045 has no source fields — the session that caused it is the network logon on the same host seconds earlier. Find the field in that logon that records where the connection came from.",
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
      timestamp: 1780974760900,
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
    "AWS WAF blocked a SQL injection payload from 64.39.106.190. Representative of a sustained burst from this single address across many parameters and endpoints, all carrying the same User-Agent.",
  raw: {
    formatVersion: 1,
    timestamp: 1781431327000,
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
  prerequisites: ["networking-protocols", "web-application-security"],
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
        `A 4xx status (404 Not Found, 403 Forbidden) means the server understood the request and refused or couldn't fulfill it — content discovery sweeps and blocked injection attempts both live here. A 5xx status, especially 500 Internal Server Error, means the application itself broke while trying to process the request — and for a SQL injection attempt specifically, a 500 very often means the malformed SQL syntax the attacker sent caused the database driver to throw an unhandled exception, which the application couldn't recover from. That's a critical, counter-intuitive point: a 500 in the middle of an injection attempt means the payload REACHED the SQL parser unsanitized and broke the query — strong evidence the parameter IS injectable, even though that particular request usually returned nothing useful. (Watch the exception: in error-based SQLi the attacker deliberately triggers 500s whose error body leaks data, so check sc-bytes on the 500s too. And blind/time-based SQLi returns ordinary 200s, where the tell is time-taken or a response-size flip rather than the status code.) A 200 OK, by contrast, means the request was processed successfully end to end. In the middle of a calibration burst against a search endpoint, a lone 200 sitting among dozens of 500s is not the boring result — it's the one attempt whose SQL syntax was valid enough to actually execute.\n\n` +
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
      checkpoint: {
        question:
          "Per Reading 2, why does a web server's own access log typically show the load balancer's IP instead of the real client's IP?",
        options: [
          "The load balancer opens its own connection to the server, so c-ip is the balancer's address unless X-Forwarded-For is captured",
          "IIS logs the X-Forwarded-For value as c-ip by default, and the load balancer overwrites that header with its own address",
          "The WAF rewrites each request's source to its own address before forwarding, so IIS records the WAF's IP rather than the client's",
          "IIS fills c-ip from a reverse-DNS lookup of the connection, and internal DNS resolves every caller to the load balancer's name",
        ],
        answer: 0,
        explanation:
          "The load balancer re-establishes its own connection to the web server, so unless X-Forwarded-For is specifically configured and captured, the web server's log shows the load balancer's own address for every request, regardless of the real source. IIS does not put X-Forwarded-For into c-ip by default — capturing it takes deliberate configuration, and the load balancer appends to that header rather than replacing the client. The address IIS sees belongs to the load balancer that opened the connection, not the WAF. And c-ip is the TCP peer's IP address, not the result of a DNS lookup.",
      },
    },
    {
      type: "question",
      id: "web-q1",
      question:
        "An access log shows a burst of 40 requests to /search.aspx?q=... from one source in two minutes: 37 return sc-status 500, and 3 return sc-status 200. Status codes alone can't tell you whether those 200s are UNION payloads that executed or harmless requests that got a normal page. Which check most directly separates the two?",
      options: [
        "Confirm the WAF logged ALLOW for those three requests, since an injection payload the WAF lets through to the application is one that executed",
        "Compare the 200s' sc-bytes with this endpoint's normal response size, since an executed UNION returns far more data than a real search",
        "Confirm the three 200s share a source IP with the 37 500s, since a shared source shows the 200s were the same tool's working payloads",
        "Check sc-substatus and sc-win32-status on the 200s, since a non-zero value there marks a request whose SQL statement actually ran",
      ],
      answer: 1,
      explanation:
        "Reading 1's response-size point: a 200 only says the request completed, so what separates an executed UNION from a harmless page is sc-bytes against the endpoint's baseline — tens of kilobytes where a real search returns a few. (For blind/time-based payloads the equivalent tell is time-taken.) A WAF ALLOW means only that no rule blocked the request; the 37 requests that crashed with 500s were allowed too. A shared source shows the same actor, not that any particular request worked — a tool interleaving control searches would share it as well. And sc-substatus / sc-win32-status describe IIS's own handling of the request, not whether the application's SQL executed.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "web-la1",
      heading: "One 200 Among a Wall of 500s",
      context:
        "Orbitline's WAF allowed 40 requests to /search.aspx from 91.203.44.187 within a two-minute window, and the IIS log on the web server shows the outcome: 37 returned sc-status 500, and 3 returned sc-status 200. This endpoint's normal response for a real search term is roughly 2,000-3,000 bytes. Review the record below — the third and final 200 in that burst.",
      event: orbitlineInjectionEvent,
      questions: [
        {
          question:
            "scStatus here is 200 and scBytes is 48,231 — against a baseline of roughly 2,000-3,000 bytes for a normal search result on this endpoint. Combined with the fact that 37 of the 40 requests in this burst returned 500, what does this specific record most likely represent?",
          options: [
            "A legitimate search that matched many products, since a broad search term can return a result page in the tens of kilobytes",
            "A payload whose SQL syntax was valid enough to execute, returning far more rows than a real search — a UNION-based extraction",
            "Error-based injection: the database error text in the body leaks data, which is why this response is far larger than baseline",
            "Time-based blind injection: the 812 ms TimeTaken shows the database was made to pause, confirming the parameter executes SQL",
          ],
          answer: 1,
          explanation:
            "A response roughly 16-24x this endpoint's normal size, on a 200 inside a burst where nearly everything else failed, carrying a UNION SELECT in csUriQuery, is the signature of a UNION-based injection that executed and pulled back extra rows. A legitimate broad search doesn't fit: the query string is an injection payload, not a product term, and the baseline for real searches is 2-3 KB. Error-based injection leaks data through 500 error pages — this response is a 200. And time-based blind injection needs a delay payload (a SLEEP/WAITFOR) and returns normal-sized pages; this payload has no delay and 812 ms is unremarkable, while the size jump is the tell here.",
          xp: 25,
        },
        {
          question: "csUriQuery contains a UNION SELECT payload targeting a users table. Does the presence of that payload text, by itself, prove the injection succeeded?",
          options: [
            "Yes — the WAF allowed this request through, and an allowed UNION payload that reaches IIS is one the database went on to execute",
            "No — the query string shows what was attempted; scStatus and scBytes are what show whether it executed and returned data",
            "No — the payload is still URL-encoded (%27), so the application received a literal %27 and the quote never broke out of the string",
            "Yes — naming the users table and its username and password columns shows the attacker knew the schema, so the query must have run",
          ],
          answer: 1,
          explanation:
            "This is Reading 1's central point: the query string tells you intent, not outcome. The 37 failed attempts in this same burst were also allowed by the WAF and carried similar payload text, yet crashed on syntax — so neither the WAF's ALLOW nor the payload's presence separates the one that worked; the status and size do. IIS logs the query string as it arrived on the wire, still percent-encoded, but the application decodes it before use, so %27 reaches the code as a real quote. And guessing table and column names like users/username/password is a standard first attempt — naming them shows intent, not knowledge or success.",
          xp: 25,
        },
        {
          question: "What is the appropriate next step given this finding?",
          options: [
            "Block 91.203.44.187 at the WAF and close the case, since once the source is cut off the attacker can no longer reach the application",
            "Treat it as a successful injection: pull the database audit log for this window to scope what was read, and contain the source",
            "Force a password reset for every account now, since a SELECT against the users table means every stored credential is exposed",
            "Fix /search.aspx with parameterized queries first, and decide whether to escalate once the patched page is deployed to production",
          ],
          answer: 1,
          explanation:
            "The evidence points to actual data exposure, not an attempted-and-failed request like the other 37 — that calls for pulling the database's own audit trail to scope exactly what the query returned, alongside containing the source. Blocking the IP and closing is containment without scoping: the data already read is still unknown, and the attacker can return from another address. A site-wide reset may follow, but deciding it before the audit shows what rows and columns were actually returned is acting ahead of scope. And fixing the code first is the right remediation at the wrong time — escalation and scoping of a confirmed breach cannot wait for a deployment.",
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
            "91.203.44.187: the WAF evaluates the request as it arrived from the internet, while 10.12.4.9 is the internal ALB that connected to IIS",
            "10.12.4.9: IIS logs the TCP peer that actually connected to it, so its cIP is the address that sent the request to the application",
            "Both: 10.12.4.9 is the attacker's private address behind their NAT, and 91.203.44.187 is the public address their traffic exits from",
            "Neither: the WAF's clientIp is copied from the client-supplied X-Forwarded-For header, so the real source can't be established here",
          ],
          answer: 0,
          explanation:
            "This is Reading 2's core mechanism: the WAF records the real client's address, while everything downstream (the load balancer, then IIS) sees a re-established connection using the load balancer's own address — Orbitline's ALB, as the WAF record's httpSourceName/httpSourceId show. IIS does log the TCP peer, but that peer is the ALB, not the sender. 10.12.4.9 is in Orbitline's own internal range (the same 10.12.4.x subnet as the web server, sIP 10.12.4.30) — an attacker's private NAT address would never appear in your logs. And AWS WAF's httpRequest.clientIp is the connecting client's address as seen at the edge, not a value read from a header.",
          xp: 25,
        },
        {
          question: "If an analyst tried to build a source-IP block list purely from IIS's own cIP field across many requests, what would go wrong?",
          options: [
            "Nothing, provided the list is built only from requests carrying injection payloads, since filtering by payload isolates the attacker",
            "Every proxied request shows the same internal address, 10.12.4.9, so the list would target Orbitline's own ALB rather than an attacker",
            "The list would hold the attacker's NAT-translated private address, which has to be mapped back to its public IP before it can be used",
            "The list would be accurate but slow, since cIP is correct and the only problem is that IIS logs reach the SIEM minutes after the WAF's",
          ],
          answer: 1,
          explanation:
            "Reading 2's central warning: because every request passes through the same load balancer, IIS's cIP field shows the same internal address for legitimate and malicious traffic alike, so it cannot support source attribution by itself. Filtering to payload-bearing requests doesn't help — those requests show 10.12.4.9 too, so the list would still name the ALB. 10.12.4.9 is not the attacker's NAT address; it is Orbitline's own load balancer, and there is nothing to map back from it. And cIP is not 'correct but late' — ingestion lag is not the problem; the value itself never identifies the client.",
          xp: 25,
        },
        {
          question: "Both records now confirm 91.203.44.187 as the true source of the successful injection from Log Analysis 1. What should the analyst do with this IP specifically?",
          options: [
            "Add it to IIS IP Address and Domain Restrictions on WEB-ORB03, since IIS is the server that processed the injected query",
            "Block it at the WAF, the one layer that sees this address, and search WAF logs for the same clientIp across the incident window",
            "Block it at the WAF and close the case, since the confirmed request is the full extent of what this address sent to Orbitline",
            "Search the IIS logs for cIP 91.203.44.187 to find its other requests, then decide at which layer the block should be applied",
          ],
          answer: 1,
          explanation:
            "Since the web server never sees the real client address, blocking has to happen at the WAF — the only point in the chain that can match on 91.203.44.187 — and the same clientIp should be searched across the broader window to find this actor's other requests. An IIS IP restriction would never match: IIS only ever sees 10.12.4.9. Blocking and closing skips scoping — this address sent a 40-request burst, and possibly more outside it. And searching IIS logs for 91.203.44.187 returns nothing for the same reason, so the scoping search has to run on the WAF logs.",
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
        "The request rate: authorized scanners throttle to a fixed requests-per-second, while attacker traffic arrives in irregular bursts visible in the timestamps alone",
        "A stable source IP, self-identifying User-Agent and covering change record versus a rotating source range, a browser or scripting User-Agent, and no change record",
        "The terminatingRuleId: scans trip generic rate-based rules while real attacks trip the managed SQLi rule group, so the rule that ended the request names the actor",
        "The source country in the WAF record: authorized scanners originate from the organization's own region, while real attackers come from foreign ASNs",
      ],
      answer: 1,
      explanation:
        "Payload shape alone is exactly what makes these look identical — the real discriminators: a scanner is typically one stable, unchanging source IP, often with a self-identifying User-Agent (many scanning tools announce themselves), backed by a documented change record covering the window; a real attacker's probing more often rotates source addresses, uses generic or scripted User-Agents, and has no matching authorization on file. Request rate doesn't separate them — scanners and attack tools are both configurable, and both can run steady or bursty. The terminatingRuleId won't either: an authorized scan sends real SQLi payloads, so it trips the same managed SQLi rule group a real attack does — that's the point of running it. And source country is no discriminator: commercial scanners run from their vendor's cloud ranges, often abroad, while attackers frequently route through infrastructure in the target's own region.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "web-ac1",
      heading: "Verdict: A Scheduled Vulnerability Scan Firing the Same Signatures",
      scenario: "AWS WAF blocked a sustained burst of SQL injection payloads against multiple Orbitline endpoints from a single source. Review the record below together with the IT verification note attached to it (the change-record lookup for this source and window), then decide.",
      event: orbitlineScanEvent,
      correct_verdict: "false_positive",
      explanation:
        "Every payload here matches the same managed SQLi signature set a real attack would trigger — which is exactly why the discriminators from Question 2 matter: 64.39.106.190 is a single, stable source inside the documented Qualys scanner range, the User-Agent self-identifies as the scanning tool rather than disguising itself, a confirmed change record covers this exact window, and — critically — nothing in this burst resembles Log Analysis 1's pattern (a 200 with an anomalous response size); every request here was BLOCKed at the WAF, meaning none of it ever reached the application or the database.",
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
        { id: "probe", text: "A burst of malformed injection payloads against /search.aspx from a single external IP passes through AWS WAF (logged ALLOW) and hits the application — the attacker calibrating what the application's SQL parser will accept" },
        { id: "success", text: "One request in that same burst returns sc-status 200 with a response body far larger than this endpoint's normal size — the payload that actually executed" },
        { id: "oversize-post", text: "A POST request to an upload-capable endpoint, from the same external IP, is allowed through the WAF after exceeding its body-inspection size limit" },
        { id: "file-write", text: "IIS's own worker process, w3wp.exe, is observed writing a new file, checkout-widget.min.aspx, into the site's assets directory" },
        { id: "shell-exec", text: "w3wp.exe spawns cmd.exe — a process a web worker should never parent" },
      ],
      correct_order: ["probe", "success", "oversize-post", "file-write", "shell-exec"],
      explanation:
        "This is the full arc from Reading 1 and Log Analysis 1/2 through to code execution: the burst the WAF allowed through to the application is the attacker calibrating their injection against the application's parser; the lone 200 with an oversized response is the moment one payload actually executed, most likely disclosing enough to enable the next stage; the oversized POST getting past the WAF's inspection limit is how a malicious file upload can slip through even a well-configured WAF; the file write by w3wp.exe itself (not an administrator, not a deployment tool) is the web shell landing on disk; and w3wp.exe parenting cmd.exe is that shell finally being used to execute commands.",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "web-qf1",
      heading: "Write It Yourself: Find a Web Worker Process Spawning a Shell",
      language: "kql",
      context: KQL_PRIMER + "Using the pattern from the last step of the attack chain you just ordered — w3wp.exe should never be the parent of a command interpreter — write the KQL a detection engineer would deploy against endpoint process telemetry to catch it.",
      template:
        "DeviceProcessEvents\n| where InitiatingProcessFileName =~ \"{{parent}}\"\n| where FileName in~ (\"{{child1}}\", \"{{child2}}\", \"{{child3}}\")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName",
      blanks: [
        { id: "parent", answers: ["w3wp.exe"], placeholder: "the IIS worker process" },
        { id: "child1", answers: ["cmd.exe", "powershell.exe", "pwsh.exe"], placeholder: "a command interpreter a web worker should never spawn" },
        { id: "child2", answers: ["powershell.exe", "pwsh.exe", "cmd.exe"], placeholder: "a second shell to watch for" },
        {
          id: "child3",
          answers: [
            "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
            "certutil.exe", "bitsadmin.exe", "whoami.exe", "net.exe", "net1.exe",
            "cmd.exe", "powershell.exe", "pwsh.exe",
          ],
          placeholder: "a script host or living-off-the-land binary to watch for",
        },
      ],
      explanation:
        "A web worker process spawning any command interpreter, scripting host or living-off-the-land binary (mshta, rundll32, certutil, whoami, net and the like) is never expected in normal IIS operation, exactly the pattern the final item in this room's ordering task showed you. Any of those is a correct entry, as long as each blank names a different binary. Filtering DeviceProcessEvents on InitiatingProcessFileName = w3wp.exe against a short list of shell/script hosts is a far more targeted detection than trying to catch the web shell's file write itself, since file names and paths are trivial for an attacker to vary while the parent-child relationship is not.",
      xp: 35,
    },
    {
      type: "flag",
      id: "web-f1",
      // Pin the correlated WAF+IIS record: the answer is derived from the WAF half
      // (httpSourceId), not copied from any stem.
      event: orbitlineCorrelationEvent,
      prompt: "IIS's cIP for the successful injection points at Orbitline's own load balancer, not the attacker. The WAF half of this correlated record identifies which load balancer handed it the request. Enter that load balancer's name as AWS records it — the name only, without the type prefix or the trailing ID.",
      answer: "orbitline-prod-alb",
      hint: "One WAF field says what kind of resource the request came through; another gives that resource's full identifier, in the form type/name/id.",
      xp: 25,
    },
  ],
};

export const roomsBatch24 = [credentialAttacksRoom, lateralMovementRoom, webAttacksRoom];
