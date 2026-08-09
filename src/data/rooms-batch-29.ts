/**
 * Learning Rooms — Batch 29
 *
 * Two rooms requested directly by the platform owner, covering the two halves
 * of "what an analyst actually does after the alert fires": running a
 * structured investigation, and writing up what was found so it holds up.
 *
 * Rooms in this batch:
 *  1. investigate-alert-workflow     — the 7-step analyst investigation
 *                                      workflow (validate, scope, collect &
 *                                      preserve, reconstruct timeline, map to
 *                                      ATT&CK + root cause, document, report
 *                                      & hand off), built on a single running
 *                                      case: a phishing-driven lateral
 *                                      movement and data-staging intrusion at
 *                                      a fictional insurer, Castleton
 *                                      Underwriting.
 *  2. incident-report-writing        — how to write the report that comes out
 *                                      the other end: two audiences (exec
 *                                      summary vs technical deep-dive),
 *                                      section anatomy, IOC extraction,
 *                                      contemporaneous documentation and
 *                                      defensibility, root cause vs vague
 *                                      hand-waving. Built on a second running
 *                                      case at a fictional actuarial firm,
 *                                      Solstice Actuarial Partners.
 *
 * Design constraint honoured throughout: no raw log field states a verdict.
 * Suspicion is carried by observable facts (an admin account authenticating
 * from a workstation it never uses, a compression utility invoked from a
 * PowerShell child process, zero failed sign-ins behind a set of first-time
 * successes) — never by a field or value that announces itself as malicious.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM 1 — The 7-Step Analyst Investigation Workflow
// ===========================================================================

// ---------------------------------------------------------------------------
// Event 1 — Step 1/Validate. Macro-spawned PowerShell on the entry host.
// ---------------------------------------------------------------------------

const inv7ValidateEvent: TelemetryEvent = {
  id: "evt-inv7-la1-001",
  ts: "2026-04-09T14:12:07.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "process_create",
  severity: "high",
  hostname: "WKS-FIN07",
  user_email: "j.alvarez@castleton-underwriting.com",
  mitre_technique: "T1059.001",
  mitre_tactic: "Execution",
  process: {
    name: "powershell.exe",
    pid: 6820,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "WINWORD.EXE",
    parent_pid: 4412,
    cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...",
    user: "CASTLETON\\j.alvarez",
    integrity: "medium",
    hash: { sha256: "9f4c2b7e1a6d8f3c5b0a9e7d4f1c8b6a3e5d7f9c1b4a6e8d0f2c4b6a8e0d1f3c", md5: "b17ef6d19c7a5fc5335c81f4bde96d20" },
  },
  description:
    "Microsoft Defender for Endpoint recorded a PowerShell process launched by WINWORD.EXE on WKS-FIN07 under j.alvarez's logon session, with a base64-encoded command-line argument. A correlation rule opened ticket INC-51204 on this record.",
  raw: {
    "DeviceName": "WKS-FIN07",
    "DeviceId": "a13f9e0c-2b71-4e3a-8f5d-1c9e6b420a37",
    "ActionType": "ProcessCreated",
    "FileName": "powershell.exe",
    "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "SHA256": "9f4c2b7e1a6d8f3c5b0a9e7d4f1c8b6a3e5d7f9c1b4a6e8d0f2c4b6a8e0d1f3c",
    "MD5": "b17ef6d19c7a5fc5335c81f4bde96d20",
    "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...",
    "AccountDomain": "CASTLETON",
    "AccountName": "j.alvarez",
    "AccountSid": "S-1-5-21-2853671940-3225465817-1594226315-1147",
    "ProcessId": 6820,
    "ParentProcessId": 4412,
    "ParentProcessFileName": "WINWORD.EXE",
    "ParentProcessCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\j.alvarez\\Downloads\\Q3_Vendor_Statement.docm\"",
    "InitiatingProcessFileName": "WINWORD.EXE",
    "InitiatingProcessCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\j.alvarez\\Downloads\\Q3_Vendor_Statement.docm\"",
    "ReportId": 84213,
  },
};

// ---------------------------------------------------------------------------
// Event 2 — Step 2/Scope. Lateral logon by a privileged account onto a second
// host, sourced from the already-compromised workstation.
// ---------------------------------------------------------------------------

const inv7ScopeEvent: TelemetryEvent = {
  id: "evt-inv7-la2-001",
  ts: "2026-04-09T15:04:51.000Z",
  source: "windows_security",
  vendor: "Microsoft Windows Security Auditing",
  event_type: "auth_success",
  severity: "high",
  hostname: "FIN-DB02",
  mitre_technique: "T1021.002",
  mitre_tactic: "Lateral Movement",
  authentication: { method: "NTLM", result: "Success", logon_type: 3 },
  description:
    "The Security event log on FIN-DB02 recorded EventID 4624 for CASTLETON\\d.reyes, a network logon originating from WKS-FIN07, 52 minutes after the PowerShell process on that same workstation.",
  raw: {
    "EventID": "4624",
    "Computer": "FIN-DB02.castleton.local",
    "SubjectUserName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "TargetUserName": "d.reyes",
    "TargetDomainName": "CASTLETON",
    "TargetLogonId": "0x3ac9f21",
    "LogonType": "3",
    "LogonProcessName": "NtLmSsp",
    "AuthenticationPackageName": "NTLM",
    "WorkstationName": "WKS-FIN07",
    "IpAddress": "10.14.6.52",
    "IpPort": "51322",
    "ProcessName": "-",
    "KeyLength": "128",
  },
};

// ---------------------------------------------------------------------------
// Event 3 — Collection artefact on the second host: an archive utility,
// invoked from a PowerShell child process, staging finance export files.
// ---------------------------------------------------------------------------

const inv7CollectionEvent: TelemetryEvent = {
  id: "evt-inv7-ac1-001",
  ts: "2026-04-09T15:41:19.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "file_create",
  severity: "high",
  hostname: "FIN-DB02",
  mitre_technique: "T1560.001",
  mitre_tactic: "Collection",
  file: {
    name: "AP_Reconciliation_Q3.rar",
    path: "C:\\ProgramData\\Intel\\Logs\\AP_Reconciliation_Q3.rar",
    sha256: "c2a97e4f1b6d8a3c5e0f9b7d4a1c6e8f3b5d7a9c1e4f6b8d0a2c5e7f9b1d3a6c",
    size: 184320411,
    extension: "rar",
  },
  description:
    "Microsoft Defender for Endpoint recorded a new archive file created on FIN-DB02 under CASTLETON\\d.reyes's session, written by a PowerShell child process invoking a compression utility against a folder of finance export files.",
  raw: {
    "DeviceName": "FIN-DB02",
    "ActionType": "FileCreated",
    "FileName": "AP_Reconciliation_Q3.rar",
    "FolderPath": "C:\\ProgramData\\Intel\\Logs\\",
    "SHA256": "c2a97e4f1b6d8a3c5e0f9b7d4a1c6e8f3b5d7a9c1e4f6b8d0a2c5e7f9b1d3a6c",
    "FileSize": 184320411,
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessCommandLine": "powershell.exe -nop -w hidden -Command \"& 'C:\\ProgramData\\Intel\\rar.exe' a -r C:\\ProgramData\\Intel\\Logs\\AP_Reconciliation_Q3.rar D:\\Finance\\AP_Exports\\*.csv\"",
    "AccountDomain": "CASTLETON",
    "AccountName": "d.reyes",
    "ReportId": 84391,
  },
};

const investigateAlertRoom: Room = {
  id: "investigate-alert-workflow",
  title: "How to Investigate an Alert — The 7-Step Analyst Workflow",
  description:
    "A repeatable, defensible sequence for what to actually do once an alert lands in your queue: validate, scope, collect and preserve, reconstruct the timeline, map to ATT&CK and find root cause, document, and report and hand off. Built on one running case — a macro-spawned PowerShell process at Castleton Underwriting that becomes lateral movement onto a finance database server and a staged archive of export files — using real Microsoft Defender for Endpoint and Windows Security fields throughout, with no field anywhere that hands you the verdict.",
  difficulty: "intermediate",
  category: "Incident Response",
  estimatedMinutes: 55,
  xp: 435,
  icon: "🔎",
  prerequisites: ["alert-triage", "investigation-methodology"],
  tasks: [
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "inv7-r1",
      heading: "Why Investigations Need a Workflow, and Why the First 15 Minutes Matter",
      content:
        `An alert triggers hundreds of times a day across a mid-sized environment, and every single one of them could, in principle, be the start of a real intrusion. An analyst who approaches each one by improvising — reading a bit, clicking around, following whatever looks interesting — will handle some of them well and quietly miss others, and there is no way to tell in advance which is which. A workflow exists to remove that gamble. It is the same reason an emergency room runs triage the same way for every patient regardless of who is on shift, and the same reason a detective's casework follows a known sequence rather than chasing whichever lead feels most exciting first: a repeatable process catches what improvisation misses, and it produces a record of what was checked, not just a feeling that something was checked.\n\n` +
        `**The seven steps, named once up front.** This room teaches them as: (1) Validate — is this real, or a detection artefact? (2) Scope — how far does it actually go, and who and what does it touch? (3) Collect and preserve — gather evidence in the right order, before anything changes state. (4) Reconstruct the timeline — merge every source into one chronological story. (5) Map to ATT&CK and find root cause — classify what happened and ask why it was possible. (6) Document — write it down as you go, not afterward. (7) Report and hand off — package the finding for whoever acts on it next. This is the SANS/NIST-aligned model most mature SOCs run in some form, and it is worth learning by name because the name is what lets you and a colleague talk about "where are we" in a shared vocabulary instead of a shared vibe.\n\n` +
        `**Why the first 15 minutes disproportionately matter.** Step 1 and the start of Step 2 happen fast, under pressure, often before you have full context — and whatever you get wrong there tends to compound. Validate an artefact as real without checking, and you burn hours investigating nothing. Scope too narrowly at the start, and you close a ticket while the actual intrusion is still running one host over. This is not a reason to rush; it is the opposite. It is the reason the early steps are the ones most worth doing carefully rather than the ones to get through quickly so the "real" work can start.\n\n` +
        `**A fact worth sitting with before you begin: identity is involved in the overwhelming majority of investigations.** Industry incident data puts identity — a compromised credential, an abused session, a privileged account used somewhere it shouldn't be — in roughly nine out of every ten investigations that go anywhere past the first alert. That is not a coincidence of any one environment; it is a structural fact about how modern intrusions work, because identity is the boundary every other lateral step has to cross. It is why Step 2 in this room is built entirely around pivoting on identity, and why the case running through this room does exactly that.\n\n` +
        `**One metric worth knowing by name: MTTI.** Mean Time to Investigate (sometimes Mean Time to Identify) measures the interval from when an alert fires to when an analyst has a validated understanding of what happened. It is not the same measure as time-to-detect or time-to-contain, and SOCs that only track those two can look fast on paper while investigations quietly drag. A workflow with clear, named steps is what makes MTTI something you can actually improve — you cannot shorten a step you never named.\n\n` +
        `The case in this room starts with one PowerShell process on one finance workstation. By the end you will have followed it through all seven steps and made a call a shift lead would actually have to make.`,
      codeExample:
        "THE 7-STEP ANALYST INVESTIGATION WORKFLOW\n" +
        "=================================================================\n" +
        "1. VALIDATE           Real, or detection artefact? Enrich. Compare\n" +
        "                      against related detections elsewhere.\n" +
        "2. SCOPE              Which accounts, hosts, and data are touched?\n" +
        "                      Revisited repeatedly as evidence grows.\n" +
        "3. COLLECT & PRESERVE Gather in order of volatility, before state\n" +
        "                      changes. Chain of custody from this point on.\n" +
        "4. RECONSTRUCT        Merge SIEM + EDR + NDR + identity into one\n" +
        "   TIMELINE           chronological narrative.\n" +
        "5. MAP TO ATT&CK      Classify each behaviour by tactic/technique.\n" +
        "   + ROOT CAUSE       Ask '5 Whys' down to the real control gap.\n" +
        "6. DOCUMENT           Contemporaneous notes: timestamps, hashes,\n" +
        "                      who touched what.\n" +
        "7. REPORT & HAND OFF  Detection method, confirmed scope, timeline,\n" +
        "                      root cause, corrective actions. Escalate if\n" +
        "                      severity or breach notification requires it.\n" +
        "=================================================================",
      checkpoint: {
        question: "Per Reading 1, roughly what proportion of investigations that go anywhere past the first alert involve identity in some form?",
        options: [
          "About one in ten", "Roughly half", "Roughly nine out of ten", "Essentially none -- identity is rarely a factor"
        ],
        answer: 2,
        explanation:
          "Industry incident data puts identity -- a compromised credential, an abused session, a privileged account used somewhere it shouldn't be -- in roughly nine out of every ten investigations, which is exactly why Step 2 in this room is built entirely around pivoting on identity.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "inv7-r2",
      heading: "Step 2 — Scope: The Step You Return to Again and Again",
      content:
        `Scoping asks three plain questions, and they only sound simple: which accounts authenticated to the affected host? Which other systems did those accounts touch? What data lives in the places they touched? Every other step in this room either feeds the answer to those questions or acts on it — which is why scope is not a single box to tick once and move past. You scope with whatever evidence Step 1 gave you, collect more evidence in Step 3, and that new evidence very often changes the answer, which means you scope again. A workflow diagram that draws scope as one box in a straight line is lying about how investigations actually feel: scope is a loop you keep re-entering until the evidence stops expanding it.\n\n` +
        `**The one technique that matters most here: pivot on the artefact, not on the person.** When a ticket names a user, the natural instinct is to query everything by that username — every sign-in that user made, every host that user touched. That query can only ever confirm what you already suspected, because it can only ever return records about that one user. To actually test whether the problem is bigger than one account, you have to pivot the other way: take an observable property of the suspicious activity itself — a source IP, an authenticating workstation, a process hash, a destination host — and ask who else, across the whole environment, shares that same property in the same window. Querying by person asks how bad is it for them. Querying by artefact asks how big is it. Only the second question can surface an account nobody has flagged yet.\n\n` +
        `**Scope answers "how far," and it has three dimensions worth separating in your notes.** Account scope: every identity that was used, misused, or reachable from the point of compromise — not just the one the ticket named. Host scope: every system the activity actually touched, reachable by pivoting on source IPs, logon records, and process lineage rather than assuming the blast radius stopped where the alert fired. Data scope: what, specifically, lived on the systems in the host-scope list — because "we touched a file server" and "we touched the file server holding unencrypted policyholder records" are two entirely different incidents that happen to look identical at the network layer.\n\n` +
        `**Why scoping too early is a common and expensive mistake.** An analyst under time pressure often stops scoping the moment they have "enough" to act — one compromised account, one obviously-affected host — and moves to containment. If a second host or a second account is still sitting unexamined at that point, containing the first one does not stop the intrusion; it just makes the analyst feel finished. The evidence you have not yet looked for is not evidence that it doesn't exist.\n\n` +
        `**A closing caution.** Scope is bounded by what you actually searched, not by what exists. If your pivot covered a six-hour window and one source system, say exactly that in your notes — "no further accounts found in this window, from this source" is a true and useful statement; "only one account is affected" is a claim you have not actually earned yet. That distinction becomes very important again in Step 6.`,
      diagram:
        "flowchart TD\n" +
        '  A["Step 1: Validate the triggering alert"] --> B["Step 2: Scope — pivot on IP / workstation / hash, not just the named user"]\n' +
        '  B --> C{"Does new evidence expand the scope?"}\n' +
        '  C -->|"Yes"| D["Step 3: Collect the new evidence"]\n' +
        '  D --> B\n' +
        '  C -->|"No further expansion found"| E["Step 4: Reconstruct the full timeline"]\n' +
        '  E --> F["Step 5: Map to ATT and CK, find root cause"]\n' +
        '  F --> G["Step 6: Document"]\n' +
        '  G --> H["Step 7: Report and hand off"]',
      diagramCaption: "Scope is a loop, not a box — this is why Steps 2 and 3 feed each other",
      checkpoint: {
        question: "Per Reading 2, what is the key difference between querying by the named person versus querying by an observable artifact (IP, workstation, hash)?",
        options: [
          "There is no meaningful difference -- both queries return the same result set regardless of which value they filter on, so the choice is purely stylistic",
          "Querying by person can only ever confirm what you already suspected about that one person; querying by artifact asks who else, across the whole environment, shares that same property -- only the second can surface an account nobody has flagged yet",
          "Querying by artifact is always slower and should be avoided under time pressure, since it has to scan every identity in the tenant instead of one named account's history",
          "Querying by person is a mandatory first gate the workflow requires before an artifact-based query is permitted to run at all",
        ],
        answer: 1,
        explanation:
          "Querying by person asks how bad is it for them; querying by artifact asks how big is it. Only the artifact-based pivot can surface an account or host nobody has flagged yet, which is exactly why Step 2 emphasizes pivoting on the artifact rather than the originally-named person.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "inv7-q1",
      question:
        "An EDR alert fires: 'Suspicious PowerShell Execution' on a single workstation, severity high. It is minute one. What is the single most useful action for Step 1 — Validate?",
      options: [
        "Immediately isolate the host from the network before looking at anything else, treating a single unconfirmed alert with the same urgency as a fully scoped, validated intrusion",
        "Enrich the alert against other data sources — was this process hash or command-line pattern seen elsewhere in the environment, does the parent process and account make sense together, is this a known-benign admin script — to confirm the record itself is real and not a parsing artefact or duplicate",
        "Close the alert if its severity is only 'high' rather than 'critical', since lower severities rarely warrant a full validation pass and are usually safe to triage away without further review",
        "Assume it is a true positive because the EDR already assigned it a severity, and move straight to Step 3 collection without first checking whether the record is even genuine",
      ],
      answer: 1,
      explanation:
        "Validation means checking that the record is real and correctly understood before you build anything on top of it — enrichment against related detections, the process/parent/account relationship, and known-benign patterns is exactly that check. Isolating the host is a Step 3/4 containment-adjacent action taken after you know what you are containing, not before; jumping there first can destroy evidence and tip off an intruder over something that might turn out to be benign. Severity is the tool's own scoring and is not a substitute for validating the record — plenty of real intrusions start at a moderate severity that only becomes obviously serious once scoped. And treating a single tool's alert as an automatic true positive is precisely the trap Step 1 exists to prevent; detection tools produce artefacts and duplicates too.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "inv7-la1",
      heading: "Step 1 — Validate: Reading the Triggering Record",
      context:
        "14:15, 9 April 2026. Ticket INC-51204 lands in your queue from a correlation rule: 'Suspicious PowerShell Execution' on WKS-FIN07, belonging to j.alvarez in Accounts Payable. You open the triggering Microsoft Defender for Endpoint record below and begin Step 1.",
      event: inv7ValidateEvent,
      questions: [
        {
          question:
            "Which fields establish that this is a genuine process execution and not a duplicated or mis-parsed record, and what do they show?",
          options: [
            "ReportId is populated, which is Defender's field for marking a record as verified and non-duplicated, so a numeric value there is itself proof the event is genuine",
            "ProcessId and ParentProcessId are both populated with real, distinct values, ActionType reads ProcessCreated, and ProcessCommandLine contains an actual, well-formed command line — together these describe a specific process creation event, not a placeholder or template record",
            "AccountDomain reads CASTLETON, which confirms the process ran under a real domain account rather than a local one, and that alone is enough to validate the record",
            "The event cannot be validated without pulling the workstation's full event log first, since no single Defender record ever contains enough detail on its own",
          ],
          answer: 1,
          explanation:
            "A genuine process-creation record has a coherent set of process fields describing one specific event: real PIDs for both the process and its parent, an ActionType naming what happened, and an actual command-line string rather than an empty or templated one. ReportId is simply Defender's internal record identifier and carries no verification meaning by itself. AccountDomain tells you which domain the account belongs to, not whether the record is genuine. And you already have enough in this single record to validate it — waiting for a full separate pull before doing any validation would stall Step 1 unnecessarily.",
          xp: 25,
        },
        {
          question:
            "ParentProcessFileName is WINWORD.EXE and ParentProcessCommandLine shows Word opening a file named Q3_Vendor_Statement.docm from the user's Downloads folder. Why does this specific parent-child relationship matter for validation?",
          options: [
            "It doesn't matter — PowerShell is commonly spawned by many applications, and a document viewer's parent-child relationship to a shell carries no investigative weight on its own",
            "Word spawning PowerShell is not a normal part of opening a document; a .docm file is macro-enabled, and a macro capable of running arbitrary code is the most direct explanation for a document viewer producing a hidden, encoded PowerShell child process moments after being opened",
            "It confirms the file is a legitimate vendor statement, since the filename describes routine Accounts Payable business that j.alvarez's role would plausibly receive",
            "It shows the user manually opened PowerShell themselves right after finishing the document, most likely to check a formula or macro setting in the file",
          ],
          answer: 1,
          explanation:
            "A word processor has no legitimate reason to spawn a hidden, base64-encoded PowerShell process as part of simply displaying a document — that behaviour is the signature of a macro executing on open. The .docm extension confirms the file is macro-enabled, which is precisely what makes this parent-child pairing meaningful rather than incidental. The filename is chosen by whoever delivered the file and describes nothing about its actual contents or legitimacy — a business-sounding name is exactly what a lure is built to have. And the command line's own -w hidden flag is the opposite of a user manually opening a visible PowerShell window.",
          xp: 25,
        },
        {
          question:
            "You've now confirmed: real process record, WINWORD.EXE parent spawning powershell.exe with -w hidden and a base64-encoded command, from a macro-enabled document opened minutes earlier. What does Step 1 have you do next, and why not something else?",
          options: [
            "Move straight to Step 5 and classify this against MITRE ATT&CK, since you already know enough to name the technique",
            "Move to Step 2 — Scope — and start pivoting on this host's and account's activity to establish how far this has already gone, before deciding on any response",
            "Reset j.alvarez's password immediately, since a compromised workstation always implies a compromised account",
            "Close the ticket as handled, since Defender already caught and would have blocked a genuinely malicious payload automatically",
          ],
          answer: 1,
          explanation:
            "Validation is complete — this is a real, malicious-looking execution chain — so the next step is Scope, exactly as this room's reading laid out: establish how far it goes before you act. Jumping to ATT&CK classification is useful but premature as the very next action; it doesn't tell you whether this is contained to one host or already lateral, which is what determines everything downstream. Resetting a password is a containment action taken before you know the actual scope, and it assumes facts — that the account itself, not just the workstation, is what's compromised — that you have not yet established. And a detection firing is not the same as a payload being blocked; EDR frequently observes and reports activity it does not prevent, which is exactly why an alert exists to investigate in the first place.",
          xp: 30,
        },
      ],
    },
    // -----------------------------------------------------------------------
    {
      type: "ordering",
      id: "inv7-o1",
      heading: "Put the 7 Steps in Their Working Order",
      instructions:
        "Arrange these seven investigation activities in the order the workflow actually runs them. Think about which steps depend on evidence that an earlier step produces.",
      items: [
        { id: "collect", text: "Gather evidence in order of volatility, before anything changes state, preserving chain of custody" },
        { id: "document", text: "Write contemporaneous notes as you go — timestamps, hashes, what was checked and by whom" },
        { id: "validate", text: "Confirm the triggering record is real and correctly understood, not a detection artefact" },
        { id: "report", text: "Package the detection method, confirmed scope, timeline, root cause and corrective actions for hand-off" },
        { id: "timeline", text: "Merge every source — SIEM, EDR, network, identity — into one chronological narrative" },
        { id: "rootcause", text: "Map each behaviour to MITRE ATT&CK and ask '5 Whys' down to the actual control gap" },
        { id: "scope", text: "Establish which accounts, hosts and data the activity actually touches" },
      ],
      correct_order: ["validate", "scope", "collect", "timeline", "rootcause", "document", "report"],
      explanation:
        "Validate comes first because every later step is wasted effort if the triggering record itself is a duplicate or artefact. Scope comes next because it tells you what to even go collect — you cannot preserve evidence from systems you don't yet know are involved. Collection follows, and it has to happen before you change anything, because containment and remediation actions destroy the very evidence you need for the next two steps. Reconstructing the timeline needs the collected evidence to merge into a narrative, and mapping to ATT&CK and root cause needs that narrative to classify behaviours in their actual sequence. Documentation is listed as its own step here for clarity, but in real practice it runs continuously alongside every step before it — the ordering still holds because the finished, coherent write-up depends on everything that came before it being done. Reporting and hand-off comes last because it is the package built from everything the previous six steps produced.",
      xp: 35,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "inv7-r3",
      heading: "Step 3 — Collect and Preserve, in the Right Order",
      content:
        `Once scope has told you what to go collect, the order you collect it in is not a matter of convenience — it follows the volatility of the evidence itself, meaning how quickly it disappears if you don't capture it now. Collect from most volatile to least volatile, because the fast-vanishing evidence is gone forever if you get to it late, while the slow-vanishing evidence will still be there tomorrow.\n\n` +
        `**The order, and why each rung sits where it does.** First, memory and live system state — running processes, open handles, loaded modules, active network sockets on the host itself. This is the most volatile evidence in the entire investigation: it evaporates the instant the process exits or the machine reboots, and a well-meaning "let's just restart it and see if that helps" from an unrelated IT ticket can erase it permanently before you ever get there. Second, network connections and flow data — session records showing what a host was actually talking to, which typically persist for some window in a firewall, proxy, or NDR platform but eventually roll off retention. Third, identity and SaaS logs — sign-in records, session tokens, mailbox rule changes, application consents — usually retained considerably longer than host-level artefacts, but still finite, and still capable of being partially overwritten by continued activity on the same account. Fourth and least volatile, disk — files, registry hives, scheduled tasks, persistence artefacts sitting on storage, which will typically still be recoverable well after everything above it has decayed, unless a wipe or reimage happens first.\n\n` +
        `**Why this order matters practically, not just academically.** An analyst who documents everything from disk first because it's the easiest thing to query, and gets to live memory state last, may find the live evidence is simply gone by the time they turn to it — a process finished, a connection closed, a session token already expired. The volatility order is a deliberate answer to that risk: spend your first collection effort where time actually costs you evidence.\n\n` +
        `**Chain of custody is what makes any of this usable later.** Every piece of evidence you collect needs three things attached to it from the moment you touch it: a timestamp of when it was collected, a hash of the artefact itself if it's a file or export (so anyone can later confirm it hasn't been altered), and a record of who collected it. This is not paperwork for its own sake — six months from now, if this case becomes a legal matter, an HR matter, or a regulatory finding, "I'm confident I remember what I saw" is worth nothing next to a timestamped, hashed record showing exactly what was pulled, when, and by whom. Chain of custody is what separates evidence from recollection.\n\n` +
        `**One more discipline worth naming here: collect before you act.** Every containment step — killing a session, resetting a password, isolating a host — changes state, and changed state cannot be un-changed to recover what you didn't capture first. This is why Step 3 sits before any containment decision in this workflow, not after it.`,
      codeExample:
        "ORDER OF VOLATILITY -- COLLECT IN THIS ORDER\n" +
        "=================================================================\n" +
        "1. MEMORY / LIVE STATE     Running processes, open handles, loaded\n" +
        "                           modules, active sockets. Gone on exit\n" +
        "                           or reboot. Most volatile -- collect\n" +
        "                           first.\n\n" +
        "2. NETWORK CONNECTIONS     Flow data, firewall/proxy/NDR session\n" +
        "                           records. Persist for a retention\n" +
        "                           window, then roll off.\n\n" +
        "3. IDENTITY / SAAS LOGS    Sign-ins, session tokens, mailbox\n" +
        "                           rules, app consents. Longer retention,\n" +
        "                           still finite.\n\n" +
        "4. DISK                    Files, registry, scheduled tasks,\n" +
        "                           persistence artefacts. Least volatile\n" +
        "                           -- usually still there tomorrow.\n" +
        "=================================================================\n" +
        "EVERY ITEM COLLECTED NEEDS: timestamp + hash (if a file/export)\n" +
        "+ who collected it. This is chain of custody, not paperwork.\n" +
        "=================================================================",
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "inv7-q2",
      question:
        "You have identified a second, possibly-affected host and need to prioritise what to collect from it in your remaining time this shift. Which order correctly follows volatility, from most to least urgent to capture?",
      options: [
        "Disk artefacts first, then identity/SaaS logs, then network connections, then live memory state",
        "Live memory state and running processes first, then active network connections, then identity/SaaS session logs, then disk artefacts",
        "Identity/SaaS logs first, then disk, then live memory state, then network connections",
        "All four should be collected simultaneously in one sweep, since volatility only matters for forensic labs, not SOC investigations",
      ],
      answer: 1,
      explanation:
        "This is the order Reading 3 laid out and the reasoning behind it: live memory and running process state vanish the moment a process exits or the machine reboots, so it is captured first; network connections persist for a retention window but do roll off; identity and SaaS logs typically last longer still; and disk artefacts are the least volatile of the four, usually recoverable well after the others have decayed. Reversing the order, as the first and third options do, risks losing the fastest-decaying evidence while spending early effort on the evidence that would have waited. And volatility is exactly why a SOC analyst, not only a forensic lab, needs to prioritise collection order — a live intrusion does not pause while you work through artefacts in a convenient sequence.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "inv7-la2",
      heading: "Step 2 — Scope: The Pivot That Finds the Second Host",
      context:
        "Following Step 2's guidance, you pivot on WKS-FIN07's own activity rather than only on j.alvarez's account — checking what else that workstation, or any account authenticating from it, touched in the hour after the PowerShell process ran. The Windows Security event log on a finance database server, FIN-DB02, returns the record below.",
      event: inv7ScopeEvent,
      questions: [
        {
          question:
            "TargetUserName is d.reyes, not j.alvarez, and WorkstationName is WKS-FIN07 — the same host from Step 1. What does this combination establish about scope?",
          options: [
            "Nothing new — d.reyes is presumably a colleague of j.alvarez's in the same department, and this logon is unrelated background activity that happens every day",
            "A different account, d.reyes, authenticated onto a second host, FIN-DB02, with the logon record naming the already-compromised workstation as its source — the activity has moved beyond the one account and one host the original ticket named",
            "It confirms j.alvarez has two Active Directory accounts under different usernames, one for daily work and one reserved for privileged database access",
            "It shows FIN-DB02 is actually the same physical machine as WKS-FIN07, just referenced by two different hostnames depending on which log source recorded it",
          ],
          answer: 1,
          explanation:
            "WorkstationName recording the source of a network logon is exactly the field this room's Step 2 reading pointed to: pivoting on the artefact (the workstation) rather than the originally-named account (j.alvarez) is what surfaces this. A different TargetUserName authenticating from that source, onto a distinct target Computer, is precisely how scope expands beyond a single ticket's original framing — this is not unrelated background activity, it is the same source host now touching a second system under a second identity. Nothing here suggests two accounts belong to one person, and FIN-DB02 and WKS-FIN07 are recorded as the Computer field and WorkstationName field respectively — two distinct machines, one being the source and one the target of this logon.",
          xp: 30,
        },
        {
          question:
            "LogonType is 3 and AuthenticationPackageName is NTLM. Combined with everything else in this record, what should this prompt you to check next, and why?",
          options: [
            "Nothing further — LogonType 3 is an interactive desktop logon and is the least noteworthy type available, so this record needs no additional scrutiny beyond what's already been noted",
            "LogonType 3 is a network logon (the kind used for things like accessing a file share or admin tooling remotely, not sitting at a physical console) — worth checking whether d.reyes normally authenticates to FIN-DB02 at all, and from where, since a privileged account reaching a database server from a Finance workstation it has never used is exactly the anomaly a baseline comparison would catch",
            "NTLM authentication always indicates the credential was stolen, regardless of any other context, since Kerberos is mandatory in any properly hardened domain",
            "This combination confirms the logon failed and no further action is needed, since AuthenticationPackageName only appears on unsuccessful attempts",
          ],
          answer: 1,
          explanation:
            "LogonType 3 specifically denotes a network logon — used for remote resource access rather than an interactive desktop session — and its presence here is a prompt to compare this logon against d.reyes's normal pattern: does this account ever reach FIN-DB02, and does it ever do so from a Finance workstation rather than its own device? NTLM being in use is common in many legacy-compatible environments and is not on its own proof of anything; it is one fact to weigh alongside the others, not a verdict by itself. And nothing in this record indicates failure — the event type is a successful authentication.",
          xp: 30,
        },
        {
          question:
            "You now have: a macro-driven PowerShell process on WKS-FIN07 under j.alvarez, followed 52 minutes later by d.reyes authenticating from that same workstation onto FIN-DB02. Per Step 2's guidance, what should you do with this finding, and what should you explicitly avoid concluding yet?",
          options: [
            "Conclude the investigation is fully scoped at two hosts and two accounts, close the scoping step, and move straight to containment on both, since two pivots is generally considered thorough enough",
            "Treat this as scope expansion requiring another loop — collect evidence from FIN-DB02 itself and check whether d.reyes's credentials or session were used anywhere else — while explicitly not yet claiming this is the full extent, since that has not been searched for",
            "Discard this finding as irrelevant, since the original ticket only named j.alvarez and this room's Step 2 only concerns the account in the ticket, not accounts discovered along the way",
            "Reset d.reyes's password immediately as the entire scoping step, since resetting a privileged account's credentials is itself considered sufficient evidence-gathering under this workflow",
          ],
          answer: 1,
          explanation:
            "This is scope doing exactly what Reading 2 described: new evidence expanding the boundary, which sends you back into another loop of collection rather than to a premature conclusion. Declaring the scope 'fully' bounded at two hosts is a claim you have not earned — you have found what you searched for, not confirmed there is nothing further, and Reading 2 was explicit that this distinction matters. Discarding the finding contradicts the entire point of pivoting on the artefact rather than the named account — this is precisely the kind of expansion that pivot exists to catch. And a password reset is a containment action, which this workflow deliberately holds until after collection and full scoping, not as a substitute for the scoping step itself.",
          xp: 35,
        },
      ],
    },
    // -----------------------------------------------------------------------
    {
      type: "matching",
      id: "inv7-m1",
      heading: "Match Each Step to the Deliverable It Actually Produces",
      instructions:
        "Match each of the 7 steps to the specific output it is responsible for. This is how you tell a step that's been genuinely completed from one that's only been ticked.",
      pairs: [
        { id: "validate", left: "Step 1 — Validate", right: "A recorded determination that the triggering record is real and correctly understood, not a duplicate or artefact" },
        { id: "scope", left: "Step 2 — Scope", right: "A stated, evidence-based boundary of which accounts, hosts and data are actually touched — re-run every time new evidence arrives" },
        { id: "collect", left: "Step 3 — Collect and preserve", right: "An evidence set gathered in volatility order, each item stamped with a timestamp, a hash where applicable, and who collected it" },
        { id: "timeline", left: "Step 4 — Reconstruct the timeline", right: "One merged, chronological narrative combining SIEM, EDR, network and identity sources into a single sequence of events" },
        { id: "rootcause", left: "Step 5 — Map to ATT&CK and root cause", right: "Each behaviour classified to a tactic/technique, plus a root cause found by asking why repeatedly until an actual control gap is named" },
        { id: "document", left: "Step 6 — Document", right: "Contemporaneous notes written as the investigation happens, not reconstructed afterward from memory" },
        { id: "report", left: "Step 7 — Report and hand off", right: "A package containing detection method, confirmed scope, full timeline, root cause and corrective actions, escalated onward where severity or breach notification requires it" },
      ],
      explanation:
        "Each step's deliverable is a specific, checkable artefact, not a feeling of having addressed it. Notice how Step 2's deliverable is explicitly described as re-run rather than one-and-done — that's the loop this room keeps returning to. And notice Step 6's wording: contemporaneous, meaning written at the time, is doing real work there — notes assembled after the fact from memory are a materially weaker record than notes taken as each fact was found, a point the companion room on writing incident reports builds on directly.",
      xp: 35,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "inv7-r4",
      heading: "Step 4 — Reconstruct the Timeline; Step 5 — Map to ATT&CK and Find Root Cause",
      content:
        `**Step 4: the super-timeline.** Every source you collected in Step 3 records its own version of events in its own format, at its own timestamp precision, in its own timezone convention if you're not careful. EDR shows process creation. Windows Security shows logons. A firewall or NDR platform shows connections. Identity logs show sign-ins and session activity. None of these sources tells the whole story alone, and reading them one at a time, in isolation, is how an analyst misses the fact that a lateral logon happened 52 minutes after a suspicious process on the same host — each individual record looks unremarkable enough by itself. A super-timeline is simply the discipline of merging every source into one chronological sequence, normalised to a single timezone, so the story reads the way it actually happened rather than the way each individual tool happened to log it. This is mechanical, sometimes tedious work, and it is also where most of the actual insight in an investigation comes from — the pattern is very often invisible until the sources sit next to each other in time order.\n\n` +
        `**Step 5, first half: map to MITRE ATT&CK.** Once you have a timeline, classify each distinct behaviour by tactic and technique. This case, reconstructed, maps cleanly: T1059.001 (Command and Scripting Interpreter: PowerShell) for the Execution stage, T1021.002 (Remote Services: SMB/Windows Admin Shares) for the Lateral Movement stage, and T1560.001 (Archive Collected Data via Utility) for the Collection stage. This is not a labelling exercise for its own sake — a technique name is a shared, precise vocabulary that lets you communicate exactly what happened to another analyst, a threat intel team, or a report reader without re-explaining the mechanics from scratch every time, and it lets you check this specific intrusion against what's typically known to follow those techniques (what usually comes after T1560.001 staging, for instance, is exfiltration).\n\n` +
        `**Step 5, second half: root cause, using "5 Whys."** ATT&CK mapping tells you what happened. Root cause asks why it was possible at all, and the discipline for getting past a shallow answer is to keep asking why, typically five times, until you land on something you could actually fix. "A user opened a malicious document" is where most analysts stop, and it is almost never the root cause — it describes the trigger, not the failure. Why did opening it lead to code execution? Because the macro was allowed to run. Why was it allowed to run? Because macro execution from internet-sourced documents wasn't blocked by policy on this workstation. Why not? Because that control exists for other business units but was never extended to Finance. Why not? Because the control rollout tracked departments requesting it, not risk exposure. That is a root cause you can actually act on — a policy gap with a specific, nameable owner — and it is nothing like "a user clicked something they shouldn't have," which blames the trigger and leaves the actual control gap sitting there for the next person to click into.\n\n` +
        `**Why this order — timeline, then classification, then root cause — and not some other order.** You cannot meaningfully classify a behaviour you haven't placed in its correct sequence relative to everything else (was this lateral movement enabling the collection, or unrelated background activity?), and you cannot ask a useful "why" about root cause until you know precisely what happened and in what order. Each half of Step 5 depends on the timeline Step 4 just built.`,
      checkpoint: {
        question:
          "In the '5 Whys' worked example in Reading 4, why is 'a user opened a malicious document' rejected as the root cause?",
        options: [
          "Because it isn't true -- the user never actually opened the document, so the entire premise of the statement is factually incorrect from the start",
          "Because it describes the trigger, not the failure -- the actual root cause is the specific control gap (e.g. macro execution from internet-sourced documents wasn't blocked by policy on that workstation) that let opening it lead to code execution",
          "Because root cause must always name a specific software vendor's product responsible for the flaw, and this phrasing names no vendor at all",
          "Because 5 Whys requires exactly five separate root causes to be listed as the end result, and this statement only offers one",
        ],
        answer: 1,
        explanation:
          "Most analysts stop at the trigger ('a user clicked something'), but the reading is explicit that this is almost never the root cause -- you keep asking why until you land on an actual, fixable control gap, like a policy rollout that never reached a specific department.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "inv7-ac1",
      heading: "The Call: True Positive, or Escalate?",
      scenario:
        "16:05. Your timeline now reads: 14:12, macro-spawned PowerShell on WKS-FIN07 under j.alvarez; 15:04, d.reyes authenticates onto FIN-DB02 from that same workstation, a logon pattern that account has never shown before; 15:41, the record below — a PowerShell child process on FIN-DB02, under d.reyes's session, invoking a compression utility against a folder of Accounts Payable export files, producing a multi-hundred-megabyte archive in a non-standard system folder. You have validated, scoped twice, and collected evidence in order at each stage. The shift lead is reachable but the decision on how to classify this before acting is yours to make first.",
      event: inv7CollectionEvent,
      correct_verdict: "escalate",
      explanation:
        "This is a true positive in the sense that the activity is clearly malicious — but 'true positive' alone understates what you're holding, and understating it is the actual mistake available here. What you have is: initial access and execution on one host, lateral movement onto a database server using a privileged account that host had never been the source for before, and collection of a large volume of finance export data staged for likely removal. That is not a single-host malware event an analyst closes out alone; it is a privileged-account intrusion that has already reached a system holding financially sensitive records and produced a package-sized artefact consistent with preparation for exfiltration. The size and sensitivity of what has already been touched — not just the fact that something bad happened — is what crosses the threshold into escalation: this is the kind of finding that can carry breach-notification and regulatory obligations depending on what the underlying export data actually contains, and that determination sits above a single analyst's authority to make alone.\n\nMarking this 'true positive' and proceeding to contain it yourself would get the technical response mostly right and still fail the organisation, because notifying legal, compliance, and the IR lead about a confirmed privileged-account compromise touching finance data is itself part of the correct response, not an optional extra step after the technical work is done. Escalating is not a substitute for the technical steps still ahead of you (collection is not finished, the timeline is not final, root cause has not been named) — it runs alongside them, informing the people whose decisions depend on knowing this exists.",
      fp_trap:
        "Calling this a straightforward 'true positive' and just handling it is the most tempting wrong answer, because every individual step in this room has trained you to build exactly the case you now have — and having built it, closing it out yourself feels like the payoff. It would also not be wrong about the facts: the activity genuinely is malicious. The mistake is one of scope of authority, not of technical judgement — the finding has grown past what a single analyst's containment decision can responsibly resolve, because it now touches a category of data (financial export records) and a category of account (a privileged credential) that most organisations have specific escalation and notification obligations around, and an individual analyst is very rarely the right person to decide those obligations don't apply. Marking it 'informational' would be indefensible against the evidence in hand. Marking it 'false_positive' would ignore every fact this room's log analysis tasks just walked you through establishing.",
      xp: 40,
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "inv7-q3",
      question:
        "The archive-creation record shows a PowerShell process invoking a compression utility against a folder of export files, producing a single large archive. Which ATT&CK tactic and technique does this specific behaviour map to?",
      options: [
        "Tactic: Exfiltration; Technique: T1041 (Exfiltration Over C2 Channel) — the data has already left the environment at this point, since compressing files is understood as the first stage of a C2 transfer",
        "Tactic: Collection; Technique: T1560.001 (Archive Collected Data via Utility) — files are being gathered and compressed into a single package, which is preparation for likely removal, not removal itself",
        "Tactic: Discovery; Technique: T1083 (File and Directory Discovery) — the activity only involves identifying which files exist, and no content has actually been read or copied yet",
        "Tactic: Persistence; Technique: T1547 (Boot or Logon Autostart Execution) — the archive is being staged in a location that will re-launch it automatically at the next system boot",
      ],
      answer: 1,
      explanation:
        "The specific, observable action — a utility compressing a folder of files into one archive — is exactly what T1560.001 describes: staging collected data via an archiving tool, under the Collection tactic. It is not yet Exfiltration; that tactic and T1041 specifically apply once data is observed actually leaving the environment over a command-and-control channel, which this record does not show. It is well past simple Discovery, which would only involve enumerating what files exist rather than compressing their contents into a package. And nothing about creating an archive relates to autostart persistence mechanisms, which concern how malicious code survives a reboot, not how data is packaged for removal.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "inv7-r5",
      heading: "Step 6 — Document; Step 7 — Report and Hand Off",
      content:
        `**Step 6 is not a step you do after the others — it is a habit you run alongside all of them, and this room is naming it separately only to make sure it doesn't get skipped.** Contemporaneous means written down at the time, not reconstructed from memory once the ticket is nearly closed. Every fact worth acting on is worth writing down the moment you establish it: the exact timestamp you observed, the exact field and value that told you something, the hash of anything you collected, which tool or query produced the finding, and who did the collecting if it wasn't you. The reason this matters goes beyond tidiness — six months from now, when someone asks why an account was disabled or why a customer was notified, "a timestamped, hashed record of what was found and when" is defensible in a way that "I'm fairly sure that's what I saw" is not. If it wasn't written down, for every practical purpose that matters later, it didn't happen.\n\n` +
        `**Step 7 packages everything into a hand-off, and a complete one contains five specific things, not a general summary.** Detection method: what actually caught this, and how (a correlation rule, a manual pivot, an analyst's own suspicion) — this matters because it tells the next reader whether existing tooling would catch a repeat of this, or whether it only worked because a person happened to notice. Confirmed scope: the accounts, hosts and data you established were touched, stated with its actual boundaries — what you searched and found, not a claim about everything that exists. Timeline: the full chronological reconstruction from Step 4, in order, with timestamps. Root cause: the specific, actionable control gap from Step 5 — not "a user clicked something." Corrective actions: what should change so this specific gap doesn't produce the same outcome again, ideally with an owner.\n\n` +
        `**Escalation is a decision this step forces you to make explicitly, not a fallback for when you're unsure.** The criteria are concrete, not a feeling: does the confirmed scope include data categories that may trigger breach notification obligations? Does it involve a privileged account, an executive, or a system whose compromise carries regulatory weight? Has the activity already progressed to a stage (collection, staging, active exfiltration) that changes the response timeline from "handle this shift" to "this needs legal and leadership now"? Answering these honestly, using what Steps 1 through 5 actually established, is what separates escalating because the evidence calls for it from escalating reflexively out of uncertainty, or — the more dangerous failure mode — not escalating because closing the ticket yourself feels like finishing the job.\n\n` +
        `**A last, practical point tying this back to Step 1's MTTI metric.** A hand-off package built from contemporaneous notes and a clean, already-classified timeline takes the next person minutes to act on. A hand-off assembled from memory after the fact, with gaps the analyst has to reconstruct under questioning, costs everyone downstream real time — which is exactly the kind of hidden cost that makes MTTI worse for the whole team, not just for the ticket in front of you.`,
      codeExample:
        "STEP 7 HAND-OFF PACKAGE -- WHAT IT MUST CONTAIN\n" +
        "=================================================================\n" +
        "1. DETECTION METHOD    What caught this, and how (rule / manual\n" +
        "                       pivot / analyst judgement).\n" +
        "2. CONFIRMED SCOPE     Accounts, hosts, data touched -- stated\n" +
        "                       with its actual searched boundary.\n" +
        "3. TIMELINE            Full chronological reconstruction, with\n" +
        "                       timestamps, from Step 4.\n" +
        "4. ROOT CAUSE          The specific, actionable control gap from\n" +
        "                       Step 5 -- not 'a user clicked something.'\n" +
        "5. CORRECTIVE ACTIONS  What changes so this gap doesn't produce\n" +
        "                       the same outcome again.\n" +
        "=================================================================\n" +
        "ESCALATE WHEN: data category may trigger breach notification, OR\n" +
        "a privileged/executive account or regulated system is involved,\n" +
        "OR activity has progressed to staging/exfiltration.\n" +
        "=================================================================",
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "inv7-q4",
      question:
        "A colleague hands off a ticket with the note: 'Confirmed malicious PowerShell on one host, contained, closed.' Based on this room, what is missing from a complete Step 7 hand-off, and why does it matter?",
      options: [
        "Nothing is missing — containment is the goal of an investigation, and once a host is contained the hand-off note has done its job regardless of what else it does or doesn't say",
        "It is missing detection method, full timeline, root cause and corrective actions — without them, the next person (or the next shift) has no way to know how this was found, whether it could recur, or whether the scope claim was ever actually tested by pivoting beyond the one host named",
        "It is missing only the exact time the ticket was closed, which is a formatting issue a ticketing system's audit trail already captures automatically anyway",
        "It is missing nothing substantive, since the word 'confirmed' already implies every one of Step 7's five required elements was independently verified",
      ],
      answer: 1,
      explanation:
        "A one-line note like this answers none of the five things a complete hand-off needs: how it was actually found, the full ordered timeline, the specific root cause, and the corrective action that would prevent a repeat — and 'one host' is an unverified scope claim unless a pivot was actually run to check for more, which this room's own case shows does not hold up under scrutiny. This is not a formatting issue; a closing timestamp is a minor detail next to the substantive gaps here. And 'contained' describes an action taken, not proof that scoping happened correctly before that action — the whole point of Step 2 is that scope has to be established with evidence, not assumed from the fact that a response occurred.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "query_fill",
      id: "inv7-qf1",
      heading: "Write It Yourself: The Step 2 Pivot Query",
      language: "kql",
      context:
        "You want a repeatable query for exactly the Step 2 technique this room taught: instead of asking what did this user do, ask who else used this specific identity anywhere in the environment. Fill in the Windows logon event ID and the account you're pivoting on from this case.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TargetUserName == \"{{account}}\"\n| project TimeGenerated, Computer, WorkstationName, IpAddress, LogonType",
      blanks: [
        { id: "eventid", answers: ["4624"], placeholder: "Windows successful logon event ID" },
        { id: "account", answers: ["d.reyes"], placeholder: "account to pivot on" },
      ],
      explanation:
        "EventID 4624 is the Windows Security event for a successful logon, and pivoting on TargetUserName d.reyes — rather than re-querying j.alvarez, the account the original ticket named — is exactly the artefact-first technique from the Step 2 reading: it asks every host this specific account touched, across the whole environment, instead of only confirming what one workstation already showed you.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "flag",
      id: "inv7-f1",
      prompt:
        "Step 3 requires hashing every artefact you collect. What is the exact SHA256 hash of the archive file created on FIN-DB02, exactly as recorded in the raw log?",
      answer: "c2a97e4f1b6d8a3c5e0f9b7d4a1c6e8f3b5d7a9c1e4f6b8d0a2c5e7f9b1d3a6c",
      xp: 25,
    },
  ],
};

// ===========================================================================
// ROOM 2 — Writing the Incident Report: Documentation That Holds Up
// ===========================================================================

// ---------------------------------------------------------------------------
// Event 1 — Persistence artefact used as the "what becomes evidence /
// what becomes an IOC" worked example.
// ---------------------------------------------------------------------------

const docScheduledTaskEvent: TelemetryEvent = {
  id: "evt-doc-la1-001",
  ts: "2026-06-02T23:14:08.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "scheduled_task",
  severity: "critical",
  hostname: "AP-SRV14",
  mitre_technique: "T1053.005",
  mitre_tactic: "Persistence",
  file: {
    name: "sync.exe",
    path: "C:\\ProgramData\\OneDriveSyncHelper\\sync.exe",
    sha256: "d4b8f61a2e9c5073b6a1d8f4c2e7b905a3f6c8d1b4e7a9c2f5d8b1e4a7c9f0d2",
  },
  description:
    "Microsoft Defender for Endpoint recorded a new scheduled task created on AP-SRV14 under the svc-report service account, configured to run an executable in ProgramData at every logon with SYSTEM privileges.",
  raw: {
    "DeviceName": "AP-SRV14",
    "ActionType": "ScheduledTaskCreated",
    "TaskName": "OneDriveSyncHelper",
    "InitiatingProcessFileName": "schtasks.exe",
    "InitiatingProcessCommandLine": "schtasks.exe /create /tn \"OneDriveSyncHelper\" /tr \"C:\\ProgramData\\OneDriveSyncHelper\\sync.exe\" /sc onlogon /ru SYSTEM /rl HIGHEST",
    "InitiatingProcessAccountName": "svc-report",
    "InitiatingProcessAccountDomain": "SOLSTICE",
    "AccountSid": "S-1-5-21-3982104477-2847710093-1038822615-2201",
    "FileName": "sync.exe",
    "FolderPath": "C:\\ProgramData\\OneDriveSyncHelper\\",
    "SHA256": "d4b8f61a2e9c5073b6a1d8f4c2e7b905a3f6c8d1b4e7a9c2f5d8b1e4a7c9f0d2",
    "ReportId": 51027,
  },
};

// ---------------------------------------------------------------------------
// Event 2 — legitimate overnight admin sign-in, IT-verified. This must be
// excluded from the eventual IOC list, not written up as one.
// ---------------------------------------------------------------------------

const docLegitimateAdminEvent: TelemetryEvent = {
  id: "evt-doc-ac1-001",
  ts: "2026-06-03T02:10:44.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "medium",
  user_email: "d.whitfield@solstice-actuarial.com",
  src_ip: "203.14.88.9",
  authentication: { method: "Password", result: "Success" },
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-2291 authorises d.whitfield (IT infrastructure) to perform a scheduled patch deployment against AP-SRV14 and two other servers between 01:30 and 04:00 on 2026-06-03. IPAddress matches the corporate VPN's registered static address.",
  description:
    "Entra ID recorded an interactive sign-in for d.whitfield@solstice-actuarial.com during the overnight maintenance window associated with change ticket CHG-2291.",
  raw: {
    "OperationName": "Sign-in activity",
    "Category": "SignInLogs",
    "ResultType": "0",
    "UserPrincipalName": "d.whitfield@solstice-actuarial.com",
    "UserDisplayName": "Derek Whitfield",
    "AppDisplayName": "Azure Portal",
    "IPAddress": "203.14.88.9",
    "AutonomousSystemNumber": 14618,
    "LocationDetails.city": "Columbus",
    "LocationDetails.countryOrRegion": "US",
    "ConditionalAccessStatus": "success",
    "AuthenticationRequirement": "multiFactorAuthentication",
    "DeviceDetail.isCompliant": true,
    "DeviceDetail.isManaged": true,
    "RiskLevelDuringSignIn": "none",
    "RiskState": "none",
  },
};

const writingIncidentReportRoom: Room = {
  id: "incident-report-writing",
  title: "Writing the Incident Report — Documentation That Holds Up",
  description:
    "The investigation is only half the job. This room teaches the other half: writing an incident report that serves two different audiences from one document, extracting IOCs correctly, building a technical timeline a stranger can follow six months later, writing a root cause that names an actual control gap instead of blaming a user, and keeping the whole thing defensible under later scrutiny. Built on a second case — a persistence foothold at Solstice Actuarial Partners — using real Microsoft Defender for Endpoint and Entra ID fields.",
  difficulty: "intermediate",
  category: "Incident Response",
  estimatedMinutes: 50,
  xp: 310,
  icon: "📝",
  prerequisites: ["incident-response-methodology"],
  tasks: [
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "doc-r1",
      heading: "Two Audiences, One Incident: Why Every Report Has Two Halves",
      content:
        `The person who reads an incident report first is very often not the person who will act on its technical detail — and writing one document that serves both readers well, rather than picking one and disappointing the other, is the actual skill this room teaches.\n\n` +
        `**The first audience: leadership, legal, and sometimes the board or a regulator.** They need to know, in plain language, in roughly the time it takes to read a paragraph: what happened, how bad is it, is it still happening, and what is being done about it. They do not need — and will usually not read past — a paragraph explaining ProcessCommandLine fields or ATT&CK sub-technique numbers. What they need is scope translated into business and risk terms: which systems, whether customer or financial data was involved, current containment status, and estimated impact where it can be responsibly estimated.\n\n` +
        `**The second audience: the technical team, and your future self.** Whoever remediates this, whoever reviews it for lessons learned, whoever has to explain a related finding eight months from now needs the actual mechanics: exact timestamps, exact field values, exact command lines, exact hashes, the methodology behind every conclusion. This audience is poorly served by a report that stays at the business-summary level throughout — they need to be able to reproduce your reasoning, not just trust your conclusion.\n\n` +
        `**Why one document, not two separate ones, is usually the right call.** Splitting into genuinely separate documents invites drift — the executive version says one thing, the technical version quietly says something slightly different six revisions later, and nobody notices until someone compares them line by line during a post-incident review. The standard, more defensible structure is one report with an Executive Summary section at the top — typically three to six sentences — followed by the full technical detail beneath it. Anyone can stop reading after the summary and walk away with an accurate, honest picture; anyone who needs the mechanics keeps reading.\n\n` +
        `**What actually belongs in those three to six sentences.** State the incident type in plain terms, the systems and data categories affected, the current status (contained, under investigation, resolved), and — carefully — the business impact, translated: not "T1560.001 collection was observed on AP-SRV14" but "a persistence mechanism was found on a server hosting Accounts Payable processing tools; no confirmed data loss has occurred as of this writing; the affected server has been isolated." Every word in that summary should be something a non-technical reader can act on without a follow-up question, and nothing in it should be a claim you cannot back up in the technical section below.\n\n` +
        `**The trap this room is built to catch.** It is tempting to write the executive summary as a shorter version of the technical narrative — the same content, condensed. That produces a summary full of jargon-adjacent phrasing that reads as technical-lite rather than genuinely translated, and it is the single most common failure mode in real incident reports. A good executive summary is not the technical section with details removed; it is a different piece of writing, aimed at a different question — not "what exactly happened" but "what does this mean for us."`,
      diagram:
        "flowchart LR\n" +
        '  A["One Incident"] --> B["Executive Summary\\n3-6 sentences, business/risk language\\nfor leadership, legal, regulators"]\n' +
        '  A --> C["Technical Deep-Dive\\nexact fields, timestamps, hashes\\nfor remediation team, future reviewers"]\n' +
        '  B --> D["Read alone: accurate, honest, actionable"]\n' +
        '  C --> E["Read alongside B: fully reproducible reasoning"]',
      diagramCaption: "One document, two audiences, no drift between them",
      checkpoint: {
        question: "Per Reading 1, why is one report with an executive summary at the top usually preferred over two entirely separate documents?",
        options: [
          "Separate documents are harder to store on a shared drive, since most document-management systems only version-control a single file at a time",
          "Splitting into separate documents invites drift -- the executive version can quietly diverge from the technical version over revisions, which nobody notices until they're compared line by line later",
          "Executives are legally required to read the full technical report, so producing a separate summary document would fail to satisfy that requirement",
          "Two documents take longer to write than one, since the writer has to format and proofread each file separately before either can be circulated",
        ],
        answer: 1,
        explanation:
          "The risk named in Reading 1 is drift between two separately-maintained versions of the same incident. One document with an executive summary on top and technical detail below lets each audience stop where they need to, with no risk of the two versions disagreeing.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "doc-r2",
      heading: "The Anatomy of a Complete Incident Report",
      content:
        `A complete report has a fixed set of sections, each with a distinct job. Knowing what each one is actually for is what stops a report from becoming one long undifferentiated narrative that neither audience from the previous reading can use efficiently.\n\n` +
        `**Executive Summary.** Covered in the previous reading — three to six sentences, business and risk framing, sits at the very top so it's the first thing anyone opens the document to.\n\n` +
        `**Incident Overview.** A concise, plain-but-complete description of the chain of events — a few paragraphs, not a page — that a technical reader can absorb in under a minute before diving into detail: how it was initially detected, the general shape of what happened, and where things currently stand. Think of it as the bridge between the summary above and the full detail below.\n\n` +
        `**Affected Systems & Data.** A specific inventory: which hosts, which accounts, which applications, and — critically — which categories of data were reachable from those systems. This section is what a privacy or legal reviewer usually goes to directly, because it is what determines notification obligations, and it needs to be exact rather than approximate ("the AP-SRV14 export share, containing vendor payment records for Q2" rather than "some finance files").\n\n` +
        `**Evidence Sources & Analysis.** What you actually looked at, and how you reached each conclusion — which log sources, which queries, which tools, and the reasoning connecting evidence to finding. This is the methodology section, and its purpose is reproducibility: another analyst should be able to follow your exact path and reach the same conclusion.\n\n` +
        `**IOCs.** A discrete, extractable list — IP addresses, file names and paths, file hashes, scheduled task names, domains, URLs — formatted so another defender or an automated tool can search on it directly, without needing to read prose to find the values. This section lives or dies on precision: an IOC list with an approximate or paraphrased value is close to useless for anyone trying to actually hunt on it.\n\n` +
        `**Technical Timeline.** Covered in full in Reading 3 — a chronological, per-event account with formal timestamps, from initial compromise through containment, eradication and recovery.\n\n` +
        `**Root Cause.** Covered in full in Reading 5 — the specific control gap or configuration weakness that allowed the intrusion to succeed, not a restatement of what the attacker did.\n\n` +
        `**Recommendations.** Concrete, assigned, verifiable corrective actions tied directly to the root cause identified above — not a generic list of best practices that would apply to any organisation regardless of what actually happened here.\n\n` +
        `**Why this fixed structure matters more than it seems to.** A reader under time pressure — and every reader of an incident report is under time pressure — needs to be able to jump straight to the section relevant to their question. A regulator's counsel wants Affected Systems & Data. A remediation engineer wants the Timeline and Evidence Sources. A CISO preparing a board update wants the Executive Summary and Recommendations. A rigid, named structure is what makes that possible; a report that wanders through these ideas in whatever order occurred to the writer forces every reader to hunt.`,
      codeExample:
        "INCIDENT REPORT -- SECTION ANATOMY\n" +
        "=================================================================\n" +
        "1. EXECUTIVE SUMMARY          3-6 sentences. Scope, impact,\n" +
        "                              status. Business/risk language.\n" +
        "2. INCIDENT OVERVIEW          Concise chain-of-events narrative.\n" +
        "3. AFFECTED SYSTEMS & DATA    Exact hosts, accounts, apps, data\n" +
        "                              categories reachable.\n" +
        "4. EVIDENCE SOURCES &         What was checked, how, and the\n" +
        "   ANALYSIS                  reasoning behind each conclusion.\n" +
        "5. TECHNICAL TIMELINE         Per-event, formal timestamps,\n" +
        "                              compromise through recovery.\n" +
        "6. IOCs                      IPs, hashes, filenames, task names,\n" +
        "                              domains -- directly searchable.\n" +
        "7. ROOT CAUSE                 The actual control gap, not the\n" +
        "                              attacker's actions restated.\n" +
        "8. RECOMMENDATIONS            Assigned, verifiable actions tied\n" +
        "                              to the root cause above.\n" +
        "=================================================================",
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "doc-q1",
      question:
        "A draft executive summary reads: 'T1053.005 persistence was established via a scheduled task on AP-SRV14 using svc-report credentials; ATT&CK mapping and MITRE technique classification are documented in Section 5.' What is the strongest criticism of this summary?",
      options: [
        "It is too short and needs additional technical detail to be complete, including the full command-line strings and process tree Section 5 already documents",
        "It reads as technical-lite rather than genuinely translated — ATT&CK IDs and technique names are not business language, and a non-technical reader still cannot answer 'what does this mean for us' from this text alone, which is the entire purpose of the section",
        "It should not mention the affected hostname, since hostnames are always considered too sensitive for an executive summary and belong exclusively in the technical section",
        "It is fine as written, since executives at a technology-driven company should be expected to understand MITRE ATT&CK terminology as part of general business literacy",
      ],
      answer: 1,
      explanation:
        "This is precisely the trap Reading 1 named: a shortened technical sentence is not the same thing as a genuine translation. A reader with no security background gains nothing actionable from 'T1053.005' or 'ATT&CK mapping' — they still don't know whether data was exposed, whether it's contained, or how serious this is for the business, which is what an executive summary exists to answer. Length is not the flaw here; a short summary can be excellent if it's translated correctly. Hostnames are not inherently too sensitive to name in a summary when relevant to describing scope. And assuming executive readers are fluent in ATT&CK terminology is exactly the assumption that produces reports nobody outside the SOC can actually use.",
      xp: 20,
    },
    // -----------------------------------------------------------------------
    {
      type: "ordering",
      id: "doc-o1",
      heading: "Order the Sections of a Complete Incident Report",
      instructions:
        "Arrange these eight sections in the order a well-structured incident report presents them.",
      items: [
        { id: "exec", text: "Executive Summary — 3-6 sentences, business and risk language, scope/impact/status" },
        { id: "overview", text: "Incident Overview — a concise description of the chain of events" },
        { id: "timeline", text: "Technical Timeline — per-event, formal timestamps, compromise through recovery" },
        { id: "affected", text: "Affected Systems & Data — exact hosts, accounts, applications, and data categories reachable" },
        { id: "evidence", text: "Evidence Sources & Analysis — what was checked, how, and the reasoning behind each conclusion" },
        { id: "iocs", text: "IOCs — IPs, hashes, filenames, scheduled task names, domains, directly searchable" },
        { id: "rootcause", text: "Root Cause — the specific control gap or weakness that allowed the intrusion to succeed" },
        { id: "recs", text: "Recommendations — concrete, assigned, verifiable actions tied to the root cause" },
      ],
      correct_order: ["exec", "overview", "affected", "evidence", "timeline", "iocs", "rootcause", "recs"],
      explanation:
        "Executive Summary opens the document because it is what most readers open the file to find, and it must not require reading anything else first. Incident Overview follows as the bridge into technical detail — a short narrative before the specifics. Affected Systems & Data comes next because it establishes exactly what's in scope before the report explains how that scope was determined. Evidence Sources & Analysis then lays out the methodology, which the Technical Timeline builds on by presenting that same evidence in chronological order. IOCs sit after the timeline as an extractable reference list distilled from it. Root Cause comes near the end because it requires the full timeline and evidence to support its conclusion — you cannot credibly name a control gap before showing the chain of events that exposed it. Recommendations close the report because they are only meaningful once tied to the specific root cause identified immediately before them.",
      xp: 30,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "doc-r3",
      heading: "Writing IOCs and the Technical Timeline",
      content:
        `**IOCs: precision over prose.** An Indicators of Compromise section is not a paragraph describing what was found — it is a list, formatted for direct lookup. Every IOC type has a canonical form worth knowing: IP addresses written exactly, without ranges unless a range is truly what was observed; file names and full paths, not just a name in isolation, since the same filename in a legitimate location and a suspicious one are different findings entirely; scheduled task names exactly as recorded, since these are frequently searched directly against other hosts' task schedulers; file hashes, always with the algorithm labelled (SHA256 versus MD5 are not interchangeable and a hunt tool needs to know which it's matching against); and domains or URLs exactly as observed, since a single mistyped character makes the entry unsearchable. A good test for this section: could someone with no context on this incident paste each line into a search tool and get a meaningful result? If a value needs a sentence of explanation to be usable, it belongs in the timeline or evidence section, not the IOC list.\n\n` +
        `**Technical Timeline: one entry per event, each with two parts.** A formal timestamp — full date, time, and timezone, not "around 11pm" — and a short paragraph explaining what happened at that moment and what it means in the context of the intrusion. The timeline should read as a chronological account of the full lifecycle: initial compromise (how access was first gained), enumeration or reconnaissance (what the intruder learned about the environment), lateral movement (where they went from the entry point), data access or collection (what they actually reached or gathered), and then containment, eradication and recovery times — when the response actually started acting, and when each remediation step completed. That last piece is easy to forget and frequently the first thing a post-incident review asks about: how long between detection and containment, and between containment and full recovery.\n\n` +
        `**Why formal timestamps specifically, and not relative ones.** "20 minutes after the phishing email" is meaningless to a reader six months later who wasn't in the room when the email itself was time-stamped. "2026-06-02T23:14:08 UTC" is meaningful to anyone, at any point, cross-referenced against any other system's own timestamped records — and cross-referencing across systems is frequently exactly what a later reviewer, a legal team, or a regulator needs to do.\n\n` +
        `**A timeline entry, worked as an example.** "2026-06-02T23:14:08 UTC — A scheduled task named OneDriveSyncHelper was created on AP-SRV14 under the svc-report service account, configured to execute an unsigned binary from a ProgramData directory at every logon with SYSTEM-level privileges. This represents an established persistence mechanism (MITRE ATT&CK T1053.005) surviving a reboot or credential rotation on the host." Notice the shape: exact timestamp, exact facts (task name, account, privilege level, execution trigger), and one sentence of interpretation tying it to what it means for the intrusion — not speculation about intent, just a grounded statement of consequence.`,
    },
    // -----------------------------------------------------------------------
    {
      type: "matching",
      id: "doc-m1",
      heading: "Match the Content to the Section and Audience It Belongs In",
      instructions:
        "Match each type of information to the report section (and audience) it is actually written for.",
      pairs: [
        { id: "impact", left: "Business impact in dollars, current operational status, and what leadership needs to decide next", right: "Executive Summary — for leadership and legal, translated into business and risk terms, 3-6 sentences" },
        { id: "cmdline", left: "Exact command lines, registry paths, and process lineage supporting a conclusion", right: "Evidence Sources & Analysis — the methodology a technical peer can reproduce" },
        { id: "iocvalues", left: "File hashes, IP addresses, domains, and scheduled task names, listed for direct lookup", right: "IOCs — a discrete, directly searchable reference list" },
        { id: "perevent", left: "Per-event chronological entries with formal timestamps and a short interpretive paragraph each", right: "Technical Timeline — the full lifecycle from initial compromise to recovery" },
        { id: "gap", left: "The specific control gap or configuration weakness that allowed the intrusion to succeed", right: "Root Cause — answers why this was possible, not just what happened" },
        { id: "actions", left: "Concrete, assigned, verifiable actions with an owner and a target date", right: "Recommendations — the corrective actions tied to the root cause above" },
      ],
      explanation:
        "Each pair reflects both a section and the audience it primarily serves — business-and-status information belongs at the top for readers who won't go further, exact technical mechanics belong in the sections a remediation team will actually work from, and the IOC list is written for direct machine or human lookup rather than narrative reading. Misplacing any of these — putting exact command-line syntax in the executive summary, or business impact language nowhere at all — is what produces a report that fails one of its two audiences.",
      xp: 30,
    },
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "doc-la1",
      heading: "From Raw Log to Report: Extracting the Evidence",
      context:
        "You are drafting the Evidence Sources & Analysis and IOCs sections for Solstice Actuarial's incident report. The record below, from Microsoft Defender for Endpoint on AP-SRV14, is the persistence mechanism you found. Decide what belongs in each section of the report you're writing.",
      event: docScheduledTaskEvent,
      questions: [
        {
          question:
            "Which single field in this record is the correct IOC value to list under 'scheduled task names' in the IOCs section?",
          options: [
            "InitiatingProcessAccountName, since svc-report is the account that performed the action",
            "TaskName, exactly as recorded — OneDriveSyncHelper — since this is the specific, directly searchable value another defender would query their own environment's task scheduler for",
            "InitiatingProcessCommandLine in full, since the entire command line is what should be pasted into the IOC list as a single entry",
            "ReportId, since it uniquely identifies this specific detection record",
          ],
          answer: 1,
          explanation:
            "TaskName is the precise, directly searchable value this IOC category calls for — another SOC could search their own tenant for a scheduled task with this exact name. InitiatingProcessAccountName belongs in the Evidence Sources & Analysis narrative (which account performed the action) rather than the IOC list itself, which is reserved for atomic, searchable indicators. The full command line contains useful context but is not itself the kind of atomic value an IOC list is built from — the task name and the file hash extracted from within it are. ReportId is an internal record identifier local to this one detection tool and has no meaning to search for elsewhere.",
          xp: 25,
        },
        {
          question:
            "Which field should be listed as a file-hash IOC, and what critical detail must accompany it in the report so the value is actually usable?",
          options: [
            "SHA256, and it must be labelled as SHA256 specifically — a hash value with no algorithm stated is ambiguous and can't be matched correctly against another tool's hash database",
            "FolderPath, since a full path is more precise than any hash value and should be listed instead of a hash whenever both are available",
            "AccountSid, since it uniquely identifies the account regardless of hash type and is a more stable long-term identifier than any file-level indicator",
            "No labelling is needed — all hash algorithms produce values in the same fixed-length format and are interchangeable once extracted from a Defender record",
          ],
          answer: 0,
          explanation:
            "The SHA256 value is the correct hash IOC, and labelling it explicitly as SHA256 is not optional — SHA256 and MD5 values are different lengths and formats, and a hunting tool or another analyst needs to know which algorithm produced the value to match it correctly elsewhere. FolderPath is a legitimate IOC in its own right (a file path) but is a different indicator type, not a substitute for a hash. AccountSid identifies an account, not a file, and carries no hash meaning. And hash algorithms are absolutely not interchangeable — a SHA256 value pasted into an MD5 search field will never match anything.",
          xp: 25,
        },
        {
          question:
            "Drafting the technical timeline entry for this event, which of the following is written correctly per this room's standard?",
          options: [
            "'Late one night, something suspicious happened on the AP server involving a task' — vague phrasing chosen deliberately, on the reasoning that fewer specific claims means fewer things a reviewer could later dispute",
            "'2026-06-02T23:14:08 UTC — A scheduled task named OneDriveSyncHelper was created on AP-SRV14 under the svc-report account, configured to run an unsigned binary from ProgramData at every logon with SYSTEM privileges — an established persistence mechanism (T1053.005) surviving reboot or credential rotation'",
            "'This is definitely the attacker's primary backdoor and the most important finding in the entire case' — strong, decisive language chosen for maximum clarity and impact on the reader",
            "The event should be left out of the timeline entirely and only listed in the IOCs section, since the file hash by itself already captures everything a reviewer would need to know about this finding",
          ],
          answer: 1,
          explanation:
            "This is the exact shape Reading 3 modelled: a formal, unambiguous timestamp, the specific observed facts (task name, account, privilege level, execution trigger), and one grounded sentence of interpretation tied to what it means — not speculation, just consequence. The vague version fails the formal-timestamp and specific-facts requirements entirely. The dramatic version oversteps what the evidence actually supports — 'definitely the primary backdoor' and 'most important finding' are judgements the evidence doesn't establish and that a defensible report should not assert past what's shown. And the IOC list is a distilled reference extracted from findings like this one — it is not a substitute for describing the finding itself in the timeline, where the full context belongs.",
          xp: 30,
        },
      ],
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "doc-q2",
      question:
        "Three weeks after the report is submitted, you're asked why AP-SRV14 was disabled for four hours during the response. Your notes on that decision were never written down and you're relying on memory. What does this room's principle of defensibility say about that situation?",
      options: [
        "It's fine, as long as your memory of the decision is accurate, since a reviewer's job is to evaluate whether the decision itself was sound, not whether it was written down at the time",
        "An undocumented decision is, for practical and defensibility purposes, indistinguishable from a decision with no basis at all — 'if it wasn't documented, it didn't happen' means a reviewer three weeks later has no way to verify your reasoning was sound at the time, regardless of whether it actually was",
        "This only matters if the incident becomes a legal matter; for an internal-only review, memory is an acceptable substitute for contemporaneous notes since no outside party will ever scrutinize it",
        "Defensibility only applies to evidence collected from logs, not to operational decisions like disabling a host, which are judgment calls that don't require the same documentation standard",
      ],
      answer: 1,
      explanation:
        "The principle is exactly this: a decision's soundness at the time and a reviewer's ability to verify that soundness later are two different things, and only contemporaneous documentation bridges them. Being right in fact does not make an undocumented decision defensible in review — the reviewer has no way to confirm it. This distinction matters regardless of whether the incident ever becomes a formal legal matter; internal post-incident reviews rely on the same standard, because they exist precisely to check whether decisions were sound, which memory alone cannot demonstrate. And defensibility is not limited to log-derived evidence — operational decisions (isolating a host, resetting an account) are exactly the kind of judgement calls that most need a contemporaneous record explaining the reasoning behind them.",
      xp: 20,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "doc-r4",
      heading: "Defensibility, Chain of Custody, and Writing as You Go",
      content:
        `Everything in this room's report anatomy assumes the underlying facts are solid enough to survive being questioned later — by a manager, an auditor, opposing counsel in a dispute, or simply your own team six months from now trying to remember why a decision was made. That survivability has a name: defensibility, and it rests on habits that have to start during the investigation, not during the writing of the report afterward.\n\n` +
        `**"If it wasn't documented, it didn't happen."** This phrase sounds harsh, and it is meant to. A finding you remember clearly but never wrote down, timestamped, at the time you found it, cannot be distinguished later from a finding you're only now convincing yourself you made. This is not a comment on your honesty — it is a comment on what a document can prove versus what a memory can prove. A reviewer six months out has no access to your memory, only to what you wrote. Writing contemporaneously — as each fact is established, not reconstructed afterward in one sitting — is what makes the difference between a report a reviewer can trust and one they have to take on faith.\n\n` +
        `**Chain of custody, restated for the report itself.** Every piece of evidence cited in a report should be traceable to where it came from, when it was pulled, and by whom — this is the same discipline the companion investigation room teaches for evidence collection, and it belongs in the report's Evidence Sources & Analysis section explicitly, not left implicit. "The SHA256 hash was extracted from the Microsoft Defender for Endpoint DeviceFileEvents record, ReportId 51027, retrieved 2026-06-03 by [analyst]" is a chain-of-custody statement. "We found a suspicious hash" is not.\n\n` +
        `**Who/what/when/where/why/how — a checklist for every claim in the report, not just the summary.** Any factual assertion in a report should be able to answer: who was involved (account, analyst, or both), what happened (the specific observed action), when (a formal timestamp), where (host, system, or location), why it matters (the consequence for the investigation), and how you know (the evidence source). A sentence missing several of these is a sentence a reviewer will have to come back and ask about — better to answer it the first time, in writing.\n\n` +
        `**Writing for both audiences without contradicting yourself.** The discipline from Reading 1 — one document, two sections, no drift between them — is enforced by defensibility as much as by clarity: if the executive summary claims something the technical section doesn't actually support with evidence, that gap is exactly what a skeptical later reader will find first, and it undermines trust in the entire document, not just the one claim.\n\n` +
        `**A closing habit worth naming: say what you didn't check.** A report that states its own boundaries — "this scope reflects a review of the preceding 72 hours; earlier activity was not examined" — is more defensible, not less, than one that implies completeness it hasn't earned. Reviewers trust a report more, not less, when it is honest about the edges of what was actually verified.`,
      codeExample:
        "CHAIN-OF-CUSTODY LINE -- WHAT A DEFENSIBLE CITATION LOOKS LIKE\n" +
        "=================================================================\n" +
        "WEAK:   'We found a suspicious hash on the server.'\n\n" +
        "DEFENSIBLE:\n" +
        "  Source:      Microsoft Defender for Endpoint, DeviceFileEvents\n" +
        "  Record ID:   ReportId 51027\n" +
        "  Retrieved:   2026-06-03T09:40:00 UTC\n" +
        "  Retrieved by: [analyst name]\n" +
        "  Value:       SHA256 d4b8f61a2e9c5073b6a1d8f4c2e7b905a3f6c8d1b4e7a9c2f5d8b1e4a7c9f0d2\n" +
        "=================================================================\n" +
        "EVERY CLAIM SHOULD ANSWER: who / what / when / where / why / how\n" +
        "=================================================================",
      checkpoint: {
        question: "Per Reading 4, what six questions should every factual claim in a report be able to answer?",
        options: [
          "Severity, priority, confidence, impact, likelihood, and cost -- the standard six-field scoring rubric Reading 4 says every claim should be rated against before it's included",
          "Who, what, when, where, why, and how -- and a sentence missing several of these is one a reviewer will have to come back and ask about",
          "Detection method, scope, timeline, root cause, recommendations, and owner -- the six section headings Reading 2 lists for the report as a whole, applied here to individual sentences",
          "Vendor, product, version, hostname, IP, and hash -- the six technical fields Reading 4 says must accompany every claim drawn from a log record",
        ],
        answer: 1,
        explanation:
          "The checklist is who/what/when/where/why/how -- applied to every factual claim in the report, not just the summary, so a reviewer never has to come back and ask a basic question the report should already have answered.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "doc-ac1",
      heading: "Before It Goes in the Report: Verify This Candidate IOC",
      scenario:
        "While assembling the IOCs and Affected Systems sections, you find a second Entra ID sign-in during the same overnight window as the scheduled task discovery — an administrative account, from an unfamiliar-looking hour, authenticating to the Azure Portal. It looks exactly like the kind of second foothold this room has taught you to hunt for. Before it goes anywhere near your IOC list or timeline, verify it.",
      event: docLegitimateAdminEvent,
      correct_verdict: "false_positive",
      explanation:
        "This sign-in should not appear in the report as a finding or an IOC. it_verify_result is confirmed, tied explicitly to change ticket CHG-2291 authorising d.whitfield to perform a scheduled patch deployment against AP-SRV14 during exactly this window. The IPAddress matches the corporate VPN's registered static address, ConditionalAccessStatus reads success with multiFactorAuthentication satisfied, the device is both compliant and managed, and RiskLevelDuringSignIn is none. Every field that would support escalation instead supports a routine, ticketed maintenance action. Writing this up as a second foothold would put a false finding into a document meant to be defensible — and once a reviewer catches one unverifiable or wrong claim in a report, they reasonably start questioning every other claim in it too.",
      fp_trap:
        "An admin account authenticating at an odd hour, on the very night a persistence mechanism was found on the exact same server, is precisely the coincidence that should raise your guard — and the instinct to write it up as a related finding is not unreasonable on its face. But 'looks related' is not the same as 'is confirmed related,' and this room's whole point about defensibility is that a report's credibility depends on verifying before writing, not writing and hoping it holds up. The it_verify_result and it_verify_message fields exist precisely so this verification step doesn't rely on you personally happening to know about CHG-2291 — they are the record that this was checked. Skipping that check and including the finding anyway is the exact mistake a defensible report process is built to prevent.",
      xp: 35,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "doc-r5",
      heading: "Root Cause and Recommendations: From Vague to Actionable",
      content:
        `The companion investigation room introduced "5 Whys" as an investigative technique for finding root cause. This reading is about the specific discipline of writing that root cause down in a way a reader can act on — because a correct root cause, badly written, is nearly as useless to the reader as no root cause at all.\n\n` +
        `**The failure mode: vague causes that restate the attack instead of explaining the gap.** "The intrusion occurred because a scheduled task was created for persistence" describes what the attacker did — it is a restatement of the Technical Timeline, not a root cause. It gives a Recommendations section nothing to work with, because there is no actual control failure named to fix. "Human error" is the other common version of the same failure: it sounds like an explanation but names no specific, correctable gap, and it tends to unfairly concentrate blame on an individual for a failure that was actually organisational — a control that should have stopped the outcome regardless of the individual action that triggered it.\n\n` +
        `**What a written root cause needs to contain.** Not what the attacker did, but what allowed it to succeed: which specific control was missing, misconfigured, or not enforced, and — where relevant — why that gap existed (a process failure, a rollout that never reached this system, a monitoring blind spot). For the Solstice case: not "an attacker created a scheduled task," but "the svc-report service account held local administrative rights on AP-SRV14 that were broader than its function required, and no change-detection alerting existed for scheduled task creation under service accounts on servers in this tier — a gap that let a persistence mechanism run undetected for eleven days." That sentence names an actual, fixable thing: the account's excess privilege, and the missing detection coverage.\n\n` +
        `**Recommendations have to trace back to that specific root cause, one for one.** A recommendations section padded with generic best-practice advice ("improve security awareness training," "patch systems regularly") that isn't tied to what actually failed here reads as filler, and worse, it lets the actual gap go unaddressed while looking like the report did its job. Against the root cause above, the correct recommendations are specific: review and reduce svc-report's privilege level to only what its function requires; deploy detection logic for scheduled task creation events involving service accounts on Tier 1 servers; audit other service accounts on this server tier for the same excess-privilege pattern. Each one is concrete, assignable to an owner, and verifiable — someone can check, later, whether it was actually done.\n\n` +
        `**Why this section is often the most consequential part of the whole report, even though it's usually the shortest.** The Executive Summary gets read the most, but Root Cause and Recommendations are what determines whether this exact incident happens again. A report that nails the timeline and IOCs but writes a vague root cause has done excellent forensic work and still left the organisation exactly as exposed as before the incident started.`,
      checkpoint: {
        question: "Why does Reading 5 single out 'human error' as a failure mode for a root cause statement, alongside vague restatements of the attack?",
        options: [
          "Because human error is never actually a factor in real intrusions, so citing it as a cause is factually incorrect in every case, not just an unhelpfully vague one",
          "Because it sounds like an explanation but names no specific, correctable gap, and tends to unfairly concentrate blame on an individual for a failure that was actually organisational",
          "Because 'human error' is a term reserved exclusively for safety incidents, not security incidents, and using it here is simply the wrong vocabulary for this document type",
          "Because naming human error always triggers a legal disclosure requirement that the SOC would rather avoid creating in the first place",
        ],
        answer: 1,
        explanation:
          "'Human error' sounds like a cause but isn't actionable -- it names no specific fixable gap, and it shifts blame onto an individual for something a missing organizational control should have stopped regardless of which person triggered it.",
      },
    },
    // -----------------------------------------------------------------------
    {
      type: "query_fill",
      id: "doc-qf1",
      heading: "Write It Yourself: Pulling the Evidence Cited in the Timeline",
      language: "kql",
      context:
        "Before the Technical Timeline entry for the scheduled task can be written, you need the query that actually produced the evidence you're about to cite in Evidence Sources & Analysis. Fill in the host and the action type from the case.",
      template:
        "DeviceEvents\n| where DeviceName == \"{{host}}\"\n| where ActionType == \"{{action}}\"\n| project Timestamp, InitiatingProcessAccountName, InitiatingProcessCommandLine",
      blanks: [
        { id: "host", answers: ["AP-SRV14"], placeholder: "affected host" },
        { id: "action", answers: ["ScheduledTaskCreated"], placeholder: "Defender ActionType for task creation" },
      ],
      explanation:
        "This is the exact query whose output becomes both the Evidence Sources & Analysis citation and the basis for the Technical Timeline entry — DeviceName scopes it to the affected host, and ActionType ScheduledTaskCreated is the specific Defender for Endpoint action type for this persistence mechanism. Writing the query into the report's methodology section, not just its result, is what makes the finding reproducible by another analyst.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "doc-q3",
      question:
        "A draft Recommendations section reads: 'Improve overall security awareness training' and 'Patch systems regularly,' with no reference to anything specific from this incident. What is the correct criticism, based on this room?",
      options: [
        "These are strong recommendations because they are broadly applicable to any organization, and broad applicability is exactly what makes a recommendation valuable in a report",
        "These recommendations don't trace back to the specific root cause identified in this incident — they read as generic filler that lets the actual gap (in this case, excess service-account privilege and missing detection coverage) go unaddressed while making the report look complete",
        "Recommendations should never mention training or patching under any circumstances, regardless of the incident, since those two categories are considered out of scope for any SOC report by convention",
        "This is fine as long as the Root Cause section above it is written well, since Recommendations are read independently and don't need to connect to it directly",
      ],
      answer: 1,
      explanation:
        "Reading 5 was direct about this: recommendations that aren't tied to the specific, actual root cause read as filler, and worse, they create the appearance of a resolved finding while the real gap sits unaddressed. Being broadly applicable is exactly the problem, not a strength — a recommendation that would apply to any organization regardless of what happened here isn't doing the job of this specific report. Training or patching recommendations aren't categorically wrong; they're wrong here because nothing in this case's root cause was about awareness or missing patches. And recommendations are supposed to trace directly back to root cause, one for one — treating them as unconnected sections defeats the purpose of naming a root cause at all.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "flag",
      id: "doc-f1",
      prompt:
        "You are finalising the IOCs section. What is the exact scheduled task name that should be listed, taken directly from the TaskName field in the raw log?",
      answer: "OneDriveSyncHelper",
      xp: 20,
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "doc-q4",
      question:
        "A reviewer asks why your Technical Timeline states 'no activity beyond AP-SRV14 was identified' rather than 'no activity beyond AP-SRV14 occurred.' Why does this room's approach to defensibility prefer the first phrasing?",
      options: [
        "There is no meaningful difference between the two phrasings, and either is equally acceptable in a report since both convey the same finding to the reader",
        "The first phrasing accurately states the boundary of what was actually searched and found, while the second asserts a fact about the entire environment that the investigation cannot actually prove — only what was checked, and what that check found, can be honestly claimed",
        "The second phrasing should always be preferred, since a confident report is more useful to leadership than a hedged one, even when that confidence outruns what the evidence actually supports",
        "This distinction only matters for reports that will be reviewed by outside legal counsel, and can be safely ignored for reports staying entirely inside the SOC",
      ],
      answer: 1,
      explanation:
        "This is the same discipline both rooms return to: a scope claim is only as strong as what was actually searched for, and 'identified' honestly reflects that boundary, while 'occurred' claims a fact about the whole environment the investigation never actually verified. A report that overstates its own certainty is less defensible, not more useful — a reviewer who later finds activity the report claimed didn't exist has just found a reason to distrust every other claim in the document too. Confidence is not the same virtue as accuracy in a report meant to be reviewed later. And this distinction matters for every reader of the report, not only outside counsel — an internal remediation team acting on an overstated scope claim can just as easily miss something real.",
      xp: 25,
    },
  ],
};

export const roomsBatch29 = [investigateAlertRoom, writingIncidentReportRoom];
