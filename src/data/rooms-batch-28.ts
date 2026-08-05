/**
 * Learning Rooms — Batch 28
 *
 * One deep, capstone-style room on the single most common real SOC workflow
 * that no prior room walks end to end: receiving an EDR detection and
 * actually investigating it — process tree, hash pivot, sibling-alert
 * merging, severity reassessment, scoping, verdict, containment.
 *
 * Room in this batch:
 *  1. edr-detection-investigation — CrowdStrike Falcon + Microsoft Defender
 *     for Endpoint fields (Tactic, Technique, SeverityName,
 *     PatternDispositionDescription, ContextProcessName, CommandLine,
 *     SHA256HashData, GrantedAccess, CallStackModuleNames, mde.* equivalents),
 *     the six-step investigation workflow, process-tree anomaly reading,
 *     sibling-alert / IncidentId correlation, and severity reassessment
 *     (tool severity vs. analyst verdict).
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Investigating an EDR Detection, End to End
// ===========================================================================

const lsassAccessEvent: TelemetryEvent = {
  id: "evt-edr-la1-001",
  ts: "2026-02-12T14:38:52.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_access",
  severity: "critical",
  hostname: "WKS-FIN-0231",
  user_email: "r.callahan@nexacorp.com",
  mitre_technique: "T1003.001",
  mitre_tactic: "Credential Access",
  description:
    "Falcon flagged a process requesting full access to lsass.exe on a finance workstation. This is the third correlated behavior logged against this host in the last twenty-two minutes.",
  process: {
    name: "UpdateHelper.exe",
    pid: 6620,
    path: "C:\\Users\\r.callahan\\AppData\\Local\\Temp\\UpdateHelper.exe",
    parent_name: "explorer.exe",
    parent_pid: 2244,
    cmdline: "\"UpdateHelper.exe\"",
    user: "NEXACORP\\r.callahan",
    hash: {
      sha256: "b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessAccess",
    "crowdstrike.DetectId": "ldt:9f2ab6c4de3f4a1c8b7e2d5f0a9c3b6e:88213",
    "crowdstrike.IncidentId": "inc:9f2ab6c4de3f4a1c8b7e2d5f0a9c3b6e:20260212",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Credential Access",
    "crowdstrike.Technique": "OS Credential Dumping",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "explorer.exe",
    "crowdstrike.ParentProcessName": "explorer.exe",
    "crowdstrike.FileName": "UpdateHelper.exe",
    "crowdstrike.FilePath": "C:\\Users\\r.callahan\\AppData\\Local\\Temp\\UpdateHelper.exe",
    "crowdstrike.CommandLine": "\"UpdateHelper.exe\"",
    "crowdstrike.SHA256HashData": "b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a",
    "crowdstrike.TargetProcessName": "lsass.exe",
    "crowdstrike.GrantedAccess": "0x1FFFFF",
    "crowdstrike.CallStackModuleNames": "dbghelp.dll,KERNELBASE.dll,ntdll.dll",
    "crowdstrike.UserName": "NEXACORP\\r.callahan",
    "crowdstrike.HostName": "WKS-FIN-0231",
    "event.action": "process-access",
    "event.outcome": "success",
  },
};

const regsvr32DeploymentEvent: TelemetryEvent = {
  id: "evt-edr-ac1-001",
  ts: "2026-02-03T15:10:04.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "SRV-DEPLOY-07",
  user_email: "svc-sccm@nexacorp.com",
  mitre_technique: "T1218.010",
  mitre_tactic: "Defense Evasion",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG0052291 authorizes NexaDeploy's scheduled rollout of ReportViewerCtl.dll to finance-team workstations during this maintenance window. svc-sccm is the deployment service account used for all NexaDeploy software pushes.",
  description:
    "Falcon flagged a regsvr32.exe execution on an application deployment server, matching a known Signed Binary Proxy Execution pattern.",
  process: {
    name: "regsvr32.exe",
    pid: 5104,
    path: "C:\\Windows\\System32\\regsvr32.exe",
    parent_name: "cmd.exe",
    parent_pid: 3388,
    cmdline: "regsvr32.exe /s C:\\ProgramData\\NexaDeploy\\Modules\\ReportViewerCtl.dll",
    user: "NEXACORP\\svc-sccm",
    hash: {
      sha256: "3c9f81a46b2d0e758f1a3c6d9e0b4f275a8d3c61e97f0b426c1a9d38f04e7b25",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:7b2f4c1a9e6d3f082b5c7a1e4d9f6b03:55102",
    "crowdstrike.IncidentId": "inc:7b2f4c1a9e6d3f082b5c7a1e4d9f6b03:20260203",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Defense Evasion",
    "crowdstrike.Technique": "Signed Binary Proxy Execution",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "cmd.exe",
    "crowdstrike.ParentProcessName": "cmd.exe",
    "crowdstrike.FileName": "regsvr32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\System32\\regsvr32.exe",
    "crowdstrike.CommandLine": "regsvr32.exe /s C:\\ProgramData\\NexaDeploy\\Modules\\ReportViewerCtl.dll",
    "crowdstrike.SHA256HashData": "3c9f81a46b2d0e758f1a3c6d9e0b4f275a8d3c61e97f0b426c1a9d38f04e7b25",
    "crowdstrike.UserName": "NEXACORP\\svc-sccm",
    "crowdstrike.HostName": "SRV-DEPLOY-07",
    "event.action": "process-create",
    "event.outcome": "success",
  },
};

const edrDetectionInvestigationRoom = {
  id: "edr-detection-investigation",
  title: "Investigating an EDR Detection — End to End",
  description:
    "Follow one EDR detection from the moment it lands to the moment a host is contained. Covers CrowdStrike Falcon and Microsoft Defender for Endpoint fields (Tactic, Technique, SeverityName, PatternDispositionDescription, ContextProcessName, CommandLine, SHA256HashData, GrantedAccess, CallStackModuleNames), how to read a process tree for parent-child anomalies and LOLBins, why sibling behavioral alerts on the same host need to be merged before triage, why a tool's own severity rating is never the analyst's verdict, and the full pivot-scope-contain workflow real investigations actually run.",
  difficulty: "advanced" as const,
  category: "Endpoint Security",
  estimatedMinutes: 75,
  xp: 460,
  icon: "🔎",
  prerequisites: ["endpoint-security-fundamentals", "crowdstrike-falcon"],
  tasks: [
    // ── Reading 1: EDR depth vs SIEM summary ────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r1",
      heading: "Why the Detection Is the Doorway, Not the Whole Story",
      content:
        "A SIEM alert is almost always a one-line summary assembled from fragments of many different systems — a bit like a building manager who receives a single note from a hundred different properties: 'motion detected, third floor, 2:14 AM.' An EDR agent is the actual camera system installed inside one specific building, recording everything that happens there in detail: who came in, which door, what they carried, who they spoke to, and where they went next. When enough of those one-line notes get correlated into an alert worth investigating, a good analyst doesn't stop at the note. They open the camera system for that one building and watch what actually happened.\n\n" +
        "**What EDR telemetry actually contains.** The agent sitting on an endpoint sees the full causal chain of a process: its parent, its parent's parent, the exact command-line arguments it ran with, whether its binary was signed and by whom, every file it created or deleted, every registry key it touched, and every network or DNS request it personally made — not just 'the host', but that specific process. For the most sensitive category of activity, it also sees one process reaching into another process's memory space, an action ordinary logs never capture at all.\n\n" +
        "**Why this is fundamentally different from a firewall log or a single Windows event.** A firewall only sees packets crossing a boundary — it has no idea which process on either end generated them. A single Windows Security event captures one action in isolation, with no causal thread connecting it to what happened a minute before or after. The EDR agent, because it sits on the endpoint itself, is the one source that sees the entire chain as one continuous story: what launched what, with what arguments, and what happened immediately around it.\n\n" +
        "**The habit this creates.** An experienced analyst treats every EDR detection as an entry point into a much richer dataset, never as a self-contained verdict. The vendor's console — the Falcon UI, the Microsoft Defender Security Center, whichever platform is in front of you — is where the actual investigation happens: expanding the process tree, pulling the full command line, checking the file's hash, and reading what else that same process (and that same host) did in the minutes around the flagged action. A detection that arrives with a severity label and a technique name is the beginning of the work, not the end of it.\n\n" +
        "**What this room does.** Every reading, question, and task from here follows one real detection from the moment it lands in the console to the moment a host gets contained — teaching the exact fields you'd actually read and the exact reasoning you'd actually apply at each step, in the order a real investigation runs.",
    },
    // ── Reading 2: field anatomy across CrowdStrike + MDE ───────────────────
    {
      type: "reading" as const,
      id: "edr-r2",
      heading: "Anatomy of a Detection: The Fields That Actually Carry the Story",
      content:
        "Every major EDR platform reduces 'what happened' down to a specific, learnable set of fields. Reading them fluently — instead of skimming a detection's title and severity color — is the actual difference between an analyst who investigates and one who just reacts to labels.\n\n" +
        "**CrowdStrike Falcon's core fields.** Tactic and Technique are the MITRE ATT&CK category and specific method Falcon's behavioral engine matched — useful for framing what kind of goal the activity serves, but not a verdict by itself, since a single technique like Signed Binary Proxy Execution fires just as reliably against a benign internal deployment script as against a real attacker. SeverityName is Falcon's own automatic rating (Critical, High, Medium, Low), assigned the instant the behavior pattern matches — before any human has added context, which is exactly why Reading 6 later spends a full reading on why this field is not the analyst's final word. PatternDispositionDescription answers a different, sharper question: what did Falcon actually do about it. A value like 'Detected, no action taken' means the behavior was only observed; 'Prevented' or 'Detected, kill process' means Falcon actually intervened. Severity tells you how seriously the tool rated the pattern; PatternDispositionDescription tells you whether the potentially malicious action already ran to completion.\n\n" +
        "**The process-identity fields.** ContextProcessName and ParentProcessName identify the process that launched the one being flagged — one link of the process tree, readable without opening the full graphical view. CommandLine is the exact string of arguments the flagged process executed with, including any Base64 encoding, unusual file paths, or suspicious destination arguments. FileName, FilePath, and SHA256HashData identify the specific binary, where it lives on disk, and its cryptographic fingerprint — the fingerprint being the single most useful field for pivoting entirely outside the console, into hash-reputation lookups and fleet-wide hunting, which Reading 7 builds on directly.\n\n" +
        "**Microsoft Defender for Endpoint's equivalents.** The underlying questions are identical; only the field names change. mde.AlertTitle and mde.Category summarize what fired and its broad classification. mde.InitiatingProcessFileName and mde.InitiatingProcessCommandLine are Defender's version of ContextProcessName and CommandLine. mde.SHA256 and mde.DeviceName complete the identification, and mde.DetectionSource tells you which Defender component — the EDR behavioral engine, the antivirus scanning engine, or another — actually generated the alert in the first place.\n\n" +
        "**Why this matters before anything else in the room.** Whichever vendor's console is open in front of you, the questions are the same: what ran, launched by what, with what exact arguments, identified by what hash, and what did the tool actually do in response. Every later reading in this room builds directly on top of these fields.",
      codeExample:
        "CrowdStrike Falcon                         Microsoft Defender for Endpoint\n" +
        "-----------------------------------------------------------------------\n" +
        "Tactic / Technique                          mde.Category\n" +
        "SeverityName                                mde.AlertTitle (severity is a sibling field)\n" +
        "PatternDispositionDescription                mde.DetectionSource\n" +
        "ContextProcessName / ParentProcessName        mde.InitiatingProcessFileName\n" +
        "CommandLine                                  mde.InitiatingProcessCommandLine\n" +
        "FileName / FilePath                          mde.InitiatingProcessFolderPath\n" +
        "SHA256HashData                               mde.SHA256\n" +
        "HostName                                     mde.DeviceName\n" +
        "IncidentId                                   mde.IncidentId",
    },
    // ── Question 1 — severity is not the verdict (conceptual) ───────────────
    {
      type: "question" as const,
      id: "edr-q1",
      question:
        "A CrowdStrike detection fires with crowdstrike.SeverityName: 'Critical' and crowdstrike.Tactic: 'Defense Evasion', tagged for a well-known LOLBin technique pattern. Based on Reading 2, what is the correct way to treat the SeverityName field at this stage of the investigation?",
      options: [
        "Treat it as the final verdict — Critical severity means the detection is automatically a confirmed compromise requiring no further review",
        "Treat it as the tool's own automatic rating, assigned the instant the technique pattern matched — useful for prioritizing your queue, but not a substitute for reading the process tree and surrounding context yourself",
        "Ignore the field entirely, since severity ratings carry no useful information in any EDR platform",
        "Treat it as proof the malicious action was already blocked, since higher severity always means the tool intervened automatically",
      ],
      answer: 1,
      explanation:
        "Reading 2 was explicit: SeverityName is assigned the moment a behavior pattern matches, before any human has added organizational context — it's a prioritization signal, not a verdict. Whether the tool actually intervened is a separate question answered by PatternDispositionDescription, not SeverityName, which is exactly why option d is wrong. Severity is far from useless (option c) — it's just not sufficient on its own, which is the entire point of this room's workflow.",
      xp: 25,
    },
    // ── Matching: fields to meaning ──────────────────────────────────────────
    {
      type: "matching" as const,
      id: "edr-m1",
      heading: "Match the EDR Field to What It Actually Tells You",
      instructions: "Match each CrowdStrike Falcon / Microsoft Defender field to what it records or reveals during an investigation.",
      pairs: [
        { id: "context", left: "ContextProcessName / ParentProcessName", right: "The process that launched the one being flagged — one link of the process tree, without opening the full graphical view" },
        { id: "cmdline", left: "CommandLine", right: "The exact arguments the flagged process ran with, including any encoding or unusual destination paths" },
        { id: "hash", left: "SHA256HashData", right: "The binary's cryptographic fingerprint — the field used to pivot into hash-reputation lookups and fleet-wide hunting" },
        { id: "tactic", left: "Tactic", right: "The MITRE ATT&CK category describing the broad adversary goal behind the matched behavior pattern" },
        { id: "technique", left: "Technique", right: "The specific ATT&CK method the matched behavior pattern corresponds to" },
        { id: "severity", left: "SeverityName", right: "The tool's own automatic severity rating, assigned the instant the pattern matched, before any analyst has added context" },
        { id: "disposition", left: "PatternDispositionDescription", right: "What the tool actually did in response — merely observed the behavior, or actually stopped it" },
        { id: "granted", left: "GrantedAccess", right: "The Windows access mask a process requested against another process's handle — 0x1FFFFF is full control" },
        { id: "callstack", left: "CallStackModuleNames", right: "The DLLs loaded in the call stack at the moment of access, revealing the specific mechanism used — e.g., dbghelp.dll pointing at MiniDumpWriteDump" },
      ],
      explanation:
        "Notice that no single field in this list determines a verdict by itself. Severity tells you priority, not truth; disposition tells you whether the tool intervened, not whether the underlying activity was malicious; the hash gives you an outside pivot, not a conclusion. Reading a detection fluently means reading all of these together, which is exactly the habit the rest of this room builds.",
      xp: 35,
    },
    // ── Reading 3: the six-step workflow ────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r3",
      heading: "The Investigation Workflow: Six Steps From Detection to Verdict",
      content:
        "Every field in Reading 2 matters, but reading them well only gets you through step one of an actual investigation. A real EDR case runs through six distinct phases, and skipping straight from 'I read the detection' to 'here's my verdict' is the single most common mistake an analyst makes — because the detection alone almost never contains enough context to separate malicious from benign.\n\n" +
        "**Step one: read the detection.** Technique, severity, and pattern disposition — exactly what Reading 2 covered — give you the starting shape of what the tool believes happened and whether it thinks it stopped anything.\n\n" +
        "**Step two: expand the process tree.** Pull the full chain — parent, grandparent, and further back if the console shows it — along with the complete command line and file hash for every link in that chain. Reading 4 builds this skill in depth: this is where parent-child anomalies and LOLBin abuse actually reveal themselves.\n\n" +
        "**Step three: pivot outward.** Take the file hash to a reputation source, check what network or DNS activity the process made, and check what files it created or modified afterward. Reading 7 covers this pivot in full.\n\n" +
        "**Step four: scope across the fleet.** Ask whether the same hash or the same behavior pattern has touched any other host in the environment — the single question that turns 'one workstation has a problem' into either 'good, it's contained' or 'this is bigger than the first detection suggested.'\n\n" +
        "**Step five: decide the verdict.** Only now, with the tree expanded, the hash checked, and the scope understood, does deciding true positive versus false positive actually mean something — informed by context, not by the tool's severity label alone. Readings 5 and 6 build the two specific skills this step depends on: merging sibling alerts, and reassessing severity in context.\n\n" +
        "**Step six: contain and remediate.** Isolate the host, kill the malicious process, and — if credential material may have been exposed — treat any credentials on that host as compromised pending rotation.\n\n" +
        "**Why the order itself matters, not just the six items.** Pivoting or scoping before you've even expanded the tree wastes effort chasing the wrong process or the wrong hash entirely. Deciding a verdict before scoping means you might close an incident that's still quietly active on three other hosts. Containing a host before you've scoped the rest of the environment can mean acting on incomplete information — cutting off the one host you found while missing others you haven't looked for yet. The ordering task that follows asks you to reconstruct this exact sequence yourself.",
      diagram:
        "flowchart LR\n" +
        "  A[1. Read the detection] --> B[2. Expand the process tree]\n" +
        "  B --> C[3. Pivot outward: hash, network, files]\n" +
        "  C --> D[4. Scope across the fleet]\n" +
        "  D --> E[5. Decide the verdict]\n" +
        "  E --> F[6. Contain and remediate]\n",
      diagramCaption: "The six-step EDR investigation workflow",
    },
    // ── Ordering: the six-step workflow ──────────────────────────────────────
    {
      type: "ordering" as const,
      id: "edr-o1",
      heading: "Order the EDR Investigation Workflow",
      instructions: "Arrange these steps in the order a real EDR investigation should actually run.",
      items: [
        { id: "read", text: "Read the detection itself: technique, severity, and what the tool's pattern disposition says it actually did" },
        { id: "tree", text: "Expand the full process tree: parent, grandparent, command lines, and file hashes" },
        { id: "pivot", text: "Pivot outward: check hash reputation, network/DNS activity, and any files created or modified" },
        { id: "scope", text: "Scope across the fleet: has this hash or behavior appeared on any other host" },
        { id: "verdict", text: "Decide the verdict: true positive or false positive, based on context — not on severity alone" },
        { id: "contain", text: "Contain and remediate: isolate the host, kill the process, rotate any credentials that may be exposed" },
      ],
      correct_order: ["read", "tree", "pivot", "scope", "verdict", "contain"],
      explanation:
        "Reading 3 walked through exactly why this order matters: pivoting or scoping before expanding the tree risks chasing the wrong process entirely; deciding a verdict before scoping can close an incident that's still active elsewhere; containing before scoping risks acting on an incomplete picture of what's actually compromised. Each step depends on information the previous one produced.",
      xp: 30,
    },
    // ── Reading 4: process tree anomalies ────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r4",
      heading: "Reading the Process Tree: Parents, Children, and the Anomalies That Matter",
      content:
        "Every process has a parent — the process that launched it — and tracing that chain backward tells you the real story of how something started running, not just the fact that it ran. Most parent-child pairings are completely unremarkable: explorer.exe launching a user-opened application, svchost.exe hosting a Windows service, outlook.exe opening an attachment in Word. The skill this reading builds is recognizing the specific pairings and patterns that essentially never occur in legitimate business use.\n\n" +
        "**The anomaly that matters most: an Office application spawning a shell or scripting engine.** WINWORD.EXE, EXCEL.EXE, or OUTLOOK.EXE launching powershell.exe, cmd.exe, or wscript.exe is a pairing that has no legitimate business reason to exist — Word does not need to open PowerShell to display a document. When a process tree shows this exact pairing, it is the classic signature of a malicious macro firing its payload the moment a user enabled macro content on a phishing attachment. The chain itself, before any hash lookup, is already strong evidence.\n\n" +
        "**LOLBins: legitimate tools abused for something else.** rundll32.exe, regsvr32.exe, mshta.exe, and certutil.exe are all signed, legitimate Windows utilities that can be abused for purposes other than their intended one — this is why they're called Living-off-the-Land Binaries. None of them is inherently malicious; what matters is the combination of parent process, command-line arguments, and destination. rundll32.exe launched by cmd.exe with an argument referencing comsvcs.dll and a target of lsass.exe is a well-documented credential-dumping pattern. The exact same binary, launched by a signed software installer with a routine DLL-registration argument pointing at an internal application path, is completely ordinary — the file name tells you almost nothing on its own; the full command line and parent process tell you nearly everything.\n\n" +
        "**Process injection: when the anomaly isn't in the parent-child chain at all.** Sometimes the suspicious activity is one process reaching directly into a second, entirely unrelated process's memory — with no parent-child relationship between the two whatsoever. EDR telemetry captures this as an access event: an 'accessing' process requesting a handle to a 'target' process, with an access mask like GrantedAccess 0x1FFFFF granting full control. The anomaly here is the handle access itself, together with what's loaded in the accessing process's call stack at that exact moment — which is precisely what the CallStackModuleNames field, covered in this room's log analysis task, is built to reveal.\n\n" +
        "**The three questions a process tree should always answer.** Does this specific parent-child pairing happen anywhere in legitimate business use? Does the command line contain anything that shouldn't need to be there — encoding, an unusual path, an unexpected destination file? And is there any sensitive object being touched — another process's memory, LSASS, a domain controller's credential store — that has no legitimate reason to be reached by this particular chain at all?",
      codeExample:
        "Example tree read as a chain, not isolated events:\n\n" +
        "OUTLOOK.EXE (user opened attachment)\n" +
        "  -> WINWORD.EXE (attachment rendered, macro enabled)\n" +
        "      -> powershell.exe -EncodedCommand SQBuAHYAbwBr...\n" +
        "          -> outbound connection to an unfamiliar domain\n\n" +
        "Read top to bottom: each link alone might look explainable.\n" +
        "Read as one chain, the WINWORD -> powershell link is the anomaly\n" +
        "that essentially never occurs in ordinary business use.",
    },
    // ── Question 2 — parent-child anomaly ────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q2",
      question:
        "A process tree shows OUTLOOK.EXE launching WINWORD.EXE after a user opened an email attachment, which then launches powershell.exe with an encoded command-line argument. Based on Reading 4, what is the correct read of this chain?",
      options: [
        "Routine — Word frequently needs to launch PowerShell to render document formatting correctly",
        "This is the classic malicious-macro pattern: an Office application spawning a scripting engine essentially never happens in legitimate use, and the encoded PowerShell argument on top of it strengthens the case further",
        "Nothing meaningful can be concluded until the file's SHA256 hash comes back flagged in a threat intelligence feed",
        "The chain is irrelevant, because OUTLOOK.EXE launching WINWORD.EXE to open an attachment is itself already the malicious action",
      ],
      answer: 1,
      explanation:
        "Reading 4 was direct about this exact pairing: Word has no legitimate reason to spawn PowerShell, and an encoded argument on top of that pairing reinforces the read further. Opening an attachment in Word (OUTLOOK.EXE to WINWORD.EXE) is itself completely routine, which is why option d overclaims. And Reading 4 was explicit that the tree anomaly itself is already strong evidence — hash reputation is a later pivot step (Reading 7), not a prerequisite for recognizing what this chain already shows.",
      xp: 25,
    },
    // ── Log Analysis: LSASS process-tree investigation ──────────────────────
    {
      type: "log_analysis" as const,
      id: "edr-la1",
      heading: "Process Tree Investigation: A Credential Access Detection on a Finance Workstation",
      context:
        "NexaCorp's Falcon console fires a Critical-severity behavioral detection on WKS-FIN-0231, a finance analyst's workstation. This is the third behavior logged against this host in the past twenty-two minutes, all three sharing the same crowdstrike.IncidentId. The first behavior was a scheduled-task creation and the second a PowerShell download from an external site, both tagged Medium severity by Falcon. Review the third behavior below, then reason through the process tree and surrounding fields the way a real investigation would.",
      event: lsassAccessEvent,
      questions: [
        {
          question:
            "crowdstrike.FilePath shows the flagged binary running from a user's AppData\\Local\\Temp folder, launched directly under explorer.exe (crowdstrike.ContextProcessName), and crowdstrike.FileName suggests a routine update utility. What should this combination make you want to check first, based on the process-tree reasoning in Reading 4?",
          options: [
            "Nothing — explorer.exe launching any process is always completely routine and needs no further review",
            "Whether this specific file is actually a signed, known update utility installed on this machine, or an unsigned binary using a generic name to blend in — the file name alone is not evidence either way",
            "The file name alone confirms this is legitimate update software, since real malware never uses names that sound like routine utilities",
            "The file path alone confirms this is malicious, since Temp folders are used exclusively by attackers",
          ],
          answer: 1,
          explanation:
            "explorer.exe is the normal parent for anything a user launches directly, so that link alone isn't the anomaly — but that doesn't mean nothing needs checking, which is why option a goes too far. A plausible-sounding file name proves nothing on its own (masquerading as a routine utility is a well-known tactic), and Temp/AppData folders legitimately host countless installers and browser downloads too, so option d overclaims just as much as option c does. The correct habit is checking whether this specific binary is actually signed and known-good — exactly the pivot the rest of this task performs.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.TargetProcessName reads lsass.exe and crowdstrike.GrantedAccess reads 0x1FFFFF. What does this access mask represent, and why is it significant against this specific target?",
          options: [
            "0x1FFFFF is a Windows error code meaning the access attempt was denied",
            "0x1FFFFF is PROCESS_ALL_ACCESS — full control over the target process — and against lsass.exe, the process holding Windows credential material in memory, that level of access is exactly what a credential-dumping tool needs to read and extract it",
            "0x1FFFFF only applies to Windows services and has no relevance when the target is a process like lsass.exe",
            "GrantedAccess values are internal sensor noise with no operational meaning for an analyst",
          ],
          answer: 1,
          explanation:
            "0x1FFFFF is the PROCESS_ALL_ACCESS mask — full control over the target process's handle. LSASS specifically stores credential material (NTLM hashes, Kerberos tickets, sometimes plaintext passwords), so full access to it is the access level credential-dumping tools like Mimikatz require. GrantedAccess isn't an error code and isn't service-specific — it's a directly meaningful field for exactly this kind of triage.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.CallStackModuleNames lists dbghelp.dll among the modules loaded at the moment of the LSASS access. Why does this specific detail matter on top of the GrantedAccess value alone?",
          options: [
            "dbghelp.dll is loaded by every Windows process at all times, so its presence here carries no meaning",
            "dbghelp.dll contains the MiniDumpWriteDump function used to create process memory dumps — its presence in the call stack of a process requesting full access to lsass.exe is consistent with the exact mechanism Mimikatz-style credential dumpers use, though the same DLL is also loaded by legitimate diagnostic and crash-dump tools",
            "dbghelp.dll is a networking library, indicating the process was about to exfiltrate data over the network",
            "The presence of any DLL in CallStackModuleNames automatically confirms the detection is a false positive",
          ],
          answer: 1,
          explanation:
            "dbghelp.dll's role in producing memory dumps is exactly why its presence alongside a full-access LSASS request lines up with known credential-dumping mechanics. The reading is careful to note the dual nature of this signal: legitimate diagnostic tooling creating a crash dump can load the same DLL, which is precisely why this detail strengthens the case rather than closing it — it still needs to be weighed alongside the unsigned, generically-named binary and its unusual Temp-folder path, not read in isolation.",
          xp: 40,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads 'Detected, no action taken', and this is the third behavior in twenty-two minutes on this host sharing the same IncidentId, following a scheduled-task creation and a PowerShell download. Taken together with the unsigned, generically-named binary requesting full access to lsass.exe, what should the analyst do next?",
          options: [
            "Close the detection as informational, since PatternDispositionDescription shows Falcon didn't consider it worth blocking",
            "Treat this as a likely true positive credential-access attempt that Falcon only observed rather than stopped — pull the full sibling behaviors under this IncidentId, check the file hash's reputation, then move toward containing the host and treating credentials on it as potentially exposed",
            "Wait for a fourth behavior before taking any action, since three correlated behaviors in twenty-two minutes isn't yet a strong enough pattern",
            "Immediately reset every domain user's password across the entire company before doing any further investigation on this specific host",
          ],
          answer: 1,
          explanation:
            "'Detected, no action taken' means Falcon only observed the behavior — it did not stop it, which raises urgency rather than lowering it, the opposite of what option a assumes. Reading 5 (covered right after this task) treats three correlated behaviors sharing one IncidentId inside twenty-two minutes as already a strong, actionable pattern, not a reason to wait. And resetting every domain password company-wide, before scoping has even confirmed what's actually compromised, is a wildly disproportionate first move — the correct next steps are exactly the pivot, scope, and contain phases of this room's workflow.",
          xp: 40,
        },
      ],
    },
    // ── Reading 5: sibling alerts / IncidentId ───────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r5",
      heading: "Sibling Alerts: Why One Host Rarely Fires Just One Detection",
      content:
        "Real intrusions are sequences of individual actions, not a single moment in time — and behavior-based EDR detection typically produces a separate alert for each distinct technique step an attacker takes, rather than one alert covering the whole intrusion. On a single compromised host, within a span of minutes, it is entirely normal to see a scheduled-task creation flagged as persistence, a suspicious file download flagged separately, and then a credential-access attempt flagged a third time — three detections describing one continuous event.\n\n" +
        "**The field that ties them together.** CrowdStrike's IncidentId groups multiple behaviors that Falcon's own correlation logic considers related, typically on the same host within a short window. Pulling every behavior sharing an IncidentId reconstructs the actual sequence of what happened, instead of reading three disconnected tickets as three disconnected stories.\n\n" +
        "**Why triaging each behavior in isolation is a real risk.** A scheduled-task creation on its own can look like a low-priority IT automation quirk. A PowerShell download on its own can look like a developer testing something. Only reading all three together, in order, reveals the coherent story: establish persistence, pull down a tool, then use that tool against LSASS. An analyst who closes the first two as unrelated, routine notices — because neither one alone looked severe — can leave the actual persistence mechanism completely untouched even after the workstation gets remediated for the headline detection.\n\n" +
        "**The practical habit.** Whenever a new behavior fires, before triaging it as its own isolated case, check whether the same host produced any other behavior in roughly the last thirty minutes — with a shared IncidentId if the platform auto-correlates, or by hostname and timestamp proximity if it doesn't — and read whatever you find as one sequence, not several unrelated coincidences.\n\n" +
        "**The necessary caveat.** This does not mean every cluster of close-together detections on a host is automatically one intrusion — a host can legitimately produce several unrelated Medium-severity notices during a busy patch cycle, for instance. The habit isn't 'always assume correlation'; it's 'always check for it,' which is exactly what prevents missing the real correlated case on the day it actually happens.",
      diagram:
        "sequenceDiagram\n" +
        "  participant H as WKS-FIN-0231\n" +
        "  participant B1 as Behavior 1: Scheduled task (Medium)\n" +
        "  participant B2 as Behavior 2: PowerShell download (Medium)\n" +
        "  participant B3 as Behavior 3: LSASS access (Critical)\n" +
        "  Note over B1,B3: All three share one crowdstrike.IncidentId\n" +
        "  H->>B1: t+0 min\n" +
        "  H->>B2: t+13 min\n" +
        "  H->>B3: t+22 min\n" +
        "  Note over B3: Read as one sequence: persistence, then tooling, then credential access\n",
      diagramCaption: "Reconstructing one intrusion from sibling behaviors sharing an IncidentId",
    },
    // ── Question 3 — merging sibling alerts ──────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q3",
      question:
        "Three Falcon behaviors fire against the same host within nine minutes, all sharing one IncidentId: a scheduled-task creation (Medium), a PowerShell download from an external site (Medium), and a credential-access attempt against lsass.exe (Critical). An analyst triages only the Critical one and closes the other two separately as routine, unrelated notices. What is wrong with this approach, based on Reading 5?",
      options: [
        "Nothing — severity alone should always determine which behaviors get full attention, and lower-severity ones can safely be closed independently",
        "Treating the three behaviors as separate, unrelated cases misses the actual sequence — the scheduled task and PowerShell download are plausibly the persistence and tooling steps of the same intrusion that ends in the credential-access attempt, and closing them separately can leave the persistence mechanism untouched even after the workstation is remediated",
        "IncidentId only groups behaviors for licensing and billing purposes and carries no investigative value",
        "A PowerShell download is always unrelated to a credential-access detection, regardless of timing or a shared IncidentId",
      ],
      answer: 1,
      explanation:
        "Reading 5's core point is exactly this: severity alone doesn't establish whether behaviors are related, and the risk of triaging them separately is leaving an actual persistence mechanism in place. IncidentId is a correlation field with real investigative value, not a billing artifact. And option d overgeneralizes in the other direction — timing plus a shared IncidentId is precisely the signal Reading 5 said to weigh, not dismiss automatically.",
      xp: 30,
    },
    // ── Reading 6: severity reassessment ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r6",
      heading: "Severity Reassessment: Why the Tool's Severity Isn't the Analyst's Verdict",
      content:
        "EDR severity ratings are assigned by matching a behavior against a known technique pattern, the instant that pattern matches — before any human has looked at who ran it, on what kind of asset, or why. That means the exact same technique-based detection, say Signed Binary Proxy Execution via regsvr32.exe, fires at the identical High or Critical severity whether it's an actual attacker registering a malicious COM object, or a company's own software-deployment tool doing precisely what it was built to do, from a documented change ticket, on an ordinary Tuesday afternoon.\n\n" +
        "**Why vendors build it this way.** Rating severity around technique risk rather than organizational context is the only way a vendor can ship a rating that's useful for every customer at once. Falcon has no built-in way to know that a specific regsvr32 command line belongs to a particular company's approved deployment tooling — that contextual judgment is exactly what an analyst exists to provide, and no automated system upstream of the analyst can substitute for it.\n\n" +
        "**The reassessment questions worth asking before accepting a tool's severity at face value.** Is the account running this process a known service or automation account with a documented purpose, or a human user's account behaving unusually? Is there a change ticket or maintenance window that explains the timing? Is the file signed by a publisher the organization actually uses, or is it unsigned and generically named? Did PatternDispositionDescription show the action was actually blocked — suggesting the tool itself judged it worth stopping in real time — or merely observed? And is the affected asset a sensitive one, like a domain controller or an executive's workstation, where even a small residual chance of a true positive deserves extra scrutiny regardless of the tool's default rating?\n\n" +
        "**The risk in both directions.** Accepting every Critical or High rating at face value, without checking any of these questions, drowns a SOC in false escalations on routine deployment tooling — and eventually trains the team to skim past real ones out of sheer alert fatigue. But downgrading severity out of habit, without actually checking the context fields, is exactly how a genuine credential-access attempt gets waved through as 'probably another one of those deployment alerts.' Neither shortcut is safe; the actual fields have to be checked every time.\n\n" +
        "**What comes next.** The analyst_choice task that follows hands you exactly this kind of decision — a technique-based, High-severity detection, plus the surrounding context fields you need to reassess it properly, the same way this reading just walked through.",
    },
    // ── Analyst Choice: TP vs FP — severity reassessment ─────────────────────
    {
      type: "analyst_choice" as const,
      id: "edr-ac1",
      heading: "Verdict: A High-Severity LOLBin Detection During a Deployment Window",
      scenario:
        "Falcon fires a High-severity detection on SRV-DEPLOY-07, tagged Tactic: Defense Evasion and Technique: Signed Binary Proxy Execution — the exact technique family covered earlier in this room as a well-known LOLBin pattern, and the same family the log analysis task's credential-access case belonged to as well. Review the detection before deciding whether this is a true positive or a false positive.",
      event: regsvr32DeploymentEvent,
      correct_verdict: "false_positive",
      explanation:
        "crowdstrike.UserName is NEXACORP\\svc-sccm, a known deployment service account, not a human user's account behaving unusually. crowdstrike.CommandLine points at an internal deployment path (C:\\ProgramData\\NexaDeploy\\Modules\\...) rather than a generic Temp or AppData location. crowdstrike.PatternDispositionDescription reads 'Detected, no action taken', consistent with a tuned, expected deployment pattern that Falcon itself didn't judge worth blocking. And it_verify_result confirms change ticket CHG0052291 authorizing exactly this rollout, on this host, during this window. SeverityName 'High' and Tactic 'Defense Evasion' were assigned automatically the instant the regsvr32 pattern matched — Reading 6's exact point — regardless of who ran it or why.",
      fp_trap:
        "A High-severity Signed Binary Proxy Execution detection is precisely the kind of alert that gets escalated on reflex, because this room's earlier reading and log analysis task both taught you to take LOLBin patterns and credential-access attempts seriously. But High severity here is the tool's automatic technique-based rating, not a verdict on its own — the service account, the internal (not generic) deployment path, the matching change ticket, and Falcon's own choice not to block it are the specific fields that separate this case from the log analysis task's genuine credential-access attempt. Escalating every LOLBin detection without checking these fields either buries a SOC in noise on every deployment night, or — just as dangerously — teaches the team to stop reading past the technique name entirely.",
      xp: 35,
    },
    // ── Reading 7: pivot & scope ──────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r7",
      heading: "Pivoting and Scoping: Hash Reputation, Network Activity, and the Rest of the Fleet",
      content:
        "Once the process tree is expanded and severity has been reassessed in context, the next move is to step entirely outside the single detection and ask two different questions: what else did this specific file or process do, and has anything like it touched any other host in the environment.\n\n" +
        "**Hash reputation.** SHA256HashData (or mde.SHA256 in Defender) is the field this pivot is built around — paste it into a threat intelligence platform such as VirusTotal, or the organization's own TIP, to see whether other security vendors already recognize the file as malicious and whether it has appeared in other organizations' incidents. A hash with zero detections isn't proof of innocence on its own — a brand-new or custom-built tool simply won't have a reputation yet — but a hash flagged by a dozen independent vendors as a known credential-dumping utility removes almost all remaining doubt.\n\n" +
        "**Network and file pivot.** Expand beyond the single flagged process to everything else it touched: did it make an outbound network connection, to what domain or IP address; was any file written to disk afterward, such as a memory-dump artifact or a second-stage payload; was any registry key modified for persistence. Both Falcon's Investigate module and Defender's device timeline let an analyst walk this out visually, one connected action at a time.\n\n" +
        "**Scoping across the fleet.** The single most important pivot for actually containing an intrusion before it spreads further is asking whether the same file hash, or the same behavior pattern, has appeared on any other host in the environment. This is the exact question that turns 'one workstation has a problem' into either 'good, this is contained to a single machine' or 'this hash is already present on four other hosts, and the real incident is considerably larger than the first detection suggested.'\n\n" +
        "**Why this is a query, not a click.** Fleet-wide scoping is exactly what a hunting query is built for — whether written in CrowdStrike's own query language inside the Falcon console, or in Microsoft Defender's Advanced Hunting KQL against tables like DeviceProcessEvents. The exercise that follows has you write exactly this kind of hunt yourself, using the hash from this room's log analysis finding.",
      codeExample:
        "Microsoft Defender Advanced Hunting (KQL) — has this hash run anywhere else\n" +
        "DeviceProcessEvents\n" +
        "| where SHA256 == \"b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a\"\n" +
        "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine\n\n" +
        "The same question, asked inside CrowdStrike, uses Falcon's own query\n" +
        "language against SHA256HashData instead of KQL against SHA256 — different\n" +
        "syntax, identical investigative question.",
    },
    // ── Query Fill: hunt the same hash across the fleet ──────────────────────
    {
      type: "query_fill" as const,
      id: "edr-qf1",
      heading: "Write It Yourself: Hunt the Same File Hash Across Every Other Host",
      language: "kql" as const,
      context:
        "Before closing the WKS-FIN-0231 case, the team wants to know whether the exact same file has executed anywhere else in the fleet. Using Microsoft Defender's Advanced Hunting schema, fill in the table name, the hash column, and the exact hash value from this room's log analysis finding.",
      template:
        "{{table}}\n| where {{field}} == \"{{hash}}\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine",
      blanks: [
        { id: "table", answers: ["DeviceProcessEvents"], placeholder: "Advanced Hunting table for process execution telemetry" },
        { id: "field", answers: ["SHA256"], placeholder: "column holding the file's hash" },
        { id: "hash", answers: ["b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a"], placeholder: "exact hash from the log analysis finding" },
      ],
      explanation:
        "DeviceProcessEvents is the Advanced Hunting table for process execution telemetry, and SHA256 is the column carrying the file's cryptographic fingerprint. Using the exact hash from the WKS-FIN-0231 detection turns a single-host finding into a fleet-wide answer — precisely the scoping step Reading 7 described. Even though this specific hunt is written in Defender's KQL, the identical logic applies inside the CrowdStrike console using Falcon's own query language against SHA256HashData.",
      xp: 30,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "edr-f1",
      prompt:
        "Look at the log analysis finding on WKS-FIN-0231. What is the exact value of the crowdstrike.DetectId field in the raw log?",
      answer: "ldt:9f2ab6c4de3f4a1c8b7e2d5f0a9c3b6e:88213",
      hint: "Look inside the raw block of the log analysis event for the field named crowdstrike.DetectId.",
      xp: 20,
    },
    // ── Question 4 — containment decision ────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q4",
      question:
        "On WKS-FIN-0231, the credential-access behavior is confirmed as a true positive: PatternDispositionDescription showed 'Detected, no action taken', and the SHA256 hash pivots back as a known credential-dumping utility in your threat intelligence platform. What is the correct immediate containment action?",
      options: [
        "Shut the workstation down completely to stop any further activity",
        "Network-contain (isolate) the host through the EDR console so it can no longer communicate while staying reachable for forensic collection, kill the malicious process, and treat any credentials that were logged onto this host as potentially exposed pending rotation",
        "Wait until the end of the business day to avoid disrupting the finance analyst's workday",
        "Email the finance analyst directly and ask them to close their laptop lid",
      ],
      answer: 1,
      explanation:
        "Shutting the host down destroys volatile memory evidence and offers no guarantee that a persistence mechanism already written to disk is actually stopped. Network containment through the EDR console cuts off further communication while keeping the host reachable for continued forensic work through the same channel — the balance a real incident response actually needs. Since PatternDispositionDescription showed the access was never blocked, credentials on this host should be treated as compromised without delay, ruling out waiting for end of day. Emailing the user risks tipping off an attacker if the session is still active, and doesn't actually contain anything on its own.",
      xp: 30,
    },
    // ── Question 5 — cross-host hash scoping escalation ─────────────────────
    {
      type: "question" as const,
      id: "edr-q5",
      question:
        "Two days later, a new Falcon detection fires on a completely different host, and its crowdstrike.SHA256HashData exactly matches the hash from the WKS-FIN-0231 case. What does this tell you, and what should you do?",
      options: [
        "It's a coincidence — identical SHA256 hashes across two unrelated hosts happen regularly and mean nothing",
        "The exact same file is now confirmed present on a second host — treat this as part of the same incident rather than a brand-new case, and re-run the fleet-wide scoping step before assuming containment is complete",
        "SHA256 hashes are commonly reused by Windows across many unrelated legitimate files, so this match carries no investigative weight",
        "Since WKS-FIN-0231 was already contained, this new detection can be closed automatically without any further review",
      ],
      answer: 1,
      explanation:
        "SHA256 is a cryptographic fingerprint specifically designed so that two different files essentially never produce the same value — a match means, for all practical purposes, the same file, not a coincidence and not a reused generic hash. That's exactly the scoping step from Reading 7 and the six-step workflow bearing out: the incident is larger than first believed, so it should be treated as one ongoing case and scoped further, not closed automatically because the first host was already handled.",
      xp: 30,
    },
  ],
};

export const roomsBatch28 = [edrDetectionInvestigationRoom];
