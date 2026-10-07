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
 *     PatternDispositionDescription, ContextBaseFileName, CommandLine,
 *     SHA256HashData, DesiredAccess, CallStackModuleNames, mde.* equivalents),
 *     the six-step investigation workflow, process-tree anomaly reading,
 *     sibling-alert / AggregateId correlation, and severity reassessment
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
    "crowdstrike.AggregateId": "aggind:9f2ab6c4de3f4a1c8b7e2d5f0a9c3b6e:2670376644",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Credential Access",
    "crowdstrike.Technique": "OS Credential Dumping",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextBaseFileName": "explorer.exe",
    "crowdstrike.ParentBaseFileName": "explorer.exe",
    "crowdstrike.FileName": "UpdateHelper.exe",
    "crowdstrike.FilePath": "C:\\Users\\r.callahan\\AppData\\Local\\Temp\\UpdateHelper.exe",
    "crowdstrike.CommandLine": "\"UpdateHelper.exe\"",
    "crowdstrike.SHA256HashData": "b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a",
    "crowdstrike.TargetProcessImageFileName": "lsass.exe",
    "crowdstrike.DesiredAccess": "2097151",
    "crowdstrike.CallStackModuleNames": "dbghelp.dll,KERNELBASE.dll,ntdll.dll",
    "crowdstrike.UserName": "NEXACORP\\r.callahan",
    "crowdstrike.ComputerName": "WKS-FIN-0231",
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
    "crowdstrike.DetectId": "ldt:8006beb3bcd2593362266fe370c2b36f:55102",
    "crowdstrike.AggregateId": "aggind:8006beb3bcd2593362266fe370c2b36f:2147925683",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Defense Evasion",
    "crowdstrike.Technique": "Signed Binary Proxy Execution",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextBaseFileName": "cmd.exe",
    "crowdstrike.ParentBaseFileName": "cmd.exe",
    "crowdstrike.FileName": "regsvr32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\System32\\regsvr32.exe",
    "crowdstrike.CommandLine": "regsvr32.exe /s C:\\ProgramData\\NexaDeploy\\Modules\\ReportViewerCtl.dll",
    "crowdstrike.SHA256HashData": "3c9f81a46b2d0e758f1a3c6d9e0b4f275a8d3c61e97f0b426c1a9d38f04e7b25",
    "crowdstrike.UserName": "NEXACORP\\svc-sccm",
    "crowdstrike.ComputerName": "SRV-DEPLOY-07",
    "event.action": "process-create",
    "event.outcome": "success",
  },
};

const edrDetectionInvestigationRoom = {
  id: "edr-detection-investigation",
  title: "Investigating an EDR Detection: End to End",
  description:
    "Follow one EDR detection from the moment it lands to the moment a host is contained. Covers CrowdStrike Falcon and Microsoft Defender for Endpoint fields (Tactic, Technique, SeverityName, PatternDispositionDescription, ContextBaseFileName, CommandLine, SHA256HashData, DesiredAccess, CallStackModuleNames), how to read a process tree for parent-child anomalies and LOLBins, why sibling behavioral alerts on the same host need to be merged before triage, why a tool's own severity rating is never the analyst's verdict, and the full pivot-scope-contain workflow real investigations actually run.",
  difficulty: "advanced" as const,
  category: "Endpoint Security",
  estimatedMinutes: 75,
  xp: 435,
  icon: "🔎",
  prerequisites: ["endpoint-security-fundamentals", "crowdstrike-falcon"],
  tasks: [
    // ── Reading 1: EDR depth vs SIEM summary ────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r1",
      heading: "Why the Detection Is the Doorway, Not the Whole Story",
      content:
        "A SIEM alert is almost always a one-line summary assembled from fragments of many different systems, a bit like a building manager who receives a single note from a hundred different properties: 'motion detected, third floor, 2:14 AM.' An EDR agent is the actual camera system installed inside one specific building, recording everything that happens there in detail: who came in, which door, what they carried, who they spoke to, and where they went next. When enough of those one-line notes get correlated into an alert worth investigating, a good analyst doesn't stop at the note. They open the camera system for that one building and watch what actually happened.\n\n" +
        "**What EDR telemetry actually contains.** The agent sitting on an endpoint sees the full causal chain of a process: its parent, its parent's parent, the exact command-line arguments it ran with, whether its binary was signed and by whom, every file it created or deleted, every registry key it touched, and every network or DNS request it personally made, not just 'the host', but that specific process. For the most sensitive category of activity, it also sees one process reaching into another process's memory space, an action ordinary logs never capture at all.\n\n" +
        "**Why this is fundamentally different from a firewall log or a single Windows event.** A firewall only sees packets crossing a boundary. It has no idea which process on either end generated them. A single Windows Security event captures one action in isolation, with no causal thread connecting it to what happened a minute before or after. The EDR agent, because it sits on the endpoint itself, is the one source that sees the entire chain as one continuous story: what launched what, with what arguments, and what happened immediately around it.\n\n" +
        "**The habit this creates.** An experienced analyst treats every EDR detection as an entry point into a much richer dataset, never as a self-contained verdict. The vendor's console, the Falcon UI, the Microsoft Defender Security Center, whichever platform is in front of you. Is where the actual investigation happens: expanding the process tree, pulling the full command line, checking the file's hash, and reading what else that same process (and that same host) did in the minutes around the flagged action. A detection that arrives with a severity label and a technique name is the beginning of the work, not the end of it.\n\n" +
        "**What this room does.** Every reading, question, and task from here follows one real detection from the moment it lands in the console to the moment a host gets contained, teaching the exact fields you'd actually read and the exact reasoning you'd actually apply at each step, in the order a real investigation runs.",
      checkpoint: {
        question: "Per Reading 1, what does an EDR agent see that a firewall log or a single Windows event cannot?",
        options: [
          "Packets crossing the network boundary, with the ports and IPs each side of the session used",
          "Which process did each action: its parent, exact command line, and the files and connections it made",
          "One action such as a single logon, recorded on its own with its account and its timestamp",
          "Whether a file is on a threat-intel blocklist, checked before it is allowed to execute at all",
        ],
        answer: 1,
        explanation:
          "The EDR agent sits on the endpoint and ties every action to the process that did it, with its parent, arguments, files, registry keys and connections, as one continuous story. “Packets crossing the network boundary…” is what a firewall log already records, without knowing which process sent them. “One action such as a single logon…” is a single Windows event, with no thread to what happened before or after. “Whether a file is on a threat-intel blocklist…” describes signature-style blocking, not the causal visibility Reading 1 describes.",
      },
    },
    // ── Reading 2: field anatomy across CrowdStrike + MDE ───────────────────
    {
      type: "reading" as const,
      id: "edr-r2",
      heading: "Anatomy of a Detection: The Fields That Actually Carry the Story",
      content:
        "Every major EDR platform reduces 'what happened' down to a specific, learnable set of fields. Reading them fluently (instead of skimming a detection's title and severity color) is the actual difference between an analyst who investigates and one who just reacts to labels.\n\n" +
        "**CrowdStrike Falcon's core fields.** Tactic and Technique are the MITRE ATT&CK category and specific method Falcon's behavioral engine matched. Useful for framing what kind of goal the activity serves, but not a verdict by itself, since a single technique like Signed Binary Proxy Execution fires just as reliably against a benign internal deployment script as against a real attacker. SeverityName is Falcon's own automatic rating (Critical, High, Medium, Low), assigned the instant the behavior pattern matches. Before any human has added context, which is exactly why Reading 6 later spends a full reading on why this field is not the analyst's final word. PatternDispositionDescription answers a different, sharper question: what did Falcon actually do about it. A value like 'Detected, no action taken' means the behavior was only observed; 'Prevented' or 'Detected, kill process' means Falcon actually intervened. Severity tells you how seriously the tool rated the pattern; PatternDispositionDescription tells you whether the potentially malicious action already ran to completion.\n\n" +
        "**The process-identity fields.** ParentBaseFileName (and ContextBaseFileName, the acting process on a network or file event) identify the process that launched the one being flagged: one link of the process tree, readable without opening the full graphical view. CommandLine is the exact string of arguments the flagged process executed with, including any Base64 encoding, unusual file paths, or suspicious destination arguments. FileName, FilePath, and SHA256HashData identify the specific binary, where it lives on disk, and its cryptographic fingerprint: the fingerprint being the single most useful field for pivoting entirely outside the console, into hash-reputation lookups and fleet-wide hunting, which Reading 7 builds on directly.\n\n" +
        "**Microsoft Defender for Endpoint's equivalents.** The underlying questions are identical; only the field names change. mde.AlertTitle and mde.Category summarize what fired and its broad classification. mde.InitiatingProcessFileName and mde.InitiatingProcessCommandLine describe the process that LAUNCHED the flagged one, Defender's version of ContextBaseFileName / ParentBaseFileName; the flagged process's own name, command line and hash are FileName, ProcessCommandLine and SHA256, and every InitiatingProcess* column (InitiatingProcessSHA256 included) points one level up the tree. mde.SHA256 and mde.DeviceName complete the identification, and mde.DetectionSource tells you which Defender component (the EDR behavioral engine, the antivirus scanning engine, or another) actually generated the alert in the first place.\n\n" +
        "**Why this matters before anything else in the room.** Whichever vendor's console is open in front of you, the questions are the same: what ran, launched by what, with what exact arguments, identified by what hash, and what did the tool actually do in response. Every later reading in this room builds directly on top of these fields.",
      codeExample:
        "CrowdStrike Falcon                         Microsoft Defender for Endpoint\n" +
        "-----------------------------------------------------------------------\n" +
        "Tactic / Technique                          mde.Category\n" +
        "SeverityName                                mde.AlertTitle (severity is a sibling field)\n" +
        "PatternDispositionDescription                mde.DetectionSource\n" +
        "ContextBaseFileName / ParentBaseFileName      mde.InitiatingProcessFileName\n" +
        "CommandLine                                  mde.ProcessCommandLine\n" +
        "FileName / FilePath                          mde.FileName / mde.FolderPath\n" +
        "SHA256HashData                               mde.SHA256\n" +
        "ComputerName                                 mde.DeviceName\n" +
        "AggregateId                                  mde.IncidentId",
      checkpoint: {
        question:
          "A Falcon detection shows SeverityName ‘Critical’ and PatternDispositionDescription ‘Detected, no action taken’. What do these two fields tell you together?",
        options: [
          "Falcon rated the pattern Critical and blocked it, so the action never completed",
          "Falcon rated the pattern Critical but only observed it, so the action likely ran",
          "Falcon is unsure: Critical with no action taken marks a low-confidence pattern match",
          "An analyst has reviewed it and decided no action was needed, so the case is closed",
        ],
        answer: 1,
        explanation:
          "SeverityName is the tool’s automatic rating of the matched pattern; PatternDispositionDescription says what the tool did about it. ‘Detected, no action taken’ means it only observed, so the potentially malicious action ran to completion. “…and blocked it…” would need a disposition such as ‘Prevented’ or ‘Detected, kill process’. “Falcon is unsure…” confuses disposition with confidence: whether Falcon intervenes depends on policy, not on doubt. “An analyst has reviewed it…” misreads a sensor field as a case status; no human has touched it yet.",
      },
    },
    // ── Question 1 — severity is not the verdict (conceptual) ───────────────
    {
      type: "question" as const,
      id: "edr-q1",
      question:
        "A CrowdStrike detection fires with crowdstrike.SeverityName: 'Critical' and crowdstrike.Tactic: 'Defense Evasion', tagged for a well-known LOLBin technique pattern. Based on Reading 2, what is the correct way to treat the SeverityName field at this stage of the investigation?",
      options: [
        "As the final verdict: Critical means confirmed compromise, so escalate without reading the tree",
        "As the tool's automatic rating at match time: good for queue order, not a substitute for the tree",
        "As noise to set aside, since a technique-based rating says little about this specific host",
        "As proof the action was blocked, since Critical is given to behaviour the sensor has stopped",
      ],
      answer: 1,
      explanation:
        "SeverityName is assigned the moment the pattern matches, before anyone adds context, so it helps you order the queue but does not replace reading the process tree, command line and context. “As the final verdict…” skips the investigation entirely. “As noise to set aside…” overcorrects: the rating is still a useful prioritisation signal. “As proof the action was blocked…” confuses severity with disposition; whether Falcon intervened is recorded in PatternDispositionDescription.",
      xp: 25,
    },
    // ── Matching: fields to meaning ──────────────────────────────────────────
    {
      type: "matching" as const,
      id: "edr-m1",
      heading: "Match the EDR Field to What It Actually Tells You",
      instructions: "Match each CrowdStrike Falcon / Microsoft Defender field to what it records or reveals during an investigation.",
      pairs: [
        { id: "context", left: "ContextBaseFileName / ParentBaseFileName", right: "The process that launched the one being flagged: one link of the process tree, without opening the full graphical view" },
        { id: "cmdline", left: "CommandLine", right: "The exact arguments the flagged process ran with, including any encoding or unusual destination paths" },
        { id: "hash", left: "SHA256HashData", right: "The binary's cryptographic fingerprint: the field used to pivot into hash-reputation lookups and fleet-wide hunting" },
        { id: "tactic", left: "Tactic", right: "The MITRE ATT&CK category describing the broad adversary goal behind the matched behavior pattern" },
        { id: "technique", left: "Technique", right: "The specific ATT&CK method the matched behavior pattern corresponds to" },
        { id: "severity", left: "SeverityName", right: "The tool's own automatic severity rating, assigned the instant the pattern matched, before any analyst has added context" },
        { id: "disposition", left: "PatternDispositionDescription", right: "What the tool actually did in response: merely observed the behavior, or actually stopped it" },
        { id: "granted", left: "DesiredAccess", right: "The Windows access mask a process requested against another process's handle: 0x1FFFFF is full control" },
        { id: "callstack", left: "CallStackModuleNames", right: "The DLLs loaded in the call stack at the moment of access, revealing the specific mechanism used: e.g., dbghelp.dll pointing at MiniDumpWriteDump" },
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
        "Every field in Reading 2 matters, but reading them well only gets you through step one of an actual investigation. A real EDR case runs through six distinct phases, and skipping straight from 'I read the detection' to 'here's my verdict' is the single most common mistake an analyst makes, because the detection alone almost never contains enough context to separate malicious from benign.\n\n" +
        "**Step one: read the detection.** Technique, severity, and pattern disposition, exactly what Reading 2 covered, give you the starting shape of what the tool believes happened and whether it thinks it stopped anything.\n\n" +
        "**Step two: expand the process tree.** Pull the full chain (parent, grandparent, and further back if the console shows it) along with the complete command line and file hash for every link in that chain. Reading 4 builds this skill in depth: this is where parent-child anomalies and LOLBin abuse actually reveal themselves.\n\n" +
        "**Step three: pivot outward.** Take the file hash to a reputation source, check what network or DNS activity the process made, and check what files it created or modified afterward. Reading 7 covers this pivot in full.\n\n" +
        "**Step four: scope across the fleet.** Ask whether the same hash or the same behavior pattern has touched any other host in the environment, the single question that turns 'one workstation has a problem' into either 'good, it's contained' or 'this is bigger than the first detection suggested.'\n\n" +
        "**Step five: decide the verdict.** Only now, with the tree expanded, the hash checked, and the scope understood, does deciding true positive versus false positive actually mean something, informed by context, not by the tool's severity label alone. Readings 5 and 6 build the two specific skills this step depends on: merging sibling alerts, and reassessing severity in context.\n\n" +
        "**Step six: contain and remediate.** Isolate the host, kill the malicious process, and (if credential material may have been exposed) treat any credentials on that host as compromised pending rotation.\n\n" +
        "**Why the order itself matters, not just the six items.** Pivoting or scoping before you've even expanded the tree wastes effort chasing the wrong process or the wrong hash entirely. Deciding a verdict before scoping means you might close an incident that's still quietly active on three other hosts. Containing a host before you've scoped the rest of the environment can mean acting on incomplete information, cutting off the one host you found while missing others you haven't looked for yet. The ordering task that follows asks you to reconstruct this exact sequence yourself.",
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
        { id: "verdict", text: "Decide the verdict: true positive or false positive, based on context, not on severity alone" },
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
        "Every process has a parent, the process that launched it, and tracing that chain backward tells you the real story of how something started running, not just the fact that it ran. Most parent-child pairings are completely unremarkable: explorer.exe launching a user-opened application, svchost.exe hosting a Windows service, outlook.exe opening an attachment in Word. The skill this reading builds is recognizing the specific pairings and patterns that essentially never occur in legitimate business use.\n\n" +
        "**The anomaly that matters most: an Office application spawning a shell or scripting engine.** WINWORD.EXE, EXCEL.EXE, or OUTLOOK.EXE launching powershell.exe, cmd.exe, or wscript.exe is a pairing that has no legitimate business reason to exist. Word does not need to open PowerShell to display a document. When a process tree shows this exact pairing, it is the classic signature of a malicious macro firing its payload the moment a user enabled macro content on a phishing attachment. The chain itself, before any hash lookup, is already strong evidence.\n\n" +
        "**LOLBins: legitimate tools abused for something else.** rundll32.exe, regsvr32.exe, mshta.exe, and certutil.exe are all signed, legitimate Windows utilities that can be abused for purposes other than their intended one. This is why they're called Living-off-the-Land Binaries. None of them is inherently malicious; what matters is the combination of parent process, command-line arguments, and destination. rundll32.exe launched by cmd.exe with an argument referencing comsvcs.dll and a target of lsass.exe is a well-documented credential-dumping pattern. The exact same binary, launched by a signed software installer with a routine DLL-registration argument pointing at an internal application path, is completely ordinary: the file name tells you almost nothing on its own; the full command line and parent process tell you nearly everything.\n\n" +
        "**Process injection: when the anomaly isn't in the parent-child chain at all.** Sometimes the suspicious activity is one process reaching directly into a second, entirely unrelated process's memory, with no parent-child relationship between the two whatsoever. EDR telemetry captures this as an access event: an 'accessing' process requesting a handle to a 'target' process, with an access mask like GrantedAccess 0x1FFFFF granting full control. The anomaly here is the handle access itself, together with what's loaded in the accessing process's call stack at that exact moment, which is precisely what the CallStackModuleNames field, covered in this room's log analysis task, is built to reveal. One module worth knowing there: dbghelp.dll exports MiniDumpWriteDump, the routine that writes a process's memory to a dump file. Credential dumpers load it to dump LSASS, but legitimate crash-reporting and diagnostic tools such as Windows Error Reporting and ProcDump load it too, so it strengthens a case rather than proving one.\n\n" +
        "**The three questions a process tree should always answer.** Does this specific parent-child pairing happen anywhere in legitimate business use? Does the command line contain anything that shouldn't need to be there, encoding, an unusual path, an unexpected destination file? And is there any sensitive object being touched (another process's memory, LSASS, a domain controller's credential store) that has no legitimate reason to be reached by this particular chain at all?",
      codeExample:
        "Example tree read as a chain, not isolated events:\n\n" +
        "OUTLOOK.EXE (user opened attachment)\n" +
        "  -> WINWORD.EXE (attachment rendered, macro enabled)\n" +
        "      -> powershell.exe -EncodedCommand SQBuAHYAbwBr...\n" +
        "          -> outbound connection to an unfamiliar domain\n\n" +
        "Read top to bottom: each link alone might look explainable.\n" +
        "Read as one chain, the WINWORD -> powershell link is the anomaly\n" +
        "that essentially never occurs in ordinary business use.",
      checkpoint: {
        question: "Per Reading 4, what determines whether a LOLBin like rundll32.exe or regsvr32.exe is worth escalating?",
        options: [
          "Its signature: a Microsoft-signed rundll32.exe or regsvr32.exe can be trusted as benign",
          "Its parent, command-line arguments and target together, since the name alone says little",
          "Its hash reputation: a clean VirusTotal result on the binary clears the launch as benign",
          "Its location: running from C:\\Windows\\System32 rather than elsewhere marks it as genuine",
        ],
        answer: 1,
        explanation:
          "A LOLBin is a legitimate, signed Windows utility, so what matters is how it was used: which parent launched it, with what arguments, against what target (for example cmd.exe → rundll32.exe comsvcs.dll MiniDump against lsass.exe). “Its signature…” is the very property attackers rely on; the binary is genuinely Microsoft-signed either way. “Its hash reputation…” fails for the same reason: the real rundll32.exe always comes back clean. “Its location…” is also true of the abused copy, which runs from System32 like the legitimate one.",
      },
    },
    // ── Question 2 — parent-child anomaly ────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q2",
      question:
        "A process tree shows OUTLOOK.EXE launching WINWORD.EXE after a user opened an email attachment, which then launches powershell.exe with an encoded command-line argument. Based on Reading 4, what is the correct read of this chain?",
      options: [
        "Likely routine: Word starts PowerShell to render embedded objects, and add-ins often encode arguments",
        "The malicious-macro pattern: Office spawning a scripting engine is rare, and the encoding adds weight",
        "Inconclusive until the SHA256 is flagged in a threat-intel feed, since a tree alone is not evidence",
        "Malicious from the first link: Outlook opening Word for an attachment is itself the attack step",
      ],
      answer: 1,
      explanation:
        "Word launching PowerShell is the classic signature of a macro firing its payload, and an encoded command on top of that strengthens the read. “Likely routine…” invents a rendering mechanism; Word does not need PowerShell to display a document. “Inconclusive until the SHA256 is flagged…” puts a later pivot (Reading 7) ahead of evidence the tree already shows, and the PowerShell binary itself would come back clean anyway. “Malicious from the first link…” overclaims: Outlook opening an attachment in Word is routine; the anomaly is the next link.",
      xp: 25,
    },
    // ── Log Analysis: LSASS process-tree investigation ──────────────────────
    {
      type: "log_analysis" as const,
      id: "edr-la1",
      heading: "Process Tree Investigation: A Credential Access Detection on a Finance Workstation",
      context:
        "NexaCorp's Falcon console fires a Critical-severity behavioral detection on WKS-FIN-0231, a finance analyst's workstation. This is the third behavior logged against this host in the past twenty-two minutes, all three sharing the same crowdstrike.AggregateId. The first behavior was a scheduled-task creation and the second a PowerShell download from an external site, both tagged Medium severity by Falcon. Review the third behavior below, then reason through the process tree and surrounding fields the way a real investigation would.",
      event: lsassAccessEvent,
      questions: [
        {
          question:
            "crowdstrike.FilePath shows the flagged binary running from a user's AppData\\Local\\Temp folder, launched directly under explorer.exe (crowdstrike.ParentBaseFileName), and crowdstrike.FileName suggests a routine update utility. What should this combination make you want to check first, based on the process-tree reasoning in Reading 4?",
          options: [
            "Nothing: explorer.exe is the normal parent of anything a user starts, so the tree is clean",
            "Whether it is a signed, known updater installed here, or an unsigned binary with a bland name",
            "Nothing yet: a name like UpdateHelper.exe matches routine software, so the hash can wait",
            "Escalate on the path alone, since a binary running from a user's Temp folder is proof enough",
          ],
          answer: 1,
          explanation:
            "explorer.exe is the normal parent for anything a user launches, so the parent link is not the anomaly; the open question is whether this file is the legitimate signed updater it claims to be or something masquerading under a routine name. “Nothing: explorer.exe is the normal parent…” stops at the parent and ignores the file itself. “Nothing yet: a name like UpdateHelper.exe…” trusts the name, and masquerading as a routine utility is a well-known tactic. “Escalate on the path alone…” overclaims the other way: installers and browser downloads run from Temp folders every day.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.TargetProcessImageFileName reads lsass.exe and crowdstrike.DesiredAccess reads 2097151 (0x1FFFFF in hex. Falcon writes the access mask in decimal). What does this access mask represent, and why is it significant against this specific target?",
          options: [
            "PROCESS_VM_READ only: enough to read LSASS memory, but not to write to it or to control it",
            "PROCESS_ALL_ACCESS, full control of lsass.exe, which holds the credentials a dumper reads",
            "An access-denied code: the handle request was refused, so LSASS memory was not read",
            "The rights lsass.exe requested on UpdateHelper.exe, so LSASS is the process acting here",
          ],
          answer: 1,
          explanation:
            "0x1FFFFF is PROCESS_ALL_ACCESS, full control of the target process, and lsass.exe holds credential material (NTLM hashes, Kerberos tickets), so that access is what a dumping tool needs. “PROCESS_VM_READ only…” understates the mask: read access is a small part of it, not the whole of 0x1FFFFF. “An access-denied code…” misreads the field, and the record’s event.outcome is success. “The rights lsass.exe requested…” reverses the direction: UpdateHelper.exe is the accessing process and lsass.exe (TargetProcessImageFileName) is the target.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.CallStackModuleNames lists dbghelp.dll among the modules loaded at the moment of the LSASS access. Why does this specific detail matter on top of the DesiredAccess value alone?",
          options: [
            "Nothing: dbghelp.dll is mapped into every process at startup, like ntdll.dll, so it is constant noise",
            "dbghelp.dll provides MiniDumpWriteDump, the routine dumpers use, though crash tools load it too",
            "dbghelp.dll is the networking library behind getaddrinfo, so the process was about to exfiltrate",
            "It shows the dump already finished, since dbghelp.dll appears only after a dump file is written",
          ],
          answer: 1,
          explanation:
            "dbghelp.dll exports MiniDumpWriteDump, the routine that writes a process’s memory to a file, so seeing it in the call stack of a full-access request on lsass.exe matches credential-dumping mechanics; Reading 4 notes that crash-reporting tools such as Windows Error Reporting and ProcDump load it too, which is why it strengthens the case rather than closing it. “Nothing: dbghelp.dll is mapped into every process…” confuses it with ntdll.dll, which really is loaded everywhere. “…the networking library behind getaddrinfo…” describes the Winsock libraries, not dbghelp. “It shows the dump already finished…” misreads a call stack, which shows what was loaded at the moment of the access, not what happened afterwards.",
          xp: 40,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads ‘Detected, no action taken’, and this is the third behavior in twenty-two minutes on this host sharing the same AggregateId, after a scheduled-task creation and a PowerShell download. Together with a generically named binary from a Temp folder requesting full access to lsass.exe, what should the analyst do next?",
          options: [
            "Close it as informational: ‘no action taken’ is Falcon's signal it was not worth stopping",
            "Likely true positive Falcon only observed: pull the sibling behaviours, check the hash, then contain",
            "Wait for a fourth behaviour under the AggregateId before acting, since three is still a weak pattern",
            "Isolate the host and close the case, since containment ends the incident without further scoping",
          ],
          answer: 1,
          explanation:
            "‘Detected, no action taken’ means Falcon watched the LSASS access happen without stopping it, which raises urgency. With three correlated behaviours forming persistence, tooling and credential access, you pull the siblings, pivot on the hash and move to containment with the host’s credentials treated as exposed. “Close it as informational…” misreads disposition as a verdict: it says whether the action ran, not whether it was benign. “Wait for a fourth behaviour…” ignores that three correlated steps already form the story Reading 5 describes. “Isolate the host and close the case…” contains one host but skips the hash pivot and fleet scoping, and the scheduled task would survive.",
          xp: 40,
        },
      ],
    },
    // ── Reading 5: sibling alerts / AggregateId ───────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r5",
      heading: "Sibling Alerts: Why One Host Rarely Fires Just One Detection",
      content:
        "Real intrusions are sequences of individual actions, not a single moment in time, and behavior-based EDR detection typically produces a separate alert for each distinct technique step an attacker takes, rather than one alert covering the whole intrusion. On a single compromised host, within a span of minutes, it is entirely normal to see a scheduled-task creation flagged as persistence, a suspicious file download flagged separately, and then a credential-access attempt flagged a third time: three detections describing one continuous event.\n\n" +
        "**The field that ties them together.** CrowdStrike's AggregateId (aggind:<sensor id>:<tree id>) groups multiple behaviors that Falcon's own correlation logic ties to one process tree, typically on the same host within a short window. Pulling every behavior sharing an AggregateId reconstructs the actual sequence of what happened, instead of reading three disconnected tickets as three disconnected stories.\n\n" +
        "**Why triaging each behavior in isolation is a real risk.** A scheduled-task creation on its own can look like a low-priority IT automation quirk. A PowerShell download on its own can look like a developer testing something. Only reading all three together, in order, reveals the coherent story: establish persistence, pull down a tool, then use that tool against LSASS. An analyst who closes the first two as unrelated, routine notices (because neither one alone looked severe) can leave the actual persistence mechanism completely untouched even after the workstation gets remediated for the headline detection.\n\n" +
        "**The practical habit.** Whenever a new behavior fires, before triaging it as its own isolated case, check whether the same host produced any other behavior in roughly the last thirty minutes, with a shared AggregateId if the platform auto-correlates, or by hostname and timestamp proximity if it doesn't, and read whatever you find as one sequence, not several unrelated coincidences.\n\n" +
        "**The necessary caveat.** This does not mean every cluster of close-together detections on a host is automatically one intrusion: a host can legitimately produce several unrelated Medium-severity notices during a busy patch cycle, for instance. The habit isn't 'always assume correlation'; it's 'always check for it,' which is exactly what prevents missing the real correlated case on the day it actually happens.",
      diagram:
        "sequenceDiagram\n" +
        "  participant H as WKS-FIN-0231\n" +
        "  participant B1 as Behavior 1: Scheduled task (Medium)\n" +
        "  participant B2 as Behavior 2: PowerShell download (Medium)\n" +
        "  participant B3 as Behavior 3: LSASS access (Critical)\n" +
        "  Note over B1,B3: All three share one crowdstrike.AggregateId\n" +
        "  H->>B1: t+0 min\n" +
        "  H->>B2: t+13 min\n" +
        "  H->>B3: t+22 min\n" +
        "  Note over B3: Read as one sequence: persistence, then tooling, then credential access\n",
      diagramCaption: "Reconstructing one intrusion from sibling behaviors sharing an AggregateId",
    },
    // ── Question 3 — merging sibling alerts ──────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q3",
      question:
        "Three Falcon behaviors fire against the same host within nine minutes, all sharing one AggregateId: a scheduled-task creation (Medium), a PowerShell download from an external site (Medium), and a credential-access attempt against lsass.exe (Critical). An analyst triages only the Critical one and closes the other two separately as routine, unrelated notices. What is wrong with this approach, based on Reading 5?",
      options: [
        "Nothing: Medium behaviours belong in their own queue, and the Critical one carries the case",
        "It misses the sequence: the task and download are likely persistence and tooling, and the task can survive",
        "Nothing, provided the Critical case ends in host isolation, since that stops the three behaviours",
        "Merge same-tactic behaviours, since Execution and Credential Access serve separate attacker goals",
      ],
      answer: 1,
      explanation:
        "Read together and in order, the three behaviours are one intrusion: persistence (the scheduled task), tooling (the download) and use of that tool against LSASS. Closing the first two separately can leave the scheduled task in place after the headline detection is remediated. “Nothing: Medium behaviours belong in their own queue…” lets severity decide relatedness, which Reading 5 warns against. “Nothing, provided the Critical case ends in host isolation…” confuses containment with remediation: isolation cuts the network, but the scheduled task still runs when the host is released. “Merge same-tactic behaviours…” misunderstands correlation: an intrusion moves through different tactics, and the shared AggregateId and timing are the evidence that ties them.",
      xp: 30,
    },
    // ── Reading 6: severity reassessment ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r6",
      heading: "Severity Reassessment: Why the Tool's Severity Isn't the Analyst's Verdict",
      content:
        "EDR severity ratings are assigned by matching a behavior against a known technique pattern, the instant that pattern matches. Before any human has looked at who ran it, on what kind of asset, or why. That means the exact same technique-based detection, say Signed Binary Proxy Execution via regsvr32.exe, fires at the identical High or Critical severity whether it's an actual attacker registering a malicious COM object, or a company's own software-deployment tool doing precisely what it was built to do, from a documented change ticket, on an ordinary Tuesday afternoon.\n\n" +
        "**Why vendors build it this way.** Rating severity around technique risk rather than organizational context is the only way a vendor can ship a rating that's useful for every customer at once. Falcon has no built-in way to know that a specific regsvr32 command line belongs to a particular company's approved deployment tooling. That contextual judgment is exactly what an analyst exists to provide, and no automated system upstream of the analyst can substitute for it.\n\n" +
        "**The reassessment questions worth asking before accepting a tool's severity at face value.** Is the account running this process a known service or automation account with a documented purpose, or a human user's account behaving unusually? Is there a change ticket or maintenance window that explains the timing? Is the file signed by a publisher the organization actually uses, or is it unsigned and generically named? Did PatternDispositionDescription show the action was actually blocked (suggesting the tool itself judged it worth stopping in real time) or merely observed? And is the affected asset a sensitive one, like a domain controller or an executive's workstation, where even a small residual chance of a true positive deserves extra scrutiny regardless of the tool's default rating?\n\n" +
        "**The risk in both directions.** Accepting every Critical or High rating at face value, without checking any of these questions, drowns a SOC in false escalations on routine deployment tooling, and eventually trains the team to skim past real ones out of sheer alert fatigue. But downgrading severity out of habit, without actually checking the context fields, is exactly how a genuine credential-access attempt gets waved through as 'probably another one of those deployment alerts.' Neither shortcut is safe; the actual fields have to be checked every time.\n\n" +
        "**What comes next.** The analyst_choice task that follows hands you exactly this kind of decision: a technique-based, High-severity detection, plus the surrounding context fields you need to reassess it properly, the same way this reading just walked through.",
    },
    // ── Analyst Choice: TP vs FP — severity reassessment ─────────────────────
    {
      type: "analyst_choice" as const,
      id: "edr-ac1",
      heading: "Verdict: A High-Severity LOLBin Detection During a Deployment Window",
      scenario:
        "Falcon fires a High-severity detection on SRV-DEPLOY-07, tagged Tactic: Defense Evasion and Technique: Signed Binary Proxy Execution, the LOLBin technique family covered earlier in this room. Review the detection before deciding whether this is a true positive or a false positive.",
      event: regsvr32DeploymentEvent,
      correct_verdict: "false_positive",
      explanation:
        "crowdstrike.UserName is NEXACORP\\svc-sccm, a known deployment service account, not a human user's account behaving unusually. crowdstrike.CommandLine points at an internal deployment path (C:\\ProgramData\\NexaDeploy\\Modules\\...) rather than a generic Temp or AppData location. crowdstrike.PatternDispositionDescription reads 'Detected, no action taken', which only tells you the command ran; as in the log analysis task, a disposition says whether the action happened, not whether it was benign, so it neither clears nor condemns this case. What decides it is the IT verification note: change ticket CHG0052291 authorizing exactly this rollout, on this host, during this window. SeverityName 'High' and Tactic 'Defense Evasion' were assigned automatically the instant the regsvr32 pattern matched, Reading 6's exact point, regardless of who ran it or why.",
      fp_trap:
        "A High-severity Signed Binary Proxy Execution detection is precisely the kind of alert that gets escalated on reflex, because this room's earlier reading and log analysis task both taught you to take LOLBin patterns and credential-access attempts seriously. But High severity here is the tool's automatic technique-based rating, not a verdict on its own: the service account, the internal (not generic) deployment path and the matching change ticket are the specific fields that separate this case from the log analysis task's genuine credential-access attempt. Escalating every LOLBin detection without checking these fields either buries a SOC in noise on every deployment night, or, just as dangerously, teaches the team to stop reading past the technique name entirely.",
      xp: 35,
    },
    // ── Reading 7: pivot & scope ──────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r7",
      heading: "Pivoting and Scoping: Hash Reputation, Network Activity, and the Rest of the Fleet",
      content:
        "Once the process tree is expanded and severity has been reassessed in context, the next move is to step entirely outside the single detection and ask two different questions: what else did this specific file or process do, and has anything like it touched any other host in the environment.\n\n" +
        "**Hash reputation.** SHA256HashData (or mde.SHA256 in Defender) is the field this pivot is built around. Paste it into a threat intelligence platform such as VirusTotal, or the organization's own TIP, to see whether other security vendors already recognize the file as malicious and whether it has appeared in other organizations' incidents. A hash with zero detections isn't proof of innocence on its own (a brand-new or custom-built tool simply won't have a reputation yet) but a hash flagged by a dozen independent vendors as a known credential-dumping utility removes almost all remaining doubt.\n\n" +
        "**Network and file pivot.** Expand beyond the single flagged process to everything else it touched: did it make an outbound network connection, to what domain or IP address; was any file written to disk afterward, such as a memory-dump artifact or a second-stage payload; was any registry key modified for persistence. Both Falcon's Investigate module and Defender's device timeline let an analyst walk this out visually, one connected action at a time.\n\n" +
        "**Scoping across the fleet.** The single most important pivot for actually containing an intrusion before it spreads further is asking whether the same file hash, or the same behavior pattern, has appeared on any other host in the environment. This is the exact question that turns 'one workstation has a problem' into either 'good, this is contained to a single machine' or 'this hash is already present on four other hosts, and the real incident is considerably larger than the first detection suggested.'\n\n" +
        "**Why this is a query, not a click.** Fleet-wide scoping is exactly what a hunting query is built for, whether written in CrowdStrike's own query language inside the Falcon console, or in Microsoft Defender's Advanced Hunting KQL against tables like DeviceProcessEvents. The exercise that follows has you write exactly this kind of hunt yourself, using the hash from this room's log analysis finding.",
      codeExample:
        "Microsoft Defender Advanced Hunting (KQL). Has this hash run anywhere else\n" +
        "DeviceProcessEvents\n" +
        "| where SHA256 == \"b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a\"\n" +
        "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine\n\n" +
        "The same question, asked inside CrowdStrike, uses Falcon's own query\n" +
        "language against SHA256HashData instead of KQL against SHA256: different\n" +
        "syntax, identical investigative question.",
    },
    // ── Query Fill: hunt the same hash across the fleet ──────────────────────
    {
      type: "query_fill" as const,
      id: "edr-qf1",
      heading: "Write It Yourself: Hunt What the Dumper Launched, Fleet-Wide",
      language: "kql" as const,
      context:
        "Reading 7's hunt already asks whether the file from WKS-FIN-0231 ran anywhere else. The team now wants the next question: on any host, which processes did that binary itself START (its children, such as a second-stage tool or an exfiltration helper)? Using Microsoft Defender's Advanced Hunting schema, fill in the table, the column that holds the hash of the process that launched each row's process, and the exact hash from this room's log analysis finding.",
      template:
        "{{table}}\n| where {{field}} == \"{{hash}}\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine",
      blanks: [
        { id: "table", answers: ["DeviceProcessEvents"], placeholder: "Advanced Hunting table for process execution telemetry" },
        { id: "field", answers: ["InitiatingProcessSHA256"], placeholder: "column holding the launching (parent) process's hash" },
        { id: "hash", answers: ["b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a"], placeholder: "exact hash from the log analysis finding" },
      ],
      explanation:
        "DeviceProcessEvents is the Advanced Hunting table for process execution. In each row, SHA256 is the hash of the process that started, while InitiatingProcessSHA256 is the hash of the process that launched it, so filtering InitiatingProcessSHA256 on the dumper's hash returns every child it spawned, on any host. Filtering SHA256 instead would repeat Reading 7's question (where did the dumper itself run). Together the two hunts scope both the file and what it did next, which is the scoping step Reading 7 described. Inside the CrowdStrike console the same idea uses Falcon's own query language and parent-process fields.",
      xp: 30,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "edr-f1",
      event: lsassAccessEvent, // show the WKS-FIN-0231 log this flag reads
      prompt:
        "The credential-access behavior on WKS-FIN-0231 ran unblocked, so the account whose session ran the dumper is the first credential to rotate. Which account was it? Enter the account name without the domain prefix.",
      answer: "r.callahan",
      hint: "The raw event records the user context of the flagged process; drop the part before the backslash.",
      xp: 20,
    },
    // ── Question 4 — containment decision ────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q4",
      question:
        "On WKS-FIN-0231, the credential-access behavior is confirmed as a true positive: PatternDispositionDescription showed 'Detected, no action taken', and the SHA256 hash pivots back as a known credential-dumping utility in your threat intelligence platform. What is the correct immediate containment action?",
      options: [
        "Power the host off: a hard shutdown stops all activity and keeps memory in the hibernation file",
        "Network-contain it via the EDR console, kill the process, and treat its credentials as exposed",
        "Kill the process and delete the binary, but leave the network up so the user can keep working",
        "Re-image the host right away, since a clean rebuild removes the dumper and any persistence",
      ],
      answer: 1,
      explanation:
        "EDR network containment cuts the host off while keeping it reachable through the console for forensics; killing the process stops the activity, and because the LSASS access was never blocked, credentials used on the host are treated as exposed. “Power the host off…” destroys volatile memory: a hard shutdown is not hibernation, and nothing is written to a hibernation file. “Kill the process and delete the binary…” leaves an attacker with a foothold free to relaunch over the network, and does nothing about the stolen credentials. “Re-image the host right away…” destroys the evidence needed to scope the incident, and the stolen credentials remain valid after the rebuild.",
      xp: 30,
    },
    // ── Question 5 — cross-host hash scoping escalation ─────────────────────
    {
      type: "question" as const,
      id: "edr-q5",
      question:
        "Two days later, a new Falcon detection fires on a completely different host, and its crowdstrike.SHA256HashData exactly matches the hash from the WKS-FIN-0231 case. What does this tell you, and what should you do?",
      options: [
        "A separate incident on that host: open a new case and handle it independently of the first",
        "The same file on a second host: one incident, so re-scope the fleet before calling it contained",
        "Re-image the second host straight away and close, since the hash is already known to be bad",
        "A duplicate of the handled case: WKS-FIN-0231 is contained, so close it after a quick look",
      ],
      answer: 1,
      explanation:
        "An identical SHA256 means, for practical purposes, the same file, so the incident is larger than the first host and you re-run fleet-wide scoping before treating it as contained. “A separate incident…” splits one attacker’s activity into unconnected cases and loses the link to the first investigation. “Re-image the second host straight away and close…” skips scoping: if the file reached a second host, it may be on others. “A duplicate of the handled case…” assumes containing the first host contained the incident, which the new detection disproves.",
      xp: 30,
    },
  ],
};

export const roomsBatch28 = [edrDetectionInvestigationRoom];
