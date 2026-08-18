/**
 * Learning Rooms — Batch 35
 *
 * One deep, authoring-focused room closing the sharpest Tier-1 -> Tier-2 gap
 * flagged in docs/LEARNING-ROOMS-EXPERT-REVIEW-2026-08.md: the platform
 * already teaches students to READ and TUNE Sigma rules (detection-rules-
 * tuning, detection-engineering) and to READ a YARA rule (malware-analysis-
 * fundamentals), but no room ever hands a student a blank page and an
 * attacker technique and asks them to WRITE the detection logic themselves.
 *
 * This room assumes both of those rooms already happened and deliberately
 * does not re-teach what they already cover (Sigma's title/id/logsource/
 * detection/condition/falsepositives/level/tags section names, the OR-by-
 * default list behavior, the SigmaHQ/pySigma ecosystem, YARA's meta/strings/
 * condition shape and its three string types). Instead it teaches the next
 * layer: field modifiers (|contains|all, |startswith, |endswith, |re),
 * multi-block quantifiers (1 of selection_*, all of them), how a Sigma rule
 * actually compiles into a running KQL/SPL query, YARA's sharper operators
 * (hex wildcard gaps, filesize, #count, @offset, fullword), and — in both
 * formats — the specific-vs-brittle tuning discipline of writing a rule that
 * survives the next variant of an attack without flooding the queue on
 * everything else.
 *
 * Room in this batch:
 *  1. sigma-yara-rule-authoring — write pieces of a real Sigma rule
 *     (LOLBin scriptlet execution, shadow-copy deletion / T1490) and a real
 *     YARA rule (PHP webshell family), compile a Sigma rule to KQL by hand,
 *     and judge a brittle rule against a tuned one on a live event.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Writing Detection Rules: Sigma & YARA Authoring
// ===========================================================================

const acEncodedPowerShellEvent: TelemetryEvent = {
  id: "evt-sigyara-ac1-001",
  ts: "2026-04-14T10:22:07.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "process_create",
  severity: "high",
  hostname: "WKS-MKT-0447",
  user_email: "p.doran@meridianretail.com",
  mitre_technique: "T1059.001",
  mitre_tactic: "Execution",
  description:
    "A Sigma rule tuned to match the -enc or -EncodedCommand PowerShell flag, case-insensitively, matched this process creation event.",
  process: {
    name: "powershell.exe",
    pid: 7784,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "WINWORD.EXE",
    parent_pid: 5192,
    cmdline: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    user: "MERIDIAN\\p.doran",
  },
  raw: {
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "event.code": "1",
    "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "winlog.event_data.ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "winlog.event_data.ParentCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\p.doran\\Downloads\\Q2_Vendor_Invoice.docm\"",
    "winlog.event_data.CommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "winlog.event_data.User": "MERIDIAN\\p.doran",
    "winlog.event_data.IntegrityLevel": "Medium",
    "winlog.event_data.Hashes": "SHA256=91E3E6A6C4B4E5D3F2A0C9B8E7D6F5A4C3B2A1908F7E6D5C4B3A2918070605040",
    "event.action": "process-create",
  },
};

const lsassSigmaAlertEvent: TelemetryEvent = {
  id: "evt-sigyara-la1-001",
  ts: "2026-05-03T09:14:22.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_access",
  severity: "critical",
  hostname: "WKS-CLM-1187",
  user_email: "n.brandt@solvarahealth.com",
  mitre_technique: "T1003.001",
  mitre_tactic: "Credential Access",
  description:
    "A custom Sigma rule mapped onto this SIEM's CrowdStrike Falcon data source matched this LSASS access event. Review the rule's own selection and filter logic against the raw fields below.",
  process: {
    name: "SysHealthMon.exe",
    pid: 4488,
    path: "C:\\Users\\n.brandt\\AppData\\Roaming\\SysHealthMon\\SysHealthMon.exe",
    parent_name: "explorer.exe",
    parent_pid: 3120,
    cmdline: "\"SysHealthMon.exe\" -silent",
    user: "SOLVARA\\n.brandt",
    hash: { sha256: "a4e8f1c62b7d0e935a2f6c8b1d4e7f092a5c8b3d6e1f4a7092c5b8d3e6f1a4c7" },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessAccess",
    "crowdstrike.DetectId": "ldt:5c2d8a1e4f96b3c07d2a9e6f1b4c8d3a:73004",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Credential Access",
    "crowdstrike.Technique": "OS Credential Dumping",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "explorer.exe",
    "crowdstrike.ParentProcessName": "explorer.exe",
    "crowdstrike.FileName": "SysHealthMon.exe",
    "crowdstrike.FilePath": "C:\\Users\\n.brandt\\AppData\\Roaming\\SysHealthMon\\SysHealthMon.exe",
    "crowdstrike.CommandLine": "\"SysHealthMon.exe\" -silent",
    "crowdstrike.SHA256HashData": "a4e8f1c62b7d0e935a2f6c8b1d4e7f092a5c8b3d6e1f4a7092c5b8d3e6f1a4c7",
    "crowdstrike.TargetProcessName": "lsass.exe",
    "crowdstrike.GrantedAccess": "0x1FFFFF",
    "crowdstrike.CallStackModuleNames": "dbghelp.dll,KERNELBASE.dll,ntdll.dll",
    "crowdstrike.UserName": "SOLVARA\\n.brandt",
    "crowdstrike.HostName": "WKS-CLM-1187",
    "event.action": "process-access",
    "event.outcome": "success",
  },
};

const sigmaYaraRuleAuthoringRoom = {
  id: "sigma-yara-rule-authoring",
  title: "Writing Detection Rules: Sigma & YARA Authoring",
  description:
    "Detection Engineering Fundamentals taught you to read a complete Sigma rule. Malware Analysis Fundamentals taught you to read a YARA rule. Neither one handed you a blank page. This room does: the field modifiers and multi-block quantifiers Sigma rules actually need, how a rule you write compiles into a real KQL query, YARA's sharper string and condition operators, and the specific-vs-brittle discipline of tuning a rule so it survives the next variant of an attack without flooding the queue on everything else.",
  difficulty: "advanced" as const,
  category: "SIEM",
  estimatedMinutes: 70,
  xp: 400,
  icon: "🛠️",
  prerequisites: ["detection-engineering", "malware-analysis-fundamentals"],
  tasks: [
    // ── Reading 1: framing ───────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r1",
      heading: "From Reading Rules to Writing Them",
      content:
        "Detection Engineering Fundamentals already walked you through a complete Sigma rule, field by field — title, id, status, logsource, detection, condition, falsepositives, level, tags — and the organizational lifecycle a rule travels through from a threat idea to a retired detection nobody needs anymore. Malware Analysis Fundamentals already introduced YARA's three-part shape and its three string types: text, hex bytes, and regular expressions. If either of those feels distant, you can still recognize the pieces; that is enough to start here, because reading a rule fluently and writing one from a blank page turn out to be two different skills entirely.\n\n" +
        "Both of those earlier rooms taught you to read a rule someone else already wrote. Neither one handed you a blank page, a specific attacker technique, and asked you to produce the actual detection logic yourself: the field-level modifiers that decide whether a rule survives the next slightly-different variant of an attack or quietly stops working the day it changes, the multi-block conditions a technique with several tool variants genuinely needs, and the discipline of testing a draft against both malicious and benign material before anyone trusts it in production. That authoring skill — not rule-reading — is what actually separates an analyst who tunes exclusions into a rule someone else wrote from one who builds the detections the rest of the team relies on.\n\n" +
        "Almost every authoring mistake, in either format, falls into one of two directions. Write the logic too broadly — one common function call, one generic path fragment, one loosely related keyword — and the rule floods the queue with legitimate activity that happens to share that single trait, until analysts stop reading alerts from it at all. Write it too narrowly — hardcode one exact command-line string, one literal byte sequence lifted from a single sample — and the very next variant, with different casing, different whitespace, or a recompiled binary, sails through completely untouched. Recognizing which direction a rule has drifted turns out to matter just as much as writing the first draft, and this room spends real time on both directions in both formats.\n\n" +
        "The path through this room follows the order a rule actually gets built in practice: the specific modifiers and quantifiers Detection Engineering Fundamentals did not cover, one complete Sigma rule built up from a real technique step by step, watching that rule turn into an actual running KQL query, and testing your own judgment on a side-by-side comparison of a brittle rule and a properly tuned one. Then the exact same discipline, applied to YARA: the operators Malware Analysis Fundamentals left out, and a webshell rule built up the same deliberate way, narrow draft to broad draft to a tuned final version. By the end, you will have written pieces of both — not just read them.",
      checkpoint: {
        question: "Per Reading 1, what are the two failure modes that most detection-rule authoring mistakes fall into?",
        options: [
          "Writing the rule in the wrong file format, and forgetting to add a title field",
          "Writing the logic too broadly, which floods the queue with legitimate matches, and writing it too narrowly, which lets the next variant of the same attack through untouched",
          "Choosing the wrong severity level, and forgetting to add MITRE ATT&CK tags",
          "Testing the rule against too much historical data, and deploying it too quickly after writing it",
        ],
        answer: 1,
        explanation:
          "Reading 1 named these as the two directions almost every authoring mistake falls into: too broad drowns the queue in false positives and trains analysts to stop reading that rule's alerts; too narrow misses the very next variant of the technique it was written to catch. The other options describe real but much smaller mistakes that Reading 1 did not identify as the core recurring failure modes.",
      },
    },
    // ── Reading 2: Sigma modifiers & quantifiers ────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r2",
      heading: "Sigma Modifiers and Multi-Block Quantifiers",
      content:
        "Detection Engineering Fundamentals showed CommandLine|contains with a list of values and explained that Sigma evaluates a list under one field as OR — matching if the field contains any one of the listed items. That much is already familiar. What it did not cover is the modifier that flips that default, the modifiers that anchor a match instead of searching anywhere in a string, the regex escape hatch, and the way a condition can combine more than one named block at once — all four of which come up constantly the moment a rule needs to describe more than one simple pattern.\n\n" +
        "Start with the AND-versus-OR distinction, because it is the single most common way a new rule ends up looser than its author intended. CommandLine|contains|all: ['-nop', '-enc'] only matches when both substrings appear somewhere in the same command line — genuinely different from a plain |contains list, which matches on any one item alone. Writing |contains with a list when the actual intent was 'both of these together' silently turns a tight rule into a much looser one, because it will now also fire on command lines that only happen to contain one of the two.\n\n" +
        "Image|startswith and Image|endswith anchor a match to one specific end of a field's value, instead of searching for the substring anywhere inside it. Image|endswith: '\\regsvr32.exe' matches any path ending in that string regardless of install directory — deliberately loose about where the binary lives, deliberately strict about what the binary actually is. Anchoring matters because an unanchored |contains: 'regsvr32' would also match a completely unrelated file simply named something like regsvr32_wrapper_notes.txt, or a command line that merely mentions the word inside a passed argument or comment.\n\n" +
        "CommandLine|re: applies a full regular expression, the modifier reserved for anything the simpler ones cannot express precisely enough — a specific numeric pattern, an argument that has to appear in a particular position, several optional variants at once. It is also, exactly like YARA's regex strings covered later in this room, the modifier most likely to run slowly or match far more than intended if written carelessly; reach for the simpler modifiers first and treat |re as the tool for when they genuinely cannot do the job.\n\n" +
        "Finally, a condition is not limited to one named block. Real techniques often have more than one tool that can carry them out — regsvr32.exe and rundll32.exe are both LOLBins abused for similar scriptlet-execution purposes. Writing separate named blocks, selection_regsvr32 and selection_rundll32 as shown below, then combining them with 1 of selection_* — matching if any block whose name starts with selection matches — lets one rule cover every known tool variant of the same technique instead of either missing half of them or cramming incompatible logic into a single unreadable block. Reading 3 builds an entire rule around exactly this same shape, for a different technique: vssadmin.exe versus wmic.exe, both deleting the same shadow copies. all of them, by contrast, requires every defined block to match at once — the tightest possible combination, reserved for the rarer case where several distinct signals all have to be present together.",
      codeExample:
        "title: Suspicious LOLBin Scriptlet Execution via regsvr32 or rundll32\n" +
        "id: 8a4f1c72-6b3e-4d9a-9f21-3c7e5b8a1d64\n" +
        "status: stable\n" +
        "description: Detects regsvr32.exe or rundll32.exe invoked with arguments consistent\n" +
        "  with remote scriptlet execution, rather than routine local DLL or COM registration.\n" +
        "references:\n" +
        "  - https://attack.mitre.org/techniques/T1218/010/\n" +
        "  - https://attack.mitre.org/techniques/T1218/011/\n" +
        "author: SOC Detection Engineering\n" +
        "date: 2026/02/25\n" +
        "tags:\n" +
        "  - attack.defense_evasion\n" +
        "  - attack.t1218.010\n" +
        "  - attack.t1218.011\n" +
        "logsource:\n" +
        "  category: process_creation\n" +
        "  product: windows\n" +
        "detection:\n" +
        "  selection_regsvr32:\n" +
        "    Image|endswith: '\\regsvr32.exe'\n" +
        "    CommandLine|contains|all:\n" +
        "      - 'scrobj.dll'\n" +
        "      - 'http'\n" +
        "  selection_rundll32:\n" +
        "    Image|endswith: '\\rundll32.exe'\n" +
        "    CommandLine|contains: 'javascript:'\n" +
        "  filter_known_deploy:\n" +
        "    ParentImage|startswith: 'C:\\ProgramData\\NexaDeploy\\'\n" +
        "  condition: 1 of selection_* and not filter_known_deploy\n" +
        "falsepositives:\n" +
        "  - Internal software deployment tooling that legitimately registers local COM\n" +
        "    controls through a scripted wrapper\n" +
        "level: high",
      checkpoint: {
        question: "Per Reading 2, what is the difference between CommandLine|contains: ['-nop', '-enc'] and CommandLine|contains|all: ['-nop', '-enc']?",
        options: [
          "There is no difference — both syntaxes are interchangeable ways of writing the exact same logic",
          "The first requires either substring to be present (OR); the second requires both substrings to be present somewhere in the same command line (AND)",
          "The first only matches PowerShell processes; the second matches any process regardless of binary",
          "The first is case-sensitive by default; the second is case-insensitive by default",
        ],
        answer: 1,
        explanation:
          "A list under a plain field|modifier is evaluated as OR by default — matching if any one item is present. Adding |all changes that to AND — every item in the list must be present. Confusing the two, as Reading 2 pointed out, is one of the most common ways a rule ends up looser than the author intended. Neither syntax restricts which binary it applies to (that is the Image field's job) or changes case sensitivity, which is a separate, unrelated setting.",
      },
    },
    // ── Question 1 — condition operators applied ─────────────────────────────
    {
      type: "question" as const,
      id: "sigyara-q1",
      question:
        "A Sigma detection block reads:\n\nselection:\n  Image|endswith: '\\powershell.exe'\n  CommandLine|contains|all:\n    - '-nop'\n    - '-enc'\ncondition: selection\n\nWhich of these command lines would this selection actually match?",
      options: [
        "cmd.exe /c whoami",
        "powershell.exe -Command Get-ChildItem C:\\Temp",
        "powershell.exe -nop -w hidden -enc JABzAGUAYwB1AHIAZQ...",
        "powershell.exe -windowstyle hidden -encodedcommand JABzAGUAYwB1AHIAZQ...",
      ],
      answer: 2,
      explanation:
        "Option a fails Image|endswith entirely — cmd.exe never ends in powershell.exe, so this selection cannot match it regardless of its command line. Option b is the right binary but its command line contains neither '-nop' nor '-enc' as substrings, so contains|all fails on both required items. Option c is the right binary and its command line contains both '-nop' and '-enc' as literal substrings, satisfying contains|all completely — this is the only match. Option d contains '-enc' as a substring of '-encodedcommand', but never contains '-nop' anywhere, so contains|all still fails on one of the two required items — a rule using |contains|all needs every listed substring present, not just one of them.",
      xp: 25,
    },
    // ── Reading 3: Sigma step-by-step case study ────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r3",
      heading: "Writing a Sigma Rule Step by Step: Shadow Copy Deletion",
      content:
        "Now build a complete rule from scratch, using the multi-block pattern Reading 2 introduced, for a genuinely different technique: ransomware operators, in the minutes before they start encrypting files, routinely delete the Volume Shadow Copies Windows keeps as local recovery points — because a victim who can just restore yesterday's files from a shadow copy has no reason to pay a ransom. The two most common tools for that specific action are vssadmin.exe, Windows' own built-in shadow-copy management utility, and wmic.exe, invoked with its shadowcopy alias. This single hypothesis — a specific, well-documented pre-encryption step, MITRE ATT&CK T1490, Inhibit System Recovery — is what the whole rule gets built around.\n\n" +
        "Step one is always a hypothesis stated in plain language, not syntax, exactly as above. Step two is the logsource: this is process-launch activity, which on a Windows endpoint means logsource: category: process_creation, product: windows.\n\n" +
        "Step three is drafting the selection. A first attempt might be a single loose match: CommandLine|contains: 'delete shadows' — but this is already wrong in two different directions at once. It is too narrow in one direction, because it misses wmic's entirely different phrasing. And it is too broad in another, separately, because a bare string search with no anchor on the binary itself could in principle match a log line, a ticket comment, or a script filename containing that same phrase for an unrelated reason. The fix is two named selection blocks, one per tool. selection_vssadmin requires Image|endswith: '\\vssadmin.exe' together with CommandLine|contains|all: ['delete', 'shadows'] — both words must appear, in any order, which survives minor phrasing differences while still anchoring to the real binary. selection_wmic requires Image|endswith: '\\wmic.exe' together with CommandLine|contains: 'shadowcopy delete' as one combined phrase, since that is how the wmic alias syntax is actually invoked.\n\n" +
        "Step four is the condition: selection_vssadmin or selection_wmic — either tool tripping the pattern is enough on its own to fire the rule; there is no reason to require both in the same event, since a single execution only ever uses one of them.\n\n" +
        "Step five is falsepositives, and honesty here matters more than completeness: backup software performing scheduled shadow-copy cleanup as part of its own retention policy, and IT administrators manually freeing disk space on a documented change ticket, are the two realistic sources of legitimate matches — writing this list down is what lets a future analyst triage a hit in thirty seconds instead of re-deriving the same reasoning from scratch.\n\n" +
        "Step six is level and tags: level: high, because a confirmed shadow-copy deletion this close to encryption has essentially no benign majority-case even though the false positives above are real and worth checking first; tags: attack.impact and attack.t1490 map the rule directly to its ATT&CK technique, which is what lets a coverage report later confirm this technique is actually detected rather than just documented as a gap.",
      codeExample:
        "title: Shadow Copy Deletion via vssadmin or wmic\n" +
        "id: 4b6a1f2e-9c3d-4a7b-8e21-6f0a9d3c5b17\n" +
        "status: stable\n" +
        "description: Detects deletion of Volume Shadow Copies via vssadmin.exe or wmic.exe\n" +
        "  shadowcopy delete, a common ransomware pre-encryption step that removes local\n" +
        "  backup and recovery points.\n" +
        "references:\n" +
        "  - https://attack.mitre.org/techniques/T1490/\n" +
        "author: SOC Detection Engineering\n" +
        "date: 2026/03/10\n" +
        "tags:\n" +
        "  - attack.impact\n" +
        "  - attack.t1490\n" +
        "logsource:\n" +
        "  category: process_creation\n" +
        "  product: windows\n" +
        "detection:\n" +
        "  selection_vssadmin:\n" +
        "    Image|endswith: '\\vssadmin.exe'\n" +
        "    CommandLine|contains|all:\n" +
        "      - 'delete'\n" +
        "      - 'shadows'\n" +
        "  selection_wmic:\n" +
        "    Image|endswith: '\\wmic.exe'\n" +
        "    CommandLine|contains: 'shadowcopy delete'\n" +
        "  condition: selection_vssadmin or selection_wmic\n" +
        "falsepositives:\n" +
        "  - Backup software performing scheduled shadow copy cleanup as part of its own\n" +
        "    retention policy\n" +
        "  - IT administrators manually clearing disk space on a documented change ticket\n" +
        "level: high",
      checkpoint: {
        question: "Per Reading 3, why does the selection use CommandLine|contains|all: ['delete', 'shadows'] instead of a single CommandLine|contains: 'delete shadows' phrase match?",
        options: [
          "Because |contains|all runs faster than a single phrase match, which matters for high-volume log sources",
          "Because requiring both words to be present, in any order, survives minor phrasing or word-order differences while still anchoring to the real binary — a single exact phrase would miss any variant that phrases the command slightly differently",
          "Because Sigma does not support multi-word phrase matching inside a single contains modifier under any circumstances",
          "Because 'delete' and 'shadows' need to be evaluated by two entirely separate detection rules, not one",
        ],
        answer: 1,
        explanation:
          "Reading 3 was explicit: two words that must both be present, in any order, survive small variations in exact phrasing that a single literal phrase match would miss entirely. Option a invents a performance claim the reading never made; option c is simply false — Sigma's contains modifier can absolutely match a literal multi-word phrase, that is just not the best choice here; option d misdescribes what a single selection block does.",
      },
    },
    // ── Query Fill: complete the Sigma selection block ──────────────────────
    {
      type: "query_fill" as const,
      id: "sigyara-qf1",
      heading: "Write It Yourself: Complete the Selection Block for Shadow Copy Deletion",
      language: "kql" as const,
      context:
        "This task type's language badge only supports KQL, SPL, or PowerShell — the content below is Sigma YAML, not KQL. Reading 3 built the vssadmin branch of the shadow-copy-deletion rule step by step. Reproduce its selection_vssadmin block from memory: the field that identifies the binary itself, the modifier that requires every listed word to be present, and the condition value that fires on this block alone.",
      template:
        "selection_vssadmin:\n  {{field}}|endswith: '\\vssadmin.exe'\n  CommandLine|contains|{{modifier}}:\n    - 'delete'\n    - 'shadows'\ncondition: {{condition}}",
      blanks: [
        { id: "field", answers: ["Image"], placeholder: "field name for the process binary path" },
        { id: "modifier", answers: ["all"], placeholder: "modifier requiring every listed word present" },
        { id: "condition", answers: ["selection_vssadmin"], placeholder: "condition value for this block alone" },
      ],
      explanation:
        "Image is the field Sigma's process_creation category uses for the binary path, and |endswith anchors the match to the actual executable rather than any substring anywhere in a string. |contains|all is what requires both 'delete' and 'shadows' to be present, in any order, surviving small phrasing differences the way Reading 3 described. condition: selection_vssadmin fires on this single named block alone — the full rule later combines it with selection_wmic using or, but this exercise is just the vssadmin branch on its own.",
      xp: 30,
    },
    // ── Reading 4: compiling Sigma to KQL/SPL ───────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r4",
      heading: "From Sigma to Query: How a Rule Actually Runs",
      content:
        "Once a Sigma rule exists, it still has to become a query some SIEM actually runs — and the tool that does that translation is pySigma, the current open-source library (the older sigma-cli tool wraps the same underlying idea, and Detection Engineering Fundamentals already used it to compile a different rule to Splunk SPL). Two things determine what comes out the other end: the backend, which is the target query language, and the pipeline, which maps Sigma's generic field names — Image, CommandLine, TargetProcessName — onto whatever column names the chosen data source actually uses once it lands in that SIEM.\n\n" +
        "Walk the shadow-copy-deletion rule from Reading 3 through this process. Its logsource, category: process_creation, product: windows, tells the pipeline this rule targets process-launch telemetry — which, once mapped onto a specific Microsoft Sentinel table, becomes DeviceProcessEvents. Image becomes FolderPath, and CommandLine becomes ProcessCommandLine. The condition's boolean logic translates directly: and becomes a chain of KQL where clauses joined with and, or becomes literal or, and the contains|all modifier from selection_vssadmin becomes two separate has clauses joined with and — has being KQL's own substring-match operator, doing exactly the same job |contains does in Sigma.\n\n" +
        "Compiled for a Splunk backend against the same rule, the field-name mapping looks different again, because Splunk's own convention, when data arrives straight from a Windows or Sysmon technology add-on, frequently keeps the original field names Sigma already uses — Image stays Image, CommandLine stays CommandLine — with the translation work happening mostly in the search syntax itself.\n\n" +
        "The practical payoff is what makes this worth learning at all: the actual detection reasoning — which technique, which exact field values distinguish it, which known-good sources need excluding — gets captured exactly once, in the Sigma rule. Migrating to a new SIEM, or simply running the same detection logic in two SIEMs during a transition period, becomes a matter of running a different backend, not re-deriving the entire rule from scratch in an unfamiliar query language.",
      codeExample:
        "Sigma detection (Reading 3, vssadmin branch only):\n" +
        "  selection_vssadmin:\n" +
        "    Image|endswith: '\\vssadmin.exe'\n" +
        "    CommandLine|contains|all:\n" +
        "      - 'delete'\n" +
        "      - 'shadows'\n" +
        "  condition: selection_vssadmin\n\n" +
        "Compiles to Microsoft Sentinel KQL:\n" +
        "DeviceProcessEvents\n" +
        "| where FolderPath endswith @'\\vssadmin.exe'\n" +
        "| where ProcessCommandLine has 'delete' and ProcessCommandLine has 'shadows'\n\n" +
        "Compiles to Splunk SPL:\n" +
        "index=main sourcetype=WinEventLog:Sysmon EventCode=1 Image=\"*\\vssadmin.exe\" CommandLine=\"*delete*\" CommandLine=\"*shadows*\"",
      diagram:
        "flowchart LR\n" +
        "  A[Sigma rule YAML] --> B[pySigma parser]\n" +
        "  B --> C{Backend and pipeline}\n" +
        "  C --> D[Microsoft Sentinel KQL]\n" +
        "  C --> E[Splunk SPL]\n" +
        "  C --> F[Elastic EQL]\n",
      diagramCaption: "One Sigma rule, compiled to many SIEM query languages",
      checkpoint: {
        question: "Per Reading 4, when a Sigma rule is compiled to Splunk SPL instead of Microsoft Sentinel KQL, what actually changes?",
        options: [
          "The underlying detection logic has to be rewritten by hand for each SIEM, since Sigma only ever targets one backend at a time",
          "The field names, table names, and query syntax change to match the target backend's schema, but the analyst's detection reasoning captured in the Sigma rule itself does not need to be rewritten",
          "Nothing changes at all — Sigma rules are already valid SPL and KQL simultaneously with no conversion step required",
          "Only the rule's severity level changes between backends, since KQL and SPL score severity differently",
        ],
        answer: 1,
        explanation:
          "This is the entire point of writing detection logic in Sigma rather than directly in one SIEM's query language: the backend and pipeline choice handles the mechanical translation of field and table names, while the actual reasoning — which technique, which values, which exclusions — is captured once in the Sigma rule and does not need to be rethought for every SIEM the organization happens to run.",
      },
    },
    // ── Query Fill: compile the full OR condition to KQL ────────────────────
    {
      type: "query_fill" as const,
      id: "sigyara-qf2",
      heading: "Write It Yourself: Compile the Full OR Condition to KQL",
      language: "kql" as const,
      context:
        "Reading 3's full condition is selection_vssadmin or selection_wmic. Extend Reading 4's KQL translation so it also matches the wmic.exe branch, combined the same way the Sigma condition combines the two selections.",
      template:
        "DeviceProcessEvents\n| where (FolderPath endswith @'\\vssadmin.exe' and ProcessCommandLine has 'delete' and ProcessCommandLine has 'shadows')\n   {{op}} (FolderPath endswith @'\\wmic.exe' and ProcessCommandLine has '{{phrase}}')",
      blanks: [
        { id: "op", answers: ["or"], placeholder: "boolean operator combining the two branches" },
        { id: "phrase", answers: ["shadowcopy delete"], placeholder: "combined phrase the wmic branch matches" },
      ],
      explanation:
        "Sigma's selection_vssadmin or selection_wmic maps directly onto KQL's own or, combining the two parenthesized branches exactly the way the Sigma condition combines the two named blocks. The wmic branch matches the literal combined phrase 'shadowcopy delete', which is how the wmic shadowcopy alias is actually invoked on the command line, exactly as Reading 3 described.",
      xp: 30,
    },
    // ── Matching: Sigma modifiers + YARA operators ───────────────────────────
    {
      type: "matching" as const,
      id: "sigyara-m1",
      heading: "Match the Modifier or Operator to What It Actually Does",
      instructions: "These are the field-level modifiers and condition operators this room covers, beyond the section names Detection Engineering Fundamentals and Malware Analysis Fundamentals already taught. Match each one to its behavior.",
      pairs: [
        { id: "containslist", left: "Sigma: field|contains: [a, b]", right: "OR logic — matches if the field contains either listed substring" },
        { id: "containsall", left: "Sigma: field|contains|all: [a, b]", right: "AND logic — matches only if the field contains both listed substrings" },
        { id: "anchors", left: "Sigma: field|startswith / field|endswith", right: "Anchors the match to the beginning or end of the field's value, instead of matching the substring anywhere inside it" },
        { id: "regex", left: "Sigma: field|re", right: "Applies a full regular expression — the most flexible modifier, and the easiest to accidentally write too broadly" },
        { id: "oneof", left: "Sigma: 1 of selection_*", right: "Matches if any one of several named blocks whose names share that prefix matches — useful when one technique has multiple tool variants" },
        { id: "allof", left: "Sigma: all of them", right: "Requires every named detection block in the rule to match simultaneously" },
        { id: "yaramods", left: "YARA: nocase / fullword / wide", right: "String modifiers: case-insensitive matching, whole-word-only matching, and matching the UTF-16 encoding Windows binaries commonly use internally" },
        { id: "filesize", left: "YARA: filesize < 150KB", right: "Bounds the rule to a realistic size range for the artifact being hunted, cheaply eliminating unrelated content before string matching even runs" },
        { id: "count", left: "YARA: #string_name", right: "Counts how many times a given string occurs in the file — distinguishes a one-off legitimate call from the same call repeated inside an obfuscation loop" },
        { id: "offset", left: "YARA: @string_name[1] / string at 0", right: "Gives the byte offset of a string's occurrence, letting a condition anchor a match to a specific location such as the very start of the file" },
      ],
      explanation:
        "None of these operators replace good pattern selection by themselves — they sharpen it. |contains|all and 1 of selection_* let a Sigma rule describe several tool variants of one technique precisely instead of one loose guess. filesize, #count, and offset anchoring let a YARA rule use structural facts about the file, not just string presence, to separate a real match from an unrelated one. Confusing OR-by-default with the |all AND modifier is the single most common way a new rule ends up looser than intended.",
      xp: 35,
    },
    // ── Ordering: iterating a rule's own detection logic ────────────────────
    {
      type: "ordering" as const,
      id: "sigyara-o1",
      heading: "Order the Steps of Tuning a Single Rule's Detection Logic",
      instructions: "This is not the organizational rollout lifecycle (alert-only, promote, retire) covered elsewhere — it is the narrower loop of shaping one rule's own logic from a technique into something tuned, the way Readings 3 and 6 each did. Put these steps in order.",
      items: [
        { id: "state", text: "State the specific attacker technique this rule needs to catch, in plain language, before writing any syntax" },
        { id: "draft", text: "Write a first draft using the most obvious single indicator you can think of" },
        { id: "check", text: "Check whether that single indicator is too broad (matches unrelated legitimate activity) or too narrow (only matches one historical sample)" },
        { id: "corroborate", text: "Add a second, independent indicator so the rule requires several individually-common signals together, rather than relying on one alone" },
        { id: "anchor", text: "Anchor the rule to the smallest realistic scope available — a file-size ceiling, a specific binary, a specific log source — to cut unrelated matches cheaply" },
        { id: "test", text: "Test the draft against both a known-malicious sample or event and a known-benign corpus, not just one or the other" },
        { id: "document", text: "Document the false positives actually found as the rule's falsepositives or meta notes, not a guess" },
        { id: "assign", text: "Only then assign the rule its severity or level field and hand it off for deployment" },
      ],
      correct_order: ["state", "draft", "check", "corroborate", "anchor", "test", "document", "assign"],
      explanation:
        "This is exactly the loop Reading 3 ran for the vssadmin rule (a loose single-phrase draft, checked, then split into two anchored, corroborated blocks) and Reading 6 ran for the webshell rule (one common string alone, checked, then combined with a second signal and a filesize ceiling). Skipping the check-and-corroborate steps and jumping straight from a first draft to assigning severity is exactly how a brittle or overly broad rule reaches production untested.",
      xp: 30,
    },
    // ── Analyst Choice: brittle vs tuned verdict ─────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "sigyara-ac1",
      heading: "Verdict: Which Rule Actually Caught This, and Why It Matters",
      scenario:
        "Two Sigma rules exist in the SIEM for encoded PowerShell execution, both tagged T1059.001. Rule A was written the week of a specific past incident and hardcodes the exact CommandLine string captured from that one intrusion. Rule B, written afterward specifically to replace it, matches on Image ending in powershell.exe together with CommandLine containing either the -enc or -EncodedCommand flag, case-insensitively, with a filter excluding SCCM-initiated deployments. The alert below just fired from Rule B. Decide whether this is a true positive worth escalating.",
      event: acEncodedPowerShellEvent,
      correct_verdict: "true_positive",
      explanation:
        "winlog.event_data.ParentImage is WINWORD.EXE, not a deployment tool, and an Office application spawning a scripting engine has essentially no legitimate business reason to occur. winlog.event_data.CommandLine carries -enc with a long base64 blob, and winlog.event_data.User is a regular employee account, not a service or automation identity. This alert only exists because Rule B was written to match the structural pattern — the flag itself, case-insensitively — rather than one literal historical string. Rule A, hardcoded to the exact command line from a previous incident, would not have matched this event at all: the base64 payload here is entirely different content, so a byte-for-byte string match fails even though the underlying technique is identical. This is Reading 1's too-narrow failure mode made concrete — a rule that looked precise on the day it was written quietly stopped detecting the technique it was named after the moment a different payload was used.",
      fp_trap:
        "It is tempting to reflexively trust Rule A's tighter-looking match as higher confidence precisely because it is so specific — but that specificity is exactly the flaw. A rule anchored to one sample's literal bytes is not more precise about the technique; it is precise about a single historical artifact that will never recur exactly. Rule B's broader match on the structural pattern (Office parent, scripting engine, encoded-command flag) is what actually keeps catching the technique across different campaigns and different payloads — the SCCM-deployment exclusion is what keeps it from also flooding the queue with legitimate automated use of the same flag.",
      xp: 35,
    },
    // ── Reading 5: YARA sharper operators ────────────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r5",
      heading: "Beyond the Basics: Hex Wildcards, Counting, and Offsets",
      content:
        "Malware Analysis Fundamentals already covered YARA's three-part shape — meta, strings, condition — and its three string types: plain text, hex bytes, and regular expressions, plus the basic condition operators at 0, 1 of (...), and and. This reading picks up exactly where that one left off: the modifiers and operators that turn a rule from roughly right into something a hunt team would actually trust in production.\n\n" +
        "Hex strings support wildcarding, not just fixed byte sequences. { 4D 5A } matches only those exact two bytes back to back — fine for a header that never varies, but real binary structures often have a gap between two fixed landmarks that shifts slightly between compiler versions or build configurations of the same tool. { 40 00 00 00 [4-8] 50 45 00 00 } matches the first four bytes, then any 4 to 8 unknown bytes, then the second four bytes — the bracketed range is YARA's wildcard-gap syntax, and it is what lets a hex pattern survive small structural differences between build variants of the same underlying tool without becoming a full regular expression.\n\n" +
        "String modifiers add one more useful constraint beyond the ascii/wide/nocase trio already covered: fullword requires the match not be embedded inside a larger word — $s = 'admin' fullword would match a standalone argument like -admin but not the substring buried inside administrator, which matters enormously for short, common strings that would otherwise match constantly inside unrelated longer words. Combining modifiers is normal: ascii wide nocase on one string means match both the single-byte and UTF-16 encodings, case-insensitively, in one declaration instead of three.\n\n" +
        "The condition section has more built-in power than and, or, and N of (...). filesize, compared against a size like 150KB or 2MB, bounds a rule to a realistic range for the artifact being hunted — cheaply eliminating an enormous amount of unrelated content before YARA even bothers evaluating a single string pattern, which matters both for accuracy and for how long a large-scale scan actually takes to run. #string_name counts how many times that string occurs in the file: a single incidental appearance of a common function call reads very differently from the same call repeated dozens of times inside an obfuscation loop, and #a > 5 captures exactly that distinction where 1 of ($a) alone cannot. @string_name[1] gives the byte offset of a string's first occurrence, which lets a condition anchor a match to a specific location the way $mz at 0 requires the MZ header to sit at the very first byte of the file — exactly where a genuine executable's header belongs, and nowhere a webshell's decoy content would put it.\n\n" +
        "None of these operators replaces good string selection; they sharpen it. A hex wildcard gap still needs two genuinely meaningful fixed landmarks on either side of it. A count threshold still needs a string worth counting in the first place. The skill this room is actually building — picking signals that are individually common but collectively rare — is exactly the same skill Malware Analysis Fundamentals introduced; these operators are simply sharper tools for expressing it precisely.",
      codeExample:
        "rule Suspicious_Binary_Structure_And_RawIP_Callback\n" +
        "{\n" +
        "    meta:\n" +
        "        author = \"SOC Detection Engineering\"\n" +
        "        description = \"Generic structural indicator for a small PE binary that also embeds a raw-IP HTTP callback pattern, common in loader and stager samples\"\n\n" +
        "    strings:\n" +
        "        $mz    = { 4D 5A }\n" +
        "        $stub  = { 40 00 00 00 [4-8] 50 45 00 00 }\n" +
        "        $c2url = /http:\\/\\/[0-9]{1,3}(\\.[0-9]{1,3}){3}\\/[a-z0-9]{6,10}\\.php/ nocase\n\n" +
        "    condition:\n" +
        "        $mz at 0 and $stub and $c2url and filesize < 2MB\n" +
        "}",
      checkpoint: {
        question: "Per Reading 5, what does the hex pattern { 40 00 00 00 [4-8] 50 45 00 00 } mean?",
        options: [
          "Match the four bytes 40 00 00 00, then any 4 to 8 unknown bytes, then the four bytes 50 45 00 00",
          "Match exactly 4 to 8 occurrences of the byte sequence 40 00 00 00 50 45 00 00 repeated in a row",
          "Match a file that is between 4 and 8 kilobytes in size, containing those two byte sequences anywhere",
          "This syntax is invalid in YARA; hex strings cannot contain wildcard byte ranges",
        ],
        answer: 0,
        explanation:
          "The bracketed range [4-8] inside a hex string is YARA's wildcard-gap syntax: match this many unknown bytes between two fixed byte sequences. It is exactly what Reading 5 used it for — bridging a gap between two structural landmarks that varies slightly between build versions of the same tool. It has nothing to do with file size (that is the separate filesize keyword) or repetition count.",
      },
    },
    // ── Reading 6: YARA step-by-step case study ─────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r6",
      heading: "Writing a YARA Rule Step by Step: A PHP Webshell Family",
      content:
        "The same six-step discipline Reading 3 used for Sigma applies just as directly to YARA, now aimed at a file-hunting problem instead of a log-search one: a compromised web application server needs a rule that catches single-file PHP webshells dropped after an initial-access exploit, without also flagging the thousands of legitimate PHP files already living on that same server.\n\n" +
        "Step one, the hypothesis: a webshell's entire purpose is letting an attacker send commands to a compromised server and have them executed, so nearly every variant shares the same underlying shape — take input from an HTTP request, decode it if it was obfuscated to dodge simple text search, and hand it to eval() or an equivalent execution function. The specific obfuscation wrapper changes constantly (base64, gzinflate-then-base64, rot13, XOR with a hardcoded key); the underlying shape barely does.\n\n" +
        "Step two, drafting the strings, is where the specific-versus-brittle tradeoff has to be made explicit. The most brittle possible rule hardcodes one exact byte-for-byte sample: matching the literal full obfuscated payload string from the one webshell already found in the incident. It will never fire on the next sample, because the next attacker — or the same one, on the next compromised server — will vary a single byte of the encoded blob and invalidate the exact match completely. A rule that specific is really just a hash lookup wearing a YARA rule's clothing. The opposite mistake — a single common string like eval(base64_decode( with no other condition — is exactly the trap this room's own broad-vs-narrow question walks through: any framework, plugin, or license-checking library that happens to call the same two functions together for entirely unrelated reasons will match too, and a rule that fires on hundreds of legitimate files gets disabled by an exhausted analyst within a week.\n\n" +
        "The workable middle ground layers several individually-common, jointly-rare signals: the PHP open tag itself ($php_tag), one of the known obfuscation wrappers ($eval_b64 or $eval_gz — 1 of them, since a given sample will only use one), and one of the superglobal input sources an attacker actually needs to receive their command through ($post_in or $req_in — again 1 of them). None of these three signals is remotely rare by itself. All three appearing together, inside a file also small enough to be a single-purpose dropped script rather than an entire application (filesize < 150KB), essentially never happens by coincidence in ordinary application code.\n\n" +
        "Step three is testing, and for YARA specifically this means two different corpora: run the draft rule against a known-malicious sample set to confirm it still matches the real thing, and — just as importantly — run it against a large known-benign sample set (the organization's own legitimate PHP codebase is ideal) to measure the real-world false-positive rate before the rule goes anywhere near a live alerting pipeline. Many YARA-capable platforms and threat-intel services support retrohunting: running a brand-new rule retroactively against files collected over the past days or weeks, which surfaces both the false-positive rate and any already-present, previously-undetected match, before the rule is trusted for the future.",
      codeExample:
        "rule Webshell_PHP_Obfuscated_Eval_Backdoor\n" +
        "{\n" +
        "    meta:\n" +
        "        author = \"SOC Detection Engineering\"\n" +
        "        description = \"Detects PHP webshells that decode and execute an attacker-supplied payload via base64 or gzinflate-wrapped eval, a common single-file backdoor pattern dropped after a web application compromise\"\n" +
        "        reference = \"internal-ir-2026-0143\"\n" +
        "        date = \"2026-04-02\"\n" +
        "        malware_family = \"generic-php-webshell\"\n\n" +
        "    strings:\n" +
        "        $php_tag  = \"<?php\" ascii\n" +
        "        $eval_b64 = \"eval(base64_decode(\" ascii nocase\n" +
        "        $eval_gz  = \"eval(gzinflate(base64_decode(\" ascii nocase\n" +
        "        $post_in  = \"$_POST[\" ascii\n" +
        "        $req_in   = \"$_REQUEST[\" ascii\n\n" +
        "    condition:\n" +
        "        filesize < 150KB\n" +
        "        and $php_tag\n" +
        "        and 1 of ($eval_b64, $eval_gz)\n" +
        "        and 1 of ($post_in, $req_in)\n" +
        "}",
      checkpoint: {
        question: "Per Reading 6, what is wrong with a YARA rule that hardcodes the exact byte-for-byte obfuscated payload string from one already-found webshell sample?",
        options: [
          "Nothing is wrong with it — an exact byte-for-byte match is always the strongest possible detection a YARA rule can offer",
          "It is too brittle: the very next variant, with even a single byte of the encoded payload changed, will not match at all, even though the underlying technique is identical",
          "It is too broad: matching one exact known-bad sample will flood the queue with unrelated legitimate files",
          "YARA rules cannot match exact byte sequences longer than 64 bytes, so this rule would fail to compile",
        ],
        answer: 1,
        explanation:
          "Reading 6 called this out directly: a rule that specific is really just a hash lookup wearing a YARA rule's clothing — it will never fire on the next sample once even one byte of the obfuscated blob changes, which happens constantly. The opposite mistake, matching too broadly, is the false-positive-flood failure mode (option c), not this one. There is no such length restriction in YARA.",
      },
    },
    // ── Query Fill: complete the YARA webshell condition ────────────────────
    {
      type: "query_fill" as const,
      id: "sigyara-qf3",
      heading: "Write It Yourself: Complete the Webshell YARA Condition",
      language: "powershell" as const,
      context:
        "This task type's language badge only supports KQL, SPL, or PowerShell — the content below is a YARA rule, not PowerShell. Reading 6 built a PHP webshell rule around three joined signals: the PHP open tag, one of two decode-and-eval wrappers, and one of two superglobal input sources, plus a file-size ceiling. Complete the final condition block from memory using the string names already defined in Reading 6's strings section.",
      template:
        "condition:\n  filesize {{sizeop}} 150KB\n  and $php_tag\n  and {{n1}} of ($eval_b64, $eval_gz)\n  and {{n2}} of ($post_in, $req_in)",
      blanks: [
        { id: "sizeop", answers: ["<"], placeholder: "comparison operator for the file-size ceiling" },
        { id: "n1", answers: ["1"], placeholder: "quantifier over the eval-wrapper strings" },
        { id: "n2", answers: ["1"], placeholder: "quantifier over the superglobal-input strings" },
      ],
      explanation:
        "filesize < 150KB keeps the rule scoped to a realistic single-file dropped script rather than an entire application. 1 of ($eval_b64, $eval_gz) matches either obfuscation wrapper, since a given sample only ever uses one. 1 of ($post_in, $req_in) matches either input source the same way. Together these three individually-common signals combine into something jointly rare, exactly as Reading 6 built up step by step.",
      xp: 30,
    },
    // ── Question 2 — too broad / FP flood ────────────────────────────────────
    {
      type: "question" as const,
      id: "sigyara-q2",
      question:
        "A YARA rule for a PHP webshell family is written with a single string and a single-string condition: strings: $s1 = \"eval(base64_decode(\" ascii; condition: $s1 — no filesize limit, no second required string. Deployed against the web server's file share, it fires on 340 files overnight, the large majority of which turn out to be legitimate WordPress and Composer vendor-library files that call the same two functions together for unrelated reasons. What is the most accurate diagnosis and fix?",
      options: [
        "The rule is too broad: a single common function-call string, with no file-size bound and no requirement for a second corroborating signal, matches an enormous amount of unrelated legitimate code. Add a realistic file-size ceiling, require an additional string such as one of the superglobal input sources, and combine both with and in the condition.",
        "The rule is too narrow: condition: $s1 alone should be replaced with all of them, since all of them always reduces the number of files a rule matches, regardless of how many strings are defined.",
        "The false positives are unrelated to the rule and are caused entirely by the file share's antivirus scanner re-scanning the same files, so no change to the YARA rule is needed.",
        "YARA rules cannot use filesize or the and operator inside a condition, so this rule is already as tight as the syntax allows, and 340 matches is an unavoidable outcome of scanning a large file share.",
      ],
      answer: 0,
      explanation:
        "This is the false-positive-flood failure mode from Reading 1 and Reading 6, playing out exactly as described: one common signal with no corroborating requirement and no size bound matches everything that happens to share it for unrelated reasons. Option b is simply wrong about what all of them does when only one string is defined — it changes nothing, since there is nothing else to require. Option c invents an unrelated cause with no basis in what is described. Option d is factually wrong — Reading 5 covered both filesize and and directly, and they are exactly the tools that fix this rule.",
      xp: 25,
    },
    // ── Log Analysis: verify a live alert against its own rule logic ────────
    {
      type: "log_analysis" as const,
      id: "sigyara-la1",
      heading: "Reading a Live Alert Back Against the Rule That Wrote It",
      context:
        "Solvara Health's SIEM runs a custom Sigma rule mapped onto its CrowdStrike Falcon data source, tagged T1003.001. Its selection block requires TargetProcessName equal to lsass.exe together with GrantedAccess equal to 0x1FFFFF. Its filter block excludes any event where the file path starts inside the CrowdStrike installation directory or the Windows System32 directory — legitimate AV self-scan and OS-owned processes. Its condition is selection and not filter, and its level is set to critical. This rule just fired on WKS-CLM-1187, a claims-processing workstation. Work through the raw fields against the rule's own logic the way a real investigation would.",
      event: lsassSigmaAlertEvent,
      questions: [
        {
          question: "crowdstrike.TargetProcessName reads lsass.exe and crowdstrike.GrantedAccess reads 0x1FFFFF. Does the rule's selection block actually match this event?",
          options: [
            "No — GrantedAccess would need to read a lower-privilege value like 0x1400 for the selection to match; 0x1FFFFF is out of range for this field",
            "Yes — both required values are present exactly as the selection specifies, so the selection block matches regardless of anything else in the event",
            "No — the selection also silently requires the process name of the accessing process to match a known hash, which is not shown here",
            "It cannot be determined without first checking the filter block, since selection and filter are always evaluated together as a single condition",
          ],
          answer: 1,
          explanation:
            "The selection is evaluated independently of the filter; both fields hold exactly the required literal values. Option a invents a false GrantedAccess range — 0x1FFFFF is PROCESS_ALL_ACCESS, the value the rule is actually looking for. Option c invents a requirement not stated in the rule. Option d wrongly claims selection cannot be judged alone — Sigma explicitly evaluates named blocks independently, then the condition combines them.",
          xp: 30,
        },
        {
          question: "crowdstrike.FilePath reads C:\\Users\\n.brandt\\AppData\\Roaming\\SysHealthMon\\SysHealthMon.exe. Given the rule's filter block, does the filter suppress this alert?",
          options: [
            "Yes — AppData is a subfolder of the user's profile, which Windows treats as trusted by default, so the filter's System32 exclusion covers it",
            "No — the path starts inside neither the CrowdStrike installation directory nor Windows\\System32, so the filter block does not match, and the alert correctly still fires",
            "Yes — SysHealthMon.exe is a plausible-sounding monitoring utility name, and the filter is written to exclude any process whose name suggests legitimate system monitoring software",
            "It cannot be determined, because Sigma filter blocks can only reference the Image field, never FilePath",
          ],
          answer: 1,
          explanation:
            "The filter only excludes the two literal path prefixes actually defined, not user-profile paths generally, so option a is wrong. Option c is wrong for the same reason this room has repeated throughout: a filter matches fields and values, not how plausible a filename sounds — a file's name proves nothing about what it actually is. Sigma filters can reference any field the logsource provides, including FilePath, so option d is also wrong.",
          xp: 35,
        },
        {
          question: "crowdstrike.CallStackModuleNames again lists dbghelp.dll among the loaded modules. A colleague proposes tightening the rule's condition to also require dbghelp.dll appear in CallStackModuleNames before firing at all. Based on this room's tuning principles, what is the risk in that specific change?",
          options: [
            "No risk — dbghelp.dll appears in literally every LSASS-access attempt ever recorded, so requiring it would have zero effect on the rule either way",
            "It would make the rule too narrow: some credential-dumping techniques access LSASS without loading dbghelp.dll at all, so hard-requiring it in the condition would let those variants evade detection entirely, even though the GrantedAccess-based selection alone already catches them",
            "It would make the rule too broad: adding any additional required string to a condition always increases, never decreases, the number of events a rule matches",
            "It would have no effect on detection quality, only on rule readability, since YARA and Sigma always evaluate every possible string regardless of what the condition requires",
          ],
          answer: 1,
          explanation:
            "Option a overclaims universality — dbghelp.dll does not always appear. Option c inverts how adding a required AND condition works — it narrows the set of matching events, it does not broaden it. Option d conflates YARA's evaluation model with Sigma's and is simply false regardless. The correct narrowing risk exactly mirrors the specific-vs-brittle lesson from the YARA readings, applied here to Sigma: the access-mask-based selection is already the strong, general signal, and call-stack modules are corroborating detail, not something the core condition should hard-require.",
          xp: 35,
        },
        {
          question: "crowdstrike.PatternDispositionDescription reads 'Detected, no action taken', the rule's level is critical, and this workstation belongs to a claims-processing employee at a healthcare company with access to patient records. Selection matched, filter did not suppress it. What should the analyst do next?",
          options: [
            "Close the alert as informational, since 'Detected, no action taken' means Falcon's own analysis already concluded the behavior was not a real threat",
            "Escalate as a likely true positive: the tool only observed rather than blocked the access, the confirmed selection/filter match rules out the two documented false-positive sources, and the sensitivity of this specific asset raises the cost of being wrong in the direction of under-reacting — move toward containment and treat locally-stored credentials as potentially exposed",
            "Downgrade the rule's own level field from critical to low directly in the SIEM before finishing the investigation, since one hit on a non-executive workstation is evidence the severity was set too high",
            "Wait for the same rule to fire a second time on this host before taking any action, since a single Sigma match is never considered sufficient grounds to begin containment",
          ],
          answer: 1,
          explanation:
            "'Detected, no action taken' means the access was only observed, not stopped — that raises urgency rather than lowering it, the opposite of what option a assumes. Option c wrongly treats one triage outcome as grounds to retune a rule's global severity — that is a tuning decision made from many observations over time, not something to change mid-investigation. Option d invents a duplicate-hit policy this room never taught. The correct move is exactly what a confirmed selection match, an unsuppressed filter, and a sensitive asset all point toward together.",
          xp: 40,
        },
      ],
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "sigyara-f1",
      prompt: "In Reading 3's completed Sigma rule for shadow copy deletion, what is the exact value of the rule's id field (the UUID)?",
      answer: "4b6a1f2e-9c3d-4a7b-8e21-6f0a9d3c5b17",
      hint: "It is the id: field right under title: in the YAML front matter of the completed rule shown in Reading 3.",
      xp: 20,
    },
  ],
};

export const roomsBatch35 = [sigmaYaraRuleAuthoringRoom];
