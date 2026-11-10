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
 *  1. sigma-yara-rule-authoring: six readings, then four practical missions
 *     (src/lib/missions/rooms/ruleAndSign.ts) in which the learner writes a
 *     Sigma rule, its KQL twin and two YARA rules, and the server runs them on
 *     test corpora with held-back variants (Pelham Instruments, calhelper.exe).
 */

import { RULE_AND_SIGN_FIX, RULE_AND_SIGN_KQL, RULE_AND_SIGN_SIGMA, RULE_AND_SIGN_YARA } from "@/lib/missions/rooms/ruleAndSign";

// ===========================================================================
// ROOM — Writing Detection Rules: Sigma & YARA Authoring
// ===========================================================================



const sigmaYaraRuleAuthoringRoom = {
  id: "sigma-yara-rule-authoring",
  title: "Writing Detection Rules: Sigma & YARA Authoring",
  description:
    "Detection Engineering Fundamentals taught you to read a complete Sigma rule. Malware Analysis Fundamentals taught you to read a YARA rule. Neither one handed you a blank page. This room does: the field modifiers and multi-block quantifiers Sigma rules actually need, how a rule you write compiles into a real KQL query, YARA's sharper string and condition operators, and the specific-vs-brittle discipline of tuning a rule so it survives the next variant of an attack without flooding the queue on everything else.",
  difficulty: "advanced" as const,
  category: "SIEM",
  estimatedMinutes: 70,
  xp: 440,
  icon: "🛠️",
  prerequisites: ["detection-engineering", "malware-analysis-fundamentals"],
  tasks: [
    // ── Reading 1: framing ───────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r1",
      heading: "From Reading Rules to Writing Them",
      content:
        "Detection Engineering Fundamentals already walked you through a complete Sigma rule, field by field (title, id, status, logsource, detection, condition, falsepositives, level, tags) and the organizational lifecycle a rule travels through from a threat idea to a retired detection nobody needs anymore. Malware Analysis Fundamentals already introduced YARA's three-part shape and its three string types: text, hex bytes, and regular expressions. If either of those feels distant, you can still recognize the pieces; that is enough to start here, because reading a rule fluently and writing one from a blank page turn out to be two different skills entirely.\n\n" +
        "Both of those earlier rooms taught you to read a rule someone else already wrote. Neither one handed you a blank page, a specific attacker technique, and asked you to produce the actual detection logic yourself: the field-level modifiers that decide whether a rule survives the next slightly-different variant of an attack or quietly stops working the day it changes, the multi-block conditions a technique with several tool variants genuinely needs, and the discipline of testing a draft against both malicious and benign material before anyone trusts it in production. That authoring skill, not rule-reading, is what actually separates an analyst who tunes exclusions into a rule someone else wrote from one who builds the detections the rest of the team relies on.\n\n" +
        "Almost every authoring mistake, in either format, falls into one of two directions. Write the logic too broadly (one common function call, one generic path fragment, one loosely related keyword) and the rule floods the queue with legitimate activity that happens to share that single trait, until analysts stop reading alerts from it at all. Write it too narrowly, hardcode one exact command-line string, one literal byte sequence lifted from a single sample, and the very next variant, with different casing, different whitespace, or a recompiled binary, sails through completely untouched. Recognizing which direction a rule has drifted turns out to matter just as much as writing the first draft, and this room spends real time on both directions in both formats.\n\n" +
        "The path through this room follows the order a rule actually gets built in practice: the specific modifiers and quantifiers Detection Engineering Fundamentals did not cover, one complete Sigma rule built up from a real technique step by step, watching that rule turn into an actual running KQL query, and testing your own judgment on a side-by-side comparison of a brittle rule and a properly tuned one. Then the exact same discipline, applied to YARA: the operators Malware Analysis Fundamentals left out, and a webshell rule built up the same deliberate way, narrow draft to broad draft to a tuned final version. By the end, you will have written pieces of both, not just read them.",
      checkpoint: {
        question: "Per Reading 1, what are the two failure modes that most detection-rule authoring mistakes fall into?",
        options: [
          "Testing a draft only against malicious samples, and testing it only against benign data",
          "Logic too broad, flooding the queue, and logic too narrow, letting the next variant slip through",
          "Reaching for |re when a simpler modifier would do, and leaving the Image field unanchored",
          "Setting the level before tuning is done, and leaving out the ATT&CK tags coverage reports need",
        ],
        answer: 1,
        explanation:
          "Reading 1 says almost every authoring mistake goes one of two directions: too broad (one common trait, so legitimate activity floods the queue) or too narrow (one literal string or byte sequence, so the next variant sails through). “Testing a draft only against malicious samples ...” describes a testing gap the room covers later, not the two directions. “Reaching for |re ... unanchored” names two specific Reading 2 mistakes, each just a cause of drifting too broad. “Setting the level before tuning ...” is a process slip from the tuning loop, not one of the two failure modes.",
      },
    },
    // ── Reading 2: Sigma modifiers & quantifiers ────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r2",
      heading: "Sigma Modifiers and Multi-Block Quantifiers",
      content:
        "Detection Engineering Fundamentals showed CommandLine|contains with a list of values and explained that Sigma evaluates a list under one field as OR, matching if the field contains any one of the listed items. That much is already familiar. What it did not cover is the modifier that flips that default, the modifiers that anchor a match instead of searching anywhere in a string, the regex escape hatch, and the way a condition can combine more than one named block at once, all four of which come up constantly the moment a rule needs to describe more than one simple pattern.\n\n" +
        "Start with the AND-versus-OR distinction, because it is the single most common way a new rule ends up looser than its author intended. CommandLine|contains|all: ['-nop', '-enc'] only matches when both substrings appear somewhere in the same command line, genuinely different from a plain |contains list, which matches on any one item alone. Writing |contains with a list when the actual intent was 'both of these together' silently turns a tight rule into a much looser one, because it will now also fire on command lines that only happen to contain one of the two.\n\n" +
        "Those two strings are real PowerShell flags. -nop is short for -NoProfile, which skips loading the user's PowerShell profile, and -enc is short for -EncodedCommand, which runs a base64-encoded command and so hides the script from a casual reader. Encoded PowerShell has legitimate uses in management tooling, but when the parent process is an Office application opening a macro document there is almost no legitimate explanation, so treat it as a true positive and act on it.\n\n" +
        "Image|startswith and Image|endswith anchor a match to one specific end of a field's value, instead of searching for the substring anywhere inside it. Image|endswith: '\\regsvr32.exe' matches any path ending in that string regardless of install directory: deliberately loose about where the binary lives, deliberately strict about what the binary actually is. Anchoring matters because an unanchored |contains: 'regsvr32' would also match a completely unrelated file simply named something like regsvr32_wrapper_notes.txt, or a command line that merely mentions the word inside a passed argument or comment.\n\n" +
        "CommandLine|re: applies a full regular expression, the modifier reserved for anything the simpler ones cannot express precisely enough, a specific numeric pattern, an argument that has to appear in a particular position, several optional variants at once. It is also, exactly like YARA's regex strings covered later in this room, the modifier most likely to run slowly or match far more than intended if written carelessly; reach for the simpler modifiers first and treat |re as the tool for when they genuinely cannot do the job.\n\n" +
        "Finally, a condition is not limited to one named block. Real techniques often have more than one tool that can carry them out: regsvr32.exe and rundll32.exe are both LOLBins abused for similar scriptlet-execution purposes. Writing separate named blocks, selection_regsvr32 and selection_rundll32 as shown below, then combining them with 1 of selection_* (matching if any block whose name starts with selection matches) lets one rule cover every known tool variant of the same technique instead of either missing half of them or cramming incompatible logic into a single unreadable block. Reading 3 builds an entire rule around exactly this same shape, for a different technique: vssadmin.exe versus wmic.exe, both deleting the same shadow copies. all of them, by contrast, requires every defined block to match at once: the tightest possible combination, reserved for the rarer case where several distinct signals all have to be present together.",
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
        "  - attack.stealth\n" +
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
          "The first requires both substrings (AND); the second matches if either one appears (OR)",
          "The first matches if either substring appears (OR); the second requires both in the same line (AND)",
          "The first matches the substrings in any order; the second requires them in the order listed",
          "The first matches either substring; the second needs each item to equal the whole field exactly",
        ],
        answer: 1,
        explanation:
          "A list under one field is OR by default; adding |all makes it AND, so every item must appear somewhere in the same value. “The first requires both substrings (AND)” inverts the default, which is exactly the confusion Reading 2 warns turns a tight rule loose. “Requires them in the order listed” is wrong: |all checks presence, not order. Order or position needs |re. “Equal the whole field exactly” confuses |all with dropping |contains; it is the contains modifier that keeps this a substring match.",
      },
    },
    // ── Reading 3: Sigma step-by-step case study ────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r3",
      heading: "Writing a Sigma Rule Step by Step: Shadow Copy Deletion",
      content:
        "Now build a complete rule from scratch, using the multi-block pattern Reading 2 introduced, for a genuinely different technique: ransomware operators, in the minutes before they start encrypting files, routinely delete the Volume Shadow Copies Windows keeps as local recovery points, because a victim who can just restore yesterday's files from a shadow copy has no reason to pay a ransom. The two most common tools for that specific action are vssadmin.exe, Windows' own built-in shadow-copy management utility, and wmic.exe, invoked with its shadowcopy alias. This single hypothesis (a specific, well-documented pre-encryption step, MITRE ATT&CK T1490, Inhibit System Recovery) is what the whole rule gets built around.\n\n" +
        "Step one is always a hypothesis stated in plain language, not syntax, exactly as above. Step two is the logsource: this is process-launch activity, which on a Windows endpoint means logsource: category: process_creation, product: windows.\n\n" +
        "Step three is drafting the selection. A first attempt might be a single loose match: CommandLine|contains: 'delete shadows', but this is already wrong in two different directions at once. It is too narrow in one direction, because it misses wmic's entirely different phrasing. And it is too broad in another, separately, because a bare string search with no anchor on the binary itself could in principle match a log line, a ticket comment, or a script filename containing that same phrase for an unrelated reason. The fix is two named selection blocks, one per tool. selection_vssadmin requires Image|endswith: '\\vssadmin.exe' together with CommandLine|contains|all: ['delete', 'shadows'], both words must appear, in any order, which survives minor phrasing differences while still anchoring to the real binary. selection_wmic requires Image|endswith: '\\wmic.exe' together with CommandLine|contains: 'shadowcopy delete' as one combined phrase, since that is how the wmic alias syntax is actually invoked.\n\n" +
        "Step four is the condition: selection_vssadmin or selection_wmic, either tool tripping the pattern is enough on its own to fire the rule; there is no reason to require both in the same event, since a single execution only ever uses one of them.\n\n" +
        "Step five is falsepositives, and honesty here matters more than completeness: backup software performing scheduled shadow-copy cleanup as part of its own retention policy, and IT administrators manually freeing disk space on a documented change ticket, are the two realistic sources of legitimate matches, writing this list down is what lets a future analyst triage a hit in thirty seconds instead of re-deriving the same reasoning from scratch. (Sigma calls this field falsepositives, but in verdict terms both entries are benign true positives: the rule correctly sees a real shadow-copy deletion, and the retention policy or the change ticket is what makes it authorized. Closing one of these cites that justification; it does not mean the rule misfired.)\n\n" +
        "Step six is level and tags: level: high, because a confirmed shadow-copy deletion this close to encryption has essentially no benign majority-case even though the legitimate matches above (benign true positives, in verdict terms) are real and worth checking first; tags: attack.impact and attack.t1490 map the rule directly to its ATT&CK technique, which is what lets a coverage report later confirm this technique is actually detected rather than just documented as a gap.\n\n" +
        "Once a rule like this is live, the analyst's side matters too. When a high or critical rule fires and its filter did not suppress the event, treat it as a likely real attack until shown otherwise. An EDR (endpoint detection and response) tool records what it did about an event in a disposition field, such as Falcon's PatternDispositionDescription. A disposition that records detection without any action, such as 'Detection, standard detection.', means the activity was seen, not stopped, so escalate and contain. Memory can be read and sent out without a file ever reaching disk, so do not wait for a dump file, and a user's word cannot settle a critical alert.",
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
          "Because |contains|all runs faster than one phrase match on high-volume process logs",
          "Because both words must appear in any order, so small phrasing differences still match",
          "Because Sigma's contains can't match a value with a space in it, so phrases must be split",
          "Because splitting the phrase widens the rule to command lines containing either word",
        ],
        answer: 1,
        explanation:
          "Reading 3: two words that must both appear, in any order, survive phrasing variations that one literal phrase would miss, while the Image anchor keeps the rule tied to vssadmin.exe. “Runs faster” is a performance claim the reading never makes. “Can't match a value with a space” is contradicted by the same rule: selection_wmic matches 'shadowcopy delete' as one phrase. “Widens the rule to command lines containing either word” describes a plain |contains list (OR); |all requires both.",
      },
    },
    // ── Mission 1: Sigma for how it arrived (src/lib/missions/rooms/ruleAndSign.ts) ──
    RULE_AND_SIGN_SIGMA,
    // ── Reading 4: compiling Sigma to KQL/SPL ───────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r4",
      heading: "From Sigma to Query: How a Rule Actually Runs",
      content:
        "Once a Sigma rule exists, it still has to become a query some SIEM actually runs, and the tool that does that translation is pySigma, the current open-source library (the sigma-cli command-line tool is built on top of pySigma, and Detection Engineering Fundamentals already used it to compile a different rule to Splunk SPL). Two things determine what comes out the other end: the backend, which is the target query language, and the pipeline, which maps Sigma's generic field names (Image, CommandLine, TargetProcessName) onto whatever column names the chosen data source actually uses once it lands in that SIEM.\n\n" +
        "Walk the shadow-copy-deletion rule from Reading 3 through this process. Its logsource, category: process_creation, product: windows, tells the pipeline this rule targets process-launch telemetry, which, once mapped onto a specific Microsoft Sentinel table, becomes DeviceProcessEvents. Image becomes FolderPath, and CommandLine becomes ProcessCommandLine. The condition's boolean logic translates directly: and becomes a chain of KQL where clauses joined with and, or becomes literal or, and the contains|all modifier from selection_vssadmin becomes two clauses joined with and, rendered here with KQL's has operator, which matches complete tokenized words rather than arbitrary substrings. It works cleanly because 'delete' and 'shadows' each appear as whole words in the command line. (Sigma's |contains is itself a substring match; its most literal KQL equivalent is the contains operator, KQL's true substring match, while has is the faster, index-backed whole-word alternative used here.)\n\n" +
        "Compiled for a Splunk backend against the same rule, the field-name mapping looks different again, because Splunk's own convention, when data arrives straight from a Windows or Sysmon technology add-on, frequently keeps the original field names Sigma already uses (Image stays Image, CommandLine stays CommandLine) with the translation work happening mostly in the search syntax itself.\n\n" +
        "The practical payoff is what makes this worth learning at all: the actual detection reasoning, which technique, which exact field values distinguish it, which known-good sources need excluding, gets captured exactly once, in the Sigma rule. Migrating to a new SIEM, or simply running the same detection logic in two SIEMs during a transition period, becomes a matter of running a different backend, not re-deriving the entire rule from scratch in an unfamiliar query language.",
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
        "index=main sourcetype=WinEventLog:Sysmon EventCode=1 Image=\"*\\\\vssadmin.exe\" CommandLine=\"*delete*\" CommandLine=\"*shadows*\"",
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
          "The selection and filter blocks are rewritten per SIEM, since each backend needs its own detection logic",
          "Field and table names and query syntax follow the backend; the rule's detection reasoning stays as written",
          "Only the logsource block changes, since Splunk and Sentinel need different product and category values",
          "Only the condition changes, since SPL and KQL express and/or differently and the field names stay put",
        ],
        answer: 1,
        explanation:
          "The backend sets the query syntax and the pipeline maps generic fields and logsources onto the target's schema (Image becomes FolderPath and the table becomes DeviceProcessEvents in Sentinel; Splunk often keeps Image). The reasoning stays in the Sigma rule. “The selection and filter blocks are rewritten per SIEM” is the vendor lock-in Sigma exists to avoid. “Only the logsource block changes” is wrong: logsource stays the same in the rule, and the pipeline maps it. “Only the condition changes” misses the field-name and table mapping shown in the reading's own example.",
      },
    },
    // ── Mission 2: same rule, two SIEMs (src/lib/missions/rooms/ruleAndSign.ts) ──
    RULE_AND_SIGN_KQL,
    // ── Reading 5: YARA sharper operators ────────────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r5",
      heading: "Beyond the Basics: Hex Wildcards, Counting, and Offsets",
      content:
        "Malware Analysis Fundamentals already covered YARA's three-part shape (meta, strings, condition) and its three string types: plain text, hex bytes, and regular expressions, plus the basic condition operators at 0, 1 of (...), and and. This reading picks up exactly where that one left off: the modifiers and operators that turn a rule from roughly right into something a hunt team would actually trust in production.\n\n" +
        "Hex strings support wildcarding, not just fixed byte sequences. { 4D 5A } matches only those exact two bytes back to back, fine for a header that never varies, but real binary structures often have a gap between two fixed landmarks that shifts slightly between compiler versions or build configurations of the same tool. { 40 00 00 00 [4-8] 50 45 00 00 } matches the first four bytes, then any 4 to 8 unknown bytes, then the second four bytes: the bracketed range is YARA's wildcard-gap syntax, and it is what lets a hex pattern survive small structural differences between build variants of the same underlying tool without becoming a full regular expression.\n\n" +
        "String modifiers add one more useful constraint beyond the ascii/wide/nocase trio already covered: fullword requires the match not be embedded inside a larger word, $s = \"admin\" fullword would match a standalone argument like -admin but not the substring buried inside administrator, which matters enormously for short, common strings that would otherwise match constantly inside unrelated longer words. Combining modifiers is normal: ascii wide nocase on one string means match both the single-byte and UTF-16 encodings, case-insensitively, in one declaration instead of three.\n\n" +
        "The condition section has more built-in power than and, or, and N of (...). filesize, compared against a size like 150KB or 2MB, bounds a rule to a realistic range for the artifact being hunted, so a file outside that range cannot match no matter what strings it holds. YARA searches for all of a rule's strings first and evaluates the condition afterwards, so filesize removes unwanted matches rather than scan work: putting it first in the condition only saves evaluating the rest of the condition. #string_name counts how many times that string occurs in the file: a single incidental appearance of a common function call reads very differently from the same call repeated dozens of times inside an obfuscation loop, and #a > 5 captures exactly that distinction where 1 of ($a) alone cannot. @string_name[1] gives the byte offset of a string's first occurrence, which lets a condition anchor a match to a specific location the way $mz at 0 requires the MZ header to sit at the very first byte of the file: exactly where a genuine executable's header belongs, and nowhere a webshell's decoy content would put it.\n\n" +
        "None of these operators replaces good string selection; they sharpen it. A hex wildcard gap still needs two genuinely meaningful fixed landmarks on either side of it. A count threshold still needs a string worth counting in the first place. The skill this room is actually building (picking signals that are individually common but collectively rare) is exactly the same skill Malware Analysis Fundamentals introduced; these operators are simply sharper tools for expressing it precisely.",
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
          "The bytes 40 00 00 00, then any 4 to 8 unknown bytes, then the bytes 50 45 00 00",
          "The sequence 40 00 00 00 50 45 00 00, repeated back to back between 4 and 8 times",
          "Both byte sequences anywhere, in a file between 4 and 8 kilobytes in size",
          "The bytes 40 00 00 00, with 50 45 00 00 starting at byte offset 4 to 8 of the file",
        ],
        answer: 0,
        explanation:
          "A bracketed range inside a hex string is YARA's wildcard gap: any 4 to 8 unknown bytes between two fixed landmarks, so the pattern survives small layout differences between builds. “Repeated back to back” confuses the gap with a repetition count (counting occurrences is the #string operator). “A file between 4 and 8 kilobytes” confuses it with the separate filesize keyword. “Starting at byte offset 4 to 8 of the file” confuses it with offset anchoring (at / @string), which pins a match to a file position.",
      },
    },
    // ── Reading 6: YARA step-by-step case study ─────────────────────────────
    {
      type: "reading" as const,
      id: "sigyara-r6",
      heading: "Writing a YARA Rule Step by Step: A PHP Webshell Family",
      content:
        "The same step-by-step discipline Reading 3 used for Sigma applies just as directly to YARA, now aimed at a file-hunting problem instead of a log-search one: a compromised web application server needs a rule that catches single-file PHP webshells dropped after an initial-access exploit, without also flagging the thousands of legitimate PHP files already living on that same server.\n\n" +
        "Step one, the hypothesis: a webshell's entire purpose is letting an attacker send commands to a compromised server and have them executed, so nearly every variant shares the same underlying shape: take input from an HTTP request, decode it if it was obfuscated to dodge simple text search, and hand it to eval() or an equivalent execution function. The specific obfuscation wrapper changes constantly (base64, gzinflate-then-base64, rot13, XOR with a hardcoded key); the underlying shape barely does.\n\n" +
        "Step two, drafting the strings, is where the specific-versus-brittle tradeoff has to be made explicit. The most brittle possible rule hardcodes one exact byte-for-byte sample: matching the literal full obfuscated payload string from the one webshell already found in the incident. It will never fire on the next sample, because the next attacker (or the same one, on the next compromised server) will vary a single byte of the encoded blob and invalidate the exact match completely. A rule that specific is really just a hash lookup wearing a YARA rule's clothing. The opposite mistake (a single common string like eval(base64_decode( with no other condition) is exactly the trap this room's own broad-vs-narrow question walks through: any framework, plugin, or license-checking library that happens to call the same two functions together for entirely unrelated reasons will match too, and a rule that fires on hundreds of legitimate files gets disabled by an exhausted analyst within a week.\n\n" +
        "The workable middle ground layers several individually-common, jointly-rare signals: the PHP open tag itself ($php_tag), one of the known obfuscation wrappers ($eval_b64 or $eval_gz, 1 of them, since a given sample will only use one), and one of the superglobal input sources an attacker actually needs to receive their command through ($post_in or $req_in, again 1 of them). None of these three signals is remotely rare by itself. All three appearing together, inside a file also small enough to be a single-purpose dropped script rather than an entire application (filesize < 150KB), essentially never happens by coincidence in ordinary application code.\n\n" +
        "Step three is testing, and for YARA specifically this means two different corpora: run the draft rule against a known-malicious sample set to confirm it still matches the real thing, and, just as importantly, run it against a large known-benign sample set (the organization's own legitimate PHP codebase is ideal) to measure the real-world false-positive rate before the rule goes anywhere near a live alerting pipeline. Many YARA-capable platforms and threat-intel services support retrohunting: running a brand-new rule retroactively against files collected over the past days or weeks, which surfaces both the false-positive rate and any already-present, previously-undetected match, before the rule is trusted for the future.\n\nPut the two walkthroughs side by side and one tuning loop appears, whichever language you write in. State the attacker technique in plain language. Write a first draft from the most obvious single indicator. Check whether that indicator is too broad or too narrow. Add a second, independent indicator, so several individually common signals must appear together. Anchor the rule to the smallest realistic scope, such as a file-size ceiling, one binary or one log source. Test it against a known-malicious sample and a known-benign corpus. Document the legitimate matches the test really found, in the falsepositives field or the meta notes. Last, assign the severity or level and hand the rule off.",
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
          "It is too broad: other legitimate PHP files that happen to share those payload bytes will match too",
          "It is too brittle: change one byte of the encoded payload and the next variant no longer matches",
          "It is fine for hunting but too slow for production, since long literal strings make scans crawl",
          "It needs the nocase modifier, since attackers vary letter case in the payload to slip past it",
        ],
        answer: 1,
        explanation:
          "Reading 6: a rule that specific is a hash lookup wearing a YARA rule's clothing, the next sample changes a byte of the encoded blob and the match fails. “It is too broad” inverts the problem: a long, exact obfuscated payload is essentially unique, so it matches almost nothing, including the next attack. “Too slow for production” is not the reading's objection; the issue is what the rule misses, not speed. “It needs the nocase modifier” fixes only case changes, while the next variant changes the encoded bytes themselves, and base64 content is case-sensitive anyway.",
      },
    },
    // ── Mission 3: let the corpus vote (src/lib/missions/rooms/ruleAndSign.ts) ──
    RULE_AND_SIGN_YARA,
    // ── Mission 4 (boss): the builds with nothing left to read (src/lib/missions/rooms/ruleAndSign.ts) ──
    RULE_AND_SIGN_FIX,
  ],
};

export const roomsBatch35 = [sigmaYaraRuleAuthoringRoom];
