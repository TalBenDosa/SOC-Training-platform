import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content — group "de". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_de: Record<string, AuthoredPathLesson> = {
  "detection-engineer--sigma-selection-patterns": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What Sigma Is and Why It Exists",
        "body": "A Security Information and Event Management (SIEM) platform is only as useful as the detections written for it, and for two decades those detections were locked inside whatever query language the vendor shipped: Splunk's SPL, Microsoft Sentinel's KQL, Elastic's EQL. An analyst who spent years writing brilliant Splunk searches had to start from zero when their organization migrated to Sentinel. Sigma was created to solve exactly this problem.\n\nSigma is an open, YAML-based, vendor-agnostic format for describing log-based detections. It was originally developed by Florian Roth and Thomas Patzke and is now maintained as a community project (SigmaHQ) with a public repository holding thousands of rules mapped to MITRE ATT&CK techniques. Think of Sigma as a universal recipe format: instead of writing a different recipe for every brand of oven (every SIEM), you write the recipe once in a shared notation, and a converter adapts it to whichever oven you actually own.\n\nThat converter is a piece of software called a **backend**. The current generation of Sigma tooling is built on a Python library called **pySigma**, which replaced the earlier \"sigmac\" converter. A pySigma backend takes a Sigma YAML rule and a **pipeline** (a mapping profile for a specific product) and emits a ready-to-run query in SPL, KQL, EQL, or another target language.\n\n### Why a detection engineer needs this\n- **Portability** — one rule, many SIEMs, without rewriting logic by hand.\n- **Community leverage** — thousands of peer-reviewed public rules covering known techniques, so you are not starting detection coverage from a blank page.\n- **Machine-readability** — because Sigma rules are structured YAML with standardized tags, they can be converted into MITRE ATT&CK Navigator layers, fed into detection-as-code pipelines, or transformed into other formats like STIX (covered later in this module).\n\nThis lesson focuses on how a Sigma rule is built and how its selection logic works. Later lessons in this module cover the modifier syntax that fine-tunes matching, and how to test a rule's real-world coverage before it ships to production.",
        "codeExample": "flowchart LR\n  A[\"Analyst writes\\none Sigma rule (YAML)\"] --> B[\"pySigma + pipeline\\n(e.g. splunk, sysmon,\\nmicrosoft365defender)\"]\n  B --> C1[\"Splunk SPL query\"]\n  B --> C2[\"Sentinel KQL query\"]\n  B --> C3[\"Elastic EQL query\"]",
        "keyPoints": [
          "Sigma is an open, YAML-based, vendor-agnostic detection rule format maintained by the SigmaHQ community.",
          "pySigma is the current conversion engine; it uses per-product pipelines to translate generic Sigma fields into a specific backend's query language.",
          "One Sigma rule can be converted into SPL, KQL, EQL, and other query languages without being rewritten by hand.",
          "SigmaHQ's public repository is a large, MITRE ATT&CK-tagged library of community-reviewed detections."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Anatomy of a Sigma Rule",
        "body": "Every Sigma rule is a YAML document with a fixed set of top-level fields. Reading a rule from top to bottom tells you what it detects, where it looks, how confident the author was, and what to do if it fires.\n\n### Metadata fields\n- **title** — a short, human-readable description of what the rule catches.\n- **id** — a unique identifier (a UUID) so the rule can be referenced unambiguously, including by exception documents covered later in this module.\n- **status** — the maturity of the rule: commonly stable, test, experimental, or deprecated. A detection engineer should never treat an experimental rule with the same trust as a stable one.\n- **description** — a longer explanation of the behavior being detected and why it matters.\n- **references** — links to write-ups, threat reports, or vendor documentation that justify the rule.\n- **author** and **date** — provenance and change history.\n- **tags** — machine-readable labels, most importantly MITRE ATT&CK technique and tactic IDs (for example attack.t1003.001 and attack.credential-access).\n\n### The logsource block\nlogsource tells the backend where to look, using up to three fields: **category** (a normalized event type, such as process_creation or network_connection), **product** (the platform, such as windows, linux, or aws), and **service** (a specific log channel, such as sysmon or security). The pipeline uses these three fields together to decide which raw log source and field names to target.\n\n### The detection block\ndetection contains one or more named selections (and optional filters) plus a condition string that combines them with logical operators. This is the actual matching logic and is the subject of the rest of this lesson.\n\n### Closing metadata\n- **falsepositives** — a plain-language list of legitimate activity known to trigger the rule, so a triaging analyst has a head start.\n- **level** — the rule author's baseline severity (informational, low, medium, high, or critical) — the starting point for the severity-tiering work covered later in this Learning Path.",
        "codeExample": "title: Suspicious LSASS Access via ProcessAccess\nid: 4a7c1b2e-9f3d-4e6a-8b1c-2d5e7f9a1b3c\nstatus: stable\ndescription: Detects processes accessing lsass.exe with access rights consistent with credential dumping\nreferences:\n    - https://attack.mitre.org/techniques/T1003/001/\nauthor: NexaCorp Detection Engineering\ndate: 2026-01-15\ntags:\n    - attack.credential-access\n    - attack.t1003.001\nlogsource:\n    category: process_access\n    product: windows\ndetection:\n    selection:\n        TargetImage|endswith: '\\\\lsass.exe'\n        GrantedAccess:\n            - '0x1010'\n            - '0x1410'\n            - '0x1FFFFF'\n    condition: selection\nfalsepositives:\n    - Endpoint protection agents performing legitimate memory inspection\nlevel: high",
        "keyPoints": [
          "A Sigma rule has three regions: metadata (title/id/status/tags), logsource (where to look), and detection (what pattern to match).",
          "logsource uses category, product, and service together to tell the backend which raw telemetry to target.",
          "tags carry MITRE ATT&CK technique and tactic IDs, making rules machine-mappable to a coverage heatmap.",
          "level is the rule author's baseline severity, later adjusted by asset and confidence context in production."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Selections: Key-Value Pairs and Lists",
        "body": "A selection is a YAML mapping of field names to expected values. Within a single selection, the logic connecting different fields is always AND: every field listed must match for the selection to match. When a single field is given a list of values, the logic between the items in that list is OR: any one of the listed values satisfies that field.\n\nConsider a selection with two fields, Image and ParentImage, where Image is given three possible values. That selection matches only if ParentImage equals its target AND Image equals one of the three listed values.\n\n### Implicit wildcards\nWithout any modifier, a plain string value is matched as an exact, case-insensitive string by most backends unless it contains the wildcard characters asterisk (any number of characters) or question mark (exactly one character). Writing a value such as star-backslash-rundll32.exe matches any path ending in that binary name — this is the same effect the endswith modifier produces, and Sigma authors can use either style. The modifier style (covered in the next lesson) is generally preferred because it is explicit and less error-prone when values legitimately contain literal asterisks or question marks.\n\n### Multiple selections\nA rule commonly defines more than one selection, each named descriptively (selection_img, selection_cli, selection_parent, and so on). Naming selections clearly is not cosmetic — it is what makes the condition field (next page) readable, and it is what an exception author references when writing a targeted filter later. A rule with a single anonymous block named simply \"selection\" is fine for a simple rule, but as detection logic grows more complex, descriptive names keep the rule maintainable for the next engineer who has to read it at 2 a.m. during an incident.\n\n### Keywords list detection\nSigma also supports a keywords search style — a plain list of strings matched against the full raw event text rather than a specific field — useful for log sources that do not have reliably structured fields, though it is less precise than field-based selections and should be a last resort.",
        "codeExample": "detection:\n    selection_parent:\n        ParentImage|endswith:\n            - '\\\\winword.exe'\n            - '\\\\excel.exe'\n            - '\\\\outlook.exe'\n    selection_child:\n        Image|endswith:\n            - '\\\\powershell.exe'\n            - '\\\\cmd.exe'\n            - '\\\\wscript.exe'\n    condition: selection_parent and selection_child",
        "keyPoints": [
          "Within one selection, different fields are ANDed together; multiple values on one field are ORed together.",
          "Wildcards asterisk and question mark work without a modifier, but explicit modifiers (next lesson) are clearer and safer.",
          "Descriptive selection names (selection_parent, selection_cli) make complex conditions readable and easy to reference from exceptions.",
          "A keywords block matches raw event text and is a fallback for unstructured log sources, not a first choice."
        ]
      },
      {
        "pageNumber": 4,
        "title": "The Condition Field: Combining Selections with Logic",
        "body": "The condition field is where the named selections and filters are combined into the rule's final decision logic. It reads like a small boolean expression, and Sigma supports a handful of operators and shorthand patterns that cover almost every real-world case.\n\n### Basic operators\n- **and** / **or** — combine two named blocks, for example selection_a and selection_b, or selection_a or selection_b.\n- **not** — negates a block, most commonly used to subtract a filter: selection and not filter.\n- Parentheses can group expressions when mixing and/or to avoid ambiguity: (selection_a or selection_b) and not filter.\n\n### Shorthand patterns for many blocks\nRules often define several similarly-named blocks using a wildcard suffix, such as selection_cmd_1, selection_cmd_2, selection_cmd_3. Two shorthand keywords operate over all blocks whose name matches a given prefix pattern:\n- **1 of selection star** — matches if at least one of the blocks named selection_ followed by anything matches (logical OR across the group).\n- **all of selection star** — matches only if every block named selection_ followed by anything matches (logical AND across the group).\n- **all of them** — every selection defined anywhere in the detection block must match.\n\nThese shorthands matter because as a rule accumulates more indicators for the same behavior (several known malicious command-line fragments, for example), spelling out a long chain of \"or\" between four or five selection names by hand becomes error-prone; the \"1 of\" shorthand expresses the same intent more safely as the list grows.\n\n### A worked condition\nImagine a rule detecting a scripting engine (wscript.exe or cscript.exe) launched by a document application, but excluding a known internal macro-signing tool. The selections would be selection_parent (the Office parent process), selection_child (the scripting engine), and filter_signed (the approved internal tool's exact path and hash). The condition \"selection_parent and selection_child and not filter_signed\" reads naturally: match the suspicious pattern, but not when it is the approved tool.\n\nGetting condition logic right is the single most common source of Sigma authoring mistakes — an accidentally-missing \"not\", or an \"or\" that should have been an \"and\", silently turns a precise rule into either a false-positive generator or a rule that never fires at all.",
        "codeExample": "detection:\n    selection_parent:\n        ParentImage|endswith:\n            - '\\\\winword.exe'\n            - '\\\\excel.exe'\n    selection_child:\n        Image|endswith:\n            - '\\\\wscript.exe'\n            - '\\\\cscript.exe'\n    filter_signed:\n        Image: 'C:\\\\Program Files\\\\NexaCorp\\\\MacroSign\\\\cscript.exe'\n        Hashes|contains: 'SHA256=9F2B1C4A5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708'\n    condition: selection_parent and selection_child and not filter_signed",
        "keyPoints": [
          "condition combines named blocks with and, or, not, and parentheses for grouping.",
          "'1 of selection*' means OR across a group of similarly-named blocks; 'all of selection*' means AND across that group.",
          "'selection and not filter' is the standard pattern for excluding a known-benign case without writing a second rule.",
          "A wrong operator in condition (or instead of and, a missing not) is one of the most common and most damaging Sigma authoring mistakes."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Filters: Excluding Noise Without New Rules",
        "body": "A filter block uses exactly the same YAML syntax as a selection — it is a set of field-value pairs — but its role in the condition is to be subtracted, not added. Writing \"selection and not filter\" means: match the pattern described by selection, except when the event also matches filter.\n\n### When to use an inline filter\nInline filters belong in the rule when the exception is conceptually part of the detection's own noise model — that is, part of what any deployment of this rule will predictably need to exclude, regardless of environment. A classic example: a PowerShell execution rule that would otherwise fire every time a legitimate software deployment tool (like a patch management agent) launches PowerShell with a recognizable, fixed argument pattern. That exception is baked into the rule because it is a known, structural source of noise for that detection.\n\n### Filters versus environment-specific exceptions\nNot every exception belongs inside the rule. A filter that references this specific organization's internal tool path, hostname, or service account does not belong hard-coded into a community rule (which other organizations will also run) — that kind of narrow, local exception belongs either in a standalone Sigma filter document or in SIEM-level suppression, both covered in the Allowlists & Exceptions lab later in this path. Mixing organization-specific noise into the core detection logic makes the rule harder to share, harder to review, and harder to keep in sync when it is updated upstream.\n\n### Writing precise filters\nA weak filter (matching only on Image, for example) can silently blind the entire rule if an attacker names a malicious binary the same as the legitimate tool being excluded. Strong filters combine multiple fields — path, parent process, and ideally a file hash — so that the exception is narrow enough to only ever match the specific legitimate behavior it was written for, not merely something that superficially resembles it.\n\n### Testing the subtraction\nAfter adding a filter, an author should always re-run the rule against both the original malicious sample (to confirm it still fires) and the newly-excluded benign sample (to confirm it now stays silent). The next lesson in this module covers this testing discipline in depth.",
        "codeExample": "detection:\n    selection:\n        Image|endswith: '\\\\powershell.exe'\n        CommandLine|contains: '-ExecutionPolicy Bypass'\n    filter_patch_agent:\n        ParentImage: 'C:\\\\Program Files\\\\NexaCorp\\\\PatchAgent\\\\agent.exe'\n        CommandLine|contains: '-File C:\\\\ProgramData\\\\NexaCorp\\\\PatchAgent\\\\deploy.ps1'\n    condition: selection and not filter_patch_agent",
        "keyPoints": [
          "A filter uses the same syntax as a selection but is subtracted via 'and not' rather than added.",
          "Inline filters belong in the rule for structural, universal noise; organization-specific noise belongs in a standalone exception, not hard-coded into shared rule logic.",
          "Weak, single-field filters (e.g., matching on Image alone) can be abused by an attacker who mimics the excluded tool's name.",
          "Always re-test both the malicious sample and the newly-excluded benign sample after adding a filter."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Field Mappings Across Backends",
        "body": "Sigma's fields (Image, CommandLine, ParentImage, TargetFilename, and so on) form a generic, backend-agnostic taxonomy. No raw log source actually calls a field \"Image\" — that name is Sigma's own convention, closely modeled on Sysmon's field names because Sysmon was the most common Windows telemetry source when Sigma was designed. The actual translation from Sigma's generic field name to a specific product's real column or field name happens in a pySigma pipeline.\n\nA pipeline is a configuration profile — either built into a backend package or supplied separately — that tells the converter two things: how to translate the logsource block into a concrete index/table/sourcetype, and how to rename each generic field into that product's real field name.\n\n### Worked example: process creation across three products\n| Sigma field | Sysmon (Windows Event Log) | Microsoft Defender (DeviceProcessEvents) | CrowdStrike Falcon |\n|---|---|---|---|\n| Image | Image | FolderPath / FileName | ImageFileName |\n| CommandLine | CommandLine | ProcessCommandLine | CommandLine |\n| ParentImage | ParentImage | InitiatingProcessFolderPath | ParentBaseFileName |\n| User | User | AccountName | UserName |\n\nNotice that a single Sigma field can even map to more than one real field in the target product (Image splitting into a folder path and a file name in Defender's schema, for instance) — the pipeline encodes that translation so the rule author never has to.\n\n### Why this matters for a detection engineer\nWithout this abstraction layer, an organization running both Sysmon and Microsoft Defender for Endpoint would need two hand-written, hand-maintained copies of every rule — doubling the maintenance burden and doubling the chance the two copies drift apart. With pySigma pipelines, the same YAML source rule converts cleanly for either backend.\n\n### Running a conversion\nThe sigma-cli tool wraps pySigma for command-line use. A typical invocation names the target backend with -t and the pipeline with -p.",
        "codeExample": "# Convert one Sigma rule to a Splunk SPL query using the Sysmon field pipeline\nsigma convert -t splunk -p sysmon rules/lsass_access.yml\n\n# Convert the same rule to Microsoft Sentinel KQL using the Defender pipeline\nsigma convert -t microsoft365defender -p microsoft365defender rules/lsass_access.yml",
        "keyPoints": [
          "Sigma's field names (Image, CommandLine, ParentImage) are a generic taxonomy, not real log field names.",
          "A pySigma pipeline maps generic Sigma fields to a specific product's actual field names and translates the logsource into a concrete table/index.",
          "One Sigma field can map to multiple real fields in a target product's schema (e.g., Image splitting into FolderPath and FileName in Microsoft Defender).",
          "Writing rules once against Sigma's generic taxonomy avoids maintaining separate, drifting rule sets per SIEM."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Common Anti-Patterns and How to Avoid Them",
        "body": "Most Sigma rules that generate excessive false positives, or that silently fail to detect what they claim to, share a small set of recurring mistakes. Recognizing these patterns before a rule ships saves the tuning work covered later in the False Positive Analysis lesson.\n\n### 1. Selections that are too broad\nMatching only on Image ending in powershell.exe with no other constraint will fire on essentially every PowerShell invocation in the environment, malicious or not. A precise selection layers multiple weak signals (parent process, command-line fragment, unusual flags) so that the combination, not any single field, is what is genuinely rare.\n\n### 2. Hard-coded paths without accounting for path variants\nWindows stores 32-bit and 64-bit programs in different Program Files directories (Program Files versus Program Files (x86)), and some tools install to per-user AppData paths instead. A selection that only checks one exact path will silently miss the other. Using contains or endswith modifiers on the distinctive suffix of a path is usually safer than a full literal match.\n\n### 3. Missing or wrong logsource fields\nA rule without a category, or with the wrong product, may convert to the wrong index or field mapping entirely — passing YAML validation while never matching real production data. This failure mode is dangerous specifically because it produces no errors, only silent non-detection.\n\n### 4. Skipping falsepositives and level metadata\nThese fields cost the author almost nothing to fill in and save the triaging analyst significant time later. A rule with an empty falsepositives list and a default level implicitly tells the next analyst \"we don't know\" — which is a worse outcome than an honest \"this fires on X and Y benign tools.\"\n\n### 5. Ambiguous boolean grouping\nMixing and/or across more than two blocks without parentheses is technically legal but easy to misread, both by the author and by whoever reviews the rule later. A condition like \"selection_a or selection_b and not filter\" is genuinely ambiguous to a human reader even where the parser has a defined operator precedence — always group explicitly with parentheses when mixing operators.\n\n### 6. Testing against only the malicious sample\nA rule that has only ever been run against the attack sample it was designed to catch has never been proven not to fire on everyday legitimate activity. The next lesson in this module covers building a proper test corpus that includes both positive and negative cases.",
        "codeExample": "# Anti-pattern: single weak field, no path-variant handling, no parentheses\ndetection:\n    selection:\n        Image|endswith: '\\\\powershell.exe'\n    filter:\n        ParentImage: 'C:\\\\Program Files\\\\Vendor\\\\tool.exe'\n    condition: selection or filter and not selection   # ambiguous and logically broken",
        "keyPoints": [
          "Overly broad single-field selections are the leading cause of noisy Sigma rules.",
          "Hard-coded literal paths miss Program Files (x86) variants and per-user install paths; prefer endswith/contains on distinctive suffixes.",
          "A wrong or missing logsource field causes silent non-detection — the rule looks valid but never matches real data.",
          "Always test a new rule against both a malicious sample and representative benign samples, never the malicious sample alone."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: From ATT&CK Technique to Sigma Rule",
        "body": "Detection engineering rarely starts from a blank page — it typically starts from a specific gap: a MITRE ATT&CK technique the organization has no reliable detection for, surfaced by a coverage review, a red team finding, or a threat intelligence report. Turning that gap into a working Sigma rule follows a repeatable sequence.\n\n### Step 1 — Pick the technique and understand attacker behavior\nTake T1003.001 (OS Credential Dumping: LSASS Memory) as a running example. The MITRE ATT&CK page for this technique describes the underlying behavior: a process opens a handle to lsass.exe (Local Security Authority Subsystem Service — the Windows process that holds credential material in memory) with access rights broad enough to read its memory, most commonly to extract password hashes or Kerberos tickets.\n\n### Step 2 — Identify available telemetry\nSysmon's Event ID 10 (ProcessAccess) records exactly this: a SourceImage opening a handle to a TargetImage, with a GrantedAccess value describing the requested permissions. This is the telemetry the rule will target.\n\n### Step 3 — Write the selection\nTarget TargetImage ending in lsass.exe, combined with GrantedAccess values known to correspond to memory-reading access (such as 0x1010, 0x1410, or the maximal 0x1FFFFF used by tools like Mimikatz and by the comsvcs.dll MiniDump technique).\n\n### Step 4 — Write the filter\nLegitimate processes also open handles to lsass.exe — most notably Windows Error Reporting (WerFault.exe) generating a crash dump, and some endpoint security agents performing memory inspection. These become filter blocks.\n\n### Step 5 — Set logsource, condition, and metadata\ncategory: process_access, product: windows; condition: selection and not filter; tags including attack.credential-access and attack.t1003.001; level: high, given the technique's severity.\n\n### Step 6 — Test before shipping\nThe next lesson in this module (Coverage Testing) covers running the rule through sigma-cli's validation, converting it to the production backend, and confirming it matches a known-malicious sample while staying silent on the filtered benign cases — the step that turns a rule from \"looks right\" into \"proven to work.\"",
        "codeExample": "flowchart TD\n  A[\"Pick ATT&CK technique\\n(T1003.001 LSASS Memory)\"] --> B[\"Identify telemetry\\n(Sysmon EID 10 ProcessAccess)\"]\n  B --> C[\"Write selection\\n(TargetImage=lsass.exe,\\nGrantedAccess values)\"]\n  C --> D[\"Write filter\\n(WerFault.exe, EDR agent)\"]\n  D --> E[\"Set logsource,\\ncondition, tags, level\"]\n  E --> F[\"Test: fires on malicious sample,\\nsilent on filtered benign sample\"]\n  F --> G[\"Ship to production backend\\nvia pySigma pipeline\"]",
        "keyPoints": [
          "Detection engineering typically starts from an identified ATT&CK coverage gap, not from a blank page.",
          "LSASS (Local Security Authority Subsystem Service) is the Windows process targeted by T1003.001 credential dumping.",
          "Sysmon Event ID 10 (ProcessAccess) with specific GrantedAccess values is the standard telemetry for detecting LSASS memory access.",
          "A rule is not finished at 'condition and metadata written' — it must be tested against both malicious and benign samples before shipping."
        ]
      }
    ],
    "quiz": [
      {
        "question": "An analyst's organization is migrating its SIEM from Splunk to Microsoft Sentinel. What is the main advantage of having detections written as Sigma rules rather than as hand-written SPL searches?",
        "options": [
          {
            "label": "Sigma rules run faster than native SPL queries because YAML is less verbose",
            "value": "d"
          },
          {
            "label": "A pySigma pipeline converts the rule into KQL, so it never needs to be rewritten by hand",
            "value": "a"
          },
          {
            "label": "Sigma rules automatically update themselves when MITRE ATT&CK publishes new techniques",
            "value": "b"
          },
          {
            "label": "Sentinel can only import detections that are written in the Sigma format",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "Sigma's whole purpose is backend-agnostic detection logic: a pySigma pipeline translates the same rule into whichever query language the target SIEM uses. Sigma has no effect on query execution speed, does not self-update from ATT&CK, and Sentinel accepts KQL rules written directly, not only Sigma conversions."
      },
      {
        "question": "A Sigma rule's logsource block is written as 'category: process_creation, product: windows' but should have been 'category: network_connection'. What is the most likely consequence?",
        "options": [
          {
            "label": "The YAML fails to parse and sigma-cli reports a syntax error immediately",
            "value": "a"
          },
          {
            "label": "The rule converts and deploys without error, but silently never matches the intended network telemetry",
            "value": "b"
          },
          {
            "label": "The rule automatically matches both process creation and network connection events",
            "value": "c"
          },
          {
            "label": "pySigma refuses to convert any rule with a category and product mismatch",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A wrong logsource field is valid YAML and converts cleanly, but the pipeline maps it to the wrong table or field set, so the rule silently fails to detect what it was designed for — a dangerous failure mode precisely because it produces no visible error."
      },
      {
        "question": "A detection engineer has five selections named selection_cmd_1 through selection_cmd_5, each capturing a different known-malicious command-line fragment for the same technique. Which condition expresses 'match if any one of them is present' most safely as the list grows?",
        "options": [
          {
            "label": "all of selection_cmd*",
            "value": "b"
          },
          {
            "label": "1 of selection_cmd*",
            "value": "c"
          },
          {
            "label": "selection_cmd_1 and selection_cmd_5",
            "value": "d"
          },
          {
            "label": "not selection_cmd*",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "'1 of selection_cmd*' means OR across every block matching that name pattern — exactly 'any one of them.' 'all of' would require every fragment to be present simultaneously, 'and' between only two of the five ignores the others, and 'not' would invert the logic entirely."
      },
      {
        "question": "A rule fires correctly on a malicious PowerShell sample, but also fires on a known internal patch-management tool that legitimately runs PowerShell with a fixed, predictable argument set. What is the most appropriate fix within the rule itself?",
        "options": [
          {
            "label": "Delete the selection block entirely so the rule never fires again",
            "value": "c"
          },
          {
            "label": "Add a filter for the patch tool's pattern, using 'selection and not filter'",
            "value": "d"
          },
          {
            "label": "Lower the rule's level field from high down to informational",
            "value": "a"
          },
          {
            "label": "Change the logsource product field from windows to linux",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "This is the standard Sigma pattern for excluding a known, structural source of noise: a filter block describing the benign case, subtracted with 'and not filter.' Deleting the selection defeats the rule's purpose, lowering severity doesn't stop the false positive, and changing the product field would break the rule for a different reason entirely."
      },
      {
        "question": "Why does Sigma use a generic field taxonomy (Image, CommandLine, ParentImage) instead of each rule using the exact field names of the target SIEM?",
        "options": [
          {
            "label": "Because generic field names are shorter and reduce the rule's file size",
            "value": "d"
          },
          {
            "label": "So one rule converts to many backends via pipelines, avoiding duplicate copies",
            "value": "a"
          },
          {
            "label": "Because Sysmon technically requires all field names to be generic",
            "value": "b"
          },
          {
            "label": "So that filters and selections can be merged into one block automatically",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "The generic taxonomy is the entire basis of Sigma's portability: pySigma pipelines translate it per backend, avoiding duplicate, drifting rule sets across every SIEM an organization runs. File size and automatic filter/selection merging are not real Sigma mechanisms, and Sysmon does not impose the taxonomy — Sigma's design simply mirrors Sysmon's field names for familiarity."
      }
    ]
  },
  "detection-engineer--sigma-modifiers": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Modifiers Exist",
        "body": "The previous lesson covered plain selections: a field name mapped to a value, matched as an exact (or wildcard) string. That is enough for many rules, but real detection logic frequently needs something more precise than \"equals\" or \"contains a wildcard somewhere.\" Sigma provides this precision through modifiers — suffixes attached to a field name with a pipe character, written as field-pipe-modifier: value.\n\nModifiers change how the value is compared against the field, not which field is being examined. They fall into a handful of families, each solving a specific matching problem:\n\n- **String position modifiers** (contains, startswith, endswith) — control where in the string a substring must appear.\n- **List logic modifiers** (all) — change how multiple values on the same field combine.\n- **Pattern modifiers** (re) — allow full regular expression matching with flags.\n- **Encoding-aware modifiers** (base64, base64offset, wide) — catch values that only appear in an encoded form in the raw log.\n- **Command-line normalization** (windash) — account for the several interchangeable ways Windows accepts a dash in a command-line flag.\n- **Structural modifiers** (fieldref, exists, cidr, gt/gte/lt/lte) — compare against another field, check presence, match a network range, or perform numeric comparison.\n\n### Why this precision matters\nAn imprecise selection either misses the attack (false negative) or fires on everything that superficially resembles it (false positive) — the exact anti-patterns covered in the previous lesson. Modifiers are the tool that lets a detection engineer say precisely what they mean: this value must appear at the very start of the field, not merely somewhere in the field, or all four of these substrings must be present together, not merely any one of them.\n\nThis lesson works through each modifier family with a real, working example, and closes with a combined worked example detecting encoded PowerShell — the kind of rule that genuinely requires several modifiers working together to be both precise and evasion-resistant.",
        "codeExample": "# Modifier syntax: fieldname|modifier1|modifier2: value\ndetection:\n    selection:\n        CommandLine|contains: '-enc'",
        "keyPoints": [
          "Modifiers are pipe-separated suffixes on a field name (field|modifier: value) that change how a value is compared.",
          "They fall into families: string position, list logic, regex, encoding-aware, command-line normalization, and structural comparisons.",
          "Modifiers exist to make selections precise enough to avoid both false negatives (missing the attack) and false positives (matching too broadly).",
          "Multiple modifiers can be chained on the same field (field|modifier1|modifier2) when a value needs more than one transformation."
        ]
      },
      {
        "pageNumber": 2,
        "title": "String Matching Modifiers: contains, startswith, endswith",
        "body": "These three modifiers control where a substring is allowed to appear within the target field's value, and are the most frequently used modifiers in the entire Sigma ecosystem.\n\n### contains\nfield-pipe-contains matches if the value appears anywhere in the field — equivalent to wrapping the value in wildcards on both sides. This is the right choice when the interesting substring could be preceded or followed by other, unpredictable text, such as a suspicious flag appearing somewhere in a long, variable command line.\n\n### startswith\nfield-pipe-startswith matches only if the field begins with the value — equivalent to a trailing wildcard. This is useful for anchoring to the beginning of a path, such as detecting execution from a known-suspicious directory root (for example, a temp folder or a newly-created user profile path), where matching the very start of the string rules out unrelated paths that merely happen to contain the same folder name deeper in their structure.\n\n### endswith\nfield-pipe-endswith matches only if the field ends with the value — equivalent to a leading wildcard. This is the standard way to match a binary name regardless of its install directory, since the same executable name (rundll32.exe, for example) can legitimately live in several different paths.\n\n### Multiple values under one modifier\nWhen a field is given a list of values with the same modifier, the values are combined with OR by default — any one of them satisfies the field. The next page covers the all modifier, which changes this default from OR to AND.\n\n### Choosing the right one\nA common authoring mistake is using contains when endswith would be more precise — contains matching on the string \"rundll32.exe\" would also match a hypothetical file called evil_rundll32.exe_backup.txt if that string appeared anywhere in a longer field, whereas endswith requires the field to genuinely end with that exact binary name preceded by a path separator, which is a meaningfully tighter and safer match.",
        "codeExample": "detection:\n    selection:\n        # contains: anywhere in the command line\n        CommandLine|contains: '-EncodedCommand'\n        # endswith: exact binary name regardless of install path\n        Image|endswith: '\\\\rundll32.exe'\n        # startswith: anchored to the beginning of the path\n        Image|startswith: 'C:\\\\Users\\\\Public\\\\'\n    condition: selection",
        "keyPoints": [
          "contains matches anywhere in the field; startswith anchors to the beginning; endswith anchors to the end.",
          "endswith is the standard way to match a binary name across multiple possible install paths.",
          "startswith is useful for anchoring to a suspicious directory root without matching unrelated paths that merely contain the same folder name.",
          "Multiple values on one field with the same modifier are combined with OR by default."
        ]
      },
      {
        "pageNumber": 3,
        "title": "The all Modifier: Changing List Logic from OR to AND",
        "body": "By default, when a field is given a list of values, Sigma combines them with OR: the selection matches if the field equals (or contains, or starts/ends with) any one of the listed values. The all modifier reverses this default for that field, requiring every listed value to be present simultaneously.\n\nThis distinction matters most when combined with contains, since a single field like CommandLine can legitimately contain several independent substrings at once. Consider detecting a PowerShell command line that both downloads a payload and disables execution policy protections — two independent, suspicious fragments that could each appear alone in a benign command line, but together are a much stronger signal.\n\nWithout the all modifier, a CommandLine-contains selection listing both fragments would match if the command line contains either fragment — likely too broad, since the execution-policy-bypass fragment alone is common in many legitimate automation scripts. Adding the all modifier requires both fragments to appear together in the same command line, which is a far more specific and higher-confidence indicator.\n\n### Syntax\nThe all modifier is written as an additional pipe segment on the field, typically paired with contains, followed by the list of required substrings.\n\n### When not to use all\nIf the goal genuinely is \"any one of these known-bad values is enough,\" using all would make the rule too strict and cause it to miss cases where only one indicator is present — the opposite failure mode from the anti-patterns discussed in the previous lesson. The choice between the default OR and the all-driven AND should reflect the actual relationship between the indicators: are they alternative ways an attacker might do the same thing (OR), or are they independent conditions that must co-occur to be meaningful (AND)?\n\n### A note on readability\nBecause the default behavior (OR) is implicit and all silently changes it, a reviewer scanning a rule quickly should always check for the all suffix before assuming a list of values behaves the way a first glance suggests.",
        "codeExample": "detection:\n    selection:\n        CommandLine|contains|all:\n            - '-ExecutionPolicy Bypass'\n            - 'DownloadString'\n            - 'Net.WebClient'\n    condition: selection",
        "keyPoints": [
          "By default, a list of values on one field is combined with OR (any one value matches).",
          "The all modifier changes this to AND (every listed value must be present simultaneously).",
          "all combined with contains is commonly used to require several independent suspicious command-line fragments to co-occur, raising confidence.",
          "Using all when OR logic was intended makes a rule too strict and can cause it to miss valid single-indicator matches."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Regex with the re Modifier and Its Flags",
        "body": "The re modifier tells the backend to treat the given value as a regular expression rather than a literal string or wildcard pattern. This unlocks matching that plain contains/startswith/endswith cannot express: character classes, alternation, anchors, and quantifiers.\n\n### Basic usage\nfield-pipe-re matches the field against the regex pattern. Sigma's regex support covers the common constructs analysts expect from most regex flavors: wildcards, anchors (start and end of string), quantifiers (zero-or-more, one-or-more, optional, and bounded repetition), character classes, alternation, and grouping.\n\n### Regex flags\nRegex matching is case-sensitive by default, which is often not what an analyst wants when matching Windows paths or command lines (Windows is not case-sensitive for paths, and attackers sometimes deliberately vary case to evade naive string matches). Additional pipe-separated flag modifiers adjust this behavior:\n- **i** — case-insensitive matching.\n- **m** — multiline mode (start/end anchors match at line boundaries within the value, not just the whole string).\n- **s** — single-line/dotall mode (the any-character wildcard matches newline characters too).\n\nThese are written as additional modifier segments, for example field-pipe-re-pipe-i.\n\n### When to reach for re instead of contains/startswith/endswith\nRegex is the right tool when the pattern to match has structure that a plain substring cannot express — for instance, an encoded PowerShell payload that always starts with a specific short prefix followed by a long run of base64 characters, or a process name that varies by a single digit across malware samples (such as svchost followed by one or two digits followed by .exe). Reaching for re when a simple contains would do adds unnecessary complexity and a small performance cost on some backends — regex should be the precision tool for genuinely structured patterns, not the default choice.\n\n### A caution on regex portability\nNot every Sigma backend supports every regex construct identically — some backends translate re to a native regex operator in the target query language (for example Splunk's rex command or a match function), and subtle flavor differences (lookahead/lookbehind support, for instance) can behave differently across backends. Testing the converted query against real sample data, not just validating the Sigma YAML, is the only reliable way to confirm a regex-based rule behaves as intended in production — the subject of the next lesson.",
        "codeExample": "detection:\n    selection:\n        # Case-insensitive match for a service name pattern used by a malware family\n        ServiceName|re|i: '^svc(update|helper)[0-9]{2,4}$'\n    condition: selection",
        "keyPoints": [
          "The re modifier treats the value as a regular expression, supporting anchors, quantifiers, character classes, alternation, and grouping.",
          "Regex matching is case-sensitive by default; the i flag modifier makes it case-insensitive.",
          "re is the right tool for genuinely structured patterns that contains/startswith/endswith cannot express — not a default replacement for them.",
          "Regex behavior can differ subtly across backends, so a regex-based rule must be tested against the converted, real query, not just validated as YAML."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Evasion-Aware Modifiers: base64offset and windash",
        "body": "Two modifiers exist specifically because attackers routinely try to defeat naive string matching, and Sigma's design accounts for both evasion techniques directly in the specification.\n\n### base64offset: catching an encoded substring regardless of alignment\nAttackers frequently base64-encode a payload or command before embedding it in a command line (most visibly with PowerShell's -EncodedCommand flag). The problem for a detection engineer is that base64 encodes data in fixed 3-byte groups into 4-character blocks — so the same substring, embedded at a different position within a larger encoded blob, can produce a completely different sequence of base64 characters purely because of where the 3-byte alignment falls. There are exactly three possible byte-alignment shifts (0, 1, or 2 bytes), and each produces a different base64 representation of the same underlying text.\n\nThe base64offset modifier solves this by pre-computing all three shifted base64 representations of the given value and matching if any of them appears in the field — so a rule looking for an encoded reference to, for example, a suspicious PowerShell cmdlet still catches it no matter where in the larger encoded string that substring happens to fall.\n\n### windash: normalizing command-line dash characters\nWindows command-line tools generally accept several visually similar but distinct dash characters interchangeably as a flag prefix: the standard hyphen-minus, the forward slash in many older tools, and several Unicode dash variants (en dash, em dash, horizontal bar) that some LOLBins (Living-Off-the-Land Binaries — legitimate, pre-installed system tools abused for malicious purposes) and obfuscation techniques substitute for the plain hyphen specifically to slip past a rule that only checks for the hyphen.\n\nThe windash modifier expands a single value into every one of these interchangeable variants automatically, so a windash-modified match for the \"-enc\" flag matches \"-enc\", \"/enc\", and the Unicode dash variants without the author having to enumerate each variant by hand.\n\n### Why both matter for the same rule\nAn encoded PowerShell payload detection frequently needs both: windash to catch every way the -EncodedCommand flag itself might be written, and base64offset to catch a known-malicious encoded substring regardless of its alignment within the larger blob — the worked example on the final page of this lesson combines exactly these two.",
        "codeExample": "detection:\n    selection_flag:\n        # Matches -enc, /enc, and Unicode dash variants of the flag\n        CommandLine|windash|contains: '-enc'\n    selection_payload:\n        # Matches the value regardless of its 3-byte base64 alignment\n        CommandLine|base64offset|contains: 'IEX (New-Object'\n    condition: selection_flag and selection_payload",
        "keyPoints": [
          "base64offset pre-computes all three possible byte-alignment shifts of a value's base64 encoding, since the same substring encodes differently depending on its position.",
          "windash expands a value into every Windows-accepted dash-character variant so a rule isn't evaded by simply swapping the flag prefix character.",
          "LOLBins (Living-Off-the-Land Binaries) are legitimate system tools that attackers abuse, and windash specifically defends against flag-character substitution tricks used with them.",
          "Encoded-command detections often need both modifiers together: one for the flag, one for the encoded payload substring."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Field and Network Modifiers: fieldref, cidr, exists",
        "body": "Several modifiers compare a field against something other than a fixed literal value: another field in the same event, a network range, or simply whether the field is present at all.\n\n### fieldref: comparing one field to another\nNormally, a selection value is a fixed string or number known in advance. The fieldref modifier instead compares the target field's value to another named field in the same event, evaluated dynamically at match time. This is useful for detecting relationships between fields rather than fixed values — for example, flagging a process where the CommandLine field contains the value of the ParentImage field, which can indicate a process re-launching or referencing its own parent in a way that is unusual for normal software behavior.\n\n### cidr: matching an IP against a network range\nThe cidr modifier interprets the given value as CIDR (Classless Inter-Domain Routing) notation and matches if the field's IP address falls within that range, rather than requiring an exact IP match. This is the standard way to write a rule against a known-malicious or known-internal address block rather than a single IP, since attacker infrastructure and internal network segments are both naturally expressed as ranges.\n\n### exists: checking field presence, not field value\nAn exists modifier set to true matches events where the field is present at all (regardless of its value); set to false it matches events where the field is absent. This is useful when the absence of an expected field is itself the anomaly — for instance, a process creation event missing a ParentImage field entirely can indicate an orphaned process or a process injected directly rather than spawned normally through the expected parent-child chain.\n\n### Comparison modifiers: gt, gte, lt, lte\nNumeric fields can be compared with greater-than, greater-than-or-equal, less-than, and less-than-or-equal modifiers instead of exact equality — useful for thresholds such as a file size, a port number range, or a numeric access-rights value above a known-suspicious level.\n\n### Putting them together\nA single rule can combine several of these: a network-range check on a destination IP (cidr), a presence check on an expected field (exists), and a numeric threshold (gte) all within the same selection, each contributing an independent, structural constraint rather than a string-matching one.",
        "codeExample": "detection:\n    selection:\n        DestinationIp|cidr: '203.0.113.0/24'\n        ParentImage|exists: false\n        GrantedAccess|gte: '0x1000'\n    condition: selection",
        "keyPoints": [
          "fieldref compares a field's value against another field in the same event, evaluated dynamically rather than against a fixed literal.",
          "cidr (Classless Inter-Domain Routing) matches an IP field against a network range instead of requiring an exact address match.",
          "exists checks whether a field is present (true) or absent (false) — useful when the absence of an expected field is itself suspicious.",
          "gt/gte/lt/lte perform numeric comparisons instead of exact-value matching, useful for thresholds."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Comparison and Chaining Modifiers",
        "body": "Modifiers are not limited to one per field — Sigma allows chaining several modifiers on the same field when a value needs more than one transformation before it can be compared correctly against the raw log data.\n\n### Encoding-chain modifiers: base64 and wide\nThe base64 modifier encodes the given literal value into base64 before matching, useful when the raw log field itself stores data in already-encoded form and the author wants to express the search value in its original, readable form rather than pre-encoding it by hand. The wide (also called utf16) modifier accounts for the fact that some Windows telemetry stores strings in UTF-16 encoding, where each character is padded with null bytes — a plain base64 encoding of a value would not match a UTF-16-encoded-then-base64-encoded string unless the UTF-16 transformation is applied first. Chaining these two modifiers together (wide before base64) reproduces the exact byte sequence the raw log actually contains.\n\n### Order matters when chaining\nBecause each modifier transforms the value before the next one is applied, the order of chained modifiers changes the result — encoding to UTF-16 and then base64-encoding the result is not the same operation as base64-encoding first and then attempting to reinterpret as UTF-16. A detection engineer chaining encoding modifiers should verify the exact expected byte sequence against a real captured sample of the raw log field, not assume the chain is correct from the modifier names alone.\n\n### cased: opting into case-sensitivity\nMost Sigma string matching is case-insensitive by default (reflecting that Windows itself is largely case-insensitive for paths and many field values). The cased modifier is the inverse of that default, forcing an otherwise case-insensitive comparison to become case-sensitive — useful in the rare case where case itself is the meaningful signal, such as detecting an attacker deliberately altering the case of a system binary's filename in an attempt to look different from monitored baselines on a case-sensitive log source.\n\n### A practical takeaway\nMost rules a detection engineer writes day-to-day need only the simpler modifiers — contains, startswith, endswith, all, and occasionally re or cidr. The encoding-chain and case-sensitivity modifiers are specialist tools reserved for the specific, narrower scenarios described here, and reaching for them without a concrete reason to suspect an encoding or case-sensitivity issue adds unnecessary complexity to a rule.",
        "codeExample": "detection:\n    selection:\n        # Match a value as it would appear UTF-16 encoded, then base64 encoded\n        CommandLine|wide|base64offset|contains: 'Invoke-Mimikatz'\n    condition: selection",
        "keyPoints": [
          "Modifiers can be chained on one field (e.g., wide then base64offset) when a value needs more than one transformation to match the raw log's actual encoding.",
          "The order of chained modifiers matters — transformations are applied sequentially, so wide-then-base64 is not equivalent to base64-then-wide.",
          "cased forces an otherwise case-insensitive match to become case-sensitive, for the rare cases where case itself is the meaningful signal.",
          "Most day-to-day rules only need the simpler modifiers; encoding chains and cased are specialist tools for specific scenarios."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Example: Detecting Encoded PowerShell with Modifiers",
        "body": "This final page combines several modifiers from across the lesson into one realistic detection: identifying PowerShell launched with an encoded command that downloads content from the network, a common pattern in both commodity malware and hands-on-keyboard intrusions.\n\n### The behavior being targeted\nAn attacker (or a malicious script) launches powershell.exe with the -EncodedCommand flag (frequently abbreviated -enc) carrying a base64-encoded script that, once decoded, performs a network download — commonly via .NET's Net.WebClient class or Invoke-WebRequest cmdlet. Because the payload is encoded, a plain-text contains check against the decoded script's content will never match the raw command line as logged.\n\n### Building the selection, piece by piece\n1. **The flag itself, evasion-resistant**: a windash-and-contains match for \"-enc\" catches the flag whether written as \"-enc\", \"/enc\", or a Unicode dash variant.\n2. **The base64-encoded payload fragment, alignment-resistant**: a base64offset-and-contains match for \"Net.WebClient\" catches a known-suspicious .NET class reference regardless of which of the three possible byte-alignment shifts it happens to fall on.\n3. **Requiring both together**: since either fragment alone is weaker evidence (the flag alone is used by many legitimate automation scripts; the base64 fragment alone could theoretically appear in unrelated encoded data), the condition combines both selections with and.\n\n### Why this is stronger than any single modifier alone\nNeither windash nor base64offset alone would make this rule reliable — windash only helps with the flag, and base64offset only helps with the payload. It is the combination, matched together in one condition, that produces a rule resistant to two independent evasion techniques (dash substitution and base64 misalignment) while still requiring both a strong contextual signal (the encoded-command flag) and a strong content signal (the suspicious .NET reference).\n\n### What this rule does not solve\nIt does not detect encoded PowerShell where the payload avoids the specific .NET class referenced here, and it does not decode and inspect the full payload — only match a known-suspicious fragment within it. The Coverage Testing lesson that follows covers how to validate exactly how much of the real attack space a rule like this actually catches, and where its blind spots are.",
        "codeExample": "title: Encoded PowerShell Command with Network Download Indicator\nid: 7b3e9c1a-2d4f-4a8e-9c1b-3e5f7a9b1c3d\nstatus: stable\ndescription: Detects PowerShell launched with an encoded command containing a known network-download class reference\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_process:\n        Image|endswith: '\\\\powershell.exe'\n    selection_flag:\n        CommandLine|windash|contains: '-enc'\n    selection_payload:\n        CommandLine|base64offset|contains: 'Net.WebClient'\n    condition: selection_process and selection_flag and selection_payload\ntags:\n    - attack.execution\n    - attack.t1059.001\nlevel: high",
        "keyPoints": [
          "Encoded PowerShell detection typically needs windash (for the flag) and base64offset (for the payload) working together, not either alone.",
          "windash defends against dash-character substitution; base64offset defends against base64 byte-alignment differences — two independent evasion techniques.",
          "Combining a contextual signal (the encoded-command flag) with a content signal (a suspicious encoded fragment) produces a stronger rule than either alone.",
          "A rule that matches a known-suspicious fragment does not decode or fully inspect the payload — it has a defined, limited detection scope that must be understood and tested."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A rule needs to match a CommandLine field whether it contains 'DownloadString' anywhere within a long, variable command line. Which modifier is the correct choice?",
        "options": [
          {
            "label": "startswith, since the string must appear at the very beginning",
            "value": "a"
          },
          {
            "label": "contains, since the string may appear anywhere in the field",
            "value": "b"
          },
          {
            "label": "endswith, since the string must appear at the very end",
            "value": "c"
          },
          {
            "label": "exists, since the field must simply be present",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "contains matches a substring anywhere in the field, which fits a value that could appear at any position within a variable command line. startswith and endswith anchor to a specific end of the string, and exists only checks whether the field is present, not its content."
      },
      {
        "question": "A selection lists three command-line fragments under CommandLine with a contains modifier, without the all modifier. What logic combines those three values by default?",
        "options": [
          {
            "label": "AND — all three fragments must be present together",
            "value": "b"
          },
          {
            "label": "OR — any one of the three fragments is enough to match",
            "value": "c"
          },
          {
            "label": "XOR — exactly one fragment must be present, not more than one",
            "value": "d"
          },
          {
            "label": "NOT — the field must contain none of the three fragments",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "Sigma's default logic for multiple values on one field is OR: any single listed value satisfies the field. The all modifier is required to change this to AND, and Sigma has no built-in XOR or NOT-list behavior for a plain value list."
      },
      {
        "question": "An analyst wants a rule to require that a command line contain both '-ExecutionPolicy Bypass' AND 'DownloadString' together, not just either one alone, to reduce false positives from common automation scripts. Which modifier combination achieves this?",
        "options": [
          {
            "label": "contains with no additional modifier, listing both values",
            "value": "c"
          },
          {
            "label": "contains combined with the all modifier, listing both values",
            "value": "d"
          },
          {
            "label": "Two separate rules, one for each fragment, run independently",
            "value": "a"
          },
          {
            "label": "startswith combined with the all modifier, listing both values",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "contains combined with all requires every listed substring to be present together, which is exactly the AND behavior needed here. Plain contains without all would use OR (matching either fragment alone), two separate rules wouldn't express the co-occurrence requirement, and startswith would incorrectly require both fragments at the very beginning of the field, which is not how command lines are structured."
      },
      {
        "question": "A rule intended to catch a base64-encoded reference to a suspicious .NET class fails to match a real malicious sample, even though the class name is genuinely present in the decoded payload. The selection uses a plain base64 modifier rather than base64offset. What is the most likely explanation?",
        "options": [
          {
            "label": "The base64 modifier only works on numeric fields, not string fields",
            "value": "d"
          },
          {
            "label": "The same substring encodes differently by byte alignment; plain base64 only computes one of three shifts",
            "value": "a"
          },
          {
            "label": "base64 modifiers are deprecated and no longer supported by any backend",
            "value": "b"
          },
          {
            "label": "The rule's logsource category was set incorrectly",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "base64 encoding groups data in 3-byte units, so the same substring can encode differently depending on where it falls within a larger encoded blob — exactly the problem base64offset solves by checking all three possible shifts. The base64 modifier works on any string value, is not deprecated, and this failure mode is unrelated to logsource."
      },
      {
        "question": "A rule matches a command's -enc flag but an attacker evades it by writing the flag as /enc instead. Which modifier should have been used to prevent this evasion?",
        "options": [
          {
            "label": "cidr, to match the flag against a network range",
            "value": "a"
          },
          {
            "label": "windash, to normalize interchangeable Windows dash/slash flag characters",
            "value": "b"
          },
          {
            "label": "exists, to check whether the flag field is present",
            "value": "c"
          },
          {
            "label": "fieldref, to compare the flag against another field",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "windash expands a value into every dash-character variant Windows command-line tools accept interchangeably (hyphen, slash, and Unicode dash variants), which is exactly the evasion described. cidr is for IP ranges, exists checks field presence, and fieldref compares against a different field entirely — none address flag-character substitution."
      }
    ]
  },
  "detection-engineer--sigma-coverage-testing": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Test Detections Before Shipping Them",
        "body": "The previous two lessons covered how to write a Sigma rule's logic — selections, filters, conditions, and modifiers. None of that guarantees the rule actually works once deployed. A rule can be syntactically perfect YAML, pass every review, and still fail in production for reasons that only testing reveals: a wrong logsource mapping, a field that the real log source spells slightly differently than expected, or a filter written so broadly it silently swallows the very attack the rule was meant to catch.\n\nThis lab focuses on the discipline of proving a detection works before it ships, and on measuring how much of an organization's overall attack surface its detection rules actually cover — two related but distinct activities.\n\n### Two different questions\n- **Does this one rule work?** — validated through syntax checking and matching the rule against both known-malicious and known-benign log samples.\n- **How much of our attack surface do all our rules, together, actually cover?** — answered by mapping every rule's MITRE ATT&CK tags onto the full ATT&CK Enterprise matrix and visualizing the result as a coverage heatmap.\n\n### Why this is a lab, not a lesson\nUnlike the conceptual material in the previous two lessons, this module is hands-on: running sigma-cli commands, building a small test corpus, and generating an actual heatmap output are procedural skills that only solidify through repetition. The pages that follow walk through each step in the order a detection engineer would actually perform them: local validation, then unit testing against sample logs, then integrating that testing into a continuous integration (CI) pipeline, then rolling the results up into ATT&CK-mapped coverage reporting.\n\n### The cost of skipping this step\nAn unvalidated rule that never fires gives a false sense of security — the organization believes a technique is covered when it is not. An unvalidated rule that fires too broadly does the opposite: it trains analysts to ignore alerts from that rule, quietly degrading trust in the detection program as a whole. Both failure modes are addressed by the testing and coverage-tracking practices in this lab.",
        "codeExample": "flowchart LR\n  A[\"Write rule\"] --> B[\"Validate syntax\"]\n  B --> C[\"Test against\\nmalicious + benign samples\"]\n  C --> D[\"Run in CI pipeline\"]\n  D --> E[\"Tag with ATT&CK\\ntechnique/tactic\"]\n  E --> F[\"Roll up into\\ncoverage heatmap\"]",
        "keyPoints": [
          "A syntactically valid Sigma rule is not the same as a working, tested detection.",
          "Testing answers 'does this one rule work'; coverage mapping answers 'how much of our attack surface do all our rules cover, together'.",
          "An unvalidated rule that never fires creates false confidence; one that fires too broadly trains analysts to ignore it.",
          "This lab is procedural: local validation, sample-based testing, CI integration, and ATT&CK-mapped coverage reporting, in that order."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Local Testing: Validating Syntax and Matching Sample Logs",
        "body": "Before a rule goes anywhere near production, it needs two forms of local validation: confirming the YAML itself is well-formed Sigma, and confirming it actually matches the telemetry it claims to detect.\n\n### Syntax validation\nThe sigma-cli tool (built on pySigma) provides a check command that validates a rule file against the Sigma specification — confirming required fields are present, the YAML parses, and the condition expression references only selections and filters that actually exist in the detection block. This catches typos and structural mistakes immediately, before any conversion or deployment attempt.\n\n### Building a test corpus\nSyntax validity says nothing about whether the rule matches real data. A proper test corpus contains at least two categories of sample log events:\n- **Positive samples** — real or realistic log lines representing the actual malicious behavior the rule targets (for example, a captured Sysmon ProcessAccess event from a genuine LSASS-dumping test in a lab environment).\n- **Negative samples** — realistic benign log lines that share surface similarity with the malicious pattern but should NOT trigger the rule (for example, WerFault.exe legitimately accessing lsass.exe after a crash).\n\n### Running the rule against the corpus\nAfter converting the rule to the target backend's query language via sigma convert, that query is run against an index containing both sample categories (or, for backends and tools that support it, matched directly against the sample events without needing a live SIEM). The rule passes local testing only when it matches every positive sample and matches none of the negative samples.\n\n### Iterating\nA rule that misses a positive sample needs a broader or corrected selection; a rule that matches a negative sample needs either a tighter selection or an added filter (covered in the Sigma Selection Patterns lesson). This loop — test, adjust, retest — continues until both conditions are satisfied, and only then does the rule move to the next stage: integration into a CI pipeline.",
        "codeExample": "# Validate rule syntax\nsigma check rules/lsass_access.yml\n\n# Convert to the production backend for testing\nsigma convert -t splunk -p sysmon rules/lsass_access.yml -o test_query.spl\n\n# Run the converted query against a test index containing both\n# positive (malicious) and negative (benign) sample events\nsplunk search \"$(cat test_query.spl)\" -index test_lsass_samples",
        "keyPoints": [
          "sigma check validates YAML structure and specification compliance before any conversion is attempted.",
          "A test corpus needs both positive samples (real malicious behavior) and negative samples (benign but similar-looking activity).",
          "A rule passes local testing only when it matches every positive sample and none of the negative samples.",
          "A rule that fails testing is adjusted (broader selection or added filter) and retested, not shipped as-is."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Detection-as-Code: Version Control and CI Pipelines",
        "body": "Treating detection rules the same way software engineers treat application code — stored in version control, reviewed via pull request, and automatically tested before merge — is the practice generally called detection-as-code. SigmaHQ's own public repository follows this model, organizing rules into directories by log source category (for example, rules for Windows process creation, rules for cloud services) with accompanying test files.\n\n### Why version control matters for detections\nEvery change to a rule (a new filter, a tightened selection, an added tag) has a clear author, timestamp, and rationale captured in the commit history — the same audit trail a codebase gets, and one that becomes essential later when investigating why a rule stopped firing or started generating unexpected noise.\n\n### A typical CI pipeline for Sigma rules\n1. A detection engineer opens a pull request adding or modifying a rule.\n2. An automated CI job runs sigma check against every changed rule to catch syntax errors.\n3. The CI job converts each changed rule to the organization's production backend(s) and runs it against the stored positive/negative test corpus for that rule.\n4. If all checks pass, a human reviewer checks the rule's logic, tags, and metadata quality before approving the merge.\n5. On merge, a deployment step pushes the converted query to the production SIEM (or triggers the SIEM to re-pull from the rule repository, depending on the organization's setup).\n\n### Benefits beyond catching bugs\nA CI pipeline also enforces consistency — for example, failing the build if a new rule is missing a level field, a falsepositives entry, or an ATT&CK tag — turning the authoring best practices from earlier lessons into automated, unskippable gates rather than optional guidelines a busy engineer might forget under deadline pressure.\n\n### The link to coverage reporting\nBecause every merged rule's tags are known and version-controlled, the CI pipeline (or a scheduled job reading the same repository) can also regenerate the ATT&CK coverage heatmap automatically every time the rule set changes — the subject of the remaining pages in this lesson.",
        "codeExample": "flowchart TD\n  A[\"Pull request:\\nnew/modified rule\"] --> B[\"CI: sigma check\\n(syntax)\"]\n  B --> C[\"CI: convert + run\\nagainst test corpus\"]\n  C -->|pass| D[\"Human review:\\nlogic, tags, metadata\"]\n  C -->|fail| A\n  D -->|approved| E[\"Merge and deploy\\nto production SIEM\"]\n  E --> F[\"Regenerate ATT&CK\\ncoverage heatmap\"]",
        "keyPoints": [
          "Detection-as-code stores rules in version control with pull-request review and automated testing, just like application code.",
          "Version control gives every rule change a clear author, timestamp, and rationale — an audit trail for later investigation.",
          "A CI pipeline can enforce authoring standards automatically (level, falsepositives, ATT&CK tags) rather than relying on manual discipline.",
          "Because rule tags are version-controlled, the ATT&CK coverage heatmap can be regenerated automatically whenever the rule set changes."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Mapping Rules to MITRE ATT&CK: Tags and the Navigator",
        "body": "The tags field introduced in the Sigma Selection Patterns lesson is what makes automated coverage reporting possible at all. Without consistent, correctly-applied tags, there is no reliable way to know which ATT&CK techniques an organization's rule set actually addresses.\n\n### Tag format\nSigmaHQ convention represents both the tactic and the technique as separate tags: a tactic tag such as attack.credential-access, and a technique (or sub-technique) tag such as attack.t1003.001. A single rule can carry multiple technique tags if the behavior it detects genuinely maps to more than one technique, and should always include at least the tactic and the most specific technique or sub-technique that applies — tagging only the parent technique when a more specific sub-technique exists loses precision in the resulting coverage picture.\n\n### The MITRE ATT&CK Navigator\nThe Navigator is a browser-based tool published by MITRE for visualizing the ATT&CK matrix as an interactive heatmap, where each technique cell can be colored and scored according to a JSON \"layer\" file. A layer file lists technique IDs alongside a score and a color, and the Navigator renders the full matrix with those techniques highlighted accordingly.\n\n### From Sigma tags to a Navigator layer\nConverting a set of Sigma rules' tags into a Navigator layer is a matter of extracting every attack.tXXXX tag across the rule set, counting or scoring how many (and how mature) rules exist for each technique, and emitting that as a Navigator layer JSON file — either through a small custom script reading the rules directory, or through purpose-built tooling in the broader Sigma ecosystem.\n\n### Why the tactic tag matters too, not just the technique\nThe tactic tag groups related techniques under the broader adversary goal (Credential Access, Persistence, Lateral Movement, and so on) — useful when reporting coverage at a higher level to stakeholders who care less about which specific sub-technique is covered and more about whether an entire category of adversary behavior has any detection at all.",
        "codeExample": "tags:\n    - attack.credential-access\n    - attack.t1003.001\n\n# Minimal ATT&CK Navigator layer JSON, generated from tags across a rule set\n{\n  \"name\": \"NexaCorp Detection Coverage\",\n  \"domain\": \"enterprise-attack\",\n  \"techniques\": [\n    { \"techniqueID\": \"T1003.001\", \"score\": 1, \"color\": \"#4caf50\" },\n    { \"techniqueID\": \"T1059.001\", \"score\": 1, \"color\": \"#4caf50\" }\n  ]\n}",
        "keyPoints": [
          "Sigma tags carry both a tactic (attack.credential-access) and a technique/sub-technique (attack.t1003.001) — the basis of automated coverage mapping.",
          "Tag the most specific sub-technique available, not just the parent technique, to preserve precision in coverage reporting.",
          "The MITRE ATT&CK Navigator renders a JSON 'layer' file as an interactive, color-coded heatmap over the full matrix.",
          "Tactic-level tags support higher-level, stakeholder-facing reporting on whether entire categories of adversary behavior have any coverage."
        ]
      },
      {
        "pageNumber": 5,
        "title": "sigma2stix and Machine-Readable Coverage Data",
        "body": "Beyond the ATT&CK Navigator, a detection engineering team often needs to share coverage information with other security tooling — a threat intelligence platform, a governance dashboard, or a risk-reporting system. This requires a machine-readable, standardized format beyond a Navigator-specific layer file, which is where STIX comes in.\n\n### What STIX is\nSTIX (Structured Threat Information Expression) is a standardized language and format, maintained under OASIS, for representing threat intelligence — including techniques, indicators, threat actors, and relationships between them — as structured JSON objects that different security tools can exchange and understand consistently.\n\n### sigma2stix\nsigma2stix is a community tool that converts Sigma rules into STIX 2.1 objects, linking each rule to the corresponding MITRE ATT&CK technique objects (which MITRE itself also publishes as a STIX bundle). The result is a set of STIX objects that represent \"this specific detection rule exists and maps to this specific ATT&CK technique\" in a format any STIX-consuming platform can ingest.\n\n### Why this matters beyond visualization\nA Navigator heatmap is excellent for a human reviewing coverage visually, but a STIX-formatted coverage dataset can be consumed programmatically — for example, feeding into a broader governance, risk, and compliance (GRC) tool that tracks detection coverage as one input alongside vulnerability data and asset criticality, or into a threat intelligence platform that can automatically flag when a newly-reported threat actor's known techniques have no corresponding Sigma rule coverage in the organization's rule set.\n\n### Where this fits in the workflow\nsigma2stix (or an equivalent conversion step) is typically run as a scheduled or CI-triggered job against the full rule repository, alongside the Navigator layer generation covered on the previous page — both are downstream consumers of the same underlying tag data, just serving different audiences and different tools.",
        "codeExample": "# Convert a directory of Sigma rules into STIX 2.1 objects\n# linked to their corresponding MITRE ATT&CK technique objects\nsigma2stix --rules-dir rules/ --output nexacorp_coverage.json",
        "keyPoints": [
          "STIX (Structured Threat Information Expression) is a standardized, machine-readable format for representing threat intelligence and techniques.",
          "sigma2stix converts Sigma rules' ATT&CK tags into STIX objects linked to MITRE's own published ATT&CK STIX bundle.",
          "STIX-formatted coverage data can be consumed programmatically by other tools (GRC platforms, threat intel platforms), not just viewed visually.",
          "Navigator layers and STIX conversion are both downstream consumers of the same underlying Sigma tag data, serving different audiences."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Building an ATT&CK Coverage Heatmap",
        "body": "With tags standardized and tooling in place to extract them, the actual heatmap-building process combines three pieces of information for every technique in the ATT&CK Enterprise matrix: whether a rule exists at all, how mature that rule is, and how confident the team is that the rule has actually been validated against real telemetry.\n\n### A simple scoring model\nMany teams use a small ordinal scale per technique, such as:\n- **0 — No coverage**: no rule exists for this technique.\n- **1 — Rule exists, unvalidated**: a rule has been written and tagged, but has not been tested against real telemetry (skipping the testing discipline from earlier in this lesson).\n- **2 — Rule exists, validated**: the rule has passed local testing against positive and negative samples and is deployed in production.\n- **3 — Rule exists, validated, and confirmed against live telemetry or a purple-team exercise**: the strongest confidence level, where the rule's real-world detection has been independently confirmed, often through the kind of adversary emulation and replay testing covered in the Purple Team learning path.\n\n### Visualizing the result\nEach technique cell in the Navigator heatmap is colored according to its score — commonly a gradient from red (no coverage) through yellow (unvalidated) to green (validated and confirmed) — giving a single glance view of where the organization's detection program is strong and where it is thin.\n\n### Reading the heatmap correctly\nA heatmap showing \"green\" for a technique means a rule exists and has been tested against the specific samples the team had available — it does not guarantee the rule catches every possible variation of that technique. Heatmaps communicate coverage of known, tested variations, not a mathematical guarantee against the technique as a whole; this distinction matters when reporting coverage to stakeholders who might otherwise read \"green\" as \"fully solved.\"",
        "codeExample": "flowchart LR\n  A[\"0: No rule\"] --> B[\"1: Rule exists,\\nunvalidated\"]\n  B --> C[\"2: Validated against\\ntest corpus, deployed\"]\n  C --> D[\"3: Confirmed via live\\ntelemetry or purple team\"]\n  D -.color.-> E[\"Navigator heatmap:\\nred -> yellow -> green\"]",
        "keyPoints": [
          "A coverage heatmap scores each ATT&CK technique on an ordinal scale from no coverage through validated-and-confirmed.",
          "A rule that only passed sigma check syntax validation is not the same maturity level as one confirmed against real telemetry.",
          "The Navigator typically renders scores as a color gradient (e.g., red to green) for at-a-glance review.",
          "A 'green' cell means the rule was tested against available samples, not that it catches every possible variation of the technique — this nuance matters for stakeholder reporting."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Identifying Coverage Gaps and Prioritizing New Rules",
        "body": "A completed heatmap is only useful if it drives a prioritization decision: which of the remaining red (uncovered) or yellow (unvalidated) cells should the team address next? Not every gap deserves equal urgency.\n\n### Prioritization inputs\n- **Threat relevance** — techniques actively used by threat actors known to target the organization's industry or region carry more urgency than rarely-observed techniques, informed by current threat intelligence reporting.\n- **Blast radius** — a technique that, if successful, grants broad access (for example, credential dumping enabling further lateral movement) generally outranks a technique with narrow, contained impact.\n- **Existing compensating controls** — a technique with no Sigma rule but strong preventive controls already in place (application allowlisting blocking the specific execution path, for instance) may be lower priority than a technique with neither detection nor prevention.\n- **Available telemetry** — a technique gap cannot be closed by writing a rule if the organization has no telemetry source that would ever record the behavior in the first place; closing that gap may require a telemetry investment (the subject of the Telemetry Sources module earlier in this path) before a rule is even possible.\n\n### A related, complementary tool: DeTT&CT\nDeTT&CT is a framework, developed for scoring detection coverage, data source visibility, and threat actor relevance per ATT&CK technique in a more structured way than a simple ordinal heatmap — it is covered in depth in the Purple Team learning path's Detection Validation module, and pairs naturally with the Sigma-tag-driven heatmap built in this lesson.\n\n### Turning gaps into backlog items\nA mature detection engineering practice treats each identified, prioritized gap as a tracked work item — feeding back into the exact \"pick the technique and write the rule\" workflow from the Sigma Selection Patterns lesson, closing the loop between coverage measurement and new rule authorship.",
        "codeExample": "# Simplified gap-prioritization scoring, one row per uncovered technique\ntechnique,threat_relevance(1-5),blast_radius(1-5),telemetry_available\nT1552.001 Credentials In Files,4,3,yes\nT1021.001 RDP Lateral Movement,5,4,yes\nT1611 Escape to Host,2,5,no",
        "keyPoints": [
          "Not every coverage gap deserves equal priority; threat relevance, blast radius, existing compensating controls, and telemetry availability all factor in.",
          "A gap cannot be closed by writing a rule if no telemetry source ever records the underlying behavior — that requires a telemetry investment first.",
          "DeTT&CT is a complementary framework for structured detection and visibility scoring, covered in depth in the Purple Team learning path.",
          "Prioritized gaps should become tracked backlog items, closing the loop back into the rule-authoring workflow."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: From New Rule to Coverage Report",
        "body": "This final page walks through the complete, end-to-end sequence a detection engineer follows, connecting every practice covered in this lesson into one repeatable workflow.\n\n### Step 1 — Author and locally validate\nWrite the rule (using the patterns and modifiers from the previous two lessons), run sigma check for syntax validation, and build or reuse a positive/negative test corpus for the targeted behavior.\n\n### Step 2 — Test locally\nConvert the rule to the production backend and confirm it matches every positive sample while staying silent on every negative sample, iterating on the selection and filters as needed.\n\n### Step 3 — Submit through the CI pipeline\nOpen a pull request; let automated checks re-run syntax validation and corpus testing; have a peer reviewer confirm the logic, metadata, and ATT&CK tags are complete and accurate.\n\n### Step 4 — Merge and deploy\nOn approval, the rule merges into the version-controlled repository and deploys to the production SIEM through the organization's established pipeline.\n\n### Step 5 — Regenerate coverage artifacts\nThe same tags that satisfied peer review now feed automated tooling: a refreshed ATT&CK Navigator layer for visual review, and optionally a sigma2stix conversion for programmatic consumption by other platforms.\n\n### Step 6 — Review the heatmap and identify the next gap\nThe updated heatmap is reviewed against threat relevance, blast radius, compensating controls, and telemetry availability to identify the next-highest-priority gap — feeding directly back into Step 1 for the next rule, closing the loop this lesson has built end-to-end.\n\n### Why the loop matters more than any single rule\nNo individual rule, however well-tested, meaningfully improves an organization's security posture in isolation. It is the repeated, disciplined cycle of author, test, ship, measure, and prioritize that compounds into genuine detection coverage over time — the core discipline this entire Sigma Mastery module has been building toward.",
        "codeExample": "flowchart TD\n  A[\"1. Author + sigma check\"] --> B[\"2. Test against\\npositive/negative corpus\"]\n  B --> C[\"3. PR + CI + peer review\"]\n  C --> D[\"4. Merge + deploy\"]\n  D --> E[\"5. Regenerate heatmap\\n+ STIX export\"]\n  E --> F[\"6. Identify next\\npriority gap\"]\n  F --> A",
        "keyPoints": [
          "The full detection engineering loop is: author, test locally, review via CI, deploy, regenerate coverage artifacts, prioritize the next gap.",
          "Coverage artifacts (Navigator layer, STIX export) are automatically regenerated from the same tags used in peer review, not built separately by hand.",
          "No single rule meaningfully improves security posture alone — the repeated, disciplined cycle is what compounds into real coverage.",
          "This workflow directly closes the loop back to Step 1, making detection engineering a continuous practice rather than a one-time project."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A newly-written Sigma rule passes sigma check with no errors. What does this confirm, and what does it NOT confirm?",
        "options": [
          {
            "label": "It confirms the rule is well-formed Sigma YAML; it does not confirm the rule matches any real telemetry",
            "value": "c"
          },
          {
            "label": "It confirms the rule has been tested against both malicious and benign samples",
            "value": "d"
          },
          {
            "label": "It confirms the rule has been deployed to the production SIEM",
            "value": "a"
          },
          {
            "label": "It confirms the rule has an ATT&CK coverage score of at least 2",
            "value": "b"
          }
        ],
        "answer": "c",
        "explanation": "sigma check only validates structure and specification compliance — required fields, valid YAML, a condition that references real selections. It says nothing about whether the rule matches real data, which requires the separate sample-testing step described in this lesson."
      },
      {
        "question": "A test corpus for a new LSASS-access rule should include which of the following?",
        "options": [
          {
            "label": "Only a captured malicious sample, since that is what the rule is meant to catch",
            "value": "b"
          },
          {
            "label": "Only a benign sample, to prove the rule doesn't fire on legitimate activity",
            "value": "c"
          },
          {
            "label": "Both a malicious sample and a realistic benign sample (such as WerFault.exe accessing lsass.exe)",
            "value": "d"
          },
          {
            "label": "Neither — sigma check alone is sufficient before shipping a rule",
            "value": "a"
          }
        ],
        "answer": "d",
        "explanation": "A proper test corpus needs both positive samples (to confirm the rule actually detects the attack) and negative samples (to confirm it doesn't fire on similar-looking benign activity). Either one alone leaves a blind spot, and sigma check does not test against sample data at all."
      },
      {
        "question": "Why does a CI (continuous integration) pipeline for Sigma rules typically fail a pull request that is missing an ATT&CK tag or a level field?",
        "options": [
          {
            "label": "Because YAML syntax requires these fields to be technically valid",
            "value": "d"
          },
          {
            "label": "Because CI turns authoring best practices into automated, unskippable gates",
            "value": "a"
          },
          {
            "label": "Because pySigma cannot convert a rule that lacks these fields",
            "value": "b"
          },
          {
            "label": "Because the ATT&CK Navigator crashes if a layer file is missing scores",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "These fields are optional as far as raw YAML/Sigma syntax is concerned, but a well-run CI pipeline adds its own checks enforcing them as organizational standards, so quality doesn't depend on an individual engineer remembering under deadline pressure. pySigma conversion and Navigator rendering don't inherently require these fields either."
      },
      {
        "question": "A coverage heatmap shows a technique cell as fully green (validated and confirmed). What is the most accurate interpretation of this result?",
        "options": [
          {
            "label": "The technique is now mathematically impossible for any attacker to execute",
            "value": "a"
          },
          {
            "label": "A tested, confirmed rule exists, but only for known variations — not a guarantee against every variation",
            "value": "b"
          },
          {
            "label": "The technique no longer appears in the current MITRE ATT&CK matrix",
            "value": "c"
          },
          {
            "label": "The SOC no longer needs to monitor alerts for this technique",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Green means validated coverage against known, tested variations — an important but bounded claim, not an absolute guarantee. Misreading it as 'fully solved' or 'no longer needs monitoring' is exactly the stakeholder-communication risk this lesson calls out."
      },
      {
        "question": "A detection engineer is deciding which of five uncovered ATT&CK techniques to address next. Which factor is LEAST relevant to that prioritization decision?",
        "options": [
          {
            "label": "Whether threat intelligence indicates actors targeting the organization's industry actively use the technique",
            "value": "d"
          },
          {
            "label": "How much access or lateral movement the technique would grant an attacker if successful",
            "value": "a"
          },
          {
            "label": "Whether the organization has any telemetry source that would ever record the behavior",
            "value": "b"
          },
          {
            "label": "The alphabetical order of the technique's official MITRE ATT&CK name",
            "value": "c"
          }
        ],
        "answer": "c",
        "explanation": "Alphabetical naming has no bearing on risk or feasibility. Threat relevance, blast radius, and telemetry availability are all legitimate prioritization inputs described in this lesson — a gap can't even be closed with a rule if no telemetry source would ever capture the behavior."
      }
    ]
  },
  "detection-engineer--edr-vs-sysmon": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Two Telemetry Philosophies: Agent-Based EDR vs. Free OS Instrumentation",
        "body": "Every detection a Sigma rule expresses depends on telemetry actually existing somewhere for it to match against. This module of the path steps back from rule syntax to ask a more fundamental question: where does that telemetry actually come from, and how does the choice of telemetry source shape what a detection engineer can and cannot detect?\n\nOn Windows endpoints, two telemetry sources dominate: Sysmon, a free Microsoft Sysinternals tool, and EDR (Endpoint Detection and Response) platforms such as CrowdStrike Falcon or Microsoft Defender for Endpoint. They are not the same thing, and understanding their differences is essential to writing rules that actually work against the telemetry an organization has.\n\n### Sysmon, briefly\nSysmon (System Monitor) is a Windows system service and driver, part of the Sysinternals suite, that logs detailed process, network, file, and registry activity to a dedicated Windows Event Log channel. It is free, requires manual deployment and configuration (an XML file defining what to log and what to filter out), and was the design template for much of Sigma's own field taxonomy, as covered in the Sigma Selection Patterns lesson.\n\n### EDR, briefly\nAn EDR platform combines an endpoint agent with a cloud-based analytics backend. Beyond raw telemetry collection, EDR platforms typically add behavioral detection logic, cross-host correlation, threat intelligence enrichment, and — critically — automated response actions like isolating a compromised host or killing a malicious process, none of which Sysmon alone provides.\n\n### Why a detection engineer needs to understand both\nMany organizations run both simultaneously, and public Sigma rules are frequently authored against Sysmon's field names as a lowest common denominator, then converted to an EDR-specific pipeline for deployment. Knowing what each source captures — and where they diverge — determines whether a given rule will actually fire once it reaches production, and whether relying on just one source leaves a detectable gap.",
        "codeExample": "flowchart TD\n  A[\"Windows endpoint\\nactivity occurs\"] --> B[\"Sysmon driver\\n(free, local, XML-configured)\"]\n  A --> C[\"EDR agent\\n(licensed, cloud-connected)\"]\n  B --> D[\"Windows Event Log:\\nMicrosoft-Windows-Sysmon/Operational\"]\n  C --> E[\"Cloud analytics backend\\n+ automated response actions\"]",
        "keyPoints": [
          "Sysmon is a free, manually-configured Microsoft Sysinternals tool logging detailed local telemetry to a Windows Event Log channel.",
          "EDR (Endpoint Detection and Response) combines an agent with cloud analytics, behavioral detection, correlation, and automated response actions.",
          "Sysmon's field taxonomy was the design template for much of Sigma's own generic field names.",
          "Many organizations run both; understanding what each captures determines whether a rule will actually fire in production."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Sysmon: What It Captures and How",
        "body": "Sysmon logs a defined set of event types, each identified by a numeric Event ID, to the Microsoft-Windows-Sysmon/Operational Windows Event Log channel. Which events actually get logged, and with how much filtering, depends entirely on the deployed XML configuration file — Sysmon out of the box with no configuration logs very little of value.\n\n### Key Sysmon Event IDs a detection engineer relies on\n| Event ID | Name | What it captures |\n|---|---|---|\n| 1 | Process Creation | A new process starts, including full command line, hashes, and parent process |\n| 3 | Network Connection | A process opens an outbound network connection |\n| 6 | Driver Loaded | A kernel driver is loaded |\n| 7 | Image Loaded | A DLL or executable image is loaded into a process |\n| 8 | CreateRemoteThread | A process creates a thread in another process — a classic process-injection indicator |\n| 10 | ProcessAccess | A process opens a handle to another process, with the requested access rights |\n| 11 | FileCreate | A file is created or overwritten |\n| 12/13/14 | RegistryEvent | A registry key or value is created, modified, or deleted |\n| 22 | DNSEvent | A process performs a DNS query |\n\n### Configuration is the deciding factor\nA common, well-regarded community configuration (such as the SwiftOnSecurity or Olaf Hartong Sysmon configs) tunes which paths, processes, and registry keys are included or excluded to balance detection value against log volume — Event ID 11 (FileCreate) and the RegistryEvent IDs, in particular, can generate enormous volumes of noise without careful path filtering.\n\n### Deployment reality\nSysmon must be installed and configured on every endpoint (typically via Group Policy or an equivalent configuration management tool), and its logs need to be forwarded somewhere central — Windows Event Forwarding, a SIEM agent, or an EDR agent's own log-shipping capability — since the local Windows Event Log by itself has limited retention and no central visibility.",
        "codeExample": "<!-- Fragment of a Sysmon XML configuration -->\n<Sysmon schemaversion=\"4.90\">\n  <EventFiltering>\n    <ProcessAccess onmatch=\"include\">\n      <TargetImage condition=\"end with\">\\lsass.exe</TargetImage>\n    </ProcessAccess>\n    <FileCreate onmatch=\"include\">\n      <TargetFilename condition=\"contains\">\\Startup\\</TargetFilename>\n    </FileCreate>\n  </EventFiltering>\n</Sysmon>",
        "keyPoints": [
          "Sysmon logs numbered event types (Event ID 1 process creation, 3 network connection, 10 ProcessAccess, 11 FileCreate, and more) to a dedicated Event Log channel.",
          "Sysmon out of the box with no configuration logs very little of value — the XML configuration file determines what is actually captured.",
          "High-volume event types like FileCreate and RegistryEvent need careful path filtering to avoid overwhelming log storage with noise.",
          "Sysmon logs must be forwarded centrally (Windows Event Forwarding, SIEM agent, or EDR log shipping) since local retention and visibility are limited."
        ]
      },
      {
        "pageNumber": 3,
        "title": "EDR Telemetry: What CrowdStrike Falcon and Microsoft Defender for Endpoint Add",
        "body": "EDR platforms collect telemetry through their own kernel-level sensors, independent of Sysmon, and typically expose that telemetry through a proprietary event taxonomy and a cloud-hosted query interface rather than a local Windows Event Log channel.\n\n### CrowdStrike Falcon\nFalcon's telemetry is organized around an event_simpleName field identifying the event type, including ProcessRollup2 (process creation, roughly analogous to Sysmon Event ID 1), NetworkConnectIP4 (outbound network connections), DnsRequest (DNS queries), and ClassifiedModuleLoad (module/image loads). Events carry an aid (agent ID) identifying the host's Falcon sensor and a cid (customer ID) identifying the tenant, and are queried through CrowdStrike's own query interfaces rather than a Windows Event Log.\n\n### Microsoft Defender for Endpoint (MDE)\nMDE exposes its telemetry as a set of Advanced Hunting tables queried with KQL (Kusto Query Language) through the Microsoft Defender portal or Microsoft Sentinel: DeviceProcessEvents (process creation, with fields like ProcessCommandLine and InitiatingProcessFileName), DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents, and DeviceLogonEvents.\n\n### What EDR platforms add beyond raw events\n- **Cloud correlation** — linking related events across a single host, and often across the whole fleet, to surface multi-stage attack chains rather than isolated events.\n- **Automated response actions** — the ability to isolate a host from the network, kill a process, or quarantine a file directly from the console, not merely observe.\n- **Longer, centralized retention** — telemetry is stored in the vendor's cloud backend rather than relying on local Windows Event Log rotation, with retention windows defined by the licensing tier.\n- **Vendor-curated behavioral detections** — many EDR platforms ship their own built-in detections independent of any Sigma rule an organization writes, based on the vendor's own threat research.\n\n### Why this matters for rule-writing\nA rule targeting DeviceProcessEvents in MDE or a CrowdStrike-specific pipeline will not work unmodified against Sysmon telemetry, and vice versa — the pySigma pipeline for each backend (covered in the Sigma Selection Patterns lesson) is what bridges this gap.",
        "codeExample": "// Example: process creation query against Microsoft Defender for Endpoint\n// Advanced Hunting table, using KQL (Kusto Query Language)\nDeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has \"-EncodedCommand\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
        "keyPoints": [
          "CrowdStrike Falcon organizes telemetry by event_simpleName (ProcessRollup2, NetworkConnectIP4, DnsRequest, ClassifiedModuleLoad) rather than numbered event IDs.",
          "Microsoft Defender for Endpoint exposes telemetry as Advanced Hunting tables (DeviceProcessEvents, DeviceNetworkEvents, and others) queried with KQL.",
          "EDR platforms add cloud correlation, automated response actions (isolate host, kill process), longer centralized retention, and vendor-curated behavioral detections beyond raw telemetry.",
          "A rule written against one platform's field names and tables does not work unmodified against another's — pySigma pipelines bridge this gap."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Event ID Mapping: Sysmon vs EDR Equivalents",
        "body": "Because Sysmon predates most modern EDR taxonomies and became the informal reference point for Sigma's own field names, it is useful to map common Sysmon event types to their rough EDR equivalents when deciding how to author or convert a detection.\n\n### Rough equivalence table\n| Behavior | Sysmon Event ID | CrowdStrike Falcon | Microsoft Defender for Endpoint |\n|---|---|---|---|\n| Process creation | 1 (Process Creation) | ProcessRollup2 | DeviceProcessEvents |\n| Network connection | 3 (Network Connection) | NetworkConnectIP4 | DeviceNetworkEvents |\n| DNS query | 22 (DNSEvent) | DnsRequest | DeviceNetworkEvents (DNS-related fields) |\n| Image/module load | 7 (Image Loaded) | ClassifiedModuleLoad | DeviceImageLoadEvents |\n| File creation | 11 (FileCreate) | (surfaced via detections/telemetry, vendor-specific) | DeviceFileEvents |\n| Registry modification | 12/13/14 (RegistryEvent) | (surfaced via detections/telemetry, vendor-specific) | DeviceRegistryEvents |\n\n### Why \"rough\" equivalence, not exact equivalence\nThese are not perfectly interchangeable one-to-one mappings. A Sysmon ProcessAccess event (Event ID 10) — a process opening a handle to another process, the telemetry behind the LSASS-access detection built in the Sigma Selection Patterns lesson — does not have one universally documented, identically-named raw telemetry event across every EDR platform. Instead, EDR platforms often surface cross-process access behavior through their own behavioral detection logic and alerting, rather than exposing every raw access event the way Sysmon's firehose does. A detection engineer working with a specific EDR platform needs to consult that platform's own documentation to confirm exactly which raw events (if any) are exposed for a given behavior, rather than assuming a Sysmon-style one-to-one match exists.\n\n### Practical implication for rule authoring\nWhen converting a Sysmon-based rule to an EDR backend via a pySigma pipeline, the pipeline maintainer has already done the work of finding the closest available equivalent field or table — but a detection engineer should still verify the converted rule against real EDR telemetry (the testing discipline from the Coverage Testing lesson) rather than assuming the mapping is perfect.",
        "codeExample": "# Same logical rule, different logsource/pipeline per backend\n# Sysmon version\nlogsource:\n    category: process_creation\n    product: windows\n\n# Converted for CrowdStrike Falcon via:\nsigma convert -t crowdstrike -p crowdstrike rules/rule.yml\n\n# Converted for Microsoft Defender for Endpoint via:\nsigma convert -t microsoft365defender -p microsoft365defender rules/rule.yml",
        "keyPoints": [
          "Sysmon's numbered Event IDs have rough, not exact, equivalents in EDR telemetry (ProcessRollup2, DeviceProcessEvents, and similar).",
          "Some Sysmon events (like ProcessAccess, Event ID 10) don't have a universally documented one-to-one raw telemetry equivalent across every EDR platform.",
          "EDR platforms often surface certain behaviors (like cross-process access) through behavioral detections rather than exposing every raw event the way Sysmon does.",
          "A converted rule should always be tested against real EDR telemetry rather than assuming the pySigma pipeline's mapping is perfect for every case."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Coverage Gaps: What Sysmon Misses That EDR Catches",
        "body": "Sysmon is a highly capable telemetry source, but it is fundamentally a logging tool, not a security platform — several categories of capability that EDR platforms provide have no Sysmon equivalent at all.\n\n### No automated response\nSysmon only observes and logs; it cannot isolate a host, kill a process, or quarantine a file. Any response action based on a Sysmon-detected Sigma rule match requires a separate orchestration layer (a SOAR platform, a script, or manual analyst action) to actually act on the detection.\n\n### No cloud correlation or fleet-wide context\nSysmon logs are local to each endpoint (until centrally forwarded and correlated by a SIEM). It has no built-in concept of correlating an event on one host with related activity on another host across the organization the way an EDR platform's cloud backend does natively.\n\n### No built-in threat intelligence enrichment\nSysmon logs a file's hash if configured to do so, but it has no built-in reputation service to tell an analyst whether that hash is known-malicious — that enrichment has to come from an external source (a threat intelligence feed queried separately, or the SIEM's own enrichment pipeline).\n\n### No memory scanning or fileless-threat detection\nSysmon's visibility is limited to the specific events it is configured to log (process, network, file, registry, and a handful of others); it does not perform active memory scanning for injected code or fileless malware the way many EDR platforms' behavioral engines do.\n\n### Manual, decentralized configuration and deployment burden\nSysmon requires manual configuration management (typically via Group Policy) across every endpoint, with no centralized management console — configuration drift between hosts is a real operational risk that a centrally-managed EDR agent largely avoids.\n\n### The practical takeaway\nNone of this means Sysmon is a poor choice — it means Sysmon on its own is a telemetry source, not a complete detection and response capability, and organizations relying on Sysmon alone need to build the correlation, enrichment, and response layers themselves (typically in a SIEM and a SOAR) rather than getting them built-in the way an EDR platform provides.",
        "codeExample": "flowchart LR\n  A[\"Sysmon: logs events\"] -->|no built-in response| B[\"Requires external\\nSOAR/script/analyst\\nto act on a match\"]\n  A -->|no cloud correlation| C[\"Requires SIEM to\\ncorrelate across hosts\"]\n  A -->|no threat intel| D[\"Requires external\\nhash reputation feed\"]",
        "keyPoints": [
          "Sysmon only logs; it has no automated response capability (host isolation, process kill, file quarantine) built in.",
          "Sysmon logs are local per-host by default; fleet-wide correlation must be built separately in a SIEM.",
          "Sysmon has no built-in threat intelligence enrichment (hash reputation) — that requires an external feed.",
          "Sysmon requires manual, decentralized configuration management, creating configuration-drift risk that centrally-managed EDR agents largely avoid."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Coverage Gaps: What EDR Might Miss That Sysmon Catches",
        "body": "The relationship is not one-directional — there are real scenarios where Sysmon's raw, fully analyst-visible telemetry provides value an EDR deployment alone does not.\n\n### Full raw visibility and configurability\nSysmon's ruleset is entirely under the analyst's own control — every field, every filter, every included or excluded path is visible and editable in the XML configuration. An EDR agent's internal detection logic and exactly which raw events it retains, at what fidelity, and for how long, depend on the vendor's own design and the organization's specific licensing tier — some tiers limit raw telemetry retention or query access, prioritizing curated detections and alerts over full raw-event hunting capability.\n\n### Registry telemetry depth\nSysmon's RegistryEvent IDs (12, 13, 14) can be configured to capture granular, value-level registry changes with fully custom path filters defined by the analyst. Some EDR agents summarize or heavily throttle registry telemetry specifically because of its volume, forwarding only registry changes tied to a triggered detection rather than the full raw stream — which can leave a gap for deep forensic work or proactive threat hunting that needs to see registry activity that never triggered any existing detection.\n\n### Cost and licensing independence\nSysmon is free and requires no per-endpoint licensing, meaning it can be deployed even on hosts where full EDR licensing is not available or not yet rolled out (for example, during an EDR migration, on legacy systems, or on budget-constrained environments) — providing at least a baseline telemetry source rather than no visibility at all.\n\n### A common defense-in-depth pattern\nBecause of these complementary strengths, many mature security programs deploy Sysmon alongside a licensed EDR agent rather than treating them as mutually exclusive choices — Sysmon providing a fully open, analyst-controlled telemetry stream for deep hunting and hand-written Sigma rules, while the EDR agent provides response capability, cloud correlation, and vendor threat intelligence.\n\n### Why public Sigma rules default to Sysmon field names\nThis is also why SigmaHQ's public rule repository, and much of the Sigma ecosystem generally, defaults to Sysmon's field taxonomy — it represents the lowest common denominator that any organization, regardless of which EDR vendor (or no EDR at all) they use, can potentially deploy and convert against via the appropriate pySigma pipeline.",
        "codeExample": "flowchart TD\n  A[\"Deploy Sysmon\\n(free, fully configurable)\"] --> C[\"Combined defense-in-depth\\ntelemetry\"]\n  B[\"Deploy licensed EDR\\n(response + correlation + intel)\"] --> C\n  C --> D[\"Sigma rules authored against\\nSysmon taxonomy, converted via\\npySigma pipeline to either source\"]",
        "keyPoints": [
          "Sysmon gives an analyst full, self-configured raw visibility; EDR telemetry retention and query access depend on vendor design and licensing tier.",
          "Some EDR agents throttle or summarize high-volume registry telemetry, forwarding only detection-tied changes rather than the full raw stream Sysmon can provide.",
          "Sysmon's zero licensing cost lets it provide baseline visibility on hosts where full EDR coverage isn't yet available.",
          "Many mature programs deploy both together (defense in depth), which is also why public Sigma rules default to Sysmon's field taxonomy as a common baseline."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Detection Implications: Writing Rules That Work Across Both",
        "body": "The practical goal for a detection engineer is not choosing Sysmon or EDR, but writing rules that reliably work regardless of which telemetry source (or both) an organization actually has deployed — and this connects directly back to the pySigma pipeline concept from the Sigma Selection Patterns lesson.\n\n### Write against the generic taxonomy, not a specific backend\nA Sigma rule's logsource block should specify category: process_creation, product: windows — the generic, backend-agnostic description — rather than hard-coding assumptions about Sysmon or a specific EDR platform's exact field names. The appropriate pySigma pipeline (sysmon, crowdstrike, microsoft365defender, and others) handles the translation to whichever backend is actually deployed.\n\n### Recognize where the abstraction breaks down\nAs the previous two pages established, not every Sysmon event has a clean EDR equivalent (and vice versa). When a detection genuinely depends on telemetry only one source provides — deep registry value tracking only available through a well-configured Sysmon deployment, for instance — the rule's logsource and field choices should reflect that reality rather than pretending a universal, backend-agnostic version exists. In these cases, documenting the dependency explicitly (in the rule's description field) helps whoever maintains the rule later understand why it only works against one specific telemetry source.\n\n### Testing across every deployed backend\nAn organization running both Sysmon and an EDR platform should test a given rule's conversion against both backends' actual data, not just one — the Coverage Testing lesson's local-testing discipline applies per backend, since a rule that matches perfectly against Sysmon-sourced data might behave differently once converted and run against EDR-sourced data, due to subtle field-mapping differences.\n\n### The organizational decision this feeds into\nUltimately, whether to deploy Sysmon, EDR, or both is a resourcing and coverage decision made above the level of any single rule — but understanding exactly what each source captures, as covered across this lesson, is what allows a detection engineer to give an accurate, technically grounded recommendation when that decision is being made.",
        "codeExample": "title: Suspicious LSASS Access\nlogsource:\n    category: process_access\n    product: windows\n# Backend-agnostic — the pipeline decides Sysmon vs CrowdStrike vs MDE\ndetection:\n    selection:\n        TargetImage|endswith: '\\\\lsass.exe'\n        GrantedAccess: '0x1FFFFF'\n    condition: selection",
        "keyPoints": [
          "Writing against Sigma's generic taxonomy (not a specific backend's exact fields) lets the same rule convert to whichever telemetry source is deployed.",
          "When a detection genuinely depends on one source's unique capability, that dependency should be documented explicitly in the rule rather than assumed to be universal.",
          "A rule should be tested against every backend an organization actually has deployed, not just one, since field-mapping differences can change real-world behavior.",
          "Choosing Sysmon, EDR, or both is an organizational resourcing decision informed by, but distinct from, individual rule-writing choices."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: Choosing (or Combining) Telemetry Sources",
        "body": "This final page brings the lesson's material together into a practical decision framework a detection engineer can apply when assessing an organization's telemetry posture, or when advising on a new deployment.\n\n### Step 1 — Inventory what is actually deployed\nBefore writing or converting any rule, confirm what telemetry sources genuinely exist across the environment: is EDR licensed and deployed fleet-wide, is Sysmon deployed anywhere, and are there gaps (unmanaged devices, legacy systems) with neither?\n\n### Step 2 — Map required telemetry to available sources\nFor each detection need (informed by the ATT&CK coverage gaps identified in the Coverage Testing lesson), confirm which available source(s) actually capture the needed behavior, using the equivalence table and caveats from this lesson.\n\n### Step 3 — Decide: EDR only, Sysmon only, or both\n- **EDR only** is reasonable where budget supports full licensing fleet-wide and deep raw-telemetry hunting is a lower priority than response capability and vendor-curated detections.\n- **Sysmon only** fits budget-constrained environments or legacy systems where EDR licensing isn't available, accepting the lack of automated response as a tradeoff.\n- **Both together** is the strongest posture where resourcing allows: EDR for response and correlation, Sysmon for full raw visibility and deep hunting — the defense-in-depth pattern discussed earlier in this lesson.\n\n### Step 4 — Author or convert rules against the chosen source(s)\nUsing the generic Sigma taxonomy and the appropriate pySigma pipeline(s), as covered on the previous page, so the rule set remains portable if the telemetry strategy changes later.\n\n### Step 5 — Document known gaps\nAny technique that cannot be detected with the current telemetry mix (because neither deployed source captures the needed behavior) should be explicitly logged as a documented gap — feeding into the coverage-gap prioritization process from the Coverage Testing lesson, and potentially justifying a future telemetry investment.\n\n### Why this workflow matters beyond any single rule\nA detection engineer who understands telemetry sources at this level can answer the question \"why don't we have a rule for X\" with a precise, technical answer — no telemetry captures it yet — rather than an unexplained coverage gap, which is a far more credible and actionable position when justifying security investment to leadership.",
        "codeExample": "flowchart TD\n  A[\"Inventory deployed\\ntelemetry sources\"] --> B[\"Map detection needs\\nto available sources\"]\n  B --> C{\"EDR only,\\nSysmon only,\\nor both?\"}\n  C --> D[\"Author/convert rules\\nvia pySigma pipeline\"]\n  D --> E[\"Document gaps where\\nno source captures\\nthe needed behavior\"]\n  E --> F[\"Feed into coverage-gap\\nprioritization\"]",
        "keyPoints": [
          "The first step in any telemetry decision is inventorying what is genuinely deployed across the environment, including gaps.",
          "EDR-only, Sysmon-only, and both-together are all valid strategies depending on budget, response needs, and hunting priorities.",
          "Rules should be authored against Sigma's generic taxonomy so the rule set stays portable if the telemetry strategy changes later.",
          "Documenting a technique gap as 'no available telemetry captures this' is a precise, actionable finding that supports future investment decisions."
        ]
      }
    ],
    "quiz": [
      {
        "question": "An organization has deployed Sysmon on all endpoints but has no EDR licensed. A detection relies on isolating a compromised host automatically the moment a rule fires. What is the correct assessment of this requirement?",
        "options": [
          {
            "label": "Sysmon can isolate a host directly through its XML configuration",
            "value": "c"
          },
          {
            "label": "Sysmon only logs; isolation needs a separate layer (SOAR, script, or EDR) since it has no response capability",
            "value": "d"
          },
          {
            "label": "This is only possible if Sysmon Event ID 1 is enabled",
            "value": "a"
          },
          {
            "label": "Sysmon automatically isolates any host where a critical-severity Sigma rule matches",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "Sysmon is purely a logging tool with no built-in response actions. Any automated response based on a Sysmon-sourced detection requires a separate layer such as a SOAR platform or custom scripting — Sysmon's configuration file only controls what is logged, not what actions are taken."
      },
      {
        "question": "A detection engineer wants to detect process creation events and needs to pick the CrowdStrike Falcon field/event equivalent to Sysmon's Event ID 1. Which is correct?",
        "options": [
          {
            "label": "NetworkConnectIP4",
            "value": "c"
          },
          {
            "label": "DnsRequest",
            "value": "d"
          },
          {
            "label": "ProcessRollup2",
            "value": "a"
          },
          {
            "label": "ClassifiedModuleLoad",
            "value": "b"
          }
        ],
        "answer": "a",
        "explanation": "ProcessRollup2 is CrowdStrike Falcon's process creation event, the rough equivalent of Sysmon Event ID 1. NetworkConnectIP4 covers network connections, DnsRequest covers DNS queries, and ClassifiedModuleLoad covers module/image loads — each a different behavior category."
      },
      {
        "question": "A Sigma rule targets Sysmon Event ID 10 (ProcessAccess) to detect LSASS memory access. The organization wants to convert this rule for a CrowdStrike Falcon deployment. What does this lesson say about that conversion?",
        "options": [
          {
            "label": "It converts perfectly, since every Sysmon event has an exact CrowdStrike equivalent",
            "value": "a"
          },
          {
            "label": "ProcessAccess has no documented one-to-one EDR equivalent; it's usually surfaced via behavioral detections instead",
            "value": "b"
          },
          {
            "label": "CrowdStrike Falcon cannot detect credential dumping under any circumstances",
            "value": "c"
          },
          {
            "label": "The conversion requires disabling Sysmon entirely first",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson specifically calls out ProcessAccess as an example where Sysmon's raw telemetry does not have a clean, universally documented EDR equivalent — EDR platforms often handle this behavior through their own behavioral detection logic instead of exposing an identical raw event, so the converted rule needs to be verified against real EDR telemetry."
      },
      {
        "question": "Which capability does an EDR platform typically provide that Sysmon, on its own, does not?",
        "options": [
          {
            "label": "Logging process creation events with command-line arguments",
            "value": "b"
          },
          {
            "label": "Automated response actions such as isolating a host or killing a malicious process",
            "value": "c"
          },
          {
            "label": "Recording file creation events",
            "value": "d"
          },
          {
            "label": "Being configurable via an XML file",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "Sysmon logs process creation (including command lines) and file creation events, and is itself configured via XML — but it has no built-in response capability. Automated actions like host isolation or process termination are a defining EDR feature Sysmon does not provide on its own."
      },
      {
        "question": "Why do many mature security programs deploy Sysmon alongside a licensed EDR agent rather than choosing only one?",
        "options": [
          {
            "label": "Because Sysmon and EDR cannot both run on the same endpoint, so this is a myth",
            "value": "b"
          },
          {
            "label": "Because EDR always fully replaces Sysmon's functionality, making the pairing redundant",
            "value": "c"
          },
          {
            "label": "Because they are complementary: EDR adds response and correlation, Sysmon adds full raw visibility EDR may throttle",
            "value": "d"
          },
          {
            "label": "Because regulatory compliance always mandates running both simultaneously",
            "value": "a"
          }
        ],
        "answer": "d",
        "explanation": "The lesson describes this as a genuine defense-in-depth pattern based on complementary strengths, not redundancy or a technical limitation preventing them from coexisting, and not a universal regulatory mandate. Sysmon and EDR agents can and often do run on the same endpoint simultaneously."
      }
    ]
  },
  "detection-engineer--o365-ual": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What the Unified Audit Log Is and Why It Matters",
        "body": "Office 365 (now more broadly branded Microsoft 365) is where most modern organizations store email, files, and collaboration data — making it one of the highest-value targets for account compromise and data exfiltration. The Unified Audit Log (UAL) is Microsoft's central audit trail recording activity across this entire ecosystem: Exchange Online (email), SharePoint Online, OneDrive, Microsoft Teams, and Microsoft Entra ID (formerly Azure Active Directory, the identity platform underlying all of it).\n\n### Why \"unified\"\nBefore the UAL existed in its current form, each service kept its own separate audit trail. The UAL consolidates activity from all of these services into a single, centrally searchable log — critical for a detection engineer, since a real intrusion (a business email compromise, for example) typically touches several of these services in sequence: a sign-in, a mailbox rule creation, a file download, all within the same incident.\n\n### How the UAL is accessed\n- **Microsoft Purview compliance portal** — a web-based interface for interactive searching, available to administrators with appropriate permissions.\n- **Search-UnifiedAuditLog PowerShell cmdlet** — the scriptable interface, commonly used for bulk investigation and export during incident response.\n- **SIEM ingestion** — most commonly, the UAL is continuously ingested into a SIEM (via Microsoft Sentinel's OfficeActivity table, or a generic Office 365 connector for other SIEMs) so it can be correlated with other telemetry and matched against detection rules in near real time.\n\n### What this lesson covers\nThis lesson focuses on the fields and specific Operations most relevant to detection engineering — the ones that repeatedly show up in real business email compromise and data exfiltration investigations — rather than attempting to catalog the UAL's full breadth, which spans dozens of Microsoft services.",
        "codeExample": "flowchart LR\n  A[\"Exchange Online\"] --> D[\"Unified Audit Log\"]\n  B[\"SharePoint / OneDrive\"] --> D\n  C[\"Microsoft Entra ID\"] --> D\n  D --> E[\"Purview portal /\\nSearch-UnifiedAuditLog\"]\n  D --> F[\"SIEM ingestion\\n(e.g. Sentinel OfficeActivity)\"]",
        "keyPoints": [
          "The Unified Audit Log (UAL) consolidates activity from Exchange Online, SharePoint, OneDrive, Teams, and Microsoft Entra ID into one searchable audit trail.",
          "Microsoft Entra ID is the current name for what was previously called Azure Active Directory, the identity platform underlying Microsoft 365.",
          "The UAL can be accessed via the Purview compliance portal, the Search-UnifiedAuditLog PowerShell cmdlet, or continuous SIEM ingestion.",
          "Real intrusions typically span several Microsoft 365 services in sequence, which is exactly why a unified, cross-service log matters for detection."
        ]
      },
      {
        "pageNumber": 2,
        "title": "UAL Record Schema: RecordType, Operation, Workload, UserId",
        "body": "Every UAL entry is a structured record with a consistent set of core fields, regardless of which Microsoft 365 service generated it — understanding these fields is the foundation for writing any detection against UAL data.\n\n### Core fields\n- **RecordType** — identifies the broad category of the event (for example, SharePointFileOperation, ExchangeItem, AzureActiveDirectory, or ExchangeAdmin), useful for filtering the log down to a relevant service before drilling into specifics.\n- **Operation** — the specific action that occurred, such as FileDownloaded, MailboxLogin, or New-InboxRule. This is usually the single most important field for detection logic, since it directly names the behavior.\n- **Workload** — identifies which Microsoft 365 service the record belongs to (Exchange, SharePoint, OneDrive, AzureActiveDirectory, and others).\n- **UserId** — the user principal name (UPN, typically the user's email-formatted sign-in identity) who performed or was associated with the action.\n- **ClientIP** — the source IP address the action was performed from, essential for identifying anomalous locations or known-malicious infrastructure.\n- **CreationTime** — the UTC timestamp of the event.\n- **ObjectId** — identifies the specific object acted upon (a file's URL for a SharePoint operation, a mailbox identifier for an Exchange operation).\n\n### Reading a record end to end\nA single UAL record answers: who (UserId), did what (Operation), to what (ObjectId), in which service (Workload), from where (ClientIP), and when (CreationTime) — the same who/what/where/when structure that underlies most log-based detection regardless of source, but expressed through Microsoft 365's specific field names.\n\n### Why Operation is the anchor field for most Sigma-style detections\nBecause Operation names the specific action directly, most UAL-based detections are built around a selection matching one or a small set of Operation values (the pages that follow work through three of the most detection-relevant ones), further narrowed by other fields like ClientIP, Workload, or record-specific parameters carried in the event.",
        "codeExample": "// Simplified structure of a Unified Audit Log record\n{\n  \"RecordType\": \"SharePointFileOperation\",\n  \"Operation\": \"FileDownloaded\",\n  \"Workload\": \"SharePoint\",\n  \"UserId\": \"j.doe@nexacorp.example\",\n  \"ClientIP\": \"203.0.113.42\",\n  \"CreationTime\": \"2026-02-10T14:32:07\",\n  \"ObjectId\": \"https://nexacorp.sharepoint.com/sites/finance/Q4_Forecast.xlsx\"\n}",
        "keyPoints": [
          "Every UAL record shares core fields: RecordType, Operation, Workload, UserId, ClientIP, CreationTime, and ObjectId.",
          "Operation names the specific action taken and is usually the anchor field for building a detection.",
          "UserId carries the user principal name (UPN), the email-formatted sign-in identity of the associated user.",
          "A UAL record answers who, what, to what, in which service, from where, and when — using Microsoft 365-specific field names."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Detecting Data Exfiltration: FileDownloaded and Related SharePoint/OneDrive Operations",
        "body": "SharePoint Online and OneDrive store the majority of an organization's working files, making file-download activity a primary signal for data exfiltration — whether by a compromised account, a malicious OAuth application, or an insider.\n\n### The FileDownloaded operation\nLogged whenever a user (or an application acting on a user's behalf) downloads a file from SharePoint or OneDrive. The record's ObjectId carries the file's URL, letting an investigator identify exactly what was accessed, and ClientIP identifies where the download originated from.\n\n### Related operations worth correlating\n- **FileAccessed** — a file was opened or viewed without necessarily being downloaded, a weaker but still relevant signal.\n- **FileSyncDownloadedFull** — a full file download via the OneDrive sync client, distinct from a browser-based download, and often used for bulk local replication of a document library.\n- **FileDownloadedExtended** — an extended-metadata version of FileDownloaded recorded for certain configurations, carrying additional detail about the download context.\n\n### Building a detection signal\nA single FileDownloaded event is normal, everyday activity. The detection-worthy pattern is usually a volume or scope anomaly: an unusually high count of FileDownloaded events by a single UserId within a short window (a mass-download pattern consistent with staging for exfiltration), especially when combined with a ClientIP that is new or geographically inconsistent with the user's typical sign-in locations (an indicator sometimes called impossible travel when correlated with sign-in telemetry).\n\n### A worked KQL example\nQuerying the OfficeActivity table in Microsoft Sentinel for a user exceeding a download-count threshold within a rolling window is a common first-pass detection for this pattern, typically refined afterward with peer-group baselining (comparing a user's download volume against their own historical baseline or their department's typical behavior) to reduce false positives from legitimately heavy file users.",
        "codeExample": "// KQL: flag users exceeding 50 SharePoint/OneDrive file downloads in one hour\nOfficeActivity\n| where Operation == \"FileDownloaded\"\n| summarize DownloadCount = count(), DistinctFiles = dcount(OfficeObjectId) by UserId, bin(TimeGenerated, 1h)\n| where DownloadCount > 50\n| project TimeGenerated, UserId, DownloadCount, DistinctFiles",
        "keyPoints": [
          "FileDownloaded is the primary UAL operation for detecting file exfiltration from SharePoint and OneDrive.",
          "Related operations (FileAccessed, FileSyncDownloadedFull) provide additional, weaker or differently-scoped signals worth correlating.",
          "A single download is normal; the detection-worthy pattern is usually an unusual volume or an anomalous source location.",
          "Peer-group or historical baselining reduces false positives from users whose job legitimately involves heavy file access."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Detecting Mailbox Access Abuse: MailboxLogin and Related Operations",
        "body": "Business Email Compromise (BEC) — where an attacker gains access to a legitimate mailbox, often to conduct fraud or reconnaissance — is one of the most common and costly attack patterns targeting Microsoft 365 environments, and mailbox audit logging is the primary UAL data source for detecting it.\n\n### MailboxLogin\nRecorded when a mailbox is accessed, including by a delegate, an administrator, or — most relevant for detection — anyone other than the mailbox owner through a mechanism other than a normal interactive sign-in (for example, via Exchange Web Services or a mail client authenticating with stored credentials). Since 2019, mailbox audit logging (the underlying feature that produces these records) has been enabled by default for Exchange Online mailboxes, removing what used to be a common visibility gap.\n\n### Why MailboxLogin matters for BEC detection\nA MailboxLogin event from an unfamiliar ClientIP, combined with sign-in telemetry from Microsoft Entra ID showing a suspicious or impossible-travel sign-in shortly before it, is a strong composite indicator of account takeover — correlating UAL mailbox activity with Entra ID sign-in logs (covered in more depth in the IAM/identity content elsewhere in this platform) produces much higher-confidence detections than either signal alone.\n\n### Related operations to correlate\n- **Send** and **SendAs** — messages sent from the mailbox, useful for detecting an attacker actually using compromised access to send phishing or fraud emails to other targets.\n- **Add-MailboxPermission** — a permission change granting another account delegate access to the mailbox, sometimes used by an attacker to maintain access to a mailbox even after the original compromised credential is reset.\n\n### The bigger picture\nMailboxLogin alone rarely proves compromise — most mailbox access is entirely legitimate. The detection value comes from correlating it with the account's normal behavioral baseline (typical access times, typical source locations) and with sign-in telemetry, the same \"combine multiple weak signals\" principle covered for Sigma rule selections earlier in this path, just applied to cloud identity and mailbox data instead of endpoint telemetry.",
        "codeExample": "// KQL: MailboxLogin from a ClientIP outside the user's usual country,\n// joined against a simplified per-user baseline table\nOfficeActivity\n| where Operation == \"MailboxLogin\"\n| extend Country = tostring(parse_json(tostring(ExtendedProperties))[0].Value)\n| join kind=leftouter (UserBaselineCountries) on UserId\n| where Country != BaselineCountry\n| project TimeGenerated, UserId, ClientIP, Country, BaselineCountry",
        "keyPoints": [
          "MailboxLogin records mailbox access, including by delegates, admins, or non-owner access paths — key telemetry for detecting Business Email Compromise (BEC).",
          "Mailbox audit logging has been enabled by default for Exchange Online since 2019, closing a formerly common visibility gap.",
          "Correlating MailboxLogin with Microsoft Entra ID sign-in telemetry (for impossible travel or risky sign-ins) produces much higher-confidence detections than either signal alone.",
          "Add-MailboxPermission changes can indicate an attacker establishing persistent delegate access even after the original credential is reset."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Detecting Persistence via Inbox Rules: New-InboxRule and Its Relatives",
        "body": "Once an attacker has mailbox access, a common next step is establishing persistence and covering their tracks — and the single most common mechanism for this in Microsoft 365 environments is a malicious inbox rule, corresponding to MITRE ATT&CK technique T1114.003 (Email Collection: Email Forwarding Rule).\n\n### The operations to watch\n- **New-InboxRule** — a new inbox rule is created, most commonly via Outlook on the web or the Exchange Online PowerShell New-InboxRule cmdlet.\n- **Set-InboxRule** — an existing inbox rule is modified.\n- **UpdateInboxRules** — a broader update operation covering inbox rule changes made through certain client paths.\n\n### Why inbox rules are attractive to attackers\nA rule can silently forward copies of incoming mail to an external address, delete or hide the forwarded messages from the mailbox owner's view, or move messages matching certain criteria (such as replies to a fraudulent wire-transfer email) into an obscure folder the owner never checks — allowing the attacker to monitor or intercept communication even after the original compromised credential is reset, as long as the rule itself remains in place.\n\n### Reading the Parameters field\nBoth New-InboxRule and Set-InboxRule events carry a Parameters property listing the specific settings applied. The parameters most relevant to detection include ForwardTo, ForwardAsAttachmentTo, and RedirectTo (all indicating mail forwarding to another address), alongside DeleteMessage and MoveToFolder (both indicating an attempt to hide the rule's activity from the mailbox owner).\n\n### Building the detection\nA Sigma rule (or equivalent KQL detection) for this pattern targets the New-InboxRule and Set-InboxRule operations, then inspects the Parameters field for the presence of any forwarding-related parameter — particularly when the forwarding destination is an external domain rather than an internal one, which is a much stronger indicator than an internal forward (a legitimate and common practice, for instance when an employee is out of office).",
        "codeExample": "title: Suspicious Inbox Rule with External Forwarding\nid: 9c2d4e6f-1a3b-4c5d-8e7f-2a4b6c8d0e1f\nstatus: stable\ndescription: Detects a new or modified inbox rule that forwards mail to an external address\nlogsource:\n    product: m365\n    service: exchange\ndetection:\n    selection_op:\n        Operation:\n            - 'New-InboxRule'\n            - 'Set-InboxRule'\n    selection_forward:\n        Parameters|contains:\n            - 'ForwardTo'\n            - 'ForwardAsAttachmentTo'\n            - 'RedirectTo'\n    condition: selection_op and selection_forward\ntags:\n    - attack.collection\n    - attack.t1114.003\nlevel: high",
        "keyPoints": [
          "New-InboxRule, Set-InboxRule, and UpdateInboxRules are the key operations for detecting persistence via mailbox forwarding rules.",
          "This behavior maps to MITRE ATT&CK T1114.003, Email Collection: Email Forwarding Rule.",
          "The Parameters field carries the rule's actual settings — ForwardTo, ForwardAsAttachmentTo, and RedirectTo indicate forwarding; DeleteMessage and MoveToFolder indicate an attempt to hide the activity.",
          "Forwarding to an external domain is a much stronger indicator than internal forwarding, which is common and often entirely legitimate."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Retention Tiers: Audit (Standard) vs Audit (Premium)",
        "body": "A detection or investigation is only as good as the data still available to query — and Microsoft 365's UAL retention period depends entirely on which audit licensing tier an organization has, a detail that directly shapes how far back a detection engineer or incident responder can look.\n\n### Audit (Standard)\nThe default tier included with most Microsoft 365 subscriptions. As of October 17, 2023, Microsoft changed the default retention for Audit (Standard) records from 90 days to 180 days — meaning organizations on this tier can search roughly six months back, but no further, for records generated after that date.\n\n### Audit (Premium)\nAn add-on tier providing longer and more flexible retention. By default, Audit (Premium) retains Exchange Online, SharePoint Online, OneDrive, and Microsoft Entra ID audit records for one year, while records for other activities default to 180 days. Organizations can also configure custom audit log retention policies under Audit (Premium) to retain specific record types for longer — up to ten years with the appropriate add-on license — which matters significantly for investigations into long-dwell-time intrusions or for meeting extended regulatory retention requirements.\n\n### Why this matters for detection engineering, not just investigation\nRetention affects two distinct things: how far back an incident responder can investigate once an alert fires, and how much historical data is available to build the behavioral baselines referenced in earlier pages of this lesson (a \"typical download volume\" baseline is only as reliable as the historical window used to compute it). A detection engineer designing a baseline-driven detection needs to know the organization's actual retention tier before assuming a 90-day or one-year lookback window is available.\n\n### A practical takeaway\nBefore designing any UAL-based detection that depends on historical comparison, confirm the organization's specific Audit tier and any custom retention policies in place — assuming Premium-level retention when only Standard is licensed will produce a detection design that silently fails to have the historical data it expects.",
        "codeExample": "// Conceptual comparison, not a query\n// Audit (Standard): 180 days default (since Oct 17, 2023)\n// Audit (Premium):   1 year default for Exchange/SharePoint/OneDrive/Entra ID,\n//                     180 days default for other activities,\n//                     up to 10 years with custom retention policies + add-on license",
        "keyPoints": [
          "Audit (Standard) retains UAL records for 180 days by default, since a policy change effective October 17, 2023 (previously 90 days).",
          "Audit (Premium) retains Exchange/SharePoint/OneDrive/Entra ID records for one year by default, with custom policies extending retention up to ten years with the right add-on license.",
          "Retention affects both incident investigation lookback and the reliability of any historical baseline a detection depends on.",
          "A detection engineer must confirm the organization's actual audit licensing tier before assuming a specific retention window is available."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Building a Detection Against UAL Data",
        "body": "With the core fields, key operations, and retention model covered, this page consolidates the practical mechanics of turning UAL data into a working detection, whether expressed as a Sigma rule or a native KQL query.\n\n### Where UAL data lands in a SIEM\nIn Microsoft Sentinel, UAL data ingested through the Office 365 connector lands in the OfficeActivity table, queryable with KQL. Other SIEMs typically ingest the same underlying UAL data through a generic Office 365 or Microsoft Graph connector, landing in a vendor-specific index or sourcetype.\n\n### Sigma's logsource for Microsoft 365\nSigmaHQ represents Microsoft 365 audit detections using logsource product: m365, with a service field identifying the specific workload — service: exchange for mailbox-related operations like the inbox rule detection built in an earlier page, or service: threat_management for certain higher-level Microsoft 365 Defender and Cloud App Security alert types. The appropriate pySigma pipeline for the organization's SIEM then handles translating this into the concrete OfficeActivity table (or equivalent) and field names.\n\n### Combining multiple UAL signals in one detection\nThe strongest UAL-based detections rarely rely on a single Operation value in isolation — a composite detection correlating a MailboxLogin from an unfamiliar location with a subsequent New-InboxRule creating external forwarding, both from the same UserId within a short time window, is a substantially higher-confidence BEC indicator than either signal alone, mirroring the same principle from the Sigma modifiers lesson where combining independent weak signals produces a stronger rule than any single field.\n\n### Validating a UAL-based detection\nThe same testing discipline from the Coverage Testing lesson applies here: a UAL detection should be validated against both a genuine test case (a controlled, authorized test of the behavior in a lab tenant, where feasible) and known-benign UAL activity (an employee's legitimate out-of-office forwarding rule, for instance) before being trusted in production.",
        "codeExample": "// KQL: composite BEC detection correlating unusual MailboxLogin\n// with a subsequent external-forwarding inbox rule, same user, within 1 hour\nlet SuspiciousLogins = OfficeActivity\n    | where Operation == \"MailboxLogin\"\n    | where ClientIP !in (KnownGoodIPs);\nlet ForwardingRules = OfficeActivity\n    | where Operation in (\"New-InboxRule\", \"Set-InboxRule\")\n    | where Parameters has_any (\"ForwardTo\", \"RedirectTo\");\nSuspiciousLogins\n| join kind=inner (ForwardingRules) on UserId\n| where (TimeGenerated1 - TimeGenerated) between (0min .. 60min)\n| project UserId, TimeGenerated, ClientIP, TimeGenerated1, Parameters",
        "keyPoints": [
          "Microsoft Sentinel ingests UAL data into the OfficeActivity table; other SIEMs ingest the same UAL data through their own Office 365 connectors.",
          "Sigma represents Microsoft 365 audit detections with logsource product: m365 and a service field (exchange, threat_management, and others) identifying the workload.",
          "The strongest UAL detections correlate multiple signals (an unusual login plus a subsequent forwarding rule change) rather than relying on one Operation value alone.",
          "UAL-based detections need the same test-before-ship discipline as endpoint Sigma rules: validated against both real test cases and known-benign activity."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: Investigating a Suspected BEC Case",
        "body": "This final page walks through how the fields and operations covered in this lesson come together during an actual Business Email Compromise investigation, from initial alert to conclusion.\n\n### Step 1 — The triggering alert\nAn alert fires on the composite MailboxLogin-plus-forwarding-rule pattern built on the previous page: UserId j.doe@nexacorp.example logged into their mailbox from an unfamiliar ClientIP, followed within minutes by a New-InboxRule event forwarding mail to an external address.\n\n### Step 2 — Pull the full UAL history for the account\nUsing Search-UnifiedAuditLog or the equivalent SIEM query, an investigator pulls every UAL record for that UserId across a window bracketing the alert — checking for related Send or SendAs events (was the compromised access used to send fraudulent emails to other targets), additional Add-MailboxPermission changes (did the attacker grant themselves further persistent access), and any FileDownloaded activity (was the mailbox compromise paired with document exfiltration).\n\n### Step 3 — Correlate with sign-in telemetry\nCross-referencing the ClientIP and timestamp against Microsoft Entra ID sign-in logs confirms whether the access was flagged as risky or anomalous by Microsoft's own identity risk scoring, and whether multi-factor authentication (MFA) was bypassed, satisfied, or not required for that sign-in.\n\n### Step 4 — Scope the blast radius\nIf SendAs activity is found, every recipient of those messages becomes a potential secondary target requiring their own notification and investigation — a business email compromise rarely stays contained to a single mailbox once the attacker starts sending from it.\n\n### Step 5 — Contain and remediate\nRemediation typically includes resetting the compromised credential, revoking active sessions and OAuth tokens, removing the malicious inbox rule (which persists independently of the credential reset, as covered earlier in this lesson), and reviewing Add-MailboxPermission changes for any persistence the attacker established.\n\n### Why UAL fluency matters here\nEvery step of this investigation depends on knowing exactly which Operation values and fields to search for — the difference between a fast, thorough BEC investigation and a slow, incomplete one is often simply whether the investigator knows the UAL schema well enough to ask the right Search-UnifiedAuditLog questions immediately, rather than discovering the relevant fields mid-investigation.",
        "codeExample": "flowchart TD\n  A[\"Alert: unusual MailboxLogin +\\nexternal forwarding rule\"] --> B[\"Pull full UAL history\\nfor UserId\"]\n  B --> C[\"Correlate with\\nEntra ID sign-in logs\"]\n  C --> D[\"Check SendAs for\\nsecondary victims\"]\n  D --> E[\"Contain: reset credential,\\nrevoke sessions/tokens,\\nremove inbox rule\"]",
        "keyPoints": [
          "A BEC investigation pulls the full UAL history for the affected UserId, not just the single event that triggered the alert.",
          "Correlating with Microsoft Entra ID sign-in logs reveals whether the access was flagged as risky and whether MFA (multi-factor authentication) was satisfied or bypassed.",
          "SendAs activity found during investigation expands the scope to every recipient, since BEC rarely stays contained to one mailbox once the attacker sends from it.",
          "Removing the malicious inbox rule is a required remediation step distinct from resetting the credential, since the rule persists independently."
        ]
      }
    ],
    "quiz": [
      {
        "question": "An investigator needs to identify what specific action a UAL record represents. Which field should they look at first?",
        "options": [
          {
            "label": "RecordType, since it always spells out the exact action taken",
            "value": "d"
          },
          {
            "label": "Operation, since it names the specific action that occurred (for example, FileDownloaded or New-InboxRule)",
            "value": "a"
          },
          {
            "label": "Workload, since it lists the specific action performed within that service",
            "value": "b"
          },
          {
            "label": "CreationTime, since it determines what type of action was possible at that moment",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "Operation is the field that directly names the specific action (FileDownloaded, MailboxLogin, New-InboxRule, and so on). RecordType only identifies the broad category, Workload identifies which service generated the record, and CreationTime is simply a timestamp."
      },
      {
        "question": "A SOC wants to detect potential data exfiltration from SharePoint. Which Operation is the primary signal, and what pattern makes it detection-worthy rather than routine?",
        "options": [
          {
            "label": "MailboxLogin; any single occurrence is treated as inherently suspicious",
            "value": "a"
          },
          {
            "label": "FileDownloaded; a single download is normal, but unusual volume or location is the real signal",
            "value": "b"
          },
          {
            "label": "New-InboxRule; every inbox rule creation should trigger an alert",
            "value": "c"
          },
          {
            "label": "Add-MailboxPermission; this operation is always malicious",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "FileDownloaded is the primary SharePoint/OneDrive exfiltration signal, but a single download is routine activity — the lesson specifically frames volume anomalies or anomalous source locations as what makes the pattern worth alerting on. MailboxLogin, New-InboxRule, and Add-MailboxPermission are all related to mailbox behavior, not SharePoint file downloads, and none of them are inherently malicious on their own."
      },
      {
        "question": "An inbox rule is created with a Parameters field containing ForwardTo pointing to an external domain, and DeleteMessage set to true. What does this combination most strongly suggest, and which MITRE ATT&CK technique does it map to?",
        "options": [
          {
            "label": "A routine out-of-office auto-reply; maps to no specific ATT&CK technique",
            "value": "b"
          },
          {
            "label": "A persistence mechanism forwarding and hiding mail; maps to T1114.003, Email Forwarding Rule",
            "value": "c"
          },
          {
            "label": "A scheduled mailbox cleanup task; maps to T1070, Indicator Removal",
            "value": "d"
          },
          {
            "label": "A legitimate delegate access grant; maps to T1078, Valid Accounts",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "External forwarding combined with automatic deletion of the forwarded messages is the classic pattern for hiding an attacker's ongoing mail collection from the mailbox owner, mapping to T1114.003 (Email Forwarding Rule) as described in this lesson. An out-of-office reply doesn't forward externally with message deletion, and this specific combination is not a routine cleanup task or a delegate access grant."
      },
      {
        "question": "An organization is licensed for Audit (Standard) only, with no Premium add-on. A detection engineer wants to build a behavioral baseline using two years of historical FileDownloaded activity per user. What is the problem with this plan?",
        "options": [
          {
            "label": "There is no problem; Audit (Standard) retains all UAL data indefinitely",
            "value": "c"
          },
          {
            "label": "Audit (Standard) retains records for 180 days by default, far short of the two years the baseline plan assumes is available",
            "value": "d"
          },
          {
            "label": "FileDownloaded events are never retained under Audit (Standard) regardless of duration",
            "value": "a"
          },
          {
            "label": "Audit (Standard) only retains Exchange Online records, never SharePoint records",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "Audit (Standard) retains records for 180 days by default (since the October 2023 policy change), not two years — a baseline plan assuming two years of history would silently fail to have the data it needs. Audit (Standard) does retain FileDownloaded and SharePoint records generally, just not for as long as Premium's extended tiers."
      },
      {
        "question": "During a BEC investigation, an analyst finds SendAs activity from the compromised mailbox. What is the correct next step according to this lesson's workflow?",
        "options": [
          {
            "label": "Close the investigation immediately, since SendAs activity is unrelated to mailbox compromise",
            "value": "d"
          },
          {
            "label": "Expand the investigation's scope to every recipient of those messages, since they are potential secondary targets",
            "value": "a"
          },
          {
            "label": "Ignore SendAs and focus exclusively on the original MailboxLogin event",
            "value": "b"
          },
          {
            "label": "Automatically assume no further remediation is needed since the rule was already removed",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "The lesson explicitly states that SendAs activity found during investigation expands scope to every recipient, since a BEC rarely stays contained to a single mailbox once the attacker starts sending from it — each recipient needs their own notification and investigation, not dismissal or a narrower focus."
      }
    ]
  },
  "detection-engineer--cloudtrail-for-detection": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What AWS CloudTrail Records and Why It Is the Backbone of AWS Detection",
        "body": "Amazon Web Services (AWS) has no equivalent of a single Windows Event Log or a Sysmon driver — nearly everything happening in an AWS account happens through API calls, whether triggered by a human in the console, a script using the AWS CLI, or one AWS service calling another. AWS CloudTrail is the service that records these API calls as structured JSON event records, and it is the foundation almost every AWS-focused detection ultimately depends on.\n\n### Always-on baseline visibility\nEvery AWS account automatically retains 90 days of management-event history (called CloudTrail Event History) accessible through the console or API, with no configuration required. However, this default history is limited in scope and duration — organizations that need longer retention, delivery to a SIEM, or coverage of data-plane activity must configure a dedicated CloudTrail trail, which delivers events continuously to an Amazon S3 bucket (and optionally to CloudWatch Logs) for long-term storage and SIEM ingestion.\n\n### Why CloudTrail matters this much\nBecause AWS has no separate, independent audit mechanism the way Windows has both Sysmon and native Security event logging, CloudTrail's completeness (or gaps, when specific event categories are not enabled) directly determines an organization's entire cloud detection capability. A technique that isn't captured by any enabled CloudTrail event category is, for practical purposes, invisible to detection — there is no equivalent fallback telemetry source the way Sysmon can sometimes substitute for missing EDR coverage on Windows.\n\n### What this lesson covers\nThis lesson works through CloudTrail's event categories, the anatomy of an individual event record, and three specific, high-value API calls detection engineers repeatedly build rules against: AssumeRole (identity), GetSecretValue (secrets access), and CreateUser (persistence) — closing with CloudTrail Insights, AWS's own anomaly-detection layer on top of this same event stream.",
        "codeExample": "flowchart TD\n  A[\"Human (console) /\\nCLI / SDK / AWS service\"] --> B[\"AWS API call\"]\n  B --> C[\"CloudTrail records\\nthe API call as a JSON event\"]\n  C --> D[\"CloudTrail Event History\\n(90 days, always on,\\nmanagement events only)\"]\n  C --> E[\"Configured Trail\\n(delivers to S3 + CloudWatch,\\nlong-term retention)\"]",
        "keyPoints": [
          "AWS CloudTrail records API calls as structured JSON events and is the foundation of nearly all AWS-focused detection.",
          "Every AWS account automatically retains 90 days of management-event history with no configuration, but a dedicated trail is needed for longer retention and SIEM ingestion.",
          "AWS has no independent audit mechanism outside CloudTrail — a technique not captured by any enabled event category is effectively invisible to detection.",
          "This lesson covers event categories, record anatomy, three key API calls (AssumeRole, GetSecretValue, CreateUser), and CloudTrail Insights."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Event Categories: Management, Data, Insight, and Network Activity Events",
        "body": "CloudTrail organizes events into four categories, each represented by the eventCategory field in the record — and critically, they are not all logged by default, which is one of the most consequential facts for a detection engineer working with AWS telemetry.\n\n### Management events\nAlso called control-plane operations, these cover configuration and administrative actions on AWS resources — creating an IAM user, launching an EC2 instance, modifying a security group. Management events are logged by default once a trail is configured, and can be further scoped to Read-only, Write-only, or both.\n\n### Data events\nCover resource-level operations, typically at much higher volume — Amazon S3 object-level calls like GetObject and PutObject, or AWS Lambda function invocations. Data events are NOT logged by default because of their volume and associated cost; an organization must explicitly enable data event logging for specific resources or resource types.\n\n### Insight events\nGenerated by CloudTrail Insights, an optional, separately-enabled feature that uses machine learning to establish a baseline of normal API call volume and error rates, then generates an Insight event (of type ApiCallRateInsight or ApiErrorRateInsight) when activity deviates significantly from that baseline. Insight events must be explicitly enabled per trail via the PutInsightSelectors API.\n\n### Network activity events\nA more recent addition covering AWS service access made through VPC endpoints, giving visibility into service-to-service network-level activity. Like data events, these require explicit opt-in.\n\n### Why this matters for detection\nA detection engineer cannot assume a given API call is being logged just because CloudTrail \"is on\" — GetObject calls against a sensitive S3 bucket, for instance, will never appear anywhere if data event logging was never enabled for that bucket. Confirming which categories are actually enabled, for which resources, is a mandatory first step before designing any CloudTrail-based detection — directly analogous to confirming a Sysmon configuration actually logs the event type a Windows-based rule depends on.",
        "codeExample": "# Check which event categories a trail is actually configured to log\naws cloudtrail get-event-selectors --trail-name nexacorp-main-trail\n\n# Enable Insight events (anomaly detection) on a trail\naws cloudtrail put-insight-selectors \\\n  --trail-name nexacorp-main-trail \\\n  --insight-selectors '[{\"InsightType\": \"ApiCallRateInsight\"}, {\"InsightType\": \"ApiErrorRateInsight\"}]'",
        "keyPoints": [
          "CloudTrail's eventCategory field distinguishes Management, Data, Insight, and Network Activity events.",
          "Management events (control-plane operations) are logged by default once a trail exists; Data, Insight, and Network Activity events all require explicit opt-in.",
          "Insight events use machine learning to flag deviations from a baseline of normal API call volume or error rate, and must be enabled via PutInsightSelectors.",
          "A detection engineer must confirm which event categories are actually enabled for which resources before assuming any specific API call is being captured."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Anatomy of a CloudTrail Event Record",
        "body": "Every CloudTrail event, regardless of category, shares a consistent JSON structure — understanding these fields is the foundation for writing any CloudTrail-based detection, in the same way understanding Sysmon's or the UAL's core fields was foundational in earlier lessons.\n\n### Core fields\n- **eventTime** — the UTC timestamp of the API call.\n- **eventSource** — the AWS service the call was made to, expressed as a service endpoint (for example, sts.amazonaws.com for AWS Security Token Service calls, or iam.amazonaws.com for IAM calls).\n- **eventName** — the specific API operation called (AssumeRole, GetSecretValue, CreateUser, and so on) — the direct AWS equivalent of the UAL's Operation field or a Sysmon Event ID.\n- **awsRegion** — the AWS region the call was made in.\n- **sourceIPAddress** — the IP address the call originated from (or an AWS service principal, for service-to-service calls).\n- **userIdentity** — an object describing who made the call: type (IAMUser, AssumedRole, Root, and others), arn (the full Amazon Resource Name identifying the principal), and accountId.\n- **requestParameters** and **responseElements** — the input parameters supplied to the API call and the values returned, respectively — often the most detail-rich fields for understanding exactly what the call did.\n- **errorCode** and **errorMessage** — populated when the call failed, useful for detecting reconnaissance (repeated failed calls probing for accessible resources) or misconfigured legitimate automation.\n\n### An important privacy safeguard\nAWS deliberately does not include sensitive secret values in CloudTrail records even when the API call itself retrieves a secret — a detail directly relevant to the GetSecretValue detection covered later in this lesson, and a reminder that CloudTrail records what happened and who did it, not necessarily the sensitive content involved.\n\n### Reading a record end to end\nA CloudTrail record answers: who (userIdentity), did what (eventName) to which service (eventSource), from where (sourceIPAddress), and with what parameters and result (requestParameters, responseElements, errorCode) — the same investigative structure as the UAL and Sysmon records covered earlier in this path, expressed through AWS's own field names.",
        "codeExample": "{\n  \"eventTime\": \"2026-03-04T09:15:22Z\",\n  \"eventSource\": \"sts.amazonaws.com\",\n  \"eventName\": \"AssumeRole\",\n  \"awsRegion\": \"us-east-1\",\n  \"sourceIPAddress\": \"203.0.113.77\",\n  \"userIdentity\": {\n    \"type\": \"IAMUser\",\n    \"arn\": \"arn:aws:iam::111122223333:user/j.doe\",\n    \"accountId\": \"111122223333\"\n  },\n  \"requestParameters\": {\n    \"roleArn\": \"arn:aws:iam::444455556666:role/AdminCrossAccountRole\",\n    \"roleSessionName\": \"j.doe-session\"\n  },\n  \"errorCode\": null\n}",
        "keyPoints": [
          "eventName is CloudTrail's equivalent of a Sysmon Event ID or a UAL Operation — it names the specific API call made.",
          "userIdentity identifies who made the call (type, ARN, account ID); eventSource identifies which AWS service was called.",
          "requestParameters and responseElements carry the detailed input and output of the call, often the most useful fields for understanding intent.",
          "AWS deliberately excludes sensitive secret values from CloudTrail records even for calls that retrieve secrets, such as GetSecretValue."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Detecting Identity Abuse: AssumeRole and Cross-Account Pivoting",
        "body": "AWS Identity and Access Management (IAM) roles let one identity temporarily \"assume\" a different set of permissions, and the Security Token Service (STS) AssumeRole API call is how that happens. It is a completely normal, heavily-used mechanism for legitimate cross-account access and service-to-service permission delegation — and also one of the most attractive privilege-escalation and lateral-movement techniques for an attacker who has compromised low-privilege credentials.\n\n### The eventSource and eventName for this detection\nAssumeRole calls appear in CloudTrail with eventSource sts.amazonaws.com and eventName AssumeRole (related variants include AssumeRoleWithSAML and AssumeRoleWithWebIdentity for federated identity flows).\n\n### What an analyst examines\n- **userIdentity.arn** — the original identity making the call, before the role is assumed.\n- **requestParameters.roleArn** — which role is being assumed; a low-privilege user suddenly assuming a role with broad administrative permissions is a strong signal worth investigating.\n- **sourceIPAddress** — an unfamiliar or geographically inconsistent source for a given identity's typical AssumeRole pattern.\n- **Cross-account context** — the requestParameters.roleArn's account ID differing from the calling identity's own account (visible in userIdentity.accountId) indicates cross-account role assumption, which is a routine pattern in well-architected multi-account AWS environments, but is also exactly how an attacker pivots from a lower-value, initially-compromised account into a higher-value target account.\n\n### Building a detection\nA baseline-driven detection — flagging AssumeRole calls to a role the calling identity has never assumed before, or role assumptions occurring from a source IP outside the organization's known ranges — is generally more effective than a static rule, since AssumeRole is used so pervasively by legitimate automation that a rule matching every occurrence would be overwhelmingly noisy, echoing the same first-time-seen baselining principle covered for UAL detections in the previous lesson.",
        "codeExample": "// Conceptual detection logic: AssumeRole to an unusually privileged role,\n// from an identity that has not assumed that role before\nCloudTrail\n| where eventSource == \"sts.amazonaws.com\" and eventName == \"AssumeRole\"\n| extend CallerArn = tostring(userIdentity.arn)\n| extend TargetRoleArn = tostring(requestParameters.roleArn)\n| join kind=leftanti (HistoricalAssumeRolePairs) on CallerArn, TargetRoleArn\n| where TargetRoleArn has \"Admin\"",
        "keyPoints": [
          "AssumeRole (eventSource sts.amazonaws.com) lets an identity temporarily take on a different role's permissions — routine for legitimate use, but also a key privilege-escalation and pivoting technique for attackers.",
          "userIdentity.arn shows who is calling; requestParameters.roleArn shows which role is being assumed.",
          "Cross-account role assumption (target role's account differing from the caller's account) is normal in multi-account architectures but is also how an attacker pivots between compromised accounts.",
          "A baseline-driven detection (flagging never-before-seen caller-to-role pairs) is generally more effective than a static rule, since AssumeRole is used too pervasively for a blanket match to be useful."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Detecting Secrets Access: GetSecretValue",
        "body": "AWS Secrets Manager stores sensitive values — database credentials, API keys, and similar secrets — and the GetSecretValue API call is how an authorized identity or application retrieves one. Because compromised secrets frequently enable further lateral movement (a database credential retrieved via GetSecretValue can grant direct access to a data store far more valuable than the AWS account itself), this call is a high-value detection target.\n\n### An important prerequisite: Secrets Manager logging is not automatic\nSecrets Manager API actions, including GetSecretValue, are not logged by CloudTrail unless the account's trail is configured to capture management events — specifically, Read-type management events must not be excluded from the trail's event selectors. A trail configured for Write-only management events would never show a GetSecretValue call at all, since retrieving a secret's value is a read operation. Confirming this configuration is a mandatory first step, directly echoing the event-category caveat from earlier in this lesson.\n\n### What appears in the record — and what deliberately does not\nA GetSecretValue CloudTrail record shows eventSource secretsmanager.amazonaws.com, eventName GetSecretValue, the calling userIdentity, and the specific secret's identifier in requestParameters — but, as noted earlier in this lesson, AWS does not include the actual secret value itself in the record. Detection is entirely based on who accessed which secret, when, and from where, not on inspecting the secret's content.\n\n### Building a detection\nThe most valuable detection pattern is typically: a GetSecretValue call for a specific secret, made by an identity that does not normally access that secret (a baseline anomaly, the same principle applied to AssumeRole on the previous page), especially when combined with an unusual sourceIPAddress or an unusually high volume of distinct secrets accessed by a single identity in a short window — the secrets-access equivalent of the mass-download pattern covered for SharePoint file exfiltration in the previous lesson.\n\n### Why access patterns matter more than access itself\nBecause many legitimate applications call GetSecretValue routinely (an application retrieving its own database credential at startup, for example), a blanket alert on every GetSecretValue call would be far too noisy — the detection value comes specifically from identifying access that deviates from an established, expected pattern.",
        "codeExample": "// Conceptual detection logic: an identity accessing an unusually broad\n// set of distinct secrets within a short window\nCloudTrail\n| where eventSource == \"secretsmanager.amazonaws.com\" and eventName == \"GetSecretValue\"\n| summarize DistinctSecrets = dcount(tostring(requestParameters.secretId)) by tostring(userIdentity.arn), bin(eventTime, 1h)\n| where DistinctSecrets > 10",
        "keyPoints": [
          "GetSecretValue (eventSource secretsmanager.amazonaws.com) retrieves a stored secret and is a high-value detection target since compromised secrets often enable deeper lateral movement.",
          "Secrets Manager actions are not logged by CloudTrail unless the trail's management-event selector includes Read-type activity — a common, easy-to-miss configuration gap.",
          "AWS never includes the actual secret value in the CloudTrail record; detection relies on who accessed which secret identifier, when, and from where.",
          "A blanket alert on every GetSecretValue call is too noisy given routine legitimate use; the detection value comes from deviation from an established access pattern."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Detecting Persistence: CreateUser and IAM Changes",
        "body": "Once an attacker gains a foothold in an AWS account, establishing persistent access independent of the originally-compromised credential is a common next step — and the IAM CreateUser API call, along with related identity-management calls, is the primary telemetry for detecting this pattern, directly analogous to the New-InboxRule persistence pattern covered for Microsoft 365 in the previous lesson.\n\n### CreateUser and its typical companions\nCreateUser (eventSource iam.amazonaws.com) creates a new IAM user. On its own, a newly-created user has no permissions — an attacker establishing meaningful persistence typically pairs it with one or more follow-on calls within the same short window:\n- **AttachUserPolicy** or **PutUserPolicy** — granting the new user permissions, often broad ones (an AdministratorAccess policy attachment is an especially strong signal).\n- **CreateAccessKey** — generating a long-lived access key and secret for the new user, enabling programmatic (API/CLI) access outside of any interactive console session.\n- **CreateLoginProfile** — enabling console (password-based) sign-in for the new user.\n\n### A stealthier alternative: reusing an existing user\nRather than creating an entirely new IAM user (which is itself a somewhat visible action), a more cautious attacker may instead call CreateAccessKey against an existing, legitimate, but rarely-used IAM user — generating a new set of credentials for persistence without the more conspicuous CreateUser event appearing at all. This is why access-key creation deserves its own detection logic, not just a downstream check following a CreateUser event.\n\n### Building a detection\nA high-confidence detection correlates CreateUser with a subsequent AttachUserPolicy (or PutUserPolicy) granting broad permissions within a short time window, and separately, a lower-noise-tolerance rule flags CreateAccessKey events for IAM users that have had no prior access-key activity, or for users normally managed exclusively through single sign-on rather than direct IAM credentials.\n\n### Why this maps naturally to a broader IAM change monitoring practice\nCreateUser and its companion calls are a subset of a broader category of IAM configuration-change events (also including role trust-policy modifications and permission boundary changes) that a mature detection engineering practice monitors collectively, since privilege-escalation and persistence techniques in AWS environments overwhelmingly route through IAM configuration changes of one kind or another.",
        "codeExample": "title: New IAM User Granted Administrative Access\nid: 3e5f7a9b-1c3d-4e5f-8091-a2b3c4d5e6f7\nstatus: stable\ndescription: Detects a newly-created IAM user immediately granted broad administrative permissions\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    selection_create:\n        eventSource: 'iam.amazonaws.com'\n        eventName: 'CreateUser'\n    selection_attach:\n        eventSource: 'iam.amazonaws.com'\n        eventName: 'AttachUserPolicy'\n        requestParameters.policyArn|contains: 'AdministratorAccess'\n    condition: selection_create and selection_attach\ntags:\n    - attack.persistence\n    - attack.t1136.003\nlevel: critical",
        "keyPoints": [
          "CreateUser (eventSource iam.amazonaws.com) creates a new IAM user, but on its own grants no permissions — follow-on calls establish actual persistence.",
          "AttachUserPolicy/PutUserPolicy grant permissions, CreateAccessKey issues programmatic credentials, and CreateLoginProfile enables console sign-in — all common companions to CreateUser in a persistence chain.",
          "A stealthier attacker may skip CreateUser entirely and call CreateAccessKey against an existing, rarely-used IAM user instead, which is why access-key creation needs its own independent detection.",
          "CreateUser and its companion calls are part of a broader IAM configuration-change monitoring practice, since most AWS privilege-escalation and persistence routes through IAM changes."
        ]
      },
      {
        "pageNumber": 7,
        "title": "CloudTrail Insights: Anomaly Detection at Scale",
        "body": "The detections built so far in this lesson are all authored, rule-based logic — a detection engineer defines exactly what pattern to look for. CloudTrail Insights takes a different, complementary approach: AWS's own machine-learning-driven anomaly detection running continuously against the same underlying event stream.\n\n### How Insights works\nOnce enabled on a trail (via the PutInsightSelectors API, as shown earlier in this lesson), CloudTrail Insights establishes a rolling baseline of normal API call volume and error rates for the account, then automatically generates an Insight event when activity deviates significantly from that baseline — without any detection engineer having to define a specific threshold or pattern in advance.\n\n### The two Insight event types\n- **ApiCallRateInsight** — triggered when the volume of calls to a specific API operation deviates sharply from the established baseline, such as a sudden, unexplained spike in AssumeRole calls that might indicate automated credential abuse or a runaway (or malicious) script.\n- **ApiErrorRateInsight** — triggered when the rate of failed API calls (calls returning an error) deviates sharply from baseline, which can indicate reconnaissance activity — an attacker systematically probing for accessible resources or valid permissions, generating many failed attempts along the way.\n\n### Where Insight events are delivered\nInsight events are delivered to a dedicated location distinct from ordinary CloudTrail events — either a specified S3 prefix or, for organizations using CloudTrail Lake, a separate queryable location — and carry eventCategory: Insight, distinguishing them clearly from the Management and Data events covered earlier.\n\n### Why Insights complements, rather than replaces, authored rules\nInsights excels at catching genuinely novel, statistically unusual activity that no one thought to write a specific rule for — but it is inherently reactive to the account's own historical baseline, meaning a slow, gradual escalation in malicious activity (designed specifically to stay under the threshold that would look statistically anomalous) may not trigger it. The authored, technique-specific rules built earlier in this lesson (AssumeRole abuse, GetSecretValue anomalies, CreateUser persistence chains) remain necessary precisely because they encode specific, known attacker behavior that a purely statistical anomaly detector might miss.",
        "codeExample": "// Example CloudTrail Insight event (simplified)\n{\n  \"eventCategory\": \"Insight\",\n  \"insightDetails\": {\n    \"state\": \"Start\",\n    \"eventSource\": \"sts.amazonaws.com\",\n    \"eventName\": \"AssumeRole\",\n    \"insightType\": \"ApiCallRateInsight\",\n    \"insightContext\": {\n      \"statistics\": {\n        \"baseline\": { \"average\": 12 },\n        \"insight\": { \"average\": 340 }\n      }\n    }\n  }\n}",
        "keyPoints": [
          "CloudTrail Insights is an optional, machine-learning-driven layer that baselines normal API call volume and error rate, then flags significant deviations automatically.",
          "ApiCallRateInsight flags volume anomalies (a sudden spike in a specific API call); ApiErrorRateInsight flags error-rate anomalies, often indicative of reconnaissance.",
          "Insight events carry eventCategory: Insight and are delivered separately from ordinary Management/Data events.",
          "Insights complements authored, technique-specific rules rather than replacing them — it can miss slow, deliberately-gradual malicious activity designed to stay under statistical thresholds."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: Building a Sigma Rule Against CloudTrail",
        "body": "This final page walks through the complete sequence a detection engineer follows to turn a CloudTrail-based detection idea into a tested, deployed Sigma rule, tying together every concept from this lesson.\n\n### Step 1 — Confirm the event category is actually captured\nBefore writing any selection logic, confirm the relevant event category (Management, Data, or otherwise) is actually enabled on the organization's trail, and confirm any relevant event-selector scoping (Read/Write/All) includes the specific API call being targeted — directly referencing the GetSecretValue configuration caveat from earlier in this lesson.\n\n### Step 2 — Identify the eventSource and eventName\nEvery CloudTrail-based Sigma rule anchors on these two fields first, exactly as a Windows-based rule anchors on Image or a UAL-based rule anchors on Operation.\n\n### Step 3 — Add context fields that distinguish malicious from benign\nuserIdentity.arn, requestParameters values, and sourceIPAddress are where the real precision comes from — an eventName match alone (matching every AssumeRole call, for instance) is almost always too broad, echoing the anti-patterns lesson's warning against single-field selections.\n\n### Step 4 — Set logsource and write the rule\nSigma represents CloudTrail-based detections with logsource product: aws, service: cloudtrail — the pySigma AWS pipeline then handles converting this to the organization's specific SIEM query language and table structure.\n\n### Step 5 — Test against sample events\nUsing the same positive/negative sample testing discipline from the Coverage Testing lesson — a captured or synthetically constructed malicious CreateUser-plus-AttachUserPolicy sequence as a positive case, and a legitimate onboarding automation's CreateUser call (without the immediate administrative policy attachment) as a negative case.\n\n### Step 6 — Consider CloudTrail Insights as a complementary layer, not a replacement\nConfirm Insights is enabled where feasible, understanding it will catch novel volume/error anomalies the authored rule doesn't anticipate, while the authored rule continues to catch the specific, known technique it was designed for regardless of whether the activity is statistically unusual for that particular account.\n\n### The throughline across this entire module\nWhether the telemetry source is Sysmon, an EDR platform, the Microsoft 365 Unified Audit Log, or AWS CloudTrail, the same detection engineering discipline applies: understand exactly what the source captures and what it doesn't, anchor selections on the field that names the specific action, layer in context to avoid overbroad matches, and test before shipping.",
        "codeExample": "flowchart TD\n  A[\"Confirm event category\\nis actually enabled\"] --> B[\"Identify eventSource\\n+ eventName\"]\n  B --> C[\"Add context fields:\\nuserIdentity, requestParameters,\\nsourceIPAddress\"]\n  C --> D[\"Set logsource:\\nproduct aws, service cloudtrail\"]\n  D --> E[\"Test against\\npositive/negative samples\"]\n  E --> F[\"Deploy alongside\\nCloudTrail Insights\"]",
        "keyPoints": [
          "Before writing a CloudTrail rule, confirm the relevant event category and event-selector scope (Read/Write/All) actually captures the target API call.",
          "CloudTrail Sigma rules anchor on eventSource and eventName, the AWS equivalent of a UAL Operation or a Sysmon Event ID.",
          "Context fields (userIdentity.arn, requestParameters, sourceIPAddress) provide the precision that a bare eventName match alone cannot.",
          "Authored rules and CloudTrail Insights are complementary: authored rules catch specific known techniques regardless of statistical unusualness, while Insights catches novel anomalies no rule anticipated."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A detection engineer wants to alert on GetSecretValue calls against a specific AWS Secrets Manager secret, but the calls never appear in CloudTrail even though the API is genuinely being called. What is the most likely cause?",
        "options": [
          {
            "label": "The trail's selectors likely exclude Read-type management events, which GetSecretValue needs",
            "value": "b"
          },
          {
            "label": "AWS Secrets Manager does not support CloudTrail logging under any configuration",
            "value": "c"
          },
          {
            "label": "GetSecretValue calls are only logged if CloudTrail Insights is enabled",
            "value": "d"
          },
          {
            "label": "The secret's value must be included in the request for logging to occur",
            "value": "a"
          }
        ],
        "answer": "b",
        "explanation": "GetSecretValue is a management (control-plane) event, and the lesson specifically notes it requires the trail's management-event selector to include Read-type activity — a trail scoped to Write-only would miss it entirely. Secrets Manager does support CloudTrail logging, Insights is unrelated to whether ordinary events are captured, and the secret's value is never included in CloudTrail regardless."
      },
      {
        "question": "Which pair of fields would an analyst check first to identify exactly which API operation and which AWS service a CloudTrail record represents?",
        "options": [
          {
            "label": "awsRegion and sourceIPAddress",
            "value": "b"
          },
          {
            "label": "eventSource and eventName",
            "value": "c"
          },
          {
            "label": "requestParameters and responseElements",
            "value": "d"
          },
          {
            "label": "errorCode and errorMessage",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "eventSource identifies the AWS service called (e.g., sts.amazonaws.com) and eventName identifies the specific API operation (e.g., AssumeRole) — together, the direct equivalent of a Sysmon Event ID or UAL Operation field. The other pairs provide supporting context (location, detail, or error status) but don't identify the action itself."
      },
      {
        "question": "An attacker compromises a low-privilege IAM user's credentials and successfully calls AssumeRole to assume a role in a different AWS account with broad administrative permissions. What does this scenario illustrate?",
        "options": [
          {
            "label": "AssumeRole calls to a different account are always blocked by AWS regardless of permissions",
            "value": "c"
          },
          {
            "label": "Cross-account role assumption is a routine multi-account pattern, but also exactly how attackers pivot to a higher-value account",
            "value": "d"
          },
          {
            "label": "This activity would automatically appear as a CloudTrail Insight event regardless of whether Insights is enabled",
            "value": "a"
          },
          {
            "label": "AssumeRole calls are never logged by CloudTrail under any trail configuration",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explicitly frames cross-account AssumeRole as dual-use: routine in well-architected multi-account environments, but also a key attacker pivoting technique. AWS does not block cross-account role assumption when permissions allow it, Insights must be explicitly enabled to generate any Insight events, and AssumeRole is a standard management event captured under normal trail configuration."
      },
      {
        "question": "A stealthier attacker, aware that CreateUser is a relatively visible event, instead calls CreateAccessKey against an existing, rarely-used IAM user to establish persistence. Why does this lesson recommend detecting CreateAccessKey independently, not just as a follow-on check after CreateUser?",
        "options": [
          {
            "label": "Because CreateAccessKey is not logged by CloudTrail unless CreateUser occurred first",
            "value": "d"
          },
          {
            "label": "Because this path against an existing user never triggers CreateUser, so a CreateUser-only detection would miss it",
            "value": "a"
          },
          {
            "label": "Because CreateAccessKey always indicates malicious activity regardless of context",
            "value": "b"
          },
          {
            "label": "Because AttachUserPolicy is required before CreateAccessKey can succeed",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "The lesson specifically describes this as a stealthier alternative precisely because it bypasses the more conspicuous CreateUser event — a detection chained only off CreateUser would have a blind spot for this path. CreateAccessKey is logged independently of CreateUser, is not inherently malicious (it has many legitimate uses), and does not require a prior AttachUserPolicy call to succeed."
      },
      {
        "question": "An organization enables CloudTrail Insights and also maintains authored Sigma rules for specific techniques like GetSecretValue anomalies. Why does the lesson recommend keeping both rather than relying on Insights alone?",
        "options": [
          {
            "label": "Insights only works for AWS accounts created within the last 90 days",
            "value": "a"
          },
          {
            "label": "Authored rules catch known techniques regardless of volume, while Insights may miss slow, deliberately-gradual activity",
            "value": "b"
          },
          {
            "label": "Insights cannot detect any activity related to IAM or Secrets Manager",
            "value": "c"
          },
          {
            "label": "Authored rules and Insights cannot both be active on the same trail simultaneously",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explains Insights is reactive to an account's own historical baseline and can miss deliberately gradual escalation designed to avoid statistical anomaly, whereas authored rules encode specific known-bad patterns regardless of volume. There's no such account-age restriction on Insights, Insights can flag anomalies in any API including IAM/Secrets Manager calls, and both mechanisms can and do run simultaneously on the same trail."
      }
    ]
  },
  "detection-engineer--fp-analysis": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why False Positives Are a SOC's Silent Killer",
        "body": "Every previous lesson in this path has focused on building detections — writing selections, choosing modifiers, mapping telemetry sources. This lesson turns to what happens after a rule ships and starts firing in production: the ongoing discipline of understanding, measuring, and reducing false positives, without which even a well-designed detection program slowly degrades.\n\n### What a false positive actually is\nA false positive (FP) is an alert that fired but did not represent the malicious or policy-violating behavior the rule was designed to detect — the rule matched, but the underlying activity was legitimate. This is distinct from a true positive (an alert that correctly identified real malicious or violating activity) and a false negative (malicious activity that occurred but no rule matched it at all).\n\n### Alert fatigue: the operational consequence\nWhen a SOC (Security Operations Center) analyst faces a high volume of low-value alerts day after day, a well-documented pattern called alert fatigue sets in: response times slow down, analysts begin unconsciously discounting alerts from historically noisy rules, and — most dangerously — genuine true positives get lost in the noise or dismissed with the same reflexive \"probably nothing\" judgment applied to the surrounding false positives. This is sometimes described as a normalization of deviance: what should be treated as anomalous becomes routine simply because it happens constantly.\n\n### Why this is a detection engineering problem, not just an analyst problem\nIt is tempting to treat false-positive volume as purely a triage or staffing issue, but the root cause is almost always upstream in the rule itself — an overly broad selection, a missing filter, a rule that doesn't account for how a specific environment actually behaves. This lesson treats false-positive analysis as a core detection engineering discipline: finding the root cause in the rule logic, not just training analysts to click through noise faster.\n\n### What this lesson builds toward\nBy the end of this lesson, a detection engineer should be able to classify why a specific false positive occurred, measure whether a rule's false-positive rate is actually a problem worth fixing, and feed findings back into the rule-tuning practices covered earlier in this path — setting up directly for the Allowlists & Exceptions lab that follows.",
        "codeExample": "flowchart LR\n  A[\"High FP volume\"] --> B[\"Alert fatigue:\\nslower response,\\ndesensitized analysts\"]\n  B --> C[\"True positives\\nget lost in noise\"]\n  C --> D[\"Real incidents\\ndetected late or missed\"]",
        "keyPoints": [
          "A false positive is an alert that fired without the underlying activity actually being the malicious or violating behavior the rule targets — distinct from a true positive and a false negative.",
          "Alert fatigue is the well-documented operational pattern where high alert volume desensitizes analysts, risking real true positives being dismissed along with the noise.",
          "False-positive root causes are almost always upstream in the rule logic itself, not simply a triage or staffing problem.",
          "This lesson builds toward classifying FP root causes, measuring FP impact, and feeding findings back into rule tuning."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Precision, Recall, and the FP/FN Tradeoff",
        "body": "Detection quality is commonly described using two metrics borrowed from information retrieval and machine learning, and understanding both — and the tension between them — is essential to making good tuning decisions rather than simply reacting to complaints about noisy rules.\n\n### Precision\nPrecision measures what fraction of a rule's alerts are genuinely true positives: precision equals true positives divided by the sum of true positives and false positives. A rule with low precision generates many false alarms relative to real detections — exactly the alert-fatigue driver described on the previous page.\n\n### Recall\nRecall (also called sensitivity) measures what fraction of actual malicious activity the rule successfully catches: recall equals true positives divided by the sum of true positives and false negatives. A rule with low recall misses a meaningful share of the real attacks it was designed to catch, even if every alert it does generate is accurate.\n\n### The fundamental tradeoff\nTightening a rule — adding more required conditions, narrowing a wildcard match, adding a filter — generally raises precision (fewer false positives) but risks lowering recall (some genuine attack variations that no longer match the tightened selection slip through undetected). Loosening a rule has the opposite effect. Neither direction is universally correct; the right balance depends on the specific technique's severity, the asset's criticality, and the SOC's actual capacity to review alerts.\n\n### Why filters are usually the better tool than blanket tightening\nThe Sigma Selection Patterns lesson introduced the filter block specifically because it lets a detection engineer improve precision (excluding a specific known-benign case) without broadly narrowing the selection logic that provides recall against genuine variations of the attack — a targeted filter is almost always preferable to a blunt tightening of the core selection, since the filter subtracts a known false-positive source precisely, while a tightened selection risks losing detection of real variants the engineer hasn't specifically considered.\n\n### Applying this to a concrete decision\nIf a PowerShell rule alerts on 200 events a week, of which 190 are a known IT automation tool and 10 are genuine investigation-worthy findings, precision is low (10/200 = 5%) — but the fix is a targeted filter excluding the specific automation tool's signature, not a broad reduction in what counts as suspicious PowerShell usage, which would risk losing recall against real attacker behavior that happens to resemble the automation tool only superficially.",
        "codeExample": "# Precision and recall, worked from a week of alert data for one rule\n# True Positives (TP): 10\n# False Positives (FP): 190\n# False Negatives (FN): 2 (confirmed via a separate incident review)\n\nPrecision = TP / (TP + FP) = 10 / (10 + 190) = 0.05   # 5%\nRecall    = TP / (TP + FN) = 10 / (10 + 2)  = 0.83   # 83%\n\n# Interpretation: recall is strong (few real attacks are missed),\n# but precision is very poor — the rule needs a targeted filter,\n# not a broader tightening that would risk lowering recall.",
        "keyPoints": [
          "Precision (TP over TP+FP) measures how much of a rule's alert volume is genuinely true positive; recall (TP over TP+FN) measures how much real malicious activity the rule actually catches.",
          "Tightening a rule generally raises precision but risks lowering recall; loosening has the opposite effect — there is no universally correct balance.",
          "A targeted filter (from the Sigma Selection Patterns lesson) usually improves precision without the recall cost of broadly tightening the core selection.",
          "Precision and recall should be calculated from real alert data, not estimated, before deciding how to tune a specific rule."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Root Cause Categories for False Positives",
        "body": "Not all false positives share the same underlying cause, and correctly categorizing a given FP is the first step toward choosing the right fix — a category-appropriate fix resolves the noise durably, while a mismatched fix (like a blanket filter for what is actually a data-quality problem) often just creates a new blind spot.\n\n### Category A: Legitimate tooling resembling attacker behavior\nIT administration tools frequently use the exact same mechanisms attackers abuse — PsExec-style remote execution, PowerShell automation, scheduled task creation — because these are simply how Windows administration works. A rule targeting the underlying mechanism without distinguishing the legitimate tool's specific signature (path, parent process, argument pattern) will match both.\n\n### Category B: Overly broad selection logic\nA selection matching on a single weak field (the anti-pattern covered in the Sigma Selection Patterns lesson) generates false positives not because of any specific legitimate tool, but simply because the pattern itself is too common to be a meaningful signal on its own.\n\n### Category C: Environment drift\nA rule tuned and validated against the environment as it existed at authoring time can start generating new false positives months later when the organization rolls out new software that happens to match the rule's existing logic — the rule didn't change, but the environment did.\n\n### Category D: Data quality and field-mapping issues\nSometimes a \"false positive\" is not really a false positive at all, but a symptom of a parsing error, an incorrect pySigma pipeline mapping, or a log source populating a field differently than the rule assumes — producing matches that look like the target behavior in the SIEM's normalized view but don't actually reflect what happened on the source system.\n\n### Category E: Missing context\nA rule with no awareness of asset criticality or user role may flag identical activity as equally noteworthy on a test virtual machine and a production domain controller — the activity itself may be genuinely rare and worth a look on a low-value asset, without being a meaningful signal worth an analyst's time in that specific context, which is really a severity and prioritization issue (covered later in this path) rather than a detection logic flaw.\n\n### Diagnosing correctly before fixing\nAn analyst or detection engineer investigating a false positive should work through these categories deliberately rather than jumping straight to \"add a filter\" — a Category C environment-drift issue and a Category D data-quality issue call for very different remedies, even though both might superficially look like \"this rule is too noisy.\"",
        "codeExample": "flowchart TD\n  A[\"FP investigation\"] --> B{\"Root cause?\"}\n  B -->|Legit tool resembles attack| C[\"A: Filter the\\nspecific tool signature\"]\n  B -->|Selection too broad| D[\"B: Add distinguishing\\nfields to selection\"]\n  B -->|New software rolled out| E[\"C: Re-baseline,\\nupdate filter\"]\n  B -->|Parsing/mapping error| F[\"D: Fix pipeline\\nor field mapping\"]\n  B -->|Missing asset context| G[\"E: Address via\\nseverity tiering\"]",
        "keyPoints": [
          "False-positive root causes fall into distinct categories: legitimate tooling resembling attacks, overly broad selections, environment drift, data quality/mapping issues, and missing context.",
          "Correctly categorizing a false positive determines the right fix — a mismatched fix can resolve the symptom while leaving the real problem (or creating a new blind spot).",
          "Environment drift means a rule that was well-tuned at authoring time can develop new false positives later purely because the environment changed, not because the rule changed.",
          "A 'false positive' caused by a data-quality or field-mapping issue isn't really a detection logic flaw — it needs a pipeline or parsing fix, not a filter."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Baselining Legitimate Activity",
        "body": "Several of the root-cause categories from the previous page — legitimate tooling, environment drift — are best addressed not by reacting to individual false positives one at a time, but by proactively building a baseline of what legitimate activity looks like in the organization's specific environment, then designing rules and filters around that baseline from the start.\n\n### What baselining means in practice\nBaselining is the process of systematically observing a rule's (or a broader behavior category's) matches over a representative period, profiling the common, recurring patterns — typical Image and CommandLine values, typical parent processes, typical users and hosts involved — and using that profile to distinguish \"common, therefore likely benign\" from \"rare, therefore worth a closer look.\"\n\n### Frequency-based approaches\nA common technique is \"rare process by parent\" or \"first-time-seen\" analysis: comparing a newly-observed event against a historical table of previously-seen combinations (a specific child process under a specific parent process, for instance) and treating genuinely novel combinations as higher priority than combinations the environment has seen thousands of times before, even if both technically match the same underlying Sigma rule.\n\n### Building this into a query\nA KQL join against a historical reference table (populated by a scheduled job that continuously records seen combinations) is a common implementation pattern in Microsoft Sentinel; other SIEMs offer equivalent lookup-table or summary-index approaches.\n\n### Baselining is a starting point for tuning, not a substitute for filters\nA baseline tells a detection engineer which specific legitimate patterns are common enough to warrant a dedicated filter — it does not replace the filter itself. The output of a baselining exercise typically becomes the concrete field values (a specific tool's path, parent process, and argument pattern) that get written into the filter blocks and exception documents covered in the Sigma Selection Patterns lesson and the upcoming Allowlists & Exceptions lab.\n\n### Revisiting baselines periodically\nBecause of environment drift (Category C from the previous page), a baseline built once and never revisited gradually loses accuracy as the organization's software and processes change — baselining should be a recurring practice, not a one-time exercise performed only when a rule is first authored.",
        "codeExample": "// KQL: first-time-seen detection — flag a parent-child process pair\n// that has never been observed before in the last 90 days\nlet HistoricalPairs = DeviceProcessEvents\n    | where Timestamp between (ago(90d) .. ago(1d))\n    | summarize by InitiatingProcessFileName, FileName;\nDeviceProcessEvents\n| where Timestamp > ago(1d)\n| join kind=leftanti (HistoricalPairs) on InitiatingProcessFileName, FileName\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine",
        "keyPoints": [
          "Baselining systematically profiles a rule's typical matches over time to distinguish common (likely benign) patterns from genuinely rare ones worth closer review.",
          "First-time-seen or rare-process-by-parent analysis compares new events against a historical reference table of previously-observed combinations.",
          "Baselining output feeds directly into the concrete field values used in filter blocks and exception documents, rather than replacing them.",
          "Because of environment drift, baselines need periodic re-examination rather than being built once and treated as permanently accurate."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Investigating a Specific False Positive: A Worked Example",
        "body": "This page walks through a realistic false-positive investigation end to end, applying the root-cause categories and diagnostic mindset from earlier pages to a concrete scenario.\n\n### The alert\nA Sigma rule targeting T1003.001-style credential access fires on a host, matching rundll32.exe being invoked with an unusual export function argument pattern resembling the comsvcs.dll MiniDump technique sometimes used to dump LSASS memory via a legitimate Windows DLL. The analyst on shift needs to determine whether this is a real credential-dumping attempt or a false positive.\n\n### Step 1 — Pull the full command line and context\nThe full CommandLine, ParentImage, the executing user account, and the host's role (is this a workstation, a server, a domain controller) — the same context fields the rule's selection likely already used, but reviewed here with full human judgment rather than automated pattern matching alone.\n\n### Step 2 — Compare against known legitimate patterns\nIn this scenario, the investigation reveals the host recently received a software update from an internal patch management tool, and that tool's update process is documented to use a similar rundll32.exe invocation pattern for a legitimate, unrelated DLL registration step — placing this squarely in Category A (legitimate tooling resembling attacker behavior) from the root-cause page.\n\n### Step 3 — Verify with additional evidence\nChecking the file hash of the DLL actually referenced in the command line (not just the presence of rundll32.exe) confirms it matches the patch tool's known-good DLL, not comsvcs.dll — strong, decisive evidence this specific event is benign, distinguishing it from a genuine LSASS-dumping attempt that would reference comsvcs.dll specifically.\n\n### Step 4 — Decide on a fix\nGiven the confirmed root cause, the appropriate fix (covered in depth in the next lesson) is a targeted filter excluding this specific patch tool's DLL path and parent process combination — not a broad change to the rule's core rundll32.exe-based selection, which would risk losing detection of the genuine comsvcs.dll-based technique the rule was built to catch.\n\n### Step 5 — Document the finding\nThe investigation's conclusion (root cause, evidence, and the resulting filter) gets documented and linked to the eventual rule change — the documentation and change-tracking practices covered in depth in the upcoming Allowlists & Exceptions lab.",
        "codeExample": "# The distinguishing evidence: DLL path referenced in the command line\n# Benign (patch tool):\nrundll32.exe C:\\\\Program Files\\\\NexaCorp\\\\PatchAgent\\\\register.dll,DllRegisterServer\n\n# Malicious (credential dumping via comsvcs.dll MiniDump):\nrundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump 636 C:\\\\Users\\\\Public\\\\lsass.dmp full",
        "keyPoints": [
          "A false-positive investigation pulls full context (command line, parent process, user, host role) rather than relying on the alert summary alone.",
          "Verifying the specific DLL path/hash referenced in a rundll32.exe command line, not just the presence of rundll32.exe itself, is decisive evidence distinguishing a legitimate patch tool from comsvcs.dll-based LSASS dumping.",
          "The correct fix (a targeted filter for the confirmed legitimate case) preserves the rule's ability to catch the genuine technique, unlike a broad change to the core selection.",
          "Documenting the investigation's root cause and evidence is what makes the eventual filter change defensible and maintainable later."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Measuring Alert Fatigue and False-Positive Rate Over Time",
        "body": "Individual investigations like the worked example on the previous page are necessary but not sufficient — a mature detection engineering practice also tracks false-positive trends at the rule and SOC-wide level, to identify which rules deserve tuning attention before analysts start informally deprioritizing them.\n\n### Rule-level metrics\n- **False-positive rate** — the precision metric from earlier in this lesson, tracked per rule over time (weekly or monthly), surfacing rules whose precision is degrading (a signal of environment drift) or was never acceptable to begin with.\n- **Alert volume trend** — a rule whose daily alert count is climbing steadily, even without a corresponding rise in confirmed true positives, is a strong candidate for the root-cause investigation process from earlier pages.\n\n### SOC-wide operational metrics\n- **Alerts per analyst per shift** — a rough proxy for workload and fatigue risk; a sustained, high value here is a leading indicator of the alert-fatigue pattern described on the first page of this lesson.\n- **Percentage of alerts closed as false positive within SLA** — a high percentage across the board (not just for one rule) suggests a systemic tuning problem across the rule set rather than an isolated issue.\n- **Mean time to dismiss (a false-positive-specific variant of mean time to detect)** — tracks how long analysts spend confirming something is a false positive; a rising trend can indicate false positives are becoming harder to distinguish from genuine findings, itself a sign the underlying rule needs better context or filtering.\n\n### Turning metrics into action: the noisiest-rules review\nA recurring cadence — weekly or monthly, depending on SOC size and alert volume — reviewing the top-N noisiest rules by false-positive rate or absolute FP volume creates a structured, proactive tuning pipeline, rather than relying purely on ad hoc investigations triggered by an individual analyst's frustration with a specific rule.\n\n### Why this closes the loop back to detection engineering\nThese metrics exist specifically to route tuning attention efficiently — a detection engineering team with limited time should spend it on the rules with the worst precision and highest volume first, not on whichever rule happens to generate the most recent complaint, ensuring effort is applied where it has the greatest measurable impact on analyst workload and alert quality.",
        "codeExample": "// Simplified weekly rule-level FP tracking, one row per rule\nrule_name,alerts_fired,confirmed_tp,confirmed_fp,precision\nSuspicious_LSASS_Access,42,3,39,0.07\nEncoded_PowerShell_Download,15,12,3,0.80\nNew_Admin_IAM_User,8,7,1,0.88",
        "keyPoints": [
          "False-positive rate (precision) should be tracked per rule over time, not assessed only once at authoring time, to catch environment drift and degrading precision.",
          "SOC-wide metrics like alerts per analyst per shift and percentage of alerts closed as FP within SLA surface systemic tuning problems across the whole rule set.",
          "A recurring noisiest-rules review (weekly or monthly) creates a structured, proactive tuning pipeline rather than relying on ad hoc complaints.",
          "These metrics exist to route limited detection engineering time toward the rules with the worst precision and highest volume, for maximum impact."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Feeding FP Findings Back Into Detection Engineering",
        "body": "A false-positive investigation or a noisiest-rules review is only valuable if its findings actually change something — this page covers how those findings route back into the practices covered earlier in this path, closing the loop between measurement and improvement.\n\n### Matching the fix to the root cause\nReferring back to the root-cause categories from earlier in this lesson:\n- **Category A (legitimate tooling)** routes to a targeted Sigma filter block, as demonstrated in the worked example.\n- **Category B (overly broad selection)** routes to strengthening the core selection itself — adding a distinguishing field, switching a plain match to a more precise modifier (from the Sigma Modifiers lesson) — rather than merely filtering around the symptom.\n- **Category C (environment drift)** routes to a re-baselining exercise (from earlier in this lesson) and an updated filter reflecting the new legitimate pattern.\n- **Category D (data quality)** routes to fixing the underlying pySigma pipeline mapping or the log source's parsing configuration, not to any change in the Sigma rule's own logic at all.\n- **Category E (missing context)** routes to the severity-tiering practices covered later in this Learning Path, rather than a change to the detection logic itself.\n\n### Change management for the fix\nConsistent with the detection-as-code practice from the Coverage Testing lesson, any fix resulting from an FP investigation should go through the same pull-request, CI-tested, peer-reviewed workflow as a new rule — a filter added hastily and directly in production, without testing against both the newly-excluded benign case and the original malicious sample, risks silently blinding the rule the same way a poorly-written filter always does.\n\n### Tracking the fix back to its origin\nLinking the eventual code change (the filter, the strengthened selection, the pipeline fix) back to the specific FP investigation or ticket that justified it preserves the reasoning for future maintainers — exactly the kind of audit trail benefit the CI/version-control discussion in the Coverage Testing lesson described for detection-as-code generally.\n\n### Setting up the next lesson\nWhen the fix takes the form of an exception — a filter or suppression specifically excluding a known-benign case — the next lesson in this path (Allowlists & Exceptions) covers the full lifecycle of that exception: how to scope it safely, how to govern it, and how to eventually retire it once it's no longer needed.",
        "codeExample": "flowchart LR\n  A[\"FP root cause identified\"] --> B{\"Category?\"}\n  B -->|A: legit tool| C[\"Targeted filter\"]\n  B -->|B: broad selection| D[\"Strengthen selection\\n/modifier\"]\n  B -->|C: env drift| E[\"Re-baseline\\n+ update filter\"]\n  B -->|D: data quality| F[\"Fix pipeline/parsing\"]\n  B -->|E: missing context| G[\"Route to\\nseverity tiering\"]\n  C --> H[\"PR + CI test +\\npeer review + deploy\"]\n  D --> H\n  E --> H",
        "keyPoints": [
          "Each false-positive root-cause category routes to a specific, matched fix — legitimate tooling to a filter, broad selections to strengthened logic, drift to re-baselining, data quality to pipeline fixes, missing context to severity tiering.",
          "A fix resulting from an FP investigation should go through the same detection-as-code review and testing workflow as any new rule, not be pushed directly to production.",
          "Linking a code change back to the FP investigation that justified it preserves the reasoning for future maintainers, the same audit-trail benefit described for detection-as-code generally.",
          "Exception-style fixes (filters, suppressions) set up directly for the full lifecycle management covered in the next lesson, Allowlists & Exceptions."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: The FP Triage Loop",
        "body": "This final page consolidates the entire lesson into the repeatable loop an analyst and detection engineer follow together, from an individual alert through to a durable fix.\n\n### Step 1 — Alert fires, analyst triages\nThe analyst reviews the alert with full context (command line, parent process, user, host role, and any other fields the rule surfaced) and reaches an initial classification: true positive, false positive, or undetermined pending further investigation.\n\n### Step 2 — Root-cause the false positive\nIf classified as a false positive, the analyst (or a detection engineer, depending on SOC structure) works through the root-cause categories from this lesson — legitimate tooling, overly broad selection, environment drift, data quality, or missing context — using the diagnostic approach demonstrated in the worked example.\n\n### Step 3 — Decide the appropriate fix\nMatched to the root cause, as covered on the previous page: a targeted filter, a strengthened selection, a re-baselining exercise, a pipeline fix, or a routing to severity tiering.\n\n### Step 4 — Submit through detection engineering's review process\nThe fix is authored, tested against both the malicious sample and the newly-excluded benign case, and submitted through the same pull-request and CI process as any other rule change.\n\n### Step 5 — Validate the fix doesn't reduce true-positive coverage\nBefore merging, confirm the change still detects the original malicious sample it was designed for — the same \"test both directions\" discipline introduced in the Sigma Selection Patterns lesson's filter guidance.\n\n### Step 6 — Deploy and monitor\nAfter deployment, the rule's precision and alert volume (the metrics from earlier in this lesson) are monitored going forward, confirming the fix actually resolved the false-positive pattern without introducing a new blind spot.\n\n### Why this loop is the real deliverable of this lesson\nNo single technique in this lesson — not precision/recall, not root-cause categorization, not baselining — is valuable in isolation. It is the complete, disciplined loop from alert to root cause to tested fix to monitored outcome that turns false-positive analysis from a source of analyst frustration into a genuine, continuous improvement mechanism for the detection program as a whole.",
        "codeExample": "flowchart TD\n  A[\"1. Alert fires,\\nanalyst triages\"] --> B[\"2. Root-cause\\nthe false positive\"]\n  B --> C[\"3. Decide\\nappropriate fix\"]\n  C --> D[\"4. Submit via PR\\n+ CI + peer review\"]\n  D --> E[\"5. Validate: still\\ndetects malicious sample\"]\n  E --> F[\"6. Deploy +\\nmonitor precision\"]\n  F -.-> A",
        "keyPoints": [
          "The FP triage loop is: alert fires, triage, root-cause, decide the matched fix, submit through review, validate against the original malicious sample, deploy and monitor.",
          "Root-causing before fixing prevents mismatched fixes that resolve a symptom while leaving the real problem (or a new blind spot) in place.",
          "Every fix must be validated to still detect the original malicious sample before merging, not just confirmed to stop the false positive.",
          "The complete, disciplined loop — not any single technique in isolation — is what turns FP analysis into a continuous improvement mechanism."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A rule generates 100 alerts in a week: 8 are confirmed true positives, 92 are confirmed false positives, and a separate incident review finds 2 additional real attacks that this rule failed to catch. What is this rule's precision?",
        "options": [
          {
            "label": "8%, calculated as 8 divided by (8 plus 92)",
            "value": "c"
          },
          {
            "label": "80%, calculated as 8 divided by (8 plus 2)",
            "value": "d"
          },
          {
            "label": "92%, calculated as 92 divided by 100",
            "value": "a"
          },
          {
            "label": "20%, calculated as 2 divided by (2 plus 8)",
            "value": "b"
          }
        ],
        "answer": "c",
        "explanation": "Precision is true positives divided by (true positives plus false positives): 8 / (8 + 92) = 8%. The 80% figure is actually this rule's recall (TP over TP+FN), not precision, and the other two options don't correspond to either metric's correct formula."
      },
      {
        "question": "A detection engineer discovers that a rule's false positives are caused by a recently-deployed internal software update tool that happens to match the rule's existing selection logic, even though the rule itself has not changed. Which root-cause category does this best fit?",
        "options": [
          {
            "label": "Category A: legitimate tooling resembling attacker behavior, present since the rule was authored",
            "value": "c"
          },
          {
            "label": "Category C: environment drift, where the environment changed after the rule was already validated",
            "value": "d"
          },
          {
            "label": "Category D: data quality and field-mapping issues",
            "value": "a"
          },
          {
            "label": "Category E: missing asset-criticality context",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "The scenario specifically describes a new tool deployed after the rule was already validated — the environment changed, not the rule — which is the definition of environment drift (Category C). Category A involves a legitimate tool present from the start, Category D involves parsing/mapping problems, and Category E involves asset context, none of which match this specific scenario."
      },
      {
        "question": "An analyst investigating a rundll32.exe-based LSASS access alert confirms the referenced DLL is a legitimate patch tool's registration DLL, not comsvcs.dll. What is the most appropriate fix, and why?",
        "options": [
          {
            "label": "Delete the rule entirely, since rundll32.exe is too commonly used to reliably detect anything",
            "value": "d"
          },
          {
            "label": "Add a targeted filter for this specific DLL path and parent process, preserving genuine comsvcs.dll detection",
            "value": "a"
          },
          {
            "label": "Lower the rule's severity to informational so analysts stop noticing it",
            "value": "b"
          },
          {
            "label": "Broaden the selection to exclude all rundll32.exe activity going forward",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "This is the standard, root-cause-matched fix from this lesson: a targeted filter for the specific confirmed-benign case, which preserves detection of the actual malicious technique. Deleting the rule or broadly excluding all rundll32.exe activity would create a significant blind spot, and lowering severity doesn't address the underlying false-positive cause at all."
      },
      {
        "question": "A SOC-wide metric shows that 'percentage of alerts closed as false positive within SLA' is high not just for one rule, but across the majority of the rule set. What does this most strongly suggest?",
        "options": [
          {
            "label": "A single analyst is underperforming and needs additional training",
            "value": "a"
          },
          {
            "label": "A systemic tuning problem across the rule set, rather than an isolated issue with one rule",
            "value": "b"
          },
          {
            "label": "The SOC needs to hire more analysts rather than investigate any rules",
            "value": "c"
          },
          {
            "label": "CloudTrail Insights should be enabled to resolve the issue",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson specifically frames a high FP-closure rate across the broad rule set, not just one rule, as a systemic tuning signal warranting a structured, proactive review — not simply a staffing or individual-performance issue. CloudTrail Insights is an AWS anomaly-detection feature unrelated to this SOC-wide tuning metric."
      },
      {
        "question": "A detection engineer adds a filter to fix a confirmed false positive and deploys it directly to production without testing, since the fix 'obviously' works. What risk does this lesson explicitly warn against?",
        "options": [
          {
            "label": "The filter might be too narrow and therefore have no effect at all on the false positive",
            "value": "b"
          },
          {
            "label": "The filter might be too broad, silently excluding the genuine malicious activity it was never tested against",
            "value": "c"
          },
          {
            "label": "Filters can only be added by a SOC manager, never a detection engineer",
            "value": "d"
          },
          {
            "label": "Untested filters automatically expire after 24 hours",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "The lesson repeatedly emphasizes validating a fix against the original malicious sample, not just confirming it resolves the false positive — an untested filter risks silently blinding the rule to genuine attacks that happen to overlap with the filter's scope. The other options aren't concerns raised in this lesson."
      }
    ]
  },
  "detection-engineer--allowlists-and-exceptions": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Allowlists vs. Rule Filters vs. Suppression: Three Different Tools",
        "body": "The previous lesson's false-positive investigation ended with a decision to \"add an exception\" for a confirmed legitimate case. This lab covers that exception in depth — specifically, the three distinct mechanisms available for excluding known-benign activity, when each is appropriate, and how to manage exceptions responsibly over their entire lifecycle so they don't become a future security gap.\n\n### Tool 1: The Sigma rule-level filter block\nCovered in depth in the Sigma Selection Patterns lesson, an inline filter block is part of the rule's own detection logic, version-controlled alongside the rule, and combined via \"selection and not filter.\" This is the right tool when the exception is structural and universal — noise any deployment of this rule would predictably need to exclude.\n\n### Tool 2: The standalone Sigma filter document\nA separate YAML document (introduced later in this lesson) that references one or more existing rules by their id and applies additional exclusion logic without modifying the rules' own source files. This is the right tool for organization-specific exceptions that should not be hard-coded into a rule other organizations also run.\n\n### Tool 3: SIEM-native suppression\nA mechanism built into the SIEM platform itself (Splunk correlation search throttling, Microsoft Sentinel automation rules and watchlists) that suppresses or auto-closes matching alerts after the fact, entirely outside the Sigma rule's own YAML. This is the right tool for temporary, operational suppression — a scheduled maintenance window, for instance — that isn't meant to live as a permanent part of the detection's source of truth.\n\n### Choosing the right tool for a given exception\nThe central design question is always: is this exception structural (belongs inside the rule), organization-specific but durable (belongs in a standalone filter document), or purely temporary and operational (belongs in SIEM-native suppression)? Getting this choice wrong doesn't necessarily create a security gap immediately, but it does create long-term maintenance debt — a temporary suppression left in permanently, or an organization-specific exception hard-coded into a rule meant to be shared, both described further later in this lesson.",
        "codeExample": "flowchart TD\n  A[\"Confirmed FP,\\nneeds an exception\"] --> B{\"What kind\\nof exception?\"}\n  B -->|Structural, universal| C[\"Sigma inline filter\\n(in the rule itself)\"]\n  B -->|Org-specific, durable| D[\"Standalone Sigma\\nfilter document\"]\n  B -->|Temporary, operational| E[\"SIEM-native\\nsuppression\"]",
        "keyPoints": [
          "Three distinct exception mechanisms exist: the Sigma inline filter block, the standalone Sigma filter document, and SIEM-native suppression.",
          "Inline filters suit structural, universal noise; standalone filter documents suit organization-specific but durable exceptions; SIEM suppression suits temporary, operational exclusions.",
          "Choosing the wrong tool doesn't necessarily create an immediate gap, but does create long-term maintenance debt.",
          "The central design question is whether the exception is structural, organization-specific-but-durable, or purely temporary."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Sigma-Level Exceptions: The Standalone Filter Document",
        "body": "Beyond the inline filter block covered in the Sigma Selection Patterns lesson, the Sigma specification defines a separate document type specifically for exceptions that should live apart from the rule's own source — a standalone filter.\n\n### Structure of a standalone filter\nA standalone filter is its own YAML document with a title (a brief description of what it excludes) and a logsource block matching the target rules' log source. Its required filter section contains three parts: rules, a list of the specific rule IDs this filter applies to; selection, detection criteria using the exact same syntax as a rule's own selection block; and condition, the logic combining the selection (commonly just \"selection\" on its own for a simple exclusion). An optional id field (a UUID) and description provide the same provenance benefits as a rule's own metadata.\n\n### Why referencing rules by id matters\nBecause the filter references target rules by their unique id field (introduced in the Sigma Selection Patterns lesson) rather than by title or file path, the link between filter and rule survives a rule being renamed or moved, and is unambiguous even if two different rules happen to share a similar title.\n\n### When this is the right tool over an inline filter\nA standalone filter is appropriate when the exclusion is specific to this organization's environment (a specific internal admin account naming convention, for instance) and should not be hard-coded into a rule that is shared with, or pulled from, the broader SigmaHQ community repository — keeping the shared rule's own source clean and portable while still applying the organization's local exception during conversion.\n\n### How it takes effect\nWhen pySigma processes both the rule and its associated standalone filter together, the filter's exclusion logic is merged into the final converted query — from the SOC's perspective, the practical effect is identical to an inline filter, but the organization-specific logic remains cleanly separated in its own file, distinct from the shared rule source.",
        "codeExample": "title: Exclude NexaCorp Patch Agent from PowerShell Encoded Command Rule\nid: 5b8c1e3d-2a4f-4c6e-9d1b-7e3f5a9c1b3d\ndescription: NexaCorp's internal patch management tool legitimately uses an encoded PowerShell command with this fixed signature\nlogsource:\n    category: process_creation\n    product: windows\nfilter:\n    rules:\n        - 7b3e9c1a-2d4f-4a8e-9c1b-3e5f7a9b1c3d\n    selection:\n        ParentImage: 'C:\\\\Program Files\\\\NexaCorp\\\\PatchAgent\\\\agent.exe'\n        CommandLine|contains: 'Net.WebClient).DownloadFile'\n    condition: selection",
        "keyPoints": [
          "A standalone Sigma filter is a separate YAML document referencing one or more target rules by their unique id, with its own selection and condition logic.",
          "Referencing rules by id (not title or file path) keeps the filter's link to its target intact even if the rule is renamed or moved.",
          "Standalone filters are the right tool for organization-specific exceptions that shouldn't be hard-coded into a rule shared with the broader community.",
          "pySigma merges the standalone filter's logic with the rule during conversion, producing the same practical exclusion as an inline filter while keeping the source files cleanly separated."
        ]
      },
      {
        "pageNumber": 3,
        "title": "SIEM-Level Suppression: Splunk and Microsoft Sentinel Examples",
        "body": "Not every exception belongs in Sigma's own YAML at all — some suppression needs are inherently tied to the SIEM's own operational features and are better handled there, entirely outside the rule's version-controlled source.\n\n### Splunk: correlation search suppression\nIn Splunk Enterprise Security, a correlation search (the mechanism that generates notable events, Splunk's term for alerts) can be configured with throttling settings that suppress additional notable events matching specific field values for a defined period after the first one fires — commonly used to avoid repeated alerts for the same ongoing condition (a single compromised host triggering the same detection repeatedly within a short window) without needing to modify the underlying search logic itself.\n\n### Microsoft Sentinel: watchlists and automation rules\nMicrosoft Sentinel offers a watchlist feature — a reference list of values (known-good IP addresses, approved service accounts) that a query can check against — combined with automation rules that can automatically close or suppress an incident matching specific conditions, such as an entity appearing on a designated watchlist. Analytics rules can also define entity exclusions directly, preventing a specified user or IP from generating alerts under specific rule logic.\n\n### Why these belong outside the Sigma source\nBoth mechanisms operate on the deployed query's behavior within the SIEM platform itself, not on the underlying Sigma YAML — meaning they don't survive a rule being re-converted and redeployed from source unless the SIEM-side configuration is separately maintained and reapplied. This makes SIEM-native suppression appropriate specifically for exceptions tied to the operational reality of running the SIEM (a known maintenance window, a temporary noisy condition during a planned change) rather than for exceptions that should persist as part of the detection's actual logic.\n\n### The risk of using SIEM suppression as a permanent fix\nBecause SIEM-level suppression lives outside the version-controlled rule repository, it is easy for it to become invisible to the peer-review and audit-trail practices covered in the Coverage Testing lesson — a suppression rule added directly in the SIEM console, without a corresponding ticket or documentation, can persist indefinitely and be forgotten, which is exactly the allowlist rot risk covered later in this lesson.",
        "codeExample": "# Conceptual Splunk correlation search throttling configuration\n[Suspicious LSASS Access - Rule]\nthrottle.enable = 1\nthrottle.fields = host, user\nthrottle.window = 3600\n\n# Conceptual Microsoft Sentinel automation rule condition\n# \"If incident entity IP is in watchlist 'ApprovedScannerIPs', close as False Positive\"",
        "keyPoints": [
          "Splunk correlation search throttling suppresses repeated notable events for the same field values within a defined time window, without modifying the search logic.",
          "Microsoft Sentinel watchlists combined with automation rules can automatically close or suppress incidents matching specific reference-list conditions.",
          "SIEM-native suppression operates on the deployed platform, not the Sigma source, so it doesn't survive a rule being re-converted from source unless separately maintained.",
          "Suppression added directly in a SIEM console without documentation is easy to forget, creating the allowlist rot risk covered later in this lesson."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Designing a Safe Allowlist Entry: The Least-Scope Principle",
        "body": "Regardless of which of the three mechanisms is used, the single most important design principle for any exception is scope: an allowlist entry should be as narrow as the specific legitimate case actually requires, and no narrower — meaning it must still reliably match the real benign activity, but should never be broader than necessary.\n\n### Ranking specificity, from strongest to weakest\n- **Full file hash** — the strongest possible identifier, since a hash uniquely identifies the exact binary content; even a byte-for-byte identical-looking malicious file with the same name would have a different hash.\n- **Full path plus parent process plus user or account** — a strong combination when a hash isn't available or practical to maintain (for a frequently-updated legitimate tool, for instance).\n- **Path alone** — weaker, since an attacker who gains write access to that specific path could place a malicious binary there and inherit the exception.\n- **Process name alone** — the weakest and most dangerous option, since it is trivial for an attacker to name a malicious binary identically to a trusted process (the exact LOLBin-adjacent risk discussed in the Sigma Modifiers lesson's windash coverage).\n\n### Why \"never allowlist by process name alone\" is close to an absolute rule\nA process-name-only exception (excluding every event where Image equals a specific trusted binary name, regardless of its path, parent, or hash) is functionally equivalent to disabling the rule for that binary name across the entire environment — precisely the \"weak filter\" anti-pattern warned about in both the Sigma Selection Patterns lesson and the FP Analysis lesson's worked example.\n\n### Time-bounding entries where possible\nAn exception tied to a specific, known-temporary condition (a migration project, a time-limited vendor engagement) should carry an explicit expiration rather than being written as permanent by default — the lifecycle management covered later in this lesson depends on this being set deliberately at creation time, not added as an afterthought.\n\n### Documentation as part of the design, not an add-on\nEvery exception entry should record its justification, the owner responsible for it, and its planned review or expiration date at the moment it is created — treating this as integral to the exception's design, not paperwork to be completed later, which in practice often means it never gets completed at all.",
        "codeExample": "# Weakest possible exception (avoid): process name alone\nfilter_weak:\n    Image|endswith: '\\\\psexec.exe'\n\n# Strong exception: path + parent + hash, documented and time-bounded\nfilter_strong:\n    Image: 'C:\\\\Program Files\\\\NexaCorp\\\\PatchAgent\\\\psexec.exe'\n    ParentImage: 'C:\\\\Program Files\\\\NexaCorp\\\\PatchAgent\\\\orchestrator.exe'\n    Hashes|contains: 'SHA256=3F2A1B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708'\n# Owner: detection-engineering@nexacorp.example | Ticket: DET-4821 | Review by: 2026-08-01",
        "keyPoints": [
          "The least-scope principle: an exception should be exactly as narrow as the legitimate case requires — no broader.",
          "Specificity ranking from strongest to weakest: full file hash, then path+parent+user combination, then path alone, then process name alone (the weakest and most abusable).",
          "A process-name-only exception is functionally equivalent to disabling the rule for that name across the whole environment — an attacker can trivially rename a malicious binary to match.",
          "Justification, owner, and expiration date should be recorded at the moment an exception is created, not added later as an afterthought."
        ]
      },
      {
        "pageNumber": 5,
        "title": "The Allowlist Lifecycle: Creation, Review, Expiration",
        "body": "An exception is not a one-time decision — it is an ongoing commitment that needs active management across a defined lifecycle, from the moment it is created through to the point it is either renewed or retired.\n\n### Stage 1: Creation\nTriggered by a root-caused false-positive investigation (from the previous lesson) or a known, upcoming operational need. At creation, the exception is scoped according to the least-scope principle from the previous page, documented with justification/owner/expiration, and linked to the ticket or investigation that justified it.\n\n### Stage 2: Implementation and review\nThe exception (whichever of the three mechanisms is appropriate) is implemented as code — a filter block, a standalone filter document, or a SIEM suppression configuration — and submitted through the same pull-request and peer-review process as any other detection change, consistent with the detection-as-code practice from the Coverage Testing lesson.\n\n### Stage 3: Active monitoring\nWhile the exception is in place, it should be periodically confirmed to still be doing its job — still matching the legitimate case it was designed for, and not inadvertently matching anything broader than intended (a risk if, for instance, the legitimate tool it excludes is later updated and its command-line pattern changes).\n\n### Stage 4: Scheduled review\nAt the expiration date set during creation, someone — ideally an owner distinct from whoever originally created the exception, to avoid rubber-stamping — actively reviews whether the underlying justification still holds: is the legitimate tool still in use, is the exception still narrowly scoped enough, has anything changed that warrants tightening or removing it.\n\n### Stage 5: Renewal or retirement\nBased on the review, the exception is either renewed with a new expiration date (if the justification still holds) or retired entirely (if the underlying tool has been decommissioned, replaced, or the exception is no longer needed) — removed from the rule repository just as deliberately as it was added.\n\n### Why skipping any stage undermines the whole system\nAn exception created without documentation (skipping Stage 1's discipline) cannot be meaningfully reviewed at Stage 4, since no one will know why it exists or whether it's still needed — which is precisely how exceptions accumulate into the allowlist rot problem covered on the next page.",
        "codeExample": "flowchart LR\n  A[\"1. Creation:\\nscoped + documented\"] --> B[\"2. Implementation:\\nPR + peer review\"]\n  B --> C[\"3. Active monitoring\"]\n  C --> D[\"4. Scheduled review\\nat expiration\"]\n  D -->|still needed| E[\"5a. Renew with\\nnew expiration\"]\n  D -->|no longer needed| F[\"5b. Retire:\\nremove from repo\"]",
        "keyPoints": [
          "The allowlist lifecycle has five stages: creation, implementation and review, active monitoring, scheduled review, and renewal or retirement.",
          "Creation should always include justification, owner, and an explicit expiration date, since the later review stage depends on this documentation existing.",
          "The scheduled review at expiration should ideally be performed by someone other than the original creator, to avoid rubber-stamping a stale exception.",
          "Skipping the documentation discipline at creation makes a meaningful review at expiration impossible, which is how exceptions accumulate into long-term risk."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Allowlist Rot and Its Risks",
        "body": "Allowlist rot is the accumulation, over months or years, of stale, overly broad, or simply forgotten exceptions that were never retired — and it represents a genuine, often underappreciated security risk distinct from any individual detection rule's own tuning quality.\n\n### How rot accumulates\nEach individual exception, added at the time, may have been perfectly justified and appropriately scoped — but organizations change: tools get decommissioned, employees who understood the original justification leave, and without the active lifecycle management from the previous page, exceptions simply persist because removing them feels riskier than leaving them in place (a natural but ultimately mistaken bias, since an unreviewed exception's risk compounds silently over time).\n\n### The specific security risk\nAn accumulated allowlist represents institutional knowledge of exactly what the organization's detection rules will not catch — and this is exactly the kind of knowledge that is valuable to an attacker who gains any visibility into it (through an insider, a compromised detection engineer's credentials, or even a leaked internal document). A broad, stale exception for a long-decommissioned tool's file path, for instance, is a standing blind spot an attacker could exploit simply by placing a malicious file at that same path — the exact risk the least-scope principle from earlier in this lesson is designed to minimize, and one that only gets worse the longer a stale exception goes unreviewed.\n\n### Mitigations\n- **Periodic allowlist audits** — a scheduled, dedicated review (distinct from the per-exception scheduled review in the lifecycle) examining the full accumulated set of exceptions together, looking for patterns of overly broad scope or exceptions tied to decommissioned tools that individual reviews may have missed.\n- **Mandatory owner and expiration fields** — enforced at the point of creation (potentially via the same CI pipeline checks described in the Coverage Testing lesson for other rule metadata), so an exception without an assigned owner or expiration date simply cannot be merged in the first place.\n- **Automatic flagging of overdue reviews** — a scheduled job that surfaces any exception past its expiration date without a recorded review, rather than relying on individual owners to remember on their own.\n\n### The mindset shift this requires\nTreating allowlist entries with the same security scrutiny as the detections they exclude — rather than as a one-time administrative chore — is the core mindset this lesson is building toward, and it directly counters the natural but risky assumption that an exception, once added, is safe to forget about indefinitely.",
        "codeExample": "flowchart TD\n  A[\"Exception created,\\nno owner/expiration enforced\"] --> B[\"Tool decommissioned,\\noriginal author leaves\"]\n  B --> C[\"Exception never reviewed\\nor retired: allowlist rot\"]\n  C --> D[\"Stale, broad exception becomes\\na standing blind spot\"]\n  D --> E[\"Attacker exploits the\\nknown-excluded path/pattern\"]",
        "keyPoints": [
          "Allowlist rot is the accumulation of stale, overly broad, or forgotten exceptions that were never retired as the organization and its tools changed over time.",
          "An accumulated set of exceptions represents institutional knowledge of exactly what detection will not catch — valuable and dangerous if it becomes visible to an attacker.",
          "Periodic allowlist audits, mandatory owner/expiration fields enforced at creation, and automatic flagging of overdue reviews all mitigate allowlist rot.",
          "Allowlist entries deserve the same ongoing security scrutiny as the detections they exclude, not one-time administrative treatment."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Governance: Approval, Documentation, and Audit Trail",
        "body": "Beyond the technical lifecycle covered so far, a mature exception-management practice needs organizational governance — clear rules about who can create exceptions, what documentation is required, and how the resulting history is preserved for later accountability.\n\n### Required documentation fields\nConsistent with the least-scope principle's design guidance, every exception should record: the specific justification (ideally linked to the FP investigation or business need that prompted it), the responsible owner, the creation date, the planned expiration or review date, and the linked ticket or change request. Some organizations also record the specific analyst or engineer who approved the exception, distinct from whoever authored it, providing a clear separation between the person requesting an exception and the person accountable for approving its scope.\n\n### Approval authority: who should be able to add exceptions\nLimiting the ability to merge a new exception to a defined set of detection engineers or a designated review role — rather than allowing any analyst to add one unilaterally — prevents uncontrolled sprawl. This mirrors the pull-request peer-review requirement from the Coverage Testing lesson, but with a specific emphasis here: exceptions are inherently higher-risk changes than new detections, since they reduce visibility rather than add it, and arguably deserve at least the same level of scrutiny, if not more.\n\n### Audit trail through version control\nBecause exceptions implemented as Sigma filter blocks or standalone filter documents live in the same version-controlled repository as the rules themselves (the detection-as-code practice from the Coverage Testing lesson), the full git history of every exception — who added it, when, and with what justification in the commit message and linked pull request — is preserved automatically, without needing a separate governance system.\n\n### Governance for SIEM-native suppression\nBecause SIEM-native suppression (covered earlier in this lesson) often lives outside version control, its governance requires more deliberate effort: many organizations maintain a supplementary tracking mechanism (a dedicated ticket type, a shared register) specifically to prevent SIEM-console suppression rules from becoming invisible to the same audit and review practices applied to version-controlled exceptions — directly addressing the risk flagged earlier in this lesson.\n\n### Periodic access review\nJust as the exceptions themselves need periodic review, the list of people with approval authority to create them should also be periodically reviewed — ensuring the governance boundary stays intact as team membership and roles change over time.",
        "codeExample": "# Required fields for any new exception pull request, enforced by a PR template\n# Justification: [linked FP investigation ticket]\n# Owner: [responsible engineer or team]\n# Approved by: [reviewer, distinct from author]\n# Created: [date]\n# Review/expiration date: [date]\n# Scope: [hash / path+parent+user / path only — and why this level was chosen]",
        "keyPoints": [
          "Every exception should record justification, owner, creation date, review/expiration date, linked ticket, and ideally a distinct approver from the author.",
          "Limiting exception-creation authority to designated detection engineers or reviewers, rather than any analyst, prevents uncontrolled sprawl.",
          "Version-controlled exceptions (filter blocks, standalone filter documents) get their audit trail automatically through git history; SIEM-native suppression needs a deliberate supplementary tracking mechanism.",
          "The list of people with approval authority itself should be periodically reviewed, just like the exceptions they approve."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: Building and Retiring an Exception End-to-End",
        "body": "This final page walks through the complete lifecycle from a real false-positive finding to an eventual, deliberate retirement, consolidating every practice covered in this lab.\n\n### Step 1 — Start from a root-caused false positive\nFollowing directly from the previous lesson's FP Analysis workflow: a confirmed Category A false positive (legitimate tooling resembling attacker behavior) — NexaCorp's patch management tool legitimately triggering the encoded-PowerShell detection built in the Sigma Modifiers lesson's worked example.\n\n### Step 2 — Choose the right mechanism\nSince this exception is organization-specific (tied to NexaCorp's own internal tool) and durable (expected to remain valid for as long as the tool is in use) rather than temporary, a standalone Sigma filter document is the appropriate choice over either an inline filter (which would hard-code NexaCorp-specific detail into a potentially-shared rule) or SIEM-native suppression (appropriate only for temporary, operational needs).\n\n### Step 3 — Scope it narrowly and document it\nFollowing the least-scope principle: reference the patch tool's specific path, parent process, and ideally its file hash rather than any single weaker field, and record justification (linked to the FP investigation ticket), owner (the detection engineering team), and a review date six months out.\n\n### Step 4 — Submit, test, and deploy\nFollowing detection-as-code practice: a pull request, CI validation confirming the exception still allows the rule to match the original malicious encoded-PowerShell sample while now excluding the patch tool's specific pattern, peer review by a designated approver, and merge.\n\n### Step 5 — Monitor and review\nAt the six-month review date, the assigned owner confirms the patch tool is still in active use with the same command-line signature — if so, the exception is renewed with a new expiration date; if the tool has since been replaced or retired, the exception is removed from the repository in the same disciplined, reviewed manner it was added.\n\n### Why this end-to-end discipline matters\nAn exception managed this way — narrowly scoped, documented, peer-reviewed, and eventually either renewed or retired on schedule — never becomes part of the allowlist rot problem described earlier in this lesson. It remains, throughout its life, a precisely understood, deliberately maintained piece of the organization's detection logic rather than an invisible, accumulating blind spot.",
        "codeExample": "flowchart TD\n  A[\"1. Root-caused FP\\n(Category A: legit tooling)\"] --> B[\"2. Choose mechanism:\\nstandalone filter document\"]\n  B --> C[\"3. Scope narrowly +\\ndocument justification/owner/expiry\"]\n  C --> D[\"4. PR, CI test\\n(still catches malicious sample),\\npeer review, deploy\"]\n  D --> E[\"5. Review at expiry:\\nrenew or retire\"]",
        "keyPoints": [
          "An end-to-end exception lifecycle starts from a root-caused false positive, not an ad hoc noise complaint.",
          "The mechanism (inline filter, standalone filter, or SIEM suppression) should be chosen deliberately based on whether the exception is structural, organization-specific-durable, or temporary.",
          "Testing must confirm the exception still allows detection of the original malicious sample while excluding the newly-scoped benign case.",
          "A well-managed exception is eventually either renewed or retired on schedule — never left to become an invisible, accumulating blind spot."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A detection engineer needs to exclude a legitimate internal tool's specific command-line pattern from a shared Sigma rule pulled from the public SigmaHQ repository, without modifying that shared rule's own source file. Which mechanism is most appropriate?",
        "options": [
          {
            "label": "An inline filter block added directly to the shared rule's YAML",
            "value": "c"
          },
          {
            "label": "A standalone Sigma filter document referencing the shared rule by its id",
            "value": "d"
          },
          {
            "label": "Deleting the shared rule entirely and writing a new one from scratch",
            "value": "a"
          },
          {
            "label": "A comment added to the shared rule's description field explaining the exception informally",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "A standalone filter document is specifically designed for organization-specific exceptions that shouldn't be hard-coded into a shared rule's own source — it references the rule by id and applies separately. Modifying the shared rule directly would complicate future updates from the upstream source, deleting and rewriting the rule loses the benefit of using the shared, peer-reviewed version, and an informal comment provides no actual enforcement."
      },
      {
        "question": "Which of the following is the weakest, most exploitable way to scope an allowlist exception?",
        "options": [
          {
            "label": "Matching on the file's full SHA256 hash",
            "value": "c"
          },
          {
            "label": "Matching on the full path, parent process, and executing account together",
            "value": "d"
          },
          {
            "label": "Matching on the process name alone, regardless of path or hash",
            "value": "a"
          },
          {
            "label": "Matching on the full path alone",
            "value": "b"
          }
        ],
        "answer": "a",
        "explanation": "A process-name-only match is the weakest option described in this lesson, since an attacker can trivially name a malicious binary identically to a trusted process, inheriting the exception. A full hash is the strongest identifier, path+parent+account is a strong combination, and path alone is weaker than that combination but still meaningfully more specific than name alone."
      },
      {
        "question": "An exception was created two years ago for a tool that was decommissioned eighteen months ago, but no one reviewed or removed the exception since the original creator left the company shortly after adding it. What does this lesson call this specific accumulated risk?",
        "options": [
          {
            "label": "Detection-as-code drift",
            "value": "a"
          },
          {
            "label": "Allowlist rot",
            "value": "b"
          },
          {
            "label": "False negative inflation",
            "value": "c"
          },
          {
            "label": "CloudTrail Insight decay",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "This scenario — a stale, unreviewed, forgotten exception for a decommissioned tool — is precisely the definition of allowlist rot given in this lesson. The other terms either don't appear in this lesson or refer to unrelated concepts from earlier lessons in this path."
      },
      {
        "question": "Why does this lesson recommend that a distinct approver, rather than the original author, review an exception at its scheduled expiration date?",
        "options": [
          {
            "label": "Because the original author is legally prohibited from reviewing their own work",
            "value": "b"
          },
          {
            "label": "To avoid rubber-stamping a stale exception, since a distinct reviewer is more likely to genuinely re-evaluate whether the justification still holds",
            "value": "c"
          },
          {
            "label": "Because Sigma's specification technically forbids the same person from both creating and reviewing a filter",
            "value": "d"
          },
          {
            "label": "Because only SIEM administrators are permitted to review exceptions",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "The lesson's rationale is specifically about avoiding rubber-stamping — a distinct reviewer is more likely to critically re-examine whether an exception is still justified, rather than reflexively renewing their own past decision. There is no legal prohibition, no such Sigma specification rule, and review authority is not restricted only to SIEM administrators."
      },
      {
        "question": "A false positive is caused by a temporary, one-week maintenance window during which a specific automated script triggers a rule repeatedly. Which mechanism is most appropriate for this specific situation?",
        "options": [
          {
            "label": "A permanent inline Sigma filter with no expiration",
            "value": "b"
          },
          {
            "label": "A standalone Sigma filter document intended to remain in the rule repository indefinitely",
            "value": "c"
          },
          {
            "label": "SIEM-native suppression scoped to the maintenance window's duration",
            "value": "d"
          },
          {
            "label": "Deleting the rule entirely until the maintenance window ends",
            "value": "a"
          }
        ],
        "answer": "d",
        "explanation": "This lesson specifically identifies SIEM-native suppression as the right tool for temporary, operational exceptions like a scheduled maintenance window — not meant to become a permanent part of the detection's source of truth. A permanent inline filter or an indefinite standalone filter document would outlive the actual temporary need, and deleting the rule entirely would remove detection capability far more broadly than necessary."
      }
    ]
  },
  "detection-engineer--tiered-severities": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Severity Tiers Exist: Triage Under Alert Volume",
        "body": "Every lesson in this path so far has focused on individual detections — writing them, testing them, tuning them, and managing their exceptions. This final lesson addresses a different, organization-wide question: once dozens or hundreds of rules are deployed and firing, in what order should an analyst actually work through the resulting queue of alerts?\n\n### The core problem\nA SOC (Security Operations Center) analyst on a single shift may face far more alerts than can be individually investigated with equal depth and speed. Without a principled way to rank them, analysts either work alerts in arrival order (treating a routine, low-impact alert on a test server identically to a credential-dumping alert on a domain controller simply because it happened to fire first) or rely on inconsistent, ad hoc personal judgment that varies analyst to analyst and shift to shift.\n\n### What severity tiering solves\nSeverity tiering assigns each alert a rank — commonly Critical, High, Medium, Low, and Informational — reflecting a structured combination of how confident the detection is and how much genuine harm the underlying activity could cause if it is real. This lets a SOC establish clear triage order and service-level expectations (how quickly a Critical alert must be acknowledged, versus a Low one) rather than leaving prioritization to chance.\n\n### The relationship to everything covered earlier in this path\nThe Sigma level field (introduced in the Sigma Selection Patterns lesson) is a rule author's starting-point severity assessment, made once, at authoring time, without full knowledge of the specific asset or user context any individual future alert will involve. This lesson covers how that starting point gets refined — and sometimes overridden — once a specific alert fires against a specific asset, closing the loop on the full lifecycle of a detection from authored rule to triaged, prioritized alert.\n\n### What this lesson builds toward\nBy the end of this lesson, a detection engineer should be able to design a severity scoring model that accounts for more than just the rule's static level field, recognize when the same rule should reasonably produce different priority outcomes on different assets, and avoid the common severity-design mistakes that undermine effective triage.",
        "codeExample": "flowchart LR\n  A[\"100 alerts fire\\nacross a shift\"] --> B{\"No severity\\ntiering?\"}\n  B -->|Yes| C[\"Analyst works in\\narrival order —\\ncritical alert may\\nwait behind noise\"]\n  B -->|No, tiered| D[\"Analyst works\\nCritical first,\\nthen High, etc.\"]",
        "keyPoints": [
          "Severity tiering ranks alerts (commonly Critical/High/Medium/Low/Informational) so analysts triage in a principled order rather than arrival order or ad hoc judgment.",
          "A Sigma rule's level field is a starting-point severity set at authoring time, without knowledge of the specific asset or user context any future individual alert will involve.",
          "Severity tiering enables consistent service-level expectations (how quickly each tier must be acknowledged) across the SOC.",
          "This lesson covers how the rule-level starting point gets refined into a per-alert priority once real context is available."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Standard Severity Tiers: Critical, High, Medium, Low, Informational",
        "body": "Most SIEM platforms and detection frameworks converge on a similar five-tier severity scale, even though the exact criteria for each tier varies by organization and vendor.\n\n### The common five tiers\n- **Critical** — activity strongly indicating an active, high-impact compromise in progress (confirmed credential dumping on a domain controller, active ransomware encryption behavior) requiring immediate response.\n- **High** — activity with a strong likelihood of malicious intent and meaningful potential impact, but not yet confirmed as an active, unfolding compromise (a single high-confidence indicator on a standard workstation, for instance).\n- **Medium** — activity that is suspicious and worth investigation, but with either lower confidence in malicious intent or lower potential impact than High.\n- **Low** — activity that is a minor deviation from expected behavior, often useful as supporting context during a broader investigation but rarely actionable in isolation.\n- **Informational** — activity logged for visibility, audit, or future correlation purposes, not expected to require analyst action on its own.\n\n### Where these tiers come from in practice\nThe Sigma level field (informational, low, medium, high, critical) directly mirrors this scale, and most SIEM platforms use the same or a very similar taxonomy for their own native alerting — CrowdStrike Falcon, for instance, assigns each detection both an objective numeric score and a corresponding severity category following a comparable structure, and Microsoft Sentinel's analytics rules carry their own severity field using this same five-tier language.\n\n### Why the tier alone is not the whole picture\nA rule's level field, set once at authoring time as discussed on the previous page, reflects the rule author's general assessment of the technique's severity in the abstract — it does not, and cannot, account for which specific asset, user, or environment a future alert will actually involve. The remainder of this lesson covers how that static starting point gets combined with real per-alert context to produce a final, actionable priority.",
        "codeExample": "# Sigma's level field, the common five-tier baseline\nlevel: critical   # active, high-impact compromise\nlevel: high       # strong malicious likelihood, meaningful impact\nlevel: medium     # suspicious, worth investigation\nlevel: low        # minor deviation, supporting context\nlevel: informational  # logged for visibility/audit, not typically actionable alone",
        "keyPoints": [
          "The common five-tier scale is Critical, High, Medium, Low, and Informational, used by Sigma's level field and most SIEM platforms' native severity fields alike.",
          "Critical implies an active, high-impact compromise in progress; Informational implies logging for visibility with no expected standalone action.",
          "CrowdStrike Falcon and Microsoft Sentinel both use comparable severity taxonomies for their own native detections and analytics rules.",
          "A rule's static level field is a general, authoring-time assessment — it cannot account for the specific asset or user context of any individual future alert."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Risk Scoring Inputs: Likelihood, Impact, Asset Criticality, and Confidence",
        "body": "Beyond the rule's static level field, a more complete severity assessment for any individual alert combines several distinct inputs — treating severity as a calculated outcome of multiple factors, rather than a single fixed label attached to the rule.\n\n### The classical risk equation\nRisk management generally expresses risk as a function of likelihood and impact: how probable is it that the observed activity represents a genuine threat, multiplied by how much harm would result if it does. This general framing, familiar from broader risk management practice, is the conceptual starting point for alert-level severity scoring.\n\n### Extending the model with detection-specific inputs\nIn practical SOC alert triage, this general risk framing is typically extended with inputs specific to detection engineering:\n- **Rule confidence/precision** — informed directly by the false-positive-rate tracking covered in the FP Analysis lesson; a rule with a historically strong precision record deserves more trust in its individual alerts than one with a poor track record, even if both carry the same static level field.\n- **Asset criticality** — is the affected host a domain controller, a database server holding regulated data, or a disposable test virtual machine? The same underlying technique carries very different real-world consequences depending on the answer.\n- **User privilege** — is the associated account a standard user or a privileged administrator whose compromise would grant far broader access?\n- **ATT&CK tactic severity** — techniques under certain tactics (Impact, for instance, covering destructive actions like data encryption or deletion) generally carry more immediate severity than techniques under tactics like Discovery, reflecting how close the observed behavior is to causing irreversible harm.\n\n### Vendor implementations of this extended model\nMicrosoft Sentinel's Fusion correlation engine combines multiple, individually lower-severity signals into a single higher-confidence composite alert when their combination matches a known attack pattern — an implementation of exactly this \"combine multiple inputs\" principle at the platform level, rather than relying on any single rule's static severity alone.\n\n### Why no single formula is universal\nDifferent organizations weight these inputs differently based on their own risk tolerance and asset landscape — the goal of this lesson is not to prescribe one specific formula, but to ensure every input that matters is deliberately considered somewhere in the organization's severity model, rather than silently ignored.",
        "codeExample": "flowchart LR\n  A[\"Rule confidence\\n(precision history)\"] --> E[\"Combined\\nalert priority\"]\n  B[\"Asset criticality\"] --> E\n  C[\"User privilege\"] --> E\n  D[\"ATT&CK tactic\\nseverity\"] --> E",
        "keyPoints": [
          "Classical risk is a function of likelihood and impact; SOC alert scoring extends this with detection-specific inputs.",
          "Rule confidence (from FP-rate tracking), asset criticality, user privilege, and ATT&CK tactic severity are all common extended inputs beyond the rule's static level field.",
          "Microsoft Sentinel's Fusion correlation engine implements this combine-multiple-inputs principle at the platform level, producing composite alerts from multiple lower-severity signals.",
          "No single universal formula exists; the goal is ensuring every relevant input is deliberately considered in the organization's own severity model."
        ]
      },
      {
        "pageNumber": 4,
        "title": "NIST's Impact-Based Categorization: Functional, Information, Recoverability",
        "body": "While the earlier pages in this lesson focus on scoring individual alerts before an incident is confirmed, NIST (the U.S. National Institute of Standards and Technology) provides a complementary categorization scheme that applies once an incident has actually been declared — useful context for understanding how alert-level severity connects to formal incident response prioritization.\n\n### NIST SP 800-61 and its incident categorization\nNIST Special Publication 800-61 has long provided guidance on incident handling, including a scheme (originally detailed in Revision 2, the Computer Security Incident Handling Guide) for categorizing a confirmed incident's severity along three independent dimensions:\n- **Functional Impact** — the effect on the organization's ability to provide its normal business functions or services, ranging from none through low, medium, and high.\n- **Information Impact** — the type of information affected, such as a privacy breach, a proprietary-data breach, or an integrity loss.\n- **Recoverability Effort** — the resources required to recover, ranging from regular (recovery is predictable with existing resources), through supplemented and extended, up to not recoverable (for example, when sensitive data has already been exfiltrated and publicly posted, an outcome no recovery effort can undo).\n\n### The current framework: NIST SP 800-61 Revision 3\nIn April 2025, NIST published Revision 3, retitled Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile, which reframes incident response guidance around the six functions of the NIST Cybersecurity Framework (CSF) 2.0 — Govern, Identify, Protect, Detect, Respond, and Recover — rather than the four-phase lifecycle from Revision 2 (Preparation; Detection and Analysis; Containment, Eradication, and Recovery; Post-Incident Activity). Both framings remain useful for a detection engineer to recognize: the CSF 2.0 functions describe the broader organizational risk-management context an incident sits within, while the earlier four-phase lifecycle remains a widely-referenced, practical description of the operational sequence an incident response actually follows.\n\n### Why this matters for a detection engineer, not just an incident responder\nThis impact-based categorization operates at a different level than the per-alert severity scoring covered earlier in this lesson — it applies once activity is confirmed as a genuine incident, informing how much organizational response effort to mobilize, whereas alert-level severity tiering determines which alerts get analyst attention first, before an incident has necessarily been confirmed at all. Understanding both levels helps a detection engineer design alert severity that feeds naturally into, rather than conflicts with, the organization's formal incident categorization once escalation occurs.",
        "codeExample": "# NIST SP 800-61's incident categorization dimensions (independent of each other)\n# Functional Impact:     None -> Low -> Medium -> High\n# Information Impact:    None -> Privacy Breach -> Proprietary Breach -> Integrity Loss\n# Recoverability Effort: Regular -> Supplemented -> Extended -> Not Recoverable",
        "keyPoints": [
          "NIST SP 800-61 provides a scheme for categorizing a confirmed incident's severity along Functional Impact, Information Impact, and Recoverability Effort.",
          "NIST SP 800-61 Revision 3 (April 2025) reframes incident response around the six NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover), superseding Revision 2's four-phase lifecycle (Preparation; Detection and Analysis; Containment, Eradication, and Recovery; Post-Incident Activity).",
          "Recoverability Effort's most severe category, Not Recoverable, applies when an outcome (such as publicly-posted exfiltrated data) cannot be undone by any amount of recovery effort.",
          "This impact-based categorization applies to confirmed incidents and operates at a different level than the pre-confirmation, per-alert severity tiering covered earlier in this lesson."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Building a Severity Matrix",
        "body": "With the individual inputs from earlier pages established, a severity matrix is the practical tool that combines them into a consistent, repeatable scoring approach a SOC can apply uniformly across every alert, rather than relying on case-by-case judgment for each one.\n\n### A simple two-dimensional matrix\nOne common, accessible approach cross-references detection confidence against asset criticality:\n\n| Confidence \\\\ Asset criticality | Crown jewel | Standard | Low-value |\n|---|---|---|---|\n| Confirmed malicious | Critical | Critical | High |\n| Likely malicious | Critical | High | Medium |\n| Suspicious | High | Medium | Low |\n| Anomalous, possibly benign | Medium | Low | Informational |\n\n### Reading the matrix\nThe same underlying detection confidence produces a different final tier depending on asset criticality — a \"suspicious\" finding on a crown-jewel asset (a domain controller, a primary financial database) rises to High, while the identical confidence level on a low-value asset (a disposable test VM) settles at Low. This directly operationalizes the \"combine likelihood and impact\" risk framing from earlier in this lesson into a lookup table any analyst or automation can apply consistently.\n\n### Extending the matrix with additional dimensions\nA more sophisticated model might add a third dimension (user privilege, for instance), producing a three-dimensional matrix or, more commonly in practice, a weighted-scoring formula that avoids the combinatorial explosion of a matrix with too many dimensions to remain readable as a simple table.\n\n### Where the matrix gets applied\nThis matrix (or its scoring-formula equivalent) is typically implemented as enrichment logic in the SIEM or SOAR (Security Orchestration, Automation, and Response) platform — automatically looking up the affected asset's criticality tag and combining it with the rule's confidence level to compute a final priority score at alert time, rather than requiring an analyst to manually consult the matrix for every single alert.\n\n### The organizational work this depends on\nA severity matrix is only as good as the asset criticality data feeding it — this depends on the organization maintaining an accurate, up-to-date asset inventory with criticality tags assigned, a data-quality dependency worth recognizing explicitly, since a matrix fed with stale or missing asset criticality data will silently misprioritize alerts regardless of how well-designed the matrix itself is.",
        "codeExample": "// Simplified SOAR enrichment logic implementing the severity matrix\nfunction computeFinalSeverity(ruleConfidence, assetCriticality) {\n  const matrix = {\n    confirmed:   { crown_jewel: \"Critical\", standard: \"Critical\", low_value: \"High\" },\n    likely:      { crown_jewel: \"Critical\", standard: \"High\",     low_value: \"Medium\" },\n    suspicious:  { crown_jewel: \"High\",     standard: \"Medium\",   low_value: \"Low\" },\n    anomalous:   { crown_jewel: \"Medium\",   standard: \"Low\",      low_value: \"Informational\" },\n  };\n  return matrix[ruleConfidence][assetCriticality];\n}",
        "keyPoints": [
          "A severity matrix cross-references detection confidence against asset criticality, producing a consistent, repeatable final tier for every alert combination.",
          "The same confidence level can produce different final tiers depending on asset criticality — operationalizing the likelihood-times-impact risk framing as a lookup table.",
          "Matrices are typically implemented as automated enrichment logic in a SIEM or SOAR platform, not manually consulted by analysts per alert.",
          "A severity matrix is only as reliable as the asset criticality data feeding it — stale or missing asset inventory data silently undermines the whole model."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Dynamic Severity: Why the Same Rule Can Fire at Different Tiers",
        "body": "The severity matrix from the previous page implies a conclusion worth stating explicitly: a single Sigma rule, with one static level field, can and should produce alerts at different final priority tiers depending on the specific context each individual firing occurs in — severity is dynamic per alert, not fixed per rule.\n\n### A worked example: the same LSASS-access rule, two outcomes\nThe T1003.001 LSASS-access detection built in the Sigma Selection Patterns lesson carries a static level: high in its own YAML. When this rule fires on a domain controller under a privileged administrator account, the severity matrix from the previous page would push the final tier to Critical, reflecting the crown-jewel asset criticality. The exact same rule, firing with the exact same confidence level on a disposable test virtual machine under a standard user account, might settle at Medium under the same matrix — a meaningfully different, and entirely appropriate, real-world priority for what is, in terms of raw detection logic, an identical rule match.\n\n### Downward adjustment: interaction with allowlists and exceptions\nDynamic severity adjustment can also work downward: if the specific matched pattern is very close to, but not quite matching, a recently-added exception from the Allowlists & Exceptions lab (a pending review for a newly-observed but not-yet-fully-documented legitimate tool variant, for instance), a SOAR enrichment step might reasonably reduce the alert's priority pending that review, rather than treating it identically to a completely unexplained match.\n\n### Why this requires enrichment logic beyond the rule itself\nNone of this dynamic adjustment is expressed in the Sigma rule's own level field — it happens downstream, in the SIEM's or SOAR's enrichment and scoring layer that has access to real-time asset criticality, user privilege, and exception-status context the rule author could never have anticipated at authoring time.\n\n### The practical benefit for the SOC\nDynamic severity means an analyst's triage queue genuinely reflects real-world risk at the moment of triage, rather than a static, one-size-fits-all severity assigned once, months or years earlier, by whoever originally authored the rule — directly addressing the triage-under-volume problem that opened this lesson.",
        "codeExample": "flowchart LR\n  A[\"Same Sigma rule:\\nlevel: high\"] --> B[\"Fires on domain\\ncontroller, admin user\"]\n  A --> C[\"Fires on test VM,\\nstandard user\"]\n  B --> D[\"Final tier:\\nCritical\"]\n  C --> E[\"Final tier:\\nMedium\"]",
        "keyPoints": [
          "A single Sigma rule with one static level field can and should produce different final alert tiers depending on the specific asset and user context of each individual firing.",
          "Dynamic severity is computed downstream in SIEM/SOAR enrichment logic, using real-time asset criticality and user privilege data the rule author couldn't have anticipated.",
          "Dynamic adjustment can work downward too — a near-match to a pending, not-yet-finalized exception might reasonably reduce priority pending review.",
          "Dynamic severity ensures an analyst's triage queue reflects real-world risk at the moment of triage, not a static assignment made once at authoring time."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Common Mistakes in Severity Design",
        "body": "Having covered the tiers, inputs, matrix design, and dynamic adjustment, this page catalogs the recurring mistakes that undermine an otherwise well-designed severity system — several of which connect directly back to concepts from earlier lessons in this path.\n\n### Mistake 1: Static severity with no asset-context adjustment\nTreating a rule's level field as the final, unadjusted priority for every alert it generates — exactly the problem the severity matrix and dynamic severity pages in this lesson are designed to solve — means a crown-jewel-asset alert and a disposable-test-VM alert from the identical rule get identical priority, hiding genuinely urgent alerts among low-stakes noise.\n\n### Mistake 2: Too many severity tiers\nWhile the five-tier scale from earlier in this lesson is a widely-used baseline, some organizations introduce additional, finely-graded tiers (Critical-1, Critical-2, and so on) in an attempt at greater precision — but beyond a certain point, additional tiers create decision paralysis for analysts trying to distinguish between adjacent, closely-defined categories, without providing proportionally more useful triage information.\n\n### Mistake 3: Conflating detection confidence with business impact\nA very high-confidence detection on a genuinely low-value asset should not automatically outrank a lower-confidence, more ambiguous detection on a crown-jewel asset — these are two distinct inputs (confidence and impact, echoing the risk equation from earlier in this lesson) that need to be combined deliberately, not treated as interchangeable or letting one dominate the scoring entirely.\n\n### Mistake 4: Never revisiting severity after repeated benign firings\nA rule whose real-world precision, tracked using the FP Analysis lesson's metrics, turns out to be consistently poor deserves a severity reassessment (in addition to the tuning work covered in that lesson) — continuing to label a chronically noisy rule's alerts as High or Critical, despite a well-documented poor precision track record, undermines the credibility of the severity system as a whole and accelerates the alert-fatigue problem this lesson opened with.\n\n### Mistake 5: Building the matrix before the underlying data exists\nDesigning an elaborate severity matrix that depends on asset criticality tags or user privilege data the organization has not actually and reliably populated across its asset inventory produces a system that looks rigorous on paper but silently defaults to incorrect assumptions in practice — the data-quality dependency flagged explicitly on the matrix-design page deserves to be resolved before, not after, the matrix goes into production.",
        "codeExample": "# Anti-pattern: static severity, no context, ignored precision history\nrule_name,level,precision_last_90_days,asset_context_used\nSuspicious_LSASS_Access,high,0.07,none   # chronically noisy, never reassessed, no asset weighting\n\n# Better: precision-aware, context-aware\nrule_name,level,precision_last_90_days,asset_context_used\nSuspicious_LSASS_Access,high,0.07,matrix_applied   # feeds into dynamic severity + flagged for tuning",
        "keyPoints": [
          "Static, unadjusted severity treats identical-confidence alerts on crown-jewel and low-value assets the same, hiding urgent alerts among noise.",
          "Too many finely-graded severity tiers create analyst decision paralysis without proportionally improving triage quality.",
          "Detection confidence and business impact are distinct inputs that must be combined deliberately, not conflated or allowed to dominate one another.",
          "A rule with a well-documented poor precision track record (from FP Analysis lesson metrics) deserves severity reassessment, not just tuning, to avoid undermining the whole severity system's credibility."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: Triage Order in a Tiered Queue",
        "body": "This final page brings every concept from this lesson — and, in many ways, from this entire Learning Path — together into the practical triage workflow an analyst follows when facing a queue of tiered alerts during a shift.\n\n### Step 1 — Work tiers in strict priority order\nCritical alerts are addressed before any High alert is opened, High before any Medium, and so on — regardless of arrival time, directly solving the triage-under-volume problem this lesson opened with.\n\n### Step 2 — Use the combined score as a tiebreaker within a tier\nWhen multiple alerts share the same tier, the underlying combined confidence-times-impact score (from the severity matrix) serves as a finer-grained tiebreaker, ensuring the most urgent alerts within a tier still get addressed first even among peers sharing the same broad label.\n\n### Step 3 — Apply tier-specific service-level expectations\nA mature SOC typically defines explicit acknowledgment and initial-response expectations per tier — for example, a Critical alert acknowledged within minutes, a High alert within an hour, a Medium alert within a shift, and a Low alert reviewed in aggregate rather than individually — giving analysts and management a shared, explicit standard rather than an implicit, inconsistent one.\n\n### Step 4 — Escalate per the organization's incident response process\nIf triage confirms a Critical or High alert represents a genuine, active incident, it escalates into the organization's formal incident response process — where, as covered earlier in this lesson, NIST's impact-based categorization (Functional Impact, Information Impact, Recoverability Effort) takes over as the framework for scoping the organizational response, distinct from the alert-level tiering that got the incident noticed in the first place.\n\n### Step 5 — Feed outcomes back into the severity model\nEvery confirmed true or false positive outcome feeds back into the precision tracking from the FP Analysis lesson, which in turn informs whether a given rule's contribution to the severity matrix needs adjustment — closing the loop between real-world triage outcomes and the ongoing refinement of the severity system itself.\n\n### Why this closes the entire Detection Engineer learning path\nFrom authoring a precise Sigma rule, through testing it and mapping its coverage, through understanding the telemetry it depends on, through tuning out its false positives and managing its exceptions, to finally ensuring it surfaces at the right priority when it matters — this lesson's triage workflow is where every earlier lesson's work actually pays off, in the analyst's queue, at the moment a real alert needs a real decision.",
        "codeExample": "flowchart TD\n  A[\"Alert queue,\\ntiered\"] --> B[\"1. Work Critical\\nbefore High before\\nMedium before Low\"]\n  B --> C[\"2. Use combined score\\nas tiebreaker within a tier\"]\n  C --> D[\"3. Apply tier-specific\\nSLA expectations\"]\n  D --> E[\"4. Escalate confirmed\\nincidents to formal IR process\"]\n  E --> F[\"5. Feed outcome back\\ninto precision tracking\\n+ severity model\"]",
        "keyPoints": [
          "Alerts are triaged in strict tier order (Critical, then High, then Medium, then Low), with the combined confidence-impact score as a tiebreaker within a tier.",
          "Tier-specific service-level expectations (acknowledgment and response times per tier) give the SOC an explicit, shared triage standard.",
          "A confirmed incident escalates into the formal incident response process, where NIST's impact-based categorization takes over from alert-level tiering.",
          "Every triage outcome feeds back into precision tracking and the severity model, closing the loop between real-world results and ongoing detection engineering refinement."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A SOC has no formal severity tiering and analysts simply work alerts in the order they arrive. What specific problem does this lesson identify with that approach?",
        "options": [
          {
            "label": "It is technically impossible for a SIEM to display alerts in any order other than arrival order",
            "value": "d"
          },
          {
            "label": "A routine, low-impact alert could be worked before a credential-dumping alert on a domain controller, simply because it happened to fire first",
            "value": "a"
          },
          {
            "label": "Arrival-order triage is required by NIST SP 800-61",
            "value": "b"
          },
          {
            "label": "Arrival-order triage automatically maximizes analyst efficiency",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "The lesson opens by identifying exactly this problem: without tiering, a routine alert and a genuinely urgent one get treated identically if they happen to arrive in the wrong order. SIEMs can absolutely sort by severity, NIST SP 800-61 doesn't mandate arrival-order triage, and arrival order does not maximize efficiency — it's presented as the problem this lesson solves, not a benefit."
      },
      {
        "question": "A Sigma rule has level: high set in its YAML. According to this lesson, what does this field represent?",
        "options": [
          {
            "label": "The final, unchangeable priority every alert from this rule will always carry",
            "value": "a"
          },
          {
            "label": "A starting-point severity, later refined by per-alert context like asset criticality once it actually fires",
            "value": "b"
          },
          {
            "label": "A guarantee that the activity is a confirmed incident requiring formal NIST SP 800-61 categorization",
            "value": "c"
          },
          {
            "label": "The number of times the rule has fired in the past 90 days",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explicitly frames the level field as a starting point set at authoring time, without knowledge of the specific future context each alert will involve — dynamic severity (covered later in the lesson) refines it per alert using real asset and user context. It is not a fixed final priority, does not by itself confirm an incident, and has nothing to do with historical firing counts."
      },
      {
        "question": "Using the severity matrix from this lesson, a 'suspicious' confidence-level detection fires on a crown-jewel asset (such as a domain controller), while the same confidence level also fires on a low-value test VM. What does the matrix predict?",
        "options": [
          {
            "label": "Both alerts receive identical final severity, since the underlying rule confidence is the same",
            "value": "b"
          },
          {
            "label": "The crown-jewel alert resolves to a higher tier (High) than the low-value alert (Low), despite identical confidence",
            "value": "c"
          },
          {
            "label": "The low-value asset's alert always resolves higher, since test systems are inherently riskier",
            "value": "d"
          },
          {
            "label": "Severity matrices cannot account for asset criticality at all",
            "value": "a"
          }
        ],
        "answer": "c",
        "explanation": "The whole point of the severity matrix, and the worked example on the dynamic-severity page, is that identical detection confidence produces different final tiers depending on asset criticality — High for crown-jewel, Low for low-value in this specific matrix. Identical severity regardless of asset would defeat the matrix's purpose, and test systems being inherently riskier than crown-jewel assets isn't the model's logic at all."
      },
      {
        "question": "A domain controller and a disposable test virtual machine both trigger the same T1003.001 LSASS-access Sigma rule (level: high) with identical detection confidence. Under dynamic severity, what is the expected outcome?",
        "options": [
          {
            "label": "Both alerts must remain at exactly level: high, since that is what the Sigma rule specifies and it cannot be changed downstream",
            "value": "c"
          },
          {
            "label": "The two alerts can reasonably resolve to different final priorities (for example, Critical versus Medium) based on asset criticality, computed by downstream SIEM/SOAR enrichment logic",
            "value": "d"
          },
          {
            "label": "The test VM alert is automatically deleted since test systems are excluded from all detection",
            "value": "a"
          },
          {
            "label": "Both alerts are merged into a single alert regardless of which host triggered them",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "This is exactly the worked example from the Dynamic Severity page: the same rule and confidence level can and should resolve to different final tiers depending on asset criticality, computed downstream in enrichment logic beyond the rule's own static level field. The static field is a starting point, not an unchangeable final value; test systems aren't excluded from detection entirely, and the two alerts remain distinct rather than merging."
      },
      {
        "question": "A rule has a documented false-positive rate of 93% over the past 90 days (tracked using the FP Analysis lesson's metrics) but continues to be labeled level: critical with no reassessment. What mistake does this lesson identify?",
        "options": [
          {
            "label": "This is correct practice; severity should never be reassessed once a rule is authored",
            "value": "d"
          },
          {
            "label": "Keeping a well-documented, chronically noisy rule at high severity undermines the whole tiering system's credibility",
            "value": "a"
          },
          {
            "label": "This rule should be immediately reported to NIST for a formal incident categorization",
            "value": "b"
          },
          {
            "label": "A 93% false-positive rate is actually excellent and requires no action",
            "value": "c"
          }
        ],
        "answer": "a",
        "explanation": "This lesson explicitly names 'never revisiting severity after repeated benign firings' as a common mistake — a chronically noisy rule kept at high severity undermines trust in the whole tiering system and accelerates alert fatigue. This isn't correct practice, doesn't require NIST notification (which applies to confirmed incidents, not rule tuning), and a 93% false-positive rate is poor, not excellent, performance."
      }
    ]
  }
};
