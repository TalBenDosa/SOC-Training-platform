import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content — group "pt". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_pt: Record<string, AuthoredPathLesson> = {
  "purple-team--atomic-red-team": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What Atomic Red Team Is For",
        "body": "A **purple team** exercise exists to answer one question: if a real attacker did this specific thing on our network, would we actually see it? Not \"would we see something like it\" in theory, but would a specific alert fire, in a specific SIEM, from a specific log source, within a reasonable window. Atomic Red Team, maintained by Red Canary, is the tool most commonly used to ask that question cheaply and repeatably.\n\nThink of it like a fire drill for detection engineering. A fire drill does not burn the building down; it triggers the smoke detectors and the sprinkler system using a small, controlled, known input (often literal smoke in a can) so the safety team can confirm the alarm actually rings and the right people get notified. Atomic Red Team does the same thing for cyberattacks: it runs a small, safe, single-technique action -- what the project calls an **atomic test** -- that reproduces one narrow piece of adversary behavior mapped to a **MITRE ATT&CK** technique ID (for example T1003.001, OS Credential Dumping: LSASS Memory), so the SOC can confirm whether the corresponding detection actually fires.\n\nThis is different from a full red team engagement. A red team tries to achieve an objective (domain admin, exfiltrate a file) using whatever chain of techniques works, often while evading detection on purpose. Atomic Red Team is intentionally the opposite: narrow, single-step, and not trying to be stealthy. It exists to validate detections and close the \"assumed coverage\" gap, where a team believes it detects a technique because a rule exists, but nobody has ever confirmed the rule actually fires against real telemetry.\n\nAtomic Red Team ships two things: a public library of **atomics** (technique-mapped test definitions, one folder per ATT&CK technique ID) hosted on GitHub, and **Invoke-AtomicRedTeam**, a PowerShell module that parses and executes those atomics. The library alone is just documentation; the module is the execution engine. Later pages walk through the structure of an atomic test and the exact commands used to run one against a lab endpoint.",
        "keyPoints": [
          "Purple team exercises confirm a detection actually fires, not just that a rule exists on paper",
          "An atomic test is one narrow, single-technique action mapped to a MITRE ATT&CK technique ID",
          "Atomic Red Team differs from a full red team engagement: it is intentionally not stealthy and not chained toward an objective",
          "The project has two parts: the public atomics library (test definitions) and Invoke-AtomicRedTeam (the PowerShell execution engine)"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Anatomy of an Atomic Test",
        "body": "Every technique in the atomics library has its own folder named after the ATT&CK ID (for example the folder `T1003.001`), containing a YAML file that defines one or more atomic tests for that technique, plus a Markdown file that renders the same content for human reading. Understanding the YAML structure matters because it tells you exactly what will run on the endpoint before you execute anything.\n\n### Core YAML fields\n- **attack_technique** -- the ATT&CK technique ID the file implements, e.g. `T1003.001`.\n- **display_name** -- the human-readable technique name, e.g. \"OS Credential Dumping: LSASS Memory\".\n- **atomic_tests** -- a list; a single technique can have several distinct atomic tests (different tools or methods that all achieve the same technique).\n\n### Fields inside each atomic test\n- **name** -- a short description of this specific test, e.g. \"Dump LSASS.exe Memory using comsvcs.dll\".\n- **auto_generated_guid** -- a stable unique ID for this exact test. Test numbers can shift if tests are added or removed from the file; the GUID never changes, which is why scripted execution should reference tests by GUID, not by number.\n- **description** -- what the test does and any context the analyst should know.\n- **supported_platforms** -- e.g. `windows`, `linux`, `macos`.\n- **input_arguments** -- named parameters with defaults (for example a target process name or output file path), so a test can be customized without editing the YAML.\n- **executor** -- the block that defines how the test actually runs: a `command` (the literal command line or PowerShell to execute), an optional `cleanup_command` to undo the test's effects, and a `name` field identifying the interpreter (`command_prompt`, `powershell`, `bash`, `sh`).\n\nReading this structure before running anything is not optional. The command block is exactly what will execute on the endpoint -- there is no simulation layer. A test that dumps LSASS memory really dumps LSASS memory; a test that creates a scheduled task really creates one. The YAML is the full, honest disclosure of what is about to happen, and an analyst who skips reading it is running an unknown command as themselves (or as the built-in Administrator, for privileged tests).",
        "codeExample": "atomic_tests:\n  - name: Dump LSASS.exe Memory using comsvcs.dll\n    auto_generated_guid: 5c2571d0-1572-416d-9676-812e64ca9f44\n    description: |\n      Dumps the memory contents of LSASS.exe using the MiniDump export\n      of comsvcs.dll, a documented LOLBIN technique.\n    supported_platforms:\n      - windows\n    input_arguments:\n      output_file:\n        description: Path to write the dump file\n        type: Path\n        default: \"%temp%\\\\lsass.dmp\"\n    executor:\n      command: |\n        $lsassPid = (Get-Process lsass).Id\n        rundll32 C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump $lsassPid #{output_file} full\n      cleanup_command: |\n        del #{output_file} >nul 2>&1\n      name: powershell\n      elevation_required: true",
        "keyPoints": [
          "Each ATT&CK technique folder holds a YAML file with one or more atomic_tests entries",
          "auto_generated_guid is the stable identifier for a test; test numbers can shift as the library changes",
          "The executor block (command, cleanup_command, interpreter) is the literal, unmodified command that will run",
          "input_arguments let a test be parameterized (paths, process names) without editing the YAML itself"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Installing and Inspecting Tests Before Execution",
        "body": "**Invoke-AtomicRedTeam** is distributed as a PowerShell module, installable from the PowerShell Gallery. Because the atomics folder itself contains real attacker commands (some of which will trigger antivirus on sight), the module and the atomics library are installed separately, and the atomics folder is usually excluded from AV scanning on a dedicated lab or range host -- never on a production endpoint.\n\nOnce installed, the workflow always starts with inspection, not execution. `Invoke-AtomicTest` accepts a technique ID and a set of switches that control what happens:\n\n- `-ShowDetailsBrief` -- prints a one-line summary of every atomic test defined for that technique, so you can see what exists before picking one.\n- `-ShowDetails` -- prints the full test definition (description, command, cleanup command, input arguments) without running anything.\n- `-CheckPrereqs` -- verifies that everything the test needs (a tool, a registry setting, a specific file) is already present, without installing anything.\n- `-GetPrereqs` -- actually installs or stages the missing prerequisites (for example downloading a tool referenced by the test).\n\nThis inspect-first workflow exists because a test can be selected by technique ID alone (which then targets every test under that ID), by a specific `-TestNumbers`, or by `-TestGuids` for guaranteed precision in scripted/repeatable runs. Running a bare technique ID with no filters against a technique folder that has five tests means all five execute -- so a disciplined operator always runs `-ShowDetailsBrief` first, chooses the specific GUID(s) relevant to the exercise plan, and only then runs `-CheckPrereqs` followed by the actual execution.\n\nThis mirrors a broader analyst habit that extends well past Atomic Red Team: never execute a script, macro, or binary you have not read, in a lab or in production. The inspection switches exist precisely so a purple team operator never has to take a test's safety on faith.",
        "codeExample": "# Install the execution framework and pull the public atomics library\nInstall-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force\nInstall-AtomicRedTeam -getAtomics -Force\n\n# Inspect before touching anything\nInvoke-AtomicTest T1003.001 -ShowDetailsBrief\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44 -ShowDetails\n\n# Confirm prerequisites are met (no execution yet)\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44 -CheckPrereqs",
        "keyPoints": [
          "Invoke-AtomicRedTeam (the module) and the atomics library (the test definitions) are installed as separate steps",
          "-ShowDetailsBrief and -ShowDetails inspect a test's content without executing it",
          "-CheckPrereqs verifies requirements are met; -GetPrereqs installs what is missing",
          "Always select tests by -TestGuids for scripted, repeatable runs -- test numbers can shift as the library is updated"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Running a Test and Reading What Happened",
        "body": "Once a specific test's GUID has been chosen and its prerequisites confirmed, execution itself is a single command: `Invoke-AtomicTest` with the technique ID and `-TestGuids`. For a credential-access test like the LSASS memory dump shown earlier, this launches `rundll32.exe` invoking the MiniDump export of `comsvcs.dll` against the LSASS process, exactly as the YAML's executor block specified.\n\n### What actually happens on the endpoint\n- A new process is created: `rundll32.exe` with a command line referencing `comsvcs.dll` and `MiniDump`.\n- That process opens a handle to `lsass.exe` with read/dump-capable access rights.\n- A `.dmp` file is written to the path given in `input_arguments` (or its default).\n\nEach of these is a distinct, observable artifact that a detection engineer can hunt for independently of whether Atomic Red Team was involved: the process lineage, the DLL export invoked, the handle access rights on LSASS, and the file write. This is the entire point of running the atomic in the first place -- to generate exactly this telemetry on a monitored lab endpoint and then go check the SIEM or EDR console for it.\n\n### Interpreting a \"no alert fired\" result\nA test that completes without triggering any alert is not a wasted run -- it is the single most valuable outcome a purple team exercise can produce, because it just found a real, previously invisible detection gap. The next step is always to go look at the raw telemetry (not the alert queue) for the technique's known artifacts: was the event even logged? If the event was logged but no rule matched it, that is a detection-logic gap. If the event was never logged at all, that is a visibility gap -- a missing log source or an under-configured sensor -- and it needs to be closed before any detection-logic work is worth doing.",
        "codeExample": "# Execute the specific test (after prereqs confirmed)\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44\n\n# The command line that actually runs on the endpoint (from the YAML executor):\n#   rundll32 C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump 1832 C:\\\\Users\\\\Public\\\\lsass.dmp full",
        "keyPoints": [
          "Execution reproduces the exact command line and process behavior defined in the test's executor block",
          "Each test leaves observable artifacts (process lineage, handle access rights, file writes) independent of the tool used to generate them",
          "A test that produces no alert is a valuable finding, not a wasted run -- it surfaces a real detection gap",
          "Distinguish a visibility gap (event never logged) from a detection-logic gap (event logged but no rule matched it)"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Cleanup and Repeatable Execution",
        "body": "Most atomic tests define a `cleanup_command` in their executor block precisely because atomic tests are meant to be run repeatedly, on the same lab hosts, without leaving accumulating debris (dump files, scheduled tasks, registry run keys, dropped binaries) that would make the next run's telemetry harder to interpret. `Invoke-AtomicTest` exposes this directly through the `-Cleanup` switch.\n\n### Why cleanup discipline matters for a purple team program\n- **Repeatability** -- if a detection engineer tunes a rule and wants to re-run the same test to confirm the fix, leftover artifacts from the previous run (an existing dump file, a stale scheduled task) can produce false confirmations or interfere with the new run.\n- **Range hygiene** -- a shared purple team lab that accumulates every artifact from every past exercise eventually becomes noisy enough that new telemetry is hard to distinguish from old.\n- **Honest scope** -- cleanup is explicitly scoped to what the test itself created. It does not undo side effects outside the test's own footprint (for example, if a test spawned a process that itself wrote additional files, cleanup only removes what the YAML's cleanup_command targets).\n\n### A safe, disciplined single-test workflow, end to end\n1. `-ShowDetailsBrief` to see what tests exist for the technique.\n2. `-ShowDetails` on the chosen `-TestGuids` to read the exact command before running it.\n3. `-CheckPrereqs`, then `-GetPrereqs` only if something is missing.\n4. Execute the test.\n5. Go check the SIEM/EDR for the expected telemetry and any alert.\n6. `-Cleanup` to restore the host.\n\nTreating cleanup as a mandatory last step, not an optional nicety, is what separates a repeatable detection-validation program from a series of one-off scripts that slowly poison their own test environment.",
        "codeExample": "# Full disciplined cycle for one atomic test\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44 -CheckPrereqs\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44\n#   ... go check SIEM/EDR telemetry here ...\nInvoke-AtomicTest T1003.001 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44 -Cleanup",
        "keyPoints": [
          "The -Cleanup switch runs the test's cleanup_command to reverse the artifacts that specific test created",
          "Cleanup discipline keeps re-runs repeatable and prevents a shared lab from accumulating noisy leftover artifacts",
          "Cleanup is scoped to the test's own footprint, not a general-purpose host reset",
          "A disciplined cycle is: inspect, check prereqs, execute, verify telemetry, then clean up"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Tracking ATT&CK Coverage Across a Test Run",
        "body": "A single atomic test answers one narrow question about one technique. The value for a SOC comes from running many of them, deliberately, against a defined scope, and recording the result of each -- because the accumulated results become a live map of what the detection stack actually covers, as opposed to what it is assumed to cover.\n\n### What to record per test executed\n- **Technique ID and test GUID** -- exactly which atomic was run.\n- **Expected telemetry** -- what log source and field should show the activity (for example Sysmon Event ID 10, ProcessAccess, with a `TargetImage` of `lsass.exe`).\n- **Actual result** -- did the expected event appear in the SIEM at all (visibility), and did an alert fire (detection)?\n- **Gap classification** -- no visibility, visibility but no detection, or fully detected.\n\n### Why this feeds directly into ATT&CK Navigator\nBecause every atomic test is already mapped to a specific technique ID, the recorded results translate directly into a Navigator layer: each technique gets a score based on its detection outcome (for example 0 for no visibility, a mid-range score for logged-but-undetected, a high score for fully detected and alerted). This produces a heatmap of real, validated coverage rather than a checklist of rules that exist on paper -- the same practice covered in depth in the Heatmap Delta and Detection Maturity lessons later in this path.\n\n### Scaling beyond one-off tests\nRunning atomics one at a time is fine for validating a single new detection rule. For a recurring purple team cadence across dozens of techniques, teams typically script batches of `Invoke-AtomicTest` calls against a defined technique list, log every result to a tracking sheet or a small database, and re-run the same batch on a schedule (for example quarterly) to catch detection regressions caused by SIEM upgrades, log source changes, or rule edits that silently broke something that used to work.",
        "keyPoints": [
          "Recording technique ID, expected telemetry, and actual result per test turns individual runs into a coverage map",
          "Classify each result as no visibility, visibility without detection, or fully detected and alerted",
          "Atomic test results map directly onto ATT&CK Navigator layer scores because every test is already technique-tagged",
          "A recurring, scheduled batch of atomics catches detection regressions introduced by later SIEM or rule changes"
        ]
      },
      {
        "pageNumber": 7,
        "title": "From Test Result to Detection Rule",
        "body": "Atomic Red Team validates detections; it does not write them. When a test reveals a gap, the next step belongs to detection engineering, and the atomic test's own documentation is usually the fastest path to a first-draft rule, because the YAML already states exactly which artifacts the technique produces.\n\n### Turning a gap into a hypothesis\nTake the LSASS memory dump example: the executor showed that `rundll32.exe` opens a handle to `lsass.exe` and writes a `.dmp` file. On a Windows endpoint with Sysmon installed, this maps to Event ID 10 (ProcessAccess), where `TargetImage` ends in `\\lsass.exe`, `SourceImage` is `rundll32.exe`, and `GrantedAccess` includes rights consistent with memory access (commonly seen as `0x1FFFFF`, full access). A Sigma rule can express this directly.\n\n### Closing the loop\n1. Run the atomic, confirm no alert fired.\n2. Read the executor block to identify the artifact (process, handle access, file write).\n3. Draft a detection rule targeting that artifact, not the specific tool used to produce it -- a rule keyed only on `comsvcs.dll` would miss the dozens of other LSASS-dumping tools that produce the same handle-access pattern.\n4. Deploy the rule to a test environment.\n5. Re-run the same atomic test (same GUID) to confirm the new rule fires.\n6. Only then promote the rule to production.\n\nThis loop -- gap found, rule drafted against the artifact (not the tool), re-tested with the same atomic, then promoted -- is the core mechanic that makes purple teaming a detection-improvement engine rather than a one-time audit.",
        "codeExample": "title: Potential LSASS Memory Dump via Process Access\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: '\\\\lsass.exe'\n    GrantedAccess: '0x1FFFFF'\n  filter_main_known_utils:\n    SourceImage|endswith:\n      - '\\\\werfault.exe'\n      - '\\\\MsMpEng.exe'\n  condition: selection and not filter_main_known_utils\nlevel: high",
        "keyPoints": [
          "Atomic Red Team validates whether detections fire; it does not author detection rules itself",
          "The executor block's described artifacts (process, handle access, file write) are the basis for a hypothesis-driven rule",
          "Rules should target the underlying artifact (e.g. handle access to lsass.exe), not the specific tool used in the test",
          "The loop -- gap, rule, re-test with the same GUID, promote -- confirms a fix before it reaches production"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Scoping a Safe Purple Team Exercise",
        "body": "Because atomic tests execute real, unmodified attacker commands, running them safely and productively requires the same governance any change to production systems would require, plus a few controls specific to adversary emulation.\n\n### Before running anything\n- **Written authorization** -- explicit sign-off naming the systems, techniques, and time window in scope, from whoever owns those systems.\n- **Environment** -- a dedicated lab or range that mirrors production telemetry (same EDR agent, same log forwarding) without touching real production hosts or data, unless the exercise is specifically and formally scoped to a production system with extra approvals.\n- **Notification** -- the blue team lead and any 24x7 monitoring desk should know an exercise is running and when, so real alerts during that window are not dismissed as \"probably the purple team\" (which erases the exercise's value) nor treated as a live incident that triggers unnecessary escalation.\n\n### During the exercise\n- Execute one test at a time, verify the expected telemetry, and clean up before moving to the next -- this is what keeps results attributable to a specific test.\n- Keep a running log of technique ID, test GUID, timestamp, and host, so any downstream investigation (or the SIEM's own audit trail) can be cross-referenced back to the exercise.\n\n### After the exercise\n- Confirm `-Cleanup` ran successfully on every host touched; verify manually for any test whose cleanup step failed or was skipped.\n- Produce the coverage results (page 6) as the exercise's deliverable, not just \"we ran N tests\" -- the value is the gap list and the resulting detection work, which the Heatmap Delta and Investment Justification lessons later in this path turn into stakeholder-facing reporting.\n\nA purple team exercise that skips authorization, environment isolation, or notification is not a lightweight shortcut -- it is an unauthorized intrusion that happens to be well-intentioned, and it risks real incident response resources being burned chasing an exercise nobody was told about.",
        "keyPoints": [
          "Written authorization scoping systems, techniques, and time window is required before any atomic test runs",
          "A dedicated lab or range with production-equivalent telemetry keeps results meaningful without risking real systems",
          "Notifying the blue team lead prevents both false dismissal of real alerts and unnecessary escalation of exercise noise",
          "The exercise's real deliverable is the gap list and resulting detection work, not a count of tests executed"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the primary purpose of running an Atomic Red Team test against a lab endpoint?",
        "options": [
          {
            "label": "To confirm whether an existing detection actually fires against real technique behavior",
            "value": "a"
          },
          {
            "label": "To achieve a specific attacker objective such as domain admin using whatever technique chain works",
            "value": "b"
          },
          {
            "label": "To generate synthetic log volume purely for SIEM storage and indexing performance testing",
            "value": "c"
          },
          {
            "label": "To automatically patch the vulnerable software once a coverage gap has been detected",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Atomic Red Team validates detection coverage by reproducing one narrow, technique-mapped action and checking whether the corresponding telemetry and alert appear. Chaining techniques toward an objective while evading detection describes a full red team engagement, not an atomic test; Atomic Red Team is intentionally the opposite of that."
      },
      {
        "question": "Why should a scripted, repeatable purple team run select atomic tests using -TestGuids rather than -TestNumbers?",
        "options": [
          {
            "label": "The GUID stays stable across library updates, while test numbers can shift when tests are added or removed",
            "value": "b"
          },
          {
            "label": "Test numbers only work when running against Linux or macOS target hosts",
            "value": "a"
          },
          {
            "label": "GUIDs automatically install any prerequisites a test is missing before it runs",
            "value": "c"
          },
          {
            "label": "Selecting by GUID is required to run more than one atomic test at once",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "auto_generated_guid is a stable unique identifier for one specific test, so scripts referencing it keep working even after the atomics library is updated and test numbering shifts. GUIDs have nothing to do with platform support or prerequisite installation, and multiple tests can be selected by number just as by GUID."
      },
      {
        "question": "An analyst runs an atomic test for T1003.001 and no alert fires. Checking raw telemetry shows the Sysmon Event ID 10 ProcessAccess event was never logged at all. What kind of gap does this indicate?",
        "options": [
          {
            "label": "A detection-logic gap where the existing rule's matching condition simply needs tuning",
            "value": "c"
          },
          {
            "label": "A visibility gap, since the event source or sensor configuration is missing entirely",
            "value": "a"
          },
          {
            "label": "A false positive caused by the atomic test itself misbehaving on the host",
            "value": "b"
          },
          {
            "label": "A cleanup failure that left the endpoint in an inconsistent state afterward",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "If the expected event was never logged at all, no detection rule could ever have matched it -- the gap is in visibility (missing log source or under-configured sensor), which must be fixed before any rule-tuning work is meaningful. A detection-logic gap describes the opposite case, where the event was logged but no rule matched it."
      },
      {
        "question": "Why does Invoke-AtomicRedTeam's -Cleanup switch matter for a recurring purple team program?",
        "options": [
          {
            "label": "It removes the artifacts a prior run left behind so re-runs stay repeatable",
            "value": "d"
          },
          {
            "label": "It automatically writes and deploys a matching Sigma detection rule for the technique just tested",
            "value": "a"
          },
          {
            "label": "It uninstalls the entire Invoke-AtomicRedTeam module and its atomics library once an exercise finishes",
            "value": "b"
          },
          {
            "label": "It disables the endpoint's EDR agent entirely so later tests run without any interference",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "Cleanup runs the test's own cleanup_command to remove the specific artifacts that test created, keeping the lab repeatable and readable for future runs. It has no role in writing detection rules, uninstalling the module, or touching EDR agent state -- those are separate, unrelated actions."
      },
      {
        "question": "Before an atomic test is executed against a lab endpoint, what should an operator do first, and why?",
        "options": [
          {
            "label": "Read the exact command first, since the test runs it unmodified with no simulation layer",
            "value": "b"
          },
          {
            "label": "Disable all endpoint logging first so the test does not generate excess telemetry noise on the host",
            "value": "a"
          },
          {
            "label": "Skip inspection entirely, since every test in the public library is safe for any environment by default",
            "value": "c"
          },
          {
            "label": "Notify only the requesting stakeholder, treating blue team notification as an optional courtesy step",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Because atomic tests execute real, unmodified commands with no simulation layer, reading the test definition first (via -ShowDetailsBrief/-ShowDetails) is the only way to know what will actually happen on the host before it happens. Disabling logging defeats the exercise's purpose, no test is safe by default for every environment, and blue team notification is part of responsible exercise governance, not optional."
      }
    ]
  },
  "purple-team--caldera-platform": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "From Single Moves to a Full Campaign",
        "body": "The previous lesson covered Atomic Red Team, which runs one narrow, single-technique action at a time -- useful for validating one detection in isolation. **MITRE CALDERA** solves a different problem: it is an open-source **adversary emulation platform** that chains many techniques together, across multiple compromised hosts, coordinated by a central server, to reproduce something closer to a real intrusion rather than a single isolated move.\n\nThe analogy that fits best is choreography versus individual dance steps. Atomic Red Team teaches and tests one step at a time. CALDERA runs an entire choreographed routine -- initial foothold, discovery, lateral movement, persistence -- across a set of hosts, autonomously deciding what to do next based on what it has already learned about the environment, much like a real intrusion unfolds as the attacker learns more about the network they are in.\n\n### Why a SOC runs CALDERA\n- **Realistic multi-stage validation** -- confirms detections hold up across a full attack chain, not just against isolated techniques, including whether the SOC can piece together disconnected alerts into a single incident.\n- **Autonomous decision-making** -- CALDERA's planners choose the next action based on facts already discovered on the target, similar to how a human operator or a real intrusion adapts as it learns more about the environment.\n- **Repeatable adversary profiles** -- a defined set of techniques representing a specific threat actor's known TTPs can be re-run on a schedule to catch detection regressions across the whole chain, not just one step.\n\nCALDERA is built and maintained by MITRE, the same organization behind the ATT&CK framework, and every ability in CALDERA is mapped to an ATT&CK technique ID -- so, exactly like Atomic Red Team, its results translate directly into ATT&CK Navigator coverage data. The next pages walk through CALDERA's architecture: the server, the agent that runs on target hosts, and the building blocks (abilities, adversaries, operations) that turn a single technique into a full emulated campaign.",
        "keyPoints": [
          "CALDERA is an adversary emulation platform that chains many techniques across multiple hosts, unlike Atomic Red Team's single-technique focus",
          "CALDERA's planners make autonomous next-action decisions based on facts already discovered on the target",
          "Adversary profiles represent a specific threat actor's known TTPs and can be re-run on a schedule",
          "Every CALDERA ability maps to an ATT&CK technique ID, feeding the same Navigator coverage workflow as Atomic Red Team"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Server, Plugins, and the Sandcat Agent",
        "body": "CALDERA's architecture has two halves: the **server**, which an operator interacts with through a web UI, and one or more **agents** deployed onto target hosts, which check in with the server, receive instructions, execute them, and report results back.\n\n### The server and its plugins\nCALDERA's core is deliberately small; almost all functionality (including the default agent, reporting views, and training content) is delivered as **plugins**. This plugin architecture means a SOC can extend CALDERA with custom planners, custom reporting, or additional agents without modifying the core platform.\n\n### Sandcat, the default agent\n**Sandcat** (also referred to by its codename `54ndc47`) is CALDERA's primary built-in agent, written in Go and distributed as a small precompiled binary so it can run on a target with no separate runtime installed. Once deployed to a host, Sandcat checks in with the server over a configurable communication channel -- commonly plain HTTP, but also supporting alternate channels such as GitHub Gist or DNS tunneling for scenarios emulating a stealthier, low-and-slow adversary. Sandcat also supports peer-to-peer relay over SMB, letting an agent on a host with no direct route to the server relay through another already-compromised host, which is itself a realistic emulation of adversary lateral C2 (command-and-control) behavior.\n\n### Why this matters to a defender\nEach of these channels is itself something a SOC should be able to detect: an unexpected outbound HTTP beacon to an unfamiliar host, an unusual SMB named pipe used for peer relay, or DNS queries with encoded-looking subdomains. Running CALDERA with different agent communication configurations is therefore not just about testing the emulated technique itself -- it also validates whether network and C2-channel detections hold up, independent of whatever technique the agent is currently executing on the host.",
        "codeExample": "flowchart LR\n    Operator[\"Operator (web UI)\"] --> Server[\"CALDERA Server\"]\n    Server -- \"deploy agent command\" --> Host1[\"Target Host 1\\n(Sandcat agent)\"]\n    Host1 -- \"HTTP check-in / beacon\" --> Server\n    Host1 -- \"SMB peer relay\" --> Host2[\"Target Host 2\\n(Sandcat agent, no direct route)\"]\n    Host2 -. \"relayed check-in\" .-> Host1",
        "keyPoints": [
          "CALDERA's server exposes a web UI and is extended almost entirely through plugins, keeping the core small",
          "Sandcat is the default Go-based agent, distributed as a precompiled binary with no separate runtime needed",
          "Agent check-in channels include HTTP, GitHub Gist, DNS tunneling, and SMB peer-to-peer relay for stealthier emulation",
          "Each agent communication channel is itself a detectable artifact a SOC should validate independent of the technique being run"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Abilities: The Building Blocks of a Campaign",
        "body": "An **ability** in CALDERA is the smallest unit of work -- a single ATT&CK technique implemented as one or more platform-specific commands, conceptually similar to a single atomic test in Atomic Red Team, but designed from the start to be chained together autonomously rather than run in isolation.\n\n### What defines an ability\n- **ATT&CK mapping** -- every ability references a specific technique ID, exactly like an atomic test's `attack_technique` field.\n- **Executors** -- the actual commands, one or more per supported platform (for example a PowerShell command for Windows, a bash command for Linux), so the same logical ability adapts to whatever platform the agent reports it is running on.\n- **Parsers** -- an optional component that reads an ability's command output and extracts structured **facts** from it (for example parsing a discovered username or file path out of command output), which feeds directly into what later abilities in the chain can use.\n\n### Facts: what makes chaining possible\nA fact is a labeled piece of information CALDERA has learned about the target -- a discovered hostname, a valid credential, a writable directory. Facts are what separate CALDERA from a scripted sequence: instead of a fixed, hardcoded chain of commands, an ability can require certain facts as input (for example \"a discovered username\") and CALDERA's planner will only queue that ability once the relevant fact has actually been discovered by an earlier step, mirroring how a real intrusion adapts its next move to what it has actually learned about the environment so far, not a pre-scripted plan written before the operation began.\n\n### Why this distinction matters for detection validation\nBecause facts drive sequencing, the exact order of techniques in a live operation is not fully predictable in advance -- which is closer to how a genuine adversary behaves, and a better test of whether a SOC's detections and analysts can follow an evolving intrusion rather than a fixed, previously rehearsed script.",
        "keyPoints": [
          "An ability implements one ATT&CK technique as one or more platform-specific executor commands",
          "Parsers extract structured facts from an ability's command output for later steps to consume",
          "Facts (discovered hostnames, credentials, paths) drive which abilities become eligible to run next",
          "Fact-driven sequencing makes operations less predictable than a fixed script, closer to genuine adversary behavior"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Adversary Profiles and Planners",
        "body": "An **adversary profile** in CALDERA groups a specific set of abilities together to represent the TTPs (tactics, techniques, and procedures) of a particular threat actor or attack pattern -- for example a profile built from techniques publicly reported for a specific intrusion set, or a generic profile representing a common ransomware precursor chain.\n\n### Building or selecting a profile\nCALDERA ships with several default adversary profiles for common scenarios (discovery-heavy reconnaissance, a basic ransomware-style chain), and an operator can build a custom profile by selecting specific abilities from the library -- which is exactly how threat-intelligence-informed emulation plans get built, a topic covered in depth in the next lesson on custom TTPs.\n\n### Planners: how the profile actually executes\nThe adversary profile defines *what* abilities are available; the **planner** decides *in what order and how* they run during an operation. CALDERA ships with several built-in planners:\n- **Atomic** -- the default planner; sends one usable ability at a time to each agent, following the adversary profile's defined atomic ordering.\n- **Batch** -- sends all currently usable abilities to each agent at once, rather than one at a time.\n- **Buckets** -- a variation on batch that groups abilities into ordered stages (\"buckets\"), executing all usable abilities in the current bucket before moving the operation to the next bucket.\n\n### Choosing a planner for an exercise\nThe Atomic planner produces the most realistic, gradual pacing (closest to how a patient human operator would work), which is usually preferred for validating whether a SOC can detect and correlate a slow-building intrusion. Batch or Buckets planners run faster and are more useful for quickly confirming raw technique coverage across a large ability set when pacing realism is not the point of that particular exercise.",
        "keyPoints": [
          "An adversary profile groups specific abilities to represent a threat actor's or attack pattern's TTPs",
          "The planner controls execution order and pacing separately from which abilities the profile makes available",
          "The Atomic planner sends one ability at a time following atomic ordering; Batch sends all usable abilities at once",
          "The Buckets planner groups abilities into ordered stages, executing each stage fully before advancing"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Running and Monitoring an Operation",
        "body": "An **operation** is CALDERA's execution unit: it combines a chosen adversary profile, a set of target agents, and a planner, and then runs the resulting campaign against those targets. Operations are launched and monitored from the CALDERA web UI, where each executed ability becomes a **link** -- a single record showing which ability ran, on which agent, its executor's exact command, its output, and its status.\n\n### Reading operation results\nEvery link in an operation carries a status:\n- **Success** -- the command executed and returned normally.\n- **Failure** -- the command executed but returned an error or unexpected result.\n- **Discard** -- the ability was skipped because its required facts were never satisfied.\n\nReviewing links in sequence tells the story of the operation exactly as it happened: which techniques actually ran, in what order, using what specific command on each platform, and what CALDERA learned (as facts) along the way. This link-by-link record is the ground truth an analyst cross-references against SIEM and EDR telemetry to determine whether each individual technique was detected.\n\n### Autonomous versus manual execution\nAn operation can run **autonomously**, where the planner queues and executes each eligible ability without operator intervention as soon as its required facts are satisfied, or in a **manual-approval** mode, where the operator reviews and approves each link before it executes. Manual mode is typically used the first time a new adversary profile is run against a shared or sensitive environment, so an operator can confirm each step's exact command before committing to it, while autonomous mode is used for repeatable, scheduled validation runs once the profile is already trusted.",
        "codeExample": "sequenceDiagram\n    participant Operator\n    participant Server as CALDERA Server\n    participant Agent as Sandcat Agent (target host)\n    Operator->>Server: Launch operation (adversary profile + planner)\n    Server->>Agent: Queue next eligible ability (link)\n    Agent->>Agent: Execute platform-specific command\n    Agent-->>Server: Report result + parsed facts\n    Server->>Server: Planner evaluates new facts, queues next link\n    Server-->>Operator: Operation report (all links, statuses)",
        "keyPoints": [
          "An operation combines an adversary profile, target agents, and a planner into one running campaign",
          "Each executed ability becomes a link recording its command, output, and status (success, failure, or discard)",
          "A discarded link means the ability's required facts were never satisfied during the operation",
          "Manual-approval mode reviews each link before execution; autonomous mode runs the whole profile unattended"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Deploying an Agent Safely",
        "body": "Before any operation can run, at least one Sandcat agent must be deployed onto a target host and successfully check in with the CALDERA server. The server's web UI generates a deployment command tailored to the target platform and the chosen check-in channel, which the operator runs manually on the target -- CALDERA does not push agents onto hosts without that explicit step.\n\n### What deployment actually does\nRunning the generated command downloads the Sandcat binary (or a stager that fetches it) and starts it on the host. Once running, the agent identifies itself to the server with a unique identifier, historically called a **paw**, and appears in the server's agent list as available for operations. From that point forward, the server can queue links to that agent, and the agent will poll for and execute them on its configured check-in interval.\n\n### Deployment discipline for a purple team exercise\n- **Isolated range only** -- agents should be deployed exclusively to hosts inside a dedicated, isolated lab or range that mirrors production telemetry, never to a live production endpoint without a separately and explicitly approved scope.\n- **Time-boxed deployment** -- an agent left running indefinitely after an exercise ends is itself an unmonitored remote-access tool sitting on a host; agents should be killed and removed as part of exercise cleanup, the same way Atomic Red Team's `-Cleanup` removes leftover artifacts.\n- **Known agent inventory** -- the SOC running the exercise should maintain a list of every host an agent was deployed to and confirm removal from each, so no host is accidentally left with a live, forgotten C2 client.\n\nThis discipline mirrors ordinary red-team-tooling hygiene: a deployment mechanism powerful enough to run arbitrary commands on a host is exactly the kind of thing that must be inventoried, time-boxed, and torn down deliberately, not left running \"just in case it's needed again.\"",
        "keyPoints": [
          "The operator runs the server-generated deployment command manually; CALDERA does not silently push agents onto hosts",
          "A deployed agent identifies itself to the server with a unique identifier (a paw) and appears in the agent list",
          "Agents belong only on isolated range hosts during a scoped exercise, never unapproved production endpoints",
          "Agents must be killed and removed as part of cleanup; a forgotten agent is an unmonitored remote-access tool"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Turning Operation Results Into Detection Findings",
        "body": "Like Atomic Red Team, CALDERA validates detections; it does not fix them. The difference is scale: a single operation can produce dozens of links across multiple techniques and multiple hosts, so the analysis step needs the same rigor applied to every link, not just a summary glance at \"the operation succeeded.\"\n\n### A repeatable review process\n1. Export or review the operation report, which lists every link with its ability (ATT&CK technique ID), target agent, status, and timestamp.\n2. For each **successful** link, check the SIEM/EDR for the expected telemetry at that timestamp, on that host -- exactly the same \"did the expected event appear, did an alert fire\" question asked of a single atomic test.\n3. Record the result per technique ID, the same way individual atomic test results were tracked in the previous lesson.\n4. Pay particular attention to techniques that succeeded **and chained together** -- for example a discovery ability that fed a fact into a subsequent lateral movement ability -- since detecting each step individually is different from detecting that they form one connected incident.\n\n### Why multi-stage results matter more than single-technique results\nA SOC can pass every single-technique atomic test and still fail a CALDERA operation, because the operation additionally tests whether alerts from different techniques, on different hosts, at different times, get correlated into a single incident by an analyst or a correlation rule -- which is a distinct, and often weaker, SOC capability than detecting any one technique in isolation. This is precisely the gap multi-stage adversary emulation exists to surface, and it feeds directly into the coverage and maturity reporting covered later in this path.",
        "keyPoints": [
          "Every link in an operation report should be reviewed against SIEM/EDR telemetry at its own timestamp and host",
          "Track results per ATT&CK technique ID, the same discipline used for individual atomic test results",
          "Chained links (a fact from one ability feeding the next) test whether alerts get correlated into one incident",
          "Passing every single technique individually does not guarantee the SOC can correlate them into one incident"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Governance for a CALDERA Exercise",
        "body": "CALDERA's multi-host, multi-technique scope makes exercise governance even more important than for single-host atomic testing, because a single operation can touch several systems and leave several agents running across an environment if not carefully managed.\n\n### Before the exercise\n- **Written authorization** naming the specific hosts, adversary profile (or the specific abilities it contains), and the exact time window -- the same baseline requirement as any atomic test exercise, scaled to cover every host the operation may touch.\n- **Isolated range** with agents pre-staged only on approved hosts, confirmed reachable by the server before the operation starts.\n- **Review the adversary profile's abilities individually** before launch, the same inspect-before-execute discipline used for atomic tests -- a profile is only as safe as the abilities it contains, and an imported or community profile should never be trusted without reading what it actually does.\n\n### During the exercise\n- Prefer manual-approval mode for the first run of any new adversary profile, escalating to autonomous mode only once every ability's behavior has been confirmed safe and understood.\n- Monitor the operation report live so an unexpected result (a link succeeding somewhere unplanned, due to an unanticipated fact) can be caught and the operation paused if needed.\n\n### After the exercise\n- Kill and remove every deployed agent, confirming against the pre-exercise host inventory that none were missed.\n- Produce the same coverage-and-gap deliverable described in the previous lesson, now scaled across the full multi-stage chain, feeding the heatmap, KPI, and maturity reporting covered later in this path.\n\nThe core principle carries over unchanged from Atomic Red Team: a tool powerful enough to validate real detections is powerful enough to cause real harm if run without authorization, isolation, and a deliberate teardown step.",
        "keyPoints": [
          "Written authorization must name every host, the adversary profile's abilities, and the exercise time window",
          "Review every ability in an adversary profile before launch -- a profile is only as safe as what it actually runs",
          "Manual-approval mode is preferred for a new profile's first run; autonomous mode suits already-trusted profiles",
          "Every deployed agent must be killed and removed afterward, confirmed against a pre-exercise host inventory"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the main capability CALDERA adds beyond what Atomic Red Team provides?",
        "options": [
          {
            "label": "Autonomous chaining of techniques across hosts based on facts discovered mid-operation",
            "value": "b"
          },
          {
            "label": "Mapping techniques to MITRE ATT&CK technique IDs, which Atomic Red Team never does at all",
            "value": "a"
          },
          {
            "label": "Running commands on a target host without leaving any observable process artifacts whatsoever",
            "value": "c"
          },
          {
            "label": "Generating and deploying finished Sigma detection rules automatically once a gap is confirmed",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "CALDERA's distinguishing capability is multi-stage, multi-host operations where the planner autonomously sequences abilities based on facts discovered along the way, unlike Atomic Red Team's single-technique, single-host tests. Both tools map to ATT&CK technique IDs, neither is artifact-free, and neither writes detection rules automatically."
      },
      {
        "question": "In a CALDERA operation, what causes an ability's link to be marked as Discard rather than executed?",
        "options": [
          {
            "label": "The command executed but returned an unexpected error from the target host",
            "value": "a"
          },
          {
            "label": "The ability's required facts were never satisfied, so it was never eligible to run",
            "value": "b"
          },
          {
            "label": "The operator manually rejected the link during manual-approval review",
            "value": "c"
          },
          {
            "label": "The Sandcat agent lost its connection to the server before the link could be queued",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Discard specifically means the ability could not run because the facts it depended on (like a discovered credential or path) were never produced by an earlier step. An execution error is recorded as Failure, an operator rejection during manual review is a separate outcome, and a lost connection is an agent/infrastructure issue distinct from fact-based eligibility."
      },
      {
        "question": "Why might a SOC pass every individual technique in a CALDERA operation's link report, yet still fail the exercise overall?",
        "options": [
          {
            "label": "The operation also tests whether alerts across techniques and hosts are correlated into one incident",
            "value": "c"
          },
          {
            "label": "CALDERA always marks an operation as failed whenever any agent uses the HTTP check-in channel",
            "value": "a"
          },
          {
            "label": "Passing individual techniques is technically impossible unless the Atomic planner was used",
            "value": "b"
          },
          {
            "label": "The operation report is designed to record only failures and never records any successes",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Multi-stage operations expose whether disconnected alerts across techniques and hosts get pieced together into one incident, a distinct and often weaker capability than detecting any single technique alone -- that correlation gap is the real value CALDERA adds over single-technique testing. The other options describe behavior CALDERA does not actually have."
      },
      {
        "question": "What is the practical difference between the Atomic planner and the Batch planner in CALDERA?",
        "options": [
          {
            "label": "Atomic paces one ability at a time by the profile's ordering; Batch dispatches all usable abilities at once",
            "value": "a"
          },
          {
            "label": "Atomic only works with the Sandcat agent, while Batch works with any third-party agent instead",
            "value": "b"
          },
          {
            "label": "Atomic requires manual-approval mode, while Batch always runs completely autonomously by design",
            "value": "c"
          },
          {
            "label": "Atomic can only target a single host, while Batch can target an unlimited number of hosts",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The Atomic planner is CALDERA's default, pacing one ability at a time by the adversary profile's atomic ordering, while Batch dispatches every currently usable ability to an agent at once for faster, less paced execution. Planner choice is independent of agent type, approval mode, and host count."
      },
      {
        "question": "A purple team lead is about to deploy an agent for a CALDERA operation. What governance step should happen immediately before deployment?",
        "options": [
          {
            "label": "Confirm written authorization names the hosts, profile abilities, and time window in scope",
            "value": "d"
          },
          {
            "label": "Switch every agent's check-in channel to DNS tunneling regardless of the exercise's actual objective",
            "value": "a"
          },
          {
            "label": "Disable the target host's EDR agent so Sandcat's own telemetry is not duplicated during the run",
            "value": "b"
          },
          {
            "label": "Delete the pre-exercise host inventory list so it does not conflict with the new deployment plan",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "Written authorization scoping the exact hosts, abilities, and time window is the non-negotiable prerequisite before any agent is deployed, mirroring the same governance baseline covered for Atomic Red Team. Forcing a specific channel regardless of objective, disabling EDR, and deleting the host inventory are all actions that actively undermine a safe, accountable exercise rather than support one."
      }
    ]
  },
  "purple-team--custom-ttps": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Generic Libraries Are Not Enough",
        "body": "Atomic Red Team's public library and CALDERA's default adversary profiles cover common, generic techniques well -- but a mature purple team program eventually needs to answer a sharper question: \"would we detect the specific threat actor most likely to target us, doing exactly what that actor has actually been observed doing?\" Answering that requires **custom TTPs** (tactics, techniques, and procedures) built from real threat intelligence, not just whatever is already in a public test library.\n\n### The gap generic testing leaves open\nA generic library test for a technique like T1053.005 (Scheduled Task/Job: Scheduled Task) proves a SOC can detect *a* scheduled task creation. It does not prove the SOC would detect the *specific* scheduled task name, command line, and trigger pattern a real threat actor is known to use -- and real intrusions are full of exactly these narrow, procedure-level details that distinguish \"we can detect a generic scheduled task\" from \"we would detect this specific group's known playbook.\"\n\n### What drives building a custom TTP\n- **Threat-informed defense** -- prioritizing detection work around the actors and campaigns most relevant to the organization's industry and geography, rather than testing techniques generically.\n- **CTI-driven validation** -- turning a cyber threat intelligence (CTI) report's specific indicators and behaviors into something concretely testable, instead of only reading the report.\n- **Gap discovery from real incidents** -- after a real intrusion or a near-miss, building a custom TTP that reproduces exactly what happened, to confirm the fix actually closes that specific gap and not just the general technique category.\n\nThe next pages walk through where custom TTP source material comes from, how to structure an emulation plan around a real threat actor, and how to write the actual test (as an Atomic Red Team YAML or a CALDERA ability) once the procedure-level detail has been gathered.",
        "keyPoints": [
          "Custom TTPs test the specific procedure a real threat actor uses, not just the generic technique category",
          "Threat-informed defense prioritizes detection work around actors most relevant to the organization",
          "CTI-driven validation turns a threat intelligence report's specific behaviors into something testable",
          "Custom TTPs are also how a team confirms a fix after a real incident actually closes that specific gap"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Sourcing Real Procedure-Level Detail",
        "body": "Writing a credible custom TTP starts with finding trustworthy, specific source material -- generic technique descriptions are not enough; the goal is the exact commands, file names, and sequencing a real actor has used.\n\n### Primary sources for procedure-level detail\n- **MITRE ATT&CK group pages** -- each documented threat actor has a group ID (for example `G0016` for APT29) with a page listing the specific techniques and, often, the specific software and procedure examples publicly attributed to that group, each citing its original source reporting.\n- **MITRE ATT&CK software pages** -- pages for specific tools and malware families documenting exactly which techniques that tool implements and how, often with command-line examples.\n- **DFIR (digital forensics and incident response) reports** -- public write-ups from vendors and CERTs (computer emergency response teams) describing a real investigated intrusion in detail, often including literal command lines, file paths, and registry keys observed.\n- **CISA advisories** -- U.S. Cybersecurity and Infrastructure Security Agency joint advisories frequently publish detailed TTPs, indicators, and even Sigma or YARA rules tied to specific campaigns.\n\n### Reading source material critically\nNot every claim in a report is equally reliable or equally specific. A useful habit is separating what a report states as directly observed (a literal command line captured from a compromised host) from what it infers or attributes with lower confidence (a named actor behind the intrusion). Custom TTP development should prioritize building tests from the directly-observed technical detail, since that is what will actually reproduce the same telemetry a defender needs to detect -- attribution confidence matters for threat intelligence reporting, but it does not change what commands actually ran on the host.",
        "keyPoints": [
          "ATT&CK group pages (Gxxxx IDs) and software pages document specific, cited procedure-level behavior per actor or tool",
          "DFIR reports from vendors and CERTs often include literal command lines and file paths from real investigations",
          "CISA advisories frequently publish detailed TTPs and ready-made detection rules tied to specific campaigns",
          "Prioritize directly-observed technical detail over attribution confidence when building a reproducible test"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Structuring an Emulation Plan",
        "body": "An **emulation plan** is the document that turns gathered threat intelligence into a scoped, executable exercise. It sits between the raw CTI report and the actual test files, translating \"this actor does X, Y, Z\" into \"we will run these specific tests, on these specific hosts, in this specific order, and expect these specific results.\"\n\n### Core sections of a usable emulation plan\n- **Objective and scope** -- which actor or campaign is being emulated, and which hosts/network segments are in scope for the exercise.\n- **Technique sequence** -- an ordered list of ATT&CK technique IDs matching the actor's typical kill chain (for example, initial access via a specific phishing technique, then discovery, then a specific lateral movement technique, then a specific persistence mechanism), each annotated with the specific procedure detail sourced in the previous step.\n- **Expected telemetry per step** -- for each technique in the sequence, the specific log source and field pattern expected to appear, so the exercise has a concrete pass/fail criterion before it even starts.\n- **Success criteria** -- explicitly stating what \"the SOC detected this\" means for the exercise (an alert fired within a defined time window, an analyst correctly attributed it to the right host and technique, etc.), so results are not judged after the fact by a shifting standard.\n\n### Why sequencing matters\nOrdering the technique sequence to match the real actor's typical kill chain (rather than an arbitrary order convenient for testing) is what makes the exercise a genuine test of whether the SOC's detections and analysts can follow the same narrative shape a real intrusion by that actor would actually take -- which is exactly the multi-stage correlation capability the CALDERA lesson highlighted as distinct from single-technique detection.",
        "codeExample": "flowchart TD\n    A[\"CTI report / ATT&CK group page\\n(e.g. G0016 APT29)\"] --> B[\"Extract technique IDs +\\nprocedure-level detail\"]\n    B --> C[\"Emulation plan:\\nscope, ordered technique sequence,\\nexpected telemetry, success criteria\"]\n    C --> D[\"Custom atomic test YAML\\nor CALDERA ability\"]\n    D --> E[\"Run in isolated range,\\nrecord result per technique\"]\n    E --> F[\"ATT&CK Navigator layer\\n(coverage / gap heatmap)\"]",
        "keyPoints": [
          "An emulation plan translates a CTI report into a scoped, ordered, testable exercise",
          "Each technique in the sequence should carry the specific procedure detail sourced from real reporting",
          "Expected telemetry per step gives the exercise a concrete pass/fail criterion defined before execution begins",
          "Sequencing techniques to match the real actor's kill chain tests correlation, not just isolated detection"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Writing a Custom Atomic Test",
        "body": "Once a specific procedure has been sourced and placed into the emulation plan, it needs to become an actual executable test. Writing a custom Atomic Red Team YAML file follows exactly the structure covered in the Atomic Red Team lesson -- `attack_technique`, `atomic_tests`, and an `executor` block -- but the command inside the executor now reproduces the *specific* procedure detail sourced from real reporting, rather than a generic example.\n\n### Adapting a sourced procedure into a test\nSuppose a DFIR report describes an actor creating a scheduled task named with a specific, distinctive naming pattern that runs a PowerShell command with a specific set of flags to download and execute a payload. The custom atomic test's `command` field should reproduce that exact task name and PowerShell flag pattern (substituting a safe, inert stand-in for the payload in the lab), not a generic `schtasks` example -- because the whole point is testing whether the SOC's detection would catch *this* actor's known procedure, not just \"a scheduled task was created.\"\n\n### Required fields for a well-formed custom test\n- A locally-generated `auto_generated_guid` (any valid UUID) so the test can be referenced precisely in scripted runs, exactly like a public library test.\n- A `cleanup_command` that removes the scheduled task, file, or registry key the test created -- custom tests need the same cleanup discipline as any library test.\n- Accurate `supported_platforms` and a clear `description` citing the source report, so anyone re-running the test later understands what real-world behavior it is reproducing and why.\n\n### Keeping custom tests safe\nThe safe-payload substitution matters: reproduce the actor's *mechanism* (the scheduled task pattern, the specific command-line flags, the specific process lineage) without reproducing actual malicious functionality (no real payload download, no real destructive action) -- the detection telemetry that matters comes from the mechanism, not from anything actually being compromised.",
        "codeExample": "atomic_tests:\n  - name: \"Custom - Scheduled Task Mimicking [Actor] Known Procedure\"\n    auto_generated_guid: 9f2b6a10-7e44-4c2d-9a11-3e5d0c8b7a21\n    description: |\n      Reproduces the scheduled task naming and PowerShell invocation pattern\n      described in [source DFIR report] for [actor], substituting a safe\n      no-op payload for the lab environment.\n    supported_platforms:\n      - windows\n    executor:\n      command: |\n        schtasks /create /tn \"OneDriveSyncHelper\" /tr \"powershell -nop -w hidden -enc <safe_base64_noop>\" /sc onlogon /ru SYSTEM\n      cleanup_command: |\n        schtasks /delete /tn \"OneDriveSyncHelper\" /f\n      name: command_prompt\n      elevation_required: true",
        "keyPoints": [
          "A custom atomic test follows the same YAML structure as a library test, but the command reproduces sourced, actor-specific procedure detail",
          "Substitute a safe, non-functional payload while preserving the actual detection-relevant mechanism (task name, flags, process lineage)",
          "Every custom test still needs a cleanup_command and a locally-generated stable GUID",
          "The description should cite the source report so future re-runs understand what real behavior is being reproduced"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Building the ATT&CK Navigator Layer for the Plan",
        "body": "An emulation plan built around a specific threat actor should be visualized before it is even run, because a **Navigator layer** makes the plan's actual ATT&CK coverage immediately reviewable by anyone, not just the person who wrote it -- catching gaps in the plan itself, not just gaps in detection.\n\n### The layer file's basic structure\nAn ATT&CK Navigator layer is a JSON file with a required `name` and `domain` (for example `enterprise-attack`), plus an optional `description` and a `techniques` array. Each entry in that array references a `techniqueID` (for example `T1053.005`) and can carry an optional numeric `score`, an optional explicit `color` (which overrides any color implied by score), and a free-text `comment`.\n\n### Two distinct uses of a layer for a custom-TTP exercise\n- **Planning layer** -- built before the exercise, scoring or coloring every technique that appears in the emulation plan, so a reviewer can see at a glance which parts of the ATT&CK matrix this specific actor's plan actually exercises (and, just as importantly, which tactics it does not touch at all).\n- **Results layer** -- built after the exercise, using the same technique IDs but now scored by detection outcome (undetected, partially detected, fully detected), turning the planning layer into a results heatmap. This results layer is exactly the input the Heatmap Delta lesson later in this path builds on.\n\n### Why this step is worth the extra file\nA written emulation plan is a document; a Navigator layer is the same plan rendered as a shareable, standard visual artifact that any stakeholder familiar with ATT&CK (including a client who commissioned the exercise) can review without reading a page of prose -- and comments per technique preserve exactly which sourced procedure detail justified including it.",
        "codeExample": "{\n  \"name\": \"APT29-style Emulation Plan - Planning Layer\",\n  \"versions\": { \"attack\": \"17\", \"navigator\": \"5.1.0\", \"layer\": \"4.5\" },\n  \"domain\": \"enterprise-attack\",\n  \"description\": \"Techniques sourced from ATT&CK group page and DFIR reporting for this exercise\",\n  \"techniques\": [\n    { \"techniqueID\": \"T1566.001\", \"score\": 1, \"comment\": \"Spearphishing attachment per source report\" },\n    { \"techniqueID\": \"T1053.005\", \"score\": 1, \"comment\": \"Scheduled task persistence, custom procedure\" },\n    { \"techniqueID\": \"T1021.001\", \"score\": 1, \"comment\": \"RDP lateral movement per source report\" }\n  ]\n}",
        "keyPoints": [
          "A Navigator layer JSON needs a name, domain, and a techniques array of technique IDs with optional score/color/comment",
          "A planning layer built before the exercise reveals what the emulation plan does and does not exercise",
          "A results layer built after the exercise reuses the same technique IDs, now scored by detection outcome",
          "Per-technique comments preserve which sourced procedure detail justified including that technique in the plan"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Staging Safely in a Test Environment",
        "body": "A custom TTP built from real threat intelligence is, by construction, closer to an actual attacker's behavior than a generic library test -- which means the same execute-safely discipline covered in the Atomic Red Team and CALDERA lessons applies here with even more care, since a custom test has not been reviewed and hardened by a public project's maintainers and contributors the way a library test typically has.\n\n### Staging checklist before first execution\n- **Read the command twice** -- once when writing it, once immediately before running it, specifically checking that any substituted payload is genuinely inert and that no real destructive action, real credential use, or real external network call survived the adaptation from the source report.\n- **Isolated range only** -- exactly as with any atomic test or CALDERA operation, first execution of a new custom test happens only on a dedicated lab host, never on a shared or production system.\n- **Confirm cleanup works** -- run the test once, verify its cleanup_command actually removes what it created, before relying on it in a larger scripted or scheduled emulation plan run.\n- **Peer review for higher-risk procedures** -- a custom test reproducing a destructive or highly privileged procedure (disabling a security control, deleting shadow copies) should get a second person's review before its first run, the same governance a code change to a production system would receive.\n\n### Rollback planning\nEven with a correct cleanup_command, a staging plan should identify a rollback path in case the test behaves unexpectedly (for example, restoring from a known-good snapshot of the lab host) -- treating \"what if this does not do exactly what the source report described\" as an expected possibility to plan for, not a rare edge case, since custom tests are new, one-off code that has not had the benefit of a public project's community testing.",
        "keyPoints": [
          "Custom tests need extra scrutiny because they have not been reviewed by a public project's maintainers",
          "Read the command twice, confirming any substituted payload is genuinely inert before first execution",
          "First execution always happens on an isolated lab host, and cleanup should be verified before scaling the run",
          "Higher-risk custom procedures warrant peer review, the same governance a production code change would receive"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Documenting Detection Hypotheses",
        "body": "A custom TTP built without a stated expectation of what should happen is much harder to learn from than one built with an explicit **detection hypothesis** -- a written statement, made before execution, of exactly what telemetry and alert the team expects to see if the relevant detection is working correctly.\n\n### Why write the hypothesis down first\nWriting \"we expect Sysmon Event ID 1 process creation with this specific command line, followed by Event ID 3 network connection to this internal relay host, and we expect our existing scheduled-task-persistence Sigma rule to match it\" before running the test does two things: it forces the team to be specific about what \"working\" actually looks like, rather than judging the result impressionistically afterward, and it makes a negative result immediately actionable, since the hypothesis already states exactly which specific expected signal was missing.\n\n### Structuring the hypothesis alongside the emulation plan\nEach technique step in the emulation plan (page 3) should carry its own hypothesis, following a consistent format:\n- **Expected artifact** -- the specific log source, event ID, and field pattern.\n- **Expected detection** -- which existing rule (by name) is expected to match, if any currently exists.\n- **Confidence** -- whether this is a known-working detection being re-validated, or a genuinely untested hypothesis about a rule that has never been confirmed against this exact procedure.\n\n### Turning hypotheses into a lasting artifact\nOnce the exercise runs, each hypothesis gets a recorded outcome (confirmed, partially confirmed, or refuted), and this hypothesis-and-outcome record becomes the primary input for the coverage tracking, heatmap delta, and KPI reporting covered in the remaining lessons of this path -- documentation written before execution is measurably more useful than a narrative reconstructed afterward from memory or from alert-queue screenshots.",
        "keyPoints": [
          "A detection hypothesis states, before execution, exactly what telemetry and alert should appear if detection works",
          "Writing the hypothesis first makes a negative result immediately actionable instead of ambiguous",
          "Each technique step's hypothesis should record expected artifact, expected rule, and confidence level",
          "Recorded hypothesis outcomes feed directly into later coverage, heatmap, and KPI reporting"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Case Study: Assembling a Plan for a Named Actor",
        "body": "Bringing the previous pages together, consider a fictional purple team scenario for **NexaCorp**, a mid-size financial services company that has identified a specific ransomware-affiliated intrusion set as its highest-priority threat based on industry-sector targeting reported in recent CISA advisories.\n\n### Step-by-step assembly\n1. **Source** -- the team pulls the actor's ATT&CK group page and two recent DFIR reports describing intrusions attributed to the same intrusion set, noting specific procedure details: a particular initial-access phishing lure pattern, a specific LOLBIN (living-off-the-land binary) used for discovery, and a specific scheduled-task persistence mechanism.\n2. **Plan** -- these become an ordered technique sequence (initial access, discovery, persistence, then a data-staging technique before the reports describe encryption), each annotated with the specific sourced procedure and an explicit detection hypothesis.\n3. **Build** -- each step becomes a custom atomic test (or a CALDERA ability, if the team wants autonomous multi-host chaining), with safe payload substitutions and verified cleanup commands.\n4. **Visualize** -- a planning-layer Navigator JSON is built and reviewed with the detection engineering lead before execution, confirming the sequence actually spans the tactics the real actor is known to use.\n5. **Execute** -- the sequence runs in the isolated range, with each hypothesis's outcome recorded as confirmed, partially confirmed, or refuted against real SIEM/EDR telemetry.\n6. **Report** -- the results layer and the hypothesis outcomes become the exercise deliverable, feeding directly into NexaCorp's next heatmap delta and detection-investment conversations.\n\nThis end-to-end sequence -- source, plan, build, visualize, execute, report -- is the repeatable pattern a purple team program applies every time a new priority threat actor is identified, and it is the pattern the remaining lessons in this path build reporting and maturity measurement on top of.",
        "keyPoints": [
          "A real custom-TTP exercise follows source, plan, build, visualize, execute, report as a repeatable sequence",
          "Procedure detail (specific LOLBIN, specific persistence mechanism) is sourced from the actor's ATT&CK group page and DFIR reports",
          "The planning-layer Navigator JSON is reviewed with detection engineering before execution, not after",
          "Recorded hypothesis outcomes and the results layer become the exercise's stakeholder-facing deliverable"
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why might a SOC pass a generic Atomic Red Team test for T1053.005 (Scheduled Task) but still fail to detect a specific real threat actor's use of that same technique?",
        "options": [
          {
            "label": "The generic test may not reproduce the actor's specific task name, flags, and trigger pattern",
            "value": "a"
          },
          {
            "label": "T1053.005 is not actually a valid MITRE ATT&CK technique ID, so no meaningful test could exist for it",
            "value": "b"
          },
          {
            "label": "Atomic Red Team tests never create real scheduled tasks on a host, only fully simulated ones",
            "value": "c"
          },
          {
            "label": "Scheduled task creation cannot be logged by the Windows Event Log under any configuration at all",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Generic library tests validate that a SOC can detect the technique category, but a real actor's specific procedure-level detail (task name, exact flags, trigger type) may be what a narrowly written detection rule actually keys on, which a custom TTP is built to test. T1053.005 is a real technique ID, Atomic Red Team tests execute real commands, and scheduled task creation is loggable via standard Windows auditing."
      },
      {
        "question": "What kind of source material should a custom TTP prioritize when adapting a threat actor's known procedure into a test?",
        "options": [
          {
            "label": "Directly-observed detail, like literal command lines and file paths, from real DFIR reporting",
            "value": "b"
          },
          {
            "label": "Only the actor's name and the attribution confidence level stated in a report's executive summary",
            "value": "a"
          },
          {
            "label": "General technique descriptions taken from the ATT&CK matrix with no reference to any specific actor",
            "value": "c"
          },
          {
            "label": "Marketing material published by security vendors describing their own product's detection capabilities",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Directly-observed technical detail (literal commands, file paths, registry keys from real investigations) is what actually reproduces the telemetry a defender needs to detect, regardless of how confident the attribution is. Attribution confidence, generic technique descriptions, and vendor marketing material do not provide the procedure-level specificity a custom TTP needs."
      },
      {
        "question": "In an ATT&CK Navigator layer JSON, what does setting an explicit color on a technique entry do relative to that technique's numeric score?",
        "options": [
          {
            "label": "It overrides whatever color the Navigator would otherwise display based purely on the score",
            "value": "c"
          },
          {
            "label": "It is silently ignored by the Navigator whenever a numeric score is also present on that entry",
            "value": "a"
          },
          {
            "label": "It changes which ATT&CK tactic the technique entry is considered to belong to going forward",
            "value": "b"
          },
          {
            "label": "It gets averaged together with the score-based gradient color to produce a visual blend",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Per the Navigator layer format, an explicitly defined color on a technique entry overrides any color implied by that technique's score, not the reverse. Color has no effect on tactic assignment, and the two are not averaged together."
      },
      {
        "question": "Why should a detection hypothesis be written down before a custom TTP is executed, rather than after?",
        "options": [
          {
            "label": "It states what a working detection should look like, making any gap immediately actionable",
            "value": "d"
          },
          {
            "label": "Written hypotheses are required by the Atomic Red Team YAML schema before a test file will even parse",
            "value": "a"
          },
          {
            "label": "It removes the need for a cleanup command, since the hypothesis already documents the expected end state",
            "value": "b"
          },
          {
            "label": "It guarantees the detection will fire exactly as expected, since the hypothesis defines that outcome",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "A pre-written hypothesis specifies exactly what telemetry and alert should appear, so a miss is immediately clear about which specific expected signal was absent, rather than being judged impressionistically after the fact. It is not a YAML schema requirement, does not remove the need for cleanup, and writing a hypothesis does not by itself guarantee the outcome it describes."
      },
      {
        "question": "When staging a newly-written custom atomic test for its first run, what precaution matters specifically because it has not been reviewed by a public project's maintainers, unlike a library test?",
        "options": [
          {
            "label": "Reading the command twice and confirming the substituted payload is genuinely inert before running it",
            "value": "b"
          },
          {
            "label": "Skipping the -CheckPrereqs step entirely, since custom tests are assumed to never have external prerequisites",
            "value": "a"
          },
          {
            "label": "Running the test directly against a production host to avoid the cost of maintaining a lab environment",
            "value": "c"
          },
          {
            "label": "Omitting the cleanup_command entirely, since custom tests are one-off and never need to be repeatable",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Because a custom test has not benefited from a public project's community review, an extra close read before execution -- confirming any substituted payload is truly inert -- is the precaution unique to custom tests. Skipping prerequisite checks, running against production, and omitting cleanup are all unsafe practices regardless of whether a test is custom or from a public library."
      }
    ]
  },
  "purple-team--replay-frameworks": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Replay Instead of Re-Attack",
        "body": "Atomic Red Team and CALDERA validate detections by generating live activity on a real endpoint and watching for the resulting telemetry. A **replay framework** takes a different approach: it feeds previously captured or synthetically constructed log data directly into a detection pipeline, without touching any endpoint at all, to test whether the detection logic itself -- the rule -- correctly matches or ignores that data.\n\n### The analogy\nLive testing (Atomic Red Team, CALDERA) is like a fire drill: you actually set off the smoke and watch the alarm respond in real time. Log replay is like feeding a recording of that same smoke event into the alarm system's logic on a bench, disconnected from any building, to check the wiring and logic alone -- faster, safer, and repeatable thousands of times a day, but it only tests the detection logic, not whether the sensor itself would have generated that data in the first place.\n\n### Why a purple team program needs both\nLive testing (previous two lessons) proves an endpoint produces the expected telemetry and that the full pipeline -- sensor, forwarding, parsing, rule -- works end to end, but it is comparatively slow and requires a lab endpoint per run. Replay testing is near-instant and requires no endpoint, but it can only validate the rule logic against data that someone already captured or constructed -- it assumes the underlying telemetry is realistic and correctly formatted, which is precisely what live testing exists to confirm in the first place.\n\n### Where replay fits in a detection engineering workflow\nReplay is what makes **detection-as-code** possible: treating detection rules like software, with version control, automated testing, and a deployment pipeline, so every rule change is validated against known-good and known-bad log samples before it ever reaches a production SIEM. The rest of this lesson builds that pipeline, using **Sigma**, the open, vendor-neutral detection rule format, as the concrete example.",
        "keyPoints": [
          "A replay framework tests detection rule logic against captured or constructed log data, without touching a live endpoint",
          "Live testing (Atomic Red Team, CALDERA) validates the full pipeline; replay testing validates only the rule logic",
          "Replay is fast and repeatable but depends on the replayed data itself being realistic and correctly formatted",
          "Replay testing is the mechanism that makes detection-as-code (rules managed like versioned, tested software) practical"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Sigma Rule Structure, Briefly Revisited",
        "body": "Replaying logs against a rule requires understanding exactly what the rule is checking, so this page recaps **Sigma**'s core structure before building a pipeline around it. Sigma is a YAML-based, vendor-neutral format for writing detection logic once and converting it to the query language of many different SIEM and log platforms.\n\n### Core Sigma fields\n- **title** and **id** -- a human-readable name and a stable unique identifier for the rule.\n- **logsource** -- which category of data the rule applies to (for example `category: process_creation`, `product: windows`), telling any conversion tool which platform-specific field mappings to use.\n- **detection** -- the actual matching logic: one or more named selections (field-value conditions) and a `condition` field combining them with boolean logic (`selection and not filter`, `selection1 or selection2`).\n- **level** -- the severity Sigma assigns if the rule matches (`informational`, `low`, `medium`, `high`, `critical`).\n\n### Field modifiers that matter for replay testing\nSigma field names support modifiers that change how a value is matched -- `|endswith`, `|startswith`, `|contains`, `|re` (regex), and list-based OR matching when a field maps to multiple values. A replay test fixture needs to specifically exercise these modifiers: a fixture log line where a field only partially matches (for example a path that contains but does not end with the target string) is exactly the kind of edge case that proves whether `|endswith` was the right modifier choice, versus a looser `|contains` that might produce excess false positives in production.\n\n### Converting Sigma to a target query language\n**pySigma** is the Python library that performs this conversion, using **pipelines** (platform-specific field-mapping profiles, for example a Sysmon pipeline) and **backends** (target query language generators, for example a Splunk backend or a Microsoft Sentinel KQL backend) to turn one vendor-neutral rule into the exact query syntax a specific SIEM understands.",
        "codeExample": "title: Potential LSASS Memory Dump via Process Access\nid: 00000000-0000-0000-0000-000000000001\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: '\\\\lsass.exe'\n    GrantedAccess: '0x1FFFFF'\n  filter_main_known_utils:\n    SourceImage|endswith:\n      - '\\\\werfault.exe'\n      - '\\\\MsMpEng.exe'\n  condition: selection and not filter_main_known_utils\nlevel: high",
        "keyPoints": [
          "Sigma's core fields are title, id, logsource, detection (selections + condition), and level",
          "Field modifiers like |endswith, |contains, and |re change how a value is matched and need targeted test fixtures",
          "pySigma converts a Sigma rule into a target query language using pipelines (field mappings) and backends (query generators)",
          "A replay fixture should specifically exercise modifier edge cases, not just an obviously matching or obviously clean log line"
        ]
      },
      {
        "pageNumber": 3,
        "title": "The Detection-as-Code Pipeline Stages",
        "body": "A detection-as-code pipeline manages Sigma rules the same way a software team manages application code: version-controlled, peer-reviewed, and automatically tested before deployment. A typical pipeline has four stages, the first three of which block a pull request from merging if they fail.\n\n### Stage 1: Lint\nThe `sigma check` command (from the **sigma-cli** tool) validates a rule's YAML syntax and structure against Sigma's schema and a set of quality validators, catching malformed rules before they reach conversion at all.\n\n### Stage 2: Convert\nThe `sigma convert` command runs the rule through pySigma with a specified backend and pipeline (for example `-t splunk -p sysmon`), producing the actual query that would run against the target SIEM. A rule that fails to convert cleanly -- referencing a field the pipeline does not know how to map -- is caught here, before it is ever tested against data.\n\n### Stage 3: Replay test\nThe converted query runs against a set of test fixtures -- log samples known in advance to be either malicious (should match) or benign (should not match). This is the actual replay step, and it is what the rest of this lesson focuses on building.\n\n### Stage 4: Deploy\nOnly after linting, conversion, and replay testing all pass does the pipeline deploy the rule to the production SIEM via that platform's API, typically only after the pull request has been merged to the main branch -- keeping the sequence of code review, then automated testing, then deployment in the same order a software release pipeline would use.\n\nStructuring the pipeline this way means a rule change can never reach production without first proving, automatically and repeatably, that it still matches what it is supposed to match and still ignores what it is supposed to ignore.",
        "codeExample": "flowchart TD\n    A[\"Rule change (pull request)\"] --> B[\"Stage 1: sigma check\\n(lint syntax + schema)\"]\n    B -->|pass| C[\"Stage 2: sigma convert\\n(pySigma backend + pipeline)\"]\n    C -->|pass| D[\"Stage 3: Replay test\\n(known-bad + known-good fixtures)\"]\n    D -->|pass, PR merged| E[\"Stage 4: Deploy\\n(push to SIEM via API)\"]\n    B -->|fail| F[\"Blocked: fix rule\"]\n    C -->|fail| F\n    D -->|fail| F",
        "keyPoints": [
          "A detection-as-code pipeline has four stages: lint, convert, replay test, and deploy",
          "sigma check lints rule syntax and schema; sigma convert produces the actual target-platform query via pySigma",
          "The replay test stage runs the converted query against known-malicious and known-benign log fixtures",
          "Lint, convert, and replay-test failures block the pull request; deployment only happens after all three pass"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Building Test Fixtures",
        "body": "A replay test is only as good as its fixtures -- the sample log lines used to prove a rule matches what it should and ignores what it should not. Building a useful fixture set is a deliberate exercise, not an afterthought.\n\n### Two required fixture categories\n- **Known-malicious (true positive) fixtures** -- log lines that should match the rule. These should come from the same source used to build the rule in the first place: an actual atomic test run's captured telemetry, a DFIR report's published log excerpt, or a manually constructed line that precisely matches the technique the rule targets.\n- **Known-benign (true negative) fixtures** -- log lines that resemble the malicious case closely enough to be a meaningful test, but should NOT match. For the LSASS example, a benign fixture might be a legitimate backup or antivirus process also opening a handle to `lsass.exe` with high access rights -- exactly the scenario the rule's `filter_main_known_utils` exclusion exists to handle.\n\n### Why \"closely resembling\" benign fixtures matter more than obviously-clean ones\nA fixture that is trivially different from anything malicious (an unrelated log line about a printer event) proves almost nothing about the rule's precision. The fixtures that actually validate a rule are the near-miss cases: legitimate activity that shares several fields with the malicious pattern but should not trigger the rule. These are exactly the cases that produce false positives in production if the rule's condition logic is too loose, so they belong in the fixture set from day one, not discovered later from a flood of analyst complaints.\n\n### Sourcing fixtures over time\nEvery real false positive reported by an analyst in production should become a new known-benign fixture added to the pipeline, and every atomic test run's captured telemetry should become a candidate known-malicious fixture -- turning the fixture library into a continuously growing regression suite rather than a fixed set written once.",
        "keyPoints": [
          "A fixture set needs both known-malicious (should match) and known-benign (should not match) log samples",
          "Benign fixtures that closely resemble the malicious pattern test precision far better than obviously unrelated log lines",
          "Fixtures should include near-miss legitimate activity, since that is what production false positives actually look like",
          "Real production false positives should be converted into new known-benign fixtures, growing the suite continuously"
        ]
      },
      {
        "pageNumber": 5,
        "title": "A CI/CD Pipeline in Practice",
        "body": "**CI/CD** (continuous integration / continuous deployment) automates the four pipeline stages so they run automatically whenever a rule change is proposed, rather than relying on a human to remember to run them manually. GitHub Actions is a common choice for hosting this automation, since Sigma rules are typically already stored in a Git repository for version control.\n\n### What triggers the pipeline\nA pull request that adds or modifies a rule file triggers a workflow that runs `sigma check`, then `sigma convert`, then executes the converted query against the fixture set, reporting pass/fail as a check on the pull request itself -- visible to reviewers before they approve the change, the same way a failing unit test blocks a software pull request.\n\n### Why this matters for a purple team program specifically\nThe purple team lessons earlier in this path (Atomic Red Team, CALDERA, custom TTPs) generate exactly the kind of real, technique-mapped telemetry that becomes a high-quality known-malicious fixture -- captured from an actual atomic test run rather than hand-constructed from imagination. Feeding purple team exercise output directly into the replay pipeline's fixture library closes the loop between live validation and automated regression testing: a detection confirmed once by a live atomic test stays confirmed on every future rule change, automatically, without re-running the live test every time.\n\n### Handling a pipeline failure\nWhen a rule change fails the replay stage, the pipeline output should show exactly which fixture failed and why (matched when it should not have, or vice versa) -- turning a vague \"the tests failed\" signal into a specific, actionable diagnosis the rule author can fix before requesting review again.",
        "codeExample": "name: sigma-rule-ci\non:\n  pull_request:\n    paths:\n      - \"rules/**/*.yml\"\njobs:\n  validate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pip install sigma-cli\n      - run: sigma check rules/\n      - run: sigma convert -t splunk -p sysmon -o converted/lsass-dump.spl rules/credential-access/lsass-dump.yml\n      - run: python3 tests/replay_fixtures.py --query converted/lsass-dump.spl --fixtures tests/fixtures/lsass-dump/",
        "keyPoints": [
          "CI/CD automates the lint, convert, and replay-test stages on every pull request that touches a rule file",
          "Pipeline results appear as a check on the pull request, visible to reviewers before they approve the change",
          "Live purple team exercise telemetry (from Atomic Red Team or CALDERA runs) becomes high-quality known-malicious fixture data",
          "A failed replay stage should report exactly which fixture failed and why, not just a generic pass/fail result"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Automated Validation Metrics",
        "body": "Running the same fixture set against a rule repeatedly produces measurable outcomes that go beyond a simple pass/fail for the pipeline gate -- these numbers become the ongoing health metrics for the rule itself.\n\n### Core replay-derived metrics\n- **True positive rate** -- the percentage of known-malicious fixtures the rule correctly matches. A rule that only catches some of its known-malicious fixtures has a real coverage gap even before it reaches production.\n- **False positive rate (against fixtures)** -- the percentage of known-benign fixtures the rule incorrectly matches. This is a leading indicator of production alert noise, measurable before the rule is ever deployed.\n- **Regression rate** -- how often a previously passing fixture starts failing after an unrelated rule change, which signals the rule set has developed unintended interactions (for example, two rules sharing a filter list that one team modified without realizing the other rule depended on it).\n\n### Why fixture-based metrics are a leading indicator, not a replacement, for production metrics\nA rule can score perfectly against its fixture set and still generate unexpected false positives in production, because fixtures can only cover the near-miss cases someone thought to write down. Fixture-based metrics catch known problems automatically and cheaply before deployment; they do not replace the production false-positive rate and alert-fatigue tracking covered in the KPI Tracking lesson next in this path -- the two measurement layers work together, with production surprises feeding back into the fixture library as described on the previous page.\n\n### Turning metrics into pipeline gates\nA mature pipeline can enforce a minimum true positive rate (for example, 100% against known-malicious fixtures, since any known miss should block deployment) and a maximum tolerance for false positives against benign fixtures, failing the pipeline automatically if a rule change regresses either number, without requiring a human reviewer to manually re-derive that judgment on every change.",
        "keyPoints": [
          "True positive rate measures the percentage of known-malicious fixtures a rule correctly matches",
          "False positive rate against fixtures is a leading indicator of production alert noise, measured before deployment",
          "Regression rate flags previously passing fixtures that start failing after an unrelated rule change",
          "Fixture-based metrics complement, but do not replace, production false-positive and alert-fatigue tracking"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Versioning and Rolling Back Detection Rules",
        "body": "Storing Sigma rules in Git, as a detection-as-code pipeline requires, brings the same version-control benefits software gets: every change is attributable, reviewable, and reversible. This matters specifically for detection rules because a bad rule change in production has real operational cost -- either a burst of false positives overwhelming the SOC, or worse, a silent loss of detection coverage that nobody notices until an incident goes undetected.\n\n### What version control gives a detection engineering team\n- **Attribution** -- every rule change has an author, a timestamp, and a linked pull request with review comments explaining why the change was made.\n- **Diffable history** -- a reviewer or a future investigator can see exactly what changed in a rule's condition logic between any two versions, not just the current state.\n- **Reversibility** -- if a deployed rule change causes a problem in production, the previous known-good version can be redeployed immediately by reverting the commit and re-running the pipeline, rather than trying to manually reconstruct what the rule looked like before.\n\n### A rollback workflow\n1. An alert-fatigue spike or a missed-detection report is traced to a specific recent rule change.\n2. The commit that introduced the change is identified from the rule's Git history.\n3. A revert commit is created, restoring the previous rule version.\n4. The revert goes through the same pipeline (lint, convert, replay test) before redeployment, confirming the reverted version still passes its own fixture set -- since the underlying SIEM schema or log format may have changed since that version was last live.\n\n### Why replay testing matters especially during rollback\nRedeploying an old rule version without re-running it through the replay pipeline risks reintroducing a problem the old version had, or discovering the old version no longer matches current log formats -- replay testing during rollback is exactly as necessary as it was during the original deployment.",
        "keyPoints": [
          "Version control gives detection rules attribution, diffable history, and reversibility, the same as application code",
          "A rollback traces a production problem to a specific rule change and reverts that commit in Git",
          "A reverted rule should go through the full pipeline again, not be redeployed directly, since the environment may have changed",
          "Replay testing during rollback is exactly as necessary as it was during the original rule deployment"
        ]
      },
      {
        "pageNumber": 8,
        "title": "From Passing Pipeline to Production Deployment Decision",
        "body": "A rule that passes lint, conversion, and replay testing is ready for deployment in the automated sense, but a mature program still applies human judgment before certain classes of change reach production, because fixture coverage -- however good -- is never a perfect stand-in for the full diversity of real production traffic.\n\n### When automated pass is sufficient on its own\nMinor rule tuning (adjusting a filter to exclude a newly-identified known-benign process, correcting a field name) that passes the full pipeline, including regression checks against the existing fixture set, is typically safe to auto-deploy once merged, since the change is narrow and the fixture regression check already covers the risk.\n\n### When a human reviewer should look regardless of a passing pipeline\n- **New high-severity rules** (`level: critical` or `high`) being deployed for the first time, since a new rule has no production track record yet, only fixture-based confidence.\n- **Broadened matching logic** -- loosening a `|endswith` to a `|contains`, or removing an existing filter -- since these changes are the specific pattern most likely to increase false positives beyond what the current fixture set anticipates.\n- **Rules feeding automated response actions** (auto-isolation, auto-disable-account), where a false positive has an operational cost far beyond an extra alert in the queue.\n\n### Closing the loop back to live testing\nA newly deployed rule -- especially one addressing a gap first identified by an Atomic Red Team test or a CALDERA operation -- should eventually be re-validated with the same live test that originally found the gap, not just the replay fixture, confirming the full pipeline (sensor through rule) still works end to end in production, not only that the rule logic is theoretically correct against stored fixture data.",
        "keyPoints": [
          "Passing the full replay pipeline makes a rule change deployment-ready in the automated sense, not beyond human review by default",
          "Minor, narrowly-scoped tuning changes that pass regression checks are typically safe to auto-deploy",
          "New high-severity rules and broadened matching logic warrant human review even after a passing pipeline",
          "A rule addressing a gap found by live testing should eventually be re-validated with that same live test in production"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the key difference between live detection testing (Atomic Red Team, CALDERA) and log replay testing?",
        "options": [
          {
            "label": "Live testing validates the full pipeline; replay testing validates only the stored rule logic itself",
            "value": "a"
          },
          {
            "label": "Replay testing requires a dedicated lab endpoint, while live testing needs no host to run at all",
            "value": "b"
          },
          {
            "label": "Live testing only ever works for Windows techniques, and replay testing only works for Linux ones",
            "value": "c"
          },
          {
            "label": "Replay testing always produces higher-fidelity results than live testing since it uses real production data",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Live testing exercises the entire pipeline (sensor, forwarding, parsing, rule) on a real endpoint, while replay testing feeds stored data directly into the rule logic without any endpoint involved, testing the rule in isolation. It is actually replay testing that needs no endpoint at all, not live testing, platform is not the distinguishing factor, and replay fidelity depends entirely on how realistic the fixture data is."
      },
      {
        "question": "In a detection-as-code CI/CD pipeline, what happens if a rule change fails the sigma check (lint) stage?",
        "options": [
          {
            "label": "The pull request is blocked from merging before it ever reaches conversion or replay testing",
            "value": "b"
          },
          {
            "label": "The rule is automatically deployed to production anyway, but with a warning flag attached to it",
            "value": "a"
          },
          {
            "label": "The pipeline simply skips linting and proceeds directly on to the replay test stage instead",
            "value": "c"
          },
          {
            "label": "The rule's declared severity level is automatically downgraded to informational until fixed",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Lint, convert, and replay-test failures all block the pull request from merging in a properly structured pipeline, and linting is the first gate a rule must pass before conversion is even attempted. A failing rule is never auto-deployed, stages are not skipped on failure, and severity levels are not automatically altered by the pipeline."
      },
      {
        "question": "Why are known-benign fixtures that closely resemble the malicious pattern more valuable than obviously unrelated benign log lines?",
        "options": [
          {
            "label": "They exercise the near-miss cases that actually cause false positives when a rule's logic is too loose",
            "value": "c"
          },
          {
            "label": "They are formally required by the sigma-cli tool before a rule can convert to any backend at all",
            "value": "a"
          },
          {
            "label": "They automatically raise a rule's declared detection level from medium up to high once added",
            "value": "b"
          },
          {
            "label": "They eliminate the need for any known-malicious fixtures once enough of them have been collected",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Near-miss benign fixtures (legitimate activity sharing several fields with the malicious pattern) are exactly what exposes an overly loose rule condition before it reaches production, unlike an obviously unrelated log line that proves almost nothing. sigma-cli has no such fixture requirement, fixtures do not alter a rule's declared severity level, and benign fixtures never replace the need for known-malicious ones."
      },
      {
        "question": "What does a rule's true positive rate measured against its fixture set actually tell a detection engineering team?",
        "options": [
          {
            "label": "The percentage of known-malicious fixtures the rule matches correctly, revealing gaps pre-production",
            "value": "d"
          },
          {
            "label": "The exact number of production analysts who correctly triaged an alert generated by that rule",
            "value": "a"
          },
          {
            "label": "The percentage of the entire ATT&CK matrix currently covered by the organization's whole rule set",
            "value": "b"
          },
          {
            "label": "The average time between a rule's production deployment and its first confirmed live match",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "True positive rate against fixtures specifically measures whether the rule correctly matches the known-malicious samples it is supposed to catch, surfacing coverage gaps before the rule ever reaches production. Analyst triage accuracy, overall ATT&CK matrix coverage, and mean time to first match are each separate metrics measuring different things."
      },
      {
        "question": "After tracing a production alert-fatigue spike to a specific recent rule change and reverting that commit in Git, what should happen before the reverted rule is redeployed?",
        "options": [
          {
            "label": "Run the reverted rule through the full pipeline again, since the log schema may have changed meanwhile",
            "value": "b"
          },
          {
            "label": "Redeploy the reverted rule immediately without re-running any pipeline stage, purely to minimize downtime",
            "value": "a"
          },
          {
            "label": "Permanently downgrade the reverted rule's severity level to prevent the same issue from ever recurring",
            "value": "c"
          },
          {
            "label": "Delete the entire fixture set and rebuild it from scratch before any further rule changes proceed",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A reverted rule should still pass through lint, convert, and replay testing before redeployment, because the environment (log formats, schema, other rules) may have changed since that version was last in production. Skipping the pipeline to save time, permanently downgrading severity, or deleting the fixture set are not part of a sound rollback workflow."
      }
    ]
  },
  "purple-team--kpi-tracking": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Detection Engineering Needs Numbers",
        "body": "Every lesson so far in this path has produced a result that can be counted: an atomic test passed or failed, a CALDERA link succeeded or was discarded, a custom TTP's hypothesis was confirmed or refuted, a Sigma rule passed or failed its fixture set. **KPIs** (key performance indicators) turn that stream of individual results into a small set of numbers a detection engineering team tracks over time to answer questions no single exercise result can answer on its own.\n\n### Questions a single exercise cannot answer\nOne purple team exercise tells you whether specific techniques were detected on a specific day. It does not tell you whether the SOC's overall detection coverage is improving release over release, whether the team is drowning in false positives regardless of how good any individual rule is, or whether a new hire's rule-writing is measurably as effective as a senior engineer's. KPIs exist to answer exactly these longitudinal, program-level questions.\n\n### The KPI set this lesson covers\n- **MTTD** (mean time to detect) -- how long between an event occurring and it being detected.\n- **Detection coverage %** -- what fraction of the relevant ATT&CK matrix has a validated detection.\n- **False positive rate** -- how often an alert fires without representing genuine malicious activity.\n- **Rule count and rule health** -- how many rules exist, and how many are actually active, current, and non-redundant.\n- **ATT&CK coverage score** -- an aggregated, weighted view combining several of the above into one reportable figure.\n\n### A caution before diving in\nA KPI is only useful if it changes a decision. A number tracked purely because it is easy to measure, with no plan for what action a bad reading would trigger, is a vanity metric -- a theme the final page of this lesson returns to directly, because it is the single most common failure mode in detection engineering measurement programs.",
        "keyPoints": [
          "KPIs turn individual exercise results into program-level, longitudinal measurements over time",
          "A single purple team exercise cannot answer whether overall coverage is improving release over release",
          "This lesson covers MTTD, detection coverage %, false positive rate, rule health, and ATT&CK coverage score",
          "A KPI only has value if a bad reading would actually trigger a specific action -- otherwise it is a vanity metric"
        ]
      },
      {
        "pageNumber": 2,
        "title": "MTTD and MTTR: Defining the Clock",
        "body": "**MTTD** (mean time to detect) measures the average time between when malicious activity actually began and when it was first detected -- the alert firing, or an analyst confirming it in a hunt. **MTTR** here refers to mean time to respond (distinct from mean time to remediate, a related but different metric used more in incident response reporting), measuring the average time from detection to the SOC taking a containment or response action.\n\n### Where the clock starts and stops matters\nMTTD's accuracy depends entirely on knowing the true start time of the malicious activity, which is often only knowable after the fact, from a full incident timeline reconstruction -- for live-exercise purposes, purple team testing gives a cleaner, more controllable version: the clock starts at the exact moment an atomic test or CALDERA link executes (a precisely known timestamp), and stops when the corresponding alert appears in the SIEM's alert queue. This exercise-based MTTD is a proxy for real-world MTTD, cleaner because the \"start\" time is exactly known, but it is not identical to production MTTD, since production attackers may take deliberate evasive action a purple team exercise does not replicate.\n\n### A worked calculation\nIf five atomic tests are run in an exercise and detected after 2, 4, 1, 8, and 5 minutes respectively, MTTD for that exercise is the average: (2+4+1+8+5)/5 = 4 minutes. Tracking this number release over release (as detection rules are tuned, as new log sources are onboarded) shows whether the SOC's actual detection speed is improving, holding steady, or regressing.\n\n### Why MTTD alone is an incomplete picture\nA very low MTTD achieved by writing extremely broad, low-precision rules that fire on nearly anything is not actually good detection -- it is a symptom of accepting high false-positive rates in exchange for speed. MTTD needs to be read alongside false positive rate (page 4) to mean anything on its own.",
        "codeExample": "// Example KQL: mean time to detect, exercise-based, per technique\nSecurityAlert\n| where TimeGenerated > ago(90d)\n| where Tactics has \"CredentialAccess\"\n| extend DetectDelayMinutes = datetime_diff('minute', TimeGenerated, ExerciseInjectTimestamp)\n| summarize AvgMTTDMinutes = avg(DetectDelayMinutes) by AlertName",
        "keyPoints": [
          "MTTD measures average time from malicious activity starting to it being detected; MTTR (respond) measures detection to response action",
          "Purple team exercises give a cleaner MTTD measurement since the exact start timestamp is precisely known",
          "MTTD is computed as the average detection delay across a set of tested events or techniques",
          "A very low MTTD achieved through overly broad, low-precision rules is not genuinely good detection on its own"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Detection Coverage Percentage",
        "body": "**Detection coverage %** measures what fraction of a defined scope of ATT&CK techniques the organization has a validated detection for -- not a rule that exists on paper, but one confirmed to fire through the kind of live and replay testing covered in earlier lessons of this path.\n\n### Defining the denominator carefully\nCoverage percentage is meaningless without first defining the scope it is measured against. Reasonable choices include: every technique in the full ATT&CK Enterprise matrix (a very large, often impractical denominator for a single organization), only the techniques relevant to the organization's actual platforms (for example excluding macOS-specific techniques if the environment has no macOS endpoints), or only the techniques associated with the specific threat actors the organization has prioritized (the custom TTP work from an earlier lesson). Most mature programs use the second or third framing, since coverage against irrelevant techniques inflates the denominator without adding real security value.\n\n### Defining the numerator: what counts as \"covered\"\nThis is where DeTT&CT's detection scoring, covered in depth in the Heatmap Delta and Detection Maturity lessons later in this path, becomes directly useful: a technique only counts toward coverage once it has a detection scored at a meaningful level (not merely \"logged for forensic context\" with no active rule), and ideally once that detection has been validated by a live atomic test or CALDERA operation, not merely written and assumed to work.\n\n### Reporting coverage responsibly\nA coverage percentage should always be reported alongside its denominator's scope definition (for example \"62% of techniques associated with our top three prioritized threat actors\" rather than a bare \"62% coverage\"), since an unscoped coverage number invites the exact kind of unfounded confidence -- \"we're covered\" -- that purple team testing exists to challenge in the first place.",
        "keyPoints": [
          "Detection coverage % requires an explicitly defined denominator scope, not an implicit assumption",
          "Scoping to relevant platforms or prioritized threat actors avoids inflating the denominator with irrelevant techniques",
          "A technique should only count as covered once it has a meaningfully scored, ideally validated, detection",
          "Coverage percentages should always be reported alongside their scope definition, never as a bare unscoped number"
        ]
      },
      {
        "pageNumber": 4,
        "title": "False Positive Rate and Alert Fatigue",
        "body": "**False positive rate** measures how often an alert fires for activity that, on investigation, was not actually malicious. It is the metric most directly tied to **alert fatigue** -- the well-documented phenomenon where analysts facing a high volume of low-value alerts begin triaging them faster and less carefully, or start dismissing entire alert categories without full investigation, increasing the risk that a genuine incident gets missed inside the noise.\n\n### Two common ways to measure it\n- **Per-rule false positive rate** -- of all alerts a specific rule generated in a given period, what percentage were closed as benign. This isolates which specific rules are the biggest noise contributors.\n- **Overall SOC false positive rate** -- across the entire alert queue, what percentage of all closed alerts were benign, giving a single program-level noise indicator that tracks the analyst's actual day-to-day experience.\n\n### Why this metric must be read alongside coverage, not instead of it\nA team that drives false positive rate toward zero purely by narrowing every rule's condition risks quietly sacrificing detection coverage and driving MTTD up for the techniques those narrowed rules were supposed to catch -- the same trade-off the replay-testing lesson's true-positive-rate metric exists to catch on the other side. A healthy program tracks false positive rate and coverage together, treating a large swing in either one, in isolation, as a signal to check what happened to the other.\n\n### A concrete threshold example\nMany mature SOCs target a per-rule false positive rate below roughly 10 to 20 percent for a rule to remain enabled without a filter added, though the right number depends heavily on the rule's severity and the SOC's actual triage capacity -- the number itself matters less than having an explicit, agreed threshold that triggers a defined tuning action (add a filter, adjust a modifier, or disable the rule) when crossed.",
        "keyPoints": [
          "False positive rate measures the percentage of alerts that, on investigation, were not actually malicious",
          "Alert fatigue from high false positive rates increases the risk that a genuine incident is missed in the noise",
          "Per-rule false positive rate isolates specific noisy rules; overall SOC rate tracks program-level analyst experience",
          "False positive rate and detection coverage should be read together, since narrowing rules to cut noise can quietly reduce coverage"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Rule Health: Count, Activity, and Redundancy",
        "body": "Raw **rule count** (how many detection rules exist in the SIEM) is a commonly reported but weak metric on its own -- a large rule count says nothing about whether those rules are actually enabled, current, or distinct from each other. **Rule health** metrics look past the raw count to what actually matters operationally.\n\n### Rule health dimensions worth tracking\n- **Active vs. disabled** -- what fraction of the total rule count is actually enabled and running, versus disabled (often because it was too noisy and never fixed, only turned off).\n- **Stale rules** -- rules that have not matched anything, at all, in a defined period (for example 12 months), which may indicate either genuinely rare-but-important coverage (acceptable) or a rule that silently broke due to a log format or field name change upstream (a real problem worth investigating, not assuming).\n- **Redundant/overlapping rules** -- multiple rules effectively covering the same technique and the same log source with near-identical logic, inflating the rule count without adding real coverage, and multiplying the maintenance burden when the underlying log format changes.\n- **Documentation completeness** -- what fraction of rules have an up-to-date description, ATT&CK technique mapping, and named owner, versus undocumented rules nobody can confidently explain or maintain.\n\n### Why this matters for a purple team program specifically\nA disabled rule that a purple team exercise's live test would have caught firing correctly, had it been enabled, is a different and more urgent finding than a technique with no rule at all -- it means the coverage already existed and was lost, likely silently, which is exactly the kind of regression the recurring, scheduled batch-testing cadence described in the Atomic Red Team lesson exists to catch before an actual incident does.\n\n### A simple rule health dashboard query pattern\nTracking active/disabled/stale/redundant counts over time, broken out by ATT&CK tactic, turns rule health from an occasional audit into a continuously visible operational signal.",
        "codeExample": "// Example SPL: rule health summary by status\n| inputlookup detection_rules.csv\n| eval age_days=round((now()-strptime(last_match_time,\"%Y-%m-%d\"))/86400)\n| eval health_status=case(\n    enabled=0, \"disabled\",\n    age_days>365, \"stale\",\n    1=1, \"active\"\n  )\n| stats count by health_status, attack_tactic",
        "keyPoints": [
          "Raw rule count alone says nothing about whether rules are enabled, current, or distinct from each other",
          "Stale rules (no matches in a defined period) may signal either rare-but-valid coverage or a silently broken rule",
          "Redundant, overlapping rules inflate maintenance burden without adding real detection coverage",
          "A disabled rule that would have caught a live purple team test is a coverage regression, not just a missing rule"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Aggregating an ATT&CK Coverage Score",
        "body": "An **ATT&CK coverage score** combines several of the previous metrics into one weighted, reportable figure representing overall detection maturity against the ATT&CK matrix -- useful specifically because a single number is what most non-technical stakeholders (covered further in the Investment Justification lesson later in this path) can actually track quarter over quarter, compared to a dashboard full of dozens of individual metrics.\n\n### A simple weighted aggregation approach\nRather than a flat percentage of \"techniques with any rule,\" a more informative score weights each technique by its detection quality (drawing on the DeTT&CT detection scoring scale covered in the Heatmap Delta lesson: 0 for no detection, up to 5 for excellent, real-time, low-false-negative detection) and, optionally, by the technique's relevance to the organization's prioritized threat actors, so a well-detected but low-relevance technique does not carry the same weight as a poorly-detected but high-relevance one.\n\n### Worked example\nIf an organization scopes to 20 prioritized techniques and scores each from 0-5 based on validated detection quality, summing the scores and dividing by the maximum possible (20 techniques x 5 = 100) produces a single percentage-style coverage score -- for example, a raw score sum of 58 out of 100 possible points yields a 58% aggregated coverage score, which is a meaningfully different (and more honest) number than simply counting \"14 of 20 techniques have some rule,\" since it also captures how good those 14 rules actually are.\n\n### Reporting cadence\nRecalculating this score after every purple team exercise cycle (tying it directly to the heatmap delta work in the next lesson) turns it into a trend line rather than a one-time snapshot, which is what makes it useful for demonstrating measurable, over-time improvement to stakeholders who fund the detection engineering program.",
        "keyPoints": [
          "An ATT&CK coverage score aggregates multiple techniques' detection quality into one reportable figure",
          "Weighting by detection quality (0-5 scale) and threat relevance is more informative than a flat has-a-rule percentage",
          "The worked calculation is: sum of per-technique scores divided by the maximum possible score across the scoped set",
          "Recalculating the score after every exercise cycle turns it into a trend line, not a one-time snapshot"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Building the KPI Dashboard and Reporting Cadence",
        "body": "Individual metrics only become a functioning KPI program once they are tracked on a consistent schedule, visualized in a way stakeholders at different levels can actually use, and tied to specific, pre-agreed actions when a threshold is crossed.\n\n### A reasonable reporting cadence\n- **Weekly, internal to detection engineering** -- false positive rate by rule, newly stale rules, any pipeline failures from the replay-testing CI/CD system.\n- **Quarterly, tied to a purple team exercise cycle** -- MTTD, detection coverage %, and the aggregated ATT&CK coverage score, since these numbers are most meaningfully measured right after a fresh exercise generates new validated data points.\n- **Annually or per major program review** -- the SOC-CMM or DeTT&CT maturity assessment covered in the Detection Maturity lesson later in this path, which moves at a slower cadence than the operational metrics above.\n\n### Matching the metric to the audience\nA detection engineer needs per-rule false positive rate and stale-rule lists to know exactly what to fix next. A SOC manager needs MTTD trends and coverage percentage to judge whether the team's overall trajectory is healthy. A budget-holding executive, covered in depth in the Investment Justification lesson, generally needs only the aggregated coverage score and its trend line, translated into risk and cost language, not the underlying per-rule detail.\n\n### Avoiding dashboard sprawl\nA dashboard with forty tracked numbers, most of which nobody consults regularly, is worse than one with five numbers that are genuinely reviewed and acted on every reporting cycle -- the goal of a KPI program is decisions made differently because of what the numbers show, not comprehensive measurement for its own sake.",
        "keyPoints": [
          "Different reporting cadences suit different metrics: weekly operational, quarterly exercise-tied, and annual maturity review",
          "Match the metric's detail level to its audience: detection engineers need per-rule detail, executives need trend lines",
          "A small set of genuinely reviewed metrics beats a large dashboard most stakeholders never actually consult",
          "The purpose of a KPI program is to change decisions, not to accumulate the largest possible set of tracked numbers"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Avoiding Vanity Metrics",
        "body": "The single most common failure mode in detection engineering measurement is tracking numbers that look impressive, move in a reassuring direction, and change nothing about what the team actually does -- classic **vanity metrics**. Recognizing them is a core skill for anyone building or consuming a KPI program.\n\n### Warning signs of a vanity metric\n- **No defined threshold or action** -- if nobody can say what number would trigger a specific response, the metric is decorative.\n- **Easily gamed** -- a metric that can be improved without improving the underlying capability it claims to represent. Raw rule count is the clearest example: adding ten redundant, low-quality rules improves \"rule count\" while adding zero real coverage.\n- **Isolated, single-dimension reporting** -- reporting MTTD alone, or coverage percentage alone, without its natural counterpart (false positive rate, or scope definition) invites exactly the gaming described above, since either number alone can be improved at the other's expense.\n- **No denominator or baseline** -- \"we detected 40 techniques this quarter\" means nothing without knowing the total scoped technique count and the prior quarter's number for comparison.\n\n### A concrete example from this lesson\nRaw rule count, reported by itself, is the textbook vanity metric this lesson has flagged twice already: it rewards volume over quality and can trivially be inflated with redundant rules that a rule-health audit (page 5) would immediately expose as adding no real value.\n\n### The test to apply to any proposed KPI\nBefore adding a number to a dashboard, ask: if this number got dramatically better next quarter, would the organization actually be safer, and if this number got dramatically worse, would a specific person take a specific action? A metric that fails either half of that test does not belong on the reporting cadence built in the previous page, however easy it is to measure.",
        "keyPoints": [
          "A vanity metric looks impressive but has no defined threshold or action tied to a bad reading",
          "Easily gamed metrics (like raw rule count) can be improved without improving actual detection capability",
          "Reporting a metric in isolation, without its natural counterpart, invites gaming at the other metric's expense",
          "Before tracking any KPI, confirm it would actually change a decision in both directions -- better and worse"
        ]
      }
    ],
    "quiz": [
      {
        "question": "In a purple team exercise, why does MTTD (mean time to detect) measured against atomic test results give a cleaner number than production MTTD?",
        "options": [
          {
            "label": "The exact start timestamp of tested activity is known, unlike a real incident's true starting point",
            "value": "a"
          },
          {
            "label": "Production incidents are never logged with any timestamp at all, making MTTD impossible there",
            "value": "b"
          },
          {
            "label": "Exercise-based MTTD is always calculated in hours, while production MTTD is calculated only in days",
            "value": "c"
          },
          {
            "label": "Atomic tests always trigger an alert within one minute of execution, unlike a real incident",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "An atomic test's execution timestamp is known exactly, while a real incident's true start time can usually only be estimated after a full timeline reconstruction, making exercise-based MTTD a cleaner but not identical proxy. Production incidents are logged with timestamps just not always a known true start; the time unit is not fixed to hours or days by definition; and atomic tests do not guarantee any particular detection speed."
      },
      {
        "question": "A SOC drives its overall false positive rate toward zero by narrowing every detection rule's matching condition. Why is this not automatically a sign of a healthier detection program?",
        "options": [
          {
            "label": "It can quietly reduce detection coverage and raise MTTD for exactly the techniques those rules targeted",
            "value": "c"
          },
          {
            "label": "False positive rate cannot legally be reported below a fixed percentage under any security framework at all",
            "value": "a"
          },
          {
            "label": "A false positive rate of exactly zero automatically triggers an audit finding under NIST SP 800-61",
            "value": "b"
          },
          {
            "label": "Narrowing a rule's matching condition always increases the total rule count on the health dashboard",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Cutting false positives purely by narrowing conditions can silently sacrifice true detection coverage, which is why false positive rate should always be read alongside coverage and MTTD rather than optimized alone. There is no such legal floor, no such NIST-mandated audit trigger tied to a zero rate, and narrowing conditions does not by itself change the count of rules that exist."
      },
      {
        "question": "Why is raw rule count considered a weak, potentially misleading KPI on its own?",
        "options": [
          {
            "label": "It says nothing about whether rules are enabled or current, and is easily inflated with redundant ones",
            "value": "b"
          },
          {
            "label": "Rule count cannot be measured automatically and must always be counted by hand from the SIEM console",
            "value": "a"
          },
          {
            "label": "Most SIEM platforms cap the maximum number of detection rules an organization is allowed to create",
            "value": "c"
          },
          {
            "label": "A high rule count always causes the SIEM to silently drop older rules past a hidden internal limit",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Rule count is easily gamed: adding redundant, low-quality, or disabled rules increases the raw count while adding zero real coverage, which is why rule health (active/stale/redundant) matters more than the raw number. Rule count is measured automatically via SIEM APIs in practice, there is no universal platform-enforced rule cap, and SIEMs do not silently drop rules at a hidden threshold."
      },
      {
        "question": "A detection coverage percentage is reported to leadership as simply '62% coverage' with no further context. What is missing that makes this number potentially misleading?",
        "options": [
          {
            "label": "An explicit statement of the scope it was measured against, such as which techniques or threat actors",
            "value": "d"
          },
          {
            "label": "A conversion of the percentage into a monetary figure using the ROSI formula before any reporting occurs at all",
            "value": "a"
          },
          {
            "label": "Confirmation that the number came from CALDERA's Batch planner rather than its default Atomic planner",
            "value": "b"
          },
          {
            "label": "A statement naming the specific SIEM vendor used to calculate the underlying percentage value",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "Coverage percentage is only meaningful alongside its defined scope (which techniques count in the denominator); an unscoped number invites false confidence about what it actually represents. ROSI conversion, CALDERA planner choice, and SIEM vendor identity are unrelated to what makes a coverage percentage interpretable."
      },
      {
        "question": "Which of the following best describes a vanity metric in a detection engineering KPI program?",
        "options": [
          {
            "label": "A metric with no defined threshold or action, or one that can be improved without improving real capability",
            "value": "c"
          },
          {
            "label": "Any metric that is reported to an executive audience rather than to the detection engineering team directly",
            "value": "a"
          },
          {
            "label": "Any metric that is measured weekly instead of on a quarterly or annual reporting cadence",
            "value": "b"
          },
          {
            "label": "A metric that requires a Sigma rule to calculate, rather than being pulled directly from the SIEM's own dashboard",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "A vanity metric is defined by having no real action tied to it, or by being easily gamed without improving the underlying capability it claims to measure -- not by its audience, its reporting frequency, or whether a Sigma rule happens to be involved in calculating it."
      }
    ]
  },
  "purple-team--heatmap-delta": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What a Heatmap Actually Shows",
        "body": "A **heatmap**, in the ATT&CK Navigator sense, is a visualization of the full MITRE ATT&CK matrix where each technique's cell is colored according to a numeric score -- typically ranging from white or a light color (low or no score) through progressively darker shades toward red (high score), so a reviewer can scan the entire matrix at a glance and immediately see which tactics and techniques are strong, weak, or entirely uncovered.\n\n### Why a heatmap communicates better than a table\nA table of \"62% coverage\" tells a stakeholder one aggregate number. A heatmap tells them exactly where that 62% comes from: perhaps every Initial Access technique glows red (strong) while Lateral Movement is nearly white (weak) across the board -- a pattern immediately actionable for a detection engineering roadmap that a single percentage completely hides. This is precisely why the ATT&CK Navigator (introduced when building a custom TTP's planning layer, in an earlier lesson) exists as a standard, widely recognized visualization: nearly anyone familiar with ATT&CK can read a Navigator heatmap without additional explanation.\n\n### Before versus after: the delta concept\nA **heatmap delta** compares two heatmaps of the same technique scope -- one captured before a purple team exercise or a detection engineering initiative, one captured after -- to visualize exactly which techniques improved, which stayed flat, and, just as importantly, whether any technique's score actually got worse (a genuine regression, not merely an area that was never prioritized).\n\n### What this lesson builds toward\nThe rest of this lesson walks through building the \"before\" baseline layer, running an exercise and scoring detections using DeTT&CT's detection scoring table, building the \"after\" layer, computing the delta between them, and turning that delta into a roadmap document a detection engineering team and its stakeholders can act on together.",
        "keyPoints": [
          "A Navigator heatmap colors every ATT&CK technique by a numeric score, showing coverage strength at a glance across the whole matrix",
          "A heatmap reveals which specific tactics are strong or weak, information a single aggregate percentage hides",
          "A heatmap delta compares a before and after layer of the same scope to show improvement, stagnation, or regression",
          "This lesson covers baseline layers, DeTT&CT detection scoring, the after layer, computing the delta, and roadmap reporting"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Building the Baseline (Before) Layer",
        "body": "The baseline layer represents the organization's honest, current detection state before any new exercise or engineering work begins -- and \"honest\" is the operative word, since a baseline inflated by assumed-but-unvalidated coverage defeats the entire purpose of measuring a delta afterward.\n\n### What goes into the baseline score\nRather than a binary \"has a rule / does not,\" the baseline should use **DeTT&CT's detection scoring table**, a standardized scale from the DeTT&CT (Detect Tactics, Techniques & Combat Threats) framework, ranging from -1 (none -- no detection in place at all) through 0 (forensics/context -- no detection, but the technique is logged and the data can be used for investigation and context), 1 (basic, a simple signature covering minimal aspects), 2 (fair, uses a correlation rule beyond a basic signature), 3 (good, effective detection using more complex analytics), 4 (very good, near-complete real-time coverage), up to 5 (excellent, comprehensive real-time detection with low false negatives).\n\n### Sourcing the baseline honestly\nThe most defensible baseline scores come from the same validated, tested sources used throughout this path: results from previous Atomic Red Team runs, CALDERA operations, and confirmed replay-pipeline true positive rates -- not simply \"we believe we would probably catch this.\" Where a technique has never actually been tested, the honest baseline score is -1 (none) -- or 0 (forensics/context) if the activity is at least logged -- regardless of how confident the team feels about it, because an untested assumption is exactly the risk a purple team program exists to eliminate.\n\n### Building the layer file\nPractically, this means iterating through the scoped technique list (the same scoping discipline covered in the KPI Tracking lesson) and assigning each one a DeTT&CT-scale score in the layer's `techniques` array, with a `comment` field citing the evidence behind that score -- the specific exercise, date, and result that justifies it.",
        "codeExample": "{\n  \"name\": \"NexaCorp - Credential Access Baseline (Before)\",\n  \"domain\": \"enterprise-attack\",\n  \"techniques\": [\n    { \"techniqueID\": \"T1003.001\", \"score\": 0, \"comment\": \"No validated detection as of 2026-Q2 baseline; never tested\" },\n    { \"techniqueID\": \"T1053.005\", \"score\": 2, \"comment\": \"Correlation rule exists, validated by atomic test 2026-01-14\" },\n    { \"techniqueID\": \"T1078\", \"score\": 1, \"comment\": \"Basic signature only, not validated against a live test\" }\n  ]\n}",
        "keyPoints": [
          "The baseline layer should use DeTT&CT's detection scoring scale (-1 through 5), not a binary has-a-rule flag",
          "Baseline scores should be sourced from actual validated test results, not assumed or unconfirmed confidence",
          "An untested technique should honestly score -1 (none), or 0 if it is only logged for forensic context, regardless of how confident the team feels",
          "Each technique's score should carry a comment citing the specific evidence (exercise, date, result) behind it"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Running the Exercise and Scoring Results",
        "body": "With the baseline established, the exercise itself draws directly on the earlier lessons in this path: an Atomic Red Team batch, a CALDERA operation, or a custom TTP emulation plan is run against the same scoped technique list, and each technique's post-exercise detection quality is scored using the identical DeTT&CT scale used for the baseline -- this consistency is what makes a before/after comparison meaningful at all.\n\n### Scoring discipline during the exercise\nFor each technique tested, ask: did the expected telemetry appear at all (a visibility question, covered in the Atomic Red Team lesson), and if so, did an existing rule match it, and how completely -- a basic signature catching one narrow variant scores lower than a correlation-based rule catching the technique across several different tool implementations of it.\n\n### Handling techniques the exercise did not test\nAn exercise rarely re-tests every technique in the baseline's full scope. Any technique not actively re-tested in this cycle keeps its prior baseline score unchanged in the after layer -- it would be dishonest to silently improve or degrade a score for a technique nobody actually touched this cycle, and doing so would corrupt the delta calculation on the next page.\n\n### Recording new gaps discovered mid-exercise\nIt is common for an exercise to surface an unplanned finding -- a technique nobody had scored before because it was outside the original scope, but which the exercise incidentally revealed a gap in (for example, a lateral movement step in a CALDERA operation chain that was not the exercise's primary focus). These should be added to the scored set with their own baseline-equivalent score of 0 (since the layer never previously tracked them) and their new post-exercise score, expanding the scope's rigor rather than being discarded as out of scope.",
        "keyPoints": [
          "Post-exercise scoring uses the exact same DeTT&CT scale as the baseline, which is what makes the comparison valid",
          "Score based on whether the expected telemetry appeared and how completely an existing rule matched it",
          "Techniques not actively re-tested this cycle keep their prior baseline score unchanged in the after layer",
          "Unplanned findings discovered mid-exercise should be added to the scored set with a 0 baseline and their new score"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Building the After Layer",
        "body": "The after layer is structurally identical to the baseline layer -- same technique scope, same DeTT&CT scoring scale, same JSON schema -- but with each technique's score updated to reflect the result of the exercise just run, plus updated comments citing the new evidence.\n\n### Keeping the after layer honest and traceable\nEvery score change from the baseline should be traceable to a specific action: a new rule deployed and validated, a filter added that raised a rule from basic to fair, or a newly-onboarded log source that turned a -1 (no detection, nothing logged) into at least a 0 (now logged and useful for forensic context, even before an active rule exists). A score that changed with no corresponding comment explaining why is a red flag during review -- it suggests the number was adjusted based on impression rather than evidence, exactly the failure mode DeTT&CT's evidence-based scoring exists to prevent.\n\n### A practical workflow for producing the after layer\nRather than manually re-typing the entire layer, most teams copy the baseline layer JSON, then update only the `score` and `comment` fields for techniques that were actually re-tested this cycle, preserving every untouched technique's baseline value exactly -- this is both faster and safer than rebuilding from scratch, since it makes accidental, unintended score changes much easier to spot in a diff review before the after layer is finalized.\n\n### Versioning both layers\nBoth the baseline and after layers should be saved (in a shared repository alongside the emulation plans and Sigma rules covered in earlier lessons) with a clear date and exercise identifier in the filename or the layer's own `name` field, since the next purple team cycle's baseline is simply this cycle's after layer -- making heatmap delta tracking a continuous chain across cycles, not a series of disconnected one-off comparisons.",
        "keyPoints": [
          "The after layer uses the identical scope and scoring scale as the baseline, updated only where the exercise produced new evidence",
          "Every score change should be traceable to a specific action (new rule, added filter, new log source), not an unexplained adjustment",
          "Copying the baseline and editing only re-tested techniques' fields makes unintended changes easier to catch in review",
          "This cycle's after layer becomes next cycle's baseline, making delta tracking a continuous chain rather than isolated snapshots"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Computing and Visualizing the Delta",
        "body": "With both layers built on the identical technique scope, the **delta** -- the per-technique difference between the after score and the baseline score -- can be computed and visualized in the Navigator itself or with a small script, turning two separate heatmaps into one that directly highlights change.\n\n### Computing the delta\nFor each technique ID present in both layers, delta = after score - baseline score. A positive delta means improvement, zero means no change, and a negative delta means the technique's detection quality actually declined -- which can genuinely happen (a SIEM migration silently breaking a field mapping a rule depended on, for example) and is exactly the kind of regression a delta comparison surfaces that a single after-only snapshot would miss entirely.\n\n### Visualizing the delta as its own layer\nA third Navigator layer can be built purely from the delta values themselves -- scoring each technique by its numeric delta rather than its absolute score -- producing a heatmap where color intensity shows the magnitude of change rather than the absolute detection level. This delta-specific layer is often the most useful one to present in a stakeholder review, since it answers \"what changed\" directly, without requiring the viewer to mentally subtract two separate heatmaps.\n\n### Reading the delta responsibly\nA large positive delta on a technique that started at 0 and moved to 2 represents real, meaningful progress, but is a smaller absolute improvement than a technique moving from 3 to 5 -- both are legitimate improvements, and the delta layer should be read alongside the absolute after-layer scores, not instead of them, since delta alone does not show whether a technique's current state is actually adequate.",
        "codeExample": "flowchart LR\n    A[\"Baseline layer\\n(before scores, DeTT&CT 0-5)\"] --> C[\"Delta calculation:\\nafter_score - baseline_score\\nper technique ID\"]\n    B[\"After layer\\n(post-exercise scores)\"] --> C\n    C --> D[\"Delta layer\\n(color = magnitude of change)\"]\n    C --> E[\"Regression list\\n(any negative delta = investigate)\"]",
        "keyPoints": [
          "Delta is computed per technique as after score minus baseline score using the identical scoring scale",
          "A negative delta represents a real regression (for example a silently broken rule) that an after-only snapshot would miss",
          "A dedicated delta layer, scored by magnitude of change, is often the clearest artifact for a stakeholder review",
          "Delta should be read alongside absolute after-layer scores, since delta alone does not show whether current coverage is adequate"
        ]
      },
      {
        "pageNumber": 6,
        "title": "DeTT&CT Scoring in Practice",
        "body": "Because the entire baseline-to-after-to-delta workflow depends on consistent, honest DeTT&CT scoring, it is worth working through the scale's levels with concrete examples tied to the kind of evidence a purple team exercise actually produces.\n\n### The DeTT&CT detection score levels, applied\n- **-1, None** -- no detection in place at all. Example: no process-creation logging is enabled on a legacy server segment, so there is nothing to detect against.\n- **0, Forensics/context** -- no detection, but the activity is logged and useful for post-incident investigation and context. Example: Sysmon Event ID 10 is being collected, but no Sigma rule targets LSASS process access on this log source yet.\n- **1, Basic** -- a simple signature covers a minimal, narrow aspect. Example: a rule matching only the literal string `comsvcs.dll` in a command line, which a different LSASS-dumping tool would bypass entirely.\n- **2, Fair** -- a correlation rule beyond a basic signature. Example: the earlier Sigma rule matching `GrantedAccess: 0x1FFFFF` against `lsass.exe` regardless of which tool triggered it.\n- **3, Good** through **4, Very good** -- increasingly complex analytics covering more known variations, approaching real-time and comprehensive.\n- **5, Excellent** -- comprehensive, real-time coverage of essentially all known variations with low false negatives -- a genuinely rare score in practice, reserved for the most mature, extensively validated detections.\n\n### Applying DeTT&CT's own guidance\nDeTT&CT's documentation explicitly notes that a score may not always fit perfectly, and the scorer should use the score that fits best rather than forcing an exact match -- consistency of judgment across the technique set matters more than perfect precision on any single score.",
        "keyPoints": [
          "DeTT&CT's detection scale runs from -1 (none) through 0 (forensics/context: logged, no detection) up to 5 (excellent, comprehensive, real-time)",
          "A basic signature keyed on one specific tool (score 1) is meaningfully weaker than a correlation rule catching the underlying behavior (score 2)",
          "Higher scores (3-5) require increasingly complex analytics covering more known variations of the technique",
          "DeTT&CT itself advises using the best-fitting score rather than forcing exact precision on every technique"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Presenting the Heatmap Delta to Stakeholders",
        "body": "A heatmap delta's real value is realized only when it changes what happens next -- which means the presentation of it matters as much as the underlying data quality covered in the previous pages.\n\n### Structuring a delta presentation\n- **Lead with the delta layer's visual** -- most audiences grasp \"here is what got better, here is what got worse, here is what is still blank\" from a colored matrix far faster than from a table of numbers.\n- **Call out regressions explicitly, first** -- a negative delta anywhere in the set deserves attention before the good news, since it represents newly-introduced risk that needs an owner and a remediation plan, not a footnote after the improvements.\n- **Tie improvements to specific actions taken** -- \"Lateral Movement coverage improved from an average score of 1.2 to 2.8 after deploying three new correlation rules validated against the CALDERA operation run on [date]\" is a specific, credible claim; \"detection got better\" is not.\n- **Name what remains uncovered, deliberately** -- a heatmap with remaining white space is not a failure to hide; it is the roadmap input for the next cycle, and presenting it honestly is what makes the whole measurement program trustworthy over time.\n\n### Connecting to the next lessons in this path\nThis same delta data -- what improved, what regressed, what remains uncovered, and what specific actions produced each change -- is the direct input to the Investment Justification lesson's business case (translating detection improvement into financial terms) and the Detection Maturity lesson's broader maturity scoring, both covered next in this path.",
        "keyPoints": [
          "Lead a stakeholder presentation with the delta layer's visual before diving into tabular detail",
          "Call out any regression (negative delta) explicitly and first, since it represents newly-introduced, unaddressed risk",
          "Tie every claimed improvement to a specific, named action and validation event, not a vague general statement",
          "Honestly presenting remaining uncovered techniques is what keeps the measurement program credible over successive cycles"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Turning the Delta Into a Roadmap",
        "body": "The final step converts the heatmap delta from a retrospective report into a forward-looking roadmap: a prioritized list of what the next purple team and detection engineering cycle should focus on, grounded directly in what this cycle's data actually showed.\n\n### Prioritization inputs from the delta\n- **Regressions first** -- any negative delta identified needs an assigned owner and a target date for restoring the previous score, treated with the same urgency as a newly discovered gap, since it represents capability that was already validated once and then silently lost.\n- **High-relevance, low-score techniques** -- from the KPI Tracking lesson's scoping discussion, techniques tied to the organization's prioritized threat actors that still score 0 or 1 after this cycle are natural next-cycle candidates, since they combine high real-world relevance with low current protection.\n- **Techniques with rising-but-incomplete scores** -- a technique that moved from 1 to 2 this cycle but not further may be a good candidate for continued investment next cycle, since the team has already demonstrated it can move that specific technique's score, unlike a technique that has stayed at 0 across several cycles despite repeated attempts.\n\n### Structuring the roadmap document\nA usable roadmap lists each prioritized technique with its current score, target score for the next cycle, the specific planned action (new rule, new log source, custom TTP re-validation), and an owner -- mirroring the same structure the emulation plan used in the Custom TTPs lesson, because a roadmap is, in effect, next cycle's emulation plan already being drafted.\n\n### Closing the loop\nThis roadmap becomes the scope definition for the next cycle's baseline layer (page 2), completing a cycle that repeats: baseline, exercise, after layer, delta, presentation, roadmap, and back to baseline -- the operational rhythm a mature purple team program runs continuously, not a one-time project with a defined end date.",
        "keyPoints": [
          "Regressions get top priority in the roadmap, with an assigned owner and target date to restore the lost score",
          "High-relevance techniques still scoring 0 or 1 are natural next-cycle candidates, combining relevance with weak protection",
          "A technique with rising-but-incomplete scores may warrant continued investment, since progress has already been demonstrated",
          "The roadmap becomes the next cycle's baseline scope, making the whole process a continuous, repeating rhythm rather than a one-time project"
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why is a Navigator heatmap generally more useful to a detection engineering team than a single aggregate coverage percentage?",
        "options": [
          {
            "label": "It shows exactly which tactics and techniques are strong, weak, or uncovered, not one overall number",
            "value": "a"
          },
          {
            "label": "A heatmap is formally required by the DeTT&CT framework before any percentage can be legally reported",
            "value": "b"
          },
          {
            "label": "A heatmap can only ever be generated after a CALDERA operation, never after an Atomic Red Team exercise",
            "value": "c"
          },
          {
            "label": "Aggregate percentages are always calculated incorrectly unless a matching heatmap is also produced alongside them",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "A heatmap visualizes coverage at the level of individual tactics and techniques, revealing patterns (like strong Initial Access but weak Lateral Movement) that a single aggregate number completely hides. DeTT&CT has no such legal reporting requirement, heatmaps can be built from either Atomic Red Team or CALDERA results, and aggregate percentages are not inherently miscalculated without one."
      },
      {
        "question": "When building the baseline (before) layer for a heatmap delta, what score should an untested technique honestly receive, regardless of how confident the team feels about it?",
        "options": [
          {
            "label": "A score of -1 (none), since confidence without validation is not evidence",
            "value": "b"
          },
          {
            "label": "The maximum score of 5, since the team's confidence should be reflected directly in the baseline layer",
            "value": "a"
          },
          {
            "label": "The average score of every other technique already scored in that same layer's technique set",
            "value": "c"
          },
          {
            "label": "No score at all, since untested techniques must be entirely excluded from the baseline layer's scope",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "DeTT&CT-based baselines must be evidence-driven: an untested technique scores -1 (none) -- or 0 if it is only logged for context -- no matter how confident the team feels, since unvalidated confidence is exactly the risk purple team testing exists to eliminate. Assigning the maximum score, an averaged score, or excluding it entirely would all corrupt the baseline's honesty."
      },
      {
        "question": "In a heatmap delta, what does a negative delta on a specific technique indicate?",
        "options": [
          {
            "label": "That technique's detection quality actually declined between the baseline and after layer, a real regression",
            "value": "c"
          },
          {
            "label": "The technique was outside the scope of both the baseline and after layers and should be ignored entirely",
            "value": "a"
          },
          {
            "label": "A data entry error occurred, since DeTT&CT scores can never legitimately decrease between two exercise cycles",
            "value": "b"
          },
          {
            "label": "The technique was tested using CALDERA's Batch planner instead of the recommended Atomic planner",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "A negative delta means the after-layer score is lower than the baseline score for that technique, representing a genuine regression (for example a rule silently broken by a schema change) that a single after-only heatmap would not reveal on its own. It is not automatically an error, an out-of-scope indicator, or tied to which CALDERA planner was used."
      },
      {
        "question": "According to DeTT&CT's own detection scoring guidance, what should a scorer do when a technique's real-world detection state does not perfectly match any single score description?",
        "options": [
          {
            "label": "Use the score description that fits best, prioritizing consistent judgment over forcing exact precision",
            "value": "b"
          },
          {
            "label": "Automatically assign the lowest possible score of -1 whenever any ambiguity exists in the assessment",
            "value": "a"
          },
          {
            "label": "Leave that specific technique out of the layer entirely until a perfectly matching score becomes available",
            "value": "c"
          },
          {
            "label": "Escalate the decision to MITRE directly before including any score for that technique in the layer",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "DeTT&CT's own documentation states a score may not always be a perfect fit and advises using the score that fits best, valuing consistent judgment across the technique set over forced exact precision. Defaulting to the lowest score, omitting the technique, or escalating to MITRE are not part of that guidance."
      },
      {
        "question": "When presenting a heatmap delta to stakeholders, why should regressions (negative deltas) be called out explicitly and first, before improvements?",
        "options": [
          {
            "label": "A regression means newly introduced, unaddressed risk, and needs an owner rather than a footnote after good news",
            "value": "d"
          },
          {
            "label": "Regressions are always statistically larger in magnitude than any improvement a purple team exercise can produce",
            "value": "a"
          },
          {
            "label": "Stakeholders are contractually required to review every regression before any improvement can be discussed",
            "value": "b"
          },
          {
            "label": "Regressions can only ever occur when a delta layer is built manually instead of generated by the Navigator tool",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "A regression means previously-validated detection capability was silently lost, which represents active, current risk that deserves priority attention and an assigned owner, ahead of celebrating unrelated improvements. Regressions are not inherently larger in magnitude, there is no such contractual review requirement, and manual versus tool-generated delta layers has no bearing on whether regressions occur."
      }
    ]
  },
  "purple-team--investment-justification": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Security Needs a Business Case",
        "body": "Every previous lesson in this path produced technical evidence: validated detections, coverage scores, heatmap deltas. None of that evidence, by itself, secures budget. A detection engineering team competing for funding against a sales team's revenue-generating headcount request or a product team's growth initiative needs to translate its technical findings into the same financial language those competing requests already speak -- otherwise, the most rigorously validated purple team program in the world can still lose the budget conversation to a louder or more familiar business case.\n\n### What \"the business case\" actually needs to answer\nA budget-approving stakeholder is not asking \"is this detection technically sound\" (the previous lessons already answered that); they are asking \"why should this specific dollar go here instead of somewhere else, and how do I know the return is worth it.\" Answering that requires a small set of standard financial concepts -- ones widely used across cybersecurity, insurance, and general enterprise risk management -- that let a detection investment be compared, apples to apples, against any other funding request the organization is weighing.\n\n### The concepts this lesson builds, in order\n- **SLE, ARO, and ALE** -- the standard building blocks for quantifying expected loss from a risk, before any control is considered.\n- **ROSI** (return on security investment) -- the formula that turns avoided loss and control cost into a single comparable return figure.\n- **Cost per detection** -- a narrower, purple-team-specific metric connecting directly to the coverage work from earlier lessons.\n- **Translating technical risk into business risk language**, and structuring an actual board-level report.\n\nNone of this replaces the technical rigor built throughout this path -- it is the final translation layer that makes that rigor legible to the people who control the budget.",
        "keyPoints": [
          "Technical validation evidence alone does not secure budget; it must be translated into financial language",
          "Stakeholders approving budget ask why this investment beats competing requests, not whether it is technically sound",
          "SLE, ARO, ALE, and ROSI are standard financial concepts widely used across cybersecurity and enterprise risk management",
          "This lesson is a translation layer on top of the technical rigor built in earlier lessons, not a replacement for it"
        ]
      },
      {
        "pageNumber": 2,
        "title": "SLE, ARO, and ALE: Quantifying Expected Loss",
        "body": "Before a security investment's return can be calculated, the loss it prevents must be estimated in monetary terms. Three standard, related concepts do this.\n\n### Single Loss Expectancy (SLE)\n**SLE** is the expected monetary cost of one single occurrence of a specific risk event -- for example, one successful ransomware incident affecting a defined scope of systems. SLE should include both direct costs (incident response, forensics, legal, regulatory fines) and indirect costs (business downtime, customer churn, reputational impact), inventoried against the specific assets in scope.\n\n### Annual Rate of Occurrence (ARO)\n**ARO** is the expected number of times that risk event occurs in a year, estimated from the organization's own incident history where available, or from industry benchmarks and threat intelligence for a risk that has not yet occurred at that specific organization. An ARO of 0.25, for example, represents an event expected to occur roughly once every four years.\n\n### Annualized Loss Expectancy (ALE)\n**ALE** combines the two: ALE = SLE x ARO. This produces the expected annual monetary loss from a specific risk if nothing changes -- a single, comparable figure that can be weighed against the cost of any control being considered to reduce that risk.\n\n### A worked example\nIf a ransomware incident affecting NexaCorp's finance systems is estimated at 400,000 dollars in direct and indirect cost (SLE), and industry benchmarking plus NexaCorp's own near-miss history suggests such an incident is expected roughly once every five years (ARO = 0.2), then ALE = 400,000 x 0.2 = 80,000 dollars per year in expected loss before any additional control is applied. This 80,000 dollar figure becomes the baseline the next page's ROSI calculation is measured against.",
        "codeExample": "SLE (Single Loss Expectancy) = direct cost + indirect cost of one incident\nARO (Annual Rate of Occurrence) = expected incidents per year\nALE (Annualized Loss Expectancy) = SLE x ARO\n\nExample:\n  SLE = $400,000  (one ransomware incident, finance systems scope)\n  ARO = 0.2       (roughly once every 5 years)\n  ALE = $400,000 x 0.2 = $80,000 per year",
        "keyPoints": [
          "SLE is the estimated monetary cost of one occurrence of a risk event, including both direct and indirect costs",
          "ARO is the expected annual frequency of that risk event, from incident history or industry benchmarks",
          "ALE = SLE x ARO, producing the expected annual loss from a risk before any additional control is applied",
          "ALE is the baseline figure a proposed security control's return is measured against in the next page's ROSI calculation"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Calculating ROSI",
        "body": "**ROSI** (return on security investment) answers the specific question a budget stakeholder actually asks: does the cost of this proposed detection improvement produce a return, in avoided loss, that exceeds what it costs to implement?\n\n### The ROSI formula\nROSI = (monetary loss avoided - cost of the solution) / cost of the solution\n\nThe \"monetary loss avoided\" term is not simply the full ALE calculated on the previous page -- it is the ALE **multiplied by how effectively the proposed control actually mitigates that specific risk**, since few controls eliminate a risk entirely. A control estimated to reduce the likelihood or impact of the ransomware scenario by 60 percent, applied to the previous page's 80,000 dollar ALE, avoids an estimated 48,000 dollars of that annual expected loss.\n\n### A worked calculation\nContinuing the NexaCorp example: if closing the LSASS credential-dumping detection gap (identified through this path's purple team exercises) is estimated to reduce the ransomware ALE by 60 percent (avoiding 48,000 dollars annually), and implementing the new correlation rule plus the additional log source ingestion it requires costs 15,000 dollars in engineering time and licensing for the year, then:\n\nROSI = (48,000 - 15,000) / 15,000 = 2.2, or a 220 percent return\n\n### Why the mitigation-effectiveness estimate matters most\nThe single most consequential, and most frequently overstated, number in a ROSI calculation is the mitigation-effectiveness percentage -- claiming a new rule reduces risk by 90 percent when purple team testing has only validated it against a handful of known procedure variants overstates the return and risks the team's credibility on the next funding request. This is exactly why the coverage and heatmap delta evidence from earlier lessons should ground this estimate, rather than an optimistic guess.",
        "codeExample": "ROSI = (monetary loss avoided - cost of the solution) / cost of the solution\n\nExample, continuing from page 2's ALE = $80,000:\n  Mitigation effectiveness of new detection = 60%\n  Loss avoided = $80,000 x 0.60 = $48,000\n  Cost of solution (engineering time + log ingestion) = $15,000\n\n  ROSI = ($48,000 - $15,000) / $15,000 = 2.2  (a 220% return)",
        "keyPoints": [
          "ROSI = (monetary loss avoided minus cost of the solution) divided by cost of the solution",
          "Loss avoided equals ALE multiplied by the control's estimated mitigation effectiveness, not the full ALE figure",
          "A ROSI above 0 (or above 1.0 for a 100%+ return) indicates avoided loss exceeds the control's cost",
          "Mitigation-effectiveness estimates should be grounded in actual purple team validation evidence, not optimistic guessing"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Cost Per Detection",
        "body": "Alongside ROSI, which frames one specific control against one specific risk scenario, **cost per detection** is a narrower operational metric that connects directly to the coverage work from the KPI Tracking and Heatmap Delta lessons: how much does the organization spend, on average, to achieve one meaningfully validated (DeTT&CT-scored 2 or above, \"fair\" or better) detection.\n\n### Calculating cost per detection\nCost per detection = total detection engineering program cost (staff time, SIEM licensing, purple team tooling, log ingestion costs) for a period, divided by the number of techniques that achieved a meaningful validated detection score during that same period.\n\n### Why this metric is useful alongside ROSI\nROSI answers \"is this specific investment worth it relative to a specific risk.\" Cost per detection answers a related but distinct efficiency question: is the overall detection engineering program's throughput improving or declining over time, and how does the organization's cost per detection compare across different technique categories (some techniques, requiring new log source onboarding, cost far more per detection than others that only require a new correlation rule against already-ingested data).\n\n### Using cost per detection to prioritize\nTechniques with a high cost per detection (requiring a new, expensive log source, a specialized tool, or significant engineering time) should generally be weighed against their actual risk relevance (the same prioritization logic from the KPI Tracking lesson's coverage scoping discussion) before being funded ahead of lower-cost, high-relevance techniques still sitting uncovered. A roadmap that spends disproportionately on a small number of expensive, lower-relevance techniques while ignoring several cheap, high-relevance gaps is a poor use of a finite detection engineering budget, and cost per detection is the metric that makes that trade-off visible before the budget is committed.",
        "codeExample": "Cost per detection = total detection engineering program cost (period)\n                      / number of techniques achieving DeTT&CT score >= 2 (same period)\n\nExample:\n  Program cost (quarter) = $180,000\n  Techniques newly reaching score >= 2 this quarter = 12\n  Cost per detection = $180,000 / 12 = $15,000 per validated technique",
        "keyPoints": [
          "Cost per detection divides total program cost by the number of techniques reaching a meaningful validated score in a period",
          "It answers an efficiency question distinct from ROSI's single-investment-versus-single-risk framing",
          "Some technique categories cost far more per detection than others, depending on log source and tooling requirements",
          "Comparing cost per detection against risk relevance helps prioritize a finite budget toward the highest-value gaps"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Translating Technical Risk Into Business Risk Language",
        "body": "A budget-approving executive rarely shares a detection engineer's vocabulary, and successfully securing investment depends on translating findings into terms that connect to what that executive is actually accountable for.\n\n### A translation table\n| Technical language | Business language |\n|---|---|\n| \"T1003.001 has a DeTT&CT score of 0\" | \"We currently have no validated defense against the credential-theft technique used in most recent ransomware incidents in our sector\" |\n| \"MTTD for this technique is 45 minutes\" | \"If this attack happened today, we would likely notice it 45 minutes after it started -- industry-leading programs detect this in under 5\" |\n| \"False positive rate on Rule X is 40%\" | \"Our analysts spend roughly 4 of every 10 hours on this alert type investigating activity that turns out to be harmless\" |\n| \"ROSI of 2.2 on this control\" | \"For every dollar invested here, we expect to avoid $2.20 in incident-related cost\" |\n\n### Avoiding two common translation failures\n- **Over-technical** -- presenting raw DeTT&CT scores or ATT&CK technique IDs without translation forces the executive to do the translation work themselves, which they often will not do, leaving the request unfunded not because it lacks merit but because it was not understood.\n- **Over-simplified fear appeals** -- \"we could get hacked\" without the specific, quantified ALE and ROSI backing it up reads as generic alarm rather than a credible, comparable business case, and experienced executives have usually heard that exact framing before without acting on it.\n\n### The goal of translation\nThe goal is not to hide technical rigor behind business language -- it is to make that same rigor accessible enough that the technical evidence (from every earlier lesson in this path) actually reaches the decision, rather than being filtered out by an audience that could not parse it in its original technical form.",
        "keyPoints": [
          "Technical metrics need direct translation into terms connected to what the executive audience is actually accountable for",
          "Over-technical presentation (raw scores, technique IDs with no translation) often leaves a valid request unfunded because it was not understood",
          "Generic fear appeals without quantified ALE and ROSI figures read as less credible than a specific, comparable business case",
          "Translation should make technical rigor accessible, not replace it with unsupported claims"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Structuring a Board-Level Report",
        "body": "A board-level or executive report distills the entire purple team program -- exercises, heatmap deltas, KPIs, and financial justification -- into a small number of slides or pages that an audience with limited time and limited technical background can absorb and act on.\n\n### A workable structure\n1. **Headline finding** -- one sentence stating the single most important result this period, in business language, before any supporting detail (for example: \"we closed our highest-priority ransomware-related detection gap this quarter, avoiding an estimated $48,000 in annual expected loss for a $15,000 investment\").\n2. **The heatmap delta visual** -- a single slide showing the before/after (or delta-only) Navigator layer, since it communicates program-wide progress faster than any table of numbers.\n3. **The financial case** -- the ALE, avoided loss, and ROSI calculation for the period's key investment(s), structured exactly as built in pages 2-3.\n4. **What remains uncovered, and its priority** -- the honest roadmap items from the Heatmap Delta lesson, framed as the specific investment ask for the next period, not hidden as an embarrassing gap.\n5. **Ask** -- a specific, sized request (budget amount, headcount, tooling license) tied directly to the roadmap item with the strongest ROSI or highest-relevance coverage gap.\n\n### Keeping the report honest under pressure\nA board report under pressure to show only good news is tempting to over-polish by omitting regressions or inflating mitigation-effectiveness estimates -- both of which erode the report's credibility the moment a real incident later contradicts an overstated claim. The report's long-term persuasive power depends on every number in it being traceable back to the validated evidence built throughout this path, not on how impressive any single quarter's numbers look in isolation.",
        "codeExample": "flowchart TD\n    A[\"Headline finding\\n(one sentence, business language)\"] --> B[\"Heatmap delta visual\\n(before/after or delta-only layer)\"]\n    B --> C[\"Financial case\\n(ALE, avoided loss, ROSI)\"]\n    C --> D[\"What remains uncovered\\n(honest roadmap priorities)\"]\n    D --> E[\"Specific, sized ask\\n(budget/headcount/tooling)\"]",
        "keyPoints": [
          "A board report leads with a one-sentence headline finding in business language before any supporting detail",
          "The heatmap delta visual communicates program-wide progress faster than a table of raw numbers",
          "Remaining uncovered items should be framed honestly as the next investment ask, not hidden as an embarrassing gap",
          "Every number in the report should be traceable back to validated evidence, since overstated claims erode long-term credibility"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Common Pitfalls in Security Investment Cases",
        "body": "Building a financially credible case is a skill with well-documented failure modes worth naming explicitly, since each one has previously undermined otherwise sound technical work.\n\n### Inflating loss estimates\nPadding SLE or ARO estimates to make a proposed control's ROSI look more impressive is tempting but corrosive: the first time a real incident's actual cost is compared against a previously inflated SLE estimate used to justify a past investment, every subsequent number the team presents loses credibility, regardless of its accuracy. SLE and ARO should be built from the most defensible available evidence (actual incident history, credible industry benchmarks, insurance actuarial data where available) and clearly labeled with their confidence level, not silently rounded upward.\n\n### Ignoring soft costs\nDirect incident costs (forensics, legal, regulatory fines) are easier to quantify than soft costs (customer trust erosion, employee morale during a prolonged incident, competitive disadvantage from a public breach disclosure), which leads many ROSI calculations to systematically undercount SLE by omitting them entirely. A defensible estimate should at minimum acknowledge soft costs exist and note them as a conservative, likely-understated component of SLE, rather than pretending they do not exist because they are harder to quantify precisely.\n\n### Treating ROSI as the only decision factor\nA control with a modest or even negative ROSI in isolation can still be the right investment if it is a regulatory or contractual requirement, or if it protects against a low-probability but existential (rather than merely costly) risk where ARO-based expected-value reasoning understates the true stakes. ROSI is a powerful comparison tool, not a complete substitute for judgment about risks whose true cost is not well captured by an annualized average.\n\n### Presenting a single-scenario ROSI as if it covers the whole investment\nA detection improvement often reduces risk across several different attack scenarios simultaneously; presenting ROSI against only the single easiest-to-quantify scenario understates the investment's true value and should be disclosed as a conservative, partial estimate rather than the complete picture.",
        "keyPoints": [
          "Inflating SLE or ARO to improve a ROSI figure destroys long-term credibility once a real incident's actual cost is compared against it",
          "Soft costs (trust erosion, morale, competitive disadvantage) are often omitted from SLE, systematically undercounting expected loss",
          "ROSI should inform, not replace, judgment about regulatory requirements and low-probability, existential risks",
          "A ROSI calculated against only one attack scenario should be disclosed as a conservative partial estimate, not the full picture"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Case Study: NexaCorp's Detection Investment Ask",
        "body": "Bringing the lesson together, consider how NexaCorp's detection engineering lead assembles a complete investment case for closing the credential-access detection gap identified across earlier lessons in this path.\n\n### Assembling the case, step by step\n1. **Quantify the risk** -- using industry benchmark data for financial-sector ransomware incidents plus NexaCorp's own near-miss history, the team estimates SLE at $400,000 and ARO at 0.2, giving an ALE of $80,000 (page 2).\n2. **Estimate mitigation effectiveness conservatively** -- rather than claiming the new LSASS-access correlation rule (validated via the Atomic Red Team and replay-testing lessons) eliminates the risk entirely, the team estimates 60 percent effectiveness, citing the specific atomic tests and Sigma rule fixture results that support that number.\n3. **Calculate ROSI** -- $48,000 avoided loss against a $15,000 solution cost yields a 220 percent return (page 3).\n4. **Add cost-per-detection context** -- the team notes this specific technique's cost per detection ($15,000) is below the program's quarterly average ($15,000 program-wide this period, coincidentally similar here but tracked separately), supporting that this is an efficient use of the requested budget relative to other options.\n5. **Translate and present** -- the headline finding, heatmap delta visual, financial case, and a specific $15,000 budget ask for the next quarter's log ingestion licensing are assembled into the six-part board report structure from page 6.\n6. **Disclose honestly** -- the report notes this ROSI reflects only the ransomware scenario and that the same detection improvement likely also reduces risk from other credential-theft-driven attack paths not separately quantified here.\n\nThis worked sequence -- quantify, estimate conservatively, calculate, contextualize, translate, disclose -- is the repeatable pattern connecting every technical result from earlier lessons in this path to an actual, fundable, credible investment decision.",
        "keyPoints": [
          "A complete investment case chains quantified risk, conservative mitigation estimates, ROSI, and cost-per-detection context together",
          "Mitigation-effectiveness estimates should cite the specific validation evidence (atomic tests, fixture results) that supports them",
          "The board report structure from page 6 is the final delivery vehicle for the assembled financial case",
          "Honest disclosure of a ROSI's scenario-specific scope maintains credibility for future investment requests"
        ]
      }
    ],
    "quiz": [
      {
        "question": "In the ALE (Annualized Loss Expectancy) calculation, what does multiplying SLE by ARO actually represent?",
        "options": [
          {
            "label": "The expected annual monetary loss from the risk before any mitigation is applied",
            "value": "a"
          },
          {
            "label": "The total historical cost of every past incident the organization has ever experienced, summed together across all years",
            "value": "b"
          },
          {
            "label": "The exact engineering and licensing cost of the proposed detection control needed to fully eliminate the risk described",
            "value": "c"
          },
          {
            "label": "The percentage return the organization can expect from any future increase to its overall security budget",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "ALE = SLE x ARO produces the expected annual loss from a risk assuming no additional mitigation is applied, which then becomes the baseline a proposed control's return is measured against. It is not a sum of past incidents, the cost of a specific control, or a general budget return percentage."
      },
      {
        "question": "When calculating ROSI for a proposed detection improvement, why is 'monetary loss avoided' equal to ALE multiplied by mitigation effectiveness, rather than the full ALE figure?",
        "options": [
          {
            "label": "Few controls eliminate a risk entirely, so only the portion actually mitigated should count as avoided loss",
            "value": "a"
          },
          {
            "label": "ALE must always be divided by the number of years the control will remain in service before it becomes usable",
            "value": "b"
          },
          {
            "label": "ROSI calculations are legally required to discount ALE by a fixed 50 percent under most accepted frameworks",
            "value": "c"
          },
          {
            "label": "Mitigation effectiveness as a concept only applies to controls that cost more than the ALE figure itself",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Using the full ALE as avoided loss would overstate a control's benefit, since most controls reduce rather than eliminate a risk; multiplying by an evidence-based mitigation-effectiveness percentage keeps the avoided-loss figure honest. There is no such division-by-years step, no fixed legal discount, and mitigation effectiveness is not gated by the control's cost."
      },
      {
        "question": "What distinct question does cost per detection answer that ROSI does not directly address?",
        "options": [
          {
            "label": "Whether the overall detection engineering program's spending efficiency is improving or declining over time",
            "value": "b"
          },
          {
            "label": "Whether a specific single control's benefit exceeds its cost relative to one particular quantified risk scenario",
            "value": "a"
          },
          {
            "label": "Whether a proposed control is specifically required by a regulatory or contractual obligation the organization holds",
            "value": "c"
          },
          {
            "label": "Whether an attacker's dwell time on a compromised host exceeded the organization's stated MTTD target for that period",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Cost per detection measures overall program throughput and efficiency (total program cost divided by number of techniques reaching a validated score), a distinct question from whether one specific control's benefit exceeds its cost against one quantified risk scenario -- that single-control comparison is exactly what ROSI already answers. Regulatory obligation and MTTD/dwell time are separate considerations neither metric directly measures."
      },
      {
        "question": "A detection engineer presents a finding to executives as 'T1003.001 currently scores 0 on our DeTT&CT baseline' with no further explanation. What translation problem does this illustrate?",
        "options": [
          {
            "label": "Presenting raw technical scoring without translating it into business-relevant, accountability-linked language for the audience",
            "value": "c"
          },
          {
            "label": "Using a fear-based appeal with no quantified ALE or ROSI figures to support the specific claim being made",
            "value": "a"
          },
          {
            "label": "Inflating the underlying SLE estimate behind the finding to make the associated ROSI appear artificially higher",
            "value": "b"
          },
          {
            "label": "Omitting soft costs such as customer trust erosion from the underlying loss estimate calculation entirely",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Presenting a raw DeTT&CT score with no translation forces the audience to do the interpretation themselves, which is the over-technical presentation failure mode described in this lesson, distinct from a fear appeal, an inflated SLE, or an omitted soft cost, none of which are present in this specific example."
      },
      {
        "question": "Why should a security team avoid inflating its SLE or ARO estimates to make a proposed control's ROSI appear more impressive?",
        "options": [
          {
            "label": "A real incident's actual future cost compared against a past inflated estimate destroys the team's long-term credibility",
            "value": "d"
          },
          {
            "label": "Inflated SLE and ARO estimates are automatically detected and rejected by any standard ROSI calculation formula itself",
            "value": "a"
          },
          {
            "label": "Regulatory frameworks impose direct financial penalties on any organization found to have overstated an SLE figure",
            "value": "b"
          },
          {
            "label": "An inflated ROSI figure always produces a correspondingly lower cost-per-detection value in the same reporting period",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The real risk of inflating loss estimates is reputational and practical: once a real incident's actual cost contradicts a previously inflated figure used to justify an investment, every future number the team presents loses credibility. The ROSI formula itself has no built-in detection of inflated inputs, there is no such regulatory penalty framework described, and ROSI inflation has no direct mechanical link to cost-per-detection values."
      }
    ]
  },
  "purple-team--detection-maturity": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Measure Maturity, Not Just Coverage",
        "body": "Every lesson so far in this path has measured *what* is detected: coverage percentage, heatmap deltas, KPIs. **Detection maturity** asks a different, broader question: *how* the organization arrives at and sustains that coverage -- whether detection engineering is a repeatable, well-governed discipline with defined processes, skilled people, and appropriate tooling, or whether current coverage exists mostly through individual heroics that would collapse the moment a key person left the team.\n\n### The analogy\nTwo SOCs might report identical detection coverage percentages this quarter. One achieves it through a documented, repeatable process -- purple team exercises on a fixed cadence, detection-as-code pipelines, KPI review meetings -- that will keep producing similar or better results next quarter regardless of staff turnover. The other achieves the same number because one exceptionally skilled analyst personally remembers which rules need attention and manually patches gaps as they notice them, with no documentation of why. The first is mature; the second has good current coverage but low maturity, and a maturity model exists specifically to tell these two situations apart, since coverage numbers alone cannot.\n\n### Two maturity models this lesson covers\n- **SOC-CMM** (Security Operations Center Capability Maturity Model) -- a broad framework assessing the entire SOC across five domains: business, people, process, technology, and services.\n- **DeTT&CT's own maturity dimensions** -- narrower, purpose-built specifically for detection engineering: data quality, visibility, and detection scoring, already introduced in the Heatmap Delta lesson, now framed explicitly as a maturity measurement rather than a single-exercise scoring exercise.\n\n### What this lesson builds toward\nUnderstanding both models, how to conduct a self-assessment, how to interpret the resulting scores, and how to convert a maturity assessment into a genuine improvement roadmap rather than a one-time score that sits unused after the assessment is complete.",
        "keyPoints": [
          "Detection maturity measures how repeatably and sustainably coverage is achieved, not just the current coverage number itself",
          "Identical coverage percentages can hide very different maturity levels: repeatable process versus individual heroics",
          "SOC-CMM assesses the whole SOC across five domains; DeTT&CT's maturity dimensions focus narrowly on detection engineering",
          "The lesson builds toward conducting an assessment, interpreting scores, and building an improvement roadmap from them"
        ]
      },
      {
        "pageNumber": 2,
        "title": "SOC-CMM: Five Domains, Two Scales",
        "body": "**SOC-CMM** is a free, publicly available capability and maturity model and self-assessment tool purpose-built for security operations centers, measuring capability and maturity across dozens of individual aspects grouped into five domains.\n\n### The five domains\n- **Business** -- how well the SOC's mission, stakeholders, and services are defined and aligned with organizational risk and business objectives.\n- **People** -- staffing levels, skills, training, and role clarity within the SOC.\n- **Process** -- how formally defined, documented, and consistently followed the SOC's operational processes are (which directly includes the detection engineering and purple team processes covered throughout this path).\n- **Technology** -- the SOC's tooling: SIEM, EDR, orchestration, and how well that tooling is actually leveraged rather than merely deployed.\n- **Services** -- the specific services the SOC delivers (monitoring, incident response, threat hunting, and detection engineering itself as a distinct service).\n\n### Two distinct scales, scored separately\nSOC-CMM deliberately separates two related but distinct questions for each aspect:\n- **Maturity** -- scored on a six-level scale from 0 to 5, describing how formally defined and consistently executed a given aspect is (similar in spirit to the DeTT&CT detection score scale, though measuring process maturity rather than detection effectiveness).\n- **Capability** -- scored on a four-level scale from 0 to 3, describing how effectively that aspect actually performs its intended function, regardless of how formally it is documented.\n\n### Why separating maturity and capability matters\nA highly capable but low-maturity aspect (an individual analyst who is genuinely excellent at threat hunting but with no documented methodology anyone else could follow) is fragile -- it works today but is a single point of failure. A highly mature but low-capability aspect (a thoroughly documented process that nobody actually follows effectively in practice) is equally concerning, just in the opposite direction. SOC-CMM's two-scale design exists specifically to surface this distinction, which a single combined score would hide.",
        "keyPoints": [
          "SOC-CMM measures dozens of individual aspects across five domains: business, people, process, technology, and services",
          "Maturity is scored on a six-level scale (0-5); capability is scored separately on a four-level scale (0-3)",
          "Maturity measures how formally defined and consistently executed an aspect is, not how well it performs",
          "High capability with low maturity is fragile (a single-person dependency); high maturity with low capability means process nobody effectively follows"
        ]
      },
      {
        "pageNumber": 3,
        "title": "DeTT&CT's Maturity Dimensions, Revisited",
        "body": "The Heatmap Delta lesson introduced DeTT&CT's detection scoring scale (-1 through 5) for a single purple team cycle's before/after comparison. Framed as a maturity model rather than a one-time exercise score, DeTT&CT actually measures maturity across **three related dimensions**, each with its own scoring table.\n\n### The three dimensions\n- **Data quality** -- scored across five sub-dimensions (device completeness, data field completeness, timeliness, consistency, and retention, as introduced when tracking log source health), reflecting whether the raw data a detection would need is actually available and trustworthy, independent of whether any rule currently uses it.\n- **Visibility** -- whether the organization has *access* to enough reliable data sources to observe a given technique's associated behavior at all, distinct from whether a rule currently watches that data.\n- **Detection** -- the -1 to 5 scale from the Heatmap Delta lesson, scoring whether an active rule actually catches the technique, and how well.\n\n### Why three separate dimensions, not one combined score\nA technique can have excellent visibility (the right log source is fully ingested, complete, and current) but a detection score of 0, because nobody has written a rule against that data yet -- this is a detection-engineering backlog problem, solvable quickly by writing a rule. A different technique might have a detection score of 0 because visibility itself is the gap (the log source does not exist at all) -- this is a much larger, more expensive problem requiring new tooling or log source onboarding before any rule-writing is even possible. Collapsing these into one number would make these two very different problems look identical, when they require completely different remediation and completely different budget asks.\n\n### Connecting this back to earlier lessons\nThis is precisely the visibility-versus-detection-logic distinction introduced in the Atomic Red Team lesson's \"no alert fired\" interpretation guidance -- DeTT&CT's three-dimension structure formalizes that same distinction into a full maturity measurement framework applied across the entire technique matrix, not just one tested technique at a time.",
        "keyPoints": [
          "DeTT&CT measures maturity across three dimensions: data quality, visibility, and detection -- each scored separately",
          "Data quality has five sub-dimensions: device completeness, data field completeness, timeliness, consistency, and retention",
          "Visibility measures data access independent of whether a rule uses it; detection measures whether an active rule actually catches the technique",
          "Separating these dimensions distinguishes a quick rule-writing fix from a much larger, costlier log-source-onboarding problem"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Conducting a Maturity Self-Assessment",
        "body": "Both SOC-CMM and DeTT&CT are designed as **self-assessment** tools -- conducted by the organization's own team rather than requiring an external auditor, though an external review can add valuable objectivity, especially for a first assessment.\n\n### Preparing for a SOC-CMM self-assessment\n- Gather participants representing each domain being assessed -- a SOC manager and analysts for people/process, a detection engineer for technology/process, and someone with visibility into budget and stakeholder relationships for the business domain.\n- Score each of the 26 aspects honestly against the tool's defined criteria for each maturity and capability level, resisting the temptation to round scores upward -- the same evidence-based discipline emphasized for DeTT&CT scoring in the Heatmap Delta lesson applies here equally.\n- Document the specific evidence behind each score (a named process document, a specific staffing metric, a specific tool's utilization rate), so the assessment is defensible and repeatable next cycle, not a one-time impression.\n\n### Preparing for a DeTT&CT maturity assessment\n- Use the same technique scope established for the organization's purple team program (from the KPI Tracking lesson's scoping discussion), since maturity assessment benefits from the same defined boundaries as any other measurement in this path.\n- Score data quality, visibility, and detection separately for each technique in scope, using each dimension's own scoring table, rather than estimating one blended number.\n- Where a dimension has never actually been tested (unvalidated detection scores, as discussed in the Heatmap Delta lesson), score it honestly as untested rather than assumed.\n\n### A shared principle across both models\nBoth assessments produce far more value when scored conservatively and evidence-based than when scored to present the most favorable possible picture -- an inflated maturity assessment produces a roadmap that solves problems that do not actually exist while leaving real gaps unaddressed, the maturity-assessment equivalent of the inflated ROSI pitfall covered in the Investment Justification lesson.",
        "keyPoints": [
          "SOC-CMM and DeTT&CT are both self-assessment tools, though external review can add objectivity, especially for a first assessment",
          "SOC-CMM assessment requires participants covering each of the five domains, scoring honestly against defined criteria",
          "DeTT&CT assessment should reuse the same technique scope as the purple team program and score dimensions separately, not blended",
          "Conservative, evidence-based scoring produces a more useful roadmap than an inflated assessment, echoing the ROSI inflation pitfall"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Interpreting Scores and Identifying Gaps",
        "body": "Raw maturity scores only become useful once interpreted against a meaningful reference point -- an absolute scale position alone does not tell a team what to prioritize.\n\n### Reading a SOC-CMM result\nA domain scoring low maturity but moderate-to-high capability (people and process aspects are especially prone to this pattern) signals a team performing well today through informal, undocumented practice -- a near-term priority for documentation, since the current good performance is not resilient to turnover. A domain scoring moderate maturity but low capability signals a documented process that is not actually working, which needs process redesign, not merely enforcement of the existing documented steps that are not producing the intended result.\n\n### Reading a DeTT&CT result\nAggregating detection scores alone, without cross-referencing visibility and data quality for the same techniques, risks misdiagnosing the required fix (as covered on page 3). A useful interpretation pattern: for every technique with a low detection score, check its visibility and data quality scores first, since a low detection score with high visibility and good data quality is a rule-writing backlog item, while a low detection score with low visibility is a much larger data-onboarding project.\n\n### Finding the highest-priority gaps\nCross-referencing both models is often the most revealing step: a technique with strong DeTT&CT detection maturity sitting inside a SOC-CMM domain with low process maturity (for example, well-detected today, but only because one specific analyst maintains that rule manually with no documented process) represents hidden fragility that neither model alone fully surfaces -- SOC-CMM's process score flags the fragility, while DeTT&CT's detection score would look reassuringly high in isolation.\n\n### Avoiding score obsession\nThe specific numeric score matters far less than the gap it points to and the action that gap implies -- two assessments a year apart showing the same numeric score but addressing entirely different underlying gaps represent very different programs, and the score alone cannot distinguish them.",
        "keyPoints": [
          "Low maturity with moderate-to-high capability signals informal but currently-working practice, fragile to staff turnover",
          "Moderate maturity with low capability signals a documented process that does not actually work, needing redesign not enforcement",
          "For any low DeTT&CT detection score, checking visibility and data quality first distinguishes a rule-writing gap from a larger onboarding project",
          "Cross-referencing SOC-CMM process maturity against DeTT&CT detection scores surfaces hidden fragility neither model alone reveals"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Building an Improvement Roadmap From the Assessment",
        "body": "A maturity assessment's value is fully realized only when its findings become a structured, prioritized improvement roadmap -- the same principle emphasized for the heatmap delta's roadmap in an earlier lesson, now applied at the broader program-maturity level.\n\n### Prioritization logic for a maturity roadmap\n- **Fragile high performers first** -- a domain or technique showing high current capability but low maturity (the single-analyst-dependency pattern from page 5) deserves early attention even though current performance looks fine, precisely because it is the pattern most likely to fail suddenly and without warning.\n- **Foundational gaps before advanced ones** -- a visibility gap (no log source at all) should generally be addressed before investing further in detection-logic refinement for techniques that already have good visibility but a merely mediocre detection score, since visibility is a prerequisite for any detection improvement to even be possible.\n- **Process gaps that block scaling** -- a SOC-CMM process-domain gap that prevents the purple team program itself from running repeatably (no defined exercise cadence, no documented emulation-plan template) should be prioritized ahead of individual technique-level gaps, since fixing it improves the organization's ability to close every other gap faster afterward.\n\n### Structuring the roadmap document\nMirroring the heatmap-delta roadmap's structure, each prioritized item should list: the specific gap (citing which model and dimension flagged it), the target maturity or capability level for the next assessment cycle, the specific planned action, and an owner -- the same discipline applied to every roadmap artifact built throughout this path.\n\n### Timing the next assessment\nA full maturity reassessment on the same cadence as the heatmap-delta cycle would likely be excessive, since process and capability maturity shift more slowly than individual technique detection scores; most organizations reassess SOC-CMM and DeTT&CT maturity annually or semi-annually, while continuing the faster quarterly cadence for the KPI and heatmap-delta cycles covered in earlier lessons.",
        "keyPoints": [
          "Fragile high performers (high capability, low maturity) deserve early roadmap attention despite looking fine today",
          "Foundational visibility gaps should generally be prioritized before refining detection logic on already-visible techniques",
          "Process gaps that block the purple team program's own repeatability should be prioritized, since fixing them accelerates every other fix",
          "Maturity reassessment typically runs on a slower annual or semi-annual cadence than the faster quarterly KPI and heatmap-delta cycles"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Maturity Versus Capability: Avoiding Common Pitfalls",
        "body": "The maturity-versus-capability distinction introduced on page 2 is worth returning to directly, since conflating the two is the single most common misstep in applying either model.\n\n### Pitfall: treating maturity as inherently better than capability\nA team might assume that maximizing maturity (SOC-CMM's 0-5 scale, or a thorough written process for every purple team activity) is unambiguously good, but an over-engineered, heavily documented process for a low-risk, rarely-exercised activity can waste effort that would be better spent elsewhere -- maturity investment should be weighted by the risk and frequency of what it governs, not pursued as a goal in itself independent of actual value delivered.\n\n### Pitfall: chasing a numeric score instead of the underlying capability\nA team that specifically writes documentation to raise its SOC-CMM maturity score, without changing how work is actually done, produces a maturity score that no longer reflects reality -- exactly the DeTT&CT-scoring-honesty problem from page 4, now applied to process documentation rather than detection validation.\n\n### Pitfall: assessing once and never again\nA maturity assessment conducted once, filed away, and never revisited provides a useful one-time snapshot but none of the trend-over-time value that makes the heatmap-delta and KPI-tracking measurements from earlier lessons genuinely useful for demonstrating program improvement to stakeholders (the Investment Justification lesson's board-reporting structure).\n\n### Pitfall: assessing in isolation from the rest of the purple team program\nA maturity assessment that does not draw on the same emulation plans, KPI data, and heatmap deltas already being generated by the rest of the purple team program duplicates effort and risks inconsistent conclusions -- the strongest maturity assessments treat the earlier lessons' outputs as direct evidence inputs, rather than conducting maturity assessment as an entirely separate exercise disconnected from the program's existing measurement infrastructure.",
        "keyPoints": [
          "Maximizing maturity for its own sake, independent of actual risk and frequency, can waste effort better spent elsewhere",
          "Writing documentation purely to raise a maturity score, without changing real practice, produces a score that no longer reflects reality",
          "A one-time assessment loses the trend-over-time value that makes maturity measurement genuinely useful for stakeholders",
          "Maturity assessment should draw on the same emulation plans, KPI data, and heatmap deltas the program already produces, not run in isolation"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Closing the Loop: Maturity as the Program's Operating System",
        "body": "This final lesson in the Purple Team path closes a chain that began with a single atomic test: individual technique validation (Atomic Red Team, CALDERA) feeds custom TTP development, which feeds replay-tested detection rules, which feed KPI tracking and heatmap deltas, which feed investment justification, and now, maturity measurement sits above all of it -- assessing whether the entire chain itself is repeatable, well-resourced, and sustainable.\n\n### How maturity measurement uses everything else in this path\n- SOC-CMM's process domain score depends directly on whether the practices from every earlier lesson (atomic test cadence, custom TTP sourcing discipline, replay-pipeline CI/CD, KPI reporting cadence) are actually documented and consistently followed, not just occasionally performed.\n- DeTT&CT's three dimensions are populated directly by the visibility findings, detection validation results, and data quality observations generated throughout every purple team exercise run using the earlier lessons' methods.\n- The improvement roadmap this lesson builds feeds directly into the next cycle's emulation plan (Custom TTPs lesson) and the next heatmap-delta baseline (Heatmap Delta lesson), closing the loop back to where the technical work actually happens.\n\n### The operating rhythm of a mature purple team program\nA mature program runs multiple measurement cadences simultaneously: continuous replay-pipeline testing on every rule change, quarterly purple team exercises producing KPI updates and heatmap deltas, and annual or semi-annual maturity reassessments checking whether the whole system generating those faster-cadence results is itself still healthy, well-resourced, and improving -- not a sequence of disconnected activities, but one integrated program where each lesson's output becomes the next lesson's input.\n\n### The measure of success\nA purple team program's ultimate success is not a single impressive coverage percentage or ROSI figure in one quarter's report -- it is a demonstrated, multi-cycle trend of closing real, validated gaps, sustained by a maturing process that will keep producing that trend even as individual team members, tools, and threats change over time.",
        "keyPoints": [
          "Maturity measurement sits above the technical chain built throughout this path, assessing whether that whole chain is repeatable and sustainable",
          "SOC-CMM's process domain and DeTT&CT's three dimensions are populated directly by evidence from earlier lessons' exercises",
          "The maturity roadmap feeds back into the next cycle's emulation plan and heatmap-delta baseline, closing the full program loop",
          "A mature program's real measure of success is a sustained multi-cycle trend, not any single quarter's impressive number"
        ]
      }
    ],
    "quiz": [
      {
        "question": "Two SOCs report identical detection coverage percentages this quarter. Why might their SOC-CMM maturity scores differ significantly?",
        "options": [
          {
            "label": "One achieves it through a documented, repeatable process; the other relies on undocumented expertise",
            "value": "a"
          },
          {
            "label": "SOC-CMM only assigns different scores based on the total number of analysts employed by each SOC in question",
            "value": "b"
          },
          {
            "label": "Coverage percentage and maturity score are mathematically identical, so any difference indicates a calculation error",
            "value": "c"
          },
          {
            "label": "SOC-CMM maturity scores are determined entirely by which specific SIEM vendor a given SOC has deployed",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Identical current coverage can be achieved through very different means: a repeatable, documented process versus an individual's undocumented expertise, and SOC-CMM's maturity scale is specifically designed to distinguish these two situations that a coverage percentage alone cannot tell apart. Maturity is not driven by headcount alone, is not mathematically tied to coverage percentage, and is not determined by SIEM vendor choice."
      },
      {
        "question": "In SOC-CMM, what is the key difference between an aspect's maturity score and its capability score?",
        "options": [
          {
            "label": "Maturity measures how formally the aspect is defined and followed; capability measures how well it performs",
            "value": "b"
          },
          {
            "label": "Maturity is scored only by an external auditor, while capability can only be scored through internal self-assessment",
            "value": "a"
          },
          {
            "label": "Maturity applies only to the technology domain, while capability applies only to the people domain instead",
            "value": "c"
          },
          {
            "label": "Maturity and capability are simply two different names for the exact same underlying six-level scoring scale",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "SOC-CMM deliberately separates maturity (how formally defined and consistently followed an aspect is, on a 0-5 scale) from capability (how effectively it actually performs, on a 0-3 scale), since a process can be well-documented but ineffective, or effective but undocumented. Both can be self-assessed, both scales apply across all five domains, and they use different scale ranges, not the same one."
      },
      {
        "question": "A technique shows a DeTT&CT detection score of 0, but its visibility and data quality scores are both high. What does this combination most likely indicate?",
        "options": [
          {
            "label": "A rule-writing backlog item, since the data is already available and reliable but no rule exists yet",
            "value": "c"
          },
          {
            "label": "A missing log source that must first be onboarded before any further work on this technique is even possible",
            "value": "a"
          },
          {
            "label": "A data quality problem specifically tied to the retention sub-dimension of that particular log source",
            "value": "b"
          },
          {
            "label": "An error somewhere in the assessment, since a detection score of 0 always implies low visibility as well",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "High visibility and good data quality alongside a detection score of 0 means the needed data is present and trustworthy but simply lacks an active rule -- a comparatively quick rule-writing fix, distinct from a missing log source (which would show as low visibility) or a data quality issue (which would show as a low data quality score, not a high one). A detection score of 0 does not automatically imply low visibility."
      },
      {
        "question": "Why might a technique with a high DeTT&CT detection score still represent hidden fragility when cross-referenced against a low SOC-CMM process maturity score?",
        "options": [
          {
            "label": "The detection may rely on one analyst's undocumented knowledge rather than a repeatable process",
            "value": "b"
          },
          {
            "label": "A high detection score is only considered valid if the SOC-CMM technology domain also scores above 3",
            "value": "a"
          },
          {
            "label": "DeTT&CT detection scores automatically expire and reset back to 0 whenever process maturity is assessed as low",
            "value": "c"
          },
          {
            "label": "SOC-CMM and DeTT&CT cannot be used together at all, so comparing their scores is meaningless by design",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A high detection score can mask fragility if it depends on one person's informal, undocumented effort rather than a documented, repeatable process, which is exactly the pattern low process maturity flags. There is no cross-domain score dependency requiring technology above 3, detection scores do not automatically reset based on process maturity, and the two models are explicitly meant to be used together, not treated as incompatible."
      },
      {
        "question": "When building an improvement roadmap from a maturity assessment, why should a foundational visibility gap generally be prioritized ahead of refining detection logic on an already-visible technique?",
        "options": [
          {
            "label": "Visibility is a prerequisite for any detection improvement on that technique to even be possible at all",
            "value": "d"
          },
          {
            "label": "Visibility gaps are always cheaper to fix than any detection-logic refinement, regardless of the situation at hand",
            "value": "a"
          },
          {
            "label": "SOC-CMM requires every visibility gap to be resolved before any process-domain aspect can be assessed at all",
            "value": "b"
          },
          {
            "label": "DeTT&CT's scoring tool technically prevents entering any detection score for a technique with low visibility",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "Without adequate visibility, no detection rule can ever fire, since the data it would need to match against simply is not being collected -- making visibility a genuine prerequisite, not merely a preference. Visibility fixes are not universally cheaper (they can require significant new tooling), SOC-CMM has no such sequencing requirement, and DeTT&CT's scoring tool does not technically block entering a detection score regardless of visibility."
      }
    ]
  }
};
