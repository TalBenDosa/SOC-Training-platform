/**
 * Learning Rooms — Batch 32
 *
 * One foundation-tier room closing a gap flagged in the F19 platform audit:
 * five beginner-facing Dashboard scenario packs (clickFixFakeCaptcha.ts,
 * clipboardClipper.ts, seoPoisonedInstaller.ts, isoContainerSmuggling.ts,
 * driveByBrowserMiner.ts) had no theory room teaching the concepts or the
 * vocabulary a brand-new student would need before ever reaching them, so
 * "no hints" in those scenarios effectively meant "no foundation."
 *
 * Rooms in this batch:
 *  1. commodity-initial-access — the post-macro (2022+) commodity
 *     initial-access landscape: ClickFix / fake CAPTCHA (T1204.004,
 *     T1059.001, T1105), clipboard clippers (T1115, T1059.003),
 *     SEO-poisoned / malvertised installers (T1608.006, T1105, T1555.003),
 *     ISO / Mark-of-the-Web container smuggling (T1553.005, T1204.002),
 *     and drive-by in-browser cryptomining (T1189, T1496).
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Modern Commodity Initial-Access Techniques (2024–2026)
// ===========================================================================

const seoInstallerEvent: TelemetryEvent = {
  id: "evt-mcia-la1-001",
  ts: "2026-02-09T10:41:14.000Z",
  source: "firewall",
  vendor: "Palo Alto Networks PAN-OS",
  event_type: "http_request",
  severity: "high",
  mitre_technique: "T1105",
  mitre_tactic: "Command and Control",
  hostname: "LAP-9021",
  user_email: "d.mizrahi@nexacorp.com",
  user_title: "IT Support Technician",
  src_ip: "10.14.52.18",
  description:
    "LAP-9021's freshly-launched 7zSetup-2026.exe reached out to an unrelated domain, cdn-pkg-mirror19.net, four seconds after it started, and pulled down helper_upd.exe.",
  file: {
    name: "helper_upd.exe",
    path: "/pkg/helper_upd.exe",
    extension: "exe",
    size: 2_884_096,
    sha256: "b9a1a928342a6d2d55c3aa07b271609d613c66f5132326f19ed24dfcb36684ad",
  },
  network: {
    url: "https://cdn-pkg-mirror19.net/pkg/helper_upd.exe",
    domain: "cdn-pkg-mirror19.net",
    method: "GET",
    status: 200,
    bytes_in: 2_884_096,
  },
  raw: {
    "pan.type": "THREAT",
    "pan.subtype": "file",
    "pan.action": "alert",
    "pan.rule": "CORP-WEB-OUTBOUND",
    "pan.src": "10.14.52.18",
    "pan.srcuser": "nexacorp\\d.mizrahi",
    "pan.dst": "185.220.101.44",
    "pan.dport": "443",
    "pan.app": "web-browsing",
    "pan.category": "newly-registered-domain",
    "pan.url": "cdn-pkg-mirror19.net/pkg/helper_upd.exe",
    "pan.filename": "helper_upd.exe",
    "pan.filetype": "pe",
    "pan.file_hash": "b9a1a928342a6d2d55c3aa07b271609d613c66f5132326f19ed24dfcb36684ad",
    "pan.direction": "download",
    "pan.session_id": "812204",
    "source.ip": "10.14.52.18",
    "url.domain": "cdn-pkg-mirror19.net",
    "action_result": "alert",
  },
};

const driveByMinerEvent: TelemetryEvent = {
  id: "evt-mcia-la2-001",
  ts: "2026-06-03T15:47:41.000Z",
  source: "firewall",
  vendor: "Palo Alto Networks PAN-OS",
  event_type: "net_connection",
  severity: "critical",
  mitre_technique: "T1496",
  mitre_tactic: "Impact",
  hostname: "LAP-4471",
  user_email: "m.harel@nexacorp.com",
  user_title: "Marketing Coordinator",
  src_ip: "10.14.61.9",
  dst_port: 443,
  protocol: "tcp",
  description:
    "The WebSocket session LAP-4471 opened to relay-ws-pool3.net stayed connected for nineteen minutes, exchanging small steady bursts, before closing when the browser tab was moved to the background.",
  network: {
    domain: "relay-ws-pool3.net",
    bytes_out: 14_800,
    bytes_in: 51_300,
  },
  raw: {
    "pan.type": "TRAFFIC",
    "pan.subtype": "end",
    "pan.action": "allow",
    "pan.rule": "CORP-WEB-OUTBOUND",
    "pan.src": "10.14.61.9",
    "pan.srcuser": "nexacorp\\m.harel",
    "pan.dst": "45.155.207.88",
    "pan.dport": "443",
    "pan.app": "websocket",
    "pan.category": "unknown",
    "pan.bytes_sent": "14800",
    "pan.bytes_received": "51300",
    "pan.elapsed_time": "1140",
    "pan.session_id": "641177",
    "source.ip": "10.14.61.9",
    "url.domain": "relay-ws-pool3.net",
    "action_result": "allow",
  },
};

const legitPasteRunEvent: TelemetryEvent = {
  id: "evt-mcia-ac1-001",
  ts: "2026-04-17T11:02:08.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "WS-6820",
  user_email: "y.cohen@nexacorp.com",
  user_title: "DevOps Engineer",
  src_ip: "10.14.10.44",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-44190 approves the DevOps team's rollout of the Chocolatey package manager across engineering workstations this week; y.cohen's install falls inside the approved rollout window.",
  description:
    "explorer.exe launched a hidden-window PowerShell process on WS-6820 that downloaded a script from community.chocolatey.org and ran it in memory.",
  process: {
    name: "powershell.exe",
    pid: 5502,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "explorer.exe",
    parent_pid: 4108,
    cmdline:
      "powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command \"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"",
    user: "NEXACORP\\y.cohen",
    integrity: "high",
    hash: { sha256: "b1e5d29a7c4f60831e9a5c7f4b28d6039e1a7c4f6b83d05e2c8f4e6b91d3a75c" },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.Tactic": "Execution",
    "threat.tactic.id": "TA0002",
    "crowdstrike.Technique": "Command and Scripting Interpreter: PowerShell",
    "threat.technique.id": "T1059",
    "threat.technique.subtechnique.id": "T1059.001",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.PatternDispositionValue": "10",
    "crowdstrike.PatternDispositionDescription": "Detection, No Action",
    "crowdstrike.aid": "b71e04af9c2d4a86bf05e1cd8a3f7d29",
    "crowdstrike.NetworkContainmentState": "Not Contained",
    "event.action": "process_created",
    "process.name": "powershell.exe",
    "process.pid": "5502",
    "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "process.command_line":
      "powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command \"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"",
    "process.hash.sha256": "b1e5d29a7c4f60831e9a5c7f4b28d6039e1a7c4f6b83d05e2c8f4e6b91d3a75c",
    "process.code_signature.exists": true, "process.code_signature.trusted": true,
    "process.parent.name": "explorer.exe",
    "process.parent.pid": "4108",
    "user.name": "NEXACORP\\y.cohen",
    "host.name": "WS-6820",
    "host.ip": "10.14.10.44",
  },
};

const commodityInitialAccessRoom = {
  id: "commodity-initial-access",
  title: "Modern Commodity Initial-Access Techniques (2024–2026)",
  description:
    "Five ways attackers get their first foothold without a malicious document macro and often without a classic file download at all: a fake CAPTCHA that pastes its own command (ClickFix), a bundled utility that silently swaps cryptocurrency wallet addresses (clipboard clipper), a sponsored search result leading to a fake installer (SEO poisoning), a downloaded ISO that slips past the Mark-of-the-Web warning, and a compromised web page that mines cryptocurrency inside a browser tab. Learn to recognise each one, the exact MITRE ATT&CK techniques behind them, and the terms — Mark-of-the-Web, fileless execution, loader, WebAssembly, Stratum relay — that no one can guess from context alone.",
  difficulty: "beginner" as const,
  category: "Threat Detection",
  estimatedMinutes: 55,
  xp: 375,
  icon: "🪤",
  prerequisites: ["intro-cybersecurity", "malware-types"],
  tasks: [
    // ── Reading 1: the shared motif ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mcia-r1",
      heading: "Why 2024–2026 Broke the Old Playbook: Life After Macros",
      content:
        "For years, the single most common way ransomware, infostealers and remote-access trojans got their first foothold was painfully simple: a phishing email carrying a Word or Excel document, a prompt to 'Enable Content,' and a macro that quietly downloaded the real payload the moment a victim clicked one button. It was so common, and so effective, that in mid-2022 Microsoft made a change that reshaped the entire commodity-malware industry: Office now blocks macros in any file that arrives from the internet by default, full stop, with no easy 'Enable Content' escape hatch for the average user.\n\n" +
        "That single change didn't make attackers give up. It made them move — to five techniques that this room walks through one at a time, each solving the same underlying problem in a different way: how do you get a victim to run attacker-controlled code without ever handing them a macro-laden document, and ideally without handing them an obviously malicious file at all?\n\n" +
        "**The shared motif.** Every technique in this room shares something worth noticing before you learn the specifics of any one of them: none of them rely on a user opening an email attachment, and none of them rely on a document macro. Some never touch disk with a downloaded file at all. Some hide inside a container format Windows will happily open but won't flag. Some don't even require the user to run anything themselves in the traditional sense — they run because the user typed three keystrokes, or because a web page they trusted quietly loaded a second, untrusted one behind the scenes.\n\n" +
        "**Why 'commodity' matters as a word choice.** These are not nation-state techniques reserved for high-value targets. They are used at massive scale by financially-motivated criminal groups distributing infostealers, cryptominers, and access-for-sale malware to anyone unlucky enough to search for the wrong download or land on the wrong page. That scale is exactly why a SOC analyst needs to recognise all five on sight: you are far more likely to see one of these in a real queue this year than a sophisticated nation-state implant.\n\n" +
        "**Why this matters for detection specifically.** Traditional file-download-focused controls — scan the attachment, block the .exe, inspect the macro — were built around the old playbook. Every technique here was specifically selected, whether deliberately or through natural evolutionary pressure, because it slips past exactly that kind of control. That means the signal an analyst needs to learn to read is rarely 'a known-bad file arrived.' It is much more often a shape: an unexpected parent-child process relationship, a legitimate-looking tool immediately reaching out to unrelated infrastructure, a warning that should have appeared and didn't, or a browser tab quietly running hotter than it should. Learning to read those shapes — not just matching a file hash — is what the next five readings in this room build, one technique at a time.",
      diagram:
        "flowchart LR\n" +
        "  A[Office blocks internet macros, 2022] --> B{Attackers need a new way in}\n" +
        "  B --> C[ClickFix fake CAPTCHA]\n" +
        "  B --> D[Clipboard clipper]\n" +
        "  B --> E[SEO-poisoned installer]\n" +
        "  B --> F[ISO / MOTW smuggling]\n" +
        "  B --> G[Drive-by browser miner]\n",
      diagramCaption: "Five answers to the same post-macro problem",
    },
    // ── Reading 2: ClickFix ──────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mcia-r2",
      heading: "ClickFix: The Fake CAPTCHA That Types Its Own Command",
      content:
        "Real CAPTCHAs — the 'prove you're human' puzzles most people have solved a thousand times — ask you to click a checkbox, pick out traffic lights, or type distorted letters. They never, under any circumstance, ask you to open the Windows Run dialog and paste something. That single fact is the entire weakness ClickFix exploits.\n\n" +
        "**How it works, step by step.** A victim lands on a page — sometimes a fake download site, sometimes a compromised legitimate page — that displays a convincing 'Verify you are human' overlay. The moment that overlay loads, a small piece of JavaScript silently copies a command to the victim's clipboard. The overlay then instructs the victim, in plain language, to press Windows+R (opening the Run dialog), press Ctrl+V (pasting the clipboard), and press Enter. The victim never sees the command itself — they only see three simple instructions that feel like completing a normal verification step.\n\n" +
        "**What actually runs.** The pasted text is almost always a PowerShell one-liner using a pattern like Invoke-WebRequest piped straight into Invoke-Expression — fetching a script from attacker infrastructure and executing its text directly in the current PowerShell session, without ever writing that script to disk. This is called 'fileless execution,' and it matters enormously for detection: a file that never exists cannot be hashed or scanned on disk, and leaves no file-creation event for an analyst to find. Fileless does not mean invisible, though: Windows' Antimalware Scan Interface (AMSI) hands the script's text to the antivirus engine in memory before PowerShell runs it, PowerShell Script Block Logging records that text as Event ID 4104 where the policy is enabled, and the Run dialog itself saves what was typed or pasted into it in the user's registry under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU — so the pasted command can often be read back after the fact. The command frequently launches with a hidden window, so the victim never even sees a PowerShell console appear.\n\n" +
        "**The tell in the process tree.** Because the Run dialog is part of Windows Explorer, the resulting PowerShell process shows explorer.exe as its direct parent — with no antecedent file_create event anywhere before it. That absence is the signature. An analyst trained to hunt for 'what file did the user download and run' will search this exact chain for a file that was never there, and conclude, wrongly, that nothing happened before the PowerShell process appeared.\n\n" +
        "**Why perimeter controls can't see the important part.** A firewall or proxy inspects things that cross the network as files or flagged URLs. The clipboard write happens entirely inside the browser's own JavaScript sandbox — nothing is downloaded, so there is nothing to scan, and the command the victim pastes never crosses the network as a distinct object at all. This is exactly why ClickFix (used by campaigns such as ClearFake) became one of the most common commodity-malware delivery methods from 2024 onward: it is specifically engineered to slip past controls built to catch a download, by never producing one.\n\n" +
        "**MITRE ATT&CK coverage.** This technique maps to T1204.004 (User Execution: Malicious Copy and Paste) for the moment the victim pastes and runs the command, T1059.001 (Command and Scripting Interpreter: PowerShell) for the interpreter doing the work, and T1105 (Ingress Tool Transfer) for the follow-on stage that fetches whatever payload runs next.",
      checkpoint: {
        question: "A ClickFix chain ran on a workstation and left no downloaded file behind. Where can an analyst still recover the command the user pasted?",
        options: [
          "In the browser's download history, which records the text a page copies to the clipboard as a download entry",
          "In the user's RunMRU registry key, which keeps Run-dialog entries, and in PowerShell Event ID 4104 where logging is on",
          "In the firewall's URL log, which captures the clipboard text when the page's JavaScript copies it to the victim",
          "In a file_create event for the script under %TEMP%, because PowerShell saves each fetched script to disk before running it",
        ],
        answer: 1,
        explanation:
          "Reading 2 named the places a 'fileless' paste-and-run still leaves traces: the Run dialog saves what was entered into it under HKCU\\...\\Explorer\\RunMRU, and Script Block Logging records the script text as Event ID 4104 (AMSI also sees it in memory). The browser's download history only lists files the browser saved; a clipboard write is not a download, so nothing appears there. The firewall cannot see the clipboard text either: the copy happens inside the browser's JavaScript sandbox and never crosses the network as its own object. And the one-liner pattern Reading 2 described runs the fetched script's text directly in memory, so there is no %TEMP% file_create to look for -- that absence is the ClickFix tell, not a gap to fill.",
      },
    },
    // ── Question 1 (applied — ClickFix process signature) ────────────────────
    {
      type: "question" as const,
      id: "mcia-q1",
      question:
        "An EDR alert shows explorer.exe launching powershell.exe directly, with a hidden window and a one-line command that downloads and runs a script -- and there is no file_create event anywhere before it. What does the absence of an antecedent file_create event tell you?",
      options: [
        "The command was run directly, most likely pasted into the Run dialog, rather than being a file the user downloaded and opened",
        "The sensor missed the download event, so the gap should be reported and the host treated as unmonitored for file activity",
        "PowerShell loads fetched scripts into memory by design, so a missing file_create is normal and says nothing about the launch",
        "The file was downloaded and deleted within milliseconds, faster than the sensor could log the create event",
      ],
      answer: 0,
      explanation:
        "Reading 2 covered exactly this signature: a command run through the Run dialog never exists as a file at all, so there is nothing for a file_create event to record -- and explorer.exe as the direct parent fits, because the Run dialog belongs to Explorer. Assuming the sensor missed the download invents a failure with no supporting evidence. The in-memory argument mixes up two different files: fetching the second script into memory explains why that script leaves no file afterwards, but the question is what started PowerShell in the first place -- in a classic download chain a file is created and opened before PowerShell appears, and here none was. The download-then-instant-delete theory requires a delete event that also isn't present -- there is no evidence anything was ever written and removed.",
      xp: 20,
    },
    // ── Reading 3: Clipboard clippers ─────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mcia-r3",
      heading: "Clipboard Clippers: Theft That Waits for You to Paste",
      content:
        "Cryptocurrency wallet addresses are long, random-looking strings — typically 26 to 42+ characters — that essentially nobody memorises or retypes by hand. In practice, everyone copies and pastes them. That single, near-universal habit is what a category of malware called a 'clipper' (or clipboard hijacker) is built specifically to exploit.\n\n" +
        "**How it gets on the machine.** Clippers are rarely delivered on their own. The most common path is bundling: a small, genuinely-working utility — a crypto portfolio tracker, a 'free' productivity tool, a cracked version of paid software — is distributed with a second, hidden binary riding alongside it. The visible tool works exactly as advertised, which is precisely what keeps the victim from suspecting anything at all.\n\n" +
        "**What it actually does.** Once running, the clipper registers itself as a clipboard listener using standard, fully documented Windows APIs (AddClipboardFormatListener, GetClipboardData, SetClipboardData) and sits quietly, watching every copy operation. When the copied text matches the pattern of a cryptocurrency wallet address, it silently replaces it with an address the attacker controls, before the victim pastes it anywhere. The victim sees nothing: no popup, no crash, no visual change of any kind. They copy an address, paste what they believe is the same address, and send a payment — to the wrong destination.\n\n" +
        "**Why persistence usually shows up as a distinct, higher-signal event.** Most legitimate installers write their own startup registry entries directly through the installer framework's own APIs. A visibly separate step — a hidden cmd.exe process, spawned by the installer, running a 'reg add' command that points at a newly-dropped binary — is a different and more detectable pattern: a command interpreter carrying out persistence on the installer's behalf, tracked in ATT&CK as its own technique, T1059.003 (Command and Scripting Interpreter: Windows Command Shell), separate from the registry change it produces.\n\n" +
        "**Why this class of malware is so hard to catch quickly.** A clipper causes no crash, no ransom note, and no immediately visible symptom of any kind. The only outcome anyone ever notices is indirect and delayed: a payment that should have arrived somewhere never did. That gap between infection and discovery is frequently measured in days, and the trigger for investigation is often a business event — a vendor calling about a missing payment — rather than a security alert being worked promptly.\n\n" +
        "**MITRE ATT&CK coverage.** T1115 (Clipboard Data) covers the actual theft mechanism; T1059.003 covers the command-shell step that often sets up its persistence.",
    },
    // ── Question 2 (applied — clipper detection reasoning) ────────────────────
    {
      type: "question" as const,
      id: "mcia-q2",
      question:
        "A background process with no visible window has been running quietly on a laptop for two hours. It made no network connections and created no new files after it started, and there were no crashes or pop-ups. Two days later, a vendor reports a cryptocurrency payment from that laptop never arrived at the correct address. Based on this room, what should investigators specifically check for on the host?",
      options: [
        "Whether it registered as a clipboard listener and swapped copied wallet addresses for an attacker's address",
        "Whether it was logging keystrokes, since credential capture is the most common route to a stolen payment",
        "Whether it was an infostealer that had harvested the browser's saved wallet credentials and sent them out",
        "Whether it was a remote-access tool that let an attacker open and operate the wallet app interactively",
      ],
      answer: 0,
      explanation:
        "This is the exact pattern Reading 3 described: no crash, no visible symptom, and the only outcome anyone notices is a payment gone to the wrong place -- the specific artefact to check for is a clipboard-format listener substituting wallet addresses. Keylogging would produce a different downstream symptom (stolen credentials later used to log in, not a payment that went to a swapped address), and a keylogger also has to send what it captures somewhere. An infostealer and a remote-access tool both need network connections to send data out or receive commands, and the scenario states the process made none. A clipper is the one option that needs no network at all: it changes the address locally, and the victim's own payment does the rest.",
      xp: 20,
    },
    // ── Reading 4: SEO-poisoned / malvertised installers ──────────────────────
    {
      type: "reading" as const,
      id: "mcia-r4",
      heading: "SEO-Poisoned and Malvertised Installers: When the Sponsored Result Is the Attack",
      content:
        "Search engines sell advertising space above their organic results, and anyone can bid to have their link shown first for a given search term — including an attacker bidding to outrank the real project for a piece of software people search for constantly, like an SSH client or an archiving tool. This is SEO poisoning (or malvertising, when it specifically rides paid ad placement): buying or manipulating a search result to point directly at attacker-controlled infrastructure, tracked in MITRE ATT&CK as T1608.006, Stage Capabilities: SEO Poisoning.\n\n" +
        "**Why this is a distinct story from a hacked website.** A drive-by compromise requires an attacker to actually break into a legitimate site and tamper with it. SEO poisoning requires none of that — the attacker only needs to register a lookalike domain and either buy a sponsored slot or manipulate search rankings well enough to appear convincing. The domain itself often has no abuse history at all, because it was registered specifically and recently for this one purpose, which is exactly why domain-reputation checks alone often miss it on first contact.\n\n" +
        "**What the victim actually downloads.** The installer they get is frequently not a standalone trojan but a loader: a small program that opens, briefly shows a real-looking setup window, and then fails with a generic error — the victim never gets a working copy of whatever they thought they were installing. In the few seconds it ran, though, the installer process itself reached out to entirely separate infrastructure and fetched a second file. That fetch-after-execution pattern — the first file's only real job being to retrieve a different one — is Ingress Tool Transfer, T1105, and it is the detail that identifies a loader rather than a simple standalone trojan.\n\n" +
        "**What the second stage frequently goes after.** A large share of these campaigns deliver an infostealer, and one of the most reliable things to check for afterward is browser credential theft: Chrome (and Chromium-based browsers generally) stores saved passwords in a SQLite database file literally named 'Login Data,' inside the browser's own profile folder. Because Chrome holds that file open and locked while it's running, a stealer typically can't read it directly, so it copies the file instead — and that copy frequently lands somewhere with no legitimate relationship to Chrome at all, such as a Temp subfolder created by the loader itself. Finding a file named exactly 'Login Data' outside Chrome's own profile path is one of the strongest single artefacts for this specific technique, tracked as T1555.003, Credentials from Password Stores: Credentials from Web Browsers.\n\n" +
        "**Why the blast radius is bigger than one corporate account.** A browser credential store isn't scoped to any one site — it holds whatever the user saved, personal accounts included. Once that store has left the machine, remediation has to assume every saved account is exposed, not only the corporate login.",
      checkpoint: {
        question: "A user downloaded a fake SSH-client installer from a sponsored search result. A teammate starts hunting for the legitimate website that must have been broken into. Why is that the wrong starting assumption?",
        options: [
          "SEO poisoning needs no break-in: the attacker registers a lookalike domain and buys or games a search placement",
          "It is the right assumption: SEO poisoning works by injecting a script into a trusted site, as a drive-by does",
          "The break-in happened at the search engine, whose ad platform was compromised so the attacker's link was shown",
          "The real installer was swapped in transit by an attacker on the network, so no website was involved at all",
        ],
        answer: 0,
        explanation:
          "Reading 4 drew exactly this line: a drive-by compromise requires breaking into a legitimate site, while SEO poisoning only needs a recently registered lookalike domain plus a bought or manipulated search placement -- which is also why its domain often has no abuse history. Treating it as a script injected into a trusted site is the drive-by story from Reading 6, not this one. Nothing about a sponsored result implies the search engine itself was breached; the attacker simply bid for the ad slot like any advertiser. And an in-transit swap is a different attack altogether -- here the user went to the attacker's own domain, so the file was malicious before it ever left the server.",
      },
    },
    // ── Log Analysis 1: SEO-poisoned installer fetch ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "mcia-la1",
      heading: "A Sponsored Result, Four Seconds After the Installer Ran",
      context:
        "NexaCorp's IT support technician Dor Mizrahi searched for a common archiving tool and downloaded 7zSetup-2026.exe from a sponsored search result rather than the official project site. He ran the installer on his laptop, LAP-9021, accepted the elevation prompt, and briefly saw a setup window before it closed with a generic error — he never actually got a working copy of the tool. The event below is what the firewall recorded four seconds after the installer process started.",
      event: seoInstallerEvent,
      questions: [
        {
          question:
            "Read the context and the record together: the installer showed a setup window, failed with a generic error, and four seconds after it started pulled helper_upd.exe from a domain unrelated to where it was downloaded. What kind of program is 7zSetup-2026.exe most likely to be?",
          options: [
            "A loader: its real job is fetching a second-stage payload from separate infrastructure, not installing 7-Zip",
            "A genuine installer pulling an optional component from a mirror CDN, then failing on an unrelated setup error",
            "A standalone trojan carrying its payload inside itself, with this request being a routine update check",
            "A bundled utility with a hidden second binary riding inside the same download, as with clipboard clippers",
          ],
          answer: 0,
          explanation:
            "Reading 4 described exactly this shape: a fake installer that briefly shows a setup window, fails with a generic error, and in those few seconds fetches a different file from unrelated infrastructure is a loader -- the fetch-after-execution step is T1105. A genuine installer that fetches components does so from its own vendor's infrastructure and then installs a working product; here the domain is unrelated and the user never got a working copy. A standalone trojan already carries its malicious code, so it would not need to download a new executable seconds after launch, and helper_upd.exe is a full PE file, not an update check. Bundling (Reading 3) means the hidden binary arrives inside the original download; here the second file arrived afterwards, over the network, which is the loader pattern.",
          xp: 25,
        },
        {
          question:
            "pan.category on this record is 'newly-registered-domain'. How does that value fit what Reading 4 taught about the infrastructure behind SEO-poisoned installers?",
          options: [
            "It fits: these domains are registered recently for one campaign, so they have no abuse history for reputation checks to catch",
            "It suggests a legitimate mirror: software projects register new download mirrors constantly, so a new domain is expected here",
            "It means the firewall has already judged the domain malicious, so the reputation check this room describes is done",
            "It marks a typosquat of the real project's domain, which is the defining feature of SEO poisoning in Reading 4",
          ],
          answer: 0,
          explanation:
            "Reading 4 explained that the attacker's domain 'often has no abuse history at all, because it was registered specifically and recently for this one purpose' -- exactly what a newly-registered-domain category reflects, and why reputation checks alone often miss it on first contact. A new domain is not evidence of a legitimate mirror: nothing ties cdn-pkg-mirror19.net to the 7-Zip project, and the installer failed without installing anything. The category describes the domain's age, not a verdict -- the firewall logged the download rather than stopping it, so the analyst still has to judge it. And cdn-pkg-mirror19.net does not resemble 7-Zip's name at all; Reading 4 describes lookalike domains, but a typosquat is not what this category value tells you.",
          xp: 25,
        },
        {
          question:
            "Assume helper_upd.exe is an infostealer, as Reading 4 says these second stages often are. Which finding on LAP-9021 would most directly show that Chrome's saved passwords were taken?",
          options: [
            "A file named 'Login Data' inside a Temp subfolder created by the installer, outside Chrome's own profile path",
            "A 'Login Data' file inside Chrome's own profile folder showing a modification time from this morning",
            "Chrome's own process holding its 'Login Data' file open and locked while the browser was running",
            "helper_upd.exe's SHA-256 recorded in pan.file_hash, proving the stealer reached the laptop intact",
          ],
          answer: 0,
          explanation:
            "Reading 4 named the strongest single artefact: because Chrome keeps 'Login Data' locked while it runs, a stealer copies it, and that copy lands somewhere with no relationship to Chrome, such as a Temp subfolder the loader created. The same file inside Chrome's own profile is exactly where it belongs, and Chrome updates it during normal use, so a fresh modification time proves nothing. Chrome holding the file locked is normal browser behaviour -- it is the reason a stealer has to copy the file, not evidence that one did. The hash in pan.file_hash shows the second stage was downloaded, which you already know from this record; it says nothing about whether credentials were read.",
          xp: 30,
        },
      ],
    },
    // ── Reading 5: ISO / Mark-of-the-Web smuggling ─────────────────────────────
    {
      type: "reading" as const,
      id: "mcia-r5",
      heading: "ISO and Mark-of-the-Web Smuggling: A Warning That Never Travels",
      content:
        "Windows tries to protect users from files they download from the internet with a mechanism called Mark-of-the-Web (MOTW): the moment a browser saves a file from the web, Windows tags it with a small hidden marker — technically a 'Zone.Identifier' alternate data stream — recording that it came from the internet zone. That marker is what triggers SmartScreen's warning prompt when someone tries to run an unfamiliar downloaded executable, and it's a genuinely effective control against a plain downloaded .exe.\n\n" +
        "**The gap this exploits.** The marker belongs to the specific file object Windows tagged — the ISO, IMG, or VHD container itself, not automatically to whatever is inside it. When a victim double-clicks a downloaded ISO file, Windows' own built-in container-mount handler presents it as a brand-new drive letter, exposing whatever files sit inside. On Windows builds without the November 2022 security update, those inner files are read directly off the mounted volume, never go through their own internet-download path, and so never receive their own Zone.Identifier tag — a shortcut or executable inside that mounted volume can run with no SmartScreen prompt at all, even though the container that delivered it was correctly tagged the moment it landed in Downloads.\n\n" +
        "**Why this pattern boomed in 2022 — and what changed.** Once Office started blocking macros from the internet by default in 2022, several loader families that had relied on malicious Word or Excel documents moved to container formats precisely because of this gap — MITRE ATT&CK tracks it as T1553.005, Subvert Trust Controls: Mark-of-the-Web Bypass. Microsoft closed the ISO case in the November 2022 Patch Tuesday (CVE-2022-41091): on a patched system, Windows now propagates the container's Mark-of-the-Web to the files inside it, so the shortcut does trigger a warning. The technique therefore still works on hosts that missed that update, and the same idea lives on wherever MOTW fails to propagate — most notably archive tools: 7-Zip before version 24.09 did not carry MOTW onto files extracted from a nested archive (CVE-2025-0411), and archivers or container formats that never propagate the mark leave the extracted files untagged. The analyst's question stays the same: did the file that actually ran carry its own Zone.Identifier, or did the mark stop at the wrapper?\n\n" +
        "**What the shortcut actually does.** The .lnk file sitting inside the mounted volume is rarely the payload itself — its target is almost always a short command that hands off to something else, most often cmd.exe launching a hidden, base64-encoded PowerShell command. cmd.exe's command line in this pattern typically carries no logic of its own beyond the instruction to start the next interpreter — it functions purely as a relay, a detail worth reading directly off the process's own command-line field rather than assuming from the process name alone.\n\n" +
        "**Why 'the file-filter policy didn't block it' isn't the same failure as it sounds like.** Most download-filtering policies were built to catch and block risky executable types outright. A policy that only inspects or blocks .exe downloads has nothing to say about an .iso — it simply isn't the file type the policy was designed to look at, which is exactly why closing this gap means extending container formats (.iso, .img, .vhd) into the same filtering policy that executables already get, not assuming the existing exe-focused control already covers it.\n\n" +
        "**MITRE ATT&CK coverage.** T1553.005 for the Mark-of-the-Web bypass itself; T1204.002 (User Execution: Malicious File) for the victim opening the container and its shortcut in the first place; T1059.001 for the PowerShell stage the relay hands off to.",
    },
    // ── Question 3 (applied — MOTW non-propagation) ────────────────────────────
    {
      type: "question" as const,
      id: "mcia-q3",
      question:
        "A user on a Windows 10 workstation that has not received security updates since mid-2022 double-clicks a shortcut sitting inside a mounted ISO volume that came from a downloaded file, and it launches cmd.exe with no SmartScreen warning at all -- even though the ISO file itself was tagged with a Mark-of-the-Web zone identifier when it was downloaded. Why didn't the warning appear?",
      options: [
        "Mark-of-the-Web belongs to the downloaded container; files exposed once Windows mounts it are read off the volume and get no tag of their own",
        "A Group Policy on this machine disables SmartScreen for removable and virtual volumes, so nothing launched from a mounted ISO is ever checked",
        "The shortcut launches cmd.exe, a Microsoft-signed binary, and SmartScreen skips any launch whose target carries a trusted publisher signature",
        "SmartScreen cannot inspect container formats, so ISO files are excluded from checks by design, whatever zone tag they carry",
      ],
      answer: 0,
      explanation:
        "Reading 5 covered exactly this mechanism: on a host without the November 2022 fix (CVE-2022-41091), the mark belongs to the container file object, not to anything exposed once it's mounted -- inner files never go through their own download path and so never get their own tag. (On a patched host Windows propagates the mark to the ISO's contents and the prompt would appear.) Nothing in the scenario supports an administrator disabling SmartScreen or a trusted-signature exemption for cmd.exe -- both invent facts not in evidence. ISO files aren't categorically excluded from SmartScreen either; the missing propagation of the mark, not the file extension itself, is what explains the missing prompt.",
      xp: 25,
    },
    // ── Reading 6: Drive-by browser cryptomining ────────────────────────────────
    {
      type: "reading" as const,
      id: "mcia-r6",
      heading: "Drive-by Browser Cryptomining: The Attack That Lives Entirely in a Tab",
      content:
        "Every technique earlier in this room eventually produces something on disk — a script, a dropped binary, a copied credential file. This one is different, and that difference is the entire point of including it: nothing is ever downloaded to the Downloads folder, no unfamiliar process appears outside the browser itself, and the only 'malware' involved runs entirely inside a completely ordinary, unmodified browser tab.\n\n" +
        "**How the hand-off works.** A victim visits a genuine, frequently-used website — often one they've used safely many times before — that has itself been compromised or is unknowingly serving a third-party advertising or analytics script from a host with no real relationship to the site's own content. That injected script pulls in a compiled WebAssembly (WASM) module: a binary format designed to run inside a browser at close to native speed, originally built for legitimate purposes like games and video editors, but equally capable of running a cryptocurrency mining algorithm. MITRE ATT&CK tracks this hand-off as T1189, Drive-by Compromise.\n\n" +
        "**Why the browser itself is the only 'process' involved.** Modern browsers run each site's content in its own sandboxed renderer process as a routine security measure — nothing unusual has to happen for a new process to appear; it's simply how the browser already works for every tab. The WebAssembly module compiles and executes inside that same ordinary renderer process. There is no separate executable to download and no unfamiliar process name to notice in Task Manager — only an existing, completely normal browser process quietly using far more CPU than the page it's showing would normally require.\n\n" +
        "**Why the traffic looks like nothing in particular.** A browser tab cannot open a raw TCP connection straight to a cryptocurrency mining pool the way desktop mining software can — browsers only support standard web protocols. So browser-based miners tunnel the mining protocol (commonly called Stratum) over a WebSocket connection to a relay server, which speaks Stratum to the real pool on the miner's behalf. The result, at the firewall, is a connection categorised as ordinary 'websocket' application traffic to a domain with no established reputation yet — both extremely common, unremarkable classifications on their own. What actually stands out is the shape: one destination held open continuously for many minutes, exchanging small, steady bidirectional bursts, unlike a typical page's WebSocket connections which tend to close or go idle quickly. MITRE ATT&CK tracks the resource impact itself as T1496, Resource Hijacking.\n\n" +
        "**Why remediation is unusually simple, and unusually easy to under-scope.** Because nothing here writes a persistence mechanism or touches a credential, closing the browser tab and its renderer process ends the entire technical impact immediately — there is no lingering process or file to remove. What remains is scoping the delivery: identifying and blocking the injected script's domain and the mining relay, and notifying the legitimate site's owner that it is unknowingly serving attacker-controlled content to its own visitors.",
      checkpoint: {
        question: "Why does a browser-based miner talk to a relay over a WebSocket instead of connecting straight to the mining pool?",
        options: [
          "A browser tab can only use standard web protocols, so the Stratum traffic is tunnelled over a WebSocket to a relay that talks to the pool",
          "The relay hides each victim's IP address from the mining pool, so the pool cannot spot and ban the abusive miners connecting to it",
          "The relay does the mining computation itself, and the browser tab only forwards work requests to it over the WebSocket connection",
          "WebSocket encryption stops the firewall reading the traffic, whereas a direct pool connection would match a mining signature and be blocked",
        ],
        answer: 0,
        explanation:
          "Reading 6 gave the reason directly: a browser cannot open a raw TCP connection to a pool the way desktop mining software can, so the mining protocol (Stratum) is wrapped in a WebSocket to a relay, which speaks Stratum to the real pool on the miner's behalf. Hiding victims from the pool is not the purpose the reading describes -- the relay exists because of what a browser can and cannot do. The computation happens in the tab: the WebAssembly module runs inside the renderer, which is why that renderer process burns CPU. And encryption is not the reason either; the firewall still classified the session as 'websocket', and what gives it away is its long, steady shape, not its content.",
      },
    },
    // ── Analyst Choice: legitimate paste-run install ────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "mcia-ac1",
      heading: "Verdict: A Hidden PowerShell Window, Launched by explorer.exe",
      scenario:
        "A Falcon detection fires on WS-6820 for a High-severity PowerShell Command and Scripting Interpreter pattern: explorer.exe launching a hidden-window powershell.exe process that downloads a script from the internet and runs it in memory. Read the command line, the destination it pulls from, the user and host, and the IT verification note under the record, then give your verdict.",
      event: legitPasteRunEvent,
      correct_verdict: "false_positive",
      explanation:
        "The command line downloads and runs the install script from community.chocolatey.org — the real, publicly documented installation method for the Chocolatey package manager, not a lookalike or newly-registered domain. The IT verification on the record is 'confirmed': change ticket CHG-44190 approves the DevOps team's Chocolatey rollout across engineering workstations this week, and y.cohen's install falls inside that approved window on their own workstation. process.code_signature.trusted is true for powershell.exe itself, which is expected either way — powershell.exe is a Microsoft-signed interpreter on every Windows machine, so its signature says nothing about the intent of the script it is told to run — the deciding fields here are the verified domain and the confirmed change ticket, not the signature.",
      fp_trap:
        "explorer.exe launching a hidden-window PowerShell process that pulls a script straight from the internet is precisely the shape this room has been teaching you to treat as ClickFix-style paste-and-run. But real software vendors — Chocolatey among them — genuinely publish official one-line install commands that look identical in telemetry to a malicious paste-and-run chain. Escalating this pattern on shape alone, without checking the destination domain and it_verify_result, trains a team to drown in noise on the exact pattern that most needs real scrutiny when it's actually malicious.",
      xp: 30,
    },
    // ── Matching: technique to MITRE ID and motif ───────────────────────────────
    {
      type: "matching" as const,
      id: "mcia-m1",
      heading: "Match the Technique to Its MITRE ATT&CK ID and Signature",
      instructions: "Match each technique covered in this room to the MITRE ATT&CK ID and the artefact that identifies it.",
      pairs: [
        { id: "clickfix", left: "ClickFix / Fake CAPTCHA", right: "T1204.004 -- explorer.exe spawns a command interpreter directly, with no antecedent file download at all" },
        { id: "clipper", left: "Clipboard Clipper", right: "T1115 -- a background process silently substitutes copied cryptocurrency wallet addresses before the paste completes" },
        { id: "seo", left: "SEO-Poisoned / Malvertised Installer", right: "T1608.006 -- a paid or manipulated search result leads to a fake installer whose only real job is fetching a second-stage payload" },
        { id: "iso", left: "ISO / Mark-of-the-Web Smuggling", right: "T1553.005 -- a shortcut inside a mounted container runs with no SmartScreen prompt at all" },
        { id: "miner", left: "Drive-by Browser Cryptomining", right: "T1496 -- a browser's own renderer process opens a long-lived tunnel to a mining relay" },
      ],
      explanation:
        "Notice what all five have in common: none of them require a malicious document macro, and two of the five -- ClickFix and the browser miner -- begin without any downloaded file on disk before the first suspicious activity. That's exactly why file-download-focused controls, on their own, aren't enough to catch any of them.",
      xp: 35,
    },
    // ── Ordering: triage sequence for a fileless-looking initial-access alert ──
    {
      type: "ordering" as const,
      id: "mcia-o1",
      heading: "Order the Triage of an Alert With No Obviously Malicious Downloaded File",
      instructions: "Arrange these steps in the order an analyst should actually work them for an alert where a legitimate-looking process chain led to unexpected activity, with no obviously malicious file ever downloaded.",
      items: [
        { id: "ancestry", text: "Reconstruct how execution started -- which process launched the first suspicious one, whether that parent-child pair is normal, and whether any file existed on disk before it" },
        { id: "domain", text: "Assess where it went -- the destination's category, registration age and reputation, whether the connection succeeded or was blocked, and what (if anything) left the host" },
        { id: "context", text: "Check for a verified IT ticket, change record, or other known legitimate business reason before deciding on a verdict" },
        { id: "verdict", text: "Assign a verdict and document the full timeline for the incident record" },
      ],
      correct_order: ["ancestry", "domain", "context", "verdict"],
      explanation:
        "Start by reconstructing exactly what launched what -- an unusual parent-child pair, like explorer.exe launching a command interpreter directly, is the first fact worth establishing, together with whether a file was ever involved at all, since several of this room's techniques never touch disk the way a classic download does. Only once you know the technical shape of what happened does the destination's reputation and the connection's outcome tell you how far it actually got (those destination checks can be done in either order, so they form one step here). Checking for a verified business reason comes after the technical picture is complete, not before it -- deciding 'there's probably a ticket for this' too early is exactly how a real compromise gets waved through, while checking it before finalising a verdict is exactly what turned the Chocolatey install in this room's analyst-choice task from an alarming-looking pattern into a correctly-closed false positive. Only with all of that in hand should you commit to a verdict and write it up.",
      xp: 35,
    },
    // ── Log Analysis 2: drive-by browser miner connection ───────────────────────
    {
      type: "log_analysis" as const,
      id: "mcia-la2",
      heading: "Nineteen Minutes on One WebSocket Connection",
      context:
        "LAP-4471 belongs to Maya Harel, a marketing coordinator who spent close to twenty minutes on a free online image-compression site for a routine task. CrowdStrike's behavioural engine later flagged sustained high CPU usage on the single browser tab for the same window, tied to one renderer process. The event below is the firewall's summary record for the outbound connection that renderer process held open the entire time.",
      event: driveByMinerEvent,
      questions: [
        {
          question:
            "pan.app on this connection is 'websocket' and pan.category is 'unknown' -- both extremely common for ordinary web traffic. What actually makes this specific connection worth a second look?",
          options: [
            "pan.elapsed_time of 1140 s to one destination, with small byte counts both ways -- a session pages rarely hold open",
            "pan.bytes_received is more than three times pan.bytes_sent, which shows a payload was downloaded onto the laptop",
            "pan.subtype 'end' shows the firewall cut the session off after recognising mining traffic partway through it",
            "pan.category 'unknown' means the firewall has flagged the destination as suspicious and wants it reviewed",
          ],
          answer: 0,
          explanation:
            "Reading 6 said the classification fields rule nothing in or out on their own -- what stands out is the shape: pan.elapsed_time of 1140 seconds (nineteen minutes) against a single destination, with only about 15 KB sent and 51 KB received, is the long-lived, small-burst pattern of a mining relay, not a page's usual short-lived WebSocket. The received-versus-sent ratio is a misreading: 51 KB over nineteen minutes is far too little for a payload download, and steady two-way exchange is the point. pan.subtype 'end' only means this is the summary written when the session closed; pan.action is 'allow', and the description says it closed when the tab went to the background. 'unknown' means no category has been assigned yet, not that the firewall reached a verdict.",
          xp: 25,
        },
        {
          question:
            "The context says CrowdStrike tied the CPU load to a single browser renderer process, and no new file or unfamiliar process appeared on LAP-4471. What explains that combination?",
          options: [
            "The page loaded a WebAssembly miner that the browser's ordinary renderer process compiles and runs in its sandbox",
            "The page installed a browser extension that runs the miner, and extensions do not appear as processes or files",
            "The page's script injected the miner into explorer.exe, so the work ran under an existing, trusted process name",
            "The page registered a background service that keeps mining after the tab closes, hidden from Task Manager",
          ],
          answer: 0,
          explanation:
            "Reading 6 covered this directly: the 'payload' is a WebAssembly module that the browser's own renderer process -- a process every tab already gets -- compiles and runs inside its existing sandbox, so there is no separate executable and no unfamiliar process name, only one renderer using far more CPU than its page needs. An extension is installed into the browser's profile as files on disk, which is exactly what was not seen here. Injection into explorer.exe would put the CPU load on explorer.exe, not on a browser renderer, which contradicts CrowdStrike's finding. And a miner that survived the tab closing contradicts the record: the session ended when the tab went to the background, and Reading 6 notes that closing the tab ends the technical impact.",
          xp: 25,
        },
        {
          question:
            "Given that closing the browser tab ends this technique's entire impact -- there is no separate process or file to remove -- what does that mean for how you scope the response?",
          options: [
            "Confirm the tab is closed, block both the injected script's host and the relay, and tell the site's owner",
            "Confirm the tab is closed and close the case, since nothing persisted and so nothing is left to block or report",
            "Isolate LAP-4471 and search its disk for the miner's binary before the browser tab is allowed to close",
            "Reset Maya Harel's password, since the miner's code ran inside her logged-in browser session for nineteen minutes",
          ],
          answer: 0,
          explanation:
            "Reading 6 made this explicit: nothing here writes a persistence mechanism or touches a credential, so closing the tab ends the technical impact, and what remains is scoping the delivery -- blocking the injected script's domain and the mining relay, and notifying the legitimate site's owner that it is serving attacker content to its visitors. Closing the case once the tab is shut is the right first step stopped too early: both domains stay live for the next visit and the next visitor. Hunting the disk for a miner binary looks for something this technique never creates -- the code ran as WebAssembly inside the renderer -- and keeping the tab open only lets the mining continue. A password reset has no basis: no credential store or token was touched anywhere in this evidence.",
          xp: 30,
        },
      ],
    },
    // ── Flag ────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "mcia-f1",
      prompt:
        "The network team will block the mining relay from the LAP-4471 investigation by domain and by IP address. From that session's firewall record, enter the relay's IP address.",
      answer: "45.155.207.88",
      hint: "The record lists both ends of the session. One address is the laptop itself; you need the other end.",
      xp: 20,
    },
    // ── Question 4 (synthesis — cross-technique differentiation) ───────────────
    {
      type: "question" as const,
      id: "mcia-q4",
      question:
        "A user calls the helpdesk saying their laptop has been 'running a little hot' for the past hour. They used a free browser-based tool for routine work, nothing appears in their Downloads folder, and Task Manager shows no unfamiliar process outside the browser itself. Which of this room's five techniques best fits, and why?",
      options: [
        "Drive-by browser cryptomining -- the payload runs as WebAssembly in the browser's renderer, so there is no separate file or process, only CPU load tied to a tab",
        "ClickFix paste-and-run -- a command was pasted into the Run dialog without the user registering it, leaving the browser as the only process they would notice",
        "Clipboard clipper -- a background listener rewriting clipboard content runs with no visible window, and its constant clipboard polling accounts for the heat",
        "ISO container smuggling -- the user mounted a downloaded ISO from the free tool without registering the new drive letter, and the payload runs from that volume",
      ],
      answer: 0,
      explanation:
        "Only drive-by browser cryptomining matches every detail given: no downloaded file, no separate process outside the browser, and a symptom (heat, meaning sustained CPU) tied directly to an open tab. ClickFix would leave a distinct powershell.exe process outside the browser, even with its window hidden. A clipboard clipper is its own background binary (Reading 3), so Task Manager would show an unfamiliar process; it also waits quietly for copy events rather than burning CPU, and its only noticed sign is a misdirected payment. ISO smuggling requires a downloaded container file, which the scenario explicitly rules out by saying Downloads is empty.",
      xp: 30,
    },
  ],
};

export const roomsBatch32 = [commodityInitialAccessRoom];
