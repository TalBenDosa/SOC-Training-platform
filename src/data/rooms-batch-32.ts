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
    sha256: "a4f7c1e29b3d4f686a01c8f2ed37b1043c9e7a412b6d4f189a057e4c1b8d3f62",
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
    "pan.file_hash": "a4f7c1e29b3d4f686a01c8f2ed37b1043c9e7a412b6d4f189a057e4c1b8d3f62",
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
    "explorer.exe launched a hidden-window PowerShell process on WS-6820 that downloaded and ran the official Chocolatey install script from community.chocolatey.org.",
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
    "crowdstrike.detection.tactic": "Execution",
    "crowdstrike.detection.tactic_id": "TA0002",
    "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
    "crowdstrike.detection.technique_id": "T1059.001",
    "crowdstrike.detection.severity": "High",
    "crowdstrike.detection.pattern_disposition": "10",
    "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
    "crowdstrike.sensor.id": "b71e04af9c2d4a86bf05e1cd8a3f7d29",
    "crowdstrike.network_containment_state": "Not Contained",
    "event.action": "process_created",
    "process.name": "powershell.exe",
    "process.pid": "5502",
    "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "process.command_line":
      "powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command \"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"",
    "process.hash.sha256": "b1e5d29a7c4f60831e9a5c7f4b28d6039e1a7c4f6b83d05e2c8f4e6b91d3a75c",
    "process.signed": "true",
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
        "**What actually runs.** The pasted text is almost always a PowerShell one-liner using a pattern like Invoke-WebRequest piped straight into Invoke-Expression — fetching a script from attacker infrastructure and executing its text directly in the current PowerShell session, without ever writing that script to disk. This is called 'fileless execution,' and it matters enormously for detection: a file that never exists cannot be scanned, cannot be hashed, and leaves no file-creation event for an analyst to find. The command frequently launches with a hidden window, so the victim never even sees a PowerShell console appear.\n\n" +
        "**The tell in the process tree.** Because the Run dialog is part of Windows Explorer, the resulting PowerShell process shows explorer.exe as its direct parent — with no antecedent file_create event anywhere before it. That absence is the signature. An analyst trained to hunt for 'what file did the user download and run' will search this exact chain for a file that was never there, and conclude, wrongly, that nothing happened before the PowerShell process appeared.\n\n" +
        "**Why perimeter controls can't see the important part.** A firewall or proxy inspects things that cross the network as files or flagged URLs. The clipboard write happens entirely inside the browser's own JavaScript sandbox — nothing is downloaded, so there is nothing to scan, and the command the victim pastes never crosses the network as a distinct object at all. This is exactly why ClickFix (also reported as ClearFake) became one of the most common commodity-malware delivery methods from 2024 onward: it is specifically engineered to slip past controls built to catch a download, by never producing one.\n\n" +
        "**MITRE ATT&CK coverage.** This technique maps to T1204.004 (User Execution: Malicious Copy and Paste) for the moment the victim pastes and runs the command, T1059.001 (Command and Scripting Interpreter: PowerShell) for the interpreter doing the work, and T1105 (Ingress Tool Transfer) for the follow-on stage that fetches whatever payload runs next.",
      checkpoint: {
        question: "What makes the first PowerShell process in a ClickFix chain unusual compared to a normal malicious download?",
        options: [
          "It is always digitally signed by a well-known publisher, which is what makes victims trust the fake verification page enough to comply",
          "There is no antecedent file_create event anywhere before it -- the process launches directly from explorer.exe with no file ever downloaded first",
          "It always runs under a SYSTEM-level service account rather than the currently logged-in user's own session and privileges",
          "It only ever appears on Linux workstations running a Bash-compatible shell interpreter, never on Windows",
        ],
        answer: 1,
        explanation:
          "The Run dialog executes exactly the text sitting on the clipboard -- there was never a file to download in the first place, which is why no file_create event precedes the process.",
      },
    },
    // ── Question 1 (applied — ClickFix process signature) ────────────────────
    {
      type: "question" as const,
      id: "mcia-q1",
      question:
        "An EDR alert shows explorer.exe launching powershell.exe directly, with a hidden window and a one-line command that downloads and runs a script -- and there is no file_create event anywhere before it. What does the absence of an antecedent file_create event tell you?",
      options: [
        "The command was executed directly -- most likely pasted into the Windows Run dialog -- rather than being a file the user downloaded and double-clicked",
        "The EDR sensor missed logging the download event, which should be reported as a sensor gap",
        "PowerShell always launches without creating a file first, so this is completely normal behavior",
        "The file was downloaded and immediately deleted before the sensor could record it",
      ],
      answer: 0,
      explanation:
        "Reading 2 covered exactly this signature: a command run through the Run dialog never exists as a file at all, so there is nothing for a file_create event to record. Assuming a sensor gap (b) invents a failure with no supporting evidence. PowerShell processes routinely follow a preceding download in ordinary malicious chains, so (c) is false. (d) requires a delete event that also isn't present -- there is no evidence anything was ever written and removed.",
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
        "Whether the background process registered as a clipboard listener and was substituting copied wallet addresses with an attacker-controlled one",
        "Whether the process was logging keystrokes, since that is the most common way credentials are stolen",
        "Whether the laptop's webcam was accessed without the user's knowledge",
        "Whether the process modified any Microsoft Office documents on the machine",
      ],
      answer: 0,
      explanation:
        "This is the exact pattern Reading 3 described: no crash, no visible symptom, and the only outcome anyone notices is a payment gone to the wrong place -- the specific artefact to check for is a clipboard-format listener substituting wallet addresses. Keylogging (b) would produce a very different downstream symptom (stolen credentials used elsewhere, not a misdirected crypto payment). Webcam access (c) and document tampering (d) have no connection to a missing cryptocurrency payment and aren't supported by anything in the scenario.",
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
        question: "Per Reading 4, why does a fetch-after-execution pattern -- the installer reaching out to unrelated infrastructure seconds after it starts -- specifically identify a loader rather than a standalone trojan?",
        options: [
          "Because a standalone trojan only ever runs code that was already inside the original downloaded file, while a loader's real job is retrieving a separate second-stage file from different infrastructure",
          "Because loaders are always digitally signed by a recognisable software publisher, while standalone trojans are never signed by anyone at all",
          "Because a loader always specifically targets Linux systems running a compatible shell, and never runs on any version of Windows at all",
          "There is no real difference between the two terms at all -- security researchers use 'loader' and 'trojan' completely interchangeably in every report",
        ],
        answer: 0,
        explanation:
          "A plain trojan simply runs the malicious code already inside the file the user downloaded. A loader's defining behaviour is reaching out, right after execution, to entirely separate infrastructure to retrieve a different file -- that fetch is what earns it the T1105 label.",
      },
    },
    // ── Log Analysis 1: SEO-poisoned installer fetch ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "mcia-la1",
      heading: "A Sponsored Result, Four Seconds After the Installer Ran",
      context:
        "NexaCorp's IT support technician Dor Mizrahi searched for a common archiving tool and downloaded 7zSetup-2026.exe from a sponsored search result rather than the official project site. He ran the installer, accepted the elevation prompt, and briefly saw a setup window before it closed with a generic error — he never actually got a working copy of the tool. The event below is what the firewall recorded four seconds after the installer process started.",
      event: seoInstallerEvent,
      questions: [
        {
          question:
            "The domain this request went to, cdn-pkg-mirror19.net, has no relationship at all to the site 7zSetup-2026.exe was originally downloaded from. What does a freshly-launched installer immediately reaching out to unrelated infrastructure for another file tell you about what kind of program it actually is?",
          options: [
            "It is a loader -- its real job is to fetch and run a second-stage payload from separate infrastructure, not to install the software it claimed to be",
            "It is normal installer behavior -- most legitimate installers reach out to unrelated third-party domains to fetch components",
            "The firewall must be misattributing this connection to the wrong process",
            "It confirms the original download site, not this second domain, is the actual attacker infrastructure",
          ],
          answer: 0,
          explanation:
            "Reading 4 covered exactly this shape: an installer whose only real job is fetching a second, unrelated file is a loader, tracked as T1105. Legitimate installers occasionally fetch redistributable components, but not from infrastructure with zero naming or ownership relationship to the download site, which rules out (b) as the default explanation here. Nothing in the event suggests a misattributed connection (c), and the original download site being the delivery vector doesn't mean the second domain isn't also attacker-controlled (d) -- both can be true at once.",
          xp: 25,
        },
        {
          question:
            "pan.category on this event is 'newly-registered-domain' and pan.action is 'alert', not 'block'. What does that combination tell you about this firewall's policy?",
          options: [
            "The policy logs and allows traffic to newly-registered domains rather than blocking it outright -- visibility without prevention",
            "The rule is broken and should be fixed immediately to auto-block this entire category",
            "TLS inspection must have failed, so the firewall could only log a generic alert",
            "cdn-pkg-mirror19.net must be on an internal allowlist",
          ],
          answer: 0,
          explanation:
            "pan.action 'alert' is a deliberate policy outcome many organisations choose for risky-but-unconfirmed categories, because blocking every newly-registered domain wholesale breaks a large number of legitimate new sites. Full URLs and filenames are present in the log, which contradicts a TLS inspection failure (c). Nothing supports an allowlist (d) for a domain the log still categorises as risky, and assuming a bug (b) isn't warranted by a single alert-not-block decision.",
          xp: 25,
        },
        {
          question:
            "Given what Reading 4 taught about what this kind of second-stage payload usually goes after, what should investigators check for next on LAP-9021?",
          options: [
            "Whether a browser credential-store filename, such as Chrome's own 'Login Data' file, has been copied to a folder outside the browser's own profile",
            "Whether the Windows Registry Run key has a new autostart entry pointing at a completely unrelated program",
            "Whether the domain controller's Kerberos ticket-granting service issued any unusual tickets",
            "Whether a scheduled task was created to run PowerShell every night at 2 AM",
          ],
          answer: 0,
          explanation:
            "Reading 4 was specific: a large share of these loader campaigns deliver an infostealer that copies the browser's own credential database under a filename like 'Login Data', outside the browser's own profile path -- that is the artefact this exact chain most commonly produces next. The other options describe real persistence or credential-attack patterns taught elsewhere on this platform, but none of them are what this room's SEO-installer reading specifically pointed toward.",
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
        "**The gap this closes.** The marker belongs to the specific file object Windows tagged — the ISO, IMG, or VHD container itself, not to whatever is inside it. When a victim double-clicks a downloaded ISO file, Windows' own built-in container-mount handler presents it as a brand-new drive letter, exposing whatever files sit inside. Those inner files are read directly off the mounted volume; they never go through their own separate internet-download path, so they never receive their own Zone.Identifier tag — and a shortcut or executable inside that mounted volume can run with no SmartScreen prompt at all, even though the container that delivered it was correctly tagged the moment it landed in Downloads.\n\n" +
        "**Why this pattern specifically became common after 2022.** Once Office started blocking macros from the internet by default, several loader families that had relied heavily on malicious Word or Excel documents moved to container formats specifically because Windows will mount them without flagging them the way it flags a raw .exe — MITRE ATT&CK tracks this as T1553.005, Subvert Trust Controls: Mark-of-the-Web Bypass.\n\n" +
        "**What the shortcut actually does.** The .lnk file sitting inside the mounted volume is rarely the payload itself — its target is almost always a short command that hands off to something else, most often cmd.exe launching a hidden, base64-encoded PowerShell command. cmd.exe's command line in this pattern typically carries no logic of its own beyond the instruction to start the next interpreter — it functions purely as a relay, a detail worth reading directly off the process's own command-line field rather than assuming from the process name alone.\n\n" +
        "**Why 'the file-filter policy didn't block it' isn't the same failure as it sounds like.** Most download-filtering policies were built to catch and block risky executable types outright. A policy that only inspects or blocks .exe downloads has nothing to say about an .iso — it simply isn't the file type the policy was designed to look at, which is exactly why closing this gap means extending container formats (.iso, .img, .vhd) into the same filtering policy that executables already get, not assuming the existing exe-focused control already covers it.\n\n" +
        "**MITRE ATT&CK coverage.** T1553.005 for the Mark-of-the-Web bypass itself; T1204.002 (User Execution: Malicious File) for the victim opening the container and its shortcut in the first place; T1059.001 for the PowerShell stage the relay hands off to.",
    },
    // ── Question 3 (applied — MOTW non-propagation) ────────────────────────────
    {
      type: "question" as const,
      id: "mcia-q3",
      question:
        "A user double-clicks a shortcut sitting inside a mounted ISO volume that came from a downloaded file, and it launches cmd.exe with no SmartScreen warning at all -- even though the ISO file itself was tagged with a Mark-of-the-Web zone identifier when it was downloaded. Why didn't the warning appear?",
      options: [
        "Mark-of-the-Web is a property of the downloaded container file itself; files exposed once Windows mounts that container are read directly off the mounted volume and never receive their own zone tag",
        "SmartScreen was manually disabled by an administrator on this specific machine as part of an earlier, unrelated troubleshooting ticket",
        "The shortcut was digitally signed by a trusted publisher's certificate, and any signed file always bypasses SmartScreen entirely regardless of origin",
        "ISO files as a format are always excluded from SmartScreen checks by Windows by design, regardless of what they actually contain",
      ],
      answer: 0,
      explanation:
        "Reading 5 covered exactly this mechanism: the mark belongs to the container file object, not to anything exposed once it's mounted -- inner files never go through their own download path and so never get their own tag. Nothing in the scenario supports an administrator disabling SmartScreen (b) or a trusted signature (c) -- both invent facts not in evidence. ISO files aren't categorically excluded from SmartScreen (d); the mount mechanism, not the file extension itself, is what explains the missing prompt.",
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
        question: "Per Reading 6, why is a browser-based miner's WebSocket connection to its mining relay hard to distinguish from ordinary traffic using category or app-type fields alone?",
        options: [
          "WebSocket and an unclassified category both cover huge amounts of ordinary traffic -- the duration and destination pattern, a single relay held open continuously, is what actually stands out",
          "Because the connection is always encrypted end-to-end with a proprietary protocol that no firewall or proxy is technically able to log at all",
          "Because mining relays always deliberately use port 22 instead of port 443, which most firewalls simply don't inspect by default",
          "There is genuinely no way to distinguish this traffic from ordinary browsing under any circumstances, at the firewall layer or anywhere else",
        ],
        answer: 0,
        explanation:
          "Both fields describe huge swaths of normal browsing -- chat apps and dashboards use WebSocket constantly, and 'unknown' just means no category has been assigned yet. What actually stands out is behavioural: one destination held open continuously with steady small bursts, unlike how a page's WebSocket connections normally behave.",
      },
    },
    // ── Analyst Choice: legitimate paste-run install ────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "mcia-ac1",
      heading: "Verdict: A Hidden PowerShell Window, Launched by explorer.exe",
      scenario:
        "A Falcon detection fires on WS-6820 for a High-severity PowerShell Command and Scripting Interpreter pattern: explorer.exe launching a hidden-window powershell.exe process that downloads and runs a script from the internet. On the surface this is exactly the shape this room has spent several readings teaching you to escalate. Review the record before deciding how to handle it.",
      event: legitPasteRunEvent,
      correct_verdict: "false_positive",
      explanation:
        "The command line downloads and runs the install script from community.chocolatey.org — the real, publicly documented installation method for the Chocolatey package manager, not a lookalike or newly-registered domain. it_verify_result is 'confirmed', tied to change ticket CHG-44190 authorising exactly this rollout for the DevOps team this week, and the user, y.cohen, is a DevOps engineer performing the action on their own workstation. process.signed is 'true' for powershell.exe itself, which is expected either way (Reading 2 already established a signed interpreter says nothing about the intent of what it's told to run) — the deciding fields here are the verified domain and the confirmed change ticket, not the signature.",
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
        "Notice what all five have in common: none of them require a malicious document macro, and three of the five never write a downloaded payload to disk before the first suspicious activity begins. That's exactly why file-download-focused controls, on their own, aren't enough to catch any of them.",
      xp: 35,
    },
    // ── Ordering: triage sequence for a fileless-looking initial-access alert ──
    {
      type: "ordering" as const,
      id: "mcia-o1",
      heading: "Order the Triage of an Alert With No Obviously Malicious Downloaded File",
      instructions: "Arrange these steps in the order an analyst should actually work them for an alert where a legitimate-looking process chain led to unexpected activity, with no obviously malicious file ever downloaded.",
      items: [
        { id: "ancestry", text: "Check the full process ancestry -- which process actually launched the first suspicious process, and is that parent-child relationship itself normal" },
        { id: "fileless", text: "Check whether any file existed on disk before the first suspicious process started, or whether execution began with no antecedent download at all" },
        { id: "domain", text: "Check the destination domain's category, registration age, and reputation" },
        { id: "outcome", text: "Check whether the outbound connection actually succeeded or was blocked, and what -- if anything -- left the host" },
        { id: "context", text: "Check for a verified IT ticket, change record, or other known legitimate business reason before deciding on a verdict" },
        { id: "verdict", text: "Assign a verdict and document the full timeline for the incident record" },
      ],
      correct_order: ["ancestry", "fileless", "domain", "outcome", "context", "verdict"],
      explanation:
        "Start by reconstructing exactly what launched what -- an unusual parent-child pair, like explorer.exe launching a command interpreter directly, is the first fact worth establishing. From there, check whether a file was ever involved at all, since several of this room's techniques never touch disk the way a classic download does. Only once you know the technical shape of what happened does the destination's reputation and the connection's outcome tell you how far it actually got. Checking for a verified business reason comes after the technical picture is complete, not before it -- deciding 'there's probably a ticket for this' too early is exactly how a real compromise gets waved through, while checking it before finalising a verdict is exactly what turned the Chocolatey install in this room's analyst-choice task from an alarming-looking pattern into a correctly-closed false positive. Only with all of that in hand should you commit to a verdict and write it up.",
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
            "The duration and shape -- a single destination held open continuously for nineteen minutes with steady small bidirectional bursts, which is not how a typical page's WebSocket connections behave",
            "WebSocket connections are inherently malicious by design and should always be escalated as an incident the moment one appears in the firewall log",
            "The 'unknown' category value means the firewall has already independently confirmed this specific domain is malicious infrastructure",
            "Port 443 is an unusual and suspicious choice for WebSocket traffic to use, since WebSocket normally only runs over port 80",
          ],
          answer: 0,
          explanation:
            "Reading 6 was explicit that neither field rules anything in or out on its own -- what stands out is behavioural: pan.elapsed_time of 1140 seconds against one destination, with steady bytes_sent/bytes_received, is not how a typical page's WebSocket connections behave. WebSocket is mainstream, legitimate web infrastructure (b), 'unknown' is simply an absence of classification rather than a verdict (c), and 443 is the standard HTTPS/WebSocket port, not an anomaly (d).",
          xp: 25,
        },
        {
          question:
            "Per this room's Reading 6, why can this technique run entirely without a single file ever appearing in the user's Downloads folder or a new process appearing outside the browser itself?",
          options: [
            "The mining code is a WebAssembly module that a legitimate, unmodified browser process compiles and executes inside its own sandbox -- no separate executable is ever required",
            "The malware disables the EDR sensor before running, which prevents any file or process events from being logged at all",
            "The browser process itself is replaced by a malicious lookalike binary with the same name",
            "Cryptomining code cannot be executed inside a browser at all, so this connection must be something else entirely",
          ],
          answer: 0,
          explanation:
            "Reading 6 covered this directly: the 'payload' is a WebAssembly module the browser's own renderer process compiles and runs inside its existing sandbox -- no separate executable, and therefore no new file or unfamiliar process name to notice. Nothing here shows a disabled sensor (b) or a replaced binary (c), and (d) is simply false -- WebAssembly is specifically designed to run compute-heavy code inside a browser at near-native speed.",
          xp: 25,
        },
        {
          question:
            "Given that closing the browser tab ends this technique's entire impact -- there is no separate process or file to remove -- what does that mean for how you scope the response?",
          options: [
            "Confirm the tab/renderer is actually closed, and treat the two attacker domains (the script host and the relay) as the artefacts worth blocking, since nothing persists beyond the browser session itself",
            "Reimage the laptop regardless of the evidence, since any unknown code execution on a corporate asset always requires a complete rebuild",
            "Reset the user's domain password immediately, since arbitrary code executed inside their authenticated browser session",
            "No action is needed at all once the tab is closed, including no domain blocking, since Falcon's own action was 'No Action' by design",
          ],
          answer: 0,
          explanation:
            "Reading 6 made this explicit: nothing here writes a persistence mechanism or touches a credential, so closing the tab and renderer ends the technical impact -- the remaining work is scoping the delivery, meaning the injected script's domain and the mining relay both belong on a blocklist so the same tab doesn't reconnect on reload. Reimaging (b) is disproportionate when nothing reached disk outside the browser's own ordinary caching. Resetting a password (c) has no basis -- no credential store or token was touched anywhere in this evidence. Doing nothing at all (d) leaves the delivery domains live for the next visitor.",
          xp: 30,
        },
      ],
    },
    // ── Flag ────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "mcia-f1",
      prompt:
        "Look at the Log Analysis finding on LAP-4471. What is the exact value of the url.domain field in the raw log?",
      answer: "relay-ws-pool3.net",
      hint: "Look inside the raw block of the log analysis event for the field named url.domain.",
      xp: 20,
    },
    // ── Question 4 (synthesis — cross-technique differentiation) ───────────────
    {
      type: "question" as const,
      id: "mcia-q4",
      question:
        "A user calls the helpdesk saying their laptop has been 'running a little hot' for the past hour. They used a free browser-based tool for routine work, nothing appears in their Downloads folder, and Task Manager shows no unfamiliar process outside the browser itself. Which of this room's five techniques best fits, and why?",
      options: [
        "Drive-by browser cryptomining -- the entire 'payload' runs as WebAssembly inside the browser's own renderer process, so there is never a separate file or process to notice, only sustained CPU load tied to an open tab",
        "ClickFix paste-and-run -- the user must have pasted a command into the Run dialog without ever noticing it happen, leaving no memory of doing so",
        "Clipboard clipper -- the malware is quietly rewriting clipboard content in the background, which happens to produce a small but steady CPU cost",
        "ISO container smuggling -- the user must have mounted a downloaded ISO file without realising it and never noticed the new drive letter appear",
      ],
      answer: 0,
      explanation:
        "Only drive-by browser cryptomining matches every detail given: no downloaded file, no separate process outside the browser, and a symptom (heat, meaning sustained CPU) tied directly to an open tab. ClickFix (b) would leave a distinct powershell.exe process outside the browser. A clipboard clipper (c) produces no heat symptom at all -- its only sign is a misdirected payment, not CPU load. ISO smuggling (d) requires a downloaded container file, which the scenario explicitly rules out by saying Downloads is empty.",
      xp: 30,
    },
  ],
};

export const roomsBatch32 = [commodityInitialAccessRoom];
