/**
 * Learning Rooms — Batch 22
 *
 * Two rooms closing gaps found by coverage audit:
 *
 * - malware-types                 — the platform's scenarios use "dropper",
 *   "loader", "infostealer", "wiper", "RAT" freely, but only one section in
 *   the whole platform teaches the malware taxonomy at beginner level (and
 *   that one is about AV-to-EDR evolution, not the types themselves). This
 *   room organises the taxonomy around OBJECTIVE — what each type wants, how
 *   it arrives, what it looks like in telemetry, and what the analyst's
 *   priority is — rather than folklore category names memorised in isolation.
 *
 * - asset-context-prioritisation  — the platform has exactly one section on
 *   asset context, buried inside vulnerability management. Prioritisation is
 *   the daily job of a SOC analyst, and an identical alert on a domain
 *   controller versus a test VM is a different incident. This room teaches
 *   asset criticality, blast radius, exposure, business context, and the
 *   honest limits of a CMDB, then has the student rank concurrent alerts
 *   where the correct order depends on asset context rather than the
 *   severity a product assigned.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// ROOM 1: malware-types
// =============================================================================

const loaderBeaconEvent: TelemetryEvent = {
  id: "evt-malware-la1-001",
  ts: "2026-05-11T09:47:52.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "net_connection",
  severity: "high",
  hostname: "WKS-ACCT07.meridian.local",
  process: {
    name: "quarterly_invoice.exe",
    pid: 5588,
    path: "C:\\Users\\t.osei\\Downloads\\quarterly_invoice.exe",
    parent_name: "explorer.exe",
    parent_pid: 2244,
    cmdline: "\"C:\\Users\\t.osei\\Downloads\\quarterly_invoice.exe\"",
    user: "MERIDIAN\\t.osei",
    integrity: "medium",
  },
  network: {
    domain: "cdn-assets-delivery.net",
    bytes_out: 612,
  },
  description:
    "quarterly_invoice.exe, opened by t.osei nine minutes after it arrived as an email attachment, established an outbound TCP connection to cdn-assets-delivery.net roughly four seconds after the process started, before any invoice content had been displayed on screen.",
  raw: {
    "winlog.event_id": 3,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
    "winlog.computer_name": "WKS-ACCT07.meridian.local",
    "winlog.event_data.RuleName": "-",
    "winlog.event_data.UtcTime": "2026-05-11 09:47:52.000",
    "winlog.event_data.ProcessGuid": "{2b7e91c4-3a0f-6681-7e04-000000005d00}",
    "winlog.event_data.ProcessId": "6248",
    "winlog.event_data.Image": "C:\\Users\\t.osei\\Downloads\\quarterly_invoice.exe",
    "winlog.event_data.User": "MERIDIAN\\t.osei",
    "winlog.event_data.Protocol": "tcp",
    "winlog.event_data.Initiated": "true",
    "winlog.event_data.SourceIp": "10.40.12.61",
    "winlog.event_data.SourcePort": 51422,
    "winlog.event_data.DestinationHostname": "cdn-assets-delivery.net",
    "winlog.event_data.DestinationIp": "203.0.113.47",
    "winlog.event_data.DestinationPort": 443,
    "winlog.event_data.DestinationPortName": "https",
    "winlog.event_data.SourceIsIpv6": "false",
    "winlog.event_data.DestinationIsIpv6": "false",
  },
};

const infostealerEvent: TelemetryEvent = {
  id: "evt-malware-ac1-001",
  ts: "2026-05-14T22:18:03.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "file_access",
  severity: "high",
  hostname: "WKS-SALES19.meridian.local",
  process: {
    name: "SystemHealthCheck.exe",
    pid: 8814,
    path: "C:\\Users\\r.deluca\\Downloads\\SystemHealthCheck.exe",
    parent_name: "explorer.exe",
    parent_pid: 3390,
    cmdline: "\"C:\\Users\\r.deluca\\Downloads\\SystemHealthCheck.exe\"",
    user: "MERIDIAN\\r.deluca",
    integrity: "medium",
  },
  file: {
    name: "Login Data",
    path: "C:\\Users\\r.deluca\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
  },
  description:
    "SystemHealthCheck.exe, downloaded from a third-party 'PC optimizer' site roughly two hours earlier, opened Chrome's local credential-store file directly, then opened the equivalent file inside the Edge browser profile on the same host within the same second.",
  raw: {
    DeviceName: "WKS-SALES19.meridian.local",
    ActionType: "FileAccessed",
    FileName: "Login Data",
    FolderPath: "C:\\Users\\r.deluca\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    InitiatingProcessFileName: "SystemHealthCheck.exe",
    InitiatingProcessFolderPath: "C:\\Users\\r.deluca\\Downloads\\SystemHealthCheck.exe",
    InitiatingProcessCommandLine: "\"SystemHealthCheck.exe\"",
    InitiatingProcessAccountName: "r.deluca",
    InitiatingProcessParentFileName: "explorer.exe",
    Timestamp: "2026-05-14T22:18:03.000Z",
  },
};

const pupEvent: TelemetryEvent = {
  id: "evt-malware-ac2-001",
  ts: "2026-05-18T11:02:44.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "av_detection",
  severity: "low",
  hostname: "WKS-MKT22.meridian.local",
  it_verify_result: "confirmed",
  it_verify_message:
    "IT Service Desk ticket SD-30217 confirms PDFSuiteProEnterprise_Setup.exe is the licensed installer pushed to the Marketing team this week; the bundled browser toolbar it installs is listed as an accepted low-risk component in the software catalog entry for this title.",
  description:
    "Microsoft Defender flagged a browser toolbar component installed alongside PDFSuiteProEnterprise_Setup.exe, a package the Marketing team received this week as part of an approved software rollout.",
  raw: {
    ActionType: "AntivirusDetection",
    FileName: "SearchAssistantToolbar.exe",
    FolderPath: "C:\\Program Files (x86)\\PDFSuitePro\\Toolbar\\SearchAssistantToolbar.exe",
    InitiatingProcessFileName: "PDFSuiteProEnterprise_Setup.exe",
    InitiatingProcessFolderPath: "C:\\Windows\\ccmcache\\1c\\PDFSuiteProEnterprise_Setup.exe",
    AccountName: "system",
    AdditionalFields: "{\"ThreatName\":\"PUA:Win32/InstallCore\",\"WasExecutingWhileDetected\":false,\"WasRemediated\":true}",
    DeviceName: "wks-mkt22.meridian.local",
    ReportId: 31094,
    Timestamp: "2026-05-18T11:02:44.000Z",
  },
};

const malwareTypesRoom: Room = {
  id: "malware-types",
  title: "Malware Types and What Each One Wants",
  description:
    "The platform's scenarios say 'trojan-dropper', 'loader', 'infostealer', 'wiper', and 'RAT' as if you already know what each one is for, and you can't triage what you can't name. This room organises the whole malware taxonomy around one question per type: what does it want, how does it arrive, what does it look like in telemetry, and what should you do the moment you recognise it?",
  difficulty: "beginner",
  category: "Threat Intelligence",
  estimatedMinutes: 55,
  xp: 290,
  icon: "🧬",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    {
      type: "reading",
      id: "malware-r1",
      heading: "What Malware Actually Wants: Propagation vs Payload",
      content:
        `Security folklore names malware like it's cataloguing monsters (virus, worm, trojan, wiper, RAT) and a new analyst can spend hours memorising these names without gaining anything useful for triage. There's a better way in: instead of memorising labels, answer two independent questions for anything you encounter. First, how does it move: does it need a person to run it, or can it spread by itself? Second, what does it do once it's running. What is its actual objective? Every name in this room is really just a specific answer to those two questions, and once you see the frame, the names stop being folklore and start being useful shorthand.\n\n` +
        `**The propagation axis: does it need you?**\n\n` +
        `A virus needs a host file to attach itself to, and it needs a person to run that host file: the same way a biological virus needs a living cell and does nothing at all sitting inert on a surface. A trojan also needs a person to run it, but it doesn't attach to another file; instead it disguises itself as something the person actively wants (an invoice, a cracked game, a "PDF converter") and relies entirely on the user choosing to launch it. A worm is the outlier on this axis: it spreads across a network on its own, machine to machine, with no human clicking anything after the very first infection. That single difference is why worm outbreaks move on a completely different timescale than trojan campaigns: a trojan needs an entire company to individually open the same phishing email, one inbox at a time, while a worm can be on every unpatched machine on a subnet within minutes of the first one being hit. If you only remember one thing from this reading, make it this: "self-propagating, no user needed" is the single fact that should make you treat a worm report with more urgency than almost anything else on this list, purely because of the clock it starts.\n\n` +
        `**The payload axis: what does it do once it's running?**\n\n` +
        `Once code is executing, it's built toward one of a handful of objectives, and this room covers each one as its own reading: steal something and leave (infostealer), give a human attacker live hands-on-keyboard control (RAT/backdoor), encrypt files for extortion (ransomware), destroy data with no way back (wiper), or quietly steal compute cycles (cryptominer). A few more (rootkits, fileless techniques, and PUPs) are less about a distinct objective and more about how the malware hides or how seriously it deserves to be taken, and this room covers those too.\n\n` +
        `**Why keeping the two axes separate matters**\n\n` +
        `Propagation and payload are independent choices an attacker makes, not a package deal, which is exactly why a single piece of malware can combine them in ways a folklore-only vocabulary can't describe. WannaCry, for instance, used worm-style self-propagation over a Windows networking flaw to spread machine-to-machine with no user interaction at all, while its payload was ordinary file-encrypting ransomware. Calling it "a worm" describes how it moved; calling it "ransomware" describes what it did once it landed; you need both answers to actually understand what happened. The diagram below is this room's whole argument in one picture: work down the propagation question first, then the payload question, and almost any malware name you'll ever encounter falls into place.`,
      diagram:
        "flowchart TD\n" +
        "  A[Malware] --> B{Does it need a user to run it?}\n" +
        "  B -->|Yes -- needs a host file AND a user| C[Virus]\n" +
        "  B -->|Yes -- disguises itself, user launches it| D[Trojan]\n" +
        "  B -->|No -- spreads itself across the network| E[Worm]\n" +
        "  C --> F{What does the payload DO once running?}\n" +
        "  D --> F\n" +
        "  E --> F\n" +
        "  F -->|Steal credentials/data, then leave| G[Infostealer]\n" +
        "  F -->|Give an attacker live hands-on control| H[RAT / Backdoor]\n" +
        "  F -->|Encrypt for extortion| I[Ransomware]\n" +
        "  F -->|Destroy with no way back| J[Wiper]\n" +
        "  F -->|Steal CPU/GPU cycles| K[Cryptominer]",
      diagramCaption: "Two independent questions: how it moves, then what it wants",
    },
    {
      type: "question",
      id: "malware-q1",
      question:
        "An EDR alert reports a worm on one host of an unpatched subnet, at the same moment a phishing-based trojan is reported on a single user's laptop elsewhere in the company. Both are rated the same severity by the product. Why does the worm typically demand faster action?",
      options: [
        "Worms carry a more destructive payload than trojans, so each infected host costs more to recover",
        "It spreads on its own to every reachable unpatched host, so the scope grows while you triage",
        "It attaches to files that people share, so each colleague who opens one adds another victim",
        "It gives a live attacker hands-on control of the host, which a trojan's payload cannot do",
      ],
      answer: 1,
      explanation:
        "The propagation axis from Reading 1 is exactly the point: a worm's self-propagation means the population of infected hosts can grow with no further human action at all, so every minute of delay has a multiplying effect that a trojan (bottlenecked by how many individual people choose to open a file) simply doesn't have. The word worm says how it moves, not what its payload does, so a more destructive payload or hands-on control is not what sets it apart: WannaCry's worm-style spread carried a ransomware payload, and propagation and payload are separate questions. Attaching to a file that a person must run describes a virus, not a worm.",
      xp: 20,
    },
    {
      type: "reading",
      id: "malware-r2",
      heading: "Dropper vs Loader vs Stager: The Distinction Juniors Miss",
      content:
        `Once malware has landed and run for the first time, it usually still needs to get its real, fully-capable payload onto the machine, and exactly how it does that is one of the most operationally important distinctions in this whole room, precisely because juniors routinely treat "dropper" and "loader" as interchangeable synonyms when they describe two very different SOC situations.\n\n` +
        `**A dropper carries its payload inside itself**\n\n` +
        `A dropper is a single file that already contains its full malicious payload, embedded inside it, at the moment it first runs. When a user double-clicks it, there's no second download, no network request for "the real malware", everything needed is already sitting on disk inside that one file, and the dropper's only job is to extract and launch it locally. From a detection standpoint, this means the moment of execution IS the moment the full payload becomes available; there's no network step in between to intercept.\n\n` +
        `**A loader fetches stage 2 from the network**\n\n` +
        `A loader, by contrast, is a small, often unremarkable-looking file whose whole job is to reach out over the network, usually within seconds of launching, and pull down the actual malicious payload from infrastructure the attacker controls. The file that first ran is nearly harmless on its own; it's really just a fetch mechanism. A stager is the same idea taken one step further toward minimalism: an even smaller piece of code (sometimes just a few hundred bytes) whose only job is to establish just enough of a connection to pull down a larger, fully-featured payload next.\n\n` +
        `**Why this is the distinction that actually matters to a SOC**\n\n` +
        `Here's the operational consequence that makes this worth learning carefully: with a loader (or a stager), you get something a dropper never gives you, a network indicator, and a genuine window of time to act before the real payload ever lands. The destination domain or IP the loader reaches out to can be blocked at a proxy or firewall, and if that block happens fast enough, stage 2 simply never arrives, no matter how compromised the first-stage file already was. With a dropper, that window doesn't exist, the payload was already there the moment the file ran, so response has to focus immediately on the file itself: its hash, its on-disk behaviour, and full incident response, not on trying to race a network connection that already delivered everything it was going to deliver.\n\n` +
        `Blocking the destination is only half of the response to a suspected loader. Also take the host off the network, because stage 2 may already have landed or may arrive another way, and keep the file for analysis rather than deleting it, because it is your evidence of what actually ran.\n\n` +
        `The sequence below shows both paths side by side. Notice exactly where the loader path gives a defender a chance the dropper path never offers.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant U as User\n" +
        "  participant D as Dropper (one file)\n" +
        "  participant L as Loader (one file)\n" +
        "  participant N as Network\n" +
        "  Note over D: DROPPER PATH\n" +
        "  U->>D: double-clicks the attachment\n" +
        "  D->>D: payload already embedded -- extracts and runs locally\n" +
        "  Note over D: No network request needed -- nothing to intercept\n" +
        "  Note over L: LOADER PATH\n" +
        "  U->>L: double-clicks the attachment\n" +
        "  L->>N: reaches out for stage 2 within seconds\n" +
        "  Note over N: DETECTION WINDOW -- domain/IP can be blocked here\n" +
        "  N-->>L: stage 2 payload delivered (if not blocked)\n" +
        "  L->>L: executes the downloaded stage 2",
      diagramCaption: "Dropper vs loader, where the network gives you a chance",
      codeExample:
        "DROPPER vs LOADER -- WHAT EACH ONE GIVES YOU TO WORK WITH\n" +
        "=======================================================\n" +
        "Dropper\n" +
        "  Payload location at execution:  already embedded inside the file\n" +
        "  Network request for payload:    none\n" +
        "  What to prioritize in response:  the file itself -- hash, on-disk\n" +
        "                                    content, full IR from execution\n" +
        "\n" +
        "Loader / Stager\n" +
        "  Payload location at execution:  fetched over the network after launch\n" +
        "  Network request for payload:    yes, usually within seconds\n" +
        "  What to prioritize in response:  block the destination domain/IP\n" +
        "                                    FAST -- you may still be able to\n" +
        "                                    stop stage 2 from ever landing\n" +
        "=======================================================",
      checkpoint: {
        question: "What is the defining trait that separates a dropper from a loader?",
        options: [
          "A dropper needs administrator rights to run; a loader runs as a standard user",
          "A dropper carries its payload inside the file; a loader downloads it after launch",
          "A dropper arrives as an email attachment; a loader arrives on a USB drive",
          "A dropper sets up persistence; a loader runs once and then deletes itself",
        ],
        answer: 1,
        explanation:
          "A dropper carries its full payload inside itself with no network step needed, while a loader is a small fetch mechanism that reaches out over the network shortly after launch -- that stage-2 download is the blockable window a dropper never offers. Neither term is about privilege level, and both arrive by email, download or USB alike. Persistence is something either one's payload may set up; it is not what separates them.",
      },
    },
    {
      type: "log_analysis",
      id: "malware-la1",
      heading: "A Connection Four Seconds After Launch",
      context:
        "t.osei in Accounts Payable reports that an 'invoice' attachment they opened from an email nine minutes ago never actually displayed anything. Sysmon on their workstation recorded the network event below in that same window.",
      event: loaderBeaconEvent,
      questions: [
        {
          question:
            "quarterly_invoice.exe reached out to an external domain about four seconds after launch, before any invoice content had rendered, and it arrived as a single file attached to an email. What does this pattern most likely indicate?",
          options: [
            "A routine update check: many apps contact their vendor right after launch",
            "Likely a loader: it reached out to fetch a second stage right after running",
            "Likely a dropper: the connection is its embedded payload calling home",
            "Likely benign: the connection used port 443, the normal HTTPS port",
          ],
          answer: 1,
          explanation:
            "A 'document' that reaches the network before showing any of its claimed content, seconds after launching from an email attachment, matches the loader pattern from Reading 2 far better than an update check, and an invoice has no vendor to check in with. The dropper option gets the definition backwards: a dropper's defining trait is that it does NOT need a network connection, because its payload is already embedded inside it. Port 443 just means TLS was used; it says nothing about legitimacy, and it is the most common way malware blends in with everything else on a network.",
          xp: 25,
        },
        {
          question:
            "If quarterly_invoice.exe had instead been a dropper rather than a loader, what would be different about the detection and response opportunity here?",
          options: [
            "Nothing: 'dropper' and 'loader' are vendor names for the same behaviour",
            "No stage-2 download to block; response would start from the file itself",
            "A dropper needs admin rights, so a UAC prompt would have flagged it first",
            "A dropper beacons for hours, so you would hunt for C2 instead of a fetch",
          ],
          answer: 1,
          explanation:
            "This is the operational consequence from Reading 2: a dropper never gives you the stage-2 download window this loader just did, because its payload is already inside the file. Response starts from the file's hash and on-disk behaviour from the moment it ran. (The payload it drops, often a RAT or stealer, may still call out to C2 later, and that traffic can be blocked, but the chance to stop the payload arriving is gone.) The two terms describe different behaviour, not vendor branding. Neither needs admin rights by definition. Hours of recurring beacons describe a RAT's C2 channel, not a dropper.",
          xp: 25,
        },
        {
          question:
            "Given this event, what is the correct immediate response?",
          options: [
            "Block the domain, but leave the host online to watch whether stage 2 arrives",
            "Isolate the host, block the domain and its IP, and submit the file for analysis",
            "Delete quarterly_invoice.exe, run a full AV scan, then close the alert",
            "Reset t.osei's password first, since the connection may be credential theft",
          ],
          answer: 1,
          explanation:
            "This is the loader's exact detection window from Reading 2: block the destination fast, isolate the host to limit anything already in progress, and get the file itself analysed to confirm what it is. Leaving the host online to watch risks stage 2 landing through another path. Deleting the file and scanning destroys the evidence you need and skips the question of whether stage 2 already arrived. Nothing here points to credential theft yet, so a password reset is not the first move.",
          xp: 30,
        },
      ],
    },
    {
      type: "flag",
      id: "malware-f1",
      prompt:
        "Look at Log Analysis 1 (the quarterly_invoice.exe connection). Besides the domain, which IP address should go on the proxy/firewall block list? Enter it exactly as shown in the raw log.",
      answer: "203.0.113.47",
      hint: "The domain resolved to an address recorded in the same Sysmon event.",
      xp: 25,
    },
    {
      type: "reading",
      id: "malware-r3",
      heading: "RAT / Backdoor: Interactive Control, and Why Beaconing Is the Detectable Part",
      content:
        `A Remote Access Trojan (RAT) (often just called a backdoor once installed) gives an attacker something fundamentally different from every payload covered so far: a live, interactive connection to the compromised machine, the same way legitimate remote-support software gives an IT technician control of your screen, except the person on the other end was never invited. Once a RAT is running, the attacker can browse files, launch programs, take screenshots, log keystrokes, or pivot to other machines on the network, all in real time, exactly as if they were sitting at the keyboard.\n\n` +
        `**The relationship this requires: command-and-control (C2)**\n\n` +
        `A RAT can't just sit passively waiting to be interactively controlled. It has to maintain a connection back to infrastructure the attacker operates, commonly called a command-and-control (C2) server, so the attacker's instructions have somewhere to arrive from. Because that connection has to stay usable for as long as the attacker wants access, the RAT doesn't just make one network request and stop; it checks in repeatedly, over and over, for as long as it remains installed, sometimes every few seconds, sometimes only once every several hours to stay quiet.\n\n` +
        `**Why beaconing is the part you can actually catch**\n\n` +
        `This repeated check-in behavior is called beaconing, and it's the single most reliable network-based way to detect a RAT even when nothing else about the traffic looks unusual on any one occasion. A one-time connection right after execution (the loader pattern from Reading 2) looks similar to a single beacon in isolation, but a RAT's beacon keeps recurring, often at intervals close enough to regular that plotting connection timestamps to the same destination reveals an unmistakable pattern no ordinary application produces. This is exactly why "one connection to an unfamiliar domain" and "many connections to the same domain, spread out over hours or days" point an analyst toward two different conclusions: a loader fetching a payload once, versus a RAT's C2 channel still being actively used.\n\n` +
        `**What this means for triage priority**\n\n` +
        `A confirmed RAT should be treated as an active, ongoing intrusion rather than a completed event, because unlike an infostealer that already took what it wanted, a RAT represents a human attacker who may still be present and reacting in real time to whatever the SOC does next. That changes response mechanics: killing the process or blocking the C2 domain without first understanding what the attacker has already done and reached can tip them off and cause them to accelerate, which is why RAT incidents are the ones most likely to justify a quieter, more coordinated containment plan rather than an immediate, visible block.`,
      codeExample:
        "ONE-TIME FETCH vs ONGOING BEACON\n" +
        "=======================================================\n" +
        "Loader fetching stage 2  -->  ONE connection, right after launch,\n" +
        "                              then network activity stops\n" +
        "\n" +
        "RAT/backdoor beaconing   -->  RECURRING connections to the same\n" +
        "                              destination, continuing for hours\n" +
        "                              or days -- the attacker checking\n" +
        "                              back in for instructions\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "malware-q2",
      question:
        "Which network pattern is the strongest indicator of an active RAT/backdoor rather than a one-time loader fetch?",
      options: [
        "A single outbound connection right after execution that does not repeat: a RAT's beacon is strongest before the attacker issues commands",
        "Recurring outbound connections to one destination at regular or semi-regular intervals, continuing for hours or days after launch",
        "A large one-time download of an executable right after launch, since that is the defining network fingerprint of a RAT",
        "A connection that occurs during business hours, since RATs schedule check-ins to blend with working hours",
      ],
      answer: 1,
      explanation:
        "Reading 3's key distinction is recurrence over time, not any single technical detail of one connection: a loader's fetch is typically a single event, while a RAT's beacon keeps repeating for as long as the attacker wants access. A single connection that never repeats is the loader pattern, not a RAT. A large one-time executable download is a loader fetching its stage 2. Beaconing intervals are chosen by the attacker for stealth and often run around the clock, not only during business hours.",
      xp: 20,
    },
    {
      type: "reading",
      id: "malware-r4",
      heading: "Infostealer: Grab and Leave, Why the Response Is Revocation, Not Cleanup",
      content:
        `An infostealer's objective is narrow and fast: harvest whatever credentials, session cookies, and cryptocurrency wallet files it can reach on the machine, send them somewhere the attacker controls, and finish. There's no interactive control like a RAT, no encryption like ransomware: the entire "attack," from the SOC's point of view, is often over within minutes of execution.\n\n` +
        `**What it actually goes after**\n\n` +
        `Modern infostealers target the specific files browsers use to store saved logins (Chrome, Edge, and Firefox all keep a local credential database), the cookie files that let a browser stay "logged in" without re-entering a password, and increasingly, cryptocurrency wallet files and configuration data for cloud CLI tools. Cookies matter every bit as much as passwords here: a stolen session cookie can let an attacker walk directly into an already-authenticated session, skipping the login (and any multi-factor prompt) entirely.\n\n` +
        `**Why short dwell time doesn't mean low priority**\n\n` +
        `"Dwell time" is how long an attacker's tooling stays actively present and operating inside an environment before being found. An infostealer often has one of the shortest dwell times of anything covered in this room: it isn't trying to stay hidden long-term, because it doesn't need to; its entire objective can be complete within seconds of executing. That short window is exactly the trap: it's tempting to treat a fast, self-contained event as less serious than something that lingers, but the damage from an infostealer is typically already done by the time it's detected, the credentials have already left the building. Speed of detection buys you almost nothing about limiting what was taken; it only changes how quickly you can respond to the fact that it's already gone.\n\n` +
        `**Why the correct response is revocation, not cleanup**\n\n` +
        `Because the theft, not an ongoing presence, is the actual event, cleaning the malware off the endpoint (deleting the file, running a scan, confirming the process is gone) does nothing about the credentials and sessions that already left. The response an infostealer actually demands is credential and session revocation: reset every password that could plausibly have been stored in the affected browser profiles, and revoke active sessions and access tokens tied to those accounts so a stolen cookie can't be used to walk in without ever needing the password at all. Only after that containment step is complete does standard endpoint cleanup become the secondary task, not the primary one.`,
      checkpoint: {
        question: "Per Reading 4, why is deleting the infostealer file and running a scan not sufficient response on its own?",
        options: [
          "Because infostealers reinstall themselves, so the file will be back after the scan",
          "Because the theft already happened, so revoking sessions and resetting passwords comes first",
          "Because scans miss infostealers, so the process is probably still running on the host",
          "Because the stolen data is still on the disk, so the host must be wiped before anything else",
        ],
        answer: 1,
        explanation:
          "An infostealer's objective is often complete within seconds, so by the time it's detected the credentials are already gone -- cleaning the endpoint does nothing about that, which is why revocation and password resets come first. Infostealers usually grab and leave rather than persist, so reinstallation is not the core problem. Whether a scan catches the file does not change what already left. Wiping the host is cleanup too; it does not stop someone from using the stolen cookies and passwords.",
      },
    },
    {
      type: "analyst_choice",
      id: "malware-ac1",
      heading: "Verdict: A \"System Health Check\" Reading Browser Credential Files",
      scenario:
        "r.deluca in Sales downloaded a free 'PC optimizer' tool from a third-party site two hours ago and ran it once. EDR just logged the file access below. Decide whether this is worth treating as a real compromise.",
      event: infostealerEvent,
      correct_verdict: "true_positive",
      explanation:
        "A legitimate system health-check or PC optimizer has no functional reason to open a browser's local credential-store file (Login Data), reading Chrome's saved-password database matches automated credential harvesting, not disk cleanup or performance scanning. Distribution through an unofficial 'PC optimizer' site is a classic infostealer lure. Per Reading 4, the correct response is to treat every credential that could have been stored in Chrome or Edge on this host as compromised: force password resets and revoke active sessions/tokens for those accounts, not just remove the file and call it resolved.",
      xp: 30,
    },
    {
      type: "reading",
      id: "malware-r5",
      heading: "Ransomware: Encryption for Extortion, and Why Pre-Encryption Indicators Are the Actionable Part",
      content:
        `Ransomware's objective is to make an organization's own data unusable to itself and then demand payment to reverse it. The attacker encrypts files across as many systems and shares as they can reach, drops a ransom note explaining how to pay, and (if the victim has no usable backup) creates enormous pressure to pay simply to resume operating.\n\n` +
        `**Double extortion: the modern twist**\n\n` +
        `Older ransomware campaigns relied purely on encryption: no backup meant no leverage against paying. Organizations responded by investing heavily in backups, which weakened that leverage, so modern ransomware operators added a second lever, called double extortion: before ever triggering encryption, the attacker quietly exfiltrates a copy of sensitive data first. Now, even a victim with perfect backups faces a second threat that backups don't solve at all: the threat of the stolen data being published publicly or sold if the ransom isn't paid.\n\n` +
        `**Why the moments before encryption matter more than the moment of encryption itself**\n\n` +
        `By the time files are visibly encrypted, the attack has already succeeded. Recovery from that point means restoring from backup (if it exists and wasn't also touched) or living with the loss. The genuinely actionable window is earlier, in the preparation steps almost every ransomware operation performs before triggering the encryption routine, because those steps produce detectable telemetry while there's still something to prevent. Three of the most common: shadow copy deletion (using a tool like vssadmin.exe to remove Windows' built-in local backup snapshots, so the simplest recovery path is gone before encryption even starts), security log clearing (Event ID 1102, covering tracks), and a sudden burst of mass file access across many shares by one account in a short window (the encryption routine's precursor, reading through what it's about to lock). None of these three things, individually, always means ransomware, but together, in sequence, on a system that doesn't normally show this behavior, they are the last honest warning before the damage becomes irreversible.\n\n` +
        `**How this connects to wipers, next reading**\n\n` +
        `Everything up through encryption looks the same whether the attacker actually intends to restore the data for payment, or never intended to restore it at all. The diagram below shows the shared pre-encryption sequence and marks exactly where those two outcomes diverge, which is exactly what Reading 6 covers next.`,
      diagram:
        "flowchart TD\n" +
        "  A[Initial Access] --> B[Discovery and Credential Access]\n" +
        "  B --> C[Data Exfiltration -- double extortion copy]\n" +
        "  C --> D[Shadow Copy Deletion -- vssadmin]\n" +
        "  D --> E[Security Log Clearing -- Event 1102]\n" +
        "  E --> F[Mass File Access -- read+write burst across shares]\n" +
        "  F --> G{Encryption routine runs}\n" +
        "  G -->|Real key exists, decryptor sold for payment| H[Ransomware: files encrypted, ransom note dropped]\n" +
        "  G -->|No key, no intent to ever decrypt| I[Wiper: files destroyed, ransom note is a lie]\n" +
        // The title needs an explicit id + quoted label: a bare `subgraph`
        // title containing `--` is read as edge syntax and fails to parse, which
        // silently cost this room its diagram.
        "  subgraph AW[\"Actionable window - before encryption\"]\n" +
        "  D\n" +
        "  E\n" +
        "  F\n" +
        "  end",
      diagramCaption: "Pre-encryption indicators are the actionable window, and where ransomware and wipers diverge",
    },
    {
      type: "question",
      id: "malware-q3",
      question:
        "A file server shows vssadmin.exe deleting shadow copies, the Security log being cleared (Event ID 1102), and one service account reading thousands of files across multiple shares within ten minutes. No files have been encrypted yet. What should an analyst do?",
      options: [
        "Wait for the first encrypted files before escalating. Pre-encryption indicators alone do not justify an incident",
        "Escalate as an active pre-encryption ransomware sequence: the three signals together warrant containment before encryption begins",
        "Close it as backup-job activity: backup tools routinely delete shadow copies, so this is routine cleanup",
        "Escalate the log clearing by itself: shadow copy deletion and bulk file reads are separate admin tasks to review later",
      ],
      answer: 1,
      explanation:
        "This is the exact combination from Reading 5: none of these three signals alone is proof, but together (deletion of the local recovery path, evidence of tracks being covered, and a scan-like burst of file access) they are the pre-encryption sequence, and this is the last window where action can prevent, not just respond to, encryption. VSS-based backup tools do create and delete shadow copies, but they do not clear the Security log or mass-read shares under one account: the combination, plus a deletion run from an unexpected parent, is what matters. Treating log-clearing as the only relevant signal ignores that all three together are what make this pattern recognizable.",
      xp: 25,
    },
    {
      type: "reading",
      id: "malware-r6",
      heading: "Wiper vs Ransomware, and Cryptominers: 'Just Resource Theft' Is a Mistake",
      content:
        `**Wiper: looks like ransomware, isn't**\n\n` +
        `A wiper follows the exact same pre-encryption sequence as ransomware (shadow copy deletion, log clearing, mass file access, then a destructive routine) and very often even drops something that looks like a ransom note. The difference is entirely in intent: a wiper has no working decryption key, and its operator has no intention of ever restoring the data, even if a victim pays. Sometimes the "ransom note" is genuine misdirection meant to make investigators waste time treating a destructive, often geopolitically-motivated attack as an ordinary financially-motivated ransomware case; sometimes encryption is never even really the mechanism, and files or disk structures are simply corrupted or overwritten outright. Recognizing which one you're dealing with changes the entire response: with ransomware, negotiating, verifying decryptor functionality, and preserving encrypted data for possible future recovery are all live options; with a wiper, none of those options exist, and the response has to assume total data loss on affected systems from the start, shifting all effort toward containment and restoration from offline backup rather than any hope of a working key.\n\n` +
        `**Cryptominer: wants CPU, not data**\n\n` +
        `A cryptominer's objective is entirely different from everything else in this room: it doesn't want your data at all, it wants your compute. Once installed, it runs cryptocurrency-mining software continuously in the background, consuming CPU or GPU cycles (and the electricity and cooling that come with them) to generate value for the attacker, usually with no data ever touched, stolen, or destroyed.\n\n` +
        `**Why "just" resource theft is the wrong way to think about it**\n\n` +
        `It's tempting to treat a cryptominer detection as low priority. Degraded performance and a higher power bill feel minor compared to ransomware or data theft. That instinct misses the actual point: the access that successfully delivered a cryptominer to a machine is the exact same access that could have delivered ransomware, a RAT, or an infostealer instead. A cryptominer often shows up because it's the payload an opportunistic, low-effort attacker happened to choose, or because it's what an access broker sells to first while deciding what to do with the foothold next, but the vulnerability, weak credential, or misconfiguration that let it in is unchanged by which payload happened to arrive. Investigating a cryptominer detection as thoroughly as any other malware finding (how did it get here, what else could that same path have delivered, is that path still open) is the difference between closing a minor nuisance ticket and catching the fact that the same open door is still available for something far worse.`,
      codeExample:
        "WIPER vs RANSOMWARE -- SAME SEQUENCE, DIFFERENT INTENT\n" +
        "=======================================================\n" +
        "                    Ransomware              Wiper\n" +
        "-------------------------------------------------------\n" +
        "Pre-encryption steps   Shadow copy deletion,   Same steps\n" +
        "                       log clearing, mass       often identical\n" +
        "                       file access\n" +
        "Decryption key          Real, sold for payment   None -- does not exist\n" +
        "Ransom note              Genuine payment demand   Often present but a lie\n" +
        "Recovery options         Pay, negotiate, restore   Offline backup only --\n" +
        "                         from clean backup          assume total loss\n" +
        "=======================================================",
      checkpoint: {
        question: "What is the fundamental difference between a wiper and ransomware, given they often follow the same pre-encryption sequence?",
        options: [
          "A wiper leaves no ransom note, so finding a note tells you it is ransomware",
          "A wiper has no working key and no intent to restore; ransomware sells a real key",
          "A wiper skips shadow-copy deletion, since it has no recovery path to protect",
          "A wiper deletes files while ransomware encrypts them, so encryption rules out a wiper",
        ],
        answer: 1,
        explanation:
          "The sequence can look identical, but intent is the difference: ransomware has a genuine, sellable decryption key, while a wiper has none at all. Wipers often drop a fake ransom note purely to mislead investigators, so a note proves nothing. They run the same pre-encryption steps, shadow-copy deletion included. And some wipers do encrypt (with no key to undo it) so seeing encryption does not rule a wiper out.",
      },
    },
    {
      type: "matching",
      id: "malware-m1",
      heading: "Match Each Malware Type to Its Defining Trait",
      instructions: "Match each malware type to the trait that most reliably identifies it.",
      pairs: [
        { id: "worm", left: "Worm", right: "Spreads across a network by itself, machine to machine, with no user interaction needed after the first infection" },
        { id: "trojan", left: "Trojan", right: "Disguises itself as something the user wants, and relies entirely on the user choosing to launch it" },
        { id: "dropper", left: "Dropper", right: "Carries its full malicious payload embedded inside itself: no stage-2 download to intercept, though the payload may still beacon later" },
        { id: "loader", left: "Loader", right: "Fetches its real payload from the network shortly after execution, giving defenders a blockable destination and a window to act" },
        { id: "rat", left: "RAT / Backdoor", right: "Maintains a live command-and-control channel, giving an attacker interactive, hands-on-keyboard control of the machine" },
        { id: "infostealer", left: "Infostealer", right: "Harvests credentials, cookies, and wallet files fast and exits: the damage is already done by the time it's detected" },
        { id: "ransomware", left: "Ransomware (double extortion)", right: "Exfiltrates data quietly first, then encrypts it, so backups alone no longer remove the attacker's leverage" },
        { id: "wiper", left: "Wiper", right: "Follows the same pre-encryption steps as ransomware, but has no working key and never intends to restore anything" },
      ],
      explanation:
        "Each trait is the one detail that most reliably tells this type apart from its closest look-alike: worm vs trojan is about who does the spreading; dropper vs loader is about whether the payload arrives over the network at all; RAT vs infostealer is about ongoing interactive control versus a fast one-time grab; and ransomware vs wiper is about whether a real key and genuine intent to restore ever existed behind an identical-looking pre-encryption sequence.",
      xp: 40,
    },
    {
      type: "reading",
      id: "malware-r7",
      heading: "Hiding From the SOC, and When Not to Bother Escalating At All",
      content:
        `**Rootkit / bootkit: persistence below the operating system**\n\n` +
        `Most malware runs as an ordinary process that endpoint tools can see, hash, and terminate. A rootkit is built to defeat exactly that visibility by embedding itself at a privileged layer of the operating system, sometimes inside the kernel itself, sometimes (as a bootkit) in the boot process, before the operating system and its security tooling have even finished loading. From that position, a rootkit can hide its own files, processes, and network connections from the very tools that would normally detect them, because it can intercept and falsify the answers those tools receive when they ask "what's running right now?" This is why rootkit persistence "defeats normal endpoint visibility": the compromise isn't hiding well within the system the EDR agent sees. It's operating from underneath the layer the EDR agent trusts to tell it the truth, so a standard process listing or file scan can come back clean while the rootkit is very much still there.\n\n` +
        `**Fileless / living-off-the-land: nothing on disk to hash or quarantine**\n\n` +
        `A fileless attack achieves its objective (reconnaissance, credential theft, lateral movement, whatever the goal is) using tools already present on the system (PowerShell, WMI, legitimate administrative utilities, a technique called "living off the land") rather than dropping a new, attacker-authored executable onto disk at all. This directly defeats the core assumption behind traditional antivirus signature matching: a signature scanner is built to compare files against a database of known-bad hashes, but there is often no new file here to hash in the first place, just an unusually-used legitimate tool. The behavior is the malware: what matters isn't what file ran, it's what a completely legitimate tool was made to do (an unusual parent-child process relationship, an encoded PowerShell command line reaching out to an external address, a legitimate admin tool touching files it has no ordinary business touching). This is exactly why modern endpoint tools shifted from pure signature matching toward behavioral detection, watching what happens, not just what's on disk.\n\n` +
        `**PUP / adware: the triage judgement call**\n\n` +
        `A Potentially Unwanted Program (PUP) (commonly bundled toolbars, ad injectors, and "optimizer" utilities) sits in a genuinely different category from everything else in this room: it's often unwanted and mildly invasive rather than malicious in intent. Security products flag PUPs with heuristic detections that can look every bit as alarming in a console as a trojan alert, but the correct analyst instinct is judgement, not automatic escalation: check how it arrived (bundled with software the user or organization deliberately and knowingly installed, versus a drive-by install from an untrusted site) and whether it's doing anything beyond its stated, if annoying, function. A PUP that arrived through an approved, catalog-listed software deployment is a very different finding from the same detection name showing up on a machine with no such explanation.\n\n` +
        `Keep two closing labels apart when you record that finding. A false positive means the detection misfired and the thing it claims is not there. A benign true positive means the detection correctly found something real that turned out to be authorized, and you close it by citing the approval.\n\n` +
        `**Why one sample gets three different names**\n\n` +
        `Antivirus vendors each build their own detection engines, naming conventions, and family-classification logic independently, so it's completely normal for the exact same malware sample to be labeled "Trojan.GenericKD.12345" by one vendor, "Backdoor:Win32/Something.A" by a second, and "Malware.Heuristic.9001" by a third, even when scanned at the exact same moment. A vendor's family label is a hint about behavior and lineage worth taking seriously, but it is not ground truth, and it should never be the only thing an analyst relies on to understand what a sample actually does. Confirm behavior from telemetry (what did it actually connect to, read, or modify) rather than trusting a name alone to tell the whole story.`,
      checkpoint: {
        question: "Why can a rootkit hide its own files and processes from an EDR agent even during a routine scan?",
        options: [
          "It uses names that look like real Windows processes, so analysts overlook it",
          "It runs in the kernel or boot chain and falsifies what security tools are told",
          "It encrypts its own files, so the EDR agent cannot read them during a scan",
          "It deletes itself before each scan and reinstalls itself once the scan ends",
        ],
        answer: 1,
        explanation:
          "A rootkit runs in the kernel or the boot chain, below where ordinary user-mode tools look -- it isn't hiding within the system the agent sees, it's controlling what the agent is told, which is why a clean scan doesn't rule it out. A look-alike process name is masquerading: it fools a person reading a list, but the process still appears in it. An encrypted file is still visible as a file. And the rootkit does not need to leave and return around a scan, because it can answer the scan's questions falsely.",
      },
    },
    {
      type: "question",
      id: "malware-q4",
      question:
        "An analyst argues that a suspected fileless attack 'can't be malware: the antivirus scan came back completely clean, and no new file was ever created on disk.' What is wrong with that reasoning?",
      options: [
        "It is correct, with a clean AV scan and no new file, no detection method remains, since all SOC detection depends on a file to scan",
        "A clean signature scan proves little: fileless attacks abuse present tools like PowerShell and WMI, so behavior is the detection surface",
        "The scan result is only unreliable if it was not a full scan: a full on-demand scan would catch the payload, so rerun it with updated signatures",
        "A clean scan means the AV agent is unhealthy, so check its signature date before going any further",
      ],
      answer: 1,
      explanation:
        "This is Reading 7's core point about fileless/living-off-the-land techniques: they're specifically effective because they route around signature-based detection by never introducing a new file to scan in the first place, so 'nothing new on disk, clean scan' is the expected signature of a fileless attack, not proof one didn't happen. Fileless techniques are widely and actively used in real intrusions, and a clean AV scan doesn't indicate the product is malfunctioning. It indicates the product was checking the wrong thing for this technique.",
      xp: 20,
    },
    {
      type: "analyst_choice",
      id: "malware-ac2",
      heading: "Verdict: A PUA Toolbar Detection on WKS-MKT22",
      scenario:
        "Defender flagged a browser toolbar component that installed alongside a PDF editor on a Marketing workstation. Review the detection, including the installer's path and account, and the IT verification note below, then decide whether this deserves incident-level escalation.",
      event: pupEvent,
      correct_verdict: "benign_true_positive",
      explanation:
        "Defender's PUA (Potentially Unwanted Application) category exists precisely for borderline software like bundled toolbars: it's a heuristic warning about unwantedness, not a malware verdict. The installer ran from the Configuration Manager cache (C:\\Windows\\ccmcache) under the SYSTEM account, how a managed rollout looks, and the IT ticket (SD-30217) confirms this toolbar arrived through the organization's own approved deployment, not a drive-by install from an untrusted site. Per Reading 7, correct PUP triage means checking distribution channel and authorization before escalating, not treating every PUA detection identically to a trojan alert. That makes this a benign true positive: Defender correctly identified a real bundled toolbar, exactly what its PUA category targets, and the approved rollout under ticket SD-30217 is the justification you cite when closing it. It is not a false positive, because the detection did not misfire, and that label would invite weakening PUA detection that should keep catching uninvited bundles.",
      fp_trap:
        "The word 'PUA' next to a detection that lights up red in the console primes an analyst to treat it exactly like a backdoor or trojan finding, but the category was built specifically to flag software that is unwanted, not software that is malicious. Escalating a confirmed, catalog-approved bundled toolbar as a full incident wastes response capacity that a genuinely uninvited PUP install (arriving via a random ad-laden download site, with no IT ticket behind it at all) would actually deserve.",
      xp: 30,
    },
  ],
};

// =============================================================================
// ROOM 2: asset-context-prioritisation
// =============================================================================

const dcSprayEvent: TelemetryEvent = {
  id: "evt-asset-la1-001",
  ts: "2026-05-20T02:07:15.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "high",
  hostname: "DC02.meridian.local",
  description:
    "DC02 recorded a failed logon for account svc_helpdesk from source IP 10.10.44.187; this is one of a run of failed logon attempts against 14 distinct accounts from the same source IP within a two-minute window, each targeting this domain controller directly over the network rather than a downstream application server.",
  raw: {
    "event.code": "4625",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC02.meridian.local",
    "winlog.event_data.TargetUserName": "svc_helpdesk",
    "winlog.event_data.TargetDomainName": "MERIDIAN",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.WorkstationName": "DESKTOP-4LK92P",
    "winlog.event_data.IpAddress": "10.10.44.187",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4625,
  },
};

const sandboxSprayEvent: TelemetryEvent = {
  id: "evt-asset-ac1-001",
  ts: "2026-05-21T03:00:11.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "high",
  hostname: "SANDBOX-DET04.meridian.local",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-91004 confirms SANDBOX-DET04 is a malware-detonation VM on its own isolated VLAN with no route to the corporate domain; its nightly detonation script intentionally submits a list of known-bad test credentials to observe how each sample reacts to failed authentication.",
  description:
    "SANDBOX-DET04 recorded a failed logon for account test_operator from local source 172.31.9.5; this is one of a run of failed logon attempts against 9 local test accounts from the same source within a three-minute window, all on a host with no connectivity to the production domain.",
  raw: {
    "event.code": "4625",
    "winlog.channel": "Security",
    "winlog.computer_name": "SANDBOX-DET04.meridian.local",
    "winlog.event_data.TargetUserName": "test_operator",
    "winlog.event_data.TargetDomainName": "SANDBOX-DET04",
    "winlog.event_data.LogonType": "10",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.WorkstationName": "SANDBOX-DET04",
    "winlog.event_data.IpAddress": "172.31.9.5",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4625,
  },
};

const assetContextRoom: Room = {
  id: "asset-context-prioritisation",
  title: "Asset Context: Why the Same Alert Is Not the Same Alert",
  description:
    "Prioritisation is the daily job of a SOC analyst, and it depends on something most training skips: what the affected asset actually is. Failed logons on a disposable test VM, a finance workstation, and a domain controller can be the exact same log line, and three completely different incidents. This room teaches asset criticality, blast radius, exposure, and business context, then has you rank concurrent alerts where the correct order isn't the order the products assigned.",
  difficulty: "intermediate",
  category: "SOC Operations",
  estimatedMinutes: 50,
  xp: 275,
  icon: "🎯",
  prerequisites: ["soc-structure", "alert-triage"],
  tasks: [
    {
      type: "reading",
      id: "asset-r1",
      heading: "The Same Alert, Three Assets",
      content:
        `Imagine the exact same alarm going off in three different buildings: a garden shed, your family home, and a bank vault. The alarm itself (the sound, the sensor that triggered it) is identical every time. Nobody would respond to it identically, though, because the alarm never told you what's behind the door; the building did. SOC alerts work exactly the same way, and it's the single most important idea in this room.\n\n` +
        `**One log line, three responses**\n\n` +
        `Picture a detection rule that fires on "12 failed logons in 3 minutes from the same source." It fires, on the same afternoon, in three places: an isolated lab VM used for occasional software testing, with no production data and no connection to the corporate domain; a finance analyst's everyday workstation on the production network; and a domain controller, a server that authenticates every user in the company. The alert text is identical all three times. The correct response is not. On the lab VM, this is worth a glance and a log entry. There's essentially nothing behind that door to protect. On the finance workstation, this deserves a real look: check for account lockout, consider contacting the user, watch for a follow-up success. On the domain controller, this is an immediate escalation, because a domain controller isn't "a computer that happened to receive some failed logons". It's the identity infrastructure that every other system in the company implicitly trusts.\n\n` +
        `**Why this has to be taught explicitly**\n\n` +
        `Most alert-handling training focuses entirely on the alert itself: what triggered it, what the fields mean, what technique it maps to. That's necessary, but it's only half the picture, and treating it as the whole picture is exactly what produces analysts who escalate a lab VM as urgently as a domain controller, or, just as dangerous, who get so used to seeing "failed logon burst" as routine noise that they miss the one time it lands somewhere that actually matters. The rest of this room is about the other half: how to look at the asset behind the alert and let that shape the response, not just the alert's own severity field.`,
      diagram:
        "flowchart TD\n" +
        "  A[Alert: 12 failed logons in 3 minutes] --> B[Asset: isolated lab VM, no prod data]\n" +
        "  A --> C[Asset: finance workstation, production network]\n" +
        "  A --> D[Asset: domain controller]\n" +
        "  B --> B1[Log for context -- no urgent action]\n" +
        "  C --> C1[Check for lockout, contact user, monitor for a follow-up success]\n" +
        "  D --> D1[Escalate immediately -- identity infrastructure for the whole domain]",
      diagramCaption: "Same alert text, three different assets, three different responses",
      checkpoint: {
        question: "Per Reading 1, one detection rule fires three times with identical alert text. What should set the response to each firing?",
        options: [
          "The alert's severity field, because the product has already scored how bad each firing is",
          "The asset each firing landed on, because the alert never says what is behind the door",
          "The technique the rule maps to, because that decides which response procedure applies",
          "The order they arrived in, because the queue is worked from the oldest alert down",
        ],
        answer: 1,
        explanation:
          "The alert text and even the technical severity can be identical across three assets, yet the correct response differs completely, because what's 'behind the door', the asset itself, is what actually determines the risk. The severity field and the mapped technique describe the alert, which Reading 1 calls only half the picture, and arrival order says nothing about what is at risk.",
      },
    },
    {
      type: "reading",
      id: "asset-r2",
      heading: "What Makes an Asset Critical",
      content:
        `"Criticality" sounds like a vague, subjective label, but it breaks down into a small number of concrete questions you can actually ask about any asset. Think of it like the difference between losing a random door key and losing a master key that opens every room in the building: the key itself might look identical, but what it can open is what actually determines how much you care about losing it.\n\n` +
        `**What it holds**\n\n` +
        `Data classification is the first question: does this asset store or process anything sensitive (customer PII, meaning personally identifiable information, payment data, source code, health records, legal documents), or is it functionally empty of anything an attacker would want to steal? A server holding nothing but public marketing images has a very different "what it holds" answer than one holding the customer database.\n\n` +
        `**What it controls**\n\n` +
        `This is often the more important question, and the one beginners underweight: some assets aren't valuable because of what they store, but because of what they can reach or command. A domain controller doesn't necessarily hold your most sensitive files, but it controls every identity in the domain: every account, every group membership, every trust relationship. A hypervisor doesn't hold data of its own; it controls every virtual machine running on top of it. A backup server may hold nothing anyone would want to steal for its own sake, but it controls your ability to recover at all after an incident, which becomes existential the moment ransomware is involved.\n\n` +
        `**Who uses it**\n\n` +
        `The same laptop model, running the same software, means something different depending on whose hands it's in. A workstation used by a domain administrator or an executive with broad approval authority carries risk that an identical machine used by a receptionist for a single-purpose kiosk app simply doesn't, because of what the logged-in account's own privileges can do once an attacker rides along with them. A service account with broad database access is "who uses it" in the same sense: the account itself carries the criticality, not just the human behind the keyboard.\n\n` +
        `**Whether it's internet-facing**\n\n` +
        `An asset reachable from anywhere on the internet has a fundamentally larger population of potential attackers than one that's only reachable from inside a controlled internal network. This dimension gets its own full reading next, because it interacts with everything else here rather than standing alone.\n\n` +
        `Put these four questions together (what it holds, what it controls, who uses it, and whether it's exposed) and "criticality" stops being a gut feeling and becomes something you can actually justify in a triage note.`,
      codeExample:
        "FOUR QUESTIONS TO ASK ABOUT ANY ASSET\n" +
        "=======================================================\n" +
        "What does it HOLD?      -- sensitive data, or nothing valuable?\n" +
        "What does it CONTROL?    -- identities, other machines, recovery\n" +
        "                            capability, deployment pipelines?\n" +
        "WHO uses it?             -- admin/exec/service account, or a\n" +
        "                            low-privilege single-purpose login?\n" +
        "Is it INTERNET-FACING?   -- reachable by anyone, or only from\n" +
        "                            inside a controlled network?\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "asset-q1",
      question:
        "Two identical malware detections fire at the same moment, with the exact same product-assigned severity: one on a receptionist's kiosk PC that can only ever access the visitor sign-in application, and one on a backup server that holds the only offline copies of the company's file shares. Which deserves the faster response, and why?",
      options: [
        "The kiosk PC: it is publicly accessible to anyone in the lobby, and physical exposure outweighs the device's operational role",
        "The backup server: it is the recovery capability, and losing it turns every other incident from recoverable to potentially unrecoverable",
        "Neither: the identical product score already reflects asset context, so the response should be identical",
        "The kiosk PC: kiosks usually run outdated, unpatched software, so they are riskier than any purpose-built server",
      ],
      answer: 1,
      explanation:
        "This is the 'what it controls' question from Reading 2: a backup server's importance isn't about what data lives on it day to day, it's about the recovery capability the whole organization depends on it for, compromising it can turn every future incident into an unrecoverable one. Physical accessibility in a lobby doesn't outweigh that, identical product severity scores are exactly what asset context is meant to override, and kiosk devices aren't automatically higher risk just by being public-facing hardware.",
      xp: 20,
    },
    {
      type: "reading",
      id: "asset-r3",
      heading: "Blast Radius: What Else Does the Attacker Reach From Here?",
      content:
        `Blast radius answers one specific question: if this asset were fully compromised right now, what else does the attacker gain access to as a direct consequence? It's the difference between an incident that stays contained to one machine and one that cascades into dozens or thousands.\n\n` +
        `**The assets whose blast radius is almost always largest**\n\n` +
        `A domain controller's blast radius is the whole domain: full control of the KDC (Kerberos Key Distribution Center) that issues every authentication ticket means an attacker can potentially impersonate any user, including domain admins, across every system that trusts that domain. A hypervisor's blast radius is every virtual machine it hosts, and this one deserves special attention because it's a force multiplier: the hypervisor sits below each guest VM's own operating system and its own security tooling entirely, so a compromise at that layer can affect every VM on it simultaneously, regardless of how well-defended any individual guest happens to be. Backup infrastructure's blast radius is the organization's ability to recover at all, as Reading 2 introduced, this becomes the difference between "we restore from backup by tomorrow" and "we have no backup left to restore from" the moment ransomware is in play. A jump host or bastion (the single trusted hop administrators use to reach otherwise-segmented networks) has a blast radius equal to everything that segmentation was supposed to protect, because compromising the trusted hop bypasses the segmentation entirely. A CI/CD (continuous integration / continuous deployment) pipeline server's blast radius extends to every system that trusts and deploys its build output: a compromise there can become a supply-chain-scale problem, shipping malicious code into production systems that never had a security incident of their own.\n\n` +
        `**Why this changes response, not just labeling**\n\n` +
        `Recognizing a large blast radius doesn't just mean writing "high priority" in a ticket. It changes what you actually do. An incident on an asset with a large blast radius justifies broader containment thinking from the very first minutes: are there signs the attacker already moved beyond this one asset, does the incident response plan need to consider resetting credentials domain-wide rather than just on this host, does recovery capability itself need to be verified as intact before anything else. Asking "what does this asset let the attacker reach next" as one of your very first triage questions is what turns blast radius from an abstract concept into something that actually shapes your first hour of response.`,
      diagram:
        "flowchart LR\n" +
        "  DC[Domain Controller compromised] --> DC1[Every identity in the domain]\n" +
        "  HV[Hypervisor compromised] --> HV1[Every VM it hosts, simultaneously]\n" +
        "  BK[Backup infrastructure compromised] --> BK1[Ability to recover from ransomware -- gone]\n" +
        "  JH[Jump host / bastion compromised] --> JH1[Direct path into every segmented network it bridges]\n" +
        "  CI[CI/CD pipeline compromised] --> CI1[Every system that trusts its build output]",
      diagramCaption: "Blast radius: what a compromise of THIS asset hands the attacker next",
      checkpoint: {
        question: "According to Reading 3, why does a domain controller have such a large blast radius?",
        options: [
          "Because it stores the most sensitive customer data of any system in the company, holding the master copy of every record that any other application server only ever queries a subset of",
          "Because it controls the KDC (Kerberos Key Distribution Center), which issues every authentication ticket, so a compromise can let an attacker impersonate any user across every system trusting that domain",
          "Because it is always internet-facing, unlike other servers, which puts it within reach of a fundamentally larger population of potential attackers than any internally-segmented system",
          "Because it has the highest CVSS-scored vulnerabilities of any asset type, meaning its blast radius is a direct function of how severe its unpatched software flaws happen to be",
        ],
        answer: 1,
        explanation:
          "A domain controller's blast radius comes from what it controls, not necessarily what it stores -- full control of the KDC means an attacker can potentially impersonate any user, including domain admins, across every trusting system.",
      },
    },
    {
      type: "question",
      id: "asset-q2",
      question:
        "An attacker gains full control of a hypervisor hosting 40 virtual machines, including three domain controllers and the ticketing system's database server. Why does compromising the hypervisor represent a larger blast radius than compromising any single one of those 40 VMs individually?",
      options: [
        "It keeps its own master copy of the data inside all 40 VMs, which makes it the richest single store to steal from",
        "It sits beneath every guest OS and its security tooling, so one compromise can reach all 40 VMs at once",
        "It issues the authentication tickets all 40 VMs trust, so an attacker can impersonate any user on any of them",
        "It is the build source all 40 VMs trust, so a compromise can ship malicious code into every one of them",
      ],
      answer: 1,
      explanation:
        "This is the force-multiplier point from Reading 3: the hypervisor's position underneath every guest VM's own security stack means one compromise there can reach all 40 VMs at once, bypassing whatever protections exist inside each individual guest. The other reasons belong to other assets: Reading 2 says a hypervisor holds no data of its own, it is a domain controller's KDC that issues authentication tickets, and shipping code into everything that trusts its builds is a CI/CD pipeline server's reach.",
      xp: 20,
    },
    {
      type: "matching",
      id: "asset-m1",
      heading: "Match Each Asset Type to Why Its Blast Radius Is Large (or Small)",
      instructions: "Match each asset type to the reasoning that explains its blast radius.",
      pairs: [
        { id: "dc", left: "Domain Controller", right: "Controls authentication for every identity in the domain; a compromise here can be leveraged against anything that trusts domain logons" },
        { id: "hv", left: "Hypervisor", right: "Sits below every guest VM's own security controls, so a compromise can affect every VM it hosts at once: a force multiplier, not one host among many" },
        { id: "bk", left: "Backup infrastructure", right: "Holds the organization's ability to recover after an incident; compromising it can remove the safety net a ransomware response depends on" },
        { id: "ci", left: "CI/CD pipeline server", right: "Can push code into every system that trusts its build output, giving an attacker a path into production far beyond the pipeline server itself" },
        { id: "jh", left: "Jump host / bastion", right: "Is the trusted hop used to reach segmented networks, so compromising it can bypass the segmentation it was meant to protect" },
        { id: "lab", left: "Isolated lab VM with no production connectivity", right: "Has almost nowhere to go from a compromise, since it holds no sensitive data and has no trust relationship with production systems" },
      ],
      explanation:
        "Blast radius is always about what a full compromise of THIS asset hands the attacker next: identity infrastructure, every guest VM, recovery capability, deployment trust, or a bypass of segmentation, versus, at the low end, nothing beyond itself. Criticality isn't only about what an asset holds; very often it's almost entirely about what it controls or bridges.",
      xp: 40,
    },
    {
      type: "log_analysis",
      id: "asset-la1",
      heading: "A Failed Logon Burst: Against a Domain Controller",
      context:
        "A detection rule fired on DC02 for a burst of failed logon attempts. Review the representative event below, which includes the full pattern described by the SIEM's correlation summary.",
      event: dcSprayEvent,
      questions: [
        {
          question:
            "This burst is targeting DC02, a domain controller, directly over the network, attempting 14 different accounts in two minutes. Why does the target being a domain controller change the priority of this alert compared to the exact same signature landing on a single ordinary application server?",
          options: [
            "The rule scores a domain controller higher, so the severity field alone moves this alert up the queue",
            "It is the identity authority: a password guessed here is valid across the whole domain that trusts it",
            "It stores the company's most sensitive files, so the burst is an attempt to reach that data directly",
            "It faces the open internet, so exposure rather than what it controls is what raises the priority",
          ],
          answer: 1,
          explanation:
            "This is blast radius applied directly: a domain controller's compromise, or even one successfully guessed credential from a spray against it, has consequences reaching the whole domain, unlike an ordinary application server. The product's severity field cannot measure that, which is why the analyst adds it. Reading 2 says a domain controller does not necessarily hold your most sensitive files: what matters is what it controls. Exposure is not the reason either, because the source, 10.10.44.187, is an internal address.",
          xp: 25,
        },
        {
          question:
            "If this identical 14-account, two-minute failed-logon burst had instead landed on the isolated lab VM from Reading 1, how should the response differ?",
          options: [
            "It should not: 14 accounts in two minutes is a spray, so escalate at once as you would for DC02",
            "Priority drops: a glance and a log entry fit, since a compromise there has almost nowhere to go",
            "Handle it as the finance workstation: check for lockout, contact the user, watch for a success",
            "Close it with no record: lab VM alerts are test noise, so they need no entry in the queue or log",
          ],
          answer: 1,
          explanation:
            "This is Reading 1's exact idea in practice: identical alert text, different asset, different correct response. A compromise of an isolated, low-value VM doesn't reach anything further, so the same signature that demands immediate escalation on a domain controller is worth a glance and a log entry on a genuinely isolated lab box. The workstation steps belong to a production machine with a real user behind it, and closing with no record skips the log entry Reading 1 still asks for.",
          xp: 25,
        },
        {
          question:
            "What is the correct immediate response to the DC02 burst as described?",
          options: [
            "Block 10.10.44.187 at the edge firewall, reset the 14 passwords, and close the case once that is done",
            "Contain the source host, check the 14 accounts for a later successful logon (Event 4624), and escalate",
            "Disable all 14 accounts at once, since any account named in the burst counts as already compromised",
            "Log it and watch for a follow-up success, since a failed logon changes nothing until one attempt works",
          ],
          answer: 1,
          explanation:
            "This combines containment (the source is an internal workstation, so an edge block would do nothing; isolate it and investigate it) with the most important follow-up check (did any attempt actually succeed) and reflects the escalation this asset's blast radius demands. Disabling 14 accounts without investigation risks disrupting legitimate service accounts among them. Logging and watching is the lab VM response: Reading 1 says this pattern on a domain controller is an immediate escalation.",
          xp: 30,
        },
      ],
    },
    {
      type: "flag",
      id: "asset-f1",
      prompt:
        "Look at Log Analysis 1, the failed-logon burst against DC02. Containment applies to the machine the attempts came from, not to the asset under attack. Enter that machine's name exactly as logged.",
      answer: "DESKTOP-4LK92P",
      hint: "The log names two machines: the one that recorded the failed logon and the one that sent the attempt.",
      xp: 25,
    },
    {
      type: "reading",
      id: "asset-r4",
      heading: "Exposure: Internet-Facing, Internal-Only, and Segmented",
      content:
        `Exposure answers a different question than blast radius: not "what can an attacker reach from here," but "how easily can an attacker reach here in the first place." Two assets can have identical vulnerabilities and identical criticality, and still carry very different real-world risk purely because of who can actually get to them.\n\n` +
        `**Three exposure levels**\n\n` +
        `Internet-facing means the asset is directly reachable from the open internet: anyone, anywhere, with no prior foothold required, can attempt to reach it. Internal-only means the asset is reachable only from inside the organization's own network, which already rules out the vast majority of opportunistic, internet-wide scanning and attack traffic. Segmented goes a step further: the asset sits behind additional network controls even from other internal systems: reachable only from a specific management network, only through a jump host, or only with an additional authentication step like VPN plus multi-factor authentication, so even another already-compromised internal machine may not be able to reach it directly.\n\n` +
        `**Why identical vulnerability scores can mean different real risk**\n\n` +
        `A CVSS (Common Vulnerability Scoring System) score measures theoretical severity (how bad the vulnerability is if an attacker can reach and exploit it) but it says nothing about how hard reaching it actually is in your specific environment. The exact same critical vulnerability on an internet-facing web server and on a segmented internal server reachable only via VPN, MFA, and a jump host represents very different real-world exploitability: the internet-facing case can be attempted by literally anyone scanning the internet right now with no other access needed at all, while the segmented case requires an attacker to already have breached several other layers of control first. Neither one is safe to ignore (the segmented system still needs to be patched) but they don't deserve the same urgency, and exposure is exactly the missing variable that a raw CVSS score can't tell you on its own.`,
    },
    {
      type: "question",
      id: "asset-q3",
      question:
        "The exact same critical vulnerability (CVSS 9.8) is found on two servers: one is a customer-facing web portal reachable from the open internet, the other is an internal reporting server reachable only from a management VLAN that requires VPN plus MFA, with no route from ordinary user workstations. Both have identical CVSS scores. Why might these still warrant different urgency?",
      options: [
        "They shouldn't: identical CVSS means identical urgency, since the score already accounts for each environment's topology and access controls",
        "Exposure differs: the portal needs no foothold, while the internal server first needs a VPN and MFA breach; CVSS rates severity, not reachability",
        "The internal 9.8 is probably a scoring error: CVSS is automatically lower for internal systems, so report it to the scanner team",
        "The internal server is more urgent: internal systems are more trusted and more damaging to lose, whatever controls stand in front of them",
      ],
      answer: 1,
      explanation:
        "This is exactly Reading 4's distinction: CVSS captures how bad exploitation would be, not how easy reaching the vulnerable system is. Exposure fills that gap, and the internet-facing system is reachable by a vastly larger, lower-effort population of attackers than the segmented one. CVSS scores aren't automatically adjusted downward for internal systems (that's exactly why exposure has to be considered separately), and 'internal is always more urgent' ignores that the internet-facing system here is dramatically easier for an attacker to actually reach.",
      xp: 20,
    },
    {
      type: "reading",
      id: "asset-r5",
      heading: "Business Context Beats Technical Severity",
      content:
        `Every security product ships an opinion about how bad a finding is, expressed as a severity label: Critical, High, Medium, Low. That label is calculated from technical factors the product can actually measure: exploit availability, CVSS score, detection confidence. What it can never measure is something only the organization itself knows: what's happening around that asset right now.\n\n` +
        `**A concrete example worth internalizing**\n\n` +
        `A MEDIUM-severity alert (say, an unusual configuration change) on the production payment-processing system, discovered during the first hour of a major product launch with elevated transaction volume and executive attention, may deserve to outrank a HIGH-severity alert on an isolated lab box that nobody depends on this week. Nothing about the technical severity scores has to be wrong for this to be true; the product correctly measured what it could measure. What it couldn't measure is that one of these systems is, for this specific week, load-bearing for the entire business, and the other genuinely isn't.\n\n` +
        `**Severity comes from the product; priority comes from the analyst**\n\n` +
        `This is the sentence worth remembering above almost everything else in this room: severity is a technical, product-calculated property of the finding itself, while priority is the analyst's own judgment about response order, built by folding business context on top of that technical severity. A good analyst doesn't override severity labels carelessly or ignore them. They use severity as one important input, then adjust the actual order they work things in based on what the product cannot know: what's launching this week, whose account this is, what would actually hurt the business most if it went wrong right now. Treating the product's severity field as the final word on priority is exactly the gap this whole room exists to close.`,
      checkpoint: {
        question: "Per Reading 5, what is the difference between severity and priority?",
        options: [
          "Severity is the analyst's judgment of business impact; priority is the score the product calculates",
          "Severity is the product's technical score; priority is the analyst's order, with business context added",
          "Severity is the product's score; priority is that same score after the SIEM adjusts it for asset tier",
          "Severity reflects how critical the asset is; priority reflects how long the alert has been waiting",
        ],
        answer: 1,
        explanation:
          "A product can only measure what it can technically observe; it cannot know what's launching this week or whose account this is. Priority is the analyst folding that business context on top of the product's severity label, not a score the SIEM adjusts and not a measure of how long an alert has waited.",
      },
    },
    {
      type: "analyst_choice",
      id: "asset-ac1",
      heading: "Verdict: A Failed-Logon Burst on an Isolated Detonation VM",
      scenario:
        "The same detection rule that fired on DC02 in Log Analysis 1 just fired again: this time on SANDBOX-DET04. Review the event and the attached change ticket before deciding whether this deserves the same response as the domain controller case.",
      event: sandboxSprayEvent,
      correct_verdict: "benign_true_positive",
      explanation:
        "The technical signature (a burst of failed logons against several accounts from one source in a short window) is shaped identically to the DC02 spray in Log Analysis 1, but asset context changes the verdict entirely: SANDBOX-DET04 is an isolated detonation VM with local-only test accounts and no route to the production domain, and the confirmed change ticket explains the burst as an automated nightly test script, not an attacker. Nothing this host holds or controls extends beyond itself, which is the core idea of this whole room. That makes this a benign true positive: the rule correctly detected a real burst of failed logons, and the change ticket for the automated nightly test script is the justification you cite when closing it. It is not a false positive, because nothing misfired, and that label would invite weakening the same spray rule that protects DC02.",
      fp_trap:
        "It's tempting to escalate this exactly like Log Analysis 1, because the log pattern (account count, time window, repeated failures) looks just as alarming on paper. But the asset behind SANDBOX-DET04 has effectively zero blast radius (no production data, no domain trust, an isolated VLAN) and a documented, authorized reason for the behavior, which the domain controller case had neither of. Matching alert shape without checking the asset behind it is exactly the mistake this room is built to prevent.",
      xp: 30,
    },
    {
      type: "reading",
      id: "asset-r6",
      heading: "The CMDB Problem, Honestly",
      content:
        `A CMDB (Configuration Management Database) is supposed to be the organization's authoritative inventory of what assets exist, what they run, who owns them, and how critical they are. In theory, an analyst could look up any hostname and immediately know exactly what they're dealing with. In practice, almost every real CMDB is incomplete, stale, or simply wrong in places, not through negligence, but because assets get spun up, renamed, repurposed, and decommissioned faster than the paperwork tracking them can keep up, especially in cloud and containerized environments where a server might exist for hours.\n\n` +
        `**The instinct this creates, and why it's backwards**\n\n` +
        `When an analyst pulls up an unfamiliar hostname and finds nothing in the CMDB, the tempting shortcut is to treat the lack of a record as a reason to deprioritize: "if it's not in the inventory, it's probably not important, or probably not even real. Skip it and move to something documented." That reasoning is exactly backwards. An unrecognized asset isn't automatically unimportant; it's an open question, and open questions in a SOC are findings, not something to wave past. An asset with no record could be a forgotten but perfectly legitimate test box, or it could be a rogue device someone plugged in without authorization, an unmanaged piece of shadow IT nobody signed off on, or exactly the kind of infrastructure an attacker would stand up for persistence, chosen specifically because it wouldn't show up anywhere an analyst would normally check.\n\n` +
        `**What to actually do with an unrecognized hostname**\n\n` +
        `Chase it rather than skip it: check DNS and DHCP lease records for when it first appeared and what requested that address, check the cloud console or virtualization platform if it's a VM, ask the network or infrastructure team directly rather than assuming the CMDB's silence is an answer, and treat "we genuinely don't know what this is" as a real, escalatable finding in its own right rather than a dead end. A stale or incomplete CMDB is a known, common limitation of real environments: the correct response to that limitation is more scrutiny of the unknown, not less.`,
      checkpoint: {
        question: "When an analyst finds a hostname with no CMDB record, what does Reading 6 say the correct instinct is?",
        options: [
          "Deprioritize it until a record appears, since assets that matter get entered by the team that built them",
          "Chase it through DNS, DHCP, the cloud console and the infrastructure team, as an open finding",
          "Escalate it as a confirmed incident straight away, since a missing record proves the host is unauthorized",
          "File a request to add it to the CMDB and move on, since missing records are a known paperwork gap",
        ],
        answer: 1,
        explanation:
          "A missing CMDB record is a known, common limitation, not evidence of unimportance and not proof of anything malicious. The correct response is more scrutiny of the unknown, since an unrecognized host could be a forgotten test box or exactly the kind of infrastructure an attacker would choose for that reason.",
      },
    },
    {
      type: "reading",
      id: "asset-r7",
      heading: "Practical Prioritisation: Combining Severity, Criticality, and Confidence",
      content:
        `Everything in this room comes together into one practical habit: when several alerts are competing for attention at once, priority order should come from combining three separate inputs, not from reading the severity field alone.\n\n` +
        `**The three inputs**\n\n` +
        `Alert severity is what the security product already calculated: how technically bad this specific finding looks, in isolation. Asset criticality is everything from Readings 2 through 4 combined: what the asset holds, what it controls, who uses it, its blast radius, and its exposure. Confidence is how sure you actually are that this alert represents real malicious activity rather than noise, tuning gaps, or an already-explained benign cause: the same judgment call you practiced on the detonation VM verdict, where the rule fired correctly on real activity that a change ticket made authorized. None of these three, alone, is a safe way to rank a queue of alerts; combined, they produce something closer to genuine priority.\n\n` +
        `**Where this visibly overrides the product's own severity field**\n\n` +
        `A MEDIUM-severity alert on a system with very high criticality (the payment system during launch, from Reading 5) and high confidence can and should outrank a HIGH-severity alert on a low-criticality asset, or a CRITICAL-severity alert where confidence is genuinely low because of an obvious, documented benign explanation. This isn't ignoring the product's severity score. It's refusing to let that one input be the whole decision.\n\n` +
        `**When two serious alerts compete**\n\n` +
        `Business context does not automatically win. When two alerts both touch something important, ask how far each asset reaches and whether the threat is confirmed and still live or only suspected. Live malware on a device whose account holds standing admin access to something like a deployment pipeline (the automated system that ships code to production) outranks an unconfirmed alert on a busy production system, because that one compromise reaches many systems rather than one. The same logic works at the bottom of the queue: an alert the product has already contained ranks below an unresolved alert on a similarly low-value asset, even if that asset is isolated, and a finding on a decommissioned system that nothing depends on goes last.\n\n` +
        `**Writing down why you deprioritized something**\n\n` +
        `The final habit this room asks you to build: whenever you consciously rank something lower than its raw severity label would suggest, write down why, briefly, in the ticket or triage note, which asset-context factor drove the decision, and what evidence supports it (an isolated VLAN, a confirmed change ticket, a documented low-value asset). This turns an invisible judgment call into a reviewable decision: a teammate, a shift handover, or an auditor looking at the same ticket later can see exactly why a CRITICAL-labeled alert sat lower in the queue than a MEDIUM one, instead of just seeing that it did.`,
      diagram:
        "flowchart TD\n" +
        "  A[Alert Severity -- from the product] --> D{Combine}\n" +
        "  B[Asset Criticality -- holds/controls/who/exposure] --> D\n" +
        "  C[Confidence -- how sure this is real] --> D\n" +
        "  D --> E[Analyst-assigned Priority]\n" +
        "  E --> F1[MEDIUM severity + payment system during launch = ranked above its label]\n" +
        "  E --> F2[HIGH severity + isolated, decommissioned lab box = ranked below its label]",
      diagramCaption: "Severity times criticality times confidence -- not severity alone",
    },
    {
      type: "ordering",
      id: "asset-o1",
      heading: "Rank These Five Concurrent Alerts",
      instructions:
        "Five alerts land in the queue at the same time. Rank them from highest to lowest priority using asset criticality, blast radius, exposure, business context, and whether the threat is confirmed and still live, not the severity label alone.",
      items: [
        { id: "exec-laptop", text: "HIGH severity malware, still running and not quarantined, on an executive's laptop that holds saved VPN credentials and standing admin access to the CI/CD pipeline" },
        { id: "payment-launch", text: "MEDIUM severity suspicious PowerShell execution, not yet confirmed as malicious, on the production payment-processing server, during the first hours of a live product launch" },
        { id: "guest-wifi", text: "CRITICAL severity (per the product) anomalous login on an isolated guest Wi-Fi captive-portal server with no route to any production system" },
        { id: "printer-quarantined", text: "HIGH severity malware automatically detected and quarantined by AV on a shared marketing team print server holding no sensitive data" },
        { id: "lab-scan", text: "LOW severity port scan against a decommissioned test server sitting in an isolated lab VLAN" },
      ],
      correct_order: ["exec-laptop", "payment-launch", "guest-wifi", "printer-quarantined", "lab-scan"],
      explanation:
        "Raw severity labels alone would put the guest Wi-Fi CRITICAL alert first and the payment-server MEDIUM alert near the bottom: exactly backwards. The executive's laptop ranks first because the malware is live and the blast radius is huge: standing CI/CD admin access and saved VPN credentials mean this compromise reaches far beyond the laptop itself. The payment server ranks second on business context: an unconfirmed MEDIUM alert during a live launch, on a system that directly touches revenue and payment data, outranks alerts on lower-value assets regardless of the product's label, but it does not outrank a live compromise with wider reach. The guest Wi-Fi alert, despite its CRITICAL label, drops to third once exposure and blast radius are considered. Isolated, with no path to anything that matters, it still needs review but not urgent action. The quarantined printer detection is already contained and touches no sensitive data, so it ranks below the unresolved guest Wi-Fi alert. The decommissioned lab box ranks last: lowest technical severity, isolated, no production role, exactly the shape of a finding to log and move past, not chase first.",
      xp: 40,
    },
  ],
};

export const roomsBatch22 = [malwareTypesRoom, assetContextRoom];
