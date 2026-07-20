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
    "quarterly_invoice.exe, opened by t.osei nine minutes after it arrived as an email attachment, established an outbound TCP connection to cdn-assets-delivery.net roughly four seconds after the process started — before any invoice content had been displayed on screen.",
  raw: {
    "winlog.event_id": 3,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Users\\t.osei\\Downloads\\quarterly_invoice.exe",
    "winlog.event_data.User": "MERIDIAN\\t.osei",
    "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
    "winlog.event_data.Protocol": "tcp",
    "winlog.event_data.Initiated": "true",
    "winlog.event_data.SourceIp": "10.40.12.61",
    "winlog.event_data.SourcePort": 51422,
    "winlog.event_data.DestinationHostname": "cdn-assets-delivery.net",
    "winlog.event_data.DestinationIp": "185.220.101.47",
    "winlog.event_data.DestinationPort": 443,
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
    ThreatName: "PUA:Win32/InstallCore",
    FileName: "SearchAssistantToolbar.exe",
    FolderPath: "C:\\Program Files (x86)\\PDFSuitePro\\Toolbar\\SearchAssistantToolbar.exe",
    InitiatingProcessFileName: "PDFSuiteProEnterprise_Setup.exe",
    InitiatingProcessFolderPath: "C:\\Users\\n.walcott\\Downloads\\PDFSuiteProEnterprise_Setup.exe",
    AccountName: "n.walcott",
    DetectionSource: "Cloud",
    Timestamp: "2026-05-18T11:02:44.000Z",
  },
};

const malwareTypesRoom: Room = {
  id: "malware-types",
  title: "Malware Types and What Each One Wants",
  description:
    "The platform's scenarios say 'trojan-dropper', 'loader', 'infostealer', 'wiper', and 'RAT' as if you already know what each one is for — and you can't triage what you can't name. This room organises the whole malware taxonomy around one question per type: what does it want, how does it arrive, what does it look like in telemetry, and what should you do the moment you recognise it?",
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
        `Security folklore names malware like it's cataloguing monsters — virus, worm, trojan, wiper, RAT — and a new analyst can spend hours memorising these names without gaining anything useful for triage. There's a better way in: instead of memorising labels, answer two independent questions for anything you encounter. First, how does it move — does it need a person to run it, or can it spread by itself? Second, what does it do once it's running — what is its actual objective? Every name in this room is really just a specific answer to those two questions, and once you see the frame, the names stop being folklore and start being useful shorthand.\n\n` +
        `**The propagation axis: does it need you?**\n\n` +
        `A virus needs a host file to attach itself to, and it needs a person to run that host file — the same way a biological virus needs a living cell and does nothing at all sitting inert on a surface. A trojan also needs a person to run it, but it doesn't attach to another file; instead it disguises itself as something the person actively wants — an invoice, a cracked game, a "PDF converter" — and relies entirely on the user choosing to launch it. A worm is the outlier on this axis: it spreads across a network on its own, machine to machine, with no human clicking anything after the very first infection. That single difference is why worm outbreaks move on a completely different timescale than trojan campaigns — a trojan needs an entire company to individually open the same phishing email, one inbox at a time, while a worm can be on every unpatched machine on a subnet within minutes of the first one being hit. If you only remember one thing from this reading, make it this: "self-propagating, no user needed" is the single fact that should make you treat a worm report with more urgency than almost anything else on this list, purely because of the clock it starts.\n\n` +
        `**The payload axis: what does it do once it's running?**\n\n` +
        `Once code is executing, it's built toward one of a handful of objectives, and this room covers each one as its own reading: steal something and leave (infostealer), give a human attacker live hands-on-keyboard control (RAT/backdoor), encrypt files for extortion (ransomware), destroy data with no way back (wiper), or quietly steal compute cycles (cryptominer). A few more — rootkits, fileless techniques, and PUPs — are less about a distinct objective and more about how the malware hides or how seriously it deserves to be taken, and this room covers those too.\n\n` +
        `**Why keeping the two axes separate matters**\n\n` +
        `Propagation and payload are independent choices an attacker makes, not a package deal — which is exactly why a single piece of malware can combine them in ways a folklore-only vocabulary can't describe. WannaCry, for instance, used worm-style self-propagation over a Windows networking flaw to spread machine-to-machine with no user interaction at all, while its payload was ordinary file-encrypting ransomware. Calling it "a worm" describes how it moved; calling it "ransomware" describes what it did once it landed; you need both answers to actually understand what happened. The diagram below is this room's whole argument in one picture: work down the propagation question first, then the payload question, and almost any malware name you'll ever encounter falls into place.`,
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
      type: "reading",
      id: "malware-r2",
      heading: "Dropper vs Loader vs Stager: The Distinction Juniors Miss",
      content:
        `Once malware has landed and run for the first time, it usually still needs to get its real, fully-capable payload onto the machine — and exactly how it does that is one of the most operationally important distinctions in this whole room, precisely because juniors routinely treat "dropper" and "loader" as interchangeable synonyms when they describe two very different SOC situations.\n\n` +
        `**A dropper carries its payload inside itself**\n\n` +
        `A dropper is a single file that already contains its full malicious payload, embedded inside it, at the moment it first runs. When a user double-clicks it, there's no second download, no network request for "the real malware" — everything needed is already sitting on disk inside that one file, and the dropper's only job is to extract and launch it locally. From a detection standpoint, this means the moment of execution IS the moment the full payload becomes available; there's no network step in between to intercept.\n\n` +
        `**A loader fetches stage 2 from the network**\n\n` +
        `A loader, by contrast, is a small, often unremarkable-looking file whose whole job is to reach out over the network — usually within seconds of launching — and pull down the actual malicious payload from infrastructure the attacker controls. The file that first ran is nearly harmless on its own; it's really just a fetch mechanism. A stager is the same idea taken one step further toward minimalism: an even smaller piece of code (sometimes just a few hundred bytes) whose only job is to establish just enough of a connection to pull down a larger, fully-featured payload next.\n\n` +
        `**Why this is the distinction that actually matters to a SOC**\n\n` +
        `Here's the operational consequence that makes this worth learning carefully: with a loader (or a stager), you get something a dropper never gives you — a network indicator, and a genuine window of time to act before the real payload ever lands. The destination domain or IP the loader reaches out to can be blocked at a proxy or firewall, and if that block happens fast enough, stage 2 simply never arrives, no matter how compromised the first-stage file already was. With a dropper, that window doesn't exist — the payload was already there the moment the file ran, so response has to focus immediately on the file itself: its hash, its on-disk behaviour, and full incident response, not on trying to race a network connection that already delivered everything it was going to deliver.\n\n` +
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
      diagramCaption: "Dropper vs loader — where the network gives you a chance",
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
    },
    {
      type: "question",
      id: "malware-q1",
      question:
        "An EDR alert reports a worm-style outbreak beginning to spread machine-to-machine across an unpatched subnet with no user interaction required, at the same moment a phishing-based trojan is reported on a single user's laptop elsewhere in the company. Both are rated the same severity by the product. Why does the worm typically demand faster action?",
      options: [
        "It doesn't — a single infected laptop and a spreading worm should always be treated with identical urgency since both are technically 'malware present' events",
        "The worm can spread to every reachable, unpatched machine on that subnet without anyone clicking anything, so the number of compromised hosts can grow dramatically in the time it takes to triage a single ticket, while the trojan's spread is capped by how many more people open the same phishing email",
        "Trojans are always more dangerous than worms because they are disguised, and disguise is inherently worse than direct network propagation",
        "Worms cannot actually execute a payload, so they are lower priority than a trojan that has already run",
      ],
      answer: 1,
      explanation:
        "The propagation axis from Reading 1 is exactly the point: a worm's self-propagation means the population of infected hosts can grow with no further human action at all, so every minute of delay has a multiplying effect that a trojan — bottlenecked by how many individual people choose to open a file — simply doesn't have. Disguise doesn't make a trojan automatically 'worse' than a worm, and worms absolutely execute payloads (WannaCry's worm-style spread carried a ransomware payload) — propagation speed and payload capability are separate questions.",
      xp: 20,
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
            "This is normal — every Windows application checks for updates within seconds of launching, regardless of what the application claims to be",
            "This is most likely a loader: rather than carrying a full malicious payload inside itself the way a dropper would, it is reaching out to the network immediately after execution to fetch a second stage — which is exactly why a destination like cdn-assets-delivery.net now exists as a blockable network indicator",
            "This is definitely a dropper, since droppers always contact a command-and-control domain immediately by definition",
            "DestinationPort 443 proves this connection is legitimate encrypted web traffic and therefore benign",
          ],
          answer: 1,
          explanation:
            "A document viewer that reaches the network before showing any of its claimed content, seconds after launching from an email attachment, matches the loader pattern from Reading 2 far better than routine update-checking behavior. Option 2 has the definition backwards — a dropper's defining trait is that it does NOT need a network connection, because its payload is already embedded inside it. Port 443 just means TLS was used; it says nothing about legitimacy, and is in fact the most common way malware blends its traffic in with everything else on a network.",
          xp: 25,
        },
        {
          question:
            "If quarterly_invoice.exe had instead been a dropper rather than a loader, what would be different about the detection and response opportunity here?",
          options: [
            "Nothing would change — droppers and loaders are simply two different names for identical behavior",
            "A dropper would have needed no network connection at all, since its full payload is already embedded inside the file; response would have to focus on the file's hash and on-disk content from the moment of execution, since there would be no destination domain or IP available to block",
            "A dropper always requires local administrator rights to execute, while a loader never does",
            "A dropper can only be delivered via a USB drive, never as an email attachment",
          ],
          answer: 1,
          explanation:
            "This is the operational consequence from Reading 2: a dropper never gives you the network-blocking window this loader just did, because there's no second-stage fetch to intercept — everything the dropper will ever do to this host, it can already do the moment it runs. Neither dropper nor loader status has anything to do with required privilege level or delivery mechanism.",
          xp: 25,
        },
        {
          question:
            "Given this event, what is the correct immediate response?",
          options: [
            "No action needed, since the connection used standard HTTPS on port 443",
            "Isolate the host, block cdn-assets-delivery.net and its resolved IP at the proxy/firewall to try to stop stage 2 from landing (or spreading further if it already has), and submit the on-disk quarterly_invoice.exe for hash/reputation lookup and further analysis",
            "Delete the Sysmon event so it stops appearing in the console",
            "Wait for a second, independent alert before taking any action, since a single network-connection event is never actionable by itself",
          ],
          answer: 1,
          explanation:
            "This is the loader's exact detection window from Reading 2: block the destination fast, isolate the host to limit anything already in progress, and get the file itself analyzed to confirm what it is. Port 443 doesn't make a connection benign, deleting the event destroys evidence rather than resolving anything, and this event — a document attachment beaconing out before showing its claimed content — is already actionable on its own.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "malware-r3",
      heading: "RAT / Backdoor: Interactive Control, and Why Beaconing Is the Detectable Part",
      content:
        `A Remote Access Trojan (RAT) — often just called a backdoor once installed — gives an attacker something fundamentally different from every payload covered so far: a live, interactive connection to the compromised machine, the same way legitimate remote-support software gives an IT technician control of your screen, except the person on the other end was never invited. Once a RAT is running, the attacker can browse files, launch programs, take screenshots, log keystrokes, or pivot to other machines on the network, all in real time, exactly as if they were sitting at the keyboard.\n\n` +
        `**The relationship this requires: command-and-control (C2)**\n\n` +
        `A RAT can't just sit passively waiting to be interactively controlled — it has to maintain a connection back to infrastructure the attacker operates, commonly called a command-and-control (C2) server, so the attacker's instructions have somewhere to arrive from. Because that connection has to stay usable for as long as the attacker wants access, the RAT doesn't just make one network request and stop; it checks in repeatedly, over and over, for as long as it remains installed — sometimes every few seconds, sometimes only once every several hours to stay quiet.\n\n` +
        `**Why beaconing is the part you can actually catch**\n\n` +
        `This repeated check-in behavior is called beaconing, and it's the single most reliable network-based way to detect a RAT even when nothing else about the traffic looks unusual on any one occasion. A one-time connection right after execution — the loader pattern from Reading 2 — looks similar to a single beacon in isolation, but a RAT's beacon keeps recurring, often at intervals close enough to regular that plotting connection timestamps to the same destination reveals an unmistakable pattern no ordinary application produces. This is exactly why "one connection to an unfamiliar domain" and "many connections to the same domain, spread out over hours or days" point an analyst toward two different conclusions — a loader fetching a payload once, versus a RAT's C2 channel still being actively used.\n\n` +
        `**What this means for triage priority**\n\n` +
        `A confirmed RAT should be treated as an active, ongoing intrusion rather than a completed event, because unlike an infostealer that already took what it wanted, a RAT represents a human attacker who may still be present and reacting in real time to whatever the SOC does next. That changes response mechanics: killing the process or blocking the C2 domain without first understanding what the attacker has already done and reached can tip them off and cause them to accelerate — which is why RAT incidents are the ones most likely to justify a quieter, more coordinated containment plan rather than an immediate, visible block.`,
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
        "A single outbound connection immediately after execution that is never repeated again",
        "Recurring outbound connections to the same destination at regular or semi-regular intervals, continuing for hours or days after the initial process launch — the beaconing pattern of a live command-and-control channel still checking in for instructions",
        "Any connection that uses port 443, since that port is reserved exclusively for command-and-control traffic",
        "A connection that only ever occurs during normal business hours and never outside them",
      ],
      answer: 1,
      explanation:
        "Reading 3's key distinction is recurrence over time, not any single technical detail of one connection — a loader's fetch is typically a single event, while a RAT's beacon keeps repeating for as long as the attacker wants access. Port 443 is standard HTTPS used by huge amounts of entirely legitimate traffic, not a reserved C2 port, and beaconing intervals are chosen by the attacker for stealth, not tied to business hours.",
      xp: 20,
    },
    {
      type: "reading",
      id: "malware-r4",
      heading: "Infostealer: Grab and Leave — Why the Response Is Revocation, Not Cleanup",
      content:
        `An infostealer's objective is narrow and fast: harvest whatever credentials, session cookies, and cryptocurrency wallet files it can reach on the machine, send them somewhere the attacker controls, and finish. There's no interactive control like a RAT, no encryption like ransomware — the entire "attack," from the SOC's point of view, is often over within minutes of execution.\n\n` +
        `**What it actually goes after**\n\n` +
        `Modern infostealers target the specific files browsers use to store saved logins (Chrome, Edge, and Firefox all keep a local credential database), the cookie files that let a browser stay "logged in" without re-entering a password, and increasingly, cryptocurrency wallet files and configuration data for cloud CLI tools. Cookies matter every bit as much as passwords here: a stolen session cookie can let an attacker walk directly into an already-authenticated session, skipping the login (and any multi-factor prompt) entirely.\n\n` +
        `**Why short dwell time doesn't mean low priority**\n\n` +
        `"Dwell time" is how long an attacker's tooling stays actively present and operating inside an environment before being found. An infostealer often has one of the shortest dwell times of anything covered in this room — it isn't trying to stay hidden long-term, because it doesn't need to; its entire objective can be complete within seconds of executing. That short window is exactly the trap: it's tempting to treat a fast, self-contained event as less serious than something that lingers, but the damage from an infostealer is typically already done by the time it's detected — the credentials have already left the building. Speed of detection buys you almost nothing about limiting what was taken; it only changes how quickly you can respond to the fact that it's already gone.\n\n` +
        `**Why the correct response is revocation, not cleanup**\n\n` +
        `Because the theft, not an ongoing presence, is the actual event, cleaning the malware off the endpoint — deleting the file, running a scan, confirming the process is gone — does nothing about the credentials and sessions that already left. The response an infostealer actually demands is credential and session revocation: reset every password that could plausibly have been stored in the affected browser profiles, and revoke active sessions and access tokens tied to those accounts so a stolen cookie can't be used to walk in without ever needing the password at all. Only after that containment step is complete does standard endpoint cleanup become the secondary task, not the primary one.`,
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
        "A legitimate system health-check or PC optimizer has no functional reason to open a browser's local credential-store file (Login Data), let alone the equivalent file for a second, different browser within the same second — that combination matches automated credential harvesting, not disk cleanup or performance scanning. Distribution through an unofficial 'PC optimizer' site is a classic infostealer lure. Per Reading 4, the correct response is to treat every credential that could have been stored in Chrome or Edge on this host as compromised: force password resets and revoke active sessions/tokens for those accounts, not just remove the file and call it resolved.",
      xp: 30,
    },
    {
      type: "reading",
      id: "malware-r5",
      heading: "Ransomware: Encryption for Extortion, and Why Pre-Encryption Indicators Are the Actionable Part",
      content:
        `Ransomware's objective is to make an organization's own data unusable to itself and then demand payment to reverse it. The attacker encrypts files across as many systems and shares as they can reach, drops a ransom note explaining how to pay, and — if the victim has no usable backup — creates enormous pressure to pay simply to resume operating.\n\n` +
        `**Double extortion: the modern twist**\n\n` +
        `Older ransomware campaigns relied purely on encryption: no backup meant no leverage against paying. Organizations responded by investing heavily in backups, which weakened that leverage — so modern ransomware operators added a second lever, called double extortion: before ever triggering encryption, the attacker quietly exfiltrates a copy of sensitive data first. Now, even a victim with perfect backups faces a second threat that backups don't solve at all — the threat of the stolen data being published publicly or sold if the ransom isn't paid.\n\n` +
        `**Why the moments before encryption matter more than the moment of encryption itself**\n\n` +
        `By the time files are visibly encrypted, the attack has already succeeded — recovery from that point means restoring from backup (if it exists and wasn't also touched) or living with the loss. The genuinely actionable window is earlier, in the preparation steps almost every ransomware operation performs before triggering the encryption routine, because those steps produce detectable telemetry while there's still something to prevent. Three of the most common: shadow copy deletion (using a tool like vssadmin.exe to remove Windows' built-in local backup snapshots, so the simplest recovery path is gone before encryption even starts), security log clearing (Event ID 1102, covering tracks), and a sudden burst of mass file access across many shares by one account in a short window (the encryption routine's precursor, reading through what it's about to lock). None of these three things, individually, always means ransomware — but together, in sequence, on a system that doesn't normally show this behavior, they are the last honest warning before the damage becomes irreversible.\n\n` +
        `**How this connects to wipers, next reading**\n\n` +
        `Everything up through encryption looks the same whether the attacker actually intends to restore the data for payment, or never intended to restore it at all. The diagram below shows the shared pre-encryption sequence and marks exactly where those two outcomes diverge — which is exactly what Reading 6 covers next.`,
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
        "  subgraph Actionable window -- before encryption\n" +
        "  D\n" +
        "  E\n" +
        "  F\n" +
        "  end",
      diagramCaption: "Pre-encryption indicators are the actionable window — and where ransomware and wipers diverge",
    },
    {
      type: "question",
      id: "malware-q3",
      question:
        "A file server shows vssadmin.exe deleting shadow copies, the Security log being cleared (Event ID 1102), and one service account reading thousands of files across multiple shares within ten minutes. No files have been encrypted yet. What should an analyst do?",
      options: [
        "Wait until files actually start appearing with a new extension before treating this as an incident, since nothing has technically been encrypted",
        "Treat this as an active pre-encryption ransomware sequence and escalate immediately — shadow copy deletion removes the easiest recovery path, log clearing is covering tracks, and file-access volume at this scale is very rarely legitimate; the goal is to contain before encryption begins, not after",
        "This is normal end-of-quarter backup activity and can be closed without further review",
        "Only the log-clearing event is worth escalating; shadow copy deletion and file-access volume are unrelated administrative tasks",
      ],
      answer: 1,
      explanation:
        "This is the exact combination from Reading 5: none of these three signals alone is proof, but together — deletion of the local recovery path, evidence of tracks being covered, and a scan-like burst of file access — they are the pre-encryption sequence, and this is the last window where action can prevent, not just respond to, encryption. Legitimate backup jobs don't delete shadow copies or clear the security log, and treating log-clearing as the only relevant signal ignores that all three together are what make this pattern recognizable.",
      xp: 25,
    },
    {
      type: "reading",
      id: "malware-r6",
      heading: "Wiper vs Ransomware, and Cryptominers: 'Just Resource Theft' Is a Mistake",
      content:
        `**Wiper: looks like ransomware, isn't**\n\n` +
        `A wiper follows the exact same pre-encryption sequence as ransomware — shadow copy deletion, log clearing, mass file access, then a destructive routine — and very often even drops something that looks like a ransom note. The difference is entirely in intent: a wiper has no working decryption key, and its operator has no intention of ever restoring the data, even if a victim pays. Sometimes the "ransom note" is genuine misdirection meant to make investigators waste time treating a destructive, often geopolitically-motivated attack as an ordinary financially-motivated ransomware case; sometimes encryption is never even really the mechanism, and files or disk structures are simply corrupted or overwritten outright. Recognizing which one you're dealing with changes the entire response: with ransomware, negotiating, verifying decryptor functionality, and preserving encrypted data for possible future recovery are all live options; with a wiper, none of those options exist, and the response has to assume total data loss on affected systems from the start, shifting all effort toward containment and restoration from offline backup rather than any hope of a working key.\n\n` +
        `**Cryptominer: wants CPU, not data**\n\n` +
        `A cryptominer's objective is entirely different from everything else in this room — it doesn't want your data at all, it wants your compute. Once installed, it runs cryptocurrency-mining software continuously in the background, consuming CPU or GPU cycles (and the electricity and cooling that come with them) to generate value for the attacker, usually with no data ever touched, stolen, or destroyed.\n\n` +
        `**Why "just" resource theft is the wrong way to think about it**\n\n` +
        `It's tempting to treat a cryptominer detection as low priority — degraded performance and a higher power bill feel minor compared to ransomware or data theft. That instinct misses the actual point: the access that successfully delivered a cryptominer to a machine is the exact same access that could have delivered ransomware, a RAT, or an infostealer instead. A cryptominer often shows up because it's the payload an opportunistic, low-effort attacker happened to choose, or because it's what an access broker sells to first while deciding what to do with the foothold next — but the vulnerability, weak credential, or misconfiguration that let it in is unchanged by which payload happened to arrive. Investigating a cryptominer detection as thoroughly as any other malware finding — how did it get here, what else could that same path have delivered, is that path still open — is the difference between closing a minor nuisance ticket and catching the fact that the same open door is still available for something far worse.`,
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
    },
    {
      type: "matching",
      id: "malware-m1",
      heading: "Match Each Malware Type to Its Defining Trait",
      instructions: "Match each malware type to the trait that most reliably identifies it.",
      pairs: [
        { id: "worm", left: "Worm", right: "Spreads across a network by itself, machine to machine, with no user interaction needed after the first infection" },
        { id: "trojan", left: "Trojan", right: "Disguises itself as something the user wants, and relies entirely on the user choosing to launch it" },
        { id: "dropper", left: "Dropper", right: "Carries its full malicious payload embedded inside itself — no second download, nothing to intercept over the network" },
        { id: "loader", left: "Loader", right: "Fetches its real payload from the network shortly after execution, giving defenders a blockable destination and a window to act" },
        { id: "rat", left: "RAT / Backdoor", right: "Maintains a live command-and-control channel, giving an attacker interactive, hands-on-keyboard control of the machine" },
        { id: "infostealer", left: "Infostealer", right: "Harvests credentials, cookies, and wallet files fast and exits — the damage is already done by the time it's detected" },
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
      heading: "Hiding From the SOC — and When Not to Bother Escalating At All",
      content:
        `**Rootkit / bootkit: persistence below the operating system**\n\n` +
        `Most malware runs as an ordinary process that endpoint tools can see, hash, and terminate. A rootkit is built to defeat exactly that visibility by embedding itself at a privileged layer of the operating system — sometimes inside the kernel itself, sometimes (as a bootkit) in the boot process, before the operating system and its security tooling have even finished loading. From that position, a rootkit can hide its own files, processes, and network connections from the very tools that would normally detect them, because it can intercept and falsify the answers those tools receive when they ask "what's running right now?" This is why rootkit persistence "defeats normal endpoint visibility": the compromise isn't hiding well within the system the EDR agent sees — it's operating from underneath the layer the EDR agent trusts to tell it the truth, so a standard process listing or file scan can come back clean while the rootkit is very much still there.\n\n` +
        `**Fileless / living-off-the-land: nothing on disk to hash or quarantine**\n\n` +
        `A fileless attack achieves its objective — reconnaissance, credential theft, lateral movement, whatever the goal is — using tools already present on the system (PowerShell, WMI, legitimate administrative utilities, a technique called "living off the land") rather than dropping a new, attacker-authored executable onto disk at all. This directly defeats the core assumption behind traditional antivirus signature matching: a signature scanner is built to compare files against a database of known-bad hashes, but there is often no new file here to hash in the first place — just an unusually-used legitimate tool. The behavior is the malware: what matters isn't what file ran, it's what a completely legitimate tool was made to do (an unusual parent-child process relationship, an encoded PowerShell command line reaching out to an external address, a legitimate admin tool touching files it has no ordinary business touching). This is exactly why modern endpoint tools shifted from pure signature matching toward behavioral detection — watching what happens, not just what's on disk.\n\n` +
        `**PUP / adware: the triage judgement call**\n\n` +
        `A Potentially Unwanted Program (PUP) — commonly bundled toolbars, ad injectors, and "optimizer" utilities — sits in a genuinely different category from everything else in this room: it's often unwanted and mildly invasive rather than malicious in intent. Security products flag PUPs with heuristic detections that can look every bit as alarming in a console as a trojan alert, but the correct analyst instinct is judgement, not automatic escalation: check how it arrived (bundled with software the user or organization deliberately and knowingly installed, versus a drive-by install from an untrusted site) and whether it's doing anything beyond its stated, if annoying, function. A PUP that arrived through an approved, catalog-listed software deployment is a very different finding from the same detection name showing up on a machine with no such explanation.\n\n` +
        `**Why one sample gets three different names**\n\n` +
        `Antivirus vendors each build their own detection engines, naming conventions, and family-classification logic independently — so it's completely normal for the exact same malware sample to be labeled "Trojan.GenericKD.12345" by one vendor, "Backdoor:Win32/Something.A" by a second, and "Malware.Heuristic.9001" by a third, even when scanned at the exact same moment. A vendor's family label is a hint about behavior and lineage worth taking seriously — but it is not ground truth, and it should never be the only thing an analyst relies on to understand what a sample actually does. Confirm behavior from telemetry (what did it actually connect to, read, or modify) rather than trusting a name alone to tell the whole story.`,
    },
    {
      type: "question",
      id: "malware-q4",
      question:
        "An analyst argues that a suspected fileless attack 'can't be malware — the antivirus scan came back completely clean, and no new file was ever created on disk.' What is wrong with that reasoning?",
      options: [
        "It's correct — if antivirus finds nothing and no new file exists, there is nothing left to investigate",
        "A clean signature-based scan proves nothing here: fileless techniques use legitimate, already-present tools (PowerShell, WMI, admin utilities) to achieve their objective without ever dropping a new file to hash, which is exactly what defeats traditional signature matching — behavior, not file presence, is the detection surface that matters",
        "Fileless attacks are purely theoretical and have never been used in a real intrusion",
        "Antivirus always detects fileless activity through network scanning even when no file exists, so a clean scan in this specific case must mean the AV product itself is broken",
      ],
      answer: 1,
      explanation:
        "This is Reading 7's core point about fileless/living-off-the-land techniques: they're specifically effective because they route around signature-based detection by never introducing a new file to scan in the first place, so 'nothing new on disk, clean scan' is the expected signature of a fileless attack, not proof one didn't happen. Fileless techniques are widely and actively used in real intrusions, and a clean AV scan doesn't indicate the product is malfunctioning — it indicates the product was checking the wrong thing for this technique.",
      xp: 20,
    },
    {
      type: "analyst_choice",
      id: "malware-ac2",
      heading: "Verdict: A Bundled Toolbar From an Approved Installer",
      scenario:
        "Defender flagged a browser toolbar component that installed alongside this week's approved PDF editor rollout to Marketing. Review the detection and the confirming IT ticket below, then decide whether this deserves incident-level escalation.",
      event: pupEvent,
      correct_verdict: "false_positive",
      explanation:
        "Defender's PUA (Potentially Unwanted Application) category exists precisely for borderline software like bundled toolbars — it's a heuristic warning about unwantedness, not a malware verdict. The confirming IT ticket shows this toolbar arrived through the organization's own approved deployment, not a drive-by install from an untrusted site. Per Reading 7, correct PUP triage means checking distribution channel and authorization before escalating, not treating every PUA detection identically to a trojan alert.",
      fp_trap:
        "The word 'PUA' next to a detection that lights up red in the console primes an analyst to treat it exactly like a backdoor or trojan finding — but the category was built specifically to flag software that is unwanted, not software that is malicious. Escalating a confirmed, catalog-approved bundled toolbar as a full incident wastes response capacity that a genuinely uninvited PUP install — arriving via a random ad-laden download site, with no IT ticket behind it at all — would actually deserve.",
      xp: 30,
    },
    {
      type: "flag",
      id: "malware-f1",
      prompt:
        "Look at Log Analysis 1 (the quarterly_invoice.exe connection). What is the destination domain the process connected to? Enter it exactly as shown in the raw log.",
      answer: "cdn-assets-delivery.net",
      hint: "Check the winlog.event_data.DestinationHostname field in the raw log.",
      xp: 25,
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
    "Prioritisation is the daily job of a SOC analyst, and it depends on something most training skips: what the affected asset actually is. Failed logons on a disposable test VM, a finance workstation, and a domain controller can be the exact same log line — and three completely different incidents. This room teaches asset criticality, blast radius, exposure, and business context, then has you rank concurrent alerts where the correct order isn't the order the products assigned.",
  difficulty: "beginner",
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
        `Imagine the exact same alarm going off in three different buildings: a garden shed, your family home, and a bank vault. The alarm itself — the sound, the sensor that triggered it — is identical every time. Nobody would respond to it identically, though, because the alarm never told you what's behind the door; the building did. SOC alerts work exactly the same way, and it's the single most important idea in this room.\n\n` +
        `**One log line, three responses**\n\n` +
        `Picture a detection rule that fires on "12 failed logons in 3 minutes from the same source." It fires, on the same afternoon, in three places: an isolated lab VM used for occasional software testing, with no production data and no connection to the corporate domain; a finance analyst's everyday workstation on the production network; and a domain controller — a server that authenticates every user in the company. The alert text is identical all three times. The correct response is not. On the lab VM, this is worth a glance and a log entry — there's essentially nothing behind that door to protect. On the finance workstation, this deserves a real look: check for account lockout, consider contacting the user, watch for a follow-up success. On the domain controller, this is an immediate escalation, because a domain controller isn't "a computer that happened to receive some failed logons" — it's the identity infrastructure that every other system in the company implicitly trusts.\n\n` +
        `**Why this has to be taught explicitly**\n\n` +
        `Most alert-handling training focuses entirely on the alert itself: what triggered it, what the fields mean, what technique it maps to. That's necessary, but it's only half the picture, and treating it as the whole picture is exactly what produces analysts who escalate a lab VM as urgently as a domain controller, or — just as dangerous — who get so used to seeing "failed logon burst" as routine noise that they miss the one time it lands somewhere that actually matters. The rest of this room is about the other half: how to look at the asset behind the alert and let that shape the response, not just the alert's own severity field.`,
      diagram:
        "flowchart TD\n" +
        "  A[Alert: 12 failed logons in 3 minutes] --> B[Asset: isolated lab VM, no prod data]\n" +
        "  A --> C[Asset: finance workstation, production network]\n" +
        "  A --> D[Asset: domain controller]\n" +
        "  B --> B1[Log for context -- no urgent action]\n" +
        "  C --> C1[Check for lockout, contact user, monitor for a follow-up success]\n" +
        "  D --> D1[Escalate immediately -- identity infrastructure for the whole domain]",
      diagramCaption: "Same alert text, three different assets, three different responses",
    },
    {
      type: "reading",
      id: "asset-r2",
      heading: "What Makes an Asset Critical",
      content:
        `"Criticality" sounds like a vague, subjective label, but it breaks down into a small number of concrete questions you can actually ask about any asset. Think of it like the difference between losing a random door key and losing a master key that opens every room in the building — the key itself might look identical, but what it can open is what actually determines how much you care about losing it.\n\n` +
        `**What it holds**\n\n` +
        `Data classification is the first question: does this asset store or process anything sensitive — customer PII (personally identifiable information), payment data, source code, health records, legal documents — or is it functionally empty of anything an attacker would want to steal? A server holding nothing but public marketing images has a very different "what it holds" answer than one holding the customer database.\n\n` +
        `**What it controls**\n\n` +
        `This is often the more important question, and the one beginners underweight: some assets aren't valuable because of what they store, but because of what they can reach or command. A domain controller doesn't necessarily hold your most sensitive files, but it controls every identity in the domain — every account, every group membership, every trust relationship. A hypervisor doesn't hold data of its own; it controls every virtual machine running on top of it. A backup server may hold nothing anyone would want to steal for its own sake, but it controls your ability to recover at all after an incident — which becomes existential the moment ransomware is involved.\n\n` +
        `**Who uses it**\n\n` +
        `The same laptop model, running the same software, means something different depending on whose hands it's in. A workstation used by a domain administrator or an executive with broad approval authority carries risk that an identical machine used by a receptionist for a single-purpose kiosk app simply doesn't, because of what the logged-in account's own privileges can do once an attacker rides along with them. A service account with broad database access is "who uses it" in the same sense — the account itself carries the criticality, not just the human behind the keyboard.\n\n` +
        `**Whether it's internet-facing**\n\n` +
        `An asset reachable from anywhere on the internet has a fundamentally larger population of potential attackers than one that's only reachable from inside a controlled internal network — this dimension gets its own full reading next, because it interacts with everything else here rather than standing alone.\n\n` +
        `Put these four questions together — what it holds, what it controls, who uses it, and whether it's exposed — and "criticality" stops being a gut feeling and becomes something you can actually justify in a triage note.`,
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
        "The kiosk PC, because it's a public-facing device anyone in the lobby can physically touch",
        "The backup server, because of what it controls: it is the organization's recovery capability, and losing it changes every other incident from 'recoverable' to 'potentially unrecoverable', regardless of how little the server itself might seem to 'hold' day to day",
        "Neither — since the severity score is identical, the response should be identical",
        "The kiosk PC, because kiosk devices always run outdated, unpatched software and are therefore inherently higher risk",
      ],
      answer: 1,
      explanation:
        "This is the 'what it controls' question from Reading 2: a backup server's importance isn't about what data lives on it day to day, it's about the recovery capability the whole organization depends on it for — compromising it can turn every future incident into an unrecoverable one. Physical accessibility in a lobby doesn't outweigh that, identical product severity scores are exactly what asset context is meant to override, and kiosk devices aren't automatically higher risk just by being public-facing hardware.",
      xp: 20,
    },
    {
      type: "reading",
      id: "asset-r3",
      heading: "Blast Radius: What Else Does the Attacker Reach From Here?",
      content:
        `Blast radius answers one specific question: if this asset were fully compromised right now, what else does the attacker gain access to as a direct consequence? It's the difference between an incident that stays contained to one machine and one that cascades into dozens or thousands.\n\n` +
        `**The assets whose blast radius is almost always largest**\n\n` +
        `A domain controller's blast radius is the whole domain: full control of the KDC (Kerberos Key Distribution Center) that issues every authentication ticket means an attacker can potentially impersonate any user, including domain admins, across every system that trusts that domain. A hypervisor's blast radius is every virtual machine it hosts — and this one deserves special attention because it's a force multiplier: the hypervisor sits below each guest VM's own operating system and its own security tooling entirely, so a compromise at that layer can affect every VM on it simultaneously, regardless of how well-defended any individual guest happens to be. Backup infrastructure's blast radius is the organization's ability to recover at all — as Reading 2 introduced, this becomes the difference between "we restore from backup by tomorrow" and "we have no backup left to restore from" the moment ransomware is in play. A jump host or bastion — the single trusted hop administrators use to reach otherwise-segmented networks — has a blast radius equal to everything that segmentation was supposed to protect, because compromising the trusted hop bypasses the segmentation entirely. A CI/CD (continuous integration / continuous deployment) pipeline server's blast radius extends to every system that trusts and deploys its build output — a compromise there can become a supply-chain-scale problem, shipping malicious code into production systems that never had a security incident of their own.\n\n` +
        `**Why this changes response, not just labeling**\n\n` +
        `Recognizing a large blast radius doesn't just mean writing "high priority" in a ticket — it changes what you actually do. An incident on an asset with a large blast radius justifies broader containment thinking from the very first minutes: are there signs the attacker already moved beyond this one asset, does the incident response plan need to consider resetting credentials domain-wide rather than just on this host, does recovery capability itself need to be verified as intact before anything else. Asking "what does this asset let the attacker reach next" as one of your very first triage questions is what turns blast radius from an abstract concept into something that actually shapes your first hour of response.`,
      diagram:
        "flowchart LR\n" +
        "  DC[Domain Controller compromised] --> DC1[Every identity in the domain]\n" +
        "  HV[Hypervisor compromised] --> HV1[Every VM it hosts, simultaneously]\n" +
        "  BK[Backup infrastructure compromised] --> BK1[Ability to recover from ransomware -- gone]\n" +
        "  JH[Jump host / bastion compromised] --> JH1[Direct path into every segmented network it bridges]\n" +
        "  CI[CI/CD pipeline compromised] --> CI1[Every system that trusts its build output]",
      diagramCaption: "Blast radius: what a compromise of THIS asset hands the attacker next",
    },
    {
      type: "question",
      id: "asset-q2",
      question:
        "An attacker gains full control of a hypervisor hosting 40 virtual machines, including three domain controllers and the ticketing system's database server. Why does compromising the hypervisor represent a larger blast radius than compromising any single one of those 40 VMs individually?",
      options: [
        "It doesn't — compromising one VM and compromising the hypervisor carry identical risk, since a hypervisor is just one more server on the network",
        "The hypervisor sits below every guest VM's own operating system and security controls, so a compromise at that layer can affect every one of the 40 VMs simultaneously and directly, regardless of how well-defended any individual guest is — a single point of failure for all of them at once, which is what makes it a force multiplier",
        "Hypervisors are always less critical than the VMs running on them, because the VMs are where the actual applications and data live",
        "Compromising 40 individual VMs one at a time is always faster for an attacker than compromising the single hypervisor underneath them",
      ],
      answer: 1,
      explanation:
        "This is the force-multiplier point from Reading 3: the hypervisor's position underneath every guest VM's own security stack means one compromise there can reach all 40 VMs at once, bypassing whatever protections exist inside each individual guest. A hypervisor is very much not 'just one more server' given what it hosts, VM-level protections don't make the hypervisor itself less critical, and compromising the hypervisor once is exactly what makes it faster and more efficient for an attacker than attacking 40 VMs individually.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "asset-la1",
      heading: "A Failed Logon Burst — Against a Domain Controller",
      context:
        "A detection rule fired on DC02 for a burst of failed logon attempts. Review the representative event below, which includes the full pattern described by the SIEM's correlation summary.",
      event: dcSprayEvent,
      questions: [
        {
          question:
            "This burst is targeting DC02 — a domain controller — directly over the network, attempting 14 different accounts in two minutes. Why does the target being a domain controller change the priority of this alert compared to the exact same signature landing on a single ordinary application server?",
          options: [
            "It doesn't — a failed logon burst is scored identically regardless of which host receives it",
            "A domain controller is the identity authority for the entire domain (Reading 3's blast radius point); if this spray succeeds against even one of the 14 accounts, or if it's reconnaissance ahead of a more targeted attempt, the consequences extend to every resource across the domain that trusts that authentication — not just one server's worth of data",
            "Domain controllers cannot receive network logon attempts at all, so this must be a logging error",
            "LogonType 3 only ever applies to low-criticality systems, so this confirms the target has low criticality",
          ],
          answer: 1,
          explanation:
            "This is blast radius applied directly: a domain controller's compromise (or even one successfully guessed credential from a spray against it) has consequences reaching the whole domain, unlike an ordinary application server. Domain controllers absolutely receive network logons routinely — LogonType 3 (network) is completely normal for many legitimate purposes and says nothing about the target's criticality on its own; it's the target host that determines that here.",
          xp: 25,
        },
        {
          question:
            "If this identical 14-account, two-minute failed-logon burst had instead landed on an isolated lab VM used only for occasional testing, with no production data and no trust relationship to the domain, how should the response differ?",
          options: [
            "It shouldn't differ at all — the same log pattern always demands the same response regardless of the asset behind it",
            "The technical signature is identical, but the priority is much lower: a compromise of that VM has almost nowhere to go from there, so logging and monitoring is a reasonable response, unlike the domain controller case where the same pattern justifies immediate escalation",
            "It should be escalated even faster than the domain controller case, since isolated lab VMs are always the highest-priority asset type by definition",
            "No response is needed in either case, since failed logons are a routine part of daily operations everywhere",
          ],
          answer: 1,
          explanation:
            "This is Reading 1's exact idea in practice: identical alert text, different asset, different correct response — a compromise of an isolated, low-value VM simply doesn't reach anything further, so the same signature that demands immediate escalation on a DC can reasonably be logged and monitored on a genuinely isolated lab box. Isolated VMs are not automatically higher priority than anything else, and failed logons on identity infrastructure are never something to ignore outright.",
          xp: 25,
        },
        {
          question:
            "What is the correct immediate response to the DC02 burst as described?",
          options: [
            "No action — 4625 (failed logon) events are routine and this volume is within normal limits for a domain controller",
            "Block or rate-limit the source IP at the network edge, check whether any of the 14 attempted accounts show a subsequent successful logon (Event 4624) from the same or a related source, and escalate given that the target is identity infrastructure for the whole domain",
            "Immediately and permanently disable all 14 targeted accounts without further investigation",
            "Wait for an account-lockout notification from one of the affected accounts before taking any action",
          ],
          answer: 1,
          explanation:
            "This combines containment (block/rate-limit the source) with the most important follow-up check (did any attempt actually succeed) and reflects the escalation this asset's blast radius demands. This volume against a domain controller is not routine, permanently disabling 14 accounts without investigation risks disrupting legitimate service accounts among them, and waiting for a lockout notification means waiting for a symptom instead of acting on the alert already in hand.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "asset-r4",
      heading: "Exposure: Internet-Facing, Internal-Only, and Segmented",
      content:
        `Exposure answers a different question than blast radius: not "what can an attacker reach from here," but "how easily can an attacker reach here in the first place." Two assets can have identical vulnerabilities and identical criticality, and still carry very different real-world risk purely because of who can actually get to them.\n\n` +
        `**Three exposure levels**\n\n` +
        `Internet-facing means the asset is directly reachable from the open internet — anyone, anywhere, with no prior foothold required, can attempt to reach it. Internal-only means the asset is reachable only from inside the organization's own network, which already rules out the vast majority of opportunistic, internet-wide scanning and attack traffic. Segmented goes a step further: the asset sits behind additional network controls even from other internal systems — reachable only from a specific management network, only through a jump host, or only with an additional authentication step like VPN plus multi-factor authentication, so even another already-compromised internal machine may not be able to reach it directly.\n\n` +
        `**Why identical vulnerability scores can mean different real risk**\n\n` +
        `A CVSS (Common Vulnerability Scoring System) score measures theoretical severity — how bad the vulnerability is if an attacker can reach and exploit it — but it says nothing about how hard reaching it actually is in your specific environment. The exact same critical vulnerability on an internet-facing web server and on a segmented internal server reachable only via VPN, MFA, and a jump host represents very different real-world exploitability: the internet-facing case can be attempted by literally anyone scanning the internet right now with no other access needed at all, while the segmented case requires an attacker to already have breached several other layers of control first. Neither one is safe to ignore — the segmented system still needs to be patched — but they don't deserve the same urgency, and exposure is exactly the missing variable that a raw CVSS score can't tell you on its own.`,
    },
    {
      type: "question",
      id: "asset-q3",
      question:
        "The exact same critical vulnerability (CVSS 9.8) is found on two servers: one is a customer-facing web portal reachable from the open internet, the other is an internal reporting server reachable only from a management VLAN that requires VPN plus MFA, with no route from ordinary user workstations. Both have identical CVSS scores. Why might these still warrant different urgency?",
      options: [
        "They shouldn't — an identical CVSS score means identical urgency in every case, by definition",
        "Exposure differs: the internet-facing portal can be attempted by any attacker on the internet with no prior foothold at all, while reaching the segmented internal server first requires breaching a VPN and MFA-protected management network — CVSS measures theoretical severity, not how reachable the target actually is in this environment",
        "CVSS scores are automatically lower for internal systems, so a 9.8 on an internal server is actually a scoring error",
        "The internal server should always be treated as more urgent, since internal systems are inherently more trusted and therefore more damaging to lose",
      ],
      answer: 1,
      explanation:
        "This is exactly Reading 4's distinction: CVSS captures how bad exploitation would be, not how easy reaching the vulnerable system is — exposure fills that gap, and the internet-facing system is reachable by a vastly larger, lower-effort population of attackers than the segmented one. CVSS scores aren't automatically adjusted downward for internal systems (that's exactly why exposure has to be considered separately), and 'internal is always more urgent' ignores that the internet-facing system here is dramatically easier for an attacker to actually reach.",
      xp: 20,
    },
    {
      type: "reading",
      id: "asset-r5",
      heading: "Business Context Beats Technical Severity",
      content:
        `Every security product ships an opinion about how bad a finding is, expressed as a severity label — Critical, High, Medium, Low. That label is calculated from technical factors the product can actually measure: exploit availability, CVSS score, detection confidence. What it can never measure is something only the organization itself knows: what's happening around that asset right now.\n\n` +
        `**A concrete example worth internalizing**\n\n` +
        `A MEDIUM-severity alert — say, an unusual configuration change — on the production payment-processing system, discovered during the first hour of a major product launch with elevated transaction volume and executive attention, may deserve to outrank a HIGH-severity alert on an isolated lab box that nobody depends on this week. Nothing about the technical severity scores has to be wrong for this to be true; the product correctly measured what it could measure. What it couldn't measure is that one of these systems is, for this specific week, load-bearing for the entire business, and the other genuinely isn't.\n\n` +
        `**Severity comes from the product; priority comes from the analyst**\n\n` +
        `This is the sentence worth remembering above almost everything else in this room: severity is a technical, product-calculated property of the finding itself, while priority is the analyst's own judgment about response order, built by folding business context on top of that technical severity. A good analyst doesn't override severity labels carelessly or ignore them — they use severity as one important input, then adjust the actual order they work things in based on what the product cannot know: what's launching this week, whose account this is, what would actually hurt the business most if it went wrong right now. Treating the product's severity field as the final word on priority is exactly the gap this whole room exists to close.`,
    },
    {
      type: "analyst_choice",
      id: "asset-ac1",
      heading: "Verdict: A Failed-Logon Burst on an Isolated Detonation VM",
      scenario:
        "The same detection rule that fired on DC02 in Log Analysis 1 just fired again — this time on SANDBOX-DET04. Review the event and the attached change ticket before deciding whether this deserves the same response as the domain controller case.",
      event: sandboxSprayEvent,
      correct_verdict: "false_positive",
      explanation:
        "The technical signature — a burst of failed logons against several accounts from one source in a short window — is shaped identically to the DC02 spray in Log Analysis 1, but asset context changes the verdict entirely: SANDBOX-DET04 is an isolated detonation VM with local-only test accounts and no route to the production domain, and the confirmed change ticket explains the burst as an automated nightly test script, not an attacker. Nothing this host holds or controls extends beyond itself, which is the core idea of this whole room.",
      fp_trap:
        "It's tempting to escalate this exactly like Log Analysis 1, because the log pattern — account count, time window, repeated failures — looks just as alarming on paper. But the asset behind SANDBOX-DET04 has effectively zero blast radius (no production data, no domain trust, an isolated VLAN) and a documented, authorized reason for the behavior, which the domain controller case had neither of. Matching alert shape without checking the asset behind it is exactly the mistake this room is built to prevent.",
      xp: 30,
    },
    {
      type: "reading",
      id: "asset-r6",
      heading: "The CMDB Problem, Honestly",
      content:
        `A CMDB (Configuration Management Database) is supposed to be the organization's authoritative inventory of what assets exist, what they run, who owns them, and how critical they are. In theory, an analyst could look up any hostname and immediately know exactly what they're dealing with. In practice, almost every real CMDB is incomplete, stale, or simply wrong in places — not through negligence, but because assets get spun up, renamed, repurposed, and decommissioned faster than the paperwork tracking them can keep up, especially in cloud and containerized environments where a server might exist for hours.\n\n` +
        `**The instinct this creates — and why it's backwards**\n\n` +
        `When an analyst pulls up an unfamiliar hostname and finds nothing in the CMDB, the tempting shortcut is to treat the lack of a record as a reason to deprioritize: "if it's not in the inventory, it's probably not important, or probably not even real — skip it and move to something documented." That reasoning is exactly backwards. An unrecognized asset isn't automatically unimportant; it's an open question, and open questions in a SOC are findings, not something to wave past. An asset with no record could be a forgotten but perfectly legitimate test box — or it could be a rogue device someone plugged in without authorization, an unmanaged piece of shadow IT nobody signed off on, or exactly the kind of infrastructure an attacker would stand up for persistence, chosen specifically because it wouldn't show up anywhere an analyst would normally check.\n\n` +
        `**What to actually do with an unrecognized hostname**\n\n` +
        `Chase it rather than skip it: check DNS and DHCP lease records for when it first appeared and what requested that address, check the cloud console or virtualization platform if it's a VM, ask the network or infrastructure team directly rather than assuming the CMDB's silence is an answer, and treat "we genuinely don't know what this is" as a real, escalatable finding in its own right rather than a dead end. A stale or incomplete CMDB is a known, common limitation of real environments — the correct response to that limitation is more scrutiny of the unknown, not less.`,
    },
    {
      type: "reading",
      id: "asset-r7",
      heading: "Practical Prioritisation: Combining Severity, Criticality, and Confidence",
      content:
        `Everything in this room comes together into one practical habit: when several alerts are competing for attention at once, priority order should come from combining three separate inputs, not from reading the severity field alone.\n\n` +
        `**The three inputs**\n\n` +
        `Alert severity is what the security product already calculated — how technically bad this specific finding looks, in isolation. Asset criticality is everything from Readings 2 through 4 combined: what the asset holds, what it controls, who uses it, its blast radius, and its exposure. Confidence is how sure you actually are that this alert represents real malicious activity rather than noise, tuning gaps, or an already-explained benign cause — the same judgment call practiced in the false-positive tasks throughout this room. None of these three, alone, is a safe way to rank a queue of alerts; combined, they produce something closer to genuine priority.\n\n` +
        `**Where this visibly overrides the product's own severity field**\n\n` +
        `A MEDIUM-severity alert on a system with very high criticality (the payment system during launch, from Reading 5) and high confidence can and should outrank a HIGH-severity alert on a low-criticality asset, or a CRITICAL-severity alert where confidence is genuinely low because of an obvious, documented benign explanation. This isn't ignoring the product's severity score — it's refusing to let that one input be the whole decision.\n\n` +
        `**Writing down why you deprioritized something**\n\n` +
        `The final habit this room asks you to build: whenever you consciously rank something lower than its raw severity label would suggest, write down why, briefly, in the ticket or triage note — which asset-context factor drove the decision, and what evidence supports it (an isolated VLAN, a confirmed change ticket, a documented low-value asset). This turns an invisible judgment call into a reviewable decision: a teammate, a shift handover, or an auditor looking at the same ticket later can see exactly why a CRITICAL-labeled alert sat lower in the queue than a MEDIUM one, instead of just seeing that it did.`,
      diagram:
        "flowchart TD\n" +
        "  A[Alert Severity -- from the product] --> D{Combine}\n" +
        "  B[Asset Criticality -- holds/controls/who/exposure] --> D\n" +
        "  C[Confidence -- how sure this is real] --> D\n" +
        "  D --> E[Analyst-assigned Priority]\n" +
        "  E --> F1[MEDIUM severity + payment system during launch = Priority 1]\n" +
        "  E --> F2[HIGH severity + isolated, decommissioned lab box = Priority lower]",
      diagramCaption: "Severity times criticality times confidence -- not severity alone",
    },
    {
      type: "ordering",
      id: "asset-o1",
      heading: "Rank These Five Concurrent Alerts",
      instructions:
        "Five alerts land in the queue at the same time. Rank them from highest to lowest priority using asset criticality, blast radius, exposure, and business context — not the severity label the product assigned.",
      items: [
        { id: "exec-laptop", text: "HIGH severity malware detection on an executive's laptop that holds saved VPN credentials and standing admin access to the CI/CD pipeline" },
        { id: "payment-launch", text: "MEDIUM severity suspicious PowerShell execution on the production payment-processing server, during the first hours of a live product launch" },
        { id: "guest-wifi", text: "CRITICAL severity (per the product) anomalous login on an isolated guest Wi-Fi captive-portal server with no route to any production system" },
        { id: "printer-quarantined", text: "HIGH severity malware automatically detected and quarantined by AV on a shared marketing team print server holding no sensitive data" },
        { id: "lab-scan", text: "LOW severity port scan against a decommissioned test server sitting in an isolated lab VLAN" },
      ],
      correct_order: ["exec-laptop", "payment-launch", "guest-wifi", "printer-quarantined", "lab-scan"],
      explanation:
        "Raw severity labels alone would put the guest Wi-Fi CRITICAL alert first and the payment-server MEDIUM alert near the bottom — exactly backwards. The executive's laptop ranks first because of blast radius: standing CI/CD admin access and saved VPN credentials mean a successful compromise reaches far beyond the laptop itself. The payment server ranks second on business context: a MEDIUM alert during a live launch, on a system that directly touches revenue and payment data, outranks alerts on lower-value assets regardless of the product's label. The guest Wi-Fi alert, despite its CRITICAL label, drops to third once exposure and blast radius are considered — isolated, with no path to anything that matters, it still needs review but not urgent action. The quarantined printer detection is already auto-contained and touches no sensitive data, so it ranks lower still. The decommissioned lab box ranks last: lowest technical severity, isolated, no production role — exactly the shape of a finding to log and move past, not chase first.",
      xp: 40,
    },
    {
      type: "matching",
      id: "asset-m1",
      heading: "Match Each Asset Type to Why Its Blast Radius Is Large (or Small)",
      instructions: "Match each asset type to the reasoning that explains its blast radius.",
      pairs: [
        { id: "dc", left: "Domain Controller", right: "Controls authentication for every identity in the domain; a compromise here can be leveraged against anything that trusts domain logons" },
        { id: "hv", left: "Hypervisor", right: "Sits below every guest VM's own security controls, so a compromise can affect every VM it hosts at once — a force multiplier, not one host among many" },
        { id: "bk", left: "Backup infrastructure", right: "Holds the organization's ability to recover after an incident; compromising it can remove the safety net a ransomware response depends on" },
        { id: "ci", left: "CI/CD pipeline server", right: "Can push code into every system that trusts its build output, giving an attacker a path into production far beyond the pipeline server itself" },
        { id: "jh", left: "Jump host / bastion", right: "Is the trusted hop used to reach segmented networks, so compromising it can bypass the segmentation it was meant to protect" },
        { id: "lab", left: "Isolated lab VM with no production connectivity", right: "Has almost nowhere to go from a compromise, since it holds no sensitive data and has no trust relationship with production systems" },
      ],
      explanation:
        "Blast radius is always about what a full compromise of THIS asset hands the attacker next — identity infrastructure, every guest VM, recovery capability, deployment trust, or a bypass of segmentation, versus, at the low end, nothing beyond itself. Criticality isn't only about what an asset holds; very often it's almost entirely about what it controls or bridges.",
      xp: 40,
    },
    {
      type: "flag",
      id: "asset-f1",
      prompt:
        "Look at Log Analysis 1, the failed-logon burst against DC02. How many distinct accounts were targeted from the same source IP in the two-minute window described? Enter the exact number.",
      answer: "14",
      hint: "It's stated in the log analysis task's description field.",
      xp: 25,
    },
  ],
};

export const roomsBatch22 = [malwareTypesRoom, assetContextRoom];
