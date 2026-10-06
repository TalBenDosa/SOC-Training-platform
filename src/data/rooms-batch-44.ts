/**
 * Learning Rooms — Batch 44
 *
 * Closes a P1 coverage gap: MITRE ATT&CK's T1219 (Remote Access Software,
 * Command and Control tactic, TA0011) is practised in the "Callback Vishing —
 * RMM Install to Hands-on-Keyboard Discovery" scenario pack
 * (src/lib/sim/scenario-packs/vishingRmm.ts) but was never taught as its own
 * subject in any room or lesson. There is no separate theory lesson for this
 * topic, so every reading task here carries the full theoretical depth —
 * definitions, real vendor names, real domains, and two documented case
 * studies (Storm-1811/Quick Assist/Black Basta, and CVE-2024-1709/
 * ConnectWise ScreenConnect).
 *
 * Rooms in this batch:
 *  1. rmm-abuse-remote-access-tools
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK T1219, Remote Access Software (attack.mitre.org/techniques/T1219/)
 *  - CISA AA23-320A, Scattered Spider advisory (cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
 *  - Microsoft Security Blog, "Threat actors misusing Quick Assist" (May 15 2024)
 *  - Palo Alto Unit 42 threat brief, CVE-2024-1708 / CVE-2024-1709 (ConnectWise ScreenConnect)
 *  - TeamViewer's own "Ports and URLs used by TeamViewer" knowledge-base article
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — RMM Abuse & Remote Access Tools
// ===========================================================================

// Log-analysis event: an unsanctioned TeamViewer session from an Accounts
// Receivable workstation at a logistics company whose only licensed RMM
// (Remote Monitoring and Management) tool is ConnectWise ScreenConnect.
const teamViewerProxyEvent: TelemetryEvent = {
  id: "evt-rmm-la1-001",
  ts: "2026-07-14T15:47:02.000Z",
  source: "proxy",
  vendor: "Zscaler Internet Access",
  event_type: "net_connection",
  severity: "high",
  mitre_technique: "T1219",
  mitre_tactic: "Command and Control",
  hostname: "WKS-CF-118",
  user_email: "d.abara@cascadiafreight.com",
  user_title: "Accounts Receivable Specialist",
  src_ip: "10.44.6.118",
  dst_port: 5938,
  protocol: "tcp",
  description:
    "Zscaler recorded an outbound TCP/5938 connection from WKS-CF-118 to master7.teamviewer.com, three minutes after d.abara's line received an inbound call routed through the company switchboard requesting IT assistance. Cascadia Freight's only sanctioned remote-support tool is ConnectWise ScreenConnect.",
  raw: {
    "zscaler.action": "Allowed",
    "zscaler.reason": "Category allowed",
    "zscaler.login": "d.abara",
    "zscaler.hostname": "master7.teamviewer.com",
    "zscaler.urlcategory": "Remote Access Tools",
    "zscaler.appname": "TeamViewer",
    "zscaler.cip": "10.44.6.118",
    "zscaler.serverip": "84.116.239.14",
    "zscaler.destport": "5938",
    "zscaler.respsize": 96420,
    "session.bytes": 96420,
    "user.name": "d.abara",
    "user.email": "d.abara@cascadiafreight.com",
  },
};

// Analyst-choice control case: the FP a broad "any RMM traffic" rule
// guarantees — the sanctioned ScreenConnect tool, run by a known IT
// technician against a ticket the user opened herself.
const screenConnectSanctionedEvent: TelemetryEvent = {
  id: "evt-rmm-ac1-001",
  ts: "2026-07-09T10:12:00.000Z",
  source: "proxy",
  vendor: "Zscaler Internet Access",
  event_type: "net_connection",
  severity: "informational",
  hostname: "WKS-CF-055",
  user_email: "r.tolentino@cascadiafreight.com",
  user_title: "Dispatch Coordinator",
  src_ip: "10.44.6.55",
  dst_port: 443,
  protocol: "tcp",
  description:
    "Zscaler recorded an outbound TCP/443 connection from WKS-CF-055 to cascadia.hostedrmm.com, Cascadia Freight's own self-hosted ConnectWise ScreenConnect instance, ten minutes after r.tolentino opened help-desk ticket SD-88231 through the IT portal.",
  it_verify_result: "confirmed",
  it_verify_message:
    "IT confirms ticket SD-88231 was opened by r.tolentino herself through the self-service portal, requesting help with a printer-mapping issue. The session was operated by IT technician m.delacroix, whose account is one of the two named technician accounts authorized to drive ScreenConnect sessions at Cascadia Freight. ScreenConnect is the company's only licensed RMM tool and cascadia.hostedrmm.com is its own dedicated cloud instance.",
  raw: {
    "zscaler.action": "Allowed",
    "zscaler.reason": "Category allowed",
    "zscaler.login": "r.tolentino",
    "zscaler.hostname": "cascadia.hostedrmm.com",
    "zscaler.urlcategory": "Remote Access Tools",
    "zscaler.appname": "ConnectWise ScreenConnect",
    "zscaler.cip": "10.44.6.55",
    "zscaler.serverip": "162.220.11.4",
    "zscaler.destport": "443",
    "zscaler.respsize": 41280,
    "session.bytes": 41280,
    "user.name": "r.tolentino",
    "user.email": "r.tolentino@cascadiafreight.com",
  },
};

const rmmAbuseRoom = {
  id: "rmm-abuse-remote-access-tools",
  title: "RMM Abuse & Remote Access Tools: When the Legitimate Tool Is the Attack",
  description:
    "Remote Monitoring and Management (RMM) software — AnyDesk, TeamViewer, ConnectWise ScreenConnect, Atera, Splashtop, and Windows' own built-in Quick Assist — is exactly what IT help desks use every day, and exactly what attackers increasingly ride into a network as MITRE ATT&CK technique T1219 (Remote Access Software, Command and Control tactic). Learn how a signed, legitimate binary becomes an intrusion channel, two real documented case studies (Storm-1811/Quick Assist/Black Basta and the CVE-2024-1709 ConnectWise ScreenConnect authentication bypass), and the allowlist discipline that is the only detection strategy that actually works against this technique.",
  difficulty: "intermediate" as const,
  category: "Threat Detection",
  estimatedMinutes: 65,
  xp: 230,
  icon: "\ud83d\udda5\ufe0f",
  prerequisites: ["endpoint-security-fundamentals", "commodity-initial-access", "dns-investigation"],
  tasks: [
    // ── Reading 0: what RMM is, and T1219 ─────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r0",
      heading: "What Is RMM, and Why It Gets Its Own ATT&CK Technique",
      content:
        "RMM stands for Remote Monitoring and Management: software that lets an IT department or an MSP (Managed Service Provider — a third-party company that runs IT for other organizations) remotely view, control, and manage a computer without a technician being physically present. Every large IT operation depends on some version of it for patching, troubleshooting, and support.\n\n" +
        "It is worth separating RMM from remote access that is built directly into an operating system. RDP (Remote Desktop Protocol) is Microsoft's own protocol, tunnelling a full desktop session over TCP port 3389, and it needs network-level reachability — an open port and a valid credential. SSH (Secure Shell) is the equivalent for Linux/Unix systems, over port 22. Third-party RMM and remote-support tools — AnyDesk, TeamViewer, ConnectWise ScreenConnect, Atera, Splashtop, LogMeIn, N-Able, SimpleHelp, and Microsoft's own built-in Quick Assist — work differently: the client on the endpoint dials OUT to a vendor-operated cloud relay over an ordinary outbound connection, and the two ends of the session meet there. That means no inbound firewall rule is usually needed at all, and the traffic looks, at the network level, like any other outbound HTTPS-family connection to a real company's servers.\n\n" +
        "Every one of these products is entirely legitimate and in daily production use. Every one of them can also become an attacker's live, interactive channel into an environment they do not otherwise control. MITRE ATT&CK tracks this dual nature as **T1219, Remote Access Software**, which sits on the **Command and Control tactic (TA0011)** — because once the tool is running and connected, it gives an outside operator a real-time channel to type commands and see the screen, and there is nothing about the network traffic itself that marks it as hostile. T1219 has three sub-techniques: **T1219.001, IDE Tunneling** (abusing a development tool's own tunneling feature), **T1219.002, Remote Desktop Software** (the GUI remote-control products this room focuses on), and **T1219.003, Remote Access Hardware** (physical KVM-over-IP — Keyboard, Video, Mouse over Internet Protocol — devices). Everything in this room is about T1219.002: how it lands on a host, what it looks like in the logs, and how an analyst tells a legitimate support session from an intrusion when both use the exact same class of software.",
      checkpoint: {
        question: "Which MITRE ATT&CK tactic does T1219 (Remote Access Software) belong to, and why?",
        options: [
          "Command and Control (TA0011) — once the tool is connected, it gives an outside operator a live, interactive channel into the environment",
          "Persistence — because RMM software, once installed, is designed specifically to survive a reboot and cannot be used for anything else",
          "Discovery — because attackers primarily use RMM tools to run whoami and net commands, with no interactive control involved",
          "Initial Access — because installing an RMM client is, by ATT&CK's own definition, always the very first step of any intrusion",
        ],
        answer: 0,
        explanation: "T1219 sits on Command and Control (TA0011) because its defining behavior is giving an outside operator a live interactive session into the environment — that is what a command-and-control channel is. Persistence is a separate tactic for surviving reboots/logoffs, which an RMM client may incidentally provide but is not what earns it its own technique ID. Discovery describes reconnaissance commands, which typically happen THROUGH an RMM session rather than being what the technique itself describes. RMM is one of many possible initial-access vectors' follow-on tooling, not a required first step of every intrusion.",
      },
      xp: 5,
    },

    // ── Reading 1: why attackers prefer it ────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r1",
      heading: "Why Attackers Prefer a Legitimate Tool Over Custom Malware",
      content:
        "If an attacker's goal is a live channel into a compromised environment, they have a choice: build and host custom command-and-control malware, or ride a legitimate RMM product that a real vendor already built, signed, and operates. Increasingly, they choose the second option, for reasons that are entirely practical rather than exotic.\n\n" +
        "**It is code-signed by a real vendor.** A valid, trusted code signature from AnyDesk Software GmbH or ConnectWise, LLC passes exactly the checks that block unsigned or unknown binaries — the signature says the file is genuinely what it claims to be, and it is; nothing about the file itself is fraudulent.\n\n" +
        "**It is already an allowed application almost everywhere.** Because these products are genuinely useful and widely deployed, most antivirus and EDR (Endpoint Detection and Response) baselines do not flag them by static signature the way they would flag a known malware family.\n\n" +
        "**Its traffic blends in.** The connection rides the vendor's own cloud relay over an ordinary outbound port, indistinguishable at the network level from any of the thousands of legitimate support sessions happening at other organizations that same minute — network indicator-of-compromise lists built around known-bad C2 infrastructure have nothing to match against a real vendor's own servers.\n\n" +
        "**It costs nothing to build.** There is no bespoke implant to write, no attacker-owned C2 server to rent, host, and eventually lose to takedown — just an installer, and often a 'portable' or quick-support build that needs no installation step and no administrator rights to run.\n\n" +
        "**It hands over full interactive control immediately**, inheriting whatever privilege the already-logged-in user's session holds, with zero custom code required. CISA's own advisory on the threat group Scattered Spider states this tension directly: 'the use of these legitimate tools alone is not indicative of malicious activity' — which is exactly why this is a genuinely hard detection problem, not a simple one.",
      xp: 5,
    },

    // ── Question 1 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "rmm-q1",
      question:
        "Per this room's reading, what is the single biggest practical advantage a signed, legitimate RMM tool gives an attacker over building custom command-and-control malware?",
      options: [
        "RMM binaries are exempt from EDR inspection by default, because vendors pre-allowlist remote-support software to avoid breaking IT workflows",
        "It arrives vendor-signed, blends into outbound traffic over the vendor's own infrastructure, and needs no custom development to give full control",
        "RMM sessions are encrypted with vendor-held keys, so defenders cannot log any process or session activity on the endpoint itself",
        "RMM installers elevate to SYSTEM automatically on first run, giving more privilege than a custom implant could obtain on its own",
      ],
      answer: 1,
      explanation:
        "The reading names several concrete, compounding advantages — a valid vendor signature, traffic that rides real infrastructure and blends with legitimate sessions, and full interactive control with no development effort. EDR is not blanket-exempt from RMM tools (detection is this room's later subject), endpoint process and service telemetry is still logged regardless of session encryption, and a portable RMM build inherits only the logged-on user's privilege rather than escalating by itself.",
      xp: 15,
    },

    // ── Reading 2: three delivery patterns ────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r2",
      heading: "Three Ways an RMM Tool Actually Gets Onto an Endpoint",
      content:
        "**Pattern A — callback vishing.** Vishing (voice phishing) is a phone call in which an attacker impersonates IT security, a help desk, or Microsoft support, and talks a real employee into downloading and running a remote-support tool and sharing the session. This is the pattern behind the Storm-1811/Quick Assist case study in the next reading, and it needs no exploit at all — only a convincing phone call and an employee willing to help.\n\n" +
        "**Pattern B — ClickFix-style paste-and-run.** This platform's Commodity Initial-Access room already teaches ClickFix in depth: a fake CAPTCHA or verification page tricks a user into pasting a command into the Windows Run dialog, which then executes with no file ever crossing the network as a scannable object. The mechanics are identical to what that room covers — only the payload class differs, since the pasted command can just as easily silently install an RMM client as it can install commodity malware.\n\n" +
        "**Pattern C — attacking the RMM console itself.** Instead of tricking one end user, an attacker can exploit a vulnerability in the RMM product's own SERVER software — the console an MSP or IT team uses to manage every endpoint it controls. Compromising that one server can hand over fleet-wide access in a single step, covered in depth in this room's CVE-2024-1709 case study.\n\n" +
        "That these patterns are systemic, not tied to one attacker's favorite tool, is documented directly: CISA's advisory AA23-320A on the threat group Scattered Spider names an entire toolset used for exactly this purpose — AnyDesk, TeamViewer, Splashtop, Fleetdeck.io, Level.io, Pulseway, Tactical.RMM, ScreenConnect, Tailscale, Teleport.sh, and Ngrok. Eleven distinct legitimate products, named in one federal advisory, all abused by the same threat group for the same purpose: a live channel into a victim network that doesn't look like malware.",
      checkpoint: {
        question: "What is the key structural difference between Pattern A (callback vishing) and Pattern C (attacking the RMM console)?",
        options: [
          "Pattern A relies on a phone call that talks one employee into installing the tool themselves; Pattern C instead exploits a flaw in the RMM server software directly, needing no victim at all",
          "There is no real structural difference between the two patterns at all — both invariably rely on the exact same fake-CAPTCHA verification web page to succeed against a victim",
          "Pattern A only ever targets employees working from home, while Pattern C, according to CISA's advisory, only ever targets large government agencies directly",
          "Pattern C can only succeed if the attacker already holds a valid domain administrator credential before the underlying vulnerability can be exploited in any way",
        ],
        answer: 0,
        explanation: "Pattern A is social engineering aimed at one employee, who installs the tool themselves after being talked into it by phone. Pattern C instead exploits the RMM server's own software flaw, requiring no victim interaction and giving access to every endpoint the compromised server manages — a fleet-wide outcome from a single exploited server. Pattern A does not depend on a fake CAPTCHA page (that is Pattern B, ClickFix). Neither pattern is restricted to a specific victim category by the advisory, and the CVE-2024-1709 case study covered later shows the exploit itself requires no prior credentials — that is the entire point of an authentication-bypass vulnerability.",
      },
      xp: 5,
    },

    // ── Reading 3: Storm-1811 case study ──────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r3",
      heading: "Case Study: Storm-1811 and the Quick Assist Ransomware Chain",
      content:
        "In May 2024, Microsoft's own Security Blog documented a threat actor it tracks as **Storm-1811** abusing **Quick Assist** — a remote-assistance feature built directly into Windows itself, not third-party software, that lets one person share their screen with, or grant full remote control to, someone else for troubleshooting.\n\n" +
        "The chain Microsoft observed, since mid-April 2024: first, the group **email-bombed** the target — subscribing the victim's email address to a large number of legitimate mailing-list subscription services, flooding their inbox with an overwhelming volume of unwanted mail. Next, an operator **called the victim by phone**, impersonating Microsoft technical support or the target organization's own IT/help desk, offering to fix the 'spam problem' the victim was now experiencing. During that call, the victim was talked into opening Quick Assist and granting remote control to the caller.\n\n" +
        "Once connected, Storm-1811 delivered further malicious tools onto the host, performed domain enumeration to map the environment, moved laterally across the network, and ultimately deployed **Black Basta ransomware**, using **PsExec** — a legitimate Sysinternals (a genuine Microsoft-owned toolset) utility that lets an administrator remotely execute a program on another Windows machine — to run the ransomware payload across multiple hosts at once.\n\n" +
        "Microsoft's own remediation guidance is direct: uninstall or block Quick Assist across the environment entirely if it is not a tool the organization actually uses for legitimate support, and deploy privileged access management to limit what a compromised session can reach. The teaching point that matters most here: this is the 'abuse a feature that already ships with the operating system' variant of T1219 — there is no download step at all, because every modern Windows installation already has Quick Assist present and ready to use.",
      xp: 5,
    },

    // ── Question 2 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "rmm-q2",
      question:
        "According to Microsoft's own reporting on Storm-1811, what was the FIRST step of the chain, before the vishing phone call was ever placed?",
      options: [
        "Email-bombing the target — subscribing their address to many mailing lists to flood the inbox and create a pretext for the call",
        "Silently exploiting a Quick Assist vulnerability to open a session, with the vishing call added afterward as cover",
        "Compromising the organization's ScreenConnect server to push Quick Assist onto managed endpoints ahead of the call",
        "Spearphishing the victim with a malicious Office attachment whose loader staged tooling before the phone call",
      ],
      answer: 0,
      explanation:
        "Microsoft's reporting describes email-bombing as the opening move: flooding the target's inbox with subscription spam, which sets up the pretext for the following vishing call offering to 'fix' the problem. Quick Assist itself is not exploited via a vulnerability in this chain — the victim is talked into opening it and granting access voluntarily. ScreenConnect and CVE-2024-1709 belong to this room's separate case study on attacking the RMM console directly, not the Storm-1811/Quick Assist chain, and the reporting describes no attachment-based loader ahead of the call. Ransomware deployment was the LAST stage of the chain, after lateral movement.",
      xp: 15,
    },

    // ── Reading 4: CVE-2024-1709 case study ───────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r4",
      heading: "Case Study: Attacking the RMM Console Itself — CVE-2024-1709",
      content:
        "In February 2024, two related vulnerabilities were disclosed in **ConnectWise ScreenConnect** — the same RMM product used as the sanctioned tool elsewhere in this room — affecting self-hosted version 23.9.7 and earlier. **CVE-2024-1708** is a path-traversal flaw (CVSS 8.4, High) that could enable remote code execution or access to sensitive files. **CVE-2024-1709** is an authentication-bypass flaw (CVSS 10.0, Critical) that let a completely unauthenticated attacker reach an already-configured server's own initial setup wizard and create a brand-new administrator account with no credentials required at all.\n\n" +
        "Because ScreenConnect's admin console controls every single endpoint that server manages, compromising the server itself — rather than tricking one end user by phone — handed attackers fleet-wide access in one step. ConnectWise's own cloud-hosted instances (on the screenconnect.com and hostedrmm.com domains) were automatically remediated on 19 February 2024; self-hosted deployments needed manual patching to version 23.9.8.\n\n" +
        "**CISA (the Cybersecurity and Infrastructure Security Agency)** added CVE-2024-1709 to its **Known Exploited Vulnerabilities (KEV) catalog**, which under **Binding Operational Directive 22-01** gave U.S. federal civilian agencies a mandatory remediation deadline of 29 February 2024 — an unusually short window that reflected how actively the flaw was already being exploited in the wild. Metasploit (a widely used penetration-testing framework) shipped a working, unauthenticated remote-code-execution module for it within days of disclosure.\n\n" +
        "Observed post-exploitation activity included ransomware built from a leaked LockBit 3.0 builder, Cobalt Strike beacons (a commercial penetration-testing tool frequently abused as real C2 infrastructure), information-stealing malware — and, notably for this room's subject, attackers using the compromised console's own trusted access to push out entirely DIFFERENT RMM tools, including malicious AnyDesk and SimpleHelp installers, as their own follow-on access mechanism.",
      checkpoint: {
        question: "Why did CVE-2024-1709 pose a bigger single-incident risk than a typical vishing case targeting one employee?",
        options: [
          "It compromised the RMM server/console directly, giving fleet-wide access to every endpoint that server managed, rather than access to just one machine",
          "It only affected home users running the free consumer edition of ConnectWise ScreenConnect, which made it a low-priority issue for businesses",
          "It required physical access to the server's hardware, so remote exploitation was never actually possible for any attacker",
          "CISA determined the vulnerability could never be exploited without a valid administrator password already in hand",
        ],
        answer: 0,
        explanation: "The critical distinction is scope: exploiting the server's own authentication bypass gave an attacker admin control over the console that manages every endpoint it oversees — a fleet-wide outcome from one exploited server, unlike a vishing call that compromises one employee's machine. ScreenConnect is a business/MSP product, not a consumer freeware tool with a separate low-priority edition. The vulnerability was remotely, unauthenticatedly exploitable — that is precisely what CVSS 10.0 and an unauthenticated Metasploit module mean — and CISA's KEV listing with a short mandatory deadline reflects active remote exploitation, not a requirement for prior credentials.",
      },
      xp: 5,
    },

    // ── Reading 5: concrete signs of abuse ─────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r5",
      heading: "The Concrete Signs: What Actually Points to Abuse",
      content:
        "Five concrete signals separate an abusive RMM session from a routine support one, and none of them is the mere presence of the software.\n\n" +
        "**1. Tool-identity mismatch.** A process or connection for an RMM product that is simply not the organization's sanctioned tool at all — TeamViewer or AnyDesk appearing where the licensed, approved tool is ConnectWise ScreenConnect, for instance.\n\n" +
        "**2. Duplicate coverage.** Both the sanctioned tool AND a second, unrecognized one present on the same host — a strong sign something outside the normal deployment process introduced the second copy.\n\n" +
        "**3. Install and run location.** A managed RMM client is installed by IT under a standard Program Files path and runs as a Windows service under the SYSTEM account. An attacker-introduced copy is far more often a 'portable' build launched directly from a Downloads or Desktop folder, or a Temp directory, running interactively under the logged-on user's own account rather than as a service.\n\n" +
        "**4. Timing.** Installation happening outside any scheduled deployment or change window — very often minutes after a phone call, an email click, or a paste-and-run event, as this room's earlier readings describe.\n\n" +
        "**5. Outbound destination.** A connection to a relay domain belonging to a DIFFERENT RMM vendor than the one the organization actually licenses. Real, documented relay/domain patterns worth recognizing: AnyDesk's download.anydesk.com and its *.net.anydesk.com relay family; TeamViewer's master*.teamviewer.com and router*.teamviewer.com, over TCP port 5938 with a documented fallback to TCP/443 when 5938 is blocked; ConnectWise ScreenConnect's own screenconnect.com and hostedrmm.com cloud domains; and vendor-specific domains for Atera, Splashtop, and LogMeIn. None of these domains is inherently malicious — every one belongs to a real, legitimate company — so seeing one is a prompt to check signals #1 through #4, never an automatic verdict by itself.",
      xp: 5,
    },

    // ── Question 3 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "rmm-q3",
      question:
        "An EDR alert fires for a process named AnyDesk.exe running interactively (not as a service) from C:\\Users\\<user>\\Downloads\\AnyDesk.exe, on a host where the organization's sanctioned RMM tool is ScreenConnect, installed under Program Files and running as a SYSTEM service. Which detail from this room's reading is the strongest standalone indicator of concern?",
      options: [
        "The process name AnyDesk.exe, since AnyDesk appears in CISA advisories and is therefore malicious wherever it runs",
        "A tool other than the licensed ScreenConnect, running interactively from Downloads instead of as a managed service under Program Files",
        "The Downloads path alone, since any executable launched from a user profile folder is malicious regardless of product",
        "A valid AnyDesk Software GmbH signature on the binary, which confirms the session is authorized and needs no further checks",
      ],
      answer: 1,
      explanation:
        "This combines two of the five concrete signals directly: tool-identity mismatch (AnyDesk versus the organization's actual sanctioned ScreenConnect) and install-location mismatch (an interactive user-run copy from Downloads versus a managed SYSTEM service under Program Files). The tool name alone is not a verdict — AnyDesk is a legitimate product used by countless organizations, and appearing in an advisory does not make every instance malicious. A Downloads path on its own is only one weak signal, and the strongest indicator is the combination of mismatches. A valid vendor signature, as reading r1 establishes, says the file is authentic — it says nothing about whether running it here is authorized.",
      xp: 20,
    },

    // ── Reading 6: allowlist discipline ────────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r6",
      heading: "Detection Discipline: The Allowlist, Not the Tool",
      content:
        "Trying to block 'remote access software' as a whole category fails immediately, because that exact category of software is what the organization's own IT help desk legitimately depends on every single day. The only detection model that actually works for T1219 is an **allowlist** built on three elements together: (a) which specific RMM product the organization has actually licensed and centrally deployed — ideally exactly one; (b) which accounts are authorized to operate it — named IT/help-desk technician accounts, not arbitrary end-user or service accounts; and (c) the install path and service identity it should always show when legitimate. Anything outside that triad — a different product, an unexpected operator account, or a portable/user-run instance where a managed service is expected — is the alert worth working.\n\n" +
        "Three data sources layer together to make this workable in practice. EDR (Endpoint Detection and Response) supplies process- and service-creation telemetry: what actually ran, from where, and as whom. Proxy, firewall, and DNS logs supply the outbound-connection view: sessions to any of the RMM relay-domain families named in the previous reading, checked against the allowlist rather than flagged just because they touch a known RMM domain. And the organization's ITSM (IT Service Management) ticketing system supplies provenance: does a ticket exist naming this exact technician, this exact session, and this exact timeframe? This platform's `it_verify_result` mechanism used elsewhere in log analysis models exactly this check. A session on a tool the allowlist does not recognize, operated by an account with no help-desk role, with no matching ticket, is about as strong a combined signal as detection engineering gets for this technique.",
      diagram:
        "flowchart TD\n" +
        "  A[RMM process or connection observed] --> B{Matches the allowlisted\\ntool AND an authorized\\ntechnician account?}\n" +
        "  B -->|Yes| C{Matching ITSM ticket\\nexists for this session?}\n" +
        "  C -->|Yes| D[Confirm and close -- expected IT activity]\n" +
        "  C -->|No| E[Investigate -- verify with IT before closing]\n" +
        "  B -->|No, unlisted tool or\\nunexpected account| F[Escalate -- check host for\\nfollow-on discovery/lateral activity]\n",
      diagramCaption: "The allowlist-plus-ticket decision flow this reading teaches",
      checkpoint: {
        question: "Why does trying to blocklist 'remote access software' as a whole category fail as a detection strategy, per this reading?",
        options: [
          "Because that exact category of software is what the organization's own IT help desk legitimately relies on every day, making a category-wide block impossible to operate without breaking real support work",
          "Because remote access software is not capable of being detected by any modern EDR or proxy product currently on the market",
          "Because MITRE ATT&CK does not formally classify remote access software abuse as a real technique, so no detection rule can reference it",
          "Because every remote access product changes its process name and network signature on a randomized daily schedule, defeating any static rule",
        ],
        answer: 0,
        explanation: "The reading's core point is that a whole-category block is unworkable precisely because IT's own legitimate daily use of this exact category of software would be blocked along with any attacker's use of it — the allowlist (specific product + account + install pattern) is what actually distinguishes abuse. EDR and proxy tools absolutely can and do detect this traffic, as this room's own log-analysis task shows. T1219 is a real, documented ATT&CK technique. And legitimate RMM products do not randomize their process names or network signatures daily — their traffic is recognizable, which is exactly why the allowlist approach works.",
      },
      xp: 5,
    },

    // ── Reading 7: investigation workflow ──────────────────────────────────
    {
      type: "reading" as const,
      id: "rmm-r7",
      heading: "Investigating an RMM Alert: The Analyst's Workflow",
      content:
        "When an 'unrecognized remote-access tool' alert fires, a working investigation moves through the same sequence every time.\n\n" +
        "**1. Identify the product, version, and process path.** A managed install directory running as a SYSTEM service versus a portable executable launched by a user account is informative before anything else is even checked.\n\n" +
        "**2. Check it against the allowlist.** Is this the organization's sanctioned tool at all.\n\n" +
        "**3. Identify the operating account.** A named IT technician with a documented support role, or an ordinary end user or service account with no such history.\n\n" +
        "**4. Check the ITSM ticketing system** for a matching, currently open or recently closed ticket referencing this exact session.\n\n" +
        "**5. Check the destination domain or IP** the tool connected to against the known relay-domain families for major RMM vendors, and against threat intelligence — a brand-new, rarely seen destination is a stronger signal than an established vendor relay that thousands of legitimate customers also use.\n\n" +
        "**6. Walk the host's process tree** for anything spawned by or alongside the RMM session — discovery commands such as whoami, net group \"Domain Admins\", or nltest, credential-access tooling, or lateral-movement utilities such as PsExec, are the sign that a session has moved from merely 'looking' to actively acting, exactly as this platform's Discovery room teaches for reconnaissance generally.\n\n" +
        "**7. Reach and record a verdict.** Confirmed IT activity closes clean with the ticket referenced. Anything else escalates to containment: isolating the host to sever the live session, resetting the targeted account's credentials, removing the unauthorized tool, and hunting for whatever it may have staged.",
      xp: 5,
    },

    // ── Question 4 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "rmm-q4",
      question:
        "You are investigating an RMM session with no matching ITSM ticket, on a tool that is not the organization's sanctioned product, operated by an ordinary end-user account. The host's process tree shows the RMM process as the parent of cmd.exe, which ran net group \"Domain Admins\" /domain two minutes into the session. Per this room's workflow, what does this specific detail add to the case?",
      options: [
        "Little new weight — the session was already unsanctioned and unticketed, so one more command adds nothing to the existing verdict",
        "It attributes the session to a nation-state actor, since domain-group enumeration is rarely seen in financially motivated intrusions",
        "It shows the operator moved from holding a session to domain reconnaissance, which pushes the case toward escalation and containment",
        "It points back toward IT activity, since technicians routinely query Domain Admins, which lowers the priority of the case",
      ],
      answer: 2,
      explanation:
        "Steps 1-4 of the workflow already flagged this session as suspicious (unsanctioned tool, no ticket, ordinary account); step 6 asks specifically whether follow-on activity shows discovery or lateral-movement behavior. A privileged-group enumeration command spawned by the RMM session is exactly that signal — the same discovery step documented in this room's Storm-1811 and vishing-pattern case studies — and it materially raises confidence toward escalation and containment, not a lower priority. It does not by itself identify WHO the attacker is (nation-state versus criminal), and it is the opposite of evidence for a false-positive/benign IT explanation, since a routine IT session already lacking a ticket now also shows unrequested privileged-group reconnaissance.",
      xp: 20,
    },

    // ── Log analysis ────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "rmm-la1",
      heading: "Investigate: An Unsanctioned TeamViewer Session on WKS-CF-118",
      context:
        "Cascadia Freight's only licensed remote-support tool is ConnectWise ScreenConnect, self-hosted at cascadia.hostedrmm.com and operated only by two named IT technician accounts. The proxy record below shows outbound traffic from an Accounts Receivable workstation. The IT service-management system shows no ticket referencing any session on this host today.",
      event: teamViewerProxyEvent,
      questions: [
        {
          question:
            "Given Cascadia Freight's allowlist (ScreenConnect only, two named technician accounts), which single field in this record is the clearest tool-identity mismatch?",
          options: [
            "zscaler.action, reading \"Allowed\" — showing the proxy permitted the connection, which tells you the session went through but not which product it was",
            "zscaler.appname, reading \"TeamViewer\" — a product that is not Cascadia Freight's sanctioned RMM tool at all, per the allowlist in the context",
            "zscaler.destport, reading \"5938\" — TeamViewer's documented port, which helps confirm the app but is not itself the identity field",
            "zscaler.urlcategory, reading \"Remote Access Tools\" — the correct category, but one that also covers the sanctioned ScreenConnect traffic",
          ],
          answer: 1,
          explanation:
            "zscaler.appname naming TeamViewer is the direct tool-identity mismatch: the allowlist names only ScreenConnect. zscaler.action \"Allowed\" just means the proxy permitted this category — the same value appears on the benign ScreenConnect control case, so it names no product. Port 5938 corroborates that this is TeamViewer but is a property of the traffic, not the field that states the product's identity. The urlcategory \"Remote Access Tools\" is accurate yet also describes Cascadia's own sanctioned ScreenConnect sessions, so it does not single out a mismatch.",
          xp: 15,
        },
        {
          question:
            "Following this room's allowlist-based detection discipline, what is the single most important record to check next before reaching a verdict?",
          options: [
            "Whether TeamViewer's code signature is valid — a valid signature confirms the binary is authentic, not that its use here was authorized",
            "Whether the session used an encrypted transport — but both legitimate and malicious RMM sessions are routinely encrypted",
            "Whether Cascadia Freight's ITSM ticketing system has any ticket referencing this exact session, user, and time window",
            "Whether the destination IP resolves to a residential ISP — a signal for other techniques, not for an allowlist verdict",
          ],
          answer: 2,
          explanation:
            "The allowlist-plus-ticket discipline taught in “Detection Discipline: The Allowlist, Not the Tool” names the ITSM check as the decisive next step: a matching ticket for this exact session, user, and timeframe is what separates confirmed IT activity from an investigation. TeamViewer's signature is almost certainly valid regardless of authorization — a valid signature says the file is authentic, not that its use here is sanctioned. Both legitimate and malicious RMM sessions are routinely encrypted, so encryption distinguishes nothing. A residential-ISP destination matters for other techniques, but it is not what settles an allowlist-based RMM verdict.",
          xp: 20,
        },
      ],
    },

    // ── Analyst choice: FP control case ────────────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "rmm-ac1",
      heading: "Triage: ScreenConnect Session on WKS-CF-055",
      scenario:
        "An alert fires for 'remote-access tool traffic detected' on WKS-CF-055. The underlying rule matches any connection to any known RMM vendor domain, anywhere in the environment, with no allowlist filter. Checking further shows the tool is ConnectWise ScreenConnect — Cascadia Freight's own licensed product — connecting to the company's own self-hosted instance.",
      event: screenConnectSanctionedEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is the allowlist principle applied directly: the tool matches Cascadia Freight's sanctioned RMM product exactly, the destination is the company's own self-hosted ScreenConnect instance (cascadia.hostedrmm.com — not a third-party relay), the operator is a named, authorized IT technician (m.delacroix), and a matching help-desk ticket (SD-88231), opened by the affected user herself, is confirmed by IT. Every element of the allowlist triad checks out, and the it_verify_message confirms it directly.",
      fp_trap:
        "The underlying alert rule fires on ANY connection to ANY known RMM vendor domain, with no allowlist filter at all — meaning it fires identically on the organization's own sanctioned, ticketed, technician-operated support sessions and on a genuine intrusion. Escalating every RMM-domain hit without checking tool identity, operator account, and the ITSM ticket is exactly the false-positive flood this room's detection-discipline reading warns against, and it is also what would eventually train a SOC to stop taking RMM alerts seriously at all.",
      xp: 20,
    },

    // ── Matching task ─────────────────────────────────────────────────────
    {
      type: "matching" as const,
      id: "rmm-m1",
      heading: "Match Each Delivery Pattern, Case Study and Signal to What It Describes",
      instructions:
        "Match each delivery pattern, case study, and detection signal taught in this room to the description that fits it.",
      pairs: [
        { id: "p1", left: "Pattern A — callback vishing", right: "A caller posing as IT or Microsoft support talks an employee into installing and sharing a remote-support tool" },
        { id: "p2", left: "Pattern B — ClickFix-style paste-and-run", right: "A fake verification page gets the user to paste a command into the Run dialog that silently installs an RMM client" },
        { id: "p3", left: "Pattern C — attacking the RMM console", right: "One exploited RMM server hands the attacker every endpoint it manages in a single step" },
        { id: "p4", left: "Storm-1811", right: "Email-bombing, then a fake help-desk call, then Quick Assist, ending in Black Basta ransomware pushed with PsExec" },
        { id: "p5", left: "CVE-2024-1709", right: "A ScreenConnect authentication bypass that let unauthenticated attackers create an administrator account through the setup wizard" },
        { id: "p6", left: "CISA advisory AA23-320A (Scattered Spider)", right: "One advisory naming eleven legitimate remote-access products abused by the same group, from AnyDesk and TeamViewer to Ngrok" },
        { id: "p7", left: "Duplicate-coverage signal", right: "The sanctioned RMM tool and a second, unrecognized remote-access tool are both present on the same host" },
      ],
      explanation:
        "Every pairing comes from this room's readings. The three delivery patterns differ in who is fooled: vishing fools one employee by phone, ClickFix fools one user on a web page, and attacking the console needs no victim at all but yields the whole fleet. Storm-1811 is the Quick Assist case study (built-in Windows feature, no download step), CVE-2024-1709 is the ScreenConnect authentication bypass from the console case study, and AA23-320A shows the problem is systemic rather than one attacker's favourite tool. Duplicate coverage is one of the five concrete abuse signals: a second remote-access tool next to the sanctioned one suggests something outside the normal deployment process introduced it.",
      xp: 25,
    },

    // ── Ordering task ──────────────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "rmm-o1",
      heading: "Order the Investigation Steps for an Unrecognized RMM Alert",
      instructions:
        "Place these seven steps of this room's investigation workflow in the order an analyst actually performs them, from the moment an 'unrecognized remote-access tool' alert fires to reaching a final verdict.",
      items: [
        { id: "step-identify", text: "Identify exactly which RMM product and version this is, and its process path (managed install directory + SYSTEM service, versus a portable executable run by a user)" },
        { id: "step-allowlist", text: "Check the tool against the organization's sanctioned-RMM allowlist" },
        { id: "step-account", text: "Identify the operating account — a named IT technician with a documented support role, or an ordinary end-user/service account" },
        { id: "step-ticket", text: "Check the ITSM ticketing system for a matching ticket referencing this exact session, user, and timeframe" },
        { id: "step-destination", text: "Check the destination domain/IP against known RMM vendor relay-domain families and threat intelligence" },
        { id: "step-tree", text: "Walk the host's process tree for hands-on-keyboard follow-on activity (discovery commands, credential access, lateral-movement tools)" },
        { id: "step-verdict", text: "Reach a verdict: confirm and close as expected IT activity, or escalate to containment (isolate host, sever session, reset credentials, remove the tool)" },
      ],
      correct_order: ["step-identify", "step-allowlist", "step-account", "step-ticket", "step-destination", "step-tree", "step-verdict"],
      explanation:
        "This is the exact sequence this room's investigation-workflow reading teaches: start with what the tool actually is and how it was run, check it against the allowlist, then establish who is operating it and whether a ticket accounts for the session, then widen out to the network destination and the host's own process tree for follow-on activity, and only then reach a verdict. Each step narrows or confirms the picture the previous step built — jumping straight to a verdict without first checking the allowlist, account, and ticket is exactly the mistake this room's false-positive control case is built to correct.",
      xp: 25,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "rmm-f1",
      prompt:
        "A self-hosted ConnectWise ScreenConnect server is running version 23.9.7 and is therefore exposed to the authentication-bypass vulnerability from this room's console case study. According to that case study, which exact version must the administrator upgrade to in order to remediate it? Answer in the exact major.minor.patch format.",
      answer: "23.9.8",
      hint: "The reading 'Case Study: Attacking the RMM Console Itself' states the affected versions and the single version self-hosted deployments had to patch up to.",
      xp: 15,
    },
  ],
};

export const roomsBatch44 = [rmmAbuseRoom];
