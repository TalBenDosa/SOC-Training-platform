import type { RoomExperience } from "./types";

// "Operation Helping Hand" for the "rmm-abuse-remote-access-tools" room.
// Script: docs/campaign/70-rmm-abuse-remote-access-tools.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brookmere Accountants (fictional), not the graded tasks' Cascadia Freight records.
// Signature: Sanctioned or Stowaway? One signed, legitimate remote support tool, used by the
// help desk and by an intruder. A KQL hunt separates them by publisher, install path, parent,
// relay tenant and the ticket behind each session; a spotdiff lays the approved agent's config
// beside a rogue copy. A valid signature proves who made the tool, not who is using it.
// Game mix: hunt + rush + spotdiff.
//
// New task order (the room puts the flag, matching and ordering after the boss, and the boss
// should close the room; f1 belongs with the CVE, m1 with the signs, o1 with the workflow):
// rmm-r0, rmm-r1, rmm-q1 | rmm-r2, rmm-r3, rmm-q2, rmm-r4, rmm-f1 | rmm-r5, rmm-q3, rmm-m1 |
// rmm-r6, rmm-r7, rmm-q4, rmm-o1 | rmm-la1, rmm-ac1
//
// Lab data differs from the graded tasks: the tool is the fictional Quillbridge Remote and the
// unlicensed one the fictional Farlight Viewer, never ScreenConnect, TeamViewer or AnyDesk on a
// host (q3, la1, ac1); the rogue copy is renamed and sits on a Desktop, never Downloads as the
// tell (q3), and the only Downloads copy in the labs is a ticketed one; the proxy drill is a
// firewall traffic log with an app field, never Zscaler (la1); the close-out drill is a
// help-desk rescue of a dead agent, never a printer mapping (ac1); the process-tree drill is
// nltest, never net group (q4); the CVE sheet counts supplier consoles and shows the fixed build
// only as a labelled row, it never asks it (f1); the Storm-1811 chain is shown as a case file and
// sorted by where it leaves a trace, its order is never asked (q2); the case walk runs the seven
// steps on one host with its own wording (o1); the signs and the advisory appear as data on
// Brookmere's own hosts, never as the matching pairs (m1).

export const RMM_ABUSE_REMOTE_ACCESS_TOOLS: RoomExperience = {
  roomId: "rmm-abuse-remote-access-tools",
  codename: "Operation Helping Hand",
  theme: "helpinghand",
  handler: { name: "Sofie Njoroge", role: "Endpoint Security Analyst, Brookmere Accountants" },
  briefing: [
    "Brookmere Accountants. 140 staff, three offices, and the tax files of 2,100 small businesses, one week before filing closes.",
    "On Tuesday morning a thank-you note reached the service desk: 'Thanks for fixing my laptop so quickly.' Nobody on the service desk had touched it.",
    "The session ran on Quillbridge Remote, the tool Brookmere's own technicians use every day. Signed, allowed, and silent in the alert queue.",
    "Sofie Njoroge has to tell the helpers from the stowaway. Learn the tool, read the install, hunt the fleet, and make the call.",
  ],
  mission: "See how remote tools reach a machine and why a signed one beats custom malware, sort how they land, compare an approved agent with a rogue copy, run the allowlist, hunt every session on the fleet, walk one case end to end, then make the ticket call on the graded records.",
  estimate: "~55 min",
  look: { primary: "#f6bd60", secondary: "#84dcc6", warn: "#ef476f" },
  scene: "facilityhelpinghand",
  layout: "facility",
  story: {
    intro: { title: "The Thank-You Note", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-intro-887cb13c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-intro-83c5c040.jpg" },
    afterStation: {
      wayin: { title: "Nobody Called", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-ch2-94c74abc.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-ch2-8e45c7c4.jpg" },
      allowlist: { title: "Only One?", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-ch3-d9d14a23.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-ch3-b4faffc4.jpg" },
      lastcall: { title: "Helping Hand", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-finale-80b8becd.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/rmm-abuse-remote-access-tools/helpinghand-finale-2e351300.jpg" },
    },
  },
  stations: [
    {
      id: "session",
      label: "The Support Session",
      topic: "What RMM is · RDP and SSH compared · T1219 · why attackers borrow a signed tool",
      tagline: "Thanks for the help. What help?",
      building: "reception",
      taskIds: ["rmm-r0", "rmm-r1", "rmm-q1"],
    },
    {
      id: "wayin",
      label: "The Way In",
      topic: "Callback vishing · paste-and-run · attacking the console · Storm-1811 · CVE-2024-1709",
      tagline: "Three doors, and only one needs an exploit",
      building: "archive",
      taskIds: ["rmm-r2", "rmm-r3", "rmm-q2", "rmm-r4", "rmm-f1"],
    },
    {
      id: "signs",
      label: "The Five Signs",
      topic: "Tool mismatch · duplicate coverage · install path · timing · outbound destination",
      tagline: "Same signature. Whose copy?",
      building: "lab",
      taskIds: ["rmm-r5", "rmm-q3", "rmm-m1"],
    },
    {
      id: "allowlist",
      label: "The Allowlist",
      topic: "Product, operator, identity · EDR, proxy and ITSM together · the seven-step workflow",
      tagline: "Is this the only one?",
      building: "control",
      taskIds: ["rmm-r6", "rmm-r7", "rmm-q4", "rmm-o1"],
    },
    {
      id: "lastcall",
      label: "Close or Contain",
      topic: "Reading a record against the allowlist · the ticket check · the verdict",
      tagline: "The rule fired. Now what is it?",
      building: "ticket",
      taskIds: ["rmm-la1", "rmm-ac1"],
      boss: true,
    },
  ],
  personas: {
    "rmm-q1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "The partners want one line on why anyone would use this. Give me the line." },
    "rmm-q2": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Go back to the very start of that chain." },
    "rmm-f1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "The supplier file needs a build number. Which one?" },
    "rmm-q3": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "An alert is open on someone else's estate. What do you weigh first?" },
    "rmm-m1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Put each name with what it did." },
    "rmm-q4": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Read the tree and tell me what changes." },
    "rmm-o1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Same order every time. Show me yours." },
    "rmm-la1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Here's a record from a friend's SOC. Read it, then tell me what you'd pull next." },
    "rmm-ac1": { name: "Sofie Njoroge", role: "Endpoint Security Analyst", line: "Same friend, same rule, another hit. Your call." },
  },
  briefings: {
    // ── r0: what RMM is ──
    "rmm-r0": [
      {
        kind: "sort",
        title: "Inbound Door or Outbound Call?",
        prompt: "RMM means Remote Monitoring and Management: software that lets IT see and control a computer from elsewhere. Orla Brennan, the bookkeeper who wrote the thank-you note, says the session just appeared. Sofie needs to know how it reached the laptop at all. Sort each case by how the connection is made.",
        buckets: [
          { id: "in", label: "Needs a way in: reachable port, valid credential" },
          { id: "out", label: "Client dials out to a vendor relay" },
        ],
        items: [
          { id: "i1", text: "An admin opens a file server's desktop on TCP 3389", bucket: "in", why: "RDP (Remote Desktop Protocol), Microsoft's own. The server must be reachable on that port, and the admin needs a credential." },
          { id: "i2", text: "An engineer opens a shell on a Linux host on TCP 22", bucket: "in", why: "SSH (Secure Shell), the Linux and Unix equivalent. Same need: a reachable port and a credential." },
          { id: "i3", text: "A partner in a hotel gets help, and nobody touched any firewall", bucket: "out", why: "The client calls out over an ordinary connection, so no inbound rule is needed on any firewall." },
          { id: "i4", text: "The client waits on an outbound connection until a technician joins", bucket: "out", why: "Both ends connect to the vendor's cloud relay and meet there. That's the design of third-party RMM." },
          { id: "i5", text: "The perimeter firewall forwards a port to one server's desktop", bucket: "in", why: "A forwarded port is an inbound path, which is exactly what these tools don't need." },
          { id: "i6", text: "A firewall log shows an outbound HTTPS-family flow to a real company's servers", bucket: "out", why: "At the network level, a relay connection looks like any other outbound traffic to a genuine business." },
        ],
      },
      {
        kind: "inspect",
        title: "One Technique, Three Flavours",
        prompt: "Sofie opens the ATT&CK card for the ticket. Tap each line to see where this activity sits and what it doesn't mean.",
        artifact: "MITRE ATT&CK v19 · technique card",
        items: [
          { id: "t", text: "T1219: Remote Access Tools", tag: "Technique", tone: "info", note: "Older ATT&CK versions and many write-ups call it Remote Access Software. Same ID, same behaviour." },
          { id: "tac", text: "Tactic: Command and Control (TA0011)", tag: "Tactic", tone: "warn", note: "It sits here because a connected tool lets someone outside watch the screen and type in real time, and nothing in the traffic marks that as hostile." },
          { id: "not", text: "Not filed under Persistence, Discovery or Initial Access", tag: "Mix-up", tone: "info", note: "A client may survive a reboot, operators run discovery through it, and it can follow any entry route. Those are other techniques. The live channel is what earns T1219 its place." },
          { id: "s1", text: "T1219.001: IDE Tunneling", tag: "Sub-technique", tone: "info", note: "A development tool's own tunnel feature, abused. IDE means Integrated Development Environment." },
          { id: "s2", text: "T1219.002: Remote Desktop Software", tag: "This room", tone: "warn", note: "GUI remote-control products on an endpoint. Everything at Brookmere today is this one." },
          { id: "s3", text: "T1219.003: Remote Access Hardware", tag: "Sub-technique", tone: "info", note: "A physical KVM-over-IP box (Keyboard, Video, Mouse over Internet Protocol). No software on the host at all." },
        ],
      },
    ],
    // ── r1: why borrow a signed tool ──
    "rmm-r1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Signed Binary",
        prompt: "Sofie pulled the record behind Orla's support session. Read it field by field and note what each one proves, and what it can't.",
        source: "Advanced Hunting · DeviceProcessEvents + DeviceFileCertificateInfo · ba-bk-lt07",
        fields: [
          { key: "Timestamp", value: "2026-11-03T10:09:14Z", label: "When" },
          { key: "DeviceName", value: "ba-bk-lt07.brookmere.example", label: "Where" },
          { key: "FileName", value: "support_fix.exe", label: "What ran", note: "The name the caller gave it. A file name is a label anyone can change." },
          { key: "ProcessVersionInfoOriginalFileName", value: "QuillQuick.exe", label: "Built-in name", note: "The name inside the file: Quillbridge's Quick Support build, which needs no installer and no administrator rights." },
          { key: "ProcessVersionInfoCompanyName", value: "Quillbridge Software Ltd" },
          { key: "IsSigned", value: "true", note: "Valid, and rightly so. This is the vendor's real file, so checks that stop unsigned or unknown binaries pass it." },
          { key: "Signer", value: "Quillbridge Software Ltd", label: "Who made it", note: "Nothing about the file is fraudulent. The signature answers one question: who built this." },
          { key: "IsTrusted", value: "true" },
          { key: "AccountName", value: "o.brennan", label: "As whom", note: "It inherits the logged-on user's rights. A remote tool doesn't climb to SYSTEM on its own." },
          { key: "InitiatingProcessFileName", value: "explorer.exe", label: "Parent", note: "A person double-clicked it. A managed agent starts from services.exe." },
        ],
        summary: "The EDR (Endpoint Detection and Response) recorded all of this as it would any process: remote tools get no exemption from inspection, and an encrypted session doesn't hide what runs on the endpoint. What the record can't say is who sits at the far end. A valid signature proves who made the tool, not who is using it.",
      },
      {
        kind: "sort",
        title: "Build It or Borrow It?",
        prompt: "An intruder wants a live channel into Brookmere. Think like them, working out the cheaper route, and sort each line to the option it belongs to.",
        buckets: [
          { id: "build", label: "Write a custom implant" },
          { id: "borrow", label: "Borrow a legitimate remote tool" },
        ],
        items: [
          { id: "b1", text: "Weeks of development and testing before first use", bucket: "build", why: "Bespoke code has to be written, and it breaks. A real vendor already did that work." },
          { id: "b2", text: "A rented C2 server that a takedown can remove", bucket: "build", why: "C2 means command and control. Attacker infrastructure has to be paid for, hosted and eventually replaced." },
          { id: "b3", text: "A hash that lands on blocklists after the first report", bucket: "build", why: "A malware family earns signatures. A product used by honest customers doesn't." },
          { id: "b4", text: "An unsigned, unknown file that reputation checks query", bucket: "build", why: "Exactly the checks a vendor-signed binary walks straight past." },
          { id: "b5", text: "A real publisher's signature already on the file", bucket: "borrow", why: "The attacker didn't forge anything. The file is what it claims to be." },
          { id: "b6", text: "Traffic to servers that thousands of honest customers use", bucket: "borrow", why: "A list of known-bad C2 hosts has nothing to match against a vendor's own relay." },
          { id: "b7", text: "Not flagged on sight by most antivirus and EDR baselines", bucket: "borrow", why: "Not flagged isn't the same as not recorded. The process is still logged, so it can still be hunted." },
          { id: "b8", text: "Full interactive control from a no-install build", bucket: "borrow", why: "Often no admin rights and no install step. The operator gets whatever the logged-on user already has." },
        ],
      },
    ],
    // ── r2: how a tool lands ──
    "rmm-r2": [
      {
        kind: "sort",
        title: "Which Door Did It Use?",
        prompt: "Sofie collected incident notes from other firms to work out how Brookmere's session could have started. Sort each note by the pattern behind it.",
        buckets: [
          { id: "a", label: "Pattern A: callback vishing (voice phishing)" },
          { id: "b", label: "Pattern B: ClickFix-style paste-and-run" },
          { id: "c", label: "Pattern C: attacking the RMM console" },
        ],
        items: [
          { id: "n1", text: "A voice claiming to be the bank's fraud team gets a receptionist to fetch a 'secure viewer'", bucket: "a", why: "No exploit, only a convincing call and someone willing to help." },
          { id: "n2", text: "A 'prove you are human' page tells a temp to press Win+R, paste and hit Enter", bucket: "b", why: "No file crosses the network as something a scanner can inspect. The pasted line does the work." },
          { id: "n3", text: "A support firm's internet-facing server is exploited, and 400 client laptops answer to a new admin", bucket: "c", why: "One server, every endpoint behind it. No end user was involved." },
          { id: "n4", text: "A caller stays on the line until the user has shared their screen", bucket: "a", why: "The victim installs and shares the tool themselves. That's the signature of this pattern." },
          { id: "n5", text: "A one-liner pasted into the Run box quietly installs a support client", bucket: "b", why: "Same mechanics as any ClickFix lure. The payload just happens to be a legitimate tool." },
          { id: "n6", text: "Nobody at the victim did anything: the flaw was in the product's own server software", bucket: "c", why: "That's the structural difference from a phone call: no victim action is needed at all." },
        ],
      },
      {
        kind: "inspect",
        title: "The Advisory's Toolbox",
        prompt: "This isn't one crew's favourite tool. Sofie keeps this advisory on file for the partners. Tap each line.",
        artifact: "CISA advisory AA23-320A · Scattered Spider",
        items: [
          { id: "a1", text: "AnyDesk, TeamViewer, Splashtop, Fleetdeck.io, Level.io, Pulseway, Tactical.RMM, ScreenConnect, Tailscale, Teleport.sh, Ngrok", tag: "Tools named", tone: "warn", note: "Eleven legitimate products in one federal advisory, all abused by one group for the same purpose." },
          { id: "a2", text: "Purpose: a live channel that doesn't look like malware", tag: "Why", tone: "warn", note: "The list isn't a blocklist. It shows that the choice of product hardly matters to the attacker." },
          { id: "a3", text: "Caveat: using one of these tools isn't malicious in itself", tag: "Caveat", tone: "trust", note: "The advisory says so directly, and it's why this is a hard detection problem. A name on this list is never a verdict." },
        ],
      },
    ],
    // ── r3: Storm-1811 ──
    "rmm-r3": [
      {
        kind: "inspect",
        title: "Case File: Storm-1811",
        prompt: "The case Sofie thinks of first when a user mentions a helpful call. Tap each line of the file to see what each step really was.",
        artifact: "Microsoft Security Blog, May 2024 · case notes",
        items: [
          { id: "s1", text: "Email bomb: the target's address is signed up to masses of mailing lists", tag: "Pretext", tone: "warn", note: "None of that mail is malware. It creates a problem for someone to offer to fix." },
          { id: "s2", text: "Phone call: 'Microsoft support' or the firm's own help desk offers to stop the spam", tag: "Vishing", tone: "warn", note: "The victim hears a solution to a real problem, which is why it works." },
          { id: "s3", text: "Quick Assist: the victim grants the caller remote control", tag: "T1219", tone: "warn", note: "A feature built into Windows, not third-party software. There's no download step, so a rule watching for new installs sees nothing." },
          { id: "s4", text: "Tools delivered, domain enumerated, lateral movement", tag: "Hands on keyboard", tone: "warn", note: "The session stops being support the moment it starts mapping the network." },
          { id: "s5", text: "Black Basta ransomware pushed with PsExec", tag: "Impact", tone: "warn", note: "PsExec is a genuine Sysinternals utility for running programs on other Windows hosts. Another legitimate tool, used for the last step." },
          { id: "s6", text: "Microsoft's advice: block or uninstall Quick Assist if you don't use it", tag: "Defence", tone: "trust", note: "Plus privileged access management, to limit what a compromised session can reach." },
        ],
      },
      {
        kind: "sort",
        title: "Where Would It Leave a Trace?",
        prompt: "Brookmere has mail logs and EDR, and nobody records phone calls. Sort each move in the Storm-1811 file by where a defender could have seen it.",
        buckets: [
          { id: "mail", label: "Mail gateway" },
          { id: "edr", label: "EDR on the endpoint" },
          { id: "none", label: "No log at all" },
        ],
        items: [
          { id: "m1", text: "Hundreds of subscription confirmations in one inbox within the hour", bucket: "mail", why: "Each message is harmless. The volume against one mailbox is the signal, and it's a good reason to warn the user that a call may follow." },
          { id: "m2", text: "The conversation with the fake support agent", bucket: "none", why: "A voice call leaves no log in a SOC. The first trace you get is whatever the user does next, so user reports matter." },
          { id: "m3", text: "quickassist.exe starts and a session is granted", bucket: "edr", why: "It's a real process on the host, even with no download behind it." },
          { id: "m4", text: "PsExec's service appears on several hosts at once", bucket: "edr", why: "PSEXESVC starting across hosts shows up in process and service telemetry." },
          { id: "m5", text: "A domain group query from a user's workstation", bucket: "edr", why: "A child process of the session. Discovery run through a remote tool still runs on the endpoint." },
          { id: "m6", text: "What the caller said to win the user's trust", bucket: "none", why: "Only the user can tell you. Ask them, and ask without blame." },
        ],
      },
    ],
    // ── r4: the console itself ──
    "rmm-r4": [
      {
        kind: "worksheet",
        title: "Which Consoles Were Exposed?",
        prompt: "Sofie keeps this sheet from February 2024, when Brookmere asked its suppliers about CVE-2024-1709, the ScreenConnect authentication bypass. Some of them are MSPs (Managed Service Providers: firms that run IT for others). Work it out from the rows.",
        caption: "Supplier survey · ScreenConnect consoles · 20 Feb 2024",
        columns: ["Supplier", "Hosting", "Version", "Endpoints managed"],
        rows: [
          ["Vendor bulletin", "All self-hosted", "Fixed in 23.9.8", "-"],
          ["Ledgerfold Payroll", "ConnectWise cloud", "23.9.7", "310"],
          ["Tallis IT Partners", "Self-hosted", "23.9.7", "1,240"],
          ["Merrow Print", "Self-hosted", "23.9.8", "85"],
          ["Cardew Legal IT", "Self-hosted", "23.7.8", "460"],
          ["Hollins Telecoms", "ConnectWise cloud", "23.9.7", "95"],
        ],
        questions: [
          { id: "n", q: "ConnectWise fixed its own cloud instances on 19 February. How many suppliers still had to patch by hand?", hint: "Self-hosted, and older than the bulletin's build.", answer: ["2", "two"], why: "Tallis and Cardew. Merrow was already fixed, and the cloud instances were fixed for them. That's why self-hosted consoles carried the risk, and why CISA's Known Exploited Vulnerabilities catalog set federal agencies a deadline of 29 February." },
          { id: "cred", q: "Did an attacker need a password to exploit the bypass? (yes/no)", hint: "CVSS 10.0, and a public Metasploit module within days.", answer: ["no"], why: "None. An unauthenticated attacker could reach an already-configured server's setup wizard and create a new administrator." },
          { id: "reach", q: "How many endpoints did the single worst exposed console put within reach?", hint: "Read Endpoints managed, for the exposed consoles only.", answer: ["1240", "1,240"], why: "Tallis: 1,240. A phone call wins one laptop, a console wins every endpoint it manages. Attackers then used that trusted access to push out other remote tools as their own way back in." },
        ],
      },
    ],
    // ── r5: the five signs ──
    "rmm-r5": [
      {
        kind: "spotdiff",
        title: "Same Signature, Different Owner",
        prompt: "Sofie pulled the config beside the file on ba-bk-lt07. Left is the approved agent from Brookmere's golden image. Right is the copy Orla ran. Same vendor, same valid signature. Tap the lines that show this copy doesn't belong to Brookmere.",
        goodTitle: "Approved agent · golden image",
        suspectTitle: "Copy on ba-bk-lt07",
        good: [
          "signer        = Quillbridge Software Ltd (valid)",
          "product       = Quillbridge Remote",
          "version       = 9.4.2",
          "device_label  = ba-tax-lt11",
          "install_path  = C:\\Program Files\\Quillbridge\\Agent\\",
          "run_mode      = service QuillAgent, LocalSystem",
          "transport     = TLS, outbound tcp/443",
          "relay_host    = brookmere.quillbridge.example",
          "operators     = BA-HelpDesk group, company sign-in",
          "user_prompt   = accept before control",
          "session_log   = sent to tenant audit log",
          "update_ring   = stable",
        ],
        suspect: [
          "signer        = Quillbridge Software Ltd (valid)",
          "product       = Quillbridge Remote",
          "version       = 9.5.0",
          "device_label  = ba-bk-lt07",
          "install_path  = C:\\Users\\o.brennan\\Desktop\\",
          "run_mode      = interactive, user o.brennan",
          "transport     = TLS, outbound tcp/443",
          "relay_host    = trial-58ac21.quillbridge.example",
          "operators     = tenant owner, free trial sign-up",
          "user_prompt   = accept before control",
          "session_log   = sent to tenant audit log",
          "update_ring   = stable",
        ],
        diffs: [
          { line: 4, why: "IT deploys the agent under Program Files. This one ran from a user's Desktop, which IT never uses, so the user or something running as the user put it there." },
          { line: 5, why: "A managed agent is a service running as LocalSystem. This is a process in the user's own session, with the user's rights." },
          { line: 7, why: "Same vendor domain, somebody else's tenant. The relay is genuine. It just doesn't lead to Brookmere's help desk." },
          { line: 8, why: "Whoever drives this copy signed up for a free trial. Brookmere's directory has never heard of them." },
        ],
        decoys: [
          { line: 2, why: "A newer build isn't evidence: vendors ship updates and fleets move in rings. Version alone tells you nothing about ownership." },
          { line: 3, why: "Every device has its own label. It has to differ." },
        ],
        hud: "Tap the lines that show whose copy this is",
        sameLine: "That line matches the approved agent, so it can't tell the two apart.",
        howTo: [
          "Compare the two copies line by line.",
          "Tap each line on the right that shows this copy isn't Brookmere's.",
          "A wrong tap costs a life and tells you why.",
        ],
        lesson: "The signature, the product and the transport are identical, and they always will be: the intruder is using the real tool. What differs is who deployed it, how it runs and whose tenant it answers to. Even the matching session_log line hides a trap: it logs to the owner's tenant, so Brookmere will never see that audit log.",
      },
      {
        kind: "worksheet",
        title: "Five Signs, Five Hosts",
        prompt: "After ba-bk-lt07, Sofie swept the remote tools inventory. Only the managed Quillbridge agent is licensed. Each question names one sign: find the host that shows it.",
        caption: "Remote tools inventory · Tue 11-03 12:00 · ba-bk-lt07 already with Sofie",
        columns: ["Host", "Remote tools found", "Path and run mode", "First run", "Relay"],
        rows: [
          ["ba-hr-lt03", "Farlight Viewer", "Program Files, service", "Wed 14:10, change CH-221", "edge.farlight.example"],
          ["ba-rec-pc02", "Quillbridge agent, Farlight Viewer", "Program Files, services", "Agent at imaging, viewer Mon 11:26", "brookmere.quillbridge.example, edge.farlight.example"],
          ["ba-aud-lt04", "Quillbridge agent, Quick Support", "Agent: service. Quick Support: Downloads, as the user", "Agent at imaging, Quick Support Tue 09:14", "brookmere.quillbridge.example"],
          ["ba-cl-lt09", "Quillbridge agent", "Program Files, service", "Sat 02:40, no change window", "brookmere.quillbridge.example"],
          ["ba-mk-lt02", "Quillbridge agent", "Program Files, service", "At imaging", "brookmere.quillbridge.example, vault-71.farlight.example"],
        ],
        questions: [
          { id: "s1", q: "Sign 1, tool identity mismatch: a remote tool that simply isn't the licensed one, and no licensed one in sight. Which host?", hint: "Look for a host with no Quillbridge at all.", answer: ["ba-hr-lt03"], why: "Farlight isn't on the licence, and even a tidy service under Program Files doesn't change that." },
          { id: "s2", q: "Sign 2, duplicate coverage: the sanctioned agent with a second, unrecognized remote tool beside it. Which host?", hint: "Two different products in one cell.", answer: ["ba-rec-pc02"], why: "Something outside the normal deployment process added the second tool. IT doesn't deploy two." },
          { id: "s3", q: "Sign 3, install and run location: a copy in a user folder, running as the user. Which host?", hint: "Read Path and run mode.", answer: ["ba-aud-lt04"], why: "That's the sign, and it's a reason to look, not a verdict. A user folder alone proves nothing, and this host turns up again in the hunt." },
          { id: "s4", q: "Sign 4, timing: a tool that appeared outside any change window. Which host?", hint: "Read First run.", answer: ["ba-cl-lt09"], why: "An agent installed at 02:40 on a Saturday with no change behind it. Often the time to check is the minutes after a call, a click or a paste." },
          { id: "s5", q: "Sign 5, outbound destination: a relay belonging to a vendor Brookmere doesn't license, from a host with no such tool listed. Which host?", hint: "Compare Relay with Remote tools found.", answer: ["ba-mk-lt02"], why: "The domain is a real company's, so it's not malicious in itself. It's a prompt to go and check the other four signs." },
        ],
      },
      {
        kind: "rush",
        title: "Who Made It, or Who's Using It?",
        prompt: "Sofie reads out evidence from the file, fast. Does each line tell you about the tool itself, or about how it's being used here? Only the second kind moves a verdict.",
        seconds: 60,
        target: 10,
        trueLabel: "About the use",
        falseLabel: "About the tool",
        cards: [
          { id: "c1", text: "Signature valid, signer is the vendor", answer: false, why: "It proves who built the file. An intruder's copy passes too." },
          { id: "c2", text: "Zero detections on a file reputation lookup", answer: false, why: "It's a real product, so of course it's clean." },
          { id: "c3", text: "The proxy category says Remote Access Tools", answer: false, why: "True of your own help desk's traffic as well." },
          { id: "c4", text: "The product is named in a government advisory", answer: false, why: "So are plenty of tools your IT team legitimately runs." },
          { id: "c5", text: "The domain belongs to a real, legitimate vendor", answer: false, why: "It always does. It's a prompt to check, not a finding." },
          { id: "c6", text: "The session traffic is encrypted", answer: false, why: "Honest and hostile sessions are both encrypted." },
          { id: "c7", text: "The hash matches the vendor's published release", answer: false, why: "It confirms the file is genuine, which was never the question." },
          { id: "c8", text: "The relay subdomain isn't your tenant", answer: true, why: "Same vendor, different owner: this says whose session it is." },
          { id: "c9", text: "Running from Temp under the user's own account", answer: true, why: "Not how IT deploys it, so somebody else put it there." },
          { id: "c10", text: "Started nine minutes after an unexpected call", answer: true, why: "Timing ties the tool to an event, not to a change window." },
          { id: "c11", text: "No open ticket names this host and technician", answer: true, why: "Nobody at the company can account for the session." },
          { id: "c12", text: "The operator isn't in the help-desk group", answer: true, why: "Tells you who is at the controls, which a signature can't." },
          { id: "c13", text: "A second remote tool beside the managed agent", answer: true, why: "Duplicate coverage: something outside IT's process added it." },
          { id: "c14", text: "cmd.exe is a child of the tool and ran whoami", answer: true, why: "That's what the session did, and support rarely starts that way." },
        ],
        lesson: "Everything about the file is true of the intruder's copy as well, because it's the same file. A valid signature proves who made the tool, not who is using it. Build the case from how it got there, how it runs, where it dials and who can account for it, and weigh those together: no single one of them is a verdict alone.",
      },
    ],
    // ── r6: the allowlist ──
    "rmm-r6": [
      {
        kind: "match",
        title: "What Each Control Actually Gives You",
        prompt: "The partners asked Sofie why they can't just ban remote tools. Match each control or data source to what it really gives you.",
        pairs: [
          { id: "m1", left: "EDR", right: "What ran, from where, and as whom", why: "Process and service creation: the endpoint's view." },
          { id: "m2", left: "Proxy, firewall and DNS logs", right: "Where it dialled, checked against the allowlist", why: "The outbound view. A hit on a relay isn't an alert until it's compared with what you allow." },
          { id: "m3", left: "ITSM (IT Service Management) ticketing", right: "Provenance: which technician, which session, what time", why: "The only source that says somebody at the company asked for this." },
          { id: "m4", left: "Blocking the whole category", right: "Stops the help desk too, so it can't stay switched on", why: "Remote tools are what IT relies on every day. A category block breaks real support." },
          { id: "m5", left: "Alerting on every vendor relay hit", right: "A queue full of your own support sessions", why: "Identical alerts for honest and hostile sessions teach a SOC to stop reading them." },
        ],
      },
      {
        kind: "simulate",
        title: "Run the Allowlist",
        prompt: "An allowlist has three parts, and a session has to clear all of them. Run these four sessions through the checks. Anything outside any one of them is the alert worth working.",
        checks: [
          { name: "Product", question: "Is it the one product licensed and centrally deployed?" },
          { name: "Operator", question: "Is it driven by a named help-desk account?" },
          { name: "Identity", question: "Does it show the expected install path and service?" },
        ],
        scenarios: [
          { id: "ok", label: "hd-l.ferreira fixes a scanner driver on ba-tax-lt11", detail: "Managed agent, Program Files, service QuillAgent, session opened from the technician console.", results: ["pass", "pass", "pass"], why: ["The licensed product.", "A named technician in BA-HelpDesk.", "The expected path and service."], verdict: "Inside all three. A category block would have cut this session off. Check the ticket, then move on." },
          { id: "svc", label: "svc-backup opens a console session at 03:10", detail: "Managed agent on the far end, right path, right service.", results: ["pass", "fail", "pass"], why: ["The licensed product.", "A service account has no business driving a support session.", "The expected path and service."], verdict: "Right tool, wrong hands. A stolen or misused account is still the alert." },
          { id: "far", label: "Farlight Viewer on ba-hr-lt03", detail: "Installed by a contractor, tidy service under Program Files.", results: ["fail", "fail", "fail"], why: ["Not the licensed product.", "No help-desk account involved.", "Not the service the allowlist expects, however neat it looks."], verdict: "Outside on every count. Find out who approved change CH-221." },
          { id: "port", label: "A no-install Quick Support copy started by a user", detail: "Same vendor, valid signature, run from a user folder.", results: ["pass", "fail", "fail"], why: ["Same vendor and product family.", "Run by an ordinary user account.", "Not the managed path, and no service."], verdict: "A valid signature clears one check out of three. Keep going." },
        ],
      },
      {
        kind: "hunt",
        title: "Sanctioned or Stowaway?",
        prompt: "Is ba-bk-lt07 the only one? Sofie wants every Quillbridge process on the fleet that nobody can account for. Build the hunt one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceProcessEvents",
        goal: "one row: the session no install, parent, tenant or ticket can explain",
        tables: [
          {
            name: "DeviceProcessEvents",
            note: "Process creation.",
            columns: ["Timestamp", "DeviceName", "AccountName", "FileName", "FolderPath", "InitiatingProcessFileName", "ProcessId", "ProcessVersionInfoCompanyName"],
            rows: [
              ["11-03 07:58", "ba-tax-lt11", "system", "QuillAgent.exe", "C:\\Program Files\\Quillbridge\\Agent\\QuillAgent.exe", "services.exe", "3120", "Quillbridge Software Ltd"],
              ["11-03 08:01", "ba-bk-lt07", "system", "QuillAgent.exe", "C:\\Program Files\\Quillbridge\\Agent\\QuillAgent.exe", "services.exe", "4412", "Quillbridge Software Ltd"],
              ["11-03 08:06", "ba-it-wk01", "hd-c.sato", "QuillConsole.exe", "C:\\Program Files\\Quillbridge\\Console\\QuillConsole.exe", "explorer.exe", "5236", "Quillbridge Software Ltd"],
              ["11-03 08:15", "ba-tax-lt11", "r.adeyemi", "EXCEL.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "explorer.exe", "9016", "Microsoft Corporation"],
              ["11-03 08:40", "ba-aud-lt04", "system", "QuillUpdate.exe", "C:\\ProgramData\\Quillbridge\\Update\\QuillUpdate.exe", "QuillAgent.exe", "2788", "Quillbridge Software Ltd"],
              ["11-03 09:14", "ba-aud-lt04", "p.lindqvist", "QuillQuick.exe", "C:\\Users\\p.lindqvist\\Downloads\\QuillQuick.exe", "explorer.exe", "6044", "Quillbridge Software Ltd"],
              ["11-03 09:47", "ba-pay-sv01", "adm-j.okafor", "QuillQuick.exe", "C:\\Vendor\\Ledgerfold\\QuillQuick.exe", "explorer.exe", "7120", "Quillbridge Software Ltd"],
              ["11-03 10:09", "ba-bk-lt07", "o.brennan", "support_fix.exe", "C:\\Users\\o.brennan\\Desktop\\support_fix.exe", "explorer.exe", "6044", "Quillbridge Software Ltd"],
              ["11-03 10:11", "ba-bk-lt07", "o.brennan", "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "support_fix.exe", "8124", "Microsoft Corporation"],
            ],
          },
          {
            name: "DeviceNetworkEvents",
            note: "Network connections, with the process that made them.",
            columns: ["Timestamp", "DeviceName", "ActionType", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "InitiatingProcessId"],
            rows: [
              ["11-03 07:59", "ba-tax-lt11", "ConnectionSuccess", "brookmere.quillbridge.example", "443", "QuillAgent.exe", "3120"],
              ["11-03 08:02", "ba-bk-lt07", "ConnectionSuccess", "brookmere.quillbridge.example", "443", "QuillAgent.exe", "4412"],
              ["11-03 09:15", "ba-aud-lt04", "ConnectionSuccess", "brookmere.quillbridge.example", "443", "QuillQuick.exe", "6044"],
              ["11-03 09:30", "ba-aud-lt04", "ConnectionSuccess", "files.brookmere.example", "443", "msedge.exe", "7412"],
              ["11-03 09:48", "ba-pay-sv01", "ConnectionSuccess", "ledgerfold.quillbridge.example", "443", "QuillQuick.exe", "7120"],
              ["11-03 10:05", "ba-bk-lt07", "ConnectionSuccess", "downloads.quillbridge.example", "443", "msedge.exe", "6312"],
              ["11-03 10:09", "ba-bk-lt07", "ConnectionSuccess", "trial-58ac21.quillbridge.example", "443", "support_fix.exe", "6044"],
            ],
          },
          {
            name: "ServiceDeskTickets_CL",
            note: "Custom log: service desk tickets.",
            columns: ["TicketId", "DeviceName", "Requester", "Technician", "Category", "Status", "Opened"],
            rows: [
              ["SD-3977", "ba-bk-lt07", "o.brennan", "hd-g.mensah", "Hardware", "Closed", "07-02 15:40"],
              ["SD-4102", "ba-bk-lt07", "o.brennan", "hd-l.ferreira", "Password reset", "Closed", "09-14 11:02"],
              ["SD-4466", "ba-tax-lt11", "r.adeyemi", "hd-g.mensah", "Hardware", "Open", "11-02 16:20"],
              ["SD-4471", "ba-aud-lt04", "p.lindqvist", "hd-c.sato", "Remote support", "Open", "11-03 09:10"],
              ["SD-4473", "ba-pay-sv01", "adm-j.okafor", "Ledgerfold support", "Remote support", "Open", "11-03 09:40"],
              ["SD-4490", "ba-bk-lt07", "o.brennan", "Unassigned", "Email", "Open", "11-03 09:52"],
            ],
          },
        ],
        rungs: [
          {
            id: "maker", ask: "Line 2: keep everything Quillbridge built, whatever it's called on disk.",
            choices: [
              { id: "a", text: '| where FileName in~ ("QuillAgent.exe", "QuillQuick.exe")', why: "Four rows, and ba-bk-lt07's copy isn't among them. A file name is a label, and this one was changed.", apply: { op: "where", col: "FileName", test: "in", value: ["QuillAgent.exe", "QuillQuick.exe"] } },
              { id: "b", text: '| where ProcessVersionInfoCompanyName =~ "Quillbridge Software Ltd"', right: true, why: "Seven rows, helpers and stowaways alike. Version info travels with the file through a rename. It's the publisher's own label, and the signature check lives in DeviceFileCertificateInfo. Either way, this line only says who made it.", apply: { op: "where", col: "ProcessVersionInfoCompanyName", test: "ieq", value: "Quillbridge Software Ltd" } },
              { id: "c", text: '| where FolderPath has "Quillbridge"', why: "Only what sits in the vendor's own folders. You've thrown away every portable copy before looking at one.", apply: { op: "where", col: "FolderPath", test: "has", value: "Quillbridge" } },
            ],
          },
          {
            id: "path", ask: "Line 3: IT deploys under Program Files. Take out the approved install path.",
            choices: [
              { id: "a", text: '| where FolderPath has "Downloads"', why: "One row, and it isn't even the one you're after. Don't guess where a stowaway lives: remove what's approved and look at what's left.", apply: { op: "where", col: "FolderPath", test: "has", value: "Downloads" } },
              { id: "b", text: '| where FolderPath !startswith @"C:\\Program Files\\Quillbridge\\"', right: true, why: "Four left. FolderPath includes the file name, so startswith on the folder is the right test. Everything IT deployed there has gone.", apply: { op: "where", col: "FolderPath", test: "notin", value: ["C:\\Program Files\\Quillbridge\\Agent\\QuillAgent.exe", "C:\\Program Files\\Quillbridge\\Console\\QuillConsole.exe"] } },
              { id: "c", text: '| where AccountName =~ "system"', why: "That keeps the managed side, the part you were trying to remove.", apply: { op: "where", col: "AccountName", test: "ieq", value: "system" } },
            ],
          },
          {
            id: "parent", ask: "Line 4: the agent's own updater lives outside Program Files. Filter on what started each process, and drop the managed parents.",
            choices: [
              { id: "a", text: '| where InitiatingProcessFileName =~ "services.exe"', why: "No rows. That keeps service starts, and the last line already removed them. You want the opposite.", apply: { op: "where", col: "InitiatingProcessFileName", test: "ieq", value: "services.exe" } },
              { id: "b", text: '| where InitiatingProcessFileName =~ "QuillAgent.exe"', why: "That returns only the updater, the one row you meant to drop.", apply: { op: "where", col: "InitiatingProcessFileName", test: "ieq", value: "QuillAgent.exe" } },
              { id: "c", text: '| where InitiatingProcessFileName !in~ ("services.exe", "QuillAgent.exe")', right: true, why: "Three rows, all started by a person from explorer.exe. Each one is the portable build. A path looked odd on the updater, and the parent explained it.", apply: { op: "where", col: "InitiatingProcessFileName", test: "notin", value: ["services.exe", "QuillAgent.exe"] } },
            ],
          },
          {
            id: "join", ask: "Line 5: the process table can't say where each one dialled. Bring in the table that can.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceNetworkEvents on $left.ProcessId == $right.InitiatingProcessId", why: "Five rows, with connections pinned on the wrong laptops. PID 6044 runs on two devices today, and PIDs repeat across a fleet.", apply: { op: "join", table: "DeviceNetworkEvents", left: "ProcessId", right: "InitiatingProcessId" } },
              { id: "b", text: "| join kind=inner DeviceNetworkEvents on DeviceName", why: "Six rows: every connection on those devices, whichever process made it. Match the process, not just the machine.", apply: { op: "join", table: "DeviceNetworkEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "c", text: "| join kind=inner DeviceNetworkEvents on DeviceName, $left.ProcessId == $right.InitiatingProcessId", right: true, why: "Three rows, one relay each. Device plus PID identifies the process. On a long time range add the process creation time as well, because Windows reuses PIDs.", apply: { op: "join", table: "DeviceNetworkEvents", left: "ProcessId", right: "InitiatingProcessId", also: "DeviceName" } },
            ],
          },
          {
            id: "relay", ask: "Line 6: every one of these reached a Quillbridge relay. Drop the sessions on Brookmere's own tenant.",
            choices: [
              { id: "a", text: '| where RemoteUrl has "quillbridge"', why: "Nothing changed: all three are the vendor's real domain. A vendor domain is a prompt to check, never a verdict.", apply: { op: "where", col: "RemoteUrl", test: "has", value: "quillbridge" } },
              { id: "b", text: "| where RemotePort != 443", why: "No rows. They're all on 443, like most of the internet. The port can't separate these sessions.", apply: { op: "where", col: "RemotePort", test: "notin", value: ["443"] } },
              { id: "c", text: '| where RemoteUrl !endswith "brookmere.quillbridge.example"', right: true, why: "Two left. That odd-looking Downloads copy was on Brookmere's own tenant: a user folder alone proves nothing. Now two sessions lead somewhere else.", apply: { op: "where", col: "RemoteUrl", test: "notin", value: ["brookmere.quillbridge.example"] } },
            ],
          },
          {
            id: "ticket", ask: "Line 7: keep only the sessions with no live remote support ticket behind them.",
            choices: [
              { id: "a", text: "| join kind=inner ServiceDeskTickets_CL on DeviceName", why: "An inner join keeps rows that have a ticket, the opposite of the question. And look what matched ba-bk-lt07: this morning's unassigned mail ticket and two old closed ones, none of them for remote support.", apply: { op: "join", table: "ServiceDeskTickets_CL", left: "DeviceName", right: "DeviceName" } },
              { id: "b", text: "| join kind=leftanti ServiceDeskTickets_CL on DeviceName", why: "No rows. Any ticket counted, so a mail ticket and two closed ones hid the intruder. A ticket only helps if it covers this session.", apply: { op: "where", col: "DeviceName", test: "notin", value: ["ba-bk-lt07", "ba-tax-lt11", "ba-aud-lt04", "ba-pay-sv01"] } },
              { id: "c", text: '| join kind=leftanti (ServiceDeskTickets_CL | where Category == "Remote support" and Status == "Open") on DeviceName', right: true, why: "One row. leftanti keeps what has no match, and only a live remote support ticket counts as a match. Ledgerfold's payroll support session has one, so it's their tenant and it's sanctioned. In production, also check the ticket's time against the session.", apply: { op: "where", col: "DeviceName", test: "notin", value: ["ba-aud-lt04", "ba-pay-sv01"] } },
            ],
          },
          {
            id: "show", ask: "Line 8: show only what the case needs.",
            choices: [
              { id: "a", text: "| project DeviceName, AccountName, FileName, FolderPath, RemoteUrl", right: true, why: "Host, account, file, path and relay: the case in one line.", apply: { op: "project", cols: ["DeviceName", "AccountName", "FileName", "FolderPath", "RemoteUrl"] } },
              { id: "b", text: "| project DeviceName, AccountName, FileName, TicketId", why: "The console refuses it. leftanti returns only left-hand columns, and there is no ticket to show, which is the finding.", apply: { op: "project", cols: ["DeviceName", "AccountName", "FileName", "TicketId"] } },
              { id: "c", text: "| summarize count() by RemoteUrl", why: "A count says how often. The case needs what, where and as whom.", apply: { op: "summarize", by: ["RemoteUrl"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Every row in the first result was the same signed product. Path took out the deployed install, parent explained the updater, the relay cleared Brookmere's own tenant, and the ticket cleared the supplier. What's left is the one copy nobody can account for, and this morning it's the only one. Keep Timestamp limits in real queries, and once a hunt proves itself, turn it into a detection rule.",
      },
    ],
    // ── r7: the workflow ──
    "rmm-r7": [
      {
        kind: "trace",
        title: "Walk One Case, Start to Finish",
        prompt: "One row came back. Sofie works every remote tool case the same way, in the same order. Work ba-bk-lt07 with them, one source at a time, and click the row that answers each step.",
        lead: "Hunt result: ba-bk-lt07, support_fix.exe, Tuesday 10:09",
        steps: [
          {
            id: "identify", ask: "First: what is it, really? Click the row for the tool in question.", source: "DeviceProcessEvents · ba-bk-lt07",
            columns: ["Time", "FileName", "ProcessVersionInfoOriginalFileName", "FolderPath", "AccountName"],
            rows: [
              ["08:01", "QuillAgent.exe", "QuillAgent.exe", "C:\\Program Files\\Quillbridge\\Agent\\QuillAgent.exe", "system"],
              ["10:09", "support_fix.exe", "QuillQuick.exe", "C:\\Users\\o.brennan\\Desktop\\support_fix.exe", "o.brennan"],
              ["10:11", "cmd.exe", "Cmd.Exe", "C:\\Windows\\System32\\cmd.exe", "o.brennan"],
            ],
            answer: 1, why: "Product, build and path come first, because they shape everything after. A renamed no-install build run by hand is a different thing from a managed service.", learned: "Quillbridge Quick Support, renamed, on a Desktop, not a service",
          },
          {
            id: "list", ask: "Next: is it allowed at all? Click the allowlist line that could cover this copy.", source: "Allowlist · remote tools · IT Security",
            columns: ["Product", "Build", "Where", "Operators", "Condition"],
            rows: [
              ["Quillbridge Remote", "Managed agent", "Program Files, service", "BA-HelpDesk", "Always"],
              ["Quillbridge Remote", "Technician console", "IT workstations", "BA-HelpDesk", "Always"],
              ["Quillbridge Remote", "Quick Support", "Run by the user", "BA-HelpDesk", "brookmere tenant, with a ticket"],
              ["Ledgerfold vendor access", "Quick Support", "ba-pay-sv01 only", "Ledgerfold support", "With a ticket"],
            ],
            answer: 2, why: "The product is on the list, but this build only under conditions. So the allowlist hasn't cleared it: it has told you what to prove next.", learned: "Allowed only on Brookmere's tenant, by the help desk, with a ticket",
          },
          {
            id: "account", ask: "Who was operating? Click the account this copy ran as.", source: "Directory · accounts",
            columns: ["Account", "Title", "Groups", "Support sessions, 90 days"],
            rows: [
              ["hd-c.sato", "Service Desk Technician", "BA-HelpDesk", "212"],
              ["hd-g.mensah", "Service Desk Technician", "BA-HelpDesk", "187"],
              ["adm-j.okafor", "Systems Administrator", "BA-Admins", "0"],
              ["o.brennan", "Senior Bookkeeper", "BA-Bookkeeping", "0"],
            ],
            answer: 3, why: "A bookkeeper with no support role. The real operator is at the far end, in someone else's tenant, and Brookmere's directory can't name them.", learned: "Ran as o.brennan, no support role, operator unknown",
          },
          {
            id: "ticket", ask: "Does the service desk know? Click the closest ticket, then ask whether it covers this session.", source: "ServiceDeskTickets_CL · ba-bk-lt07",
            columns: ["TicketId", "Category", "Status", "Opened", "Technician"],
            rows: [
              ["SD-4490", "Email", "Open", "11-03 09:52", "Unassigned"],
              ["SD-4102", "Password reset", "Closed", "09-14 11:02", "hd-l.ferreira"],
              ["SD-3977", "Hardware", "Closed", "07-02 15:40", "hd-g.mensah"],
            ],
            answer: 0, why: "Closest, and still no match: Orla reported the mail flood, nobody picked it up, and it names no remote session. A ticket has to fit this host, this technician and this hour.", learned: "No ticket covers the 10:09 session",
          },
          {
            id: "dest", ask: "Where did it dial? Click the connection this process made.", source: "DeviceNetworkEvents · ba-bk-lt07",
            columns: ["Timestamp", "InitiatingProcessFileName", "RemoteUrl", "RemotePort", "Seen before"],
            rows: [
              ["08:02", "QuillAgent.exe", "brookmere.quillbridge.example", "443", "Daily"],
              ["10:05", "msedge.exe", "downloads.quillbridge.example", "443", "Rarely"],
              ["10:09", "support_fix.exe", "trial-58ac21.quillbridge.example", "443", "First time"],
            ],
            answer: 2, why: "A brand-new tenant on a real vendor's relay. Threat intelligence won't flag it, but rare and unseen in your estate is a stronger signal than an established relay.", learned: "Dialled a free-trial tenant, first time seen",
          },
          {
            id: "tree", ask: "What did it do? Click the first row that reaches beyond this laptop.", source: "DeviceProcessEvents · children of support_fix.exe",
            columns: ["Time", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
            rows: [
              ["10:11", "cmd.exe", "cmd.exe", "support_fix.exe"],
              ["10:12", "whoami.exe", "whoami /groups", "cmd.exe"],
              ["10:13", "notepad.exe", "notepad readme.txt", "cmd.exe"],
              ["10:14", "nltest.exe", "nltest /domain_trusts", "cmd.exe"],
            ],
            answer: 3, why: "whoami asks about this user. nltest asks about the domain. A session that does that has stopped looking and started mapping the network, and that adds real weight. It says nothing about who the operator is: discovery commands don't attribute anyone.", learned: "Domain discovery through the session at 10:14",
          },
          {
            id: "verdict", ask: "Last: the verdict. Click what the evidence supports.", source: "Response options",
            columns: ["Option", "What it does"],
            rows: [
              ["Close with the ticket", "Records confirmed IT activity"],
              ["Remove the tool", "Uninstalls it and ends the case"],
              ["Escalate to containment", "Isolate the host, reset o.brennan's credentials, remove the tool, hunt for what it staged"],
              ["Watch and wait", "Leaves the session running to gather more"],
            ],
            answer: 2, why: "Isolating severs the live session, the reset takes back the account, and removal and a hunt deal with anything staged. Removing the tool alone leaves everything the operator already did.", learned: "Contained: only confirmed IT activity closes clean",
          },
        ],
      },
    ],
    // ── la1 drill: reading a record against the allowlist ──
    "rmm-la1": [
      {
        kind: "anatomy",
        title: "What Can a Firewall Record Tell You?",
        prompt: "Before the graded record: the firewall logged ba-rec-pc02's second tool. Read each field and ask what it can and can't tell you. Brookmere's only licensed tool is Quillbridge Remote.",
        source: "Firewall traffic log · ba-rec-pc02",
        fields: [
          { key: "receive_time", value: "2026/11/02 11:26:40", label: "When" },
          { key: "src", value: "10.30.4.22", label: "From" },
          { key: "srcuser", value: "brookmere\\j.whitlock", label: "Who", note: "Whose session it left from, not who is at the far end." },
          { key: "dst", value: "198.51.100.44" },
          { key: "dport", value: "443", label: "Port", note: "How it travelled. Port numbers can back up a product's identity, but they aren't the field that states it." },
          { key: "app", value: "farlight-viewer", label: "Product", note: "The field that names the product. Hold this one against the allowlist first." },
          { key: "subcategory_of_app", value: "remote-access", label: "Category", note: "Accurate, and just as true of Quillbridge. A category can't separate licensed from unlicensed." },
          { key: "action", value: "allow", label: "Policy result", note: "The firewall's rule let it pass. That's a statement about the rule, not approval of this session." },
          { key: "rule", value: "Outbound-Web" },
          { key: "bytes", value: "48210" },
        ],
        summary: "Read the product first and compare it with the allowlist: that's where a mismatch shows. But this record can't tell you whether anyone approved the session, and neither can a signature or the fact that it's encrypted. So ask what would: a ticket for this host, this user and this hour.",
      },
    ],
    // ── ac1 drill: same rule, different endings ──
    "rmm-ac1": [
      {
        kind: "queue",
        title: "One Rule, Four Endings",
        prompt: "One rule fires on any connection to a remote support relay. Four hits from this month's queue. Open each one, read the service desk's reply, and decide what it really is. The rule isn't wrong just because the activity turned out fine.",
        console: "SIEM · Incidents",
        actions: [
          { id: "btp", label: "Close: Benign True Positive", tone: "close" },
          { id: "fp", label: "Close: False Positive", tone: "close" },
          { id: "esc", label: "Escalate to T2", tone: "escalate" },
          { id: "con", label: "Contain the host", tone: "contain" },
        ],
        alerts: [
          {
            id: "a1", time: "09:15", severity: "Medium", rule: "Remote support relay contacted", entity: "ba-aud-lt04",
            fields: [{ k: "Process", v: "QuillQuick.exe" }, { k: "FolderPath", v: "C:\\Users\\p.lindqvist\\Downloads\\QuillQuick.exe" }, { k: "RemoteUrl", v: "brookmere.quillbridge.example" }, { k: "Operator", v: "hd-c.sato" }],
            context: "Service desk: SD-4471. p.lindqvist phoned the desk at 09:10 because the agent had stopped responding, and hd-c.sato talked them through running Quick Support. Session confirmed by hd-c.sato.",
            answer: "btp",
            why: "Your tenant, a named technician, and a ticket for this host and this hour. The rule did catch a real remote session, so nothing misfired: benign true positive, closed with the ticket number. Calling it a false positive invites someone to weaken the rule. If it's noisy, add a narrow, owned allowlist entry for your own tenant.",
          },
          {
            id: "a2", time: "11:02", severity: "Low", rule: "Remote support relay contacted", entity: "ba-hr-lt03",
            fields: [{ k: "Process", v: "msedge.exe" }, { k: "RemoteUrl", v: "quillpens.example" }, { k: "Matched pattern", v: "*quill*" }, { k: "Proxy category", v: "Shopping" }],
            context: "Service desk: no ticket, and none needed. This is the stationery supplier's web shop. No remote tool was involved.",
            answer: "fp",
            why: "No remote session ever happened. A loose pattern matched a stationery shop, so the rule itself misfired: that's a false positive, and the fix is to tighten the pattern. Compare the first hit, where the rule was right and the activity was authorized.",
          },
          {
            id: "a3", time: "02:10", severity: "High", rule: "Remote support relay contacted", entity: "ba-cl-lt09",
            fields: [{ k: "Process", v: "QuillAgent.exe" }, { k: "FolderPath", v: "C:\\Program Files\\Quillbridge\\Agent\\QuillAgent.exe" }, { k: "RemoteUrl", v: "brookmere.quillbridge.example" }, { k: "Operator", v: "hd-g.mensah" }],
            context: "Service desk: no ticket on this host. hd-g.mensah was on leave that week and says they ran no session.",
            answer: "esc",
            why: "Right product, right tenant, named technician, and still wrong: nobody asked for this, and the technician denies it. That points at a stolen console account, which reaches every managed endpoint, not one laptop. It needs a senior analyst now.",
          },
          {
            id: "a4", time: "10:09", severity: "High", rule: "Remote support relay contacted", entity: "ba-bk-lt07",
            fields: [{ k: "Process", v: "support_fix.exe" }, { k: "Signer", v: "Quillbridge Software Ltd (valid)" }, { k: "RemoteUrl", v: "trial-58ac21.quillbridge.example" }, { k: "Operator", v: "Unknown, outside Brookmere's tenant" }],
            context: "Service desk: no technician touched this host today. SD-4490 is an unassigned mail ticket. nltest ran under the session five minutes in.",
            answer: "con",
            why: "A valid signature, and nothing else in its favour: foreign tenant, no ticket, no technician, and discovery on the host. The session is live, so sever it first.",
          },
        ],
      },
    ],
  },
};
