import type { RoomExperience } from "./types";

// "Operation Side Door" for the "windows-protocols-lateral" room.
// Script: docs/campaign/76-windows-protocols-lateral.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pinehurst Mills (fictional textile manufacturer), not the graded tasks' solvix.local records.
// Mentor: Nomvula Strand, Threat Hunter.
// Signature, Which Door Did They Use?: one admin account moves by SMB, a scheduled task, WMI,
// WinRM and RDP, and each door leaves its own shape on the source and the target. A deduce names
// one hop from what is missing, a KQL hunt finds another by tying the process to its logon on the
// same device, and an outbreak shows why you cut a credential or a protocol, not a host.
// Game mix: deduce + hunt + outbreak.
//
// TASK ORDER CHANGED. The room lists all six readings first, so it cannot be cut into stations.
// New order, for the integrator. It keeps the readings in their 1 to 6 order, so the "Reading N"
// cross-references inside their text stay true, and la1 stays before f1 and la2 before qf1:
//   r1 | r2, o1, r3, q2 | r4, r5, q3 | r6, q1, m1, la1, f1 | la2, qf1, ac1
//
// Lab data differs from the graded tasks. Hosts, accounts and addresses are all Pinehurst, none
// from solvix.local. The service hop is fixdrv.exe by a named admin, never PSEXESVC or m.reyes
// (la1, f1), and the path lab expands a different file (f1). The pipe record shows wkssvc; svcctl
// appears only as labelled data and in the fixdrv.exe sequence (la1, q1). The explained-or-open sort uses atsvc and shares, never
// workstation-to-workstation svcctl (q1). The Pass-the-Ticket round is a replayed service ticket
// with no 4768 or 4769 from the new host, beside an overpass-the-hash contrast (q2). The RC4 sheet has 5 tickets in one burst, not 47
// over 44 accounts, and the cut sort stays on host, credential and protocol, using no graded option (la2). LDAP labs ask about
// DONT_REQ_PREAUTH and adminCount; the SPN filter is a labelled row, never asked (q3). The count
// lab uses 4768 and PreAuthType 0, never 4769 and RC4 (qf1). The verdict queue uses a task, WMI and
// share alerts, never svcctl plus a new service from a helpdesk jump host (ac1). The packet lab
// shows the Kerberos order and never asks for it (o1, m1). WinRM and RDP appear only as table
// data; no lab asks what they ride on (m1). The hunt finds WinRM and joins processes to logons,
// never Kerberos events (qf1) or WMI's parent process (r6 checkpoint).

export const WINDOWS_PROTOCOLS_LATERAL: RoomExperience = {
  roomId: "windows-protocols-lateral",
  codename: "Operation Side Door",
  theme: "sidedoor",
  handler: { name: "Nomvula Strand", role: "Threat Hunter, Pinehurst Mills" },
  briefing: [
    "Pinehurst Mills weaves upholstery fabric in two sheds and keeps forty years of patterns on one file server.",
    "Between 01:00 and 02:30 on Sunday, one admin account touched five machines and no alert fired. adm-r.dube has been on leave since Friday.",
    "Nomvula Strand, Threat Hunter, knows the account moved. The question is which door it used each time, because each door leaves a different shape on both machines.",
    "Learn the shares, the tickets and the doors, find the hop nobody saw, and decide what actually stops it.",
  ],
  mission: "Read SMB sessions and hidden shares, follow Kerberos tickets through the KDC, take apart a relay and a directory crawl, name a door from the traces it left, hunt the hop nobody saw, then choose what to cut and judge whether the last alert was yours or theirs.",
  estimate: "~65 min",
  look: { primary: "#f4a58a", secondary: "#a8dadc", warn: "#e5383b" },
  scene: "facilitysidedoor",
  layout: "facility",
  story: {
    intro: { title: "No Alert Fired", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-intro-39525b17.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-intro-cb0a2d12.jpg" },
    afterStation: {
      tickets: { title: "A Laptop Nobody Owns", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-ch2-11f096f7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-ch2-f4cb7774.jpg" },
      doors: { title: "Five Shapes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-ch3-6dcb8c7d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-ch3-aa72f352.jpg" },
      oursortheirs: { title: "Whose Hand", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-finale-a3fa83df.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-protocols-lateral/sidedoor-finale-b9ae7528.jpg" },
    },
  },
  stations: [
    {
      id: "shares",
      label: "The Shares",
      topic: "The SMB connection sequence · default admin shares · SMB signing · SMBv1",
      tagline: "A dollar sign hides. It doesn't lock.",
      building: "archive",
      taskIds: ["winproto-r1"],
    },
    {
      id: "tickets",
      label: "The Tickets",
      topic: "AS and TGS exchanges · ticket fields · Kerberoasting · AS-REP roasting · Pass-the-Ticket",
      tagline: "A ticket works wherever it's carried",
      building: "vault",
      taskIds: ["winproto-r2", "winproto-o1", "winproto-r3", "winproto-q2"],
    },
    {
      id: "relayrecon",
      label: "Relay and Recon",
      topic: "NTLM Type 1, 2 and 3 · relay · Event ID 4776 · LDAP reconnaissance filters",
      tagline: "Someone asked who could be reached",
      building: "control",
      taskIds: ["winproto-r4", "winproto-r5", "winproto-q3"],
    },
    {
      id: "doors",
      label: "The Doors",
      topic: "Named pipes · DCERPC · PsExec · WMI · WinRM · RDP · scheduled tasks · Event ID 5145 and 7045",
      tagline: "One account, five shapes",
      building: "factory",
      taskIds: ["winproto-r6", "winproto-q1", "winproto-m1", "winproto-la1", "winproto-f1"],
    },
    {
      id: "oursortheirs",
      label: "Ours or Theirs",
      topic: "Reading a ticket sweep · what to cut · writing the rule · weighing a verdict",
      tagline: "The mechanism never tells you whose hand it was",
      building: "ticket",
      taskIds: ["winproto-la2", "winproto-qf1", "winproto-ac1"],
      boss: true,
    },
  ],
  personas: {
    "winproto-o1": { name: "Nomvula Strand", role: "Threat Hunter", line: "Put the exchange back in order for me." },
    "winproto-q2": { name: "Nomvula Strand", role: "Threat Hunter", line: "One user, two machines. What do the DC's records say?" },
    "winproto-q3": { name: "Nomvula Strand", role: "Threat Hunter", line: "It's only a directory query. So why am I asking you about it?" },
    "winproto-q1": { name: "Nomvula Strand", role: "Threat Hunter", line: "What would you want to know before you called this anything?" },
    "winproto-m1": { name: "Nomvula Strand", role: "Threat Hunter", line: "Tell me what each one rides on." },
    "winproto-la1": { name: "Nomvula Strand", role: "Threat Hunter", line: "Read the record from where it was written." },
    "winproto-f1": { name: "Nomvula Strand", role: "Threat Hunter", line: "Give me the path as it sits on disk." },
    "winproto-la2": { name: "Nomvula Strand", role: "Threat Hunter", line: "Read it as a whole, not line by line." },
    "winproto-qf1": { name: "Nomvula Strand", role: "Threat Hunter", line: "Write it so nobody has to find this by hand again." },
    "winproto-ac1": { name: "Nomvula Strand", role: "Threat Hunter", line: "One more on the board. Your verdict." },
  },
  briefings: {
    // ── Reading 1: SMB, the shares, signing ──
    "winproto-r1": [
      {
        kind: "sequence",
        title: "How an SMB Session Opens",
        prompt: "Sunday 01:12, the first hop: PM-PLOT-02 reached PM-DYE-05 over SMB and wrote a file. Nomvula has the capture. Tap the steps in the order they happened on the wire.",
        items: [
          { id: "tree", text: "Tree Connect: the client asks for \\\\PM-DYE-05\\ADMIN$", note: "Now the session is tied to one share. A share is a named resource: a folder, a printer, or a special one like this." },
          { id: "file", text: "Create: the client writes fixdrv.exe into the share", note: "Files and pipes can only be opened after a successful Tree Connect." },
          { id: "neg", text: "Negotiate: both sides agree on SMB 3.1.1 and its capabilities", note: "The dialect is chosen here, before anyone proves who they are." },
          { id: "setup", text: "Session Setup: adm-r.dube authenticates with Kerberos", note: "This step sets the identity. Everything after it runs as that user." },
        ],
        order: ["neg", "setup", "tree", "file"],
        doneNote: "Negotiate picks the dialect, Session Setup sets who you are, Tree Connect sets what you're reaching. That order is why a share log can name both the user and the share, and why nothing can be touched before all three have finished.",
        primer: {
          title: "SMB in one minute",
          points: [
            "**SMB** (Server Message Block) is the protocol behind Windows file sharing, and also behind a lot of remote administration.",
            "A session has **three stages** before any file opens. Each stage answers one question: which dialect, who are you, which share.",
            "A **share** is a named thing the server exposes, such as a folder.",
          ],
          example: {
            label: "Worked example: mapping a drive at the office",
            lines: [
              "`net use P: \\\\fileserver\\Pictures`",
              "Stage 1 agrees a dialect. Stage 2 signs you in. Stage 3 connects to `Pictures`.",
              "Only then does File Explorer list a folder.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "worksheet",
        title: "What Sits Behind a Hidden Share",
        prompt: "This is the share log from PM-DYE-05. Windows records where each share really lands in ShareLocalPath. Read it the way Nomvula does: who, from where, reaching what.",
        caption: "Security log · PM-DYE-05 · Event ID 5140 · Sunday",
        columns: ["Time", "ShareName", "ShareLocalPath", "IpAddress", "SubjectUserName"],
        rows: [
          ["01:12:03", "\\\\*\\ADMIN$", "\\??\\C:\\Windows", "172.20.8.31", "adm-r.dube"],
          ["01:12:04", "\\\\*\\IPC$", "(empty)", "172.20.8.31", "adm-r.dube"],
          ["02:00:11", "\\\\*\\C$", "\\??\\C:\\", "172.20.2.40", "svc-backup"],
          ["02:00:12", "\\\\*\\D$", "\\??\\D:\\", "172.20.2.40", "svc-backup"],
          ["08:30:40", "\\\\*\\DyeRecipes", "\\??\\D:\\DyeRecipes", "172.20.4.31", "t.achebe"],
        ],
        questions: [
          { id: "dollar", q: "Does the $ at the end of a share name stop anyone connecting? (yes/no)", hint: "svc-backup reached C$ and D$ without trouble. What does the mark change?", answer: ["no"], why: "The $ only keeps the share out of browse lists. What guards C$ and ADMIN$ is local administrator rights." },
          { id: "path", q: "The hop wrote fixdrv.exe into ADMIN$. What is its full local path on this machine?", hint: "Put the file name on the end of ADMIN$'s ShareLocalPath, without the \\??\\ prefix.", answer: ["C:\\Windows\\fixdrv.exe"], why: "ADMIN$ is %SystemRoot%, which is C:\\Windows on a default install. That's why a tool that writes to ADMIN$ drops its file straight into the Windows folder." },
          { id: "who", q: "Admin shares are used every night here. Which source IP is the one worth a question?", hint: "One address is the backup server doing its 02:00 job. Check the other.", answer: ["172.20.8.31"], why: "Admin-share access alone means nothing: svc-backup does it nightly. The pattern is what counts: an admin account, at 01:12, from a plotter PC that has no reason to manage a dye lab machine." },
        ],
      },
      {
        kind: "sort",
        title: "Normal Traffic or a Finding?",
        prompt: "Nomvula is writing up what the SMB review found across Pinehurst. Some of these are just Windows working. Some deserve a line in the report, incident or no incident. Sort them.",
        buckets: [{ id: "normal", label: "Normal by itself" }, { id: "finding", label: "Worth writing down" }],
        items: [
          { id: "s1", text: "A loom controller PC on the shed floor negotiates SMB1", bucket: "finding", why: "SMBv1 carried the EternalBlue flaw (MS17-010) that WannaCry and NotPetya used. Seeing it negotiated at all is a legacy finding, whatever else is going on." },
          { id: "s2", text: "svc-backup reads C$ on every backed-up machine at 02:00", bucket: "normal", why: "Backup agents use admin shares constantly. Same account, same time, every night." },
          { id: "s3", text: "PM-PLOT-02 has SMB signing off", bucket: "finding", why: "Without signing, nothing ties a session's authentication to this server, so a relayed sign-in can land here." },
          { id: "s4", text: "A new Windows 11 24H2 Pro PC requires signing, inbound and outbound", bucket: "normal", why: "That's the default on 24H2 Pro, Enterprise and Education. Older builds are the ones to chase." },
          { id: "s5", text: "The domain controller requires signing for SYSVOL and NETLOGON", bucket: "normal", why: "Domain controllers have long required it for those two shares." },
          { id: "s6", text: "A remote admin console opens IPC$ on a server during a ticketed job", bucket: "normal", why: "Remote administration uses IPC$ all day. The ticket and the source explain it." },
          { id: "s7", text: "A plotter PC reaches ADMIN$ on a machine it has never touched, at 01:12", bucket: "finding", why: "The share isn't the issue. Who, from where and when are. This is what a first hop looks like." },
        ],
        primer: {
          title: "Signing and the old dialect",
          points: [
            "**SMB signing** puts a cryptographic signature on every message. It stops tampering and, more importantly, relay attacks.",
            "It's set by Group Policy. Windows 11 24H2 Pro, Enterprise and Education require it both ways by default. Windows Server 2025 requires it only outbound, so inbound sessions aren't covered unless you set it.",
            "**SMBv1** is the 1980s dialect. It's off by default on current Windows, so seeing it means something old is still on the network.",
            "**Admin shares in use** are not a finding on their own. Legitimate tools use them all the time.",
          ],
          example: {
            label: "Worked example: writing down a dated setting",
            lines: [
              "`Get-SmbServerConfiguration` on an old print server shows `EnableSMB1Protocol True`.",
              "No attack is needed for this to matter: it goes in the report as a legacy finding.",
              "The same server serving print jobs all day from its usual clients does not.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 2: the ticket flow ──
    "winproto-r2": [
      {
        kind: "pcap",
        title: "Read a Kerberos Sign-In on the Wire",
        prompt: "Before Nomvula can tell a stolen ticket from a real one, you need to see a real one. This is e.sithole from Design opening the pattern archive at 07:55. The lab capture was decrypted with a test key, so the sealed fields are readable. Click a packet, read its tree, answer from it.",
        capture: "pm-des-09_archive_logon.pcapng",
        packets: [
          { no: 1, time: "0.000000", src: "172.20.4.31", dst: "172.20.2.5", proto: "KRB5", len: 318, info: "AS-REQ", tree: ["Internet Protocol Version 4, Src: 172.20.4.31, Dst: 172.20.2.5", "Transmission Control Protocol, Src Port: 50112, Dst Port: 88", "Kerberos: as-req", "  padata: PA-ENC-TIMESTAMP (etype 18, sealed with e.sithole's key)", "  req-body: cname e.sithole, realm PINEHURST.EXAMPLE", "  req-body: sname krbtgt/PINEHURST.EXAMPLE"] },
          { no: 2, time: "0.004112", src: "172.20.2.5", dst: "172.20.4.31", proto: "KRB5", len: 1604, info: "AS-REP", tree: ["Internet Protocol Version 4, Src: 172.20.2.5, Dst: 172.20.4.31", "Transmission Control Protocol, Src Port: 88, Dst Port: 50112", "Kerberos: as-rep", "  ticket: sname krbtgt/PINEHURST.EXAMPLE", "  ticket enc-part: etype 18, sealed with the krbtgt key. The client can't read this", "    PAC: group memberships", "    authtime 07:55:02, endtime 17:55:02", "  enc-part: etype 18, sealed with e.sithole's key. Holds the session key"] },
          { no: 3, time: "0.009870", src: "172.20.4.31", dst: "172.20.2.5", proto: "KRB5", len: 1712, info: "TGS-REQ", tree: ["Internet Protocol Version 4, Src: 172.20.4.31, Dst: 172.20.2.5", "Transmission Control Protocol, Src Port: 50113, Dst Port: 88", "Kerberos: tgs-req", "  padata: PA-TGS-REQ (carries the TGT from packet 2)", "  req-body: sname cifs/PM-ARCHIVE-01.pinehurst.example", "  req-body: etype 18, 17, 23"] },
          { no: 4, time: "0.013551", src: "172.20.2.5", dst: "172.20.4.31", proto: "KRB5", len: 1688, info: "TGS-REP", tree: ["Internet Protocol Version 4, Src: 172.20.2.5, Dst: 172.20.4.31", "Transmission Control Protocol, Src Port: 88, Dst Port: 50113", "Kerberos: tgs-rep", "  ticket: sname cifs/PM-ARCHIVE-01.pinehurst.example", "  ticket enc-part: etype 18, sealed with the key of the account that owns this SPN", "  enc-part: etype 18. Holds a new session key"] },
          { no: 5, time: "0.018204", src: "172.20.4.31", dst: "172.20.2.20", proto: "SMB2", len: 1790, info: "Session Setup Request", tree: ["Internet Protocol Version 4, Src: 172.20.4.31, Dst: 172.20.2.20", "Transmission Control Protocol, Src Port: 50114, Dst Port: 445", "SMB2: Session Setup Request", "  Security Blob: krb5 AP-REQ", "    ticket: the service ticket from packet 4", "    authenticator: fresh timestamp, sealed with the session key"] },
          { no: 6, time: "0.020338", src: "172.20.2.20", dst: "172.20.4.31", proto: "SMB2", len: 298, info: "Session Setup Response", tree: ["Internet Protocol Version 4, Src: 172.20.2.20, Dst: 172.20.4.31", "Transmission Control Protocol, Src Port: 445, Dst Port: 50114", "SMB2: Session Setup Response, NT Status: STATUS_SUCCESS"] },
        ],
        objectives: [
          { id: "proof", task: "Which packet number proves the user knows the password before the KDC issues anything?", hint: "padata", answer: ["1"], why: "PA-ENC-TIMESTAMP is a timestamp sealed with a key made from the password. It's the pre-authentication step, and one attack below is about skipping it." },
          { id: "tgtkey", task: "Packet 2: name the account whose key seals the TGT.", hint: "as-rep", answer: ["krbtgt"], why: "The client gets a TGT it can't read. Only the KDC can open it, because only the KDC holds the krbtgt key." },
          { id: "life", task: "Packet 2: how many hours lie between authtime and endtime?", hint: "endtime", answer: ["10", "10 hours"], why: "Ten hours is the default. A stolen copy keeps working until then, and until renew-till if it's renewed. The ticket carries no record of which machine asked for it." },
          { id: "port", task: "Packet 5: what destination port does the service ticket travel to?", hint: "smb2", answer: ["445"], why: "Nothing goes back to port 88 here. The ticket and a fresh authenticator go to the service itself, which opens it with its own key." },
        ],
        primer: {
          title: "Kerberos: two exchanges and a presentation",
          points: [
            "**KDC**: the Key Distribution Center, a service on each domain controller. It listens on TCP 88.",
            "**AS exchange**: prove who you are and receive a **TGT** (Ticket Granting Ticket).",
            "**TGS exchange**: show the TGT, name a service by its **SPN** (Service Principal Name), and receive a service ticket.",
            "**AP-REQ**: present that ticket with a fresh **authenticator**, a timestamp sealed with the session key, so an old copy of the message can't simply be replayed.",
            "**etype** is the cipher: 18 is AES-256, 23 is RC4.",
          ],
          example: {
            label: "Worked example: read sname first",
            lines: [
              "`sname krbtgt/EXAMPLE.TEST` means this exchange is for a TGT.",
              "`sname HTTP/intranet.example.test` means a web service is being asked for.",
              "One field tells you which stage of the flow you're looking at.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 3: what each attack changes ──
    "winproto-r3": [
      {
        kind: "lineup",
        title: "Which Kerberos Trick Left This?",
        prompt: "Nomvula keeps old case files from other investigations to train new hunters. Each round shows what the logs held. Open a dossier, then name the technique that fits.",
        suspects: [
          { id: "roast", name: "Kerberoasting", motive: "A service account's password, cracked offline from a service ticket", skill: "Any valid domain account and normal TGS-REQs", target: "Accounts with an SPN set, often over-privileged and rarely rotated" },
          { id: "asrep", name: "AS-REP roasting", motive: "A password, cracked offline from an AS-REP", skill: "No password at all: it only needs a username", target: "Accounts with DONT_REQ_PREAUTH set" },
          { id: "ptt", name: "Pass-the-Ticket", motive: "To reuse a valid ticket, cracking nothing", skill: "Reads tickets from LSASS memory on one machine and injects them on another", target: "Any logged-on user whose tickets sit in memory" },
          { id: "opth", name: "Overpass-the-hash", motive: "A fresh Kerberos TGT made from a stolen NTLM hash", skill: "Sends its own AS-REQ using the hash as the key", target: "Any account whose hash was stolen" },
        ],
        rounds: [
          { id: "c1", evidence: ["Event ID 4768, TargetUserName l.mbeki, PreAuthType 0, Status 0x0", "l.mbeki's userAccountControl includes 4194304", "Nobody logged on as l.mbeki that night"], suspect: "asrep", why: "PreAuthType 0 means the proof-of-password step was skipped, and the KDC answered anyway. Normal requests show PreAuthType 2. The reply can then be cracked offline, and the attacker needed no credentials." },
          { id: "c2", evidence: ["16 Event ID 4769 records in 90 seconds, all TargetUserName k.dlamini, Status 0x0", "ServiceName is a different service account in nearly every record", "k.dlamini is a payroll clerk, and none of those services saw a logon afterwards"], suspect: "roast", why: "Each request is ordinary, because issuing a ticket to any authenticated user is what a KDC does. The tell is the pattern: many different SPNs, fast, from a non-service account, and tickets that are never used. The cracking happens offline, so no log sees it." },
          { id: "c3", evidence: ["A file server records a Kerberos type 3 logon for v.naidoo from 172.16.8.60", "The DC holds no 4768 and no 4769 for v.naidoo from that address", "That morning's service ticket for the file server was requested from the laptop at 172.16.4.31"], suspect: "ptt", why: "A normal logon spans two machines, so a request from one host and a logon on another is fine by itself. What matters is where a ticket is used from. A service ticket goes straight to the service, so replaying a stolen one never touches the KDC, and an address that never asked the DC for anything is presenting a ticket anyway. A ticket has no binding to the machine that requested it." },
          { id: "c4", evidence: ["The DC holds a 4768 for v.naidoo from the laptop at 172.16.4.31", "It also holds a second 4768 for v.naidoo from 172.16.8.60, with TicketEncryptionType 0x17", "The domain issues AES tickets to everyone else"], suspect: "opth", why: "Compare this with the last round. Here the new address DID request its own TGT, so nothing was replayed. A fresh 4768 from the other host, in RC4 because the key is an NTLM hash, points to overpass-the-hash or plain credential theft." },
        ],
        primer: {
          title: "Each attack bends one step",
          points: [
            "**Kerberoasting** bends the TGS exchange. The service ticket is sealed with the service account's key, so it can be taken away and cracked offline.",
            "**AS-REP roasting** bends the AS exchange. If an account doesn't require pre-authentication, anyone can ask for its reply.",
            "**Pass-the-Ticket** bends nothing on the wire. A stolen ticket is simply used from somewhere else.",
            "**Remember the normal shape:** the workstation asks for the TGT (4768 on the DC) and the server records the logon (4624 on the server). Two machines are expected.",
            "Event IDs: **4768** TGT request, **4769** service ticket request, **4624** logon.",
          ],
          example: {
            label: "Worked example: walking one record back to one step",
            lines: [
              "A 4768 with `Status 0x6` means the KDC didn't know that username.",
              "4768 is the AS exchange, so this happened at the first step.",
              "Many of these from one source is someone testing usernames, not stealing tickets.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "worksheet",
        title: "Is RC4 Proof or a Hint?",
        prompt: "Saturday afternoon on PM-DC01. Tickets came back with two ciphers, and roasting tools like RC4 because it cracks far faster. Decide what the cipher tells you here, and what it doesn't.",
        caption: "Security log · PM-DC01 · Event ID 4769 · TicketEncryptionType: 0x12 AES-256, 0x17 RC4-HMAC",
        columns: ["Time", "TargetUserName", "ServiceName", "TicketEncryptionType", "Status", "IpAddress"],
        rows: [
          ["14:02:10", "e.sithole", "svc-dyelab", "0x17", "0x0", "172.20.4.31"],
          ["14:05:44", "e.sithole", "PM-ARCHIVE-01$", "0x12", "0x0", "172.20.4.31"],
          ["14:07:21", "t.achebe", "svc-dyelab", "0x17", "0x0", "172.20.4.36"],
          ["14:11:02", "t.achebe", "svc-erp", "0x12", "0x0", "172.20.4.36"],
          ["14:19:31", "g.pillay", "svc-erp", "0x17", "0x0", "172.20.8.31"],
          ["14:19:33", "g.pillay", "svc-dyelab", "0x17", "0x0", "172.20.8.31"],
          ["14:19:34", "g.pillay", "svc-plot", "0x17", "0x0", "172.20.8.31"],
          ["14:19:36", "g.pillay", "svc-inventory", "0x17", "0x0", "172.20.8.31"],
          ["14:19:37", "g.pillay", "svc-loomcal", "0x17", "0x0", "172.20.8.31"],
        ],
        questions: [
          { id: "legacy", q: "svc-dyelab came back RC4 for two ordinary users. Which account's settings explain that: the requester or the service account?", hint: "Two different requesters got the same cipher for the same service, and AES for others.", answer: ["service account", "the service account", "service", "svc-dyelab"], why: "The cipher comes from what the service account supports (msDS-SupportedEncryptionTypes, and whether it has AES keys), not from the requester's settings. An old service account can make RC4 tickets all day, innocently." },
          { id: "sweep", q: "Which requester looks like a sweep?", hint: "Don't count RC4 rows. Look at how many services one account reached, and how fast.", answer: ["g.pillay"], why: "Five different services in six seconds. The burst across SPNs is the decisive signal, and the cipher only supports it. Each ticket in the burst can now be cracked offline, out of sight." },
          { id: "aes", q: "svc-erp gave t.achebe AES but gave that requester RC4. Does that make the RC4 more suspicious or less? (more/less)", hint: "svc-erp can clearly do AES. So why would it come back weaker?", answer: ["more"], why: "A service that can do AES, returning RC4 in the middle of a burst, fits a tool asking for the weaker cipher. Legacy accounts explain a single RC4 ticket. They don't explain this." },
        ],
      },
    ],
    // ── Reading 4: NTLM and relay ──
    "winproto-r4": [
      {
        kind: "sequence",
        title: "Carry a Handshake Between Two Connections",
        prompt: "The Thursday before, a laptop nobody owns appeared on the Shed 2 network at 172.20.8.77. Nomvula rebuilt what it did to s.mhlongo, the shed supervisor, from the traces. Tap the steps in order.",
        items: [
          { id: "t3", text: "s.mhlongo's PC answers the challenge with a Type 3 and sends it to the rogue host", note: "The response is computed from the challenge and a key made from the password hash." },
          { id: "miss", text: "s.mhlongo mistypes a share name, and DNS can't find it", note: "Windows falls back to broadcast name lookups." },
          { id: "t1", text: "s.mhlongo's PC sends a Type 1 Negotiate to the rogue host", note: "It believes it has found the server." },
          { id: "win", text: "The rogue host forwards the Type 3 to PM-PLOT-02, and is in as s.mhlongo", note: "PM-PLOT-02 made that challenge itself, so the response looks perfect." },
          { id: "poison", text: "The rogue host answers the NBT-NS broadcast: that name is me", note: "Anyone on the segment can answer a broadcast." },
          { id: "t2", text: "PM-PLOT-02 issues a Type 2 challenge, and the rogue host passes it to s.mhlongo's PC", note: "The challenge is real and fresh, and it came from the real target." },
          { id: "open", text: "The rogue host opens its own SMB connection to PM-PLOT-02 and forwards the Type 1", note: "Now it sits between two live connections." },
        ],
        order: ["miss", "poison", "t1", "open", "t2", "t3", "win"],
        doneNote: "The rogue host never saw a password or a hash. It carried live messages between two connections that it timed itself. A saved response would have failed, because every challenge is fresh. A relay works because the response isn't tied to the server it was meant for, and that is the gap SMB signing closes.",
        primer: {
          title: "NTLM in three messages",
          points: [
            "**NTLM** is the older Windows sign-in, used when Kerberos can't be: no line of sight to a DC, or a server reached by IP address.",
            "**Type 1, Negotiate:** the client says what it supports.",
            "**Type 2, Challenge:** the server sends a random 8-byte value, new each time, so an old response can't be replayed against it.",
            "**Type 3, Authenticate:** the client mixes the challenge with a key from the password hash and sends the result. The server, or a DC on its behalf, checks it.",
            "**LLMNR and NBT-NS** are broadcast name lookups. They let any host on the segment claim a name that DNS couldn't find.",
          ],
          example: {
            label: "Worked example: a normal handshake",
            lines: [
              "Laptop to print server: Type 1.",
              "Print server to laptop: Type 2, challenge `1a2b3c4d5e6f7a8b`.",
              "Laptop to print server: Type 3, its response to that challenge.",
              "The print server asks a DC to check it, and the DC logs Event ID 4776.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "anatomy",
        title: "Read an NTLM Check on the DC",
        prompt: "This is the DC's record of the relayed sign-in. Read it field by field and notice what isn't there.",
        source: "Security log · PM-DC01 · Event ID 4776 · Thursday 16:42",
        fields: [
          { key: "event.code", value: "4776", label: "What", note: "The DC checked an NTLM credential. Kerberos sign-ins don't write this event." },
          { key: "winlog.event_data.PackageName", value: "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" },
          { key: "winlog.event_data.TargetUserName", value: "s.mhlongo", label: "Who", note: "The account being checked." },
          { key: "winlog.event_data.Workstation", value: "PM-SHED-14", label: "Claims to be from", note: "A name supplied by the client inside the handshake, not a verified address. In a relay it is the victim's PC, because the victim built the Type 3." },
          { key: "winlog.event_data.Status", value: "0x0", label: "Result", note: "Success. A relayed response is a valid response." },
        ],
        summary: "The record has no source IP. It tells you who and claims where, which is one reason NTLM is hard to trace and why teams move to Kerberos where they can. To find a relay, go to the target instead: PM-PLOT-02's 4624 shows WorkstationName PM-SHED-14 with IpAddress 172.20.8.77, and that mismatch between the name and the address is the tell.",
      },
      {
        kind: "sort",
        title: "Would the Relay Land Here?",
        prompt: "Nomvula needs to know where else that rogue laptop could have gone. Go through Pinehurst's list of targets and call each one.",
        buckets: [{ id: "lands", label: "Relay lands" }, { id: "fails", label: "Relay fails" }],
        items: [
          { id: "n1", text: "PM-DC01: domain controller, SMB signing required", bucket: "fails", why: "Each message must be signed with a key from the real authentication. The relay never holds that key." },
          { id: "n2", text: "PM-FIN-03: Windows 10 PC, server signing enabled but not required", bucket: "lands", why: "Enabled only means it will sign if the client asks. The relaying client doesn't ask. The near miss here is reading 'enabled' as 'safe'." },
          { id: "n3", text: "A new Windows 11 24H2 Enterprise laptop on default settings", bucket: "fails", why: "24H2 Enterprise, Pro and Education require inbound signing by default. Home doesn't, so the edition matters." },
          { id: "n4", text: "An internal web app using Windows sign-in over plain HTTP", bucket: "lands", why: "Relay isn't only an SMB problem. Plain HTTP has no channel to bind to, so nothing ties the response to this server." },
          { id: "n5", text: "An LDAPS service with channel binding enforced", bucket: "fails", why: "Channel binding ties the authentication to that TLS channel, and the relay's channel is a different one." },
          { id: "n6", text: "PM-ERP-02: file shares with signing turned off", bucket: "lands", why: "Nothing ties the session to the authentication, which is what the attack needs." },
        ],
        primer: {
          title: "What closes a relay",
          points: [
            "**Signing required:** every message needs a key the relay never receives.",
            "**Enabled is not required.** A server that only allows signing will happily run an unsigned session.",
            "**Channel binding** and **Extended Protection for Authentication** do the same job on TLS: they tie the sign-in to that one channel.",
          ],
          example: {
            label: "Worked example: reading the setting",
            lines: [
              "`Get-SmbServerConfiguration` on a test server:",
              "`EnableSecuritySignature True`, `RequireSecuritySignature False`",
              "It signs if asked. Nothing forces anyone to ask, so treat it as open.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 5: LDAP reconnaissance ──
    "winproto-r5": [
      {
        kind: "sort",
        title: "Crawl or Everyday Lookup?",
        prompt: "Directory queries are constant at Pinehurst, and Friday night's are mixed in with everything else. Any domain user may run nearly all of them, so permissions won't help. Sort them the way Nomvula would.",
        buckets: [{ id: "routine", label: "Everyday lookup" }, { id: "recon", label: "Reconnaissance" }],
        items: [
          { id: "l1", text: "The HR sync reads 640 user objects at 05:00 daily, the same attributes each time", bucket: "routine", why: "It's large, but it's scheduled, one job, and always the same attributes." },
          { id: "l2", text: "The computer account PM-PLOT-02$ runs 4,100 searches across 30 filters in 4 minutes", bucket: "recon", why: "Volume and breadth from an account with no history of it. A plotter PC has no reason to read the whole directory." },
          { id: "l3", text: "An admin runs (adminCount=1) once during the quarterly access review", bucket: "routine", why: "The same filter an attacker likes, but once, from someone with a reason. A filter alone proves nothing." },
          { id: "l4", text: "A clerk's account walks member and memberOf through every group in 3 minutes", bucket: "recon", why: "Recursive group walks are how tools like BloodHound build their graph of who can reach what." },
          { id: "l5", text: "The help desk tool looks up one user's phone number", bucket: "routine", why: "This is why the directory is readable: normal work depends on it." },
          { id: "l6", text: "One user account reads every object's group memberships and permissions in one sitting", bucket: "recon", why: "SharpHound, BloodHound's collector, has this high-volume, wide-reaching pattern." },
          { id: "l7", text: "The print server asks for the printers in one OU every hour", bucket: "routine", why: "Narrow, repeated, and it fits what the machine is for." },
        ],
        primer: {
          title: "LDAP: bind, then search",
          points: [
            "**LDAP** (Lightweight Directory Access Protocol) is how clients read Active Directory.",
            "A session starts with a **bind**, which signs in. Any domain user can bind.",
            "Each **search** names a base DN (where to start), a scope (how deep), and a filter (what to return).",
            "Most of the directory is readable by every user, by design. So LDAP recon needs **no special rights** and no single query proves it.",
            "The signal is **volume and breadth** from one account in a short time, compared with what it did before.",
          ],
          example: {
            label: "Worked example: reading one search",
            lines: [
              "Base: `OU=Printers,DC=example,DC=test`, scope: one level",
              "Filter: `(objectClass=printQueue)`",
              "One OU, one object type, one question. A user finding a printer.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "worksheet",
        title: "What a Filter Says Comes Next",
        prompt: "Friday 23:40, on the DC. These are searches from PM-PLOT-02, with what each one returns. An attacker runs a filter for a reason, and that reason tells you what to watch for next.",
        caption: "Directory Service log · PM-DC01 · Event ID 1644 · client 172.20.8.31",
        columns: ["Time", "Filter", "Returned", "What it returns"],
        rows: [
          ["23:40:02", "(adminCount=1)", "23", "Accounts stamped as protected, now or in the past"],
          ["23:40:05", "(userAccountControl:1.2.840.113556.1.4.803:=4194304)", "2", "Accounts with the DONT_REQ_PREAUTH bit set"],
          ["23:40:09", "(&(objectClass=user)(servicePrincipalName=*))", "61", "Every account with an SPN, computers included"],
          ["23:40:12", "(&(samAccountType=805306368)(servicePrincipalName=*))", "14", "User accounts with an SPN"],
          ["23:40:20", "(memberOf=CN=IT Admins,OU=Groups,DC=pinehurst,DC=example)", "6", "Direct members of one group"],
        ],
        questions: [
          { id: "next", q: "The second row found 2 accounts. On the DC, watch for Event ID 4768 with which PreAuthType value?", hint: "That bit means the proof-of-password step isn't needed.", answer: ["0"], why: "DONT_REQ_PREAUTH is the target list for AS-REP roasting, so the next step would be a 4768 with PreAuthType 0. The method is the point: the filter names the target list, and the target list names the next event." },
          { id: "narrow", q: "Rows 3 and 4 differ because computers are dropped. How many accounts are left once they are?", hint: "samAccountType 805306368 means normal user accounts.", answer: ["14"], why: "Computer objects also match objectClass=user and always carry SPNs, but their passwords are long and random. Attackers narrow the list, and an analyst reading the filter should see that care." },
          { id: "stamp", q: "adminCount=1 returned 23 accounts. Is every one of them an admin today? (yes/no)", hint: "What happens to the stamp when an account leaves a protected group?", answer: ["no"], why: "AdminSDHolder stamps adminCount and doesn't remove it when someone leaves the group. It's a useful hunting signal, and an imperfect one." },
        ],
        primer: {
          title: "Reading an LDAP filter",
          points: [
            "`&` means all the conditions must match, and `*` means the attribute has any value.",
            "`1.2.840.113556.1.4.803` is a **bitwise AND**: it tests one bit inside a number such as `userAccountControl`.",
            "Ask two questions of any filter: **what list does it build**, and **what could someone do with that list**.",
          ],
          example: {
            label: "Worked example: from filter to next step",
            lines: [
              "`(&(objectCategory=computer)(operatingSystem=*2012*))`",
              "It builds a list of Windows Server 2012 machines.",
              "Someone who wants that list wants old servers, so watch for new connections to them.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 6: pipes, RPC and the doors ──
    "winproto-r6": [
      {
        kind: "anatomy",
        title: "Read a Named Pipe Record",
        prompt: "Sunday 01:39. Two minutes before anything ran on PM-ERP-02, something asked that server a question. Read the record it left. Direction and pipe name are the two things people get wrong.",
        source: "Security log · PM-ERP-02 · Event ID 5145",
        fields: [
          { key: "winlog.computer_name", value: "PM-ERP-02.pinehurst.example", label: "Written on", note: "5145 is logged by the machine whose share was reached, so this is the target, not the source." },
          { key: "event.code", value: "5145", label: "What", note: "A network share object was checked for access. It needs the Detailed File Share audit setting, which is noisy and often off." },
          { key: "winlog.event_data.SubjectUserName", value: "adm-r.dube", label: "As whom" },
          { key: "winlog.event_data.IpAddress", value: "172.20.4.23", label: "From", note: "The remote client. It's PM-FIN-03, and the connection went from there to here." },
          { key: "winlog.event_data.ShareName", value: "\\\\*\\IPC$", label: "Share", note: "IPC$ has no folder behind it. It exists to carry named pipes." },
          { key: "winlog.event_data.RelativeTargetName", value: "wkssvc", label: "Pipe", note: "The pipe names the RPC interface, and so the capability. wkssvc is the workstation service, which can list who is logged on." },
          { key: "winlog.event_data.AccessMask", value: "0x12019f", note: "Read and write on the pipe: a conversation, not a look." },
        ],
        summary: "A remote client asked PM-ERP-02 who was logged on before moving there. Other pipes name other capabilities: svcctl reaches the Service Control Manager, atsvc the Task Scheduler, epmapper the RPC endpoint mapper. So the pipe name is what turns 'SMB traffic' into a specific action. Read every 5145 the same way: where it was written is the target, IpAddress is the source, RelativeTargetName is the capability.",
        primer: {
          title: "Named pipes and RPC",
          points: [
            "**RPC** (Remote Procedure Call) lets one machine call a function on another. Windows remote administration is built on **DCERPC**.",
            "A **named pipe** is a channel to one service. Over SMB, a client reaches it through **IPC$** as if opening a file.",
            "One pipe is one interface, so the name tells you the capability being used.",
          ],
          example: {
            label: "Worked example: a printer job",
            lines: [
              "A 5145 on a print server shows `ShareName \\\\*\\IPC$` and `RelativeTargetName spoolss`.",
              "`spoolss` is the Print Spooler interface.",
              "So the client was talking to the spooler, not browsing any folder.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "sequence",
        title: "Install a Service From Another Machine",
        prompt: "Back to Sunday 01:12, the file you found in ADMIN$. Nomvula wants the rest of that hop. fixdrv.exe is a stranger's tool, but it works like any service-based remote execution tool. Put the steps in order.",
        items: [
          { id: "start", text: "A second RPC call starts the service, and fixdrv.exe runs", note: "Services run as SYSTEM by default, which is why attackers like this door." },
          { id: "copy", text: "fixdrv.exe is copied into the Windows folder through ADMIN$", note: "This takes local administrator rights on the target." },
          { id: "auth", text: "adm-r.dube authenticates to PM-DYE-05 and connects to ADMIN$", note: "It's the same SMB sequence you ordered at the first station." },
          { id: "pipe", text: "The client connects to IPC$ and opens \\PIPE\\svcctl", note: "This pipe reaches the Service Control Manager." },
          { id: "create", text: "An RPC call over the pipe creates a service pointing at fixdrv.exe", note: "PM-DYE-05's System log now records Event ID 7045." },
        ],
        order: ["auth", "copy", "pipe", "create", "start"],
        doneNote: "That's the shape of every service-based tool, and PsExec is the famous one. Renaming the service changes the name in the 7045, not the fact that a 7045 was written. Only this door installs a service, as the next lab shows.",
      },
      {
        kind: "deduce",
        title: "Which Door Did They Use?",
        prompt: "Sunday 01:26. adm-r.dube went from PM-DYE-05 to PM-FIN-03, and the account says nothing, because IT uses it every week. Five doors could fit. Nomvula reads you the evidence from both machines. Strike out each door that couldn't have left this shape, then accuse.",
        nameColumn: "Door",
        columns: ["Network", "Source shows", "Target logon", "New service?", "Command starts"],
        suspects: [
          { id: "smb", name: "SMB service", cells: ["TCP 445: ADMIN$, IPC$, \\PIPE\\svcctl", "PsExec.exe or sc.exe \\\\host", "Network", "Yes: 7045", "At once, under the new service"] },
          { id: "wmi", name: "WMI", cells: ["TCP 135, then a dynamic high port", "wmic.exe /node or Invoke-WmiMethod", "Network", "No", "At once, child of WmiPrvSE.exe"] },
          { id: "winrm", name: "WinRM", cells: ["TCP 5985 (HTTP) or 5986 (HTTPS)", "powershell.exe: Invoke-Command", "Network", "No", "At once, child of wsmprovhost.exe"] },
          { id: "rdp", name: "RDP", cells: ["TCP 3389, no RPC or pipes", "mstsc.exe", "RemoteInteractive (type 10)", "No", "By hand, in a desktop session"] },
          { id: "task", name: "Scheduled task", cells: ["\\PIPE\\atsvc on TCP 445, or RPC on a high port", "schtasks.exe /create /s host", "Network, then Batch if run as a user", "No", "At trigger time, child of svchost.exe"] },
        ],
        clues: [
          "PM-FIN-03's System log has no Event ID 7045 anywhere near that hour.",
          "Nobody sat down at it: no RemoteInteractive logon, no rdpclip.exe, no new desktop session.",
          "The remote session ended at 01:27. The command ran at 01:37, ten minutes later, with nothing connected.",
        ],
        culprit: "task",
        why: "A scheduled task splits the hop in two: the session that registers it, and the run that happens later. WMI and WinRM were the near misses, and both also leave no 7045, but they run the command while the session is open. To confirm a task, look on the target for Event ID 4698 (if Other Object Access auditing is on), TaskScheduler Operational 106 for the registration and 200 for the run, and the task file under C:\\Windows\\System32\\Tasks. On the source, schtasks.exe names the target.",
        primer: {
          title: "Five doors, five shapes",
          points: [
            "A **door** is the protocol an account uses to run something on another machine. When the account is the same each time, the door is what you read.",
            "Read **two machines**. The source shows the tool that started it. The target shows what arrived.",
            "Only the service door writes **Event ID 7045**. The others register no service.",
            "On the target, each door runs the command under a different **parent process**.",
            "**A missing trace is evidence.** If a door must leave something and it isn't there, strike that door.",
          ],
          example: {
            label: "Worked example: a sixth door, OpenSSH Server",
            lines: [
              "Evidence: TCP 22 to a Windows server, no 7045, the command's parent is `sshd.exe`.",
              "TCP 22 rules out every door that needs 445, 135, 5985 or 3389.",
              "The parent process names the door. No single log line had to say 'SSH'.",
            ],
          },
          fold: true,
        },
      },
    ],
    // Drill before q1: the pipe names a capability, context judges it.
    "winproto-q1": [
      {
        kind: "sort",
        title: "Explained or Open?",
        prompt: "A week of remote access at Pinehurst, pulled from the share logs. The mechanism looks the same in every row. Sort them by whether something already explains the row, or whether you owe someone a question.",
        buckets: [{ id: "known", label: "Explained" }, { id: "ask", label: "Still open" }],
        items: [
          { id: "w1", text: "PM-PATCH-01 opens \\PIPE\\atsvc on 40 shed PCs as svc-patch, in Tuesday's change window", bucket: "known", why: "A named server, a named account, a known window. The task pipe is simply how the patch run starts." },
          { id: "w2", text: "PM-SHED-14 opens \\PIPE\\atsvc on PM-SHED-09 at 23:10, as a supervisor's account", bucket: "ask", why: "PC to PC, a user account, late at night. Workstations rarely manage each other, so someone has to say why." },
          { id: "w3", text: "PM-BKP-01 reads C$ on every backed-up machine at 02:00 as svc-backup", bucket: "known", why: "Admin share, nightly, the account built for it." },
          { id: "w4", text: "A laptop nobody recognises opens a management pipe on a PC, and no new service follows", bucket: "ask", why: "No new service clears nothing. Pipes can also query, change or stop what's already there. The unknown source is the question." },
          { id: "w5", text: "PM-JUMP1 opens wkssvc on a server as adm-l.sato, with a change open for that server", bucket: "known", why: "The approved source, an admin account, and a record that covers it." },
          { id: "w6", text: "A designer's laptop reads ADMIN$ on a finance PC at lunchtime", bucket: "ask", why: "A busy hour doesn't explain it. A designer has no reason to reach a finance PC's Windows folder." },
          { id: "w7", text: "An unsigned session opens \\PIPE\\spoolss on the print server from the print admin's PC", bucket: "known", why: "Unsigned tells you about a setting, not an attacker. A session without signing is not proof of a relay." },
        ],
        primer: {
          title: "The same pipe, two stories",
          points: [
            "Attackers and IT use **the same mechanism**, so the record alone rarely settles it.",
            "The **pipe** tells you what was done. It doesn't tell you why.",
          ],
          example: {
            label: "Worked example: a monitoring tool",
            lines: [
              "A monitoring server opens `\\PIPE\\winreg` on every server at each poll.",
              "Its setup document lists that pipe, so the row has a reason.",
              "The same pipe from a receptionist's PC has no reason on file, so it stays open.",
            ],
          },
          fold: true,
        },
      },
    ],
    // Drill before m1: the hop no service log recorded.
    "winproto-m1": [
      {
        kind: "hunt",
        title: "Find the Hop No Service Log Saw",
        prompt: "Saturday's backups ran clean, yet someone looked at them. Nomvula's tip: an admin reached PM-BKP-01 by PowerShell Remoting, from somewhere other than IT's jump host. Build the hunt one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceProcessEvents",
        goal: "one row: the remote command that didn't come from PM-JUMP1, with its source address",
        tables: [
          {
            name: "DeviceProcessEvents",
            note: "Process creation.",
            columns: ["Timestamp", "DeviceName", "AccountName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "InitiatingProcessLogonId"],
            rows: [
              ["10-30 10:14", "pm-erp-02", "adm-l.sato", "wevtutil.exe", "wevtutil qe System /c:20", "wsmprovhost.exe", "4118203"],
              ["10-30 10:22", "pm-bkp-01", "adm-l.sato", "ipconfig.exe", "ipconfig /all", "wsmprovhost.exe", "2290417"],
              ["10-30 16:40", "pm-jump1", "adm-l.sato", "tasklist.exe", "tasklist /fi \"imagename eq wsmprovhost.exe\"", "cmd.exe", "1120654"],
              ["10-31 23:02", "pm-erp-02", "svc-inventory", "systeminfo.exe", "systeminfo /fo csv", "wsmprovhost.exe", "4390771"],
              ["10-31 23:03", "pm-bkp-01", "svc-inventory", "systeminfo.exe", "systeminfo /fo csv", "wsmprovhost.exe", "2415538"],
              ["11-01 01:41", "pm-erp-02", "adm-r.dube", "cmd.exe", "cmd.exe /c whoami /groups", "WmiPrvSE.exe", "996"],
              ["11-01 01:57", "pm-bkp-01", "adm-r.dube", "wsmprovhost.exe", "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", "svchost.exe", "999"],
              ["11-01 01:58", "pm-bkp-01", "adm-r.dube", "wbadmin.exe", "wbadmin get versions", "wsmprovhost.exe", "3806115"],
              ["11-01 08:05", "pm-fin-03", "n.osei", "EXCEL.EXE", "EXCEL.EXE ledger.xlsx", "explorer.exe", "988120"],
            ],
          },
          {
            name: "DeviceLogonEvents",
            note: "Sign-ins on a device.",
            columns: ["Timestamp", "DeviceName", "AccountName", "LogonType", "RemoteIP", "LogonId"],
            rows: [
              ["10-30 10:13", "pm-erp-02", "adm-l.sato", "Network", "172.20.1.10", "4118203"],
              ["10-30 10:21", "pm-bkp-01", "adm-l.sato", "Network", "172.20.1.10", "2290417"],
              ["10-31 23:02", "pm-erp-02", "svc-inventory", "Network", "172.20.1.22", "4390771"],
              ["10-31 23:03", "pm-bkp-01", "svc-inventory", "Network", "172.20.1.22", "2415538"],
              ["11-01 01:41", "pm-erp-02", "adm-r.dube", "Network", "172.20.4.23", "3806115"],
              ["11-01 01:57", "pm-bkp-01", "adm-r.dube", "Network", "172.20.2.12", "3806115"],
              ["11-01 08:02", "pm-fin-03", "n.osei", "Interactive", "-", "988120"],
            ],
          },
        ],
        rungs: [
          {
            id: "parent", ask: "Line 2: keep what PowerShell Remoting ran on a target.",
            choices: [
              { id: "a", text: "| where FileName =~ \"wsmprovhost.exe\"", why: "That's the host process itself, one row. You want what it started, which sits in the parent column.", apply: { op: "where", col: "FileName", test: "ieq", value: "wsmprovhost.exe" } },
              { id: "b", text: "| where ProcessCommandLine has \"wsmprovhost\"", why: "Too loose: a tasklist on the jump host came back just for naming it. Filter on what ran, not on what a command line mentions.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "wsmprovhost" } },
              { id: "c", text: "| where InitiatingProcessFileName =~ \"wsmprovhost.exe\"", right: true, why: "Commands run through Remoting are children of wsmprovhost.exe. Five rows, and not one of them needed a 7045.", apply: { op: "where", col: "InitiatingProcessFileName", test: "ieq", value: "wsmprovhost.exe" } },
            ],
          },
          {
            id: "base", ask: "Line 3: svc-inventory does this on every server, every night. Drop that known baseline and nothing else.",
            choices: [
              { id: "a", text: "| where AccountName =~ \"adm-r.dube\"", why: "One name you already suspect. A hunt has to catch the admin account you haven't thought of yet, so remove what's explained and keep the rest.", apply: { op: "where", col: "AccountName", test: "ieq", value: "adm-r.dube" } },
              { id: "b", text: "| where AccountName !in~ (\"svc-inventory\")", right: true, why: "Baseline gone, three rows left. They're all admin accounts, and they may well be IT doing its job: the account can't settle that.", apply: { op: "where", col: "AccountName", test: "notin", value: ["svc-inventory"] } },
              { id: "c", text: "| where ProcessCommandLine has \"systeminfo\"", why: "That keeps the baseline and throws away everything else.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "systeminfo" } },
            ],
          },
          {
            id: "join", ask: "Line 4: this table can't say where a session came from. Bring in the sign-in behind each process.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceLogonEvents on AccountName", why: "That pairs each process with every sign-in the account ever made, on any host. The row count grew, which is the warning.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName" } },
              { id: "b", text: "| join kind=inner DeviceLogonEvents on DeviceName", why: "Every sign-in on that server, by anyone, came along. A device isn't a session.", apply: { op: "join", table: "DeviceLogonEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "c", text: "| join kind=inner DeviceLogonEvents on $left.InitiatingProcessLogonId == $right.LogonId", why: "Close, but one process now has two sign-ins, one from another server. A logon ID is unique only on one device between restarts, and here two hosts share a number.", apply: { op: "join", table: "DeviceLogonEvents", left: "InitiatingProcessLogonId", right: "LogonId" } },
              { id: "d", text: "| join kind=inner DeviceLogonEvents on DeviceName, $left.InitiatingProcessLogonId == $right.LogonId", right: true, why: "The device plus the logon ID identifies one session, so each process meets exactly one sign-in, and RemoteIP is now on the row.", apply: { op: "join", table: "DeviceLogonEvents", left: "InitiatingProcessLogonId", right: "LogonId", also: "DeviceName" } },
            ],
          },
          {
            id: "src", ask: "Line 5: IT's approved source is PM-JUMP1, 172.20.1.10. Keep what didn't come from there.",
            choices: [
              { id: "a", text: "| where RemoteIP in (\"172.20.1.10\")", why: "Reversed: that keeps the approved work and drops the question.", apply: { op: "where", col: "RemoteIP", test: "in", value: ["172.20.1.10"] } },
              { id: "b", text: "| where LogonType == \"RemoteInteractive\"", why: "Nothing returned. Remoting arrives as a Network logon. RemoteInteractive is the shape of a different door.", apply: { op: "where", col: "LogonType", test: "eq", value: "RemoteInteractive" } },
              { id: "c", text: "| where RemoteIP !in (\"172.20.1.10\")", right: true, why: "One row. The same kind of command, on the same kind of server, and only the source separates it from IT's work.", apply: { op: "where", col: "RemoteIP", test: "notin", value: ["172.20.1.10"] } },
            ],
          },
          {
            id: "show", ask: "Line 6: show what the case note needs.",
            choices: [
              { id: "a", text: "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteIP", right: true, why: "When, where, who, what ran, and the address to chase next: 172.20.2.12 is PM-ERP-02, so that is the previous hop.", apply: { op: "project", cols: ["Timestamp", "DeviceName", "AccountName", "ProcessCommandLine", "RemoteIP"] } },
              { id: "b", text: "| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteIP1", why: "Only clashing right-hand columns get the suffix 1. DeviceLogonEvents is the only table with RemoteIP, so RemoteIP1 doesn't exist.", apply: { op: "project", cols: ["Timestamp", "DeviceName", "AccountName", "ProcessCommandLine", "RemoteIP1"] } },
              { id: "c", text: "| summarize count() by RemoteIP", why: "A count says how often. The note needs what ran, where and as whom.", apply: { op: "summarize", by: ["RemoteIP"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Start from the door's shape, not the account: the parent process. Remove what's explained. Tie each process to its own sign-in, by device and logon ID, because neither alone identifies a session. Then judge by source. In a real query, add a Timestamp limit, and check that a join didn't change the row count.",
        primer: {
          title: "What Remoting leaves, and how to tie two tables",
          points: [
            "On the target, PowerShell Remoting runs in **wsmprovhost.exe**. Anything it starts has that as its parent.",
            "The session behind it is a `Network` logon in `DeviceLogonEvents`, with the source in `RemoteIP`.",
            "`LogonId` ties a process to its sign-in. In `DeviceProcessEvents`, the matching column is `InitiatingProcessLogonId`.",
            "A logon ID is only unique on one device, between restarts.",
            "`=~` ignores case, and `!in~` means not in the list, ignoring case.",
          ],
          example: {
            label: "Worked example: the parent, not the process",
            lines: [
              "Question: what did the print spooler start?",
              "`| where InitiatingProcessFileName =~ \"spoolsv.exe\"` lists what it started.",
              "`| where FileName =~ \"spoolsv.exe\"` lists the spooler itself, the wrong half.",
            ],
          },
          fold: true,
        },
      },
    ],
    // Drill before la1: the record the target writes when a service arrives.
    "winproto-la1": [
      {
        kind: "anatomy",
        title: "Read a Service Install Record",
        prompt: "This is the 7045 PM-DYE-05 wrote at Sunday 01:12, right after the pipe opened. One field fools people every time.",
        source: "System log · PM-DYE-05 · Event ID 7045",
        fields: [
          { key: "Provider", value: "Service Control Manager", label: "Written by" },
          { key: "event.code", value: "7045", label: "What", note: "A service was installed. It's in the System log, not Security." },
          { key: "ServiceName", value: "FixDrvSvc", label: "Name", note: "Whatever the tool chose. Renaming changes this field, not the event." },
          { key: "ImagePath", value: "%SystemRoot%\\fixdrv.exe", label: "What runs", note: "A plain tool in the Windows folder, with a generic name, is worth checking against the file you found in ADMIN$." },
          { key: "ServiceType", value: "user mode service" },
          { key: "StartType", value: "demand start", note: "Started on request, used once, not meant to survive a reboot." },
          { key: "AccountName", value: "LocalSystem", label: "Runs as", note: "The account the service runs under. It isn't who logged on, and it isn't who connected." },
        ],
        summary: "The 7045 says what was installed and how it will run. Its fields don't name the connecting user or the source: the header holds the installer's SID, and the share record two seconds earlier gives the source IP. Put them side by side: pipe access, then a new service seconds later, on the same host. Then ask whether anyone approved that account doing this from that source.",
      },
    ],
    // ── The boss station: the sweep, the rule, the verdict ──
    "winproto-la2": [
      {
        kind: "outbreak",
        title: "Chasing One Account Host by Host",
        prompt: "Nomvula's drill, before the real call. One admin credential is loose on a flat network, and every link on this map is a door it opens. You get one tool on purpose: isolate one host a turn. Keep it off the pattern archive, and notice what that costs you.",
        hostPrefix: "PM-WS",
        cols: 6,
        rows: 5,
        crown: "ARCHIVE",
        via: "the adm-r.dube credential through any open door",
        lesson: "Count what you did. You spent a turn per host while the account moved along every link at once, and the only way to win is to give up machines and cut ahead of it. Real incidents offer better. What's moving is a credential, so disable it and purge its tickets, and every link dies on every host in one move. If you can't do that yet, cut a protocol: a host firewall rule that blocks SMB, WinRM and RDP between workstations closes those doors everywhere at once. Isolation still has its place, to hold evidence and stop what's running on one machine. It can't stop an account that's valid everywhere else.",
        primer: {
          title: "What are you actually cutting?",
          points: [
            "**A host** is one place. **A credential** is every place it's valid.",
            "**A protocol** is one door on every host at the same time.",
            "Before you act, count what each action closes. Pick the one that closes the most for the least damage.",
          ],
          example: {
            label: "Worked example: a stolen office badge",
            lines: [
              "Lock one office: 1 of 40 rooms closed, and the badge still opens 39.",
              "Cancel the badge: 40 of 40 closed, in one move.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "sort",
        title: "What Does Each Cut Reach?",
        prompt: "Sunday 03:10 at Pinehurst, and adm-r.dube is still live. The duty manager has a list of possible moves. Sort them by how far each one reaches.",
        buckets: [{ id: "wide", label: "Closes it everywhere" }, { id: "one", label: "Closes one place" }],
        items: [
          { id: "c1", text: "Disable adm-r.dube in Active Directory", bucket: "wide", why: "A credential is every place it's valid, so this reaches every host. Tickets already issued carry on until endtime, so they need their own purge." },
          { id: "c2", text: "Block inbound SMB between workstations with a host firewall policy", bucket: "wide", why: "A protocol cut: one door closed on every workstation in one change." },
          { id: "c3", text: "Allow RDP only from PM-JUMP1, by firewall policy on every server", bucket: "wide", why: "One door narrowed everywhere, including on servers you haven't looked at yet." },
          { id: "c4", text: "Isolate PM-BKP-01", bucket: "one", why: "Good for holding evidence on that host. The account still works on every other machine." },
          { id: "c5", text: "Shut the switch port of PM-FIN-03", bucket: "one", why: "That machine stops talking, and nothing else changes." },
          { id: "c6", text: "Stop the WinRM service on PM-ERP-02", bucket: "one", why: "The right idea on one host. SMB, WMI and RDP stay open there, and WinRM stays open everywhere else." },
          { id: "c7", text: "Remove adm-r.dube from local Administrators on the ERP server", bucket: "one", why: "It protects one machine. Every other host still accepts the account." },
        ],
      },
    ],
    "winproto-qf1": [
      {
        kind: "worksheet",
        title: "Count or Distinct Count?",
        prompt: "Before the rule goes in, Nomvula tests the thinking on an old case from another site. These are Event ID 4768 records with PreAuthType 0, grouped by source into 5-minute bins. One source is noise and one is a roaster. Work out which measure can tell them apart.",
        caption: "4768, PreAuthType 0 · summarize attempts = count(), accounts = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 5m)",
        columns: ["Bin", "IpAddress", "attempts", "accounts"],
        rows: [
          ["01:05", "172.16.9.12", "9", "9"],
          ["01:10", "172.16.9.12", "2", "2"],
          ["09:00", "172.16.1.41", "38", "1"],
          ["09:05", "172.16.1.41", "41", "1"],
          ["13:15", "172.16.4.18", "3", "2"],
        ],
        questions: [
          { id: "count", q: "A rule of attempts > 20 fires on which IP?", hint: "Read the attempts column only.", answer: ["172.16.1.41"], why: "An old scanner retrying one no-preauth account over and over. Raw count catches the loud, not the wide." },
          { id: "dcount", q: "A rule of accounts > 5 fires on how many bins?", hint: "Read the accounts column only.", answer: ["1"], why: "Nine different accounts in one bin. dcount asks 'how many different targets', which is the shape of a sweep." },
          { id: "stretch", q: "The same nine requests, spread evenly over 30 minutes. Would accounts > 5 in a 5-minute bin still fire? (yes/no)", hint: "How many accounts land in each bin now?", answer: ["no"], why: "One or two per bin. The window and the threshold work together: a window too short misses slow sweeps, too long and everyday work adds up. Pick both from your own baseline." },
        ],
        primer: {
          title: "Measuring a sweep",
          points: [
            "`count()` counts rows. `dcount(x)` counts **different values** of x.",
            "`bin(TimeGenerated, 5m)` groups rows into fixed time slots.",
            "One source touching many targets shows in `dcount`, even when the raw count is small.",
          ],
          example: {
            label: "Worked example: password spraying",
            lines: [
              "`summarize tried = dcount(TargetAccount) by IpAddress, bin(TimeGenerated, 10m)`",
              "A locked-out user retrying 30 times: `tried` is 1.",
              "A spray of one password at 30 users: `tried` is 30.",
            ],
          },
          fold: true,
        },
      },
    ],
    "winproto-ac1": [
      {
        kind: "queue",
        title: "What Does the Record Have to Prove?",
        prompt: "Last month's queue, from Nomvula's training set. Each alert is a remote action, or looks like one, and some come with a reason attached. Open each one, check the reason against the fields, and close or escalate it.",
        console: "SIEM · Incidents",
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "q1", time: "Tue 12:30", severity: "Medium", rule: "Remote scheduled task created", entity: "PM-SHED-03",
            fields: [{ k: "Account", v: "svc-patch" }, { k: "Source", v: "172.20.1.30 (PM-PATCH-01)" }, { k: "TaskName", v: "\\PinehurstPatchRun" }, { k: "Action", v: "C:\\ProgramData\\PinehurstIT\\patchrun.exe" }],
            context: "IT confirms PM-PATCH-01 is the patch server. Change CHG-2291, approved the previous Thursday, covers all Shed 2 PCs in this window.",
            answer: "btp",
            why: "A remote task really was created, so the alert was right. PM-PATCH-01, the patchrun.exe path and CHG-2291 all line up for this PC in this window, so the patch run is what you saw. Close it as benign true positive with CHG-2291 in the note.",
          },
          {
            id: "q2", time: "Sat 23:40", severity: "High", rule: "Process started by WmiPrvSE.exe from a remote session", entity: "PM-FIN-03",
            fields: [{ k: "Account", v: "adm-l.sato" }, { k: "Source", v: "172.20.1.10 (PM-JUMP1)" }, { k: "CommandLine", v: "cmd.exe /c net group \"Domain Admins\" /domain" }, { k: "Ticket", v: "INC-5120" }],
            context: "IT says INC-5120 was a mailbox fault on PM-HR-02, closed last Thursday. adm-l.sato was not on call.",
            answer: "esc",
            why: "The source is the approved jump host, and a ticket number is attached, but the ticket covers another host, closed days ago, and the command has nothing to do with it. A right source can be a stolen one. Escalate.",
          },
          {
            id: "q3", time: "Wed 02:01", severity: "Low", rule: "Admin share access from another host", entity: "PM-BKP-01",
            fields: [{ k: "Account", v: "PM-BKP-01$" }, { k: "IpAddress", v: "::1" }, { k: "ShareName", v: "\\\\*\\C$" }, { k: "Process", v: "backup agent on the same host" }],
            context: "IpAddress ::1 is the machine's own loopback address. The backup agent reads its own C$ through a local path, and the rule doesn't exclude loopback.",
            answer: "fp",
            why: "Nothing remote happened, so the rule misfired on what it was built to catch. That's a false positive, and the fix belongs in the rule: exclude loopback. Compare the first alert, where the rule was right and the activity was approved.",
          },
          {
            id: "q4", time: "Mon 14:03", severity: "High", rule: "Remote process via WinRM", entity: "PM-PLOT-02",
            fields: [{ k: "Account", v: "adm-j.botha" }, { k: "Source", v: "172.20.1.10 (PM-JUMP1)" }, { k: "CommandLine", v: "C:\\Users\\Public\\drv.exe /quiet" }, { k: "Ticket", v: "INC-5188, plotter driver install" }],
            context: "IT says INC-5188 was opened at 14:22 by adm-j.botha. The plotter's assigned user didn't ask for anything, and drivers normally come from the software centre.",
            answer: "esc",
            why: "The ticket came 19 minutes after the action, written by the account being checked, and the file ran from a public folder rather than the normal deployment path. A ticket proves something only if it was opened first, by someone else, and if the footprint matches.",
          },
        ],
        primer: {
          title: "What makes a remote action ours",
          points: [
            "**Benign true positive:** the alert is right and the activity is authorised. Close it and cite the record.",
            "**False positive:** the alert matched something the rule wasn't built to catch. The fix belongs in the rule.",
            "Check the **source**: is it documented for this work? Check the **account**: is this its job?",
            "Check the **record**: does it name this host, was it opened before the action, and by someone other than the actor?",
            "Check the **footprint**: does what ran match the tool that is supposed to run? Confirm all of this with IT, not from the alert's own text.",
          ],
          example: {
            label: "Worked example: a certificate renewal",
            lines: [
              "Alert: new scheduled task on a web server, from the certificate server.",
              "Source and account match the documented renewal job, and the task's action is the renewal tool.",
              "The change record names this server and was approved last week. Benign true positive, cite the change.",
            ],
          },
          fold: true,
        },
      },
    ],
  },
};
