import type { RoomExperience } from "./types";

// Experience for "active-directory" (rooms-batch-03.ts).
//
// The 3D world is a tower climbed floor by floor, from the workstation subnet
// at the ground floor up to the domain's crown (the Domain Controller and
// Domain Admin). Each station is a floor; the tower rises as the learner clears
// the task ids below, which are listed in exact room order.
//
// Briefing labs teach each reading hands-on. Their example data is a fictional
// "Blackpine" domain (blackpine.example / BLACKPINE) on the 192.0.2.0/24 and
// 198.51.100.0/24 RFC 5737 documentation ranges, with service accounts, users
// and hosts that appear in NO graded task, so a lab never hands over an answer.
export const ACTIVE_DIRECTORY: RoomExperience = {
  roomId: "active-directory",
  codename: "Operation High Tower",
  theme: "domain",
  scene: "tower",
  layout: "stage",
  handler: { name: "Dana Reyes", role: "SOC Lead, Night Shift" },
  briefing: [
    "01:40. Something is moving inside the domain, one floor at a time.",
    "This building is Active Directory: every identity in the company lives here.",
    "Learn how the tower is built and how it proves who you are. Then read the tickets.",
    "Climb carefully. Each floor you clear puts you nearer the crown, where Domain Admin lives.",
  ],
  mission:
    "Suspicious identity activity is climbing the domain. Learn how Active Directory and Kerberos really work, read the evidence floor by floor, and decide what stops the climb before it reaches Domain Admin.",
  estimate: "~65 min",
  look: { primary: "#a78bfa", secondary: "#38bdf8", warn: "#fb7185" },
  stations: [
    {
      id: "ground",
      label: "Ground Floor: The Directory",
      tagline: "Learn what AD is, then open the first two locked terminals",
      building: "archive",
      taskIds: ["ad-r1", "ad-q1", "ad-q4"],
    },
    {
      id: "mezzanine",
      label: "Mezzanine: The Ticket Office",
      tagline: "How Kerberos proves who you are, and three questions on the flow",
      building: "office",
      taskIds: ["ad-r2", "ad-q2", "ad-q3"],
    },
    {
      id: "monitoring",
      label: "Monitoring Floor: The Evidence Room",
      tagline: "What to watch, then a live RC4 ticket, a flag and a scoping query",
      building: "lab",
      taskIds: ["ad-r3", "ad-la1", "ad-flag1", "ad-qf1"],
    },
    {
      id: "quietfloor",
      label: "The Quiet Floor",
      tagline: "The attacks that make almost no noise: roasting and relay",
      building: "factory",
      taskIds: ["ad-r4", "ad-q7", "ad-r5", "ad-la2", "ad-flag2"],
    },
    {
      id: "crown",
      label: "The Crown",
      tagline: "The whole-domain attacks, the off-hours DC logon, and the handover",
      building: "vault",
      taskIds: ["ad-q5", "ad-q6", "ad-ac1", "ad-wr1"],
      boss: true,
    },
  ],
  personas: {
    "ad-ac1": {
      name: "Priya Nair",
      role: "IT Operations · On-call",
      line: "That's one of our maintenance service accounts on DC01. I can pull the change record if you need it.",
    },
  },
  briefings: {
    // ── Reading 1: what AD is, the DC, forest/domain/OU, groups, GPOs, trusts ──
    "ad-r1": [
      {
        kind: "sort",
        title: "Workgroup or Domain?",
        prompt:
          "Blackpine is deciding how to run its Windows machines. Sort each statement under the model it describes.",
        buckets: [
          { id: "wg", label: "Workgroup" },
          { id: "dom", label: "Domain" },
        ],
        items: [
          { id: "w1", text: "Each PC keeps its own local accounts; a password change on one does nothing on the others", bucket: "wg", why: "No central directory: every machine is on its own." },
          { id: "w2", text: "Fine for a home or a 3-person office with no central control", bucket: "wg", why: "Workgroups do not scale past a handful of machines." },
          { id: "d1", text: "One account signs in everywhere, and IT disables it once to cut off new access", bucket: "dom", why: "A single directory account is the point of a domain." },
          { id: "d2", text: "IT pushes one screen-lock policy to every machine from a central place", bucket: "dom", why: "Central policy enforcement is a domain capability (Group Policy)." },
        ],
      },
      {
        kind: "match",
        title: "Name the Container",
        prompt:
          "Blackpine's directory is laid out in nested containers. Match each AD structure to what it is.",
        pairs: [
          { id: "forest", left: "Forest", right: "The outermost security boundary; shares one schema across all its domains", why: "The forest, not the domain, is the real security boundary." },
          { id: "domain", left: "Domain (blackpine.example)", right: "The main administrative unit where users, computers and groups live", why: "A domain holds the objects and has a DNS name." },
          { id: "ou", left: "Organizational Unit (OU=Finance)", right: "A folder inside a domain that Group Policy can be linked to", why: "OUs organise objects and are a GPO link target." },
          { id: "gc", left: "Global Catalog", right: "A forest-wide index for finding objects in any domain", why: "The GC answers cross-domain lookups." },
        ],
      },
      {
        kind: "sort",
        title: "Security Group or Distribution Group?",
        prompt:
          "An admin is cleaning up Blackpine's groups. Which groups can actually control access to a file share, and which only send email?",
        buckets: [
          { id: "sec", label: "Security group (controls access)" },
          { id: "dist", label: "Distribution group (email only)" },
        ],
        items: [
          { id: "g1", text: "FIN-Share-RW, placed on the Finance share's permissions so members can read and write", bucket: "sec", why: "Only a security group can sit on an ACL and grant access." },
          { id: "g2", text: "All-Staff-Announcements, used so one email reaches everyone", bucket: "dist", why: "Distribution groups are for mail only and grant no access." },
          { id: "g3", text: "Helpdesk-Admins, added to the local Administrators group on support PCs", bucket: "sec", why: "Granting rights anywhere means it must be a security group." },
          { id: "g4", text: "Book-Club, a mailing list for a social group", bucket: "dist", why: "No resource access, so a distribution group is enough." },
        ],
      },
      {
        kind: "simulate",
        title: "A GPO Change Ripples Out",
        prompt:
          "Group Policy pushes settings down to whatever it is linked to. Pick a link point and see who it reaches.",
        checks: [
          { name: "Scope", question: "Which objects sit under this link point?" },
          { name: "Applies to", question: "Who actually receives the setting?" },
        ],
        scenarios: [
          {
            id: "ou",
            label: "GPO linked to OU=Finance",
            detail: "A screen-lock policy linked to the Finance OU, which holds 40 user and computer objects.",
            results: ["pass", "pass"],
            why: ["Only objects inside OU=Finance are in scope.", "Those 40 objects apply the policy; the rest of the domain is untouched."],
            verdict: "Targeted. A GPO linked to an OU reaches only what lives in that OU.",
          },
          {
            id: "domain",
            label: "GPO linked at the domain root",
            detail: "A password-length policy linked to blackpine.example itself.",
            results: ["pass", "pass"],
            why: ["Every object in the domain is under the domain root.", "All users and computers apply it."],
            verdict: "Domain-wide. This is how one policy reaches the whole company at once.",
          },
          {
            id: "attacker",
            label: "Attacker edits a GPO linked to All-Computers",
            detail: "An attacker who can modify a widely-linked GPO adds a startup script.",
            results: ["pass", "fail"],
            why: ["The GPO is in scope for every computer.", "Every machine would run the attacker's script at startup: exactly why GPO edit rights are a prize."],
            verdict: "This is the danger the reading warns about: one GPO edit can touch every machine in scope.",
          },
        ],
      },
    ],

    // ── Reading 2: Kerberos flow and the ticket attacks ──
    "ad-r2": [
      {
        kind: "sequence",
        title: "Issue the Wristbands",
        prompt:
          "u.okonkwo signs in at Blackpine and then opens a share on FS-BP01. Tap the Kerberos steps in the order they happen.",
        items: [
          { id: "k1", text: "AS-REQ: the PC sends a timestamp encrypted with u.okonkwo's password key", note: "Proves the password without sending it." },
          { id: "k2", text: "AS-REP: the KDC returns a TGT (encrypted with the krbtgt key) and a session key", note: "Logged as Event ID 4768." },
          { id: "k3", text: "TGS-REQ: the PC presents the TGT and asks for a ticket to CIFS on FS-BP01", note: "The TGT is the wristband shown at the gate." },
          { id: "k4", text: "TGS-REP: the KDC returns a service ticket encrypted with FS-BP01's key", note: "Logged as Event ID 4769." },
          { id: "k5", text: "AP-REQ: the PC sends the service ticket to FS-BP01, which opens it with its own key", note: "The server reads identity and group memberships and decides access." },
        ],
        order: ["k1", "k2", "k3", "k4", "k5"],
        doneNote:
          "ID at the gate (AS-REQ/REP, 4768), then show the wristband to each ride (TGS-REQ/REP, 4769), then hand the ride its own ticket (AP-REQ). The password itself never crosses the wire.",
      },
      {
        kind: "match",
        title: "Which Key Seals the Ticket?",
        prompt:
          "Every Kerberos ticket is encrypted with some account's key, and that choice decides who can open it. Match each ticket to the key that seals it.",
        pairs: [
          { id: "tgt", left: "TGT", right: "The krbtgt account's key: only the KDC can open it", why: "Steal the krbtgt hash and you can forge TGTs (Golden Ticket)." },
          { id: "svc", left: "Service ticket for the CIFS service on FS-BP01", right: "FS-BP01's own key: only that server can open it", why: "The client just carries the ticket; it cannot read it." },
          { id: "spn", left: "Service ticket for the SPN of svc-reporting", right: "The svc-reporting account's password key: crackable offline", why: "This is exactly why Kerberoasting works." },
          { id: "sess", left: "The session key from AS-REP", right: "Lets the PC and the KDC talk securely afterwards", why: "Not a ticket; a shared key for the conversation." },
        ],
      },
      {
        kind: "match",
        title: "Name the Ticket Attack",
        prompt:
          "Match each Kerberos attack to the one sentence that describes it.",
        pairs: [
          { id: "ptt", left: "Pass-the-Ticket", right: "Steal a valid TGT from memory and inject it into your own session", why: "Become the user with their ticket, no password." },
          { id: "roast", left: "Kerberoasting", right: "Request a service ticket for an SPN and crack its encrypted blob offline", why: "Any domain user can request it; no special rights." },
          { id: "golden", left: "Golden Ticket", right: "Forge TGTs for any account using the krbtgt hash", why: "Whole-domain power; survives user password resets." },
          { id: "silver", left: "Silver Ticket", right: "Forge one service ticket with a service account's hash, never touching the KDC", why: "Limited to that service, but quieter." },
        ],
      },
    ],

    // ── Reading 3: what to monitor, reading 4769, scoping, verdicts ──
    "ad-r3": [
      {
        kind: "match",
        title: "What Does This Event ID Tell You?",
        prompt:
          "A Blackpine analyst is tuning alerts. Match each Windows Security Event ID to what it records.",
        pairs: [
          { id: "e4768", left: "4768", right: "A Kerberos TGT was requested (watch PreAuthType and encryption type)", why: "The AS exchange; logged on the DC." },
          { id: "e4769", left: "4769", right: "A Kerberos service ticket was requested (watch RC4 and high volume)", why: "The TGS exchange; the Kerberoasting event." },
          { id: "e4625", left: "4625", right: "A logon failed (many from one source can be a spray or brute force)", why: "Failed logon." },
          { id: "e4662", left: "4662", right: "A directory service object was accessed (the DCSync tell on the domain object)", why: "Needs Directory Service Access auditing." },
          { id: "e1102", left: "1102", right: "The security audit log was cleared", why: "A classic cover-your-tracks action." },
        ],
      },
      {
        kind: "inspect",
        title: "Read a 4769 Field by Field",
        prompt:
          "Here is a service ticket event from Blackpine's DC. Open each field: which one names the roast target, which one names the requester, and which one is the host to examine next?",
        artifact: "Event 4769 · Blackpine DC · raw event data",
        items: [
          { id: "tun", text: "TargetUserName: a.fletcher@BLACKPINE.EXAMPLE", tag: "The requester", tone: "info",
            note: "The account that ASKED for the ticket. This is who you pivot on, and may itself be compromised." },
          { id: "svc", text: "ServiceName: svc-reporting", tag: "The roast target", tone: "warn",
            note: "The service account the ticket was requested FOR. In Kerberoasting this is the account whose password is being attacked offline." },
          { id: "enc", text: "TicketEncryptionType: 0x17", tag: "RC4: suspicious", tone: "warn",
            note: "0x17 is RC4, which cracks fast. 0x11/0x12 are AES. RC4 for an account that supports AES stands out." },
          { id: "ip", text: "IpAddress: ::ffff:198.51.100.66", tag: "Examine this host next", tone: "warn",
            note: "The machine that sent the request, in IPv4-mapped form. This is the host you look at for the tool that made the request." },
          { id: "st", text: "Status: 0x0", tag: "Ticket was issued", tone: "info",
            note: "0x0 means success: a ticket was handed out. Any other value is a failure and no ticket was issued." },
        ],
      },
      {
        kind: "sort",
        title: "Close, Escalate, or Keep Open?",
        prompt:
          "The reading gives you four verdicts. Sort each Blackpine alert into the right one.",
        buckets: [
          { id: "tp", label: "True positive" },
          { id: "btp", label: "Benign true positive" },
          { id: "fp", label: "False positive" },
          { id: "esc", label: "Escalate" },
        ],
        items: [
          { id: "v1", text: "An RC4 service-ticket burst from a user workstation for five service accounts, no change record", bucket: "tp", why: "Real malicious Kerberoasting: it fired on the real thing." },
          { id: "v2", text: "A DC backup account runs its nightly replication inside the window named in change CHG00210", bucket: "btp", why: "Real activity, but authorised: close it citing the ticket, do not weaken the rule." },
          { id: "v3", text: "A 'new admin group member' alert that turns out to match a built-in group the rule mis-parsed", bucket: "fp", why: "The rule did not fire on what it was built to detect." },
          { id: "v4", text: "A Domain Admin logs on interactively to a DC at 02:00 and you cannot find any change record", bucket: "esc", why: "Risky and unconfirmed: it goes up now." },
        ],
      },
    ],

    // ── Reading 4: AS-REP Roasting ──
    "ad-r4": [
      {
        kind: "sequence",
        title: "Roast a Quiet Account",
        prompt:
          "svc-faxgw at Blackpine has pre-authentication disabled. Tap the steps of an AS-REP Roast in order.",
        items: [
          { id: "r1", text: "Pull a list of usernames from earlier directory enumeration", note: "No password needed for the targets." },
          { id: "r2", text: "Ask the KDC for an AS-REP for each username", note: "A tool like GetNPUsers or Rubeus does this." },
          { id: "r3", text: "For svc-faxgw (pre-auth disabled), the KDC returns an AS-REP straight away", note: "The encrypted part is sealed with the account's password key." },
          { id: "r4", text: "Take the encrypted blob offline and run a password cracker against it", note: "No KDC contact: no lockout, no logs." },
          { id: "r5", text: "Log in normally with the cracked password", note: "This is where the chain becomes visible again." },
        ],
        order: ["r1", "r2", "r3", "r4", "r5"],
        doneNote:
          "The only DC event is a single 4768 with PreAuthType 0 when the AS-REP is handed out. Cracking happens entirely on the attacker's machine and logs nothing.",
      },
      {
        kind: "sort",
        title: "PreAuthType: Roastable or Routine?",
        prompt:
          "Sort each 4768 PreAuthType value by what it means for an account.",
        buckets: [
          { id: "roast", label: "Pre-auth absent (roastable)" },
          { id: "normal", label: "Pre-auth present (routine)" },
        ],
        items: [
          { id: "p0", text: "PreAuthType 0", bucket: "roast", why: "No pre-authentication: only allowed when DONT_REQ_PREAUTH is set, so the account is roastable." },
          { id: "p2", text: "PreAuthType 2 (PA-ENC-TIMESTAMP)", bucket: "normal", why: "The standard password pre-auth: almost every 4768 in a password domain." },
          { id: "p15", text: "PreAuthType 15 or 16 (smart card / PKINIT)", bucket: "normal", why: "A different way of pre-authenticating, still pre-auth." },
          { id: "p138", text: "PreAuthType 138 (Kerberos armoring / FAST)", bucket: "normal", why: "Armored pre-auth, still present." },
        ],
      },
      {
        kind: "simulate",
        title: "Is Someone Roasting It?",
        prompt:
          "A flagged account always logs PreAuthType 0. The source is what tells you whether an attack is in progress. Judge each case.",
        checks: [
          { name: "PreAuthType", question: "Was pre-auth absent (0)?" },
          { name: "Source", question: "Did it come from a host that should use this account?" },
        ],
        scenarios: [
          {
            id: "app",
            label: "The real application server",
            detail: "svc-faxgw logs 4768 PreAuthType 0 from FAXGW-BP01, the documented legacy fax host, every morning.",
            results: ["pass", "pass"],
            why: ["The flag is set, so 0 is expected.", "The source is the account's own known host."],
            verdict: "Roastable by design, but this is the legitimate app. Fix the flag or harden the password; do not chase this logon.",
          },
          {
            id: "attack",
            label: "A roast in progress",
            detail: "svc-faxgw logs 4768 PreAuthType 0 from 198.51.100.202, a host that has never used the account, asking for RC4.",
            results: ["pass", "fail"],
            why: ["Pre-auth absent, as always for this account.", "The source is an unknown host asking for a crackable RC4 reply: someone just collected an AS-REP."],
            verdict: "Treat as an AS-REP Roast. The value says roastable; the strange source says it is being roasted now.",
          },
        ],
      },
    ],

    // ── Reading 5: LLMNR/NBT-NS poisoning and NTLM relay ──
    "ad-r5": [
      {
        kind: "sequence",
        title: "How a Relay Unfolds",
        prompt:
          "A Blackpine user mistypes a share name. Tap the steps of an LLMNR-poisoning NTLM relay in order.",
        items: [
          { id: "n1", text: "The user types \\\\flie-srv\\hr; DNS has no such name", note: "A typo for file-srv." },
          { id: "n2", text: "The PC broadcasts an LLMNR/NBT-NS query asking who is 'flie-srv'", note: "UDP 5355 / 137, trusts the first answer." },
          { id: "n3", text: "The attacker's Responder answers 'that's me, authenticate here'", note: "No verification of who may reply." },
          { id: "n4", text: "The PC sends its NTLM authentication to the attacker", note: "Username and challenge-response from the password hash." },
          { id: "n5", text: "The attacker relays it live to a real server the user can access", note: "Not cracking: forwarding the live auth." },
          { id: "n6", text: "That server, not requiring SMB signing, accepts it as the user", note: "The attacker now has a session as the victim." },
        ],
        order: ["n1", "n2", "n3", "n4", "n5", "n6"],
        doneNote:
          "Nothing looks like brute force. The tell is a successful NTLM logon whose claimed WorkstationName does not match the source IP the logon really came from.",
      },
      {
        kind: "inspect",
        title: "Spot the Mismatch",
        prompt:
          "An NTLM logon on a Blackpine server, enriched with inventory and DHCP. Open each field: does the logon really come from the machine it names?",
        artifact: "Event 4624 · FILE-SRV-BP03 · NTLM network logon",
        items: [
          { id: "pkg", text: "AuthenticationPackageName: NTLM", tag: "NTLM, not Kerberos", tone: "warn",
            note: "Internal server-to-server auth usually uses Kerberos. NTLM here is worth a second look." },
          { id: "wks", text: "WorkstationName: WS-BPN-114", tag: "Client-supplied name", tone: "info",
            note: "The name the client claims. The server does not verify it." },
          { id: "ip", text: "IpAddress: 198.51.100.240", tag: "Where it really came from", tone: "warn",
            note: "The actual source of the connection: this is what you trust over the claimed name." },
          { id: "cmdb", text: "Inventory lookup for 198.51.100.240: no matching asset", tag: "Unknown device", tone: "warn",
            note: "The source address belongs to no known asset: a rogue device, not WS-BPN-114." },
          { id: "dhcp", text: "DHCP lease for WS-BPN-114: 198.51.100.51", tag: "Its real address", tone: "trust",
            note: "The named workstation actually holds a different address, so the logon did not come from it." },
        ],
      },
      {
        kind: "sort",
        title: "Respond to a Confirmed Relay",
        prompt:
          "The relay on FILE-SRV-BP03 is confirmed. Sort each action into the response.",
        buckets: [
          { id: "do", label: "Do it" },
          { id: "dont", label: "Don't" },
        ],
        items: [
          { id: "a1", text: "Contain the unknown device at 198.51.100.240 first", bucket: "do", why: "It is the poisoner and keeps relaying for every user on the subnet." },
          { id: "a2", text: "Reset the victim's credentials and end the sessions the relay opened on the server", bucket: "do", why: "The relayed session is live even though the password was never cracked." },
          { id: "a3", text: "Recommend disabling LLMNR/NBT-NS and requiring SMB signing", bucket: "do", why: "The durable fixes that make relay fail." },
          { id: "a4", text: "Re-image WS-BPN-114, since the logon names it as the source", bucket: "dont", why: "The victim PC only supplied the name; the access came from the rogue device." },
          { id: "a5", text: "Close it as a DHCP glitch because the names and addresses disagree", bucket: "dont", why: "The disagreement is the attack, not a lease error." },
        ],
      },
    ],
  },
};
