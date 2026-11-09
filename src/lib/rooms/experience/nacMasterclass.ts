import type { RoomExperience } from "./types";

// "Operation Front Door" for the "nac-masterclass" room.
// Script: docs/campaign/65-nac-masterclass.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ravensford Academy Trust (fictional school group), not the graded tasks' corp.com records.
// Signature: Walk the 802.1X Door, a pathway through supplicant, authenticator and RADIUS to an
// Access-Accept, a VLAN and a posture outcome, and Tune the MAB Door, a two-dial profiling rule
// that lets printers and cameras pass and stops a cloned MAC.
// Game mix: codebreak + pathway + tune.
//
// TASK ORDER CHANGED: the room lists all readings first, which leaves no graded task inside the
// early stations. New order:
//   r1, r2, r3, q1 | r4, r7, r8, q3 | r5, r6, r9 | r10, q2 | la1, f1
//
// Lab data differs from the graded tasks. VLANs are 110/120/130/140/199, never 10/30/40/50, and
// devices are ravensford.example, never corp.com, SW-ACCESS-FL2-01 or ISE-PSN-01. The closed port
// is heard through a static-IP PC's ARP, never DHCP Discover (q1). A deployment missing a gate is
// shown missing Authenticate or Authorize, never Assess (r1 checkpoint). The profile sheet is
// wired PEAP with server validation off, never a rogue AP comparing methods (r3 checkpoint). Node
// questions are about MnT and PAN symptoms, PSN is a labelled row only (r7 checkpoint). Which Leg
// Broke? uses a shared secret, a silent supplicant, a wrong password and a CRL, never a directory
// outage (q3). Agents appear as facts in a match, never as a visiting laptop to place (r5
// checkpoint). Cloned MACs are cameras, door controllers and signage on Linux or Mac hardware,
// never a printer copied by a Windows host, and printers here are the honest devices (q2). Posture
// failures are disk encryption, EDR and banned software, never stale AV plus missing patches
// (la1). The ISE records are a contractor with an acceptable-use redirect and a table of other
// rules, never Posture-NonCompliant or the QUARANTINE profile (la1, f1). SASE parts appear only
// inside a why (r9 checkpoint).

export const NAC_MASTERCLASS: RoomExperience = {
  roomId: "nac-masterclass",
  codename: "Operation Front Door",
  theme: "frontdoor",
  handler: { name: "Lwazi Petrov", role: "Network Security Engineer, Ravensford Academy Trust" },
  briefing: [
    "Ravensford Academy Trust. Seven schools, one network, and until this summer any wall port in any classroom could reach the pupil records.",
    "Lwazi Petrov spent the holidays closing those doors with 802.1X, so every device now has to prove itself before a port opens.",
    "On the first Monday of term, a corridor camera at Hollins Vale Academy signed in from the library block, where no camera has ever been.",
    "Learn how a port decides, who really decides, what the answer carries and how the door gets cheated, then read a quarantine record on your own.",
  ],
  mission: "Hear what a closed port lets through, walk a device through the 802.1X door, read the Access-Accept, place a failure on the right leg, treat posture results as leads, tune the door so real devices pass and cloned ones do not, then read a quarantine record field by field.",
  estimate: "~70 min",
  look: { primary: "#bef264", secondary: "#7dd3fc", warn: "#f43f5e" },
  scene: "facilityfrontdoor",
  layout: "facility",
  story: {
    intro: { title: "The First Monday", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-intro-0c35e077.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-intro-470e80f4.jpg" },
    afterStation: {
      decision: { title: "That Afternoon", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-ch2-7b9d51b1.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-ch2-45c7a3d1.jpg" },
      health: { title: "After the Last Bell", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-ch3-5d11a82b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-ch3-65b908d7.jpg" },
      record: { title: "Front Door", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-finale-d278c52f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/nac-masterclass/frontdoor-finale-269a966a.jpg" },
    },
  },
  stations: [
    {
      id: "port",
      label: "The Port",
      topic: "Why NAC exists · authenticate, assess, authorize · supplicant, authenticator, server · 802.1X and EAP",
      tagline: "Plugged in proves nothing",
      building: "reception",
      taskIds: ["nac-r1", "nac-r2", "nac-r3", "nac-q1"],
    },
    {
      id: "decision",
      label: "The Decision",
      topic: "RADIUS · Access-Accept attributes · accounting · Cisco ISE · Aruba ClearPass",
      tagline: "The switch never decides",
      building: "control",
      taskIds: ["nac-r4", "nac-r7", "nac-r8", "nac-q3"],
    },
    {
      id: "health",
      label: "The Health Check",
      topic: "Posture assessment · VLAN segmentation · Zero Trust · Conditional Access · SASE",
      tagline: "Right person, healthy device?",
      building: "lab",
      taskIds: ["nac-r5", "nac-r6", "nac-r9"],
    },
    {
      id: "bypass",
      label: "The Bypass",
      topic: "MAC Authentication Bypass · profiling · multi-host ports · guest VLAN abuse · rogue RADIUS",
      tagline: "How the door gets cheated",
      building: "vault",
      taskIds: ["nac-r10", "nac-q2"],
    },
    {
      id: "record",
      label: "The Quarantine Record",
      topic: "Reading one ISE event field by field: rule, profile, VLAN, ACL, redirect",
      tagline: "One record, every decision",
      building: "ticket",
      taskIds: ["nac-la1", "nac-f1"],
      boss: true,
    },
  ],
  personas: {
    "nac-q1": { name: "Lwazi Petrov", role: "Network Security Engineer", line: "A technician is on the phone asking me this. What do I say?" },
    "nac-q3": { name: "Lwazi Petrov", role: "Network Security Engineer", line: "The outage review is at two. Where do I put the failure?" },
    "nac-q2": { name: "Lwazi Petrov", role: "Network Security Engineer", line: "Someone has to explain this entry before lunch. What's your read?" },
    "nac-la1": { name: "Lwazi Petrov", role: "Network Security Engineer", line: "One alert, one record. Read all of it before you tell me what it means." },
    "nac-f1": { name: "Lwazi Petrov", role: "Network Security Engineer", line: "Give me the name exactly as the log has it." },
  },
  briefings: {
    // ── Reading 1: what NAC is for ──
    "nac-r1": [
      {
        kind: "sort",
        title: "Three Questions at the Door",
        prompt: "Before the summer, any Ravensford wall port reached the pupil records, because being plugged in counted as proof. Network Access Control (NAC) replaces that with three questions, asked in order. Put each check under the question it answers.",
        buckets: [
          { id: "authn", label: "Authenticate: who are you?" },
          { id: "assess", label: "Assess: is the device healthy?" },
          { id: "authz", label: "Authorize: what may you reach?" },
        ],
        items: [
          { id: "i1", text: "A school laptop presents its device certificate", bucket: "authn", why: "A certificate proves which device this is. It says nothing about whether the device is healthy." },
          { id: "i2", text: "A teacher's directory password is checked", bucket: "authn", why: "User identity through Active Directory. Identity can come from the user or from the device." },
          { id: "i3", text: "Antivirus signatures are 3 days old", bucket: "assess", why: "Assessment looks at the device's state, not at who is holding it. A common limit is 7 days." },
          { id: "i4", text: "BitLocker is switched on", bucket: "assess", why: "Disk encryption is a health check, along with patches and a running endpoint agent." },
          { id: "i5", text: "A personal VPN client is found on the device", bucket: "assess", why: "Assessment also checks that banned software is absent, such as personal VPNs and unapproved remote tools." },
          { id: "i6", text: "A contractor gets the internet and one booking app", bucket: "authz", why: "Least access: identity and health went in, and this limited grant is what came out." },
          { id: "i7", text: "A healthy staff laptop gets the full staff network", bucket: "authz", why: "Full access is an authorization result too. It is earned by passing the first two questions." },
          { id: "i8", text: "A failing device is sent to a remediation zone", bucket: "authz", why: "The quarantine zone is a place the third question sends you, like secondary inspection at an airport." },
        ],
      },
      {
        kind: "simulate",
        title: "Find the Missing Gate",
        prompt: "A door with a missing question still looks like a door. Run these four Ravensford designs through all three gates and see what each one leaves open.",
        checks: [
          { name: "Authenticate", question: "Did anything prove who or what this is?" },
          { name: "Assess", question: "Did anything check the device's health?" },
          { name: "Authorize", question: "Was access limited to what this identity needs?" },
        ],
        scenarios: [
          {
            id: "july", label: "July: the old network",
            detail: "Block 1 wall port. Any cable, any device, instant access to everything.",
            results: ["fail", "fail", "fail"],
            why: ["Nobody asked. Being connected counted as proof.", "Nobody looked. The device could be running anything.", "Everyone got everything: file servers, records, printers."],
            verdict: "No door at all. This is the rogue device problem: a physical connection treated as legitimacy.",
          },
          {
            id: "flat", label: "Flat staff network",
            detail: "Device certificate, agent health check, then every device lands on one shared network.",
            results: ["pass", "pass", "fail"],
            why: ["The certificate proved the device.", "The agent reported healthy.", "A contractor and the head teacher end up with the same reach."],
            verdict: "Two gates work, and their answers are thrown away. Checks only matter if they change the access.",
          },
          {
            id: "kiosk", label: "Open Wi-Fi with a health page",
            detail: "No sign-in. A page scans the laptop, then puts it on a limited network.",
            results: ["fail", "pass", "pass"],
            why: ["Nobody knows whose device this is, so nothing in the logs can name a person.", "The scan did run.", "The limited network is a sensible grant."],
            verdict: "A healthy stranger is still a stranger. Without identity there is nobody to hold to account.",
          },
          {
            id: "sept", label: "September: the new door",
            detail: "Certificate, health check, and a network chosen from both results.",
            results: ["pass", "pass", "pass"],
            why: ["Identity proved.", "Health verified.", "Access set by who it is and how healthy it is."],
            verdict: "All three, every time. That is Zero Trust at the port: network location earns nothing.",
          },
        ],
      },
    ],
    // ── Reading 2: the three components ──
    "nac-r2": [
      {
        kind: "reactor",
        title: "Who Does This Job?",
        prompt: "Every NAC product has the same three parts, and when something breaks you need to know whose log to open. Lwazi calls out jobs: send each one to the part that does it.",
        reactors: [
          { id: "sup", label: "Supplicant", sub: "On the device: offers the credentials" },
          { id: "auth", label: "Authenticator", sub: "Switch or access point: enforces" },
          { id: "srv", label: "Authentication server", sub: "RADIUS: decides" },
        ],
        items: [
          { id: "j1", text: "The Wired AutoConfig service answers an identity request", reactor: "sup", why: "Windows has shipped this 802.1X supplicant since Vista, and macOS has its own. There is nothing extra to install." },
          { id: "j2", text: "A vendor agent adds health reporting on a laptop", reactor: "sup", why: "A vendor agent can replace or extend the built-in supplicant. Health checks are what it adds." },
          { id: "j3", text: "A port stays closed until it is told otherwise", reactor: "auth", why: "The switch is a gate, not a judge. It holds the port and waits for the answer." },
          { id: "j4", text: "A port state change is written to syslog", reactor: "auth", why: "Switch logs (syslog, SNMP) show port states and 802.1X events. Go here to see what the port did." },
          { id: "j5", text: "A port is moved to the VLAN the answer named", reactor: "auth", why: "Enforcement is carrying out an instruction it did not write." },
          { id: "j6", text: "A client certificate is checked against the trust store", reactor: "srv", why: "Trust decisions happen at the server. A switch would have no idea how to check one." },
          { id: "j7", text: "AD group membership picks a policy", reactor: "srv", why: "Only the server talks to the directory and holds the authorization policies." },
          { id: "j8", text: "An Access-Reject is sent", reactor: "srv", why: "The server's logs show the attempt, the identity and the policy match. Go here to see why a device was refused." },
          { id: "j9", text: "Microsoft NPS answers a request", reactor: "srv", why: "NPS is a RADIUS server, like Cisco ISE, Aruba ClearPass or FortiAuthenticator." },
        ],
      },
      {
        kind: "pcap",
        title: "Listen at the Closed Port",
        prompt: "A science lab PC with a fixed IP address went onto a new port at Hollins Vale, and Lwazi put a tap between the PC and the switch. The capture starts with the port closed. Read what crossed it and what did not.",
        capture: "hv-sci-lab-port31.pcapng",
        packets: [
          { no: 1, time: "0.000000", src: "3c:52:a1:77:10:4c", dst: "ff:ff:ff:ff:ff:ff", proto: "ARP", len: 60, info: "Who has 10.60.110.1? Tell 10.60.110.57", tree: ["Frame 1: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: ff:ff:ff:ff:ff:ff, Type: ARP (0x0806)", "Address Resolution Protocol (request)"] },
          { no: 2, time: "1.001220", src: "3c:52:a1:77:10:4c", dst: "ff:ff:ff:ff:ff:ff", proto: "ARP", len: 60, info: "Who has 10.60.110.1? Tell 10.60.110.57", tree: ["Frame 2: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: ff:ff:ff:ff:ff:ff, Type: ARP (0x0806)", "Address Resolution Protocol (request)"] },
          { no: 3, time: "2.002871", src: "3c:52:a1:77:10:4c", dst: "ff:ff:ff:ff:ff:ff", proto: "ARP", len: 60, info: "Who has 10.60.110.1? Tell 10.60.110.57", tree: ["Frame 3: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: ff:ff:ff:ff:ff:ff, Type: ARP (0x0806)", "Address Resolution Protocol (request)"] },
          { no: 4, time: "2.310144", src: "3c:52:a1:77:10:4c", dst: "01:80:c2:00:00:03", proto: "EAPOL", len: 60, info: "Start", tree: ["Frame 4: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: 01:80:c2:00:00:03, Type: 802.1X Authentication (0x888e)", "802.1X Authentication: Version 802.1X-2010 (3), Type: Start (1), Length: 0"] },
          { no: 5, time: "2.322610", src: "a4:6c:2a:0e:31:9f", dst: "3c:52:a1:77:10:4c", proto: "EAP", len: 60, info: "Request, Identity", tree: ["Frame 5: 60 bytes on wire", "Ethernet II, Src: a4:6c:2a:0e:31:9f, Dst: 3c:52:a1:77:10:4c, Type: 802.1X Authentication (0x888e)", "802.1X Authentication: Type: EAP Packet (0)", "Extensible Authentication Protocol: Code: Request (1), Id: 1, Type: Identity (1)"] },
          { no: 6, time: "2.329077", src: "3c:52:a1:77:10:4c", dst: "a4:6c:2a:0e:31:9f", proto: "EAP", len: 68, info: "Response, Identity", tree: ["Frame 6: 68 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: a4:6c:2a:0e:31:9f, Type: 802.1X Authentication (0x888e)", "802.1X Authentication: Type: EAP Packet (0)", "Extensible Authentication Protocol: Code: Response (2), Id: 1, Type: Identity (1)", "Identity: host/sci-lab-pc04.ravensford.example"] },
          { no: 7, time: "2.371405", src: "a4:6c:2a:0e:31:9f", dst: "3c:52:a1:77:10:4c", proto: "EAP", len: 60, info: "Request, TLS EAP (EAP-TLS)", tree: ["Frame 7: 60 bytes on wire", "Ethernet II, Src: a4:6c:2a:0e:31:9f, Dst: 3c:52:a1:77:10:4c, Type: 802.1X Authentication (0x888e)", "802.1X Authentication: Type: EAP Packet (0)", "Extensible Authentication Protocol: Code: Request (1), Id: 2, Type: TLS EAP (EAP-TLS) (13)"] },
          { no: 8, time: "2.380912", src: "3c:52:a1:77:10:4c", dst: "a4:6c:2a:0e:31:9f", proto: "EAP", len: 214, info: "Response, TLS EAP (EAP-TLS)", tree: ["Frame 8: 214 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: a4:6c:2a:0e:31:9f, Type: 802.1X Authentication (0x888e)", "Extensible Authentication Protocol: Code: Response (2), Id: 2, Type: TLS EAP (EAP-TLS) (13)", "TLS Handshake: Client Hello"] },
          { no: 9, time: "2.442018", src: "a4:6c:2a:0e:31:9f", dst: "3c:52:a1:77:10:4c", proto: "EAP", len: 1024, info: "Request, TLS EAP (EAP-TLS)", tree: ["Frame 9: 1024 bytes on wire", "Ethernet II, Src: a4:6c:2a:0e:31:9f, Dst: 3c:52:a1:77:10:4c, Type: 802.1X Authentication (0x888e)", "Extensible Authentication Protocol: Code: Request (1), Id: 3, Type: TLS EAP (EAP-TLS) (13)", "TLS Handshake: Server Hello, Certificate, Certificate Request"] },
          { no: 10, time: "2.468331", src: "3c:52:a1:77:10:4c", dst: "a4:6c:2a:0e:31:9f", proto: "EAP", len: 1024, info: "Response, TLS EAP (EAP-TLS)", tree: ["Frame 10: 1024 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: a4:6c:2a:0e:31:9f, Type: 802.1X Authentication (0x888e)", "Extensible Authentication Protocol: Code: Response (2), Id: 3, Type: TLS EAP (EAP-TLS) (13)", "TLS Handshake: Certificate, Client Key Exchange, Certificate Verify"] },
          { no: 11, time: "2.502744", src: "a4:6c:2a:0e:31:9f", dst: "3c:52:a1:77:10:4c", proto: "EAP", len: 110, info: "Request, TLS EAP (EAP-TLS)", tree: ["Frame 11: 110 bytes on wire", "Ethernet II, Src: a4:6c:2a:0e:31:9f, Dst: 3c:52:a1:77:10:4c, Type: 802.1X Authentication (0x888e)", "Extensible Authentication Protocol: Code: Request (1), Id: 4, Type: TLS EAP (EAP-TLS) (13)", "TLS Handshake: Finished"] },
          { no: 12, time: "2.509120", src: "3c:52:a1:77:10:4c", dst: "a4:6c:2a:0e:31:9f", proto: "EAP", len: 60, info: "Response, TLS EAP (EAP-TLS)", tree: ["Frame 12: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: a4:6c:2a:0e:31:9f, Type: 802.1X Authentication (0x888e)", "Extensible Authentication Protocol: Code: Response (2), Id: 4, Type: TLS EAP (EAP-TLS) (13)"] },
          { no: 13, time: "2.561276", src: "a4:6c:2a:0e:31:9f", dst: "3c:52:a1:77:10:4c", proto: "EAP", len: 60, info: "Success", tree: ["Frame 13: 60 bytes on wire", "Ethernet II, Src: a4:6c:2a:0e:31:9f, Dst: 3c:52:a1:77:10:4c, Type: 802.1X Authentication (0x888e)", "802.1X Authentication: Type: EAP Packet (0)", "Extensible Authentication Protocol: Code: Success (3), Id: 4"] },
          { no: 14, time: "3.004102", src: "3c:52:a1:77:10:4c", dst: "ff:ff:ff:ff:ff:ff", proto: "ARP", len: 60, info: "Who has 10.60.110.1? Tell 10.60.110.57", tree: ["Frame 14: 60 bytes on wire", "Ethernet II, Src: 3c:52:a1:77:10:4c, Dst: ff:ff:ff:ff:ff:ff, Type: ARP (0x0806)", "Address Resolution Protocol (request)"] },
          { no: 15, time: "3.004871", src: "00:1b:17:c4:02:6e", dst: "3c:52:a1:77:10:4c", proto: "ARP", len: 60, info: "10.60.110.1 is at 00:1b:17:c4:02:6e", tree: ["Frame 15: 60 bytes on wire", "Ethernet II, Src: 00:1b:17:c4:02:6e, Dst: 3c:52:a1:77:10:4c, Type: ARP (0x0806)", "Address Resolution Protocol (reply)"] },
          { no: 16, time: "3.006233", src: "10.60.110.57", dst: "10.40.0.10", proto: "DNS", len: 88, info: "Standard query 0x41c2 A rat-dc01.ravensford.example", tree: ["Frame 16: 88 bytes on wire", "Internet Protocol Version 4, Src: 10.60.110.57, Dst: 10.40.0.10", "User Datagram Protocol, Dst Port: 53", "Domain Name System (query)"] },
        ],
        objectives: [
          { id: "o1", task: "The PC keeps asking for its gateway in packets 1 to 3. How many ARP replies came back before the EAP Success?", hint: "arp", answer: ["0", "zero", "none"], why: "None. Until the server says yes, the port sits in its UNAUTHORIZED state and ARP, IP, DNS and everything else stop at the switch. The PC is not broken, it just is not allowed to talk yet." },
          { id: "o2", task: "Frames 4 to 13 did cross the closed port. Open one and read the Ethernet line. What is the EtherType?", hint: "eapol", answer: ["0x888e", "888e"], why: "0x888E is EAP over LAN (EAPOL). It is a Layer 2 frame with no IP address, and it is the one kind of frame a closed port will carry." },
          { id: "o3", task: "Which packet number tells the PC that the server said yes?", hint: "eap", answer: ["13"], why: "EAP Success in packet 13. The switch relayed the conversation to the server the whole time, and it only opened the port when the answer came back." },
          { id: "o4", task: "Which packet number is the first proof that ordinary traffic now passes?", hint: "arp", answer: ["15"], why: "The same ARP question in packet 14 now gets a reply in packet 15. Nothing changed on the PC. The port changed state." },
        ],
      },
    ],
    // ── Reading 3: 802.1X and EAP ──
    "nac-r3": [
      {
        kind: "codebreak",
        title: "Name the EAP Parts",
        prompt: "802.1X is the IEEE standard for port-based access control, first published in 2001. Before Lwazi can show you a laptop's settings, you need the words those settings use. Crack each one from its clue.",
        tries: 6,
        rounds: [
          { id: "c1", clue: "The container inside 802.1X. It carries an authentication method without being one, so the method can change while the network stays the same.", answer: "EAP", why: "Extensible Authentication Protocol. That extensibility is why a network can move from passwords to certificates without new switches." },
          { id: "c2", clue: "The usual choice without a full certificate system. It builds a TLS tunnel using only the server's certificate, then runs a password exchange inside, usually MS-CHAPv2.", answer: "PEAP", why: "Protected EAP. The tunnel is only as good as the client's check of who built it, as the next lab shows." },
          { id: "c3", clue: "In Cisco's EAP-FAST, the shared secret that stands in for certificates.", answer: "PAC", why: "Protected Access Credential. Cisco designed EAP-FAST to replace LEAP, with a tunnel that needs no certificates." },
          { id: "c4", clue: "What must exist before every device can carry a client certificate: the system that issues them.", answer: "PKI", why: "Public Key Infrastructure. EAP-TLS needs one because the client certificate replaces the password altogether. That is operationally heavy, and it leaves no password to spray, phish or steal." },
        ],
        lesson: "EAP is the envelope and the method is the letter. EAP-TLS uses certificates on both sides, PEAP tunnels a password under a server certificate, and EAP-FAST uses a PAC. The method decides what an attacker can take if a device talks to the wrong server.",
      },
      {
        kind: "inspect",
        title: "Read a Supplicant Profile",
        prompt: "Marsh Lane Primary built its wired profile in a hurry. Lwazi opens it on a staff laptop. Inspect each setting and find what would hurt if a device ever talked to a server that is not Ravensford's.",
        artifact: "Wired network profile · ML-Staff-Wired · ML-LT-0032",
        items: [
          { id: "p1", text: "802.1X authentication: Enabled", tag: "Fine", tone: "trust", note: "The laptop will answer the switch's identity request. The Wired AutoConfig service must be running for this." },
          { id: "p2", text: "Network authentication method: Microsoft: Protected EAP (PEAP)", tag: "Know it", tone: "info", note: "A TLS tunnel built with the server's certificate only. The client proves itself inside the tunnel, with a password." },
          { id: "p3", text: "Verify the server's identity by validating the certificate: Off", tag: "Risk", tone: "warn", note: "This is the classic misconfiguration. With it off, the laptop builds its tunnel to whichever server answers, so a rogue RADIUS server sits at the far end of it." },
          { id: "p4", text: "Inner method: Secured password (EAP-MSCHAP v2)", tag: "Risk", tone: "warn", note: "With validation off, this exchange goes to the rogue server, which can record it and attack it offline. Tunnelled does not mean safe if you do not know who is at the other end." },
          { id: "p5", text: "Authentication mode: User or computer authentication", tag: "Fine", tone: "trust", note: "Machine authentication runs at boot, before anyone signs in, so a domain laptop can reach Group Policy and finish the logon. User authentication follows once someone signs in. Some deployments require both." },
          { id: "p6", text: "Fallback to unauthorized network access: Off", tag: "Fine", tone: "trust", note: "If authentication fails, the laptop does not try to get on without it." },
        ],
      },
    ],
    // ── Reading 4: RADIUS ──
    "nac-r4": [
      {
        kind: "pathway",
        title: "Walk the 802.1X Door",
        prompt: "08:14, Hollins Vale. A history teacher opens a healthy school laptop on a Block 2 wall port. Walk the request hop by hop until that laptop has a network. Lwazi's rule: the laptop offers, the switch enforces, the server decides.",
        goal: "Reach VLAN 110",
        nodes: [
          { id: "lap", label: "Laptop", sub: "Supplicant", x: 12, y: 28 },
          { id: "dhcp", label: "DHCP server", sub: "Staff scope", x: 12, y: 78 },
          { id: "sw", label: "HV-SW-B2-03", sub: "Authenticator, port closed", x: 32, y: 28 },
          { id: "psn", label: "rat-ise-psn1", sub: "RADIUS server", x: 52, y: 14 },
          { id: "ad", label: "rat-dc01", sub: "Active Directory", x: 50, y: 56 },
          { id: "rej", label: "Access-Reject", sub: "no VLAN, port stays shut", x: 74, y: 14 },
          { id: "post", label: "Posture status", sub: "from the agent", x: 70, y: 56 },
          { id: "quar", label: "VLAN 199", sub: "Quarantine", x: 50, y: 86 },
          { id: "acc", label: "Access-Accept", sub: "with attributes", x: 88, y: 36 },
          { id: "vlan", label: "VLAN 110", sub: "Staff, port open", x: 88, y: 82 },
        ],
        edges: [["lap", "dhcp"], ["lap", "sw"], ["sw", "ad"], ["sw", "psn"], ["psn", "rej"], ["psn", "ad"], ["ad", "rej"], ["ad", "post"], ["post", "quar"], ["post", "acc"], ["acc", "quar"], ["acc", "vlan"]],
        route: ["lap", "sw", "psn", "ad", "post", "acc", "vlan"],
        notes: {
          lap: "The supplicant starts it. Windows offers the laptop's credentials over EAPOL, the one kind of frame this port will carry for now.",
          sw: "The authenticator. The switch wraps the EAP data in a RADIUS Access-Request with the username, the laptop's MAC and the port it came in on. It decides nothing.",
          psn: "The first leg ends here. RADIUS (Remote Authentication Dial-In User Service) is how the switch asks for a decision. The server now has to find out whether this identity is real.",
          ad: "A second leg with a second protocol. The server queries Active Directory over LDAP (Lightweight Directory Access Protocol). LDAP is a directory protocol, RADIUS is an access-decision protocol, and the server sits between them.",
          post: "Identity is proved, so now health. The agent's last report, sent over HTTPS on an earlier session and still inside its posture lease, says Compliant. A device with no report yet is Unknown: it gets a limited Accept first, reports, and is moved by a Change of Authorization (CoA). NonCompliant means quarantine.",
          acc: "The answer. It carries attributes that are instructions for the switch: which VLAN, which access control list (ACL), sometimes a redirect.",
          vlan: "The switch moves the port to VLAN 110 and opens it. The laptop never knows: it asks for an address, and that VLAN's DHCP scope answers. The switch then sends Accounting-Request Start to record the session.",
        },
        traps: {
          dhcp: "Not yet. The port is closed and nothing but authentication frames can cross it. Address requests wait until the server has answered.",
          ad: "That hop has to be a RADIUS server first. A switch cannot read a directory: it speaks RADIUS to the server it was configured with, and only the server talks to Active Directory.",
          rej: "Nothing here justifies a reject. Access-Reject means the identity or the policy failed, and it sends no VLAN, so the port stays UNAUTHORIZED. This teacher's identity is fine.",
          quar: "This laptop is Compliant, so it has no business there. A NonCompliant device would land there, and notice the route: quarantine comes inside an Access-Accept, with a VLAN and an ACL. Limited access is still access, unlike a reject.",
        },
        lesson: "Two legs and one judge: the switch asks over RADIUS, the server asks the directory over LDAP, and health comes from the agent over HTTPS. The answer is a set of instructions for the switch. When a login fails, first find which leg stopped working.",
      },
      {
        kind: "anatomy",
        title: "Read the Access-Accept",
        prompt: "A heating engineer visited Marsh Lane Primary this morning, and their laptop passed. This is the server's answer as the switch received it. Scan each attribute: every one is an instruction the switch will carry out.",
        source: "RADIUS Access-Accept · rat-ise-psn2 to ML-SW-MAIN-01 · UDP 1812",
        fields: [
          { key: "Code", value: "Access-Accept (2)", label: "The verdict", note: "An Access-Reject carries none of the instructions below. The port just stays closed, and that is how you tell the two apart in a log." },
          { key: "User-Name", value: "ext.heating@ravensford.example" },
          { key: "Tunnel-Type", value: "VLAN (13)", label: "Kind of order", note: "13 means a VLAN assignment follows. Tunnel-Type and Tunnel-Medium-Type always travel together." },
          { key: "Tunnel-Medium-Type", value: "IEEE-802 (6)", note: "6 says the medium is 802 Ethernet. With value 13 above, the two together mean: put this port in a VLAN." },
          { key: "Tunnel-Private-Group-ID", value: "120", label: "Which VLAN", note: "The actual VLAN number or name. This one is Contractor." },
          { key: "Filter-ID", value: "ACL-CONTRACTOR-WEB.in", label: "Which ACL", note: "Names an access list for the switch to apply to this port. The VLAN places the device and the ACL limits what its traffic may do." },
          { key: "cisco-av-pair (acl)", value: "url-redirect-acl=ACL-REDIRECT-WEB", label: "Which traffic", note: "Cisco-AVpair is a vendor attribute carrying extra instructions. This one picks the traffic the redirect below applies to." },
          { key: "cisco-av-pair (url)", value: "url-redirect=https://rat-ise-psn2.ravensford.example:8443/portal/aup", label: "Sent where", note: "Web requests matched by that ACL get bounced to this page, here the acceptable-use terms. The switch does it, with no help from the laptop." },
        ],
        summary: "The server does not touch the traffic, because it is not in the path. It sends a list of orders and the switch carries them out. After this, the switch sends Accounting-Request Start, and later Accounting-Request Stop with the duration and bytes. Authentication uses UDP 1812 and accounting uses UDP 1813.",
      },
      {
        kind: "trace",
        title: "Who Was on That Port?",
        prompt: "Monday 09:10. Lwazi spots a new address in the camera VLAN at Hollins Vale. Cameras cannot run a supplicant, so they use MAC Authentication Bypass (MAB): the switch sends the MAC as the username. RADIUS accounting records which device sat on which port and when. Follow it.",
        lead: "10.60.140.77, a new lease in VLAN 140, Monday morning",
        steps: [
          {
            id: "lease", ask: "Which MAC address holds 10.60.140.77?",
            source: "DHCP audit log · VLAN 140 scope",
            columns: ["Time", "Event", "IP", "MAC", "Hostname"],
            rows: [
              ["07:31", "Renew", "10.60.140.12", "5C-3A-91-4E-11-02", "hv-cam-b1-02"],
              ["07:44", "Renew", "10.60.140.29", "5C-3A-91-4E-07-19", "hv-cam-b2-04"],
              ["07:52", "Assign", "10.60.140.77", "5C-3A-91-4E-07-2B", ""],
              ["07:58", "Renew", "10.60.140.31", "0C-8D-DB-20-6E-11", "hv-door-b2"],
            ],
            answer: 2,
            why: "The 07:52 assignment gives the MAC. The asset list says that address is hv-cam-b2-07, a Block 2 corridor camera, yet this lease came with no hostname.",
            learned: "10.60.140.77 is 5C-3A-91-4E-07-2B, with no hostname",
          },
          {
            id: "port", ask: "Which session put that MAC on the network at the time of the lease?",
            source: "RADIUS accounting · rat-ise-mnt1",
            columns: ["Time", "Acct-Status-Type", "User-Name", "Calling-Station-Id", "NAS-IP-Address", "NAS-Port-Id", "Acct-Session-Id"],
            rows: [
              ["Fri 17:04", "Stop", "5c3a914e072b", "5C-3A-91-4E-07-2B", "10.60.2.3", "GigabitEthernet1/0/17", "0000A1C4"],
              ["Mon 07:51", "Start", "5c3a914e072b", "5C-3A-91-4E-07-2B", "10.60.5.1", "GigabitEthernet1/0/9", "0000A1F2"],
              ["Mon 07:55", "Start", "j.ferris@ravensford.example", "3C-52-A1-90-12-7E", "10.60.2.3", "GigabitEthernet1/0/22", "0000A1F3"],
              ["Mon 07:57", "Start", "0c8ddb206e11", "0C-8D-DB-20-6E-11", "10.60.2.3", "GigabitEthernet1/0/14", "0000A1F4"],
            ],
            answer: 1,
            why: "Calling-Station-Id is the device, and NAS-IP-Address and NAS-Port-Id are the switch and port. The camera's session on its own Block 2 switch ended on Friday. Monday's Start is 10.60.5.1, the library switch.",
            learned: "Same MAC, new place: library switch 10.60.5.1, port 1/0/9, session 0000A1F2",
          },
          {
            id: "stop", ask: "Which record closes session 0000A1F2 and gives its final totals?",
            source: "RADIUS accounting · rat-ise-mnt1",
            columns: ["Time", "Acct-Status-Type", "Acct-Session-Id", "Acct-Session-Time", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Terminate-Cause"],
            rows: [
              ["Mon 07:58", "Interim-Update", "0000A1F2", "420", "1204332", "88210", ""],
              ["Mon 08:10", "Interim-Update", "0000A1F2", "1140", "48120455", "902113", ""],
              ["Mon 08:12", "Stop", "0000A1F3", "1020", "2210334", "9120775", "User-Request"],
              ["Mon 08:41", "Stop", "0000A1F2", "2998", "612008731", "4020113", "Lost-Carrier"],
            ],
            answer: 3,
            why: "Stop closes the session with its time and bytes. Interim-Update only reports progress, and the 08:12 Stop belongs to another session. Input octets are what the device sent: 612 MB in 50 minutes, a lot for a camera, ending in Lost-Carrier, which means the link dropped.",
            learned: "Session 0000A1F2: 50 minutes, 612 MB sent, link lost at 08:41",
          },
        ],
      },
    ],
    // ── Reading 7: Cisco ISE ──
    "nac-r7": [
      {
        kind: "worksheet",
        title: "Which ISE Node Does What?",
        prompt: "Ravensford's Cisco ISE (Identity Services Engine) is a small cluster, and each node plays a role. Read the deployment page, then answer as Lwazi would on a bad morning.",
        caption: "ISE deployment · Ravensford · node roles",
        columns: ["Node", "Role", "Its job"],
        rows: [
          ["rat-ise-pan1", "Policy Administration Node (PAN)", "Hosts the configuration interface: policies, identity stores, settings"],
          ["rat-ise-psn1", "Policy Service Node (PSN)", "Handles live RADIUS requests, runs posture queries, enforces policy"],
          ["rat-ise-psn2", "Policy Service Node (PSN)", "The same work, for redundancy and load sharing"],
          ["rat-ise-mnt1", "Monitoring and Troubleshooting Node (MnT)", "Collects authentication logs, builds reports, runs the Troubleshooting Wizard"],
        ],
        questions: [
          { id: "n1", q: "Logins are fine, but every report since 02:00 is blank. Which role do you check? (PAN, PSN or MnT)", hint: "Which row holds the logs and reports?", answer: ["MnT"], why: "Reports live on the MnT, and it answers no logins. Losing it costs you visibility, not access." },
          { id: "n2", q: "Logins are fine, but nobody can open the console to change a rule. Which role? (PAN, PSN or MnT)", hint: "Where do administrators work?", answer: ["PAN"], why: "The PAN is where policy is written. Existing policy keeps running without it, which is why the school day carries on." },
          { id: "n3", q: "How many nodes here can answer a switch's RADIUS request?", hint: "Count the rows that do live work.", answer: ["2", "two"], why: "Two, so one can fail or be patched while the other carries the load. Match the symptom to the node's job before you restart anything." },
        ],
      },
      {
        kind: "sequence",
        title: "How ISE Reads a Request",
        prompt: "A request has just reached rat-ise-psn1. Put the policy stages in the order ISE works through them. Getting a log read right depends on knowing which stage wrote which field.",
        items: [
          { id: "accept", text: "The RADIUS answer leaves for the switch" },
          { id: "authz", text: "Authorization rule: which conditions does this match?", note: "Conditions such as: domain user? Windows profile? Posture compliant?" },
          { id: "set", text: "Policy Set: what kind of request is this?", note: "Wired 802.1X, wireless or VPN can each have a complete set of their own." },
          { id: "profile", text: "Authorization profile: what is the result?", note: "The package of VLAN and ACL attributes the matched rule points to." },
          { id: "authn", text: "Authentication Policy: where do we check the identity?", note: "Active Directory first, then the certificate store, then the guest store, for example." },
        ],
        order: ["set", "authn", "authz", "profile", "accept"],
        doneNote: "Keep the last two apart. A rule is the conditions a request has to match. A profile is the result that rule returns to the switch.",
      },
      {
        kind: "match",
        title: "What the Profiler Hears",
        prompt: "ISE Profiling fingerprints every device, mostly by listening, and sends an NMAP scan when it needs more. TrustSec then puts identity to work. Match each item to what it gives you, because the bypass work later depends on it.",
        pairs: [
          { id: "m1", left: "DHCP options", right: "Which operating system family the client runs", why: "Clients ask for options in a telling order, and that reveals the OS before any other traffic flows." },
          { id: "m2", left: "HTTP User-Agent header", right: "The browser and platform behind web requests", why: "A device that browses like a desktop is a desktop, whatever it claims to be." },
          { id: "m3", left: "CDP and LLDP data from switches", right: "What a neighbouring device announces about itself", why: "Cisco Discovery Protocol and Link Layer Discovery Protocol are how an IP phone tells the switch its model." },
          { id: "m4", left: "NMAP scan results", right: "Which ports and services are open", why: "A camera and a general-purpose computer expose very different sets of ports." },
          { id: "m5", left: "Security Group Tag (SGT)", right: "A TrustSec label that policy follows instead of an IP address", why: "Not a profiling source: it is what identity can become. Switches and firewalls enforce on the tag, so microsegmentation follows the identity." },
        ],
      },
    ],
    // ── Reading 8: ClearPass ──
    "nac-r8": [
      {
        kind: "locks",
        title: "Four Locks of ClearPass",
        prompt: "Thorncombe Sixth Form joined the Trust last year with mixed switches and kept its own NAC, Aruba ClearPass Policy Manager. It runs on any 802.1X-capable network gear and has a simpler build than ISE: it can start as one virtual appliance. Its policy has four stages. Open each lock.",
        locks: [
          {
            id: "service", letter: "1", name: "Service",
            idea: "The entry point. It matches the request type: wired 802.1X, wireless 802.1X, VPN, guest portal or MAC authentication bypass.",
            example: "A student laptop joins the sixth-form Wi-Fi. ClearPass matches the wireless 802.1X service, so nothing written for wired ports applies.",
            check: { q: "A door camera arrives with only its MAC address. What does this stage do with it?", options: ["Reads its AD groups to set a role", "Matches it to the MAC authentication bypass service"], answer: 1, why: "Service only asks what kind of request this is. Roles come two stages later." },
          },
          {
            id: "authn", letter: "2", name: "Authentication",
            idea: "Validates the identity against a source: Active Directory, LDAP, a SQL database, a certificate store or the local database.",
            example: "A teacher's login is checked against Thorncombe's Active Directory.",
            check: { q: "Which question belongs to this stage?", options: ["Is this identity real, according to the source?", "Which VLAN should this person get?"], answer: 0, why: "It proves the identity and nothing more. What the identity gets is decided after this." },
          },
          {
            id: "role", letter: "3", name: "Role Mapping",
            idea: "Translates the proved identity into a role, using AD groups, certificate attributes or other retrieved values.",
            example: "Membership of the Finance group makes this user the role Finance.",
            check: { q: "A user moves from Contractors to Staff in AD. What changes at their next login?", options: ["The Service that matches their request", "The role they are mapped to"], answer: 1, why: "The request type is the same. The attributes changed, so the role changes, and the access follows." },
          },
          {
            id: "enforce", letter: "4", name: "Enforcement",
            idea: "Maps the role to Enforcement Profiles: the VLAN, ACL and session attributes returned to the switch over RADIUS.",
            example: "Role Finance gets a VLAN and an ACL for the finance system.",
            check: { q: "Which ISE idea is closest to an Enforcement Profile?", options: ["An authorization profile", "A Policy Service Node"], answer: 0, why: "Both are the result that goes back to the switch. A PSN is a machine, not a result." },
          },
        ],
      },
      {
        kind: "match",
        title: "ClearPass Add-Ons",
        prompt: "Thorncombe's network lead lists what else ClearPass does there. Match each module to its job.",
        pairs: [
          { id: "a1", left: "ClearPass Exchange", right: "REST API link: a SIEM flags an endpoint and it is quarantined with no person involved", why: "It connects to third-party products such as SIEMs, ticketing, vulnerability scanners and device management, so a signal elsewhere can change access at the network layer." },
          { id: "a2", left: "ClearPass OnBoard", right: "A portal that provisions a device certificate after an AD sign-in", why: "It takes the certificate lifecycle work out of an EAP-TLS deployment." },
          { id: "a3", left: "ClearPass Guest", right: "Self-service portal with sponsor approval, SMS checks and time limits", why: "A corporate sponsor gets an email to approve the guest, and usage is reported." },
          { id: "a4", left: "Enforcement Profile", right: "The VLAN and ACL attributes returned over RADIUS", why: "The same RADIUS answer as ISE sends, which is why a mixed-vendor network still works." },
        ],
      },
    ],
    // ── Drill before q3: place the failure on a leg ──
    "nac-q3": [
      {
        kind: "simulate",
        title: "Which Leg Broke?",
        prompt: "Three legs, three places to look. Run four real Ravensford failures, and for each one see how far the request travelled before it stopped. Notice which logs you need for that.",
        checks: [
          { name: "Supplicant to switch", question: "Did the device answer over EAPOL?" },
          { name: "Switch to server", question: "Did RADIUS requests and replies flow?" },
          { name: "Server to its back end", question: "Could the server finish its own checks?" },
        ],
        scenarios: [
          {
            id: "secret", label: "New switch, Block 3",
            detail: "rat-ise-psn1: 5405 RADIUS Request dropped. 11036 The Message-Authenticator RADIUS attribute is invalid.",
            results: ["pass", "fail", "fail"],
            why: ["The laptops are talking to the switch normally.", "The shared secret typed on the new switch does not match the server's, so the server drops the requests.", "Never reached. The request died one leg earlier."],
            verdict: "Fix the switch's RADIUS key. The directory was never involved.",
          },
          {
            id: "silent", label: "Laptop goes quiet",
            detail: "rat-ise-psn1: 5411 Supplicant stopped responding to ISE, on one laptop only.",
            results: ["fail", "pass", "fail"],
            why: ["The device stopped answering partway through EAP. Check the endpoint's supplicant log and its trust settings.", "The server received the request and replied.", "Never reached. There was no finished exchange to check."],
            verdict: "One device with a client-side problem. Endpoint logs tell this story, not the switch.",
          },
          {
            id: "typo", label: "Wrong password",
            detail: "rat-ise-psn1: 24408 User authentication against Active Directory failed since user has entered the wrong password.",
            results: ["pass", "pass", "pass"],
            why: ["Finished.", "Finished, and an Access-Reject came back.", "The server asked the directory and got a clear answer: no."],
            verdict: "Nothing is broken. A reject after a full journey is the system doing its job.",
          },
          {
            id: "crl", label: "Revocation list out of reach",
            detail: "Certificate logins fail from 07:50. The switch sees fast replies. The server logs that it cannot download the certificate revocation list (CRL) from pki.ravensford.example.",
            results: ["pass", "pass", "fail"],
            why: ["Finished.", "Fast Access-Rejects, so this leg is healthy.", "The server cannot finish its own certificate revocation check, so it refuses."],
            verdict: "A fast reject is a healthy RADIUS leg with a verdict on it. When the switch hears answers, look behind the server.",
          },
        ],
      },
    ],
    // ── Reading 5: posture ──
    "nac-r5": [
      {
        kind: "simulate",
        title: "Run the Posture Check",
        prompt: "Authentication asks who you are. Posture asks whether your device is safe to let in. Run five Ravensford laptops through Lwazi's baseline and see the result each one gets.",
        checks: [
          { name: "Antivirus", question: "Running, with signatures under 7 days old?" },
          { name: "Patches", question: "No critical update beyond the 30-day grace?" },
          { name: "Disk encryption", question: "BitLocker or FileVault on?" },
          { name: "EDR agent", question: "Endpoint detection and response agent running?" },
        ],
        scenarios: [
          {
            id: "ok", label: "HV-LT-0231",
            detail: "Signatures 2 days old, no critical updates outstanding, BitLocker on, EDR running.",
            results: ["pass", "pass", "pass", "pass"],
            why: ["2 days.", "Nothing outstanding.", "On.", "Running."],
            verdict: "Compliant: full access, VLAN 110.",
          },
          {
            id: "edge", label: "HV-LT-0312",
            detail: "Signatures 6 days old, a critical update released 28 days ago and not yet applied, BitLocker on, EDR running.",
            results: ["pass", "pass", "pass", "pass"],
            why: ["6 days is inside the limit.", "28 days is inside the grace period.", "On.", "Running."],
            verdict: "Compliant, for now. The limits are policy numbers, so read them before you call a laptop overdue.",
          },
          {
            id: "disk", label: "HV-LT-0147",
            detail: "Signatures 1 day old, patched, BitLocker off, EDR running.",
            results: ["pass", "pass", "fail", "pass"],
            why: ["Fine.", "Fine.", "Encryption is off.", "Fine."],
            verdict: "NonCompliant: one failed check is enough. VLAN 199, remediation only.",
          },
          {
            id: "edr", label: "ML-LT-0032",
            detail: "Signatures 3 days old, patched, BitLocker on, EDR service stopped.",
            results: ["pass", "pass", "pass", "fail"],
            why: ["Fine.", "Fine.", "On.", "The agent is not running."],
            verdict: "NonCompliant, even though the first three pass. VLAN 199, and worth a second look at why it stopped.",
          },
          {
            id: "none", label: "No answer from the agent",
            detail: "ISE asks for this laptop's posture and hears nothing: the agent is missing or silent.",
            results: ["fail", "fail", "fail", "fail"],
            why: ["No report.", "No report.", "No report.", "No report."],
            verdict: "These red marks mean no report, not a failed check. Unknown, not NonCompliant: nothing failed, because nothing was measured. Typically limited access until posture is validated.",
          },
        ],
      },
      {
        kind: "match",
        title: "Who Reports Device Health?",
        prompt: "A posture result has to come from somewhere, and people often assume the wrong thing carries it. Match each item to what it actually does.",
        pairs: [
          { id: "h1", left: "Persistent agent", right: "Installed by IT on managed devices, reports continuously to the policy node over HTTPS", why: "Also called a permanent agent. It is the preferred method for managed endpoints, because the data is always current." },
          { id: "h2", left: "Temporal agent", right: "A small executable from a captive portal: runs the checks, reports, deletes itself", why: "Also called a dissolvable or web agent. It suits unmanaged devices, usually with lighter requirements or a limited VLAN anyway." },
          { id: "h3", left: "RADIUS", right: "Carries the authentication exchange between switch and server, and no posture report", why: "Posture data travels from the agent to the server. The switch only ever sees the resulting instructions." },
          { id: "h4", left: "Wired AutoConfig", right: "Handles 802.1X authentication and performs no health checks", why: "The native supplicant authenticates. Health checks are what a vendor agent adds." },
        ],
      },
      {
        kind: "queue",
        title: "Posture Results Are Leads",
        prompt: "The first week of term fills the queue with posture alerts. They are not paperwork, and they are not proof either. Open each one with Lwazi, read what else is known, and choose the next step.",
        console: "SIEM · NAC alerts",
        actions: [
          { id: "fix", label: "Send to IT to remediate", tone: "close" },
          { id: "inv", label: "Open an investigation", tone: "escalate" },
          { id: "iso", label: "Isolate the device", tone: "contain" },
        ],
        alerts: [
          {
            id: "a1", time: "08:02", severity: "Medium", rule: "Posture: NonCompliant", entity: "HV-LT-0147",
            fields: [{ k: "cisco.ise.posture_assessment_status", v: "NonCompliant" }, { k: "cisco.ise.posture_failure_reasons", v: "DiskEncryptionDisabled" }, { k: "EDR status", v: "Healthy, seen 2 min ago, no detections" }],
            context: "A replacement laptop imaged on Friday. The build sheet says encryption starts at the first staff logon.",
            answer: "fix",
            why: "Quarantine did its job, and everything else fits an innocent story: a new build, healthy EDR, nothing detected. A remediation ticket closes it.",
          },
          {
            id: "a2", time: "08:19", severity: "High", rule: "Posture: NonCompliant", entity: "ML-LT-0032",
            fields: [{ k: "cisco.ise.posture_assessment_status", v: "NonCompliant" }, { k: "cisco.ise.posture_failure_reasons", v: "EndpointAgentNotRunning" }, { k: "EDR last check-in", v: "Today 02:14" }, { k: "EDR service", v: "Stopped 02:14" }],
            context: "Nobody in IT touched it. The EDR agent stopped in the middle of the night.",
            answer: "inv",
            why: "A disabled security tool can be a ransomware indicator on some families, and it can also be a bad update. This record cannot tell you which, so find out. Isolating on this alone jumps ahead of the evidence, and a remediation ticket would lose it.",
          },
          {
            id: "a3", time: "08:33", severity: "Medium", rule: "Posture: Unknown", entity: "Art room, port 1/0/6",
            fields: [{ k: "cisco.ise.posture_assessment_status", v: "Unknown" }, { k: "cisco.ise.endpoint_profile", v: "Linux-Workstation" }, { k: "Asset list", v: "No match" }],
            context: "No agent, no ticket, and nobody has claimed it. It has been reappearing on the same port every morning this week.",
            answer: "inv",
            why: "Unknown plus no asset record is shadow IT until proved otherwise. Someone has to find out what this is and who owns it. IT cannot remediate a device nobody admits to.",
          },
          {
            id: "a4", time: "09:12", severity: "Critical", rule: "Posture: NonCompliant", entity: "HV-LT-0088",
            fields: [{ k: "cisco.ise.posture_failure_reasons", v: "AntivirusDisabled" }, { k: "EDR alert", v: "Malicious: credential dumping from LSASS" }, { k: "EDR status", v: "Online, process still running" }],
            context: "This one is not only posture: the EDR has a confirmed detection on the same laptop at the same minute.",
            answer: "iso",
            why: "Here the evidence goes beyond posture: a Malicious verdict and a live process. Contain first, then investigate. Quarantine limits the port, while EDR isolation goes with the laptop wherever it plugs in.",
          },
          {
            id: "a5", time: "09:40", severity: "Low", rule: "Posture: NonCompliant", entity: "HV-LT-0266",
            fields: [{ k: "cisco.ise.posture_failure_reasons", v: "ProhibitedSoftwareFound" }, { k: "Software", v: "Personal VPN client, installed by the user" }, { k: "EDR status", v: "Healthy, no detections" }],
            context: "The teacher installed it for streaming abroad over the summer and says so in the ticket.",
            answer: "fix",
            why: "It breaks policy, the user explains it, and EDR agrees nothing else happened. Remove it and move on. Spend the morning on the alerts above.",
          },
        ],
      },
    ],
    // ── Reading 6: VLANs ──
    "nac-r6": [
      {
        kind: "sort",
        title: "Which VLAN for Which Device?",
        prompt: "A VLAN (Virtual LAN) is a logical segment the switch enforces in hardware. Devices in different VLANs cannot talk unless a router or firewall permits it. This is Ravensford's plan. Send each device where the Access-Accept should put it.",
        buckets: [
          { id: "staff", label: "VLAN 110 Staff" },
          { id: "contractor", label: "VLAN 120 Contractor" },
          { id: "guest", label: "VLAN 130 Guest" },
          { id: "building", label: "VLAN 140 Building devices" },
          { id: "quar", label: "VLAN 199 Quarantine" },
        ],
        items: [
          { id: "v1", text: "Domain user on a compliant school laptop", bucket: "staff", why: "Authenticated and compliant: file servers, core systems, printers and the internet." },
          { id: "v2", text: "A surveyor's compliant laptop, external account", bucket: "contractor", why: "Authenticated but external: the internet and specific applications, never the core servers." },
          { id: "v3", text: "A parent's phone at open evening", bucket: "guest", why: "Internet only, and no route to any Ravensford resource." },
          { id: "v4", text: "A corridor camera that cannot run 802.1X", bucket: "building", why: "Identified by MAC or profiling, then limited to the destinations it needs, such as the recorder." },
          { id: "v5", text: "A hall projector with a network card", bucket: "building", why: "No supplicant, so it gets the restricted segment where it can do its one job." },
          { id: "v6", text: "A staff laptop with BitLocker switched off", bucket: "quar", why: "Failed posture. It can reach Windows Update, AV update servers and the remediation portal, and nothing else." },
          { id: "v7", text: "A staff laptop that just passed every check", bucket: "staff", why: "The port moved when the Accept arrived. The laptop did nothing and does not know its VLAN: it asked for an address and the right scope answered." },
        ],
      },
      {
        kind: "worksheet",
        title: "Read the Session Table",
        prompt: "For an analyst, the VLAN in a NAC log is a risk signal. Lwazi pulls the live sessions at Hollins Vale and asks you three questions about them.",
        caption: "Active sessions · Hollins Vale Academy · Monday 09:05",
        columns: ["Endpoint", "EndPointPolicy", "VLAN", "PostureStatus", "Framed-IP-Address"],
        rows: [
          ["HV-LT-0231", "Microsoft-Workstation", "110", "Compliant", "10.60.110.31"],
          ["hv-cam-b1-02", "Network-Camera", "140", "NotApplicable", "10.60.140.12"],
          ["HV-LT-0147", "Microsoft-Workstation", "199", "NonCompliant", "10.60.199.8"],
          ["hv-tv-hall", "Smart-TV", "110", "NotApplicable", "10.60.110.90"],
          ["visitor-0419", "Apple-iPhone", "130", "NotApplicable", "10.60.130.44"],
          ["ext-surveyor", "Microsoft-Workstation", "120", "Compliant", "10.60.120.15"],
        ],
        questions: [
          { id: "s1", q: "Which endpoint sits in a VLAN its profile should never get?", hint: "Compare EndPointPolicy with VLAN, row by row.", answer: ["hv-tv-hall"], why: "A Smart-TV profile in Staff VLAN 110. A building device belongs in 140, so either a rule is wrong or something is borrowing a device's identity. Both need checking today." },
          { id: "s2", q: "The firewall allowed 10.60.130.44 to 10.60.110.31 on port 445. Which VLAN is the source in?", hint: "Read the third block of the source address.", answer: ["130", "vlan 130", "guest"], why: "Guest to Staff should never happen in a properly configured network. An allow there is an immediate alert and a firewall hole, and it is why guest traffic gets watched." },
          { id: "s3", q: "HV-LT-0147 wants a file from a staff file server. Will it get there? (yes/no)", hint: "Find its VLAN in the plan you just sorted.", answer: ["no"], why: "VLAN 199 reaches remediation resources only. It has a working network connection, but a very small one." },
        ],
      },
    ],
    // ── Reading 9: Zero Trust and cloud ──
    "nac-r9": [
      {
        kind: "match",
        title: "The Same Door in the Cloud",
        prompt: "Staff marking at home never touch a Ravensford switch, so on-premises NAC cannot see them. Microsoft Entra ID with Intune plays the same game with different pieces. Match each NAC idea to its cloud twin.",
        pairs: [
          { id: "z1", left: "Posture status from the agent", right: "Device compliance reported by Intune", why: "Enrolled, encrypted, patch-current: the same question, asked by a different product." },
          { id: "z2", left: "Authorization rule", right: "Conditional Access policy", why: "Both weigh identity, device and risk, and pick a result." },
          { id: "z3", left: "VLAN and ACL in an Access-Accept", right: "Grant, require step-up MFA, block, or limit the app", why: "The mechanism changes, and the policy logic stays the same." },
          { id: "z4", left: "Checked when a device joins a port", right: "Checked for every sign-in to a cloud app", why: "The decision moves from the port to the application request, which is why it still works at a kitchen table." },
        ],
      },
      {
        kind: "sort",
        title: "Who Guards This Session?",
        prompt: "Castle-and-moat trusted everything inside the wall. Zero Trust says never trust, always verify, wherever the request comes from. Ravensford now has three guards. Decide which one has eyes on each session.",
        buckets: [
          { id: "nac", label: "On-premises NAC" },
          { id: "ca", label: "Conditional Access" },
          { id: "sase", label: "SASE, cloud-delivered" },
        ],
        items: [
          { id: "g1", text: "A supply teacher plugs into a Block 2 wall port", bucket: "nac", why: "Switches and wireless on Ravensford sites are NAC's territory. It is not a part of SASE, and it stays useful, because someone still has to guard the ports." },
          { id: "g2", text: "A tablet joins the school's staff Wi-Fi", bucket: "nac", why: "An 802.1X wireless join goes through the same door as a wired one." },
          { id: "g3", text: "A teacher at home opens cloud mail on a personal laptop", bucket: "ca", why: "No switch of ours is involved. Entra ID evaluates user, device compliance and sign-in risk." },
          { id: "g4", text: "A risky sign-in to a cloud app gets asked for MFA again", bucket: "ca", why: "Step-up MFA is one of the results Conditional Access can return." },
          { id: "g5", text: "A home worker reaches an on-site finance app with no VPN", bucket: "sase", why: "ZTNA (Zero Trust Network Access) decides user and device access per session. It is one pillar of SASE (Secure Access Service Edge), beside a web gateway (SWG), a cloud access broker (CASB) and a firewall service (FWaaS), all joined to SD-WAN networking." },
          { id: "g6", text: "A roaming laptop's web traffic passes a cloud web gateway", bucket: "sase", why: "A SWG (Secure Web Gateway) is delivered from the cloud with the rest of the stack, so one log stream replaces several." },
        ],
      },
    ],
    // ── Reading 10: bypass ──
    "nac-r10": [
      {
        kind: "tune",
        title: "Tune the MAB Door",
        prompt: "The library session was a cloned camera MAC. Lwazi's new rule rejects a MAB endpoint only when both dials trip: its profiling certainty factor against the stored profile is low, and the profiler's NMAP scan finds ports that profile does not list. Set the dials so printers and cameras pass and every clone is stopped.",
        eventColumn: "MAB endpoints, Monday's profiler run",
        dials: [
          { id: "cf", label: "Certainty factor at or below", short: "CF", min: 10, max: 90, step: 5, start: 20, dir: "below" },
          { id: "ports", label: "Unexpected open ports at least", short: "ports", min: 1, max: 5, step: 1, start: 1 },
        ],
        events: [
          { id: "g1", label: "Library label printer · MAC vendor, DHCP and SNMP all match", bad: false, values: { cf: 80, ports: 0 } },
          { id: "g2", label: "Old corridor camera, fixed IP · only the MAC vendor matches", bad: false, values: { cf: 15, ports: 0 } },
          { id: "g3", label: "Car park camera · MAC vendor and DHCP match", bad: false, values: { cf: 30, ports: 0 } },
          { id: "g4", label: "Art room plotter after a firmware update · new web admin ports", bad: false, values: { cf: 50, ports: 2 } },
          { id: "g5", label: "Door controller · one maintenance port", bad: false, values: { cf: 40, ports: 1 } },
          { id: "g6", label: "Reception sign-in kiosk · one unlisted port", bad: false, values: { cf: 35, ports: 1 } },
          { id: "g7", label: "Office copier · scan-to-folder adds SMB and more", bad: false, values: { cf: 60, ports: 3 } },
          { id: "b1", label: "Camera MAC · DHCP fingerprint of a Linux PC, SSH open", bad: true, values: { cf: 15, ports: 3 } },
          { id: "b2", label: "Door controller MAC · DHCP from a Debian client, SSH and HTTP open", bad: true, values: { cf: 25, ports: 2 } },
          { id: "b3", label: "Camera MAC · camera DHCP vendor class, but SSH and SMB open", bad: true, values: { cf: 40, ports: 2 } },
          { id: "b4", label: "Signage player MAC · macOS DHCP options, four unlisted ports", bad: true, values: { cf: 20, ports: 4 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        deploys: 3,
        lesson: "One signal is never enough. A low certainty factor alone rejects quiet old cameras that just send little. Extra ports alone reject a plotter after a firmware update, because an update changes details and does not turn a plotter into a general-purpose computer. A clone keeps the MAC vendor, so its score is never zero, and a careful one copies the DHCP class too. It still cannot hide what the machine really is.",
      },
      {
        kind: "lineup",
        title: "Which Bypass Left This Trace?",
        prompt: "No NAC bypass leaves nothing behind. Lwazi has four known ways through the door and a stack of evidence from across the Trust. Match each stack to the technique that left it.",
        suspects: [
          { id: "mac", name: "Cloned MAC", motive: "Pass as a device the network already trusts", skill: "Read a label or sniff ARP and LLDP, then change one setting", target: "Ports using MAC Authentication Bypass" },
          { id: "hub", name: "Hub on the port", motive: "Ride on a session someone else authenticated", skill: "A small unmanaged hub and physical access", target: "802.1X ports in multi-host mode" },
          { id: "guest", name: "Guest VLAN abuse", motive: "Walk from the visitor network into the real one", skill: "Only guest access", target: "Firewall rules opened for convenience" },
          { id: "evil", name: "Rogue RADIUS", motive: "Collect credentials from devices that ask", skill: "A rogue access point and a fake RADIUS server", target: "Supplicants that skip server certificate validation" },
        ],
        rounds: [
          { id: "r1", evidence: ["Known camera MAC, MAB session on a port it has never used", "Profiler: was Network-Camera, now Linux-Workstation", "DHCP class identifier: dhcpcd-9.4.1"], suspect: "mac", why: "The address says camera and the fingerprint says computer. Alert on a profile mismatch for a MAB-authenticated endpoint." },
          { id: "r2", evidence: ["HV-SW-B1-01 Gi1/0/12: 3 MAC addresses on an 802.1X wired port", "One authenticated session, no violation logged", "Port host mode: multi-host"], suspect: "hub", why: "Multi-host logs no violation, so you have to count MACs per port from the switch's MAC table (the CAM table), ISE sessions or SNMP polling. More than one is an alert." },
          { id: "r3", evidence: ["%DOT1X-5-SECURITY_VIOLATION on Gi1/0/8: new MAC seen in single-host mode", "One authenticated laptop on the port", "Extra MAC blocked by the switch"], suspect: "hub", why: "The same trick against a single-host port. The extra MAC was blocked, so this is a failed attempt rather than a working bypass, and still worth a walk to that room." },
          { id: "r4", evidence: ["Firewall allow: 10.60.130.21 to 10.60.110.20:445", "Source is in VLAN 130", "A rule was added for the open evening and never removed"], suspect: "guest", why: "Guest to Staff should never appear. No NAC failure happened at all: the hole is in the firewall." },
          { id: "r5", evidence: ["AP in the sports hall not in the authorized inventory, broadcasting the staff SSID", "Laptops show a RADIUS server certificate not issued by the Ravensford CA", "Several laptops report a brief drop and reconnect"], suspect: "evil", why: "An AP outside the inventory and a server certificate from the wrong CA are the traces, because ISE never sees a fake RADIUS server. A rogue AP that forwards to the real ISE shows up there as an unknown NAS-IP-Address instead. Any supplicant that skips certificate validation may have handed over credentials." },
        ],
      },
    ],
    // ── Drill before la1: the boss's decisive reading skill, on another record ──
    "nac-la1": [
      {
        kind: "anatomy",
        title: "Read One ISE Record",
        prompt: "An ISE record is a chain of decisions, and the one that counts is rarely the first line. Lwazi shows you how to read one using the heating engineer's visit to Marsh Lane. Scan each field before the next record lands on your desk.",
        source: "SIEM · NAC event · rat-ise-psn2 · Marsh Lane Primary",
        fields: [
          { key: "cisco.ise.identity_group", value: "Contractors", label: "Who" },
          { key: "cisco.ise.network_device_name", value: "ML-SW-MAIN-01", label: "Where" },
          { key: "cisco.ise.nas_port", value: "GigabitEthernet1/0/31", note: "The switch and port together locate the device physically." },
          { key: "cisco.ise.calling_station_id", value: "48:2A:E3:5D:90:17", label: "Which device" },
          { key: "cisco.ise.posture_assessment_status", value: "Compliant", label: "Health", note: "A separate question from identity. A failed device would list its reasons in posture_failure_reasons. Read those as risk that raises questions for EDR: more than paperwork, less than proof." },
          { key: "cisco.ise.authorization_rule", value: "Contractor-Web-Only", label: "Rule: the conditions", note: "The conditions this request matched, under the name an admin gave them. It is what you search on and quote in a ticket, spelled exactly as logged." },
          { key: "cisco.ise.selected_authorization_profile", value: "CONTRACTOR_LIMITED", label: "Profile: the result", note: "What that rule returned to the switch. Many rules can share one profile, so only the rule tells you why a device landed here." },
          { key: "cisco.ise.selected_vlan", value: "VLAN-120-CONTRACTOR", label: "Where it sits", note: "A device with a VLAN has a network. A refused device has none, because an Access-Reject carries no attributes. So this is access granted, and the question is how much." },
          { key: "cisco.ise.acl", value: "ACL-CONTRACTOR-WEB", label: "What it may reach", note: "Read it with the VLAN. The VLAN places the device, and the ACL says which traffic may leave it. Neither one alone tells you the device's reach." },
          { key: "cisco.ise.cisco_av_pair", value: "url-redirect=https://rat-ise-psn2.ravensford.example:8443/portal/aup", label: "What the person sees", note: "Part of a successful answer, not an error. The port catches browser traffic and bounces it to this page, whatever address was typed, while name resolution carries on normally. The host in the URL tells you whose page it is." },
        ],
        summary: "Read a record in the order it was decided: who, where, how healthy, which rule, which result. VLAN plus ACL gives the device's reach, a redirect tells you what the person sees, and the rule explains why.",
      },
    ],
    // ── Drill before f1: rule versus profile ──
    "nac-f1": [
      {
        kind: "worksheet",
        title: "Rule or Profile?",
        prompt: "People mix these two up in tickets, and then the next analyst searches for the wrong thing. Lwazi pulls five records from the morning: read them and answer exactly as logged.",
        caption: "SIEM · NAC events · Monday morning",
        columns: ["Endpoint", "cisco.ise.authorization_rule", "cisco.ise.selected_authorization_profile", "cisco.ise.selected_vlan"],
        rows: [
          ["HV-LT-0231", "Staff-Healthy-Laptop", "STAFF_FULL", "VLAN-110-STAFF"],
          ["ext-heating", "Contractor-Web-Only", "CONTRACTOR_LIMITED", "VLAN-120-CONTRACTOR"],
          ["hv-cam-b1-02", "Camera-MAB", "BUILDING_DEVICE", "VLAN-140-BUILDING"],
          ["hv-door-b2", "Door-Controller-MAB", "BUILDING_DEVICE", "VLAN-140-BUILDING"],
          ["HV-LT-0147", "Laptop-Unencrypted", "REMEDIATE_ONLY", "VLAN-199-QUARANTINE"],
        ],
        questions: [
          { id: "f1", q: "Which authorization rule let hv-door-b2 in?", hint: "The rule column, not the profile column.", answer: ["Door-Controller-MAB"], why: "That is the condition set it matched. Its result is written one column over." },
          { id: "f2", q: "Which authorization profile did HV-LT-0147 receive?", hint: "Now you want the result column.", answer: ["REMEDIATE_ONLY"], why: "The profile is the package sent to the switch: here a VLAN and limited access." },
          { id: "f3", q: "How many different rules returned BUILDING_DEVICE?", hint: "Count rows, then check the rule names differ.", answer: ["2", "two"], why: "Two rules, one profile. That is why a ticket quoting only the profile cannot tell the next analyst what matched." },
        ],
      },
    ],
  },
};
