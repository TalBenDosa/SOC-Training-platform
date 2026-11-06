import type { RoomExperience } from "./types";

// "Operation Deep Water" for the "protocols-masterclass" room.
// Script: docs/campaign/28-protocols-masterclass.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Quayside Shipping (fictional). Lab data differs from the graded tasks: the
// capture shows a clean handshake, data and close, never a SYN scan's RST or
// silence (q1); the ARP/DHCP console never touches internal SMB (q3); and the
// abuse drill is an HTTP beacon, not long base64 DNS labels (q2) or la1's
// Sysmon 22 query and its exfiltration sub-technique (f1).
export const PROTOCOLS_MASTERCLASS: RoomExperience = {
  roomId: "protocols-masterclass",
  codename: "Operation Deep Water",
  theme: "protocols",
  handler: { name: "Lars Eriksen", role: "Network Security Architect, Quayside Shipping" },
  briefing: [
    "Quayside Shipping. Port cranes, customs systems and 3,000 users, all talking in the same handful of protocols.",
    "Attackers don't invent new protocols. They hide inside TCP, DNS, HTTP and TLS, because those are always allowed.",
    "Lars Eriksen wants you fluent enough to read a capture, a certificate and an ARP table the way you read a sentence.",
    "Go below the surface.",
  ],
  mission: "Do subnet maths and place logs on the stack, read a TCP conversation and a UDP query in a capture, crack what DNS, HTTP and TLS give away about a portal, catch an ARP spoof and a rogue DHCP server, and take apart an HTTP beacon.",
  estimate: "~60 min",
  look: { primary: "#2dd4bf", secondary: "#a78bfa", warn: "#f43f5e" },
  scene: "protostack",
  layout: "stage",
  story: {
    intro: { title: "Always Allowed", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-intro-b4476f92.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-intro-e93754eb.jpg" },
    afterStation: {
      layers: { title: "SYN, SYN-ACK, ACK", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch2-c00e8323.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch2-e67e2e77.jpg" },
      web: { title: "Two Devices, One MAC", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch3-4c8f03b4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch3-3e1cdf30.jpg" },
      abuse: { title: "A Pipe Nobody Closes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-finale-0be912cb.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-finale-44d6d81f.jpg" },
    },
  },
  stations: [
    {
      id: "layers",
      label: "Layers and Addresses",
      topic: "OSI and TCP/IP models · IPv4, CIDR and private ranges",
      tagline: "Do the subnet maths an analyst does every day",
      building: "archive",
      taskIds: ["proto-r1", "proto-r2"],
    },
    {
      id: "transport",
      label: "TCP and UDP",
      topic: "Handshake, flags, sequence numbers · UDP without guarantees",
      tagline: "Read a conversation packet by packet",
      building: "control",
      taskIds: ["proto-r3", "proto-r4", "proto-q1"],
    },
    {
      id: "web",
      label: "Names, Pages and Locks",
      topic: "DNS resolution and records · HTTP methods and codes · TLS 1.2 vs 1.3",
      tagline: "Crack what DNS, HTTP and TLS give away",
      building: "lab",
      taskIds: ["proto-r5", "proto-r6", "proto-r7"],
    },
    {
      id: "plumbing",
      label: "The Plumbing",
      topic: "ICMP, ARP, DHCP · 50 ports every analyst knows",
      tagline: "Catch a spoofed gateway and a rogue DHCP server",
      building: "vault",
      taskIds: ["proto-r8", "proto-r9", "proto-q3"],
    },
    {
      id: "abuse",
      label: "Hiding in Plain Sight",
      topic: "C2 over HTTP and DNS · tunnelling · protocol attacks",
      tagline: "Take a beacon apart before the graded DNS alert",
      building: "ticket",
      taskIds: ["proto-r10", "proto-q2", "proto-la1", "proto-f1"],
      boss: true,
    },
  ],
  personas: {
    "proto-q1": { name: "Lars Eriksen", role: "Network Security Architect", line: "Port 23 sends RST, port 3389 sends nothing. Read that for me." },
    "proto-q2": { name: "Lars Eriksen", role: "Network Security Architect", line: "Hundreds of 50-character base64 subdomains from one workstation. What is it?" },
    "proto-q3": { name: "Lars Eriksen", role: "Network Security Architect", line: "445 is blocked at the edge. An attacker is already inside. Still a problem?" },
  },
  briefings: {
    // ── Readings 1-2: layers and addresses ──
    "proto-r2": [
      {
        kind: "worksheet",
        title: "Subnet Maths",
        prompt: "Addresses from Quayside's logs. Work out where each one lives.",
        caption: "Quayside's crane network is 10.40.16.0/20",
        columns: ["address", "seen in"],
        rows: [
          ["10.40.31.200", "crane PLC syslog"],
          ["10.40.32.5", "firewall log, same 'crane' rule"],
          ["172.31.255.4", "VPN log"],
          ["169.254.12.7", "DHCP failure on a laptop"],
          ["100.64.3.9", "ISP-side address of the backup link"],
        ],
        questions: [
          { id: "range", q: "A /20 holds how many addresses?", hint: "32 - 20 = 12 host bits. 2^12 = ?", answer: ["4096"], why: "4,096 addresses: 10.40.16.0 to 10.40.31.255." },
          { id: "in", q: "Is 10.40.32.5 inside the crane network? (yes/no)", hint: "The /20 ends at 10.40.31.255.", answer: ["no"], why: "One past the end. A firewall rule that thinks it covers 'the crane network' but matches 10.40.32.x is wrong." },
          { id: "apipa", q: "What does a 169.254.x.x address tell you about that laptop?", hint: "Link-local.", answer: ["no dhcp", "it got no dhcp address", "dhcp failed", "apipa", "link-local", "no dhcp lease"], why: "169.254/16 is self-assigned when DHCP gives no answer: the laptop never got a lease." },
          { id: "cgnat", q: "Is 100.64.3.9 private (RFC 1918), public, or shared carrier space?", hint: "100.64.0.0/10.", answer: ["shared", "carrier", "cgnat", "carrier-grade nat", "shared carrier space"], why: "100.64.0.0/10 is shared address space for carrier-grade NAT: not one of the three RFC 1918 ranges, and not public either." },
        ],
      },
    ],
    // ── Readings 3-4: TCP and UDP ──
    "proto-r4": [
      {
        kind: "pcap",
        title: "Read the Conversation",
        prompt: "A capture from a customs workstation: one HTTPS session, start to finish, and one DNS lookup before it. Use the display filter (try tcp, udp, or an address).",
        capture: "customs-ws-0412.pcapng · 9 packets",
        packets: [
          { no: 1, time: "0.000000", src: "10.40.8.21", dst: "10.40.0.53", proto: "DNS", len: 78, info: "Standard query 0x4a1c A customs.quayside.example", tree: ["Ethernet II", "Internet Protocol Version 4, Src: 10.40.8.21, Dst: 10.40.0.53", "User Datagram Protocol, Src Port: 51544, Dst Port: 53", "Domain Name System (query): customs.quayside.example A"] },
          { no: 2, time: "0.003120", src: "10.40.0.53", dst: "10.40.8.21", proto: "DNS", len: 94, info: "Standard query response 0x4a1c A customs.quayside.example A 10.40.2.60", tree: ["User Datagram Protocol, Src Port: 53, Dst Port: 51544", "Domain Name System (response): A 10.40.2.60, TTL 300"] },
          { no: 3, time: "0.004010", src: "10.40.8.21", dst: "10.40.2.60", proto: "TCP", len: 66, info: "51545 → 443 [SYN] Seq=0 Win=64240 MSS=1460", tree: ["Transmission Control Protocol, Src Port: 51545, Dst Port: 443, Seq: 0", "Flags: 0x002 (SYN)"] },
          { no: 4, time: "0.004402", src: "10.40.2.60", dst: "10.40.8.21", proto: "TCP", len: 66, info: "443 → 51545 [SYN, ACK] Seq=0 Ack=1 Win=65535", tree: ["Transmission Control Protocol, Src Port: 443, Dst Port: 51545, Seq: 0, Ack: 1", "Flags: 0x012 (SYN, ACK)"] },
          { no: 5, time: "0.004450", src: "10.40.8.21", dst: "10.40.2.60", proto: "TCP", len: 54, info: "51545 → 443 [ACK] Seq=1 Ack=1", tree: ["Transmission Control Protocol, Seq: 1, Ack: 1", "Flags: 0x010 (ACK)"] },
          { no: 6, time: "0.005120", src: "10.40.8.21", dst: "10.40.2.60", proto: "TLSv1.3", len: 571, info: "Client Hello (SNI=customs.quayside.example)", tree: ["Transport Layer Security", "Handshake Protocol: Client Hello", "Extension: server_name customs.quayside.example"] },
          { no: 7, time: "0.009870", src: "10.40.2.60", dst: "10.40.8.21", proto: "TLSv1.3", len: 1514, info: "Server Hello, Change Cipher Spec, Application Data", tree: ["Transport Layer Security", "Handshake Protocol: Server Hello", "Cipher Suite: TLS_AES_256_GCM_SHA384"] },
          { no: 8, time: "1.120400", src: "10.40.8.21", dst: "10.40.2.60", proto: "TCP", len: 54, info: "51545 → 443 [FIN, ACK] Seq=1844 Ack=22190", tree: ["Flags: 0x011 (FIN, ACK)"] },
          { no: 9, time: "1.120810", src: "10.40.2.60", dst: "10.40.8.21", proto: "TCP", len: 54, info: "443 → 51545 [FIN, ACK] Seq=22190 Ack=1845", tree: ["Flags: 0x011 (FIN, ACK)"] },
        ],
        objectives: [
          { id: "udp", task: "Which protocol carried the DNS lookup, and was there a handshake before it?", hint: "Filter: udp", answer: ["udp", "udp, no", "udp no handshake", "udp no"], why: "UDP: one question, one answer, no SYN or ACK. That speed is why DNS uses it, and why DNS answers are easy to spoof." },
          { id: "est", task: "Which packet number completes the TCP three-way handshake?", hint: "Filter: tcp. SYN, SYN-ACK, then...", answer: ["5", "packet 5", "no. 5"], why: "SYN (3), SYN-ACK (4), ACK (5): the connection is established." },
          { id: "sni", task: "Which name did the client ask the TLS server for?", hint: "Look at the Client Hello.", answer: ["customs.quayside.example"], why: "The SNI travels before encryption starts: visible even in TLS 1.3." },
          { id: "close", task: "Which flag ends the session politely, from both sides?", hint: "Packets 8 and 9.", answer: ["FIN", "fin"], why: "FIN, ACK in both directions: a graceful close. An RST instead would be an abrupt abort." },
        ],
      },
    ],
    // ── Readings 5-7: DNS, HTTP, TLS ──
    "proto-r7": [
      {
        kind: "codebreak",
        title: "Read the Vendor Portal",
        prompt: "A user says the vendor portal looks odd. Lars reads you what its DNS, its HTTP answer and its certificate show; name the term behind each clue.",
        tries: 6,
        rounds: [
          { id: "alias", clue: "The portal name does not have its own address. Its DNS record points one name at another name, here a cloud-hosted site. Which record type makes an alias?", answer: "CNAME", why: "A CNAME points one name at another. Know who really hosts what you trust: the alias target, not the pretty name, is where the traffic ends up." },
          { id: "code", clue: "The portal answers with a status whose reason phrase is Found, a temporary redirect to a login host. Which three-digit code?", answer: "302", why: "302 is a temporary redirect. Where the location header sends people matters more than the code: a login on a domain that is not the vendor's main one must be verified before anyone types a password." },
          { id: "hsts", clue: "A response header, strict-transport-security with max-age=31536000, tells browsers to use only HTTPS for this site for a year. Four-letter acronym.", answer: "HSTS", why: "HSTS stops a browser from falling back to plain HTTP, which blocks downgrade tricks. It does not prove the site is the right one, only that the connection will be encrypted." },
          { id: "sni", clue: "In the TLS Client Hello the browser says which site it wants, in the clear, even in TLS 1.3. Which three-letter extension?", answer: "SNI", why: "Server Name Indication is how proxies and firewalls log HTTPS destinations. Also check the certificate dates: a free certificate issued three days ago on a portal that looks odd is worth a call to the vendor." },
        ],
        lesson: "A CNAME says who hosts it, the status and location say where it sends you, HSTS says it must be encrypted, and SNI says what the client asked for: four fields that decide whether a page is what it claims to be.",
      },
    ],
    // ── Readings 8-9: ICMP, ARP, DHCP, ports ──
    "proto-r9": [
      {
        kind: "rush",
        title: "Plumbing Facts",
        prompt: "Users on the dock Wi-Fi report certificate warnings and Lars wants the plumbing facts straight before you touch a switch. True or false, fast.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "p1", text: "ARP maps an IP address to a MAC address", answer: true, why: "ARP asks who has this IP and the owner answers with its MAC, on the local network only." },
          { id: "p2", text: "Two IPs on one MAC in an ARP table prove ARP spoofing", answer: false, why: "One NIC can hold several IPs. It becomes suspicious when one of them is the gateway's MAC claimed by an ordinary host." },
          { id: "p3", text: "A gateway whose MAC suddenly changes deserves a ticket", answer: true, why: "A changed MAC for the router's IP is what a spoofer leaves behind: traffic now goes to another machine first." },
          { id: "p4", text: "ARP requests cross routers to reach other subnets", answer: false, why: "ARP is a Layer 2 broadcast, so it stays on the local subnet. A router answers for the remote side." },
          { id: "p5", text: "An ARP request goes to ff:ff:ff:ff:ff:ff", answer: true, why: "The request is a broadcast; only the reply comes back as a unicast." },
          { id: "p6", text: "A DHCP Discover is sent straight to the server's address", answer: false, why: "The client has no address yet, so it broadcasts from 0.0.0.0 to 255.255.255.255 (UDP 68 to 67)." },
          { id: "p7", text: "A rogue DHCP server can hand out its own DNS server", answer: true, why: "DHCP also sets the gateway and DNS server. A rogue that answers first can steer every client through itself." },
          { id: "p8", text: "DHCP snooping drops offers that arrive on untrusted ports", answer: true, why: "Only the port facing the real DHCP server is trusted, so a rogue plugged into an access port is silenced." },
          { id: "p9", text: "Dynamic ARP Inspection uses the DHCP snooping table", answer: true, why: "DAI checks each ARP reply against the IP and MAC bindings that snooping recorded, and drops liars." },
          { id: "p10", text: "ICMP echo request is type 8 and the reply is type 0", answer: true, why: "Type 8 is the ping going out and type 0 the answer. Type 3 is destination unreachable." },
          { id: "p11", text: "Port 389 is LDAP over TLS", answer: false, why: "389 is plain LDAP. LDAPS uses 636, so credentials on 389 may be readable." },
          { id: "p12", text: "Port 1433 is PostgreSQL", answer: false, why: "1433 is Microsoft SQL Server. PostgreSQL listens on 5432." },
          { id: "p13", text: "The SYN-ACK is sent by the client", answer: false, why: "The server answers a SYN with SYN-ACK, and the client then completes the handshake with an ACK." },
          { id: "p14", text: "UDP sets up a handshake before sending data", answer: false, why: "UDP sends datagrams with no connection and no guarantee. That speed is why DNS and DHCP use it." },
        ],
        lesson: "Layer 2 and the first packets of a network (ARP, DHCP) trust whoever speaks first, which is why snooping and ARP inspection exist and why a repeated MAC or a second DHCP server is worth a ticket.",
      },
    ],
    // Drill before the graded DNS alert: an HTTP beacon, field by field.
    "proto-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an HTTP Beacon",
        prompt: "Before the graded DNS record: a different C2 channel, over HTTP, as Zeek recorded it.",
        source: "Zeek · http.log · quay-ws-0661 · one of 288 identical rows",
        fields: [
          { key: "ts", value: "1793813400.118 (then every 300 s ±15)", label: "Rhythm", note: "Five minutes with a little jitter: a sleep timer, not a person." },
          { key: "id.orig_h", value: "10.40.8.61", label: "From" },
          { key: "id.resp_h", value: "198.51.100.33", label: "To" },
          { key: "method", value: "GET" },
          { key: "host", value: "cdn-update-check.example", label: "Name", note: "Sounds like an updater. Nothing at Quayside updates from it." },
          { key: "uri", value: "/api/v2/check?id=QW0661", label: "Path", note: "The same path each time, with a host ID in it." },
          { key: "user_agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", label: "Disguise", note: "A browser string, but no Referer and no cookies, every time." },
          { key: "status_code", value: "200" },
          { key: "response_body_len", value: "0 (and 412 bytes once, at 03:15)", label: "Tasks", note: "Empty means 'nothing to do'; the one non-empty reply is a command arriving." },
        ],
        summary: "Regular rhythm, constant path, no browser behaviour around it: C2 over HTTP (T1071.001). Now read the graded record, where the channel is DNS.",
      },
    ],
  },
};
