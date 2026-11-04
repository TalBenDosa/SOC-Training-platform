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
  mission: "Do subnet maths and place logs on the stack, read a TCP conversation and a UDP query in a capture, interrogate DNS, HTTP and TLS from the command line, catch an ARP spoof and a rogue DHCP server, and take apart an HTTP beacon.",
  estimate: "~60 min",
  look: { primary: "#2dd4bf", secondary: "#a78bfa", warn: "#f43f5e" },
  scene: "protostack",
  layout: "stage",
  story: {
    intro: { title: "Always Allowed", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-intro-3553a2ac.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-intro-a9f53b75.jpg" },
    afterStation: {
      layers: { title: "SYN, SYN-ACK, ACK", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch2-749ad2f4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch2-fe90a75a.jpg" },
      web: { title: "Two Devices, One MAC", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch3-990033f9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-ch3-8aed7c58.jpg" },
      abuse: { title: "A Pipe Nobody Closes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-finale-9c7c9a50.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/protocols-masterclass/deepwater-finale-44d6d81f.jpg" },
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
      tagline: "Interrogate DNS, HTTP and TLS from the shell",
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
        kind: "terminal",
        title: "Interrogate the Stack",
        prompt: "A user says the vendor portal looks odd. Check its DNS, its HTTP answer and its certificate from the shell.",
        shell: "bash",
        host: "lars@netops:~$",
        commands: [
          { match: "dig\\s+(\\+short\\s+)?portal\\.quay-vendors\\.example(\\s+a)?(\\s+\\+short)?", help: "dig +short portal.quay-vendors.example               its address",
            output: "203.0.113.150" },
          { match: "dig\\s+(\\+short\\s+)?cname\\s+portal\\.quay-vendors\\.example.*|dig\\s+portal\\.quay-vendors\\.example\\s+cname.*", help: "dig +short CNAME portal.quay-vendors.example        is it an alias?",
            output: "quay-vendors-portal.azurewebsites.example." },
          { match: "curl\\s+-s?I\\s+https://portal\\.quay-vendors\\.example.*|curl\\s+-I\\s+.*portal\\.quay-vendors\\.example.*", help: "curl -sI https://portal.quay-vendors.example        response headers only",
            output: "HTTP/2 302\nlocation: https://login.quay-vendors-sso.example/auth?next=/portal\nserver: nginx\nstrict-transport-security: max-age=31536000\nset-cookie: qv_sess=8f2a...; Secure; HttpOnly; SameSite=Lax" },
          { match: "openssl\\s+s_client\\s+.*portal\\.quay-vendors\\.example.*", help: "openssl s_client -connect portal.quay-vendors.example:443 -servername portal.quay-vendors.example </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates",
            output: "issuer=C = US, O = Let's Encrypt, CN = R11\nsubject=CN = portal.quay-vendors.example\nnotBefore=Nov  1 00:00:00 2026 GMT\nnotAfter=Jan 30 23:59:59 2027 GMT\nProtocol  : TLSv1.3" },
        ],
        objectives: [
          { id: "alias", task: "What is the portal name an alias for?", hint: "dig +short CNAME portal.quay-vendors.example", answer: ["quay-vendors-portal.azurewebsites.example", "quay-vendors-portal.azurewebsites.example."], why: "A CNAME points one name at another: here a cloud-hosted site. Know who really hosts what you trust." },
          { id: "code", task: "What status does the portal answer with?", hint: "curl -sI https://portal.quay-vendors.example", answer: ["302"], why: "302 is a redirect. Where it sends people matters more than the code." },
          { id: "where", task: "Which host does it redirect to for login?", hint: "The location header.", answer: ["login.quay-vendors-sso.example"], why: "A login domain that isn't the vendor's main one: check it's really theirs before anyone types a password." },
          { id: "new", task: "When was the certificate issued?", hint: "openssl s_client ... | openssl x509 -noout -issuer -subject -dates", answer: ["Nov 1 2026", "Nov  1 2026", "2026-11-01", "Nov 1", "1 Nov 2026"], why: "Three days ago. Free 90-day certificates are normal, but a brand-new one on a portal that 'looks odd' is worth a call to the vendor." },
        ],
      },
    ],
    // ── Readings 8-9: ICMP, ARP, DHCP, ports ──
    "proto-r9": [
      {
        kind: "terminal",
        title: "Who Is the Gateway?",
        prompt: "Users on the dock Wi-Fi report certificate warnings. Check the ARP table and DHCP settings on one of their laptops.",
        shell: "cmd",
        host: "C:\\Users\\dock07>",
        commands: [
          { match: "arp\\s+-a", help: "arp -a                                      IP-to-MAC table",
            output: "\nInterface: 10.60.4.37 --- 0xb\n  Internet Address      Physical Address      Type\n  10.60.4.1             3c-52-82-1a-9e-f7     dynamic\n  10.60.4.12            3c-52-82-1a-9e-f7     dynamic\n  10.60.4.20            00-1b-21-7a-33-c0     dynamic\n  10.60.4.255           ff-ff-ff-ff-ff-ff     static" },
          { match: "ipconfig\\s+/all", help: "ipconfig /all                               this laptop's network settings",
            output: "Wireless LAN adapter Wi-Fi:\n   IPv4 Address. . . . . . . . . . . : 10.60.4.37(Preferred)\n   Default Gateway . . . . . . . . . : 10.60.4.1\n   DHCP Server . . . . . . . . . . . : 10.60.4.12\n   DNS Servers . . . . . . . . . . . : 10.60.4.12" },
          { match: "ping\\s+(-n\\s+\\d+\\s+)?10\\.60\\.4\\.1", help: "ping -n 1 10.60.4.1                         is the gateway answering?",
            output: "Reply from 10.60.4.1: bytes=32 time=4ms TTL=64" },
        ],
        objectives: [
          { id: "dup", task: "Which IP shares the gateway's MAC address?", hint: "arp -a", answer: ["10.60.4.12"], why: "Two IPs, one MAC: 10.60.4.12 is answering ARP for the gateway. Traffic meant for the router goes to that machine first: ARP spoofing." },
          { id: "dhcp", task: "Which machine handed this laptop its settings?", hint: "ipconfig /all", answer: ["10.60.4.12"], why: "The same host is the DHCP server and the DNS server. The real ones live in the server VLAN. A rogue DHCP server can steer every client." },
          { id: "dns", task: "Why do users see certificate warnings? (who answers their DNS?)", hint: "DNS Servers line.", answer: ["10.60.4.12", "the rogue host", "rogue dhcp", "the attacker"], why: "The rogue host answers DNS and sits in the middle, so HTTPS sites present the wrong certificate. Enable DHCP snooping and Dynamic ARP Inspection on the switch." },
        ],
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
