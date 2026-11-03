import type { RoomExperience } from "./types";

// "Operation Packet Trail" for the "networking-fundamentals" room (rooms-batch-02.ts).
// Script: docs/campaign/02-networking-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Harbor Freight Logistics (fictional), night shift. The graded boss is a
// firewall log of an outbound connection to port 4444. Every lab uses other
// data: the packet builder sends to 443 on the intranet, netstat shows 8443 and
// 3389 (never 4444), the NAT trace uses 203.0.113.77 (the graded log's NAT
// address is 203.0.113.15), and the drill log is a denied SMB connection.
export const NETWORKING_FUNDAMENTALS: RoomExperience = {
  roomId: "networking-fundamentals",
  codename: "Operation Packet Trail",
  theme: "datacenter",
  handler: { name: "Ravi Menon", role: "Network Security Lead, Harbor Freight Logistics" },
  briefing: [
    "02:47. Harbor Freight Logistics, data hall B.",
    "A workstation just opened a connection to the other side of the world.",
    "To read that log you need to see what the firewall sees: addresses, ports, layers, the path.",
    "Ravi wants you to follow one packet, hop by hop, before the alert lands on your desk.",
  ],
  mission: "Follow a packet from a laptop to the internet: build it layer by layer, watch the handshake, trace it through NAT and DHCP, then read the 02:47 firewall log like an analyst.",
  estimate: "~45 min",
  look: { primary: "#38bdf8", secondary: "#a78bfa", warn: "#f97316" },
  scene: "datapath",
  layout: "stage",
  stations: [
    {
      id: "wrap",
      label: "Wrap the Packet",
      topic: "The OSI model · encapsulation · IP and MAC addresses · private vs public",
      tagline: "Build a real packet layer by layer, then read your own laptop's network settings",
      building: "lab",
      taskIds: ["net-fund-r1"],
    },
    {
      id: "handshake",
      label: "Shake Hands",
      topic: "TCP vs UDP · the three-way handshake and teardown · connection states · ports",
      tagline: "Watch a connection open and close, then read live connections with netstat",
      building: "control",
      taskIds: ["net-fund-r2"],
    },
    {
      id: "border",
      label: "Cross the Border",
      topic: "Switches and routers · NAT · DHCP · finding the real device",
      tagline: "An alert names a public IP. Trace it through NAT, DHCP and the switch to one desk",
      building: "factory",
      taskIds: ["net-fund-r3"],
    },
    {
      id: "checkpoint",
      label: "Signal Check",
      topic: "Private IPs · completed handshakes · OSI layers, in real cases",
      tagline: "Three quick calls from the floor. Answer them the way you would on shift",
      building: "ticket",
      taskIds: ["net-fund-q1", "net-fund-q2", "net-fund-q3"],
    },
    {
      id: "alert",
      label: "The 02:47 Connection",
      topic: "Reading a firewall connection log field by field",
      tagline: "The alert is on your screen. Work it, then pull the one value the ticket needs",
      building: "vault",
      taskIds: ["net-fund-la1", "net-fund-f1"],
      boss: true,
    },
  ],
  personas: {
    "net-fund-q1": {
      name: "Ravi Menon",
      role: "Network Security Lead",
      line: "The firewall named this address as the source. Before anyone chases it, tell me where it lives.",
    },
    "net-fund-q2": {
      name: "Ravi Menon",
      role: "Network Security Lead",
      line: "A workstation, an external host, a finished handshake. Tell me what that means for us.",
    },
    "net-fund-q3": {
      name: "Lena Ortiz",
      role: "Junior Analyst",
      line: "Settle an argument for me. Which layer is this?",
    },
  },
  briefings: {
    // ── Reading 1: OSI, encapsulation, IP and MAC addressing ──
    "net-fund-r1": [
      {
        kind: "encap",
        title: "Build a Packet",
        prompt: "Every request leaves your laptop wrapped in envelopes, one per layer. Build this one yourself, from the inside out.",
        story: "Laptop 10.20.4.15 (MAC 3c:52:82:1a:9f:04) opens https://intranet.harbor.local at 10.20.0.15. It is on another subnet, reached through the gateway 10.20.4.1 (MAC 00:1b:54:c2:7e:10).",
        layers: [
          {
            id: "l4", layer: "L4 Transport", pdu: "segment",
            field: "The TCP header: which destination port?",
            options: ["443", "80", "53", "51544"], answer: 0,
            why: "HTTPS listens on 443. The laptop picks a random high source port (here 51544) for its side of the conversation.",
            tree: "Transmission Control Protocol, Src Port: 51544, Dst Port: 443, Flags: [SYN]",
          },
          {
            id: "l3", layer: "L3 Network", pdu: "packet",
            field: "The IP header: which destination IP address?",
            options: ["10.20.0.15", "10.20.4.1", "10.20.4.15", "8.8.8.8"], answer: 0,
            why: "The IP header carries the final destination end to end. The gateway is only the next hop, and it never appears as the destination IP.",
            tree: "Internet Protocol Version 4, Src: 10.20.4.15, Dst: 10.20.0.15",
          },
          {
            id: "l2", layer: "L2 Data Link", pdu: "frame", chip: "00:1b:54:c2:7e:10",
            field: "The Ethernet header: which destination MAC address?",
            options: ["00:1b:54:c2:7e:10 (the gateway)", "The intranet server's own MAC", "3c:52:82:1a:9f:04 (this laptop)", "ff:ff:ff:ff:ff:ff (broadcast)"], answer: 0,
            why: "The server is on another subnet, so the frame only travels one hop: to the gateway. The MAC changes at every hop, the IP stays the same all the way.",
            tree: "Ethernet II, Src: 3c:52:82:1a:9f:04, Dst: 00:1b:54:c2:7e:10",
          },
          {
            id: "l1", layer: "L1 Physical", pdu: "bits", chip: "0101 1100 ...",
            field: "How does the finished frame leave the laptop?",
            options: ["As bits: signals on the cable or radio", "As a new IP packet", "As a TCP segment", "As a DNS query"], answer: 0,
            why: "Layer 1 has no addresses at all. It turns the frame into 1s and 0s on copper, fibre or Wi-Fi.",
            tree: "Frame 1: 74 bytes on wire (592 bits), 74 bytes captured",
          },
        ],
      },
      {
        kind: "sort",
        title: "Layer Triage",
        prompt: "When something breaks, analysts ask 'which layer?' first. Sort each event onto the OSI layer where it happens.",
        buckets: [
          { id: "l1", label: "L1 Physical" },
          { id: "l2", label: "L2 Data Link" },
          { id: "l3", label: "L3 Network" },
          { id: "l4", label: "L4 Transport" },
          { id: "l5", label: "L5 Session" },
          { id: "l6", label: "L6 Presentation" },
          { id: "l7", label: "L7 Application" },
        ],
        items: [
          { id: "port", text: "An unknown device is plugged into an empty wall port", bucket: "l1", why: "A physical connection to the medium: Layer 1. This is why NAC exists." },
          { id: "arp", text: "Forged ARP replies claim the gateway's IP belongs to another MAC", bucket: "l2", why: "ARP maps IPs to MACs on the local LAN: Layer 2, and it has no authentication." },
          { id: "bgp", text: "A provider announces routes it does not own and pulls traffic toward it", bucket: "l3", why: "BGP hijacking abuses routing between networks: Layer 3." },
          { id: "syn", text: "Half-open connections pile up until a server stops answering", bucket: "l4", why: "A SYN flood abuses TCP's handshake: Layer 4." },
          { id: "cookie", text: "A stolen session cookie takes over a signed-in user", bucket: "l5", why: "Hijacking the token that keeps a session alive: Layer 5." },
          { id: "tls", text: "Malware hides its command traffic inside TLS encryption", bucket: "l6", why: "Encryption is a Layer 6 job, which is why C2 hides there." },
          { id: "sqli", text: "SQL commands are typed into a website's login form", bucket: "l7", why: "The application itself is abused: Layer 7." },
        ],
      },
      {
        kind: "terminal",
        title: "Read Your Own Laptop",
        prompt: "The first thing an analyst does on a host is ask it who it is on the network. Use the console to answer each objective.",
        shell: "cmd",
        host: "C:\\Users\\analyst>",
        commands: [
          {
            match: "ipconfig",
            help: "ipconfig          show IP address, mask and gateway",
            output: "Windows IP Configuration\n\nEthernet adapter Ethernet:\n\n   Connection-specific DNS Suffix  . : harbor.local\n   IPv4 Address. . . . . . . . . . . : 10.20.4.15\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 10.20.4.1",
          },
          {
            match: "ipconfig\\s+/all",
            help: "ipconfig /all     full detail: MAC, DHCP, DNS",
            output: "Windows IP Configuration\n\n   Host Name . . . . . . . . . . . . : HFL-LT-0412\n   Primary Dns Suffix  . . . . . . . : harbor.local\n\nEthernet adapter Ethernet:\n\n   Description . . . . . . . . . . . : Intel(R) Ethernet Connection I219-LM\n   Physical Address. . . . . . . . . : 3C-52-82-1A-9F-04\n   DHCP Enabled. . . . . . . . . . . : Yes\n   IPv4 Address. . . . . . . . . . . : 10.20.4.15(Preferred)\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Lease Obtained. . . . . . . . . . : Tuesday, 3 November 2026 08:02:11\n   Lease Expires . . . . . . . . . . : Tuesday, 3 November 2026 16:02:11\n   Default Gateway . . . . . . . . . : 10.20.4.1\n   DHCP Server . . . . . . . . . . . : 10.20.0.5\n   DNS Servers . . . . . . . . . . . : 10.20.0.10",
          },
          {
            match: "arp\\s+-a",
            help: "arp -a            IP to MAC table for the local network",
            output: "Interface: 10.20.4.15 --- 0x7\n  Internet Address      Physical Address      Type\n  10.20.4.1             00-1b-54-c2-7e-10     dynamic\n  10.20.4.22            f8-75-a4-02-11-9c     dynamic\n  10.20.4.255           ff-ff-ff-ff-ff-ff     static\n  224.0.0.22            01-00-5e-00-00-16     static",
          },
          {
            match: "hostname",
            help: "hostname          this computer's name",
            output: "HFL-LT-0412",
          },
        ],
        objectives: [
          { id: "ip", task: "What is this laptop's IPv4 address?", hint: "ipconfig", answer: ["10.20.4.15"], why: "10.20.4.15 sits in 10.0.0.0/8: a private address. It is never routed on the internet as-is, so NAT has to translate it on the way out." },
          { id: "mac", task: "What is this laptop's MAC (physical) address?", hint: "ipconfig /all", answer: ["3C-52-82-1A-9F-04", "3c:52:82:1a:9f:04", "3c-52-82-1a-9f-04", "3C:52:82:1A:9F:04"], why: "The burned-in Layer 2 address. Windows writes it with dashes, Linux and most logs with colons: same 48 bits." },
          { id: "cidr", task: "Write the laptop's subnet in CIDR notation.", hint: "ipconfig", answer: ["10.20.4.0/24"], why: "A mask of 255.255.255.0 is 24 network bits: 10.20.4.0/24, 256 addresses from 10.20.4.0 to 10.20.4.255." },
          { id: "gwmac", task: "What MAC address does the default gateway answer from?", hint: "arp -a", answer: ["00-1b-54-c2-7e-10", "00:1b:54:c2:7e:10", "00-1B-54-C2-7E-10", "00:1B:54:C2:7E:10"], why: "The ARP cache maps the gateway's IP to its MAC. If this value suddenly changes to another device's MAC, suspect ARP spoofing." },
        ],
      },
    ],
    // ── Reading 2: TCP vs UDP, the handshake, states and ports ──
    "net-fund-r2": [
      {
        kind: "sequence",
        title: "Open and Close a Connection",
        prompt: "A client fetches a page and hangs up politely. Tap the packets in the order they cross the wire.",
        items: [
          { id: "ack3", text: "Client → Server: ACK", note: "Third step: the handshake is complete. ESTABLISHED." },
          { id: "fin1", text: "Client → Server: FIN", note: "The client has nothing more to send." },
          { id: "syn", text: "Client → Server: SYN", note: "First step: 'I want to connect.'" },
          { id: "data", text: "Client → Server: HTTP GET /", note: "Data only flows after the handshake." },
          { id: "synack", text: "Server → Client: SYN-ACK", note: "Second step: 'I got it, I am ready.'" },
          { id: "fin2", text: "Server → Client: ACK, then FIN", note: "The server acknowledges and closes its own direction." },
          { id: "ack4", text: "Client → Server: final ACK", note: "Teardown done. The client sits in TIME-WAIT briefly." },
        ],
        order: ["syn", "synack", "ack3", "data", "fin1", "fin2", "ack4"],
        doneNote: "Three packets to open, four to close (the server's ACK and FIN are two packets). A pile of SYN-RECEIVED with no final ACK is the signature of a SYN flood.",
      },
      {
        kind: "terminal",
        title: "Live Connections",
        prompt: "Ravi asks what this server is talking to right now. netstat lists every connection and its TCP state. Find the answers in the output.",
        shell: "cmd",
        host: "C:\\Windows\\system32>",
        commands: [
          {
            match: "netstat(\\s+-a)?(\\s+-n)?(\\s+-o)?|netstat\\s+-ano|netstat\\s+-nao|netstat\\s+-ona",
            help: "netstat -ano      all connections, numeric, with owning PID",
            output: "Active Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1288\n  TCP    10.20.4.30:3389        10.20.4.15:55102       ESTABLISHED     1288\n  TCP    10.20.4.30:49811       52.96.165.18:443       ESTABLISHED     5520\n  TCP    10.20.4.30:49930       198.51.100.23:8443     ESTABLISHED     7340\n  TCP    10.20.4.30:50101       10.20.9.11:445         SYN_SENT        6204\n  TCP    10.20.4.30:50102       10.20.9.12:445         SYN_SENT        6204\n  TCP    10.20.4.30:50103       10.20.9.13:445         SYN_SENT        6204\n  TCP    10.20.4.30:50104       10.20.9.14:445         SYN_SENT        6204\n  TCP    10.20.4.30:49702       13.107.42.14:443       TIME_WAIT       0\n  UDP    0.0.0.0:123            *:*                                    1440\n  UDP    10.20.4.30:53000       10.20.0.10:53          *:*             2216",
          },
          {
            match: "tasklist(\\s+/fi\\s+\"?pid eq 7340\"?)?",
            help: "tasklist /fi \"pid eq 7340\"   which program owns a PID",
            output: "Image Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\nupdater.exe                   7340 Services                   0     18,432 K",
          },
          {
            match: "tasklist\\s+/fi\\s+\"?pid eq 6204\"?",
            output: "Image Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\nsvch0st.exe                   6204 Services                   0      9,120 K",
          },
          {
            match: "tasklist\\s+/fi\\s+\"?pid eq (\\d+)\"?",
            output: "INFO: Try the PIDs from the netstat output, for example 7340 or 6204.",
          },
        ],
        objectives: [
          { id: "rdp", task: "Which local port is listening for Remote Desktop (and has a session open)?", hint: "netstat -ano", answer: ["3389"], why: "3389 is RDP. Here it is LISTENING and ESTABLISHED from 10.20.4.15: an internal admin session. Exposed to the internet, the same port is a top ransomware entry point." },
          { id: "pid", task: "Which PID owns the established connection to 198.51.100.23 on port 8443?", hint: "netstat -ano", answer: ["7340"], why: "The PID column ties a connection to a process. That is how a network alert becomes an endpoint investigation." },
          { id: "proc", task: "Which program is that PID?", hint: "tasklist /fi \"pid eq 7340\"", answer: ["updater.exe"], why: "An 'updater' talking to an external host on 8443 might be legitimate. Next step on shift: check the file's path, signer and hash." },
          { id: "scan", task: "One process has SYN_SENT to many 10.20.9.x hosts on 445. What is it doing? (one word)", hint: "netstat -ano", answer: ["scanning", "scan", "port scan", "port scanning", "scanning smb"], why: "Many half-open attempts to the same port across a range is a scan. Here it is SMB (445) from svch0st.exe, a misspelt svchost: lateral-movement reconnaissance." },
        ],
      },
      {
        kind: "match",
        title: "Port Wall",
        prompt: "You will read ports in every log. Match each port to its service.",
        pairs: [
          { id: "22", left: "22", right: "SSH: encrypted remote shell", why: "Brute-forced constantly on internet-facing hosts." },
          { id: "53", left: "53", right: "DNS: name resolution", why: "Rarely blocked, so malware tunnels through it." },
          { id: "445", left: "445", right: "SMB: Windows file sharing", why: "EternalBlue and WannaCry; lateral movement." },
          { id: "3389", left: "3389", right: "RDP: Windows remote desktop", why: "Never expose it to the internet." },
          { id: "25", left: "25", right: "SMTP: mail between servers", why: "Phishing arrives this way." },
          { id: "123", left: "123", right: "NTP: time sync (UDP)", why: "Wrong time breaks log correlation; NTP is also used for amplification DDoS." },
        ],
      },
    ],
    // ── Reading 3: routing, switching, NAT, DHCP, attribution ──
    "net-fund-r3": [
      {
        kind: "trace",
        title: "Who Was Behind the NAT?",
        prompt: "Threat intel only gives you a public IP. Find the actual laptop and the desk it sits at: one log at a time, the way an analyst does it.",
        lead: "203.0.113.77, source port 50122, reached the phishing server 198.51.100.200 at 14:05:12 UTC.",
        steps: [
          {
            id: "nat", source: "Firewall NAT log",
            ask: "Which internal address and port were translated to 203.0.113.77:50122 at 14:05:12?",
            columns: ["time (UTC)", "internal", "public (after NAT)", "destination"],
            rows: [
              ["14:05:09", "10.20.6.18:60011", "203.0.113.77:50120", "52.96.165.18:443"],
              ["14:05:11", "10.20.4.15:51544", "203.0.113.77:50121", "13.107.42.14:443"],
              ["14:05:12", "10.20.6.31:61530", "203.0.113.77:50122", "198.51.100.200:443"],
              ["14:05:12", "10.20.6.40:58233", "203.0.113.77:50123", "142.250.80.46:443"],
              ["14:05:14", "10.20.5.77:49412", "203.0.113.77:50124", "198.51.100.23:8443"],
              ["14:06:02", "10.20.6.31:61544", "203.0.113.77:50122", "13.107.42.14:443"],
            ],
            answer: 2,
            why: "Hundreds of devices share 203.0.113.77; only the public port and the exact second separate them. The last row reuses port 50122 a minute later for a different connection: time matters.",
            learned: "Internal source: 10.20.6.31 at 14:05:12",
          },
          {
            id: "dhcp", source: "DHCP lease log",
            ask: "Which device held 10.20.6.31 at 14:05:12?",
            columns: ["lease start", "lease end", "ip", "mac", "hostname"],
            rows: [
              ["06:10:44", "10:10:44", "10.20.6.31", "a4:83:e7:5c:22:10", "WH-SCAN-07"],
              ["10:31:02", "18:31:02", "10.20.6.31", "f0:2f:74:91:3b:6e", "HFL-LT-0377"],
              ["10:31:05", "18:31:05", "10.20.6.32", "a4:83:e7:5c:22:10", "WH-SCAN-07"],
              ["11:02:19", "19:02:19", "10.20.6.40", "08:00:27:4e:aa:01", "HFL-LT-0291"],
            ],
            answer: 1,
            why: "The same IP belonged to a warehouse scanner until 10:10. From 10:31 it was leased to HFL-LT-0377. Blame the wrong lease and you investigate the wrong machine.",
            learned: "Device: HFL-LT-0377 (MAC f0:2f:74:91:3b:6e)",
          },
          {
            id: "switch", source: "Access switch MAC address table (SW-F2-ACC-01)",
            ask: "Which switch port, and so which desk, is that MAC plugged into?",
            columns: ["vlan", "mac address", "type", "port", "port description"],
            rows: [
              ["20", "a4:83:e7:5c:22:10", "DYNAMIC", "Gi1/0/3", "Warehouse dock 3"],
              ["20", "08:00:27:4e:aa:01", "DYNAMIC", "Gi1/0/9", "Floor 2 desk 2-09"],
              ["20", "f0:2f:74:91:3b:6e", "DYNAMIC", "Gi1/0/14", "Floor 2 desk 2-14"],
              ["99", "00:1b:54:c2:7e:10", "STATIC", "Gi1/0/48", "Uplink to core"],
            ],
            answer: 2,
            why: "Switches learn which MAC lives on which port. From one public IP to one desk: NAT log, DHCP lease, switch table. That chain is how attribution works when only an IP is known.",
            learned: "Location: switch port Gi1/0/14, Floor 2 desk 2-14",
          },
        ],
      },
      {
        kind: "terminal",
        title: "Map the Path Out",
        prompt: "Which routers does your traffic cross on the way out? tracert lists every hop.",
        shell: "cmd",
        host: "C:\\Users\\analyst>",
        commands: [
          {
            match: "tracert(\\s+-d)?\\s+8\\.8\\.8\\.8",
            help: "tracert 8.8.8.8   list every router hop to an address",
            output: "Tracing route to 8.8.8.8 over a maximum of 30 hops\n\n  1    <1 ms    <1 ms    <1 ms  10.20.4.1\n  2     1 ms     1 ms     1 ms  10.20.0.1\n  3     3 ms     2 ms     3 ms  203.0.113.1\n  4     8 ms     7 ms     8 ms  198.51.100.9\n  5    11 ms    10 ms    11 ms  192.0.2.65\n  6    12 ms    12 ms    12 ms  8.8.8.8\n\nTrace complete.",
          },
          {
            match: "tracert(\\s+\\S+)?",
            output: "Usage here: tracert 8.8.8.8",
          },
          {
            match: "ipconfig(\\s+/all)?",
            help: "ipconfig          show IP address, mask and gateway",
            output: "Ethernet adapter Ethernet:\n\n   IPv4 Address. . . . . . . . . . . : 10.20.4.15\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 10.20.4.1\n   DHCP Server . . . . . . . . . . . : 10.20.0.5",
          },
        ],
        objectives: [
          { id: "hop1", task: "What is the first hop?", hint: "tracert 8.8.8.8", answer: ["10.20.4.1"], why: "The first hop is always your default gateway: the router that leaves your subnet. Compare it with ipconfig." },
          { id: "public", task: "At which hop number does the path first reach a public IP address?", hint: "tracert 8.8.8.8", answer: ["3"], why: "Hops 1 and 2 are private (10.x). Hop 3, 203.0.113.1, is the provider: this is where NAT has already swapped the private source for the public one." },
          { id: "dhcp", task: "Which server handed this laptop its IP address?", hint: "ipconfig /all", answer: ["10.20.0.5"], why: "The DHCP server. Its lease log is what turned an IP into a hostname in the trace above. A second, unknown DHCP server on the LAN is a rogue: a man-in-the-middle setup." },
        ],
      },
    ],
    // Drill before the graded firewall log: a different connection, decoded.
    "net-fund-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Firewall Log",
        prompt: "Before the 02:47 alert, Ravi shows you last night's entry from the same firewall. Decode it field by field.",
        source: "Perimeter firewall · connection log",
        fields: [
          { key: "timestamp", value: "2025-11-13T23:12:08Z", label: "When", note: "UTC. Always line it up with the other logs before you compare." },
          { key: "action", value: "deny", label: "What the firewall did", note: "The connection was blocked. 'allow' would mean it went through, which is a very different alert." },
          { key: "protocol", value: "TCP" },
          { key: "src_ip", value: "10.20.6.8", label: "From", note: "A private address: the connection started inside the company." },
          { key: "src_port", value: "53114", label: "Source port", note: "A high, random (ephemeral) port chosen by the client. Rarely interesting on its own." },
          { key: "dst_ip", value: "192.0.2.144", label: "To", note: "A public address: the connection was trying to leave the network." },
          { key: "dst_port", value: "445", label: "Which service", note: "SMB. Windows file sharing should never go out to the internet; malware and worms try exactly this." },
          { key: "connection_state", value: "SYN_SENT", label: "How far it got", note: "Only the first SYN went out. No handshake, so no data was exchanged." },
          { key: "bytes_sent", value: "66" },
          { key: "bytes_received", value: "0", label: "Data received", note: "Zero bytes back confirms nothing came in. Compare this field on every connection log you read." },
          { key: "rule_matched", value: "BLOCK-SMB-OUTBOUND", label: "Which rule", note: "The rule that fired. It tells you whether this was a policy you expect to catch things." },
          { key: "nat_src_ip", value: "203.0.113.15" },
          { key: "geo_dst_country", value: "NL" },
        ],
        summary: "Inside host 10.20.6.8 tried to reach an internet address on SMB (445); the firewall's outbound SMB rule denied it after the first SYN, and nothing was received. Blocked, but worth asking why a workstation tried at all.",
      },
    ],
  },
};
