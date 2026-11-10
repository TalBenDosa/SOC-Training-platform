import type { RoomExperience } from "./types";

// "Operation Wire Level" for the "tcpip-deep-dive" room.
// Script: docs/campaign/51-tcpip-deep-dive.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Kelvin Point Hosting (fictional), not the graded tasks' SRV-CORE02 or BASTION-01.
// Signature mechanic: pathway (walk a server socket through the TCP state machine).
// Game mix: pathway + deduce + defuse + rush, and a real capture in the pcap lab.
// Lab data differs from the graded tasks: the walk is the server's side and never
// reaches TIME_WAIT (r1 checkpoint) or lists segments in order (o1); the suspects
// show no technique names (m1), no Zeek states (q2, r2 checkpoint) and no closed-port
// replies (q1); the fingerprints avoid flow exports (r4 checkpoint) and the graded
// sessions (la2, f1); the blitz has no conn_state values (la1, qf1) and no health
// checks (ac1); the capture is a blocked host, with no filter-type question (r7).
export const TCPIP_DEEP_DIVE: RoomExperience = {
  roomId: "tcpip-deep-dive",
  codename: "Operation Wire Level",
  theme: "wire",
  handler: { name: "Anneke Visser", role: "Principal Network Analyst, Kelvin Point Hosting" },
  briefing: [
    "Kelvin Point Hosting. Three data halls, 1,400 customer servers, and a tap on every core link.",
    "Last month a customer swore their firewall logs were clean. The packets said otherwise, and it took Anneke Visser eleven minutes to prove it.",
    "Anneke doesn't read dashboards first. Flags, TTLs and byte counts come first, because those are the parts of a connection nobody thinks to fake.",
    "Walk a socket through its whole life, catch a scanner, fingerprint what's really behind an address, then work a live sweep and a verdict.",
  ],
  mission: "Walk a server socket through the TCP state machine, unmask a scanner, defuse a fingerprint panel, call flow or packet at speed, read a capture, then work a live sweep and a verdict.",
  estimate: "~65 min",
  look: { primary: "#fbbf24", secondary: "#38bdf8", warn: "#ef4444" },
  scene: "facilitytcpipdeepdive",
  layout: "facility",
  story: {
    intro: { title: "Eleven Minutes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-intro-f6e8e3f9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-intro-62cc4234.jpg" },
    afterStation: {
      handshake: { title: "Handwriting", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-ch2-20d5eb5a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-ch2-ccb78b4e.jpg" },
      scans: { title: "The Header Tells", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-ch3-05489f17.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-ch3-fb82ab3d.jpg" },
      verdict: { title: "Packets Don't Lie", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-finale-d626f4fa.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/tcpip-deep-dive/wirelevel-finale-e1bfbe71.jpg" },
    },
  },
  stations: [
    {
      id: "handshake",
      label: "The Three-Way Handshake",
      topic: "TCP header and flags · the state machine · RST vs FIN",
      tagline: "A connection has a life story",
      building: "control",
      taskIds: ["tcpip-r1", "tcpip-r2", "tcpip-o1", "tcpip-q1"],
    },
    {
      id: "scans",
      label: "Scan Signatures",
      topic: "SYN, FIN, NULL, XMAS, ACK and full-connect scans",
      tagline: "Every scanner has handwriting",
      building: "lab",
      taskIds: ["tcpip-r3", "tcpip-m1", "tcpip-q2", "tcpip-q3"],
    },
    {
      id: "finger",
      label: "Fingerprints",
      topic: "Fragmentation, TTL and window size: the OS behind an IP",
      tagline: "The header tells on the sender",
      building: "office",
      taskIds: ["tcpip-r4", "tcpip-la2", "tcpip-f1"],
    },
    {
      id: "flows",
      label: "Flow or Packet",
      topic: "Flow records vs full capture · retransmissions · Wireshark",
      tagline: "Pick the right microscope",
      building: "vault",
      taskIds: ["tcpip-r5", "tcpip-r6", "tcpip-r7", "tcpip-la1", "tcpip-qf1"],
    },
    {
      id: "verdict",
      label: "RST Bursts",
      topic: "Repeated resets against a web farm",
      tagline: "Make the call",
      building: "ticket",
      taskIds: ["tcpip-ac1"],
      boss: true,
    },
  ],
  personas: {
    "tcpip-q1": { name: "Anneke Visser", role: "Principal Network Analyst", line: "SYN out, RST,ACK back, nothing more. What did that tell you?" },
    "tcpip-q2": { name: "Anneke Visser", role: "Principal Network Analyst", line: "Hundreds of RSTOS0 in conn.log. Decode it for me." },
    "tcpip-q3": { name: "Anneke Visser", role: "Principal Network Analyst", line: "A NULL scan against Windows. Why doesn't that trick work there?" },
    "tcpip-la2": { name: "Anneke Visser", role: "Principal Network Analyst", line: "This jump host's TTL just changed. Tell me what that means." },
    "tcpip-la1": { name: "Anneke Visser", role: "Principal Network Analyst", line: "A file server just got swept. Read the flow record." },
    "tcpip-ac1": { name: "Anneke Visser", role: "Principal Network Analyst", line: "Resets every 15 seconds across the farm. Attack, or something else?" },
  },
  briefings: {
    // ── Reading 1: signature mechanic, the state machine ──
    "tcpip-r1": [
      {
        kind: "pathway",
        title: "Walk the State Machine",
        prompt: "One customer web server's socket is up on Anneke's screen. Walk it through its whole life, from waiting for a client to fully closed, the way the kernel does.",
        goal: "Get the server's socket from LISTEN to CLOSED, the normal way",
        nodes: [
          { id: "listen", label: "LISTEN", sub: "waiting on 443", x: 12, y: 20 },
          { id: "rcvd", label: "SYN_RCVD", sub: "half open", x: 42, y: 14 },
          { id: "est", label: "ESTABLISHED", sub: "data flows", x: 72, y: 20 },
          { id: "closewait", label: "CLOSE_WAIT", sub: "peer is done", x: 86, y: 52 },
          { id: "lastack", label: "LAST_ACK", sub: "own FIN sent", x: 62, y: 82 },
          { id: "closed", label: "CLOSED", sub: "socket freed", x: 30, y: 82 },
          { id: "finwait", label: "FIN_WAIT_1", sub: "we closed first", x: 50, y: 50 },
          { id: "syn", label: "SYN_SENT", sub: "we dialled out", x: 14, y: 54 },
        ],
        edges: [["listen", "rcvd"], ["listen", "syn"], ["rcvd", "est"], ["est", "closewait"], ["est", "finwait"], ["closewait", "lastack"], ["lastack", "closed"], ["finwait", "closed"], ["syn", "closed"]],
        route: ["listen", "rcvd", "est", "closewait", "lastack", "closed"],
        notes: {
          listen: "The socket is bound to 443 and waiting. Nothing exists yet for any client.",
          rcvd: "A SYN arrived, the server answered and is holding half-open state. This is the memory a SYN flood tries to exhaust.",
          est: "The final ACK arrived. Only now does the application see a connection.",
          closewait: "The client's FIN arrived and was acknowledged. The server can still send; it just knows the client is done.",
          lastack: "The server sent its own FIN and waits for the very last acknowledgement.",
          closed: "Done. The side that closes second never has to linger. The side that closes first passes through TIME_WAIT: held for about two minutes, so a straggler from the old connection is dropped instead of landing in a new one on the same port pair.",
        },
        traps: {
          syn: "SYN_SENT is the client's state: it means this machine dialled out. A socket in LISTEN that starts sending SYNs isn't what happened here.",
          finwait: "FIN_WAIT_1 means this side closed first. Here the client finished first, so the server takes the other branch.",
        },
        lesson: "Each side of a connection walks its own path, and the state tells you who did what. A pile of SYN_RCVD and a pile of CLOSE_WAIT are two very different problems.",
      },
    ],
    // ── Reading 3: who is scanning ──
    "tcpip-r3": [
      {
        kind: "deduce",
        title: "Who's Probing Hall 2?",
        prompt: "A customer in Hall 2 reports odd traffic overnight. Anneke pulled five internal sources that touched the rack. One isn't what it claims. Strike suspects out as clues arrive.",
        nameColumn: "Source",
        columns: ["Role", "Flags it sent", "Handshakes finished", "Ports on one target"],
        suspects: [
          { id: "nessus", name: "10.8.0.40", cells: ["Approved vuln scanner", "SYN", "Some", "1,000+"] },
          { id: "mon", name: "10.8.0.12", cells: ["Monitoring poller", "SYN, ACK, FIN", "All", "2"] },
          { id: "bak", name: "10.8.1.7", cells: ["Backup server", "SYN, ACK, PSH, FIN", "All", "1"] },
          { id: "cust", name: "10.8.2.91", cells: ["Customer VM", "FIN, PSH, URG only", "None", "1,000+"] },
          { id: "dev", name: "10.8.2.60", cells: ["Customer VM", "SYN, ACK, PSH", "All", "3"] },
          { id: "lb", name: "10.8.0.5", cells: ["Load balancer", "SYN, ACK, RST", "All", "1"] },
        ],
        clues: [
          "The traffic touched a very wide range of ports on one target.",
          "Change control shows the approved scanner was off all night.",
          "Whoever it was never finished a single handshake, and never sent a SYN at all.",
        ],
        culprit: "cust",
        why: "10.8.2.91 sent segments no normal stack sends: no SYN, no handshake, odd flags, across a thousand ports. Real clients open connections; a tool crafting packets by hand doesn't need to. These NULL, FIN and XMAS probes rely on RFC 793: an open port stays silent and a closed port answers RST. Windows stacks answer them with RST whatever the port state, so against a Windows target the scan cannot tell open from closed and is unreliable.",
      },
    ],
    // ── Reading 4: the fingerprint panel ──
    "tcpip-r4": [
      {
        kind: "defuse",
        title: "Fingerprint Panel",
        prompt: "A customer's address is supposed to be one Linux box. Anneke suspects something else is answering. Read each header on the panel and cut the wire that fits, before the clock runs out.",
        device: "HALL-2 FINGERPRINT PANEL",
        seconds: 90,
        rounds: [
          {
            id: "ttl", state: "SYN arrives with TTL 118",
            wires: [{ id: "win", label: "Windows, 10 hops away" }, { id: "lin", label: "Linux, 54 hops away" }, { id: "net", label: "Network gear, 137 hops away" }],
            cut: "win", hint: "Round the TTL up to the nearest common start value.",
            why: "128 is the nearest start above 118, so about 10 hops. Nothing on the internet is 54 hops away from you, let alone 137.",
          },
          {
            id: "ttl2", state: "SYN arrives with TTL 249 from a border router",
            wires: [{ id: "win", label: "Windows, 121 hops away" }, { id: "lin", label: "Linux, already over its limit" }, { id: "net", label: "Network gear, 6 hops away" }],
            cut: "net", hint: "Which start value sits just above 249?",
            why: "255 is typical for routers and many network devices, so 6 hops. A Linux start of 64 could never arrive as 249.",
          },
          {
            id: "win", state: "SYN window 64240, TTL 62, options MSS, SACK, timestamp, wscale",
            wires: [{ id: "lin", label: "Modern Linux, 2 hops" }, { id: "win", label: "Windows, 66 hops" }, { id: "net", label: "Printer, 193 hops" }],
            cut: "lin", hint: "Start from the TTL, then check the window fits.",
            why: "TTL 62 rounds up to 64, and 64240 with timestamps fits a current Linux kernel. Windows starts at 128, and its SYNs usually leave timestamps off.",
          },
          {
            id: "frag", state: "Two fragments of one packet overlap, and the second rewrites bytes of the first",
            wires: [{ id: "mtu", label: "Normal path MTU fragmentation" }, { id: "evade", label: "Likely evasion: stacks reassemble overlaps differently" }, { id: "retr", label: "A TCP retransmission" }],
            cut: "evade", hint: "Would a router splitting a packet ever overlap the pieces?",
            why: "Routers split cleanly at offsets. Overlap means someone crafted it, hoping a sensor and the target rebuild different data.",
          },
        ],
        lesson: "Round the TTL up to 64, 128 or 255 to get the family and the hops, then check the window and options agree. When they don't agree, something between you and the claimed OS is answering.",
      },
    ],
    // ── Reading 5: flow or packet ──
    "tcpip-r5": [
      {
        kind: "rush",
        title: "Flow or Packet?",
        prompt: "Anneke keeps a year of flow records and three days of full capture. Tickets are stacking up. For each question, call whether a NetFlow record answers it or you need Zeek logs or the packets.",
        target: 10,
        seconds: 60,
        trueLabel: "NetFlow record",
        falseLabel: "Zeek logs or packets",
        cards: [
          { id: "f1", text: "How many bytes went to that IP last March?", answer: true, why: "Volume over a year: flows keep that long, capture doesn't." },
          { id: "p1", text: "What URL did the client request over plain HTTP?", answer: false, why: "A NetFlow record holds who and how much, never the payload. The URL is in Zeek http.log or in the packets." },
          { id: "f2", text: "Did these two hosts ever talk?", answer: true, why: "Addresses and ports are the core of a flow record." },
          { id: "p2", text: "What was in the DNS TXT answer?", answer: false, why: "Answer content lives in the payload: Zeek dns.log or the packets, never a NetFlow record." },
          { id: "f3", text: "Which host sent the most data this week?", answer: true, why: "A top-talkers question is what flows are for." },
          { id: "p3", text: "Which file did the SMB session copy?", answer: false, why: "The file name is inside the protocol, so you need the packets." },
          { id: "f4", text: "How long did that session last?", answer: true, why: "Start and duration are standard flow fields." },
          { id: "p4", text: "Which TLS cipher did the server choose?", answer: false, why: "That's inside the TLS handshake: Zeek ssl.log or the packets, not a basic NetFlow record." },
          { id: "f5", text: "Which ports did this server accept last month?", answer: true, why: "Destination ports over time are easy to count in flows." },
          { id: "p5", text: "Was this retransmitted segment identical to the first?", answer: false, why: "Comparing contents needs both packets." },
          { id: "f6", text: "Did traffic to this subnet spike at 02:00?", answer: true, why: "Volume over time is a flow question." },
          { id: "p6", text: "What exact command did the Telnet user type?", answer: false, why: "Keystrokes are payload." },
          { id: "f7", text: "Is this link's usage normal for a Tuesday?", answer: true, why: "Baselines come from long-term summaries." },
          { id: "p7", text: "Did the HTTP response carry a Set-Cookie header?", answer: false, why: "Headers are application data." },
        ],
        lesson: "Flows answer who, when and how much, for a long time back. Packets answer exactly what, for a short time back. Start with flows, then pull packets for the few minutes that matter.",
      },
    ],
    // ── Reading 7: read a real capture ──
    "tcpip-r7": [
      {
        kind: "pcap",
        title: "Why Won't It Connect?",
        prompt: "A customer's app can't reach its licence server, and they blame Kelvin Point. Anneke captured it at the rack. Read the capture and find out where the packets stop.",
        capture: "hall2_rack14_licence.pcapng",
        packets: [
          { no: 1, time: "0.000000", src: "10.8.3.22", dst: "198.51.100.61", proto: "TCP", len: 66, info: "50412 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460",
            tree: ["Internet Protocol Version 4, Src: 10.8.3.22, Dst: 198.51.100.61", "    Time to Live: 64", "Transmission Control Protocol, Src Port: 50412, Dst Port: 8443", "    Flags: 0x002 (SYN)"] },
          { no: 2, time: "1.003118", src: "10.8.3.22", dst: "198.51.100.61", proto: "TCP", len: 66, info: "[TCP Retransmission] 50412 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460",
            tree: ["Transmission Control Protocol, Src Port: 50412, Dst Port: 8443", "    Flags: 0x002 (SYN)", "    [This frame is a (suspected) retransmission]"] },
          { no: 3, time: "3.011402", src: "10.8.3.22", dst: "198.51.100.61", proto: "TCP", len: 66, info: "[TCP Retransmission] 50412 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460",
            tree: ["Transmission Control Protocol, Src Port: 50412, Dst Port: 8443", "    Flags: 0x002 (SYN)", "    [This frame is a (suspected) retransmission]"] },
          { no: 4, time: "7.027760", src: "10.8.3.22", dst: "198.51.100.61", proto: "TCP", len: 66, info: "[TCP Retransmission] 50412 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460",
            tree: ["Transmission Control Protocol, Src Port: 50412, Dst Port: 8443", "    Flags: 0x002 (SYN)", "    [This frame is a (suspected) retransmission]"] },
          { no: 5, time: "7.204511", src: "10.8.3.22", dst: "10.8.3.1", proto: "DNS", len: 78, info: "Standard query 0x41c2 A licence.vendor.example",
            tree: ["User Datagram Protocol, Src Port: 53810, Dst Port: 53", "Domain Name System (query)", "    Queries: licence.vendor.example: type A, class IN"] },
          { no: 6, time: "7.219034", src: "10.8.3.1", dst: "10.8.3.22", proto: "DNS", len: 94, info: "Standard query response 0x41c2 A licence.vendor.example A 198.51.100.61",
            tree: ["Domain Name System (response)", "    Answers: licence.vendor.example: type A, class IN, addr 198.51.100.61"] },
        ],
        objectives: [
          { id: "n", task: "How many SYN packets did the client send to port 8443 in total?", hint: "tcp", answer: ["4"], why: "One original and three retransmissions." },
          { id: "back", task: "How many packets came back from 198.51.100.61?", hint: "ip.addr==198.51.100.61", answer: ["0"], why: "Silence. Nothing refused it; the SYNs simply vanished somewhere past the rack." },
          { id: "filter", task: "You want only the DNS frames on screen, but must keep every other frame in the file. Capture filter or display filter?", hint: "A capture filter (BPF, like tcp port 445) throws packets away while recording; a display filter (like dns) only hides rows.", answer: ["display", "display filter"], why: "A display filter only hides rows of a capture that already exists, so you can change it freely. A capture filter discards non-matching packets at capture time and they can never be recovered from that file." },
          { id: "gap", task: "Frames 3 and 4 are both retries. How many seconds apart are they, rounded?", hint: "Subtract the time of frame 3 from frame 4.", answer: ["4"], why: "1, 2, then 4 seconds: the kernel doubles its wait. That doubling is how you tell a TCP stack retrying from a tool on a timer." },
        ],
      },
    ],
  },
};
