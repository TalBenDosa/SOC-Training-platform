import type { RoomExperience } from "./types";

// "Operation Generations" for the "firewall-masterclass" room.
// Script: docs/campaign/48-firewall-masterclass.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Greyfield University (fictional), not the graded tasks' NexaCorp WS-DEV-09.
// Signature mechanic: reactor conveyor (route each threat to the firewall
// generation that first catches it).
// Lab data differs from the graded tasks: no ACL syntax, wildcards or port
// direction (q1, r2 checkpoint); the stateful items never cover unsolicited
// inbound replies (q2); no encrypted C2 or certificate pinning (r4, r8
// checkpoints); no rule order or shadowing (r6 checkpoint); no NAT lookups,
// byte fields, beacon timing or totals (r10 checkpoint, q3, la1, f1).
export const FIREWALL_MASTERCLASS: RoomExperience = {
  roomId: "firewall-masterclass",
  codename: "Operation Generations",
  theme: "ngfw",
  handler: { name: "Gideon Achterberg", role: "Network Security Architect, Greyfield University" },
  briefing: [
    "Greyfield University. 31,000 students, a research cluster, an exam database, and a campus network that grew one building at a time since 1991.",
    "Its edge has four generations of firewall living side by side: an old router ACL, a stateful pair, and two NGFWs bought last year.",
    "Gideon Achterberg is retiring the old walls this term. To do it safely the SOC has to know what each generation can see, and what it can't.",
    "Walk forty years of firewalls, read a live state table, catch threats at the right wall, place systems in zones, read a decryption log, then work a graded C2 case.",
  ],
  mission: "Put forty years of firewalls in order, read the stateful pair's connection table, route threats to the wall that catches them, place campus systems in zones, read a decryption log, then work the graded C2 beacon.",
  estimate: "~55 min",
  look: { primary: "#f97316", secondary: "#22d3ee", warn: "#e11d48" },
  scene: "generations",
  layout: "stage",
  stations: [
    {
      id: "firstwall",
      label: "The First Wall",
      topic: "What a firewall is for · Gen 1 stateless packet filters and ACLs",
      tagline: "Forty years in one corridor",
      building: "control",
      taskIds: ["fw-r1", "fw-r2", "fw-q1"],
    },
    {
      id: "state",
      label: "The State Table",
      topic: "Gen 2 stateful inspection and connection tracking",
      tagline: "A wall with a memory",
      building: "lab",
      taskIds: ["fw-r3", "fw-q2"],
    },
    {
      id: "inside",
      label: "Inside the Packet",
      topic: "Gen 3 DPI and application awareness · what NGFW actually means",
      tagline: "Which wall catches it?",
      building: "office",
      taskIds: ["fw-r4", "fw-r5"],
    },
    {
      id: "zones",
      label: "Zones and Keys",
      topic: "Rule bases · zones and DMZ · SSL/TLS inspection · the three big vendors",
      tagline: "Where things live, what gets opened",
      building: "vault",
      taskIds: ["fw-r6", "fw-r7", "fw-r8", "fw-r9"],
    },
    {
      id: "beacon",
      label: "The Beacon",
      topic: "Reading firewall logs in the SIEM · a C2 beacon",
      tagline: "Work the graded case",
      building: "ticket",
      taskIds: ["fw-r10", "fw-q3", "fw-la1", "fw-f1"],
      boss: true,
    },
  ],
  personas: {
    "fw-q1": { name: "Gideon Achterberg", role: "Network Security Architect", line: "One Cisco line, four packets. Which one does it match?" },
    "fw-q2": { name: "Gideon Achterberg", role: "Network Security Architect", line: "We swapped the high-port ACL for a stateful pair. What did we actually gain?" },
    "fw-q3": { name: "Gideon Achterberg", role: "Network Security Architect", line: "Every 300 seconds, three days, nobody logged on. Tell me what it is." },
    "fw-la1": { name: "Gideon Achterberg", role: "Network Security Architect", line: "Fifteen sessions, same bytes, a Tor exit. Read the FortiGate log." },
    "fw-f1": { name: "Gideon Achterberg", role: "Network Security Architect", line: "Scope it. How much did the workstation send?" },
  },
  briefings: {
    // ── Reading 1: history ──
    "fw-r1": [
      {
        kind: "sequence",
        title: "Forty Years of Walls",
        prompt: "Greyfield's edge still runs pieces of every era. Tap the milestones in the order they happened, oldest first.",
        items: [
          { id: "ngfw", text: "A firewall that names the application, not just the port, ships as 'next-generation'", note: "Late 2000s" },
          { id: "pf", text: "Routers start dropping packets by address and port: the first packet filters", note: "Late 1980s" },
          { id: "utm", text: "Firewall, antivirus, IPS and web filter get bundled into one 'UTM' box", note: "Mid 2000s" },
          { id: "state", text: "Commercial firewalls start remembering connections in a state table", note: "Early 1990s" },
          { id: "tls", text: "Most web traffic is now encrypted, so firewalls add TLS decryption to keep seeing inside", note: "2010s" },
        ],
        order: ["pf", "state", "utm", "ngfw", "tls"],
        doneNote: "Each generation was added because the one before it went blind to something. Greyfield still has one of each.",
      },
    ],
    // ── Reading 3: the state table ──
    "fw-r3": [
      {
        kind: "terminal",
        title: "Read the State Table",
        prompt: "Greyfield's stateful pair is a Linux box. Its connection table is the 'memory' of Gen 2. Read it the way an analyst would.",
        shell: "bash",
        host: "gideon@gfu-edge-fw2:~$",
        commands: [
          { match: "(sudo\\s+)?conntrack\\s+-L\\s+-d\\s+10\\.30\\.9\\.20.*", help: "sudo conntrack -L -d 10.30.9.20   every tracked session to the exam database",
            output: "tcp      6 431820 ESTABLISHED src=10.30.4.12 dst=10.30.9.20 sport=51122 dport=5432 src=10.30.9.20 dst=10.30.4.12 sport=5432 dport=51122 [ASSURED] mark=0 use=1\ntcp      6 431604 ESTABLISHED src=10.30.4.19 dst=10.30.9.20 sport=49870 dport=5432 src=10.30.9.20 dst=10.30.4.19 sport=5432 dport=49870 [ASSURED] mark=0 use=1\ntcp      6 92 TIME_WAIT src=10.30.4.12 dst=10.30.9.20 sport=51090 dport=5432 src=10.30.9.20 dst=10.30.4.12 sport=5432 dport=51090 [ASSURED] mark=0 use=1\ntcp      6 431977 ESTABLISHED src=10.30.6.40 dst=10.30.9.20 sport=60311 dport=5432 src=10.30.9.20 dst=10.30.6.40 sport=5432 dport=60311 [ASSURED] mark=0 use=1\ntcp      6 117 SYN_SENT src=10.30.4.77 dst=10.30.9.20 sport=58004 dport=5432 [UNREPLIED] src=10.30.9.20 dst=10.30.4.77 sport=5432 dport=58004 mark=0 use=1\nconntrack v1.4.7 (conntrack-tools): 5 flow entries have been shown." },
          { match: "(sudo\\s+)?sysctl\\s+net\\.netfilter\\.nf_conntrack_tcp_timeout_established.*", help: "sysctl net.netfilter.nf_conntrack_tcp_timeout_established   how long an idle session is remembered",
            output: "net.netfilter.nf_conntrack_tcp_timeout_established = 432000" },
          { match: "(sudo\\s+)?conntrack\\s+-C.*", help: "sudo conntrack -C   how many sessions the table holds right now",
            output: "18342" },
        ],
        objectives: [
          { id: "est", task: "How many ESTABLISHED sessions does the exam database have right now?", hint: "sudo conntrack -L -d 10.30.9.20", answer: ["3"], why: "Three ESTABLISHED rows. TIME_WAIT is a session that just closed; SYN_SENT has not been answered yet." },
          { id: "syn", task: "Which internal host's session is still waiting for the database to answer?", hint: "Look for [UNREPLIED].", answer: ["10.30.4.77"], why: "SYN_SENT plus [UNREPLIED]: the host asked, the database hasn't replied. Worth a look if it sits there or repeats." },
          { id: "ttl", task: "For how many seconds is an idle ESTABLISHED session remembered?", hint: "sysctl net.netfilter.nf_conntrack_tcp_timeout_established", answer: ["432000"], why: "432,000 seconds is five days. The third column of each row counts down from it." },
        ],
      },
    ],
    // ── Reading 5: signature mechanic, reactor conveyor ──
    "fw-r5": [
      {
        kind: "reactor",
        title: "Which Wall Catches It?",
        prompt: "Seven threats ride the belt toward the campus. Route each into the oldest firewall generation that could stop it on its own.",
        reactors: [
          { id: "filter", label: "PACKET FILTER", sub: "addresses and ports" },
          { id: "stateful", label: "STATEFUL", sub: "remembers each session" },
          { id: "ngfw", label: "NGFW", sub: "apps, users, content" },
        ],
        items: [
          { id: "telnet", text: "Telnet from the internet to a lab server's TCP port 23", reactor: "filter", why: "A port and a direction are enough. Any generation stops it; the oldest one already can." },
          { id: "range", text: "Anything from an address range on the university's block list", reactor: "filter", why: "Source address alone decides it." },
          { id: "rst", text: "A forged reset with a sequence number far outside the live session, trying to cut a lecture stream", reactor: "stateful", why: "Only a wall that tracks the session's sequence window knows this reset doesn't belong." },
          { id: "ftp", text: "An FTP data channel on a random high port that the control session just negotiated", reactor: "stateful", why: "A stateful helper reads the control session and opens just that one related port, for just that session." },
          { id: "torrent", text: "BitTorrent running over port 80 to slip past a 'web only' rule", reactor: "ngfw", why: "Port 80 looks like web to the older walls. App identification sees the protocol for what it is." },
          { id: "user", text: "Only payroll staff, not their machines, may reach the payroll app", reactor: "ngfw", why: "Rules by user identity are an NGFW feature; older walls only know addresses." },
          { id: "exploit", text: "A known exploit string inside a plain HTTP request to the library catalogue", reactor: "ngfw", why: "Matching content inside the payload is deep packet inspection." },
        ],
      },
    ],
    // ── Reading 7: zones ──
    "fw-r7": [
      {
        kind: "match",
        title: "Place the Campus",
        prompt: "Gideon is redrawing Greyfield's zones. Match each system to the zone it belongs in.",
        pairs: [
          { id: "web", left: "The public admissions website", right: "DMZ", why: "Reachable from the internet, so it sits between the internet and everything you care about." },
          { id: "wifi", left: "The free student Wi-Fi", right: "Guest zone (internet only)", why: "Unknown devices: they get the internet and nothing inside." },
          { id: "exam", left: "The exam results database", right: "Restricted data zone", why: "Your crown jewels get their own zone and the shortest allow list." },
          { id: "mgmt", left: "Switch and firewall admin interfaces", right: "Management network", why: "Whoever reaches these owns the network; keep them off every user zone." },
          { id: "lab", left: "Staff office PCs", right: "Internal trusted LAN", why: "Managed devices doing everyday work, still filtered on the way to restricted zones." },
        ],
      },
    ],
    // ── Reading 8: a decryption log ──
    "fw-r8": [
      {
        kind: "anatomy",
        title: "Read a Decryption Log",
        prompt: "Greyfield's PAN-OS NGFW decrypts student web traffic. Scan each field of one decryption log entry.",
        source: "Palo Alto Networks PAN-OS · Monitor > Logs > Decryption",
        fields: [
          { key: "Policy Name", value: "Decrypt-Students-Web", note: "The decryption policy that matched, separate from the security rule that allowed the session." },
          { key: "Proxy Type", value: "Forward", note: "Forward proxy: outbound traffic to sites on the internet. Inbound inspection protects your own servers." },
          { key: "Server Name Indication", value: "journals.publisher.example", note: "The site name the client asked for in the handshake." },
          { key: "TLS Version", value: "TLS1.3" },
          { key: "Key Exchange Algorithm", value: "ECDHE", note: "Forward secrecy: why the firewall has to sit in the middle rather than decrypt a copy later." },
          { key: "Subject Common Name", value: "journals.publisher.example" },
          { key: "Issuer Common Name", value: "Example Public CA G2", note: "The real server certificate's issuer, checked by the firewall. The student's browser instead sees a copy signed by Greyfield's Forward Trust CA." },
          { key: "Chain Status", value: "Trusted", note: "The firewall validated the server's real chain. If it were untrusted, the browser should get Forward Untrust and a warning." },
          { key: "Error Index", value: "None" },
        ],
        summary: "Two TLS sessions, one in the middle: the firewall checked the real site's certificate, then re-signed it with a CA every campus laptop trusts, so it could see inside.",
      },
    ],
  },
};
