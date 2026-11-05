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
        doneNote: "Each generation was added because the one before it went blind to something. Greyfield still has one of each. The oldest wall is read left to right: in the Cisco line permit udp 10.1.0.0 0.0.255.255 any eq 53 the order is action, protocol, source address with its wildcard mask, destination, then the operator and port. The eq 53 after the destination is the destination port; a port written right after the source would be the source port.",
      },
    ],
    // ── Reading 3: the state table ──
    "fw-r3": [
      {
        kind: "duel",
        title: "Beat the State Table",
        prompt: "Gideon's stateful pair keeps a conntrack table, the memory of Gen 2. An intruder tries five ways to abuse that memory or to slip past the walls around it. Play the control that answers each move.",
        attacker: "A probing intruder",
        moves: [
          { id: "spoof", move: "Spoofed campus source", detail: "Packets arrive on the internet-facing interface with source 10.30.4.12, an address inside the campus range, hoping the inside rules trust them.", counter: "antispoof", hint: "An address that cannot legitimately arrive from outside.", why: "A source from the internal range arriving on the outside interface is forged by definition. An ingress anti-spoofing rule drops it before any session is created." },
          { id: "flood", move: "Half-open flood on the exam database", detail: "conntrack -C climbs past 18,000 and most new rows read SYN_SENT with [UNREPLIED] for 10.30.9.20 port 5432.", counter: "synlimit", hint: "The attack lives in the unanswered rows, not in any one packet.", why: "Every half-open session takes a table slot until it times out. SYN cookies and a half-open limit per source answer without storing state until the handshake finishes. A bigger table only delays the failure." },
          { id: "frag", move: "Fragmented exploit", detail: "A known exploit string is split across IP fragments so no single fragment holds the whole signature.", counter: "dpi", hint: "Something has to put the pieces together before it reads them.", why: "Matching content needs the reassembled payload. Gen 3 inspection reassembles fragments and streams first, then matches the signature; port and state rules never look inside." },
          { id: "hop", move: "Port-hopping file sharing", detail: "A student client opens each connection to a different high port, so no port-based allow or deny rule ever matches twice.", counter: "appid", hint: "Stop reading the port number.", why: "Application identification names the traffic by its behaviour, whatever port it uses. Port-based rules see a new port each time and lose the thread." },
          { id: "stale", move: "Riding a stale session", detail: "A row for a student who left shows ESTABLISHED with 431,000 seconds still on its timer. The default idle timeout is 432000, five days.", counter: "idle", hint: "How long should the table remember an idle session nobody is using?", why: "ESTABLISHED rows are remembered for 432,000 seconds by default, so an old session stays open to anything that can reuse its tuple. A much shorter idle timeout for such flows removes the stale entries." },
        ],
        cards: [
          { id: "antispoof", name: "Anti-spoofing ingress rule", effect: "Drops outside-interface packets whose source is a campus range." },
          { id: "synlimit", name: "SYN cookies and half-open limit", effect: "Answers the handshake without holding a table slot until it completes." },
          { id: "dpi", name: "Reassembly and deep inspection", effect: "Rebuilds fragments and streams, then matches the payload." },
          { id: "appid", name: "Application identification", effect: "Names the application from its behaviour, whatever the port." },
          { id: "idle", name: "Shorter idle timeout", effect: "Expires quiet sessions long before five days." },
          { id: "bigtable", name: "Bigger state table", effect: "Adds more slots for tracked sessions." },
          { id: "decrypt", name: "TLS decryption policy", effect: "Opens encrypted sessions so the NGFW can read inside." },
        ],
        lesson: "A stateful wall remembers sessions, and that memory is also its weak spot: unanswered rows pile up, stale rows linger, and the table can say nothing about what a payload contains.",
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
        kind: "intercept",
        title: "Zone Gate",
        prompt: "Gideon is redrawing Greyfield's zones: guest Wi-Fi, DMZ, internal LAN, restricted data and management. Flows arrive at the new NGFW with their zones and App-ID. Block what the zone design forbids, allow what it permits.",
        protect: "the exam results zone",
        blockLabel: "Block",
        passLabel: "Allow",
        seconds: 11,
        items: [
          { id: "wifidb", text: "Student Wi-Fi to the exam database", sub: "guest zone to restricted zone, postgresql 5432", bad: true, why: "Guest Wi-Fi is unknown devices: internet and nothing inside. The restricted zone has the shortest allow list on campus." },
          { id: "dmzdb", text: "Admissions website to the exam database", sub: "DMZ to restricted zone, postgresql 5432", bad: true, why: "The DMZ is reachable from the internet, so it is the likeliest to fall. It may call its own back end, but never the crown jewels directly." },
          { id: "pcsw", text: "Staff PC to a core switch admin page", sub: "internal LAN to management network, ssh and https", bad: true, why: "Whoever reaches switch and firewall admin interfaces owns the network. Management is reached from a jump host, not from every office PC." },
          { id: "torrent", text: "Peer-to-peer client on tcp/443", sub: "guest zone to internet, App-ID bittorrent", bad: true, why: "Port 443 looks like web to a port-based wall. App-ID names it bittorrent, which the policy for guest Wi-Fi does not allow." },
          { id: "tunnel", text: "Interactive shell inside tcp/443", sub: "internal LAN to internet, App-ID ssh", bad: true, why: "The port says web, the App-ID says ssh. A shell tunnelled through an allowed port is the evasion an NGFW exists to see." },
          { id: "regdb", text: "Registrar application server to the exam database", sub: "internal LAN to restricted zone, postgresql 5432", bad: false, why: "The approved path: one named server, one service. The restricted zone's short allow list exists for exactly this." },
          { id: "jump", text: "Admin jump host to a core switch", sub: "management network, ssh", bad: false, why: "Inside the management network, from the one approved admin host, with the right application. Looks like the dangerous switch access above, but the source zone makes it legitimate." },
          { id: "journal", text: "Student Wi-Fi to a publisher site", sub: "guest zone to internet, App-ID ssl, decrypted", bad: false, why: "Guests get the internet. Decryption means the firewall read the session, and a normal web session is what guest policy allows." },
          { id: "staffweb", text: "Staff PC to the admissions website", sub: "internal LAN to DMZ, web-browsing 443", bad: false, why: "The internal zone is more trusted than the DMZ and reaches it on the published service. The reverse would be the problem." },
          { id: "stream", text: "Lecture stream on udp/3478", sub: "internal LAN to internet, App-ID web conferencing", bad: false, why: "An unusual port, but App-ID shows a sanctioned conferencing app. Judging by port alone is the old-generation mistake." },
        ],
        lesson: "Zone first, application second, port last: the same flow can be fine from one zone and forbidden from another, and the port number alone proves nothing.",
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
