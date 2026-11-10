import type { BriefingLab, RoomExperience } from "./types";

// "Operation Deep Query" for the "dns-deep-dive" room.
// Script: docs/campaign/74-dns-deep-dive.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// NEW TASK ORDER (the room's own order keeps all six readings first, so it cannot be staged):
// dns-r1, dns-o1, dns-r2 | dns-r3, dns-q1, dns-r6, dns-la1, dns-qf1 |
// dns-r4, dns-q2, dns-la2, dns-q3, dns-f1 | dns-r5, dns-m1 | dns-ac1
// r6 sits before la1 because la1 reads Sysmon Event 22 fields; q3 follows la2 because it asks about
// la2's host; qf1 follows la1 because it says so; m1 needs all the signals; ac1 is the boss.
//
// Cinderhill Observatory (fictional research site), not the graded tasks' solvix records.
// Signature: Read the Query, a capture where record types and response codes tell the night's
// story, and Three Dials, a tune lab on query length, entropy and volume against CDN and telemetry.
// Game mix: defuse + pathway + rush + tune.
// Lab data differs from the graded tasks: the laptop in the walk asks a CDN name through
// ch-res01, never the "whose log" question (r1 checkpoint); the walk is a map of hops, not the
// eight worded steps (o1); the tunnel is NULL queries carrying base32 FITS data under
// pm.plate-mirror.example from ch-sci-wk04 (600 queries, 594 unique), never hex labels in TXT, 214
// queries or WKS-FIN07 (q1, la1, r3 checkpoint); the rule drill is NULL over 20m, above 400
// unique, above 0.6, outside every graded blank (qf1); the missing Event 22 is NULL from
// platesync.exe, never TXT (r6 checkpoint); the burst is ch-dome-ctl2, 180 names and 171 NXDOMAIN
// over 12 minutes, never 340 and 318 or 300 at 96% (q2, la2, f1); the entropy cap uses 16 and 4
// characters, never 8 (la2); the verdict drill is DoT on a Linux bench PC, a misfire on the site's
// own endpoint and two real intrusions, never a browser session to a public DoH address (ac1).

type Packet = Extract<BriefingLab, { kind: "pcap" }>["packets"][number];

const RES = "10.60.0.53";
const PARENT = "pm.plate-mirror.example";
// Real base32 of a FITS header, 32 bytes a label: "SIMPLE  =   ...   T /" and what follows it.
const CHUNK1 = "kneu2ucmiuqcapjaeaqcaibaeaqcaibaeaqcaibaeaqcaicueaxq";
const CHUNK2 = "ebrw63tgn5zg24zaorxsarsjkrjsa43umfxgiylsmqqcaibaeaqa";

function pkt(no: number, time: string, src: string, dst: string, len: number, info: string, ports: [number, number], lines: string[], data?: string): Packet {
  return {
    no, time, src, dst, proto: "DNS", len, info,
    tree: [`Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, `User Datagram Protocol, Src Port: ${ports[0]}, Dst Port: ${ports[1]}`, ...lines],
    ...(data ? { data } : {}),
  };
}
const asked = (id: string, flags: string, q: string, extra: string[] = []) => ["Domain Name System (query)", `Transaction ID: ${id}`, flags, `Queries: ${q}`, ...extra];
const RD = "Flags: 0x0100 Standard query, Recursion desired";
const NO_RD = "Flags: 0x0000 Standard query, Do not query recursively";
const OK = "Reply code: No error (0)";

export const DNS_DEEP_DIVE: RoomExperience = {
  roomId: "dns-deep-dive",
  codename: "Operation Deep Query",
  theme: "deepquery",
  handler: { name: "Oskar Bello", role: "Network Forensics Lead, Cinderhill Observatory" },
  briefing: [
    "Cinderhill Observatory. One ridge, one thin link down the mountain, and a sky survey under embargo for twelve more days.",
    "The site closes almost everything outbound. One door stays open, because nothing works without names.",
    "Tonight the resolver's link is busier than the telescopes explain, and Oskar Bello wants to know who keeps asking questions.",
    "Walk the path, read the packets, tune the rule, and find out what is leaving in the queries.",
  ],
  mission: "Walk one lookup hop by hop, read a capture by record type and response code, tune a rule on length, entropy and volume, trace a packet to its process, split generated names from CDN names, turn a live domain into a tripwire, then call the last alert of the night.",
  estimate: "~70 min",
  look: { primary: "#8ecae6", secondary: "#ffb703", warn: "#e63946" },
  scene: "facilitydeepquery",
  layout: "facility",
  story: {
    intro: { title: "One Door Open", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-intro-3f156f05.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-intro-f163d5b6.jpg" },
    afterStation: {
      tunnel: { title: "Nineteen Minutes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-ch2-77b577b6.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-ch2-eac8d702.jpg" },
      flux: { title: "Someone Knocked", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-ch3-59905f11.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-ch3-61b9b826.jpg" },
      port443: { title: "First Light", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-finale-5690c97d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/dns-deep-dive/deepquery-finale-7b41b79f.jpg" },
    },
  },
  stations: [
    {
      id: "path",
      label: "The Resolution Path",
      topic: "Stub, recursive and iterative lookups · caching and TTL · record types · DoH and DoT blind spots",
      tagline: "Who keeps asking?",
      building: "control",
      taskIds: ["dns-r1", "dns-o1", "dns-r2"],
    },
    {
      id: "tunnel",
      label: "Inside the Tunnel",
      topic: "How data rides in queries · entropy, length, volume, uniqueness · Sysmon Event 22 and Zeek dns.log",
      tagline: "The name is the message",
      building: "lab",
      taskIds: ["dns-r3", "dns-q1", "dns-r6", "dns-la1", "dns-qf1"],
    },
    {
      id: "generated",
      label: "Generated Names",
      topic: "DGA against CDN randomness · NXDOMAIN rate · domain age · entropy limits",
      tagline: "Block one door, it tries a thousand",
      building: "archive",
      taskIds: ["dns-r4", "dns-q2", "dns-la2", "dns-q3", "dns-f1"],
    },
    {
      id: "flux",
      label: "Flux and Sinkholes",
      topic: "Fast flux and double flux · sinkholing · every signal side by side",
      tagline: "Turn their door into your tripwire",
      building: "vault",
      taskIds: ["dns-r5", "dns-m1"],
    },
    {
      id: "port443",
      label: "Port 443",
      topic: "Weighing a resolver bypass into one verdict",
      tagline: "The last alert of the night",
      building: "ticket",
      taskIds: ["dns-ac1"],
      boss: true,
    },
  ],
  personas: {
    "dns-o1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Put the lookup in the order the packets would." },
    "dns-q1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "One more number before anyone calls this. Which one do you want?" },
    "dns-la1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Read the record and tell me what you're looking at." },
    "dns-qf1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Write it so it still works while I'm asleep." },
    "dns-q2": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Two hosts, two bursts. Talk me through them." },
    "dns-la2": { name: "Oskar Bello", role: "Network Forensics Lead", line: "The resolver flagged this one. What do you make of it?" },
    "dns-q3": { name: "Oskar Bello", role: "Network Forensics Lead", line: "We have the address. What do we pull next?" },
    "dns-f1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Just the number." },
    "dns-m1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Six signals. Tell me what each one means." },
    "dns-ac1": { name: "Oskar Bello", role: "Network Forensics Lead", line: "Last alert of the night. Your call." },
  },
  briefings: {
    // ── Reading 1: the path ──
    "dns-r1": [
      {
        kind: "pathway",
        title: "Follow One Lookup, Hop by Hop",
        prompt: "ch-sci-lt07, a laptop in the Science wing, needs plates.skyportal.example and nothing is cached anywhere on the mountain. Walk the lookup from the laptop to the answer, one hop at a time. Each wrong hop tells you why that server won't take the question.",
        goal: "Carry one lookup there and back",
        nodes: [
          { id: "stub", label: "ch-sci-lt07", sub: "stub resolver", x: 9, y: 80 },
          { id: "public", label: "Public resolver", sub: "198.51.100.53", x: 9, y: 24 },
          { id: "res1", label: "ch-res01", sub: "cache: miss", x: 27, y: 80 },
          { id: "root", label: "Root server", sub: "the top of the tree", x: 30, y: 20 },
          { id: "res2", label: "ch-res01", sub: "holds a referral", x: 46, y: 80 },
          { id: "tld", label: "TLD server", sub: ".example", x: 52, y: 20 },
          { id: "res3", label: "ch-res01", sub: "holds a referral", x: 65, y: 80 },
          { id: "auth", label: "Authoritative server", sub: "ns1.skyportal.example", x: 74, y: 20 },
          { id: "res4", label: "ch-res01", sub: "holds the answer", x: 83, y: 62 },
          { id: "done", label: "ch-sci-lt07", sub: "stub cache", x: 91, y: 88 },
        ],
        edges: [
          ["stub", "res1"], ["stub", "root"], ["stub", "public"],
          ["res1", "root"], ["res1", "tld"], ["res1", "auth"],
          ["root", "res2"], ["root", "tld"],
          ["res2", "tld"], ["res2", "auth"],
          ["tld", "res3"], ["tld", "auth"],
          ["res3", "auth"],
          ["auth", "res4"], ["auth", "done"],
          ["res4", "done"],
        ],
        route: ["stub", "res1", "root", "res2", "tld", "res3", "auth", "res4", "done"],
        notes: {
          stub: "The laptop's stub resolver looks in its own small cache: nothing. A stub can't walk the DNS tree. All it knows is which resolver to ask.",
          res1: "The question reaches ch-res01, the site's recursive resolver. Its cache is empty for this name too, so it takes the job on and the laptop just waits.",
          root: "The root server doesn't hold the record. It sends a referral: here are the NS (nameserver) records for the TLD, the top-level domain.",
          res2: "The referral comes back to ch-res01, not to the laptop. That's what iterative means: the resolver makes each next query itself.",
          tld: "The TLD server doesn't hold the record either. It refers ch-res01 to the domain's authoritative nameservers.",
          res3: "Second referral, same shape. ch-res01 picks one of the named servers and asks it directly.",
          auth: "This server holds the record, so this is a real answer, and it carries a TTL (Time To Live): how many seconds anyone may reuse it.",
          res4: "ch-res01 keeps the answer until the TTL runs out and passes it on. Anyone on site asking in that window gets the cached copy, and no packet goes up the mountain.",
          done: "The stub caches the answer as well, and the application finally gets an address. Three outside servers worked, and the laptop only ever spoke to one machine.",
        },
        traps: {
          public: "Nothing on this laptop is configured to use a public resolver. A stub asks the resolver DHCP gave it.",
          root: "A stub doesn't talk to the root. It has one job, asking its configured resolver, and walking the tree isn't part of it.",
          tld: "Not yet, and not that way. Only the root's referral gives the TLD server's address, and the root hands that back to whoever asked it. It doesn't forward questions.",
          auth: "Nobody here can reach it yet. Its address comes from the TLD's referral, and that goes back to the resolver: these servers never pass a question along themselves.",
          done: "An authoritative server answers whoever asked it, and that was ch-res01. It has never heard of the laptop.",
        },
        lesson: "The stub asks one question of one server. The recursive resolver does all the walking, one referral at a time, so each outside server sees only its own step. Answers are cached on the resolver and again on the client for the length of the TTL. A short TTL lets an operator change an answer fast, which suits load balancing and failover. A long TTL means a bad answer can keep being served from caches after the real record is fixed.",
      },
      {
        kind: "sort",
        title: "Logged at the Resolver, or Lost?",
        prompt: "Oskar's whole plan rests on one assumption: every name on the mountain passes through ch-res01. Sort these lookups by whether a line ever reaches that resolver's query log.",
        buckets: [
          { id: "logged", label: "In ch-res01's log" },
          { id: "lost", label: "Never reaches it" },
        ],
        items: [
          { id: "l1", text: "A laptop on the site network asks for a name for the first time today", bucket: "logged", why: "DHCP hands every client ch-res01, so this is the path the whole plan depends on." },
          { id: "l2", text: "A second laptop asks for that name a minute later, inside the TTL", bucket: "logged", why: "The answer comes from cache, but the client still asked ch-res01, so the query is logged. Only the upstream walk is skipped." },
          { id: "l3", text: "The same laptop opens that site again a minute later, inside the TTL", bucket: "lost", why: "Its own stub cache answers. No packet leaves the laptop, so a resolver log undercounts repeats by design." },
          { id: "l4", text: "A weather mast camera with 198.51.100.53 hard-coded in its firmware", bucket: "lost", why: "A device with a hard-coded resolver ignores DHCP. The fix is at the firewall: only ch-res01 may send port 53 out." },
          { id: "l5", text: "An application that finds its server in the local hosts file", bucket: "lost", why: "The hosts file is checked on the machine itself. No DNS query exists at all." },
          { id: "l6", text: "A browser sending its lookups to a public provider over HTTPS", bucket: "lost", why: "The lookups leave as web traffic to a third party. ch-res01 never hears about them." },
          { id: "l7", text: "A failed lookup for a mistyped internal name", bucket: "logged", why: "A failure is still a query. Failures are often the most interesting lines in the log." },
          { id: "l8", text: "A workstation's tool sending its own UDP packets to ch-res01 on port 53", bucket: "logged", why: "The resolver answers whoever asks, however the packet was built. It logs the query and the client address, though not the program behind it." },
        ],
      },
    ],
    // ── Reading 2: record types, DoH, DoT ──
    "dns-r2": [
      {
        kind: "pcap",
        title: "Read the Query",
        prompt: "Monday 22:14. The link down the mountain is busier than the telescopes explain, so Oskar captured this at the core switch. Filter, pick a packet, and read its layers. The record type says what was asked, the response code says how it ended, and together they tell the night's story. Upstream traffic is trimmed to the lookups that matter.",
        capture: "ch-core-span_mon2214.pcapng",
        packets: [
          pkt(1, "0.000000", "10.60.12.27", RES, 80, "Standard query 0x3c11 A seeing.skyportal.example", [52114, 53], asked("0x3c11", RD, "seeing.skyportal.example: type A, class IN")),
          pkt(2, "0.000412", RES, "203.0.113.10", 91, "Standard query 0x91e2 A seeing.skyportal.example", [33871, 53], asked("0x91e2", NO_RD, "seeing.skyportal.example: type A, class IN", ["[Destination: a root server, from ch-res01's root hints]"])),
          pkt(3, "0.021305", "203.0.113.10", RES, 142, "Standard query response 0x91e2 A seeing.skyportal.example NS a.tld-servers.example NS b.tld-servers.example", [53, 33871], ["Domain Name System (response)", "Transaction ID: 0x91e2", "Flags: 0x8000 Standard query response, No error", OK, "Answer RRs: 0", "Authority RRs: 2", "Authoritative nameservers: example: type NS, a.tld-servers.example", "[A referral: no answer yet, only who to ask next]"]),
          pkt(4, "0.021688", RES, "203.0.113.20", 91, "Standard query 0x91e3 A seeing.skyportal.example", [33872, 53], asked("0x91e3", NO_RD, "seeing.skyportal.example: type A, class IN", ["[Destination: a TLD server, from the root's referral]"])),
          pkt(5, "0.046120", "203.0.113.20", RES, 118, "Standard query response 0x91e3 A seeing.skyportal.example NS ns1.skyportal.example", [53, 33872], ["Domain Name System (response)", "Transaction ID: 0x91e3", "Flags: 0x8000 Standard query response, No error", OK, "Answer RRs: 0", "Authority RRs: 1", "Authoritative nameservers: skyportal.example: type NS, ns1.skyportal.example", "[A referral: no answer yet, only who to ask next]"]),
          pkt(6, "0.046571", RES, "203.0.113.30", 91, "Standard query 0x91e4 A seeing.skyportal.example", [33873, 53], asked("0x91e4", NO_RD, "seeing.skyportal.example: type A, class IN", ["[Destination: ns1.skyportal.example]"])),
          pkt(7, "0.071240", "203.0.113.30", RES, 124, "Standard query response 0x91e4 A seeing.skyportal.example CNAME edge-17.cdnedge.example", [53, 33873], ["Domain Name System (response)", "Transaction ID: 0x91e4", "Flags: 0x8400 Standard query response, Authoritative, No error", OK, "Answers: seeing.skyportal.example: type CNAME, class IN, ttl 300, cname edge-17.cdnedge.example"]),
          pkt(8, "0.071602", RES, "203.0.113.40", 90, "Standard query 0x91e5 A edge-17.cdnedge.example", [33874, 53], asked("0x91e5", NO_RD, "edge-17.cdnedge.example: type A, class IN", ["[Destination: ns1.cdnedge.example, chasing the alias]"])),
          pkt(9, "0.092017", "203.0.113.40", RES, 106, "Standard query response 0x91e5 A edge-17.cdnedge.example A 198.51.100.40", [53, 33874], ["Domain Name System (response)", "Transaction ID: 0x91e5", "Flags: 0x8400 Standard query response, Authoritative, No error", OK, "Answers: edge-17.cdnedge.example: type A, class IN, ttl 60, addr 198.51.100.40"]),
          pkt(10, "0.092510", RES, "10.60.12.27", 134, "Standard query response 0x3c11 A seeing.skyportal.example CNAME edge-17.cdnedge.example A 198.51.100.40", [53, 52114], ["Domain Name System (response)", "Transaction ID: 0x3c11", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: seeing.skyportal.example: type CNAME, class IN, ttl 300, cname edge-17.cdnedge.example", "Answers: edge-17.cdnedge.example: type A, class IN, ttl 60, addr 198.51.100.40"]),
          pkt(11, "12.104118", "10.60.12.31", RES, 80, "Standard query 0x7a02 A seeing.skyportal.example", [49822, 53], asked("0x7a02", RD, "seeing.skyportal.example: type A, class IN")),
          pkt(12, "12.104390", RES, "10.60.12.31", 134, "Standard query response 0x7a02 A seeing.skyportal.example CNAME edge-17.cdnedge.example A 198.51.100.40", [53, 49822], ["Domain Name System (response)", "Transaction ID: 0x7a02", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: seeing.skyportal.example: type CNAME, class IN, ttl 288, cname edge-17.cdnedge.example", "Answers: edge-17.cdnedge.example: type A, class IN, ttl 48, addr 198.51.100.40"]),
          pkt(13, "15.330214", "10.60.0.25", RES, 77, "Standard query 0x5521 MX journal-press.example", [40120, 53], asked("0x5521", RD, "journal-press.example: type MX, class IN")),
          pkt(14, "15.330702", RES, "10.60.0.25", 128, "Standard query response 0x5521 MX journal-press.example MX 10 mx1.journal-press.example MX 20 mx2.journal-press.example", [53, 40120], ["Domain Name System (response)", "Transaction ID: 0x5521", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: journal-press.example: type MX, class IN, preference 10, mx1.journal-press.example", "Answers: journal-press.example: type MX, class IN, preference 20, mx2.journal-press.example"]),
          pkt(15, "15.361877", "10.60.0.25", RES, 77, "Standard query 0x5522 TXT journal-press.example", [40121, 53], asked("0x5522", RD, "journal-press.example: type TXT, class IN")),
          pkt(16, "15.362240", RES, "10.60.0.25", 129, "Standard query response 0x5522 TXT journal-press.example TXT", [53, 40121], ["Domain Name System (response)", "Transaction ID: 0x5522", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: journal-press.example: type TXT, class IN, ttl 3600"], "v=spf1 ip4:198.51.100.128/28 -all"),
          pkt(17, "18.002951", "10.60.12.27", RES, 103, "Standard query 0x3c14 SRV _ldap._tcp.dc._msdcs.cinderhill.example", [52118, 53], asked("0x3c14", RD, "_ldap._tcp.dc._msdcs.cinderhill.example: type SRV, class IN")),
          pkt(18, "18.003208", RES, "10.60.12.27", 148, "Standard query response 0x3c14 SRV _ldap._tcp.dc._msdcs.cinderhill.example SRV 0 100 389 ch-dc01.cinderhill.example", [53, 52118], ["Domain Name System (response)", "Transaction ID: 0x3c14", "Flags: 0x8580 Standard query response, Authoritative, Recursion available, No error", OK, "Answers: type SRV, class IN, priority 0, weight 100, port 389, target ch-dc01.cinderhill.example"]),
          pkt(19, "21.640372", "10.60.0.25", RES, 86, "Standard query 0x5530 PTR 7.113.0.203.in-addr.arpa", [40133, 53], asked("0x5530", RD, "7.113.0.203.in-addr.arpa: type PTR, class IN")),
          pkt(20, "21.640815", RES, "10.60.0.25", 124, "Standard query response 0x5530 PTR 7.113.0.203.in-addr.arpa PTR host-7.homebroadband.example", [53, 40133], ["Domain Name System (response)", "Transaction ID: 0x5530", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: 7.113.0.203.in-addr.arpa: type PTR, class IN, host-7.homebroadband.example", "[Reverse lookup: address to name. A sender calling itself a journal's mail server should not reverse to home broadband]"]),
          pkt(21, "24.118845", "10.60.12.27", RES, 72, "Standard query 0x3c19 A skyportl.example", [52131, 53], asked("0x3c19", RD, "skyportl.example: type A, class IN")),
          pkt(22, "24.150262", RES, "10.60.12.27", 136, "Standard query response 0x3c19 No such name A skyportl.example SOA a.tld-servers.example", [53, 52131], ["Domain Name System (response)", "Transaction ID: 0x3c19", "Flags: 0x8183 Standard query response, Recursion available, No such name", "Reply code: No such name (3)", "Answer RRs: 0", "[NXDOMAIN: the zone's authority says this name does not exist]"]),
          pkt(23, "26.771204", "10.60.0.80", RES, 86, "Standard query 0x6b02 AAAA old-plotter.cinderhill.example", [58012, 53], asked("0x6b02", RD, "old-plotter.cinderhill.example: type AAAA, class IN")),
          pkt(24, "26.771588", RES, "10.60.0.80", 146, "Standard query response 0x6b02 No such name AAAA old-plotter.cinderhill.example SOA ch-dc01.cinderhill.example", [53, 58012], ["Domain Name System (response)", "Transaction ID: 0x6b02", "Flags: 0x8583 Standard query response, Authoritative, Recursion available, No such name", "Reply code: No such name (3)", "Answer RRs: 0"]),
          pkt(25, "29.415009", "10.60.0.80", RES, 80, "Standard query 0x6b09 A feed.tidegauge.example", [58019, 53], asked("0x6b09", RD, "feed.tidegauge.example: type A, class IN")),
          pkt(26, "31.418112", RES, "10.60.0.80", 80, "Standard query response 0x6b09 Server failure A feed.tidegauge.example", [53, 58019], ["Domain Name System (response)", "Transaction ID: 0x6b09", "Flags: 0x8182 Standard query response, Recursion available, Server failure", "Reply code: Server failure (2)", "Answer RRs: 0", "[SERVFAIL: the resolver could not finish the job. It says nothing about whether the name exists]"]),
          pkt(27, "33.207115", "10.60.12.14", RES, 118, `Standard query 0x0a01 NULL ${CHUNK1}.${PARENT}`, [61044, 53], asked("0x0a01", RD, `${CHUNK1}.${PARENT}: type NULL, class IN`)),
          pkt(28, "33.207490", RES, "203.0.113.66", 118, `Standard query 0xc4d1 NULL ${CHUNK1}.${PARENT}`, [33901, 53], asked("0xc4d1", NO_RD, `${CHUNK1}.${PARENT}: type NULL, class IN`, ["[Destination: the nameserver for pm.plate-mirror.example]"])),
          pkt(29, "33.291706", "203.0.113.66", RES, 142, `Standard query response 0xc4d1 NULL ${CHUNK1}.${PARENT} NULL`, [53, 33901], ["Domain Name System (response)", "Transaction ID: 0xc4d1", "Flags: 0x8400 Standard query response, Authoritative, No error", OK, "Answers: type NULL, class IN, ttl 0, data length 8"], "ack 0001"),
          pkt(30, "33.292033", RES, "10.60.12.14", 142, `Standard query response 0x0a01 NULL ${CHUNK1}.${PARENT} NULL`, [53, 61044], ["Domain Name System (response)", "Transaction ID: 0x0a01", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: type NULL, class IN, ttl 0, data length 8"], "ack 0001"),
          pkt(31, "33.402118", "10.60.12.14", RES, 118, `Standard query 0x0a02 NULL ${CHUNK2}.${PARENT}`, [61044, 53], asked("0x0a02", RD, `${CHUNK2}.${PARENT}: type NULL, class IN`)),
          pkt(32, "33.487205", RES, "10.60.12.14", 142, `Standard query response 0x0a02 NULL ${CHUNK2}.${PARENT} NULL`, [53, 61044], ["Domain Name System (response)", "Transaction ID: 0x0a02", "Flags: 0x8180 Standard query response, Recursion available, No error", OK, "Answers: type NULL, class IN, ttl 0, data length 8"], "ack 0002"),
          {
            no: 33, time: "36.900412", src: "10.60.14.9", dst: "198.51.100.53", proto: "TLSv1.3", len: 141, info: "Application Data",
            tree: ["Internet Protocol Version 4, Src: 10.60.14.9, Dst: 198.51.100.53", "Transmission Control Protocol, Src Port: 44120, Dst Port: 853", "Transport Layer Security", "TLSv1.3 Record Layer: Application Data Protocol: Application Data"],
          },
          {
            no: 34, time: "36.931877", src: "198.51.100.53", dst: "10.60.14.9", proto: "TLSv1.3", len: 196, info: "Application Data",
            tree: ["Internet Protocol Version 4, Src: 198.51.100.53, Dst: 10.60.14.9", "Transmission Control Protocol, Src Port: 853, Dst Port: 44120", "Transport Layer Security", "TLSv1.3 Record Layer: Application Data Protocol: Application Data"],
          },
        ],
        objectives: [
          { id: "walk", task: "Packets 1 to 10 are one lookup from one laptop. How many different outside servers did the resolver ask to answer it?", hint: "ip.src==10.60.0.53", answer: ["4", "four"], why: "Root, TLD, the domain's authoritative server, then the CDN's, because the answer was an alias. The referrals in packets 3 and 5 carry zero answers, only who to ask next. The laptop sent one packet." },
          { id: "cname", task: "The laptop asked for seeing.skyportal.example. What name does it really land on?", hint: "CNAME", answer: ["edge-17.cdnedge.example", "edge-17.cdnedge.example."], why: "CNAME is an alias: one name saying 'I'm really that one'. CDNs and cloud services lean on them, so to judge a hostname you chase the chain to its end." },
          { id: "cache", task: "A second client asked the same name 12 seconds later. What TTL did its A answer carry?", hint: "ip.dst==10.60.12.31", answer: ["48"], why: "The record's TTL was 60, and a cached answer counts down, so 12 seconds later it says 48. No upstream packets sit between 11 and 12: that's what a cache hit looks like on the wire." },
          { id: "mx", task: "The mail relay looked up journal-press.example. Which server will it try first?", hint: "MX journal-press", answer: ["mx1.journal-press.example", "mx1"], why: "MX records name a domain's mail servers, and the lowest preference wins. The TXT lookup right after it is the relay fetching SPF (Sender Policy Framework) text, which is why TXT from a mail server is ordinary and TXT from a workstation isn't." },
          { id: "nx", task: "How many lookups in this capture ended in No such name?", hint: "\"No such name\"", answer: ["2", "two"], why: "No such name is NXDOMAIN: the name doesn't exist. One typo and one retired internal host, a healthy background level. A lone NXDOMAIN means little. A flood of them is a different story." },
          { id: "servfail", task: "One lookup ended in Server failure. Which name?", hint: "\"Server failure\"", answer: ["feed.tidegauge.example"], why: "SERVFAIL means the resolver couldn't finish, often a broken delegation, and the two-second gap before the reply shows it trying. It isn't NXDOMAIN: it says nothing about whether the name exists." },
          { id: "null", task: "One client keeps asking for a record type with no normal modern use. Which type?", hint: "ip.src==10.60.12.14", answer: ["NULL", "type NULL"], why: "NULL records hold raw bytes and have essentially no legitimate modern use, so seeing one at all is informative. SRV, by contrast, looks rare until you remember Active Directory clients find their domain controllers with it, as packet 17 does." },
          { id: "rcode", task: "What response code did those odd lookups get?", hint: "ip.dst==10.60.12.14", answer: ["No error", "noerror", "no error (0)", "0"], why: "They succeed. Names nobody has ever asked for get answered, with TTL 0, by a nameserver that clearly expects them. Packet 28 shows who carries them there: ch-res01 itself. Someone is running a server for this zone." },
          { id: "dot", task: "The last two packets aren't DNS on the wire at all. Which destination port do they use?", hint: "ip.addr==198.51.100.53", answer: ["853"], why: "Port 853 is DoT, DNS over TLS. You can see that it's happening and to whom, but not one name inside. That's the next lab." },
        ],
      },
      {
        kind: "simulate",
        title: "What the Wire Still Shows",
        prompt: "Encrypted DNS protects users from eavesdropping and tampering, and it takes something from you. Run each way a lookup can leave a host on the ridge and see what survives: the name, the log line, and the firewall's ability to stop it.",
        checks: [
          { name: "Name readable", question: "Can a network sensor read the queried name?" },
          { name: "In the resolver log", question: "Does the lookup land in a log you own?" },
          { name: "Port block works", question: "Can the firewall stop it by port without breaking the web?" },
        ],
        scenarios: [
          {
            id: "plain", label: "Plain DNS to ch-res01", detail: "udp 10.60.12.27:52114 > 10.60.0.53:53",
            results: ["pass", "pass", "pass"],
            why: ["Cleartext on port 53: every query and answer is readable.", "ch-res01 logs the query and the client address.", "Outbound 53 can be limited to the resolver alone."],
            verdict: "Full visibility. Everything in this room assumes at least this much, somewhere in the chain.",
          },
          {
            id: "public", label: "Plain DNS to a public resolver", detail: "udp 10.60.30.21:40911 > 198.51.100.53:53",
            results: ["pass", "fail", "pass"],
            why: ["Still cleartext, so a sensor on the path reads it.", "It never touches ch-res01, so the log has a hole.", "Deny 53 outbound for everything except ch-res01."],
            verdict: "Easy to close. If only the resolver may send port 53 out, this path simply stops working.",
          },
          {
            id: "dot", label: "DoT to a public resolver", detail: "tcp 10.60.14.9:44120 > 198.51.100.53:853 (TLS)",
            results: ["fail", "fail", "pass"],
            why: ["TLS hides the query. You see only the address, the port and the sizes.", "It bypasses ch-res01 completely.", "853 has one use, so one firewall rule ends it."],
            verdict: "DoT, DNS over TLS, is visible as DoT. You lose the content, but you know it's there and can block it outright.",
          },
          {
            id: "doh", label: "DoH to a public provider", detail: "tcp 10.60.12.27:50233 > 203.0.113.80:443 (TLS, SNI dns.provider.example)",
            results: ["fail", "fail", "fail"],
            why: ["The lookups are HTTPS requests inside TLS.", "It bypasses ch-res01 completely.", "Block 443 and you've blocked the web."],
            verdict: "DoH, DNS over HTTPS, looks like any other HTTPS session in a flow record. What it leaves is the destination: SNI (Server Name Indication) or the IP can match a list of known providers, and the shape is connection reuse and many small, similar-sized exchanges. Recent browsers can turn it on by default, so it's usually a privacy feature doing its job, not an attacker. Only TLS inspection reads the names.",
          },
          {
            id: "internal", label: "DoH to a site endpoint", detail: "tcp 10.60.12.27:50290 > 10.60.0.54:443 (TLS, SNI doh.cinderhill.example)",
            results: ["fail", "pass", "fail"],
            why: ["Encrypted on the wire, so a sensor still can't read it.", "The site runs the endpoint, so every lookup lands in a log you own.", "You don't want to block this one."],
            verdict: "The usual fix: block or intercept known public DoH and DoT endpoints, and give clients a resolver you control. That turns an invisible channel back into a visible, filterable one.",
          },
        ],
      },
    ],
    // ── Reading 3: tunnelling internals ──
    "dns-r3": [
      {
        kind: "anatomy",
        title: "Anatomy of a Tunnel Query",
        prompt: "This is one of those NULL lookups from ch-sci-wk04, as the site's Zeek sensor logged it. Scan it field by field. Everything a tunnel does, it does inside a name.",
        source: "Zeek dns.log · ch-nsm01 · 10.60.12.14",
        fields: [
          { key: "ts", value: "2026-11-02T22:14:33.207Z", label: "When" },
          { key: "id.orig_h", value: "10.60.12.14", label: "Asked by", note: "The querying host: ch-sci-wk04, a data reduction workstation." },
          { key: "id.resp_h", value: "10.60.0.53", label: "Asked of", note: "The site's own resolver. The workstation never touches the attacker's server: ch-res01 delivers every chunk for it, and DNS is the one thing the firewall has to let out." },
          { key: "proto", value: "udp", note: "Transport proves nothing. Honest clients and tunnels both use UDP, and both can fall back to TCP when an answer is too big." },
          { key: "query (first label)", value: CHUNK1, label: "The payload", note: "Not a hostname: 52 characters of base32. A label can be 63 characters and a whole name 255, and tunnels run close to that. Base32 carries 5 bits a character, so 52 characters is 32 bytes. Base64 packs more, but DNS names ignore case, so case-sensitive encoding is risky. Hex is 4 bits a character." },
          { key: "first label, decoded", value: "SIMPLE  =                    T /", label: "What it says", note: "The first line of a FITS file, the Flexible Image Transport System format astronomy images use. Those are survey plates leaving the mountain. Header padding is why this chunk looks repetitive: later chunks are image bytes and look far more random." },
          { key: "query (parent)", value: PARENT, label: "The zone", note: "The attacker controls this zone, so its authoritative nameserver is the tunnel server, decoding each query as it arrives." },
          { key: "qtype_name", value: "NULL", label: "Asked for", note: "Data going out rides in the name. Data coming back rides in the answer: an A record holds 4 bytes, TXT holds strings of up to 255 bytes each, which is why it's the favourite, and NULL holds raw bytes but stands out. Chains of CNAME answers can work too." },
          { key: "rcode_name", value: "NOERROR", label: "Result", note: "A tunnel has to work, so its queries succeed. The zone exists and answers. Failure isn't its signature." },
          { key: "AA / RD / RA", value: "false / true / true", note: "Authoritative Answer, Recursion Desired, Recursion Available: a normal client request served by a normal recursive resolver. Nothing in the flags looks odd." },
          { key: "answers", value: "[\"<unknown type=10>\"]", note: "Zeek doesn't parse NULL data, so it logs this placeholder (type 10 is NULL). The bytes that came back have to be read in the capture. The array runs parallel with TTLs below: one value, one TTL." },
          { key: "TTLs", value: "[0.0]", label: "Cache life", note: "A cached answer would stop the next query at ch-res01, and the data with it. So every name is new, and the answer is built not to be reused. Tunnel traffic gets no help from caches." },
        ],
        summary: "A tunnel spends one query per slice of the file. That's why its names look encoded, run long, never repeat, succeed, and arrive in large numbers: one query moves a few tens of bytes, so any real file takes thousands. Each of those traits has an innocent explanation somewhere. All of them together, against one parent, from one host, doesn't.",
      },
      {
        kind: "worksheet",
        title: "Count the Names",
        prompt: "Volume alone flags a busy proxy. Oskar's next column is the one a tunnel can't fake: how many of the names under a parent were ever asked before. Work these out from ten minutes of resolver aggregates.",
        caption: "ch-res01 aggregates · 10 minutes · Monday 23:00",
        columns: ["Client", "Parent domain", "Queries", "Unique names", "Top type"],
        rows: [
          ["ch-sci-wk04", PARENT, "600", "594", "NULL"],
          ["ch-prox01", "cdnedge.example", "900", "45", "A"],
          ["ch-mail01", "journal-press.example", "40", "3", "TXT"],
          ["ch-sci-lt07", "avscan.vendor.example", "92", "90", "A"],
          ["ch-dome-ctl2", "ntp.cinderhill.example", "60", "1", "A"],
        ],
        questions: [
          { id: "ratio", q: "Unique names divided by queries for ch-sci-wk04, as a fraction between 0 and 1?", hint: "594 / 600.", answer: ["0.99", ".99"], why: "Almost nothing is asked twice: a slice of a file only needs sending once. The ratio is a fraction, so it can never pass 1." },
          { id: "proxy", q: "The same ratio for ch-prox01?", hint: "45 / 900.", answer: ["0.05", ".05"], why: "More volume, and a twentieth of the uniqueness. Real software comes back to a small, stable set of names." },
          { id: "alone", q: "ch-sci-lt07's ratio is close to 1 too. Is that enough to call it a tunnel? (yes/no)", hint: "Look at its volume and who it talks to.", answer: ["no"], why: "Antivirus reputation lookups put a file hash in each name, so they're unique and random-looking too. Ninety in ten minutes to a known vendor is a product working. No signal stands alone." },
          { id: "cost", q: "Each query moves 32 bytes out. How many queries to move a 1,000,000 byte cutout of one plate?", hint: "1,000,000 / 32.", answer: ["31250"], why: "That's why tunnels are loud. A small payload per query means real data takes tens of thousands of them, and a normal workstation resolves a few dozen names an hour." },
        ],
      },
      {
        kind: "tune",
        title: "Three Dials: Length, Entropy, Volume",
        prompt: "Oskar wants one rule that fires on tunnels and stays quiet on the CDNs and vendor telemetry the site lives on. Every row below is one client and one parent over 10 minutes, replayed from a week of captures. Entropy is how random a label's characters are, in bits per character. Set the three dials, deploy, and read what your rule really caught. All three must trip for the rule to fire.",
        eventColumn: "Parent domain, one client, 10 minutes",
        dials: [
          { id: "len", label: "Leftmost label length", short: "length", unit: "chars", min: 10, max: 63, step: 1, start: 20 },
          { id: "ent", label: "Label entropy", short: "entropy", unit: "bits/char", min: 2, max: 5, step: 0.25, start: 3 },
          { id: "vol", label: "Queries to one parent", short: "volume", unit: "per 10 min", min: 0, max: 1000, step: 20, start: 100 },
        ],
        events: [
          { id: "t1", label: `${PARENT} · 52-char base32 in NULL lookups`, bad: true, values: { len: 52, ent: 4.5, vol: 600 } },
          { id: "t2", label: "relay.obs-sync.example · 48-char hex labels in TXT lookups", bad: true, values: { len: 48, ent: 3.8, vol: 420 } },
          { id: "t3", label: "dl.orbit-cache.example · 38-char base32 labels", bad: true, values: { len: 38, ent: 4.3, vol: 520 } },
          { id: "t4", label: "x.nightglow-feed.example · 60-char base32 labels", bad: true, values: { len: 60, ent: 4.6, vol: 880 } },
          { id: "t5", label: "sync.plate-cache.example · 44-char base32, one query every 20 seconds", bad: true, values: { len: 44, ent: 4.4, vol: 30 } },
          { id: "b1", label: "avscan.vendor.example · 40-char hex file hashes", bad: false, values: { len: 40, ent: 3.7, vol: 90 } },
          { id: "b2", label: "metrics.sensorvendor.example · 48-char encoded device IDs", bad: false, values: { len: 48, ent: 4.4, vol: 120 } },
          { id: "b3", label: "cdnedge.example · 14-char edge names through ch-prox01", bad: false, values: { len: 14, ent: 3.4, vol: 900 } },
          { id: "b4", label: "relay.meetvendor.example · 24-char session IDs on a video call", bad: false, values: { len: 24, ent: 4, vol: 640 } },
          { id: "b5", label: "weather-mast-north-ridge-anemometer-station-04.cinderhill.example · readable", bad: false, values: { len: 46, ent: 3.7, vol: 960 } },
          { id: "b6", label: "agent.fleetvendor.example · 36-char encoded check-ins", bad: false, values: { len: 36, ent: 4.2, vol: 260 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        deploys: 4,
        lesson: "Each dial exists because of a different innocent neighbour. Length stops short random CDN and session names. Entropy stops long readable names, but keep it low enough: hex can never pass 4.0 bits a character, so a threshold of 4 or more goes blind to a hex tunnel. Volume stops telemetry and hash lookups, which look just like a tunnel in every way except how often they ask. The cost of that dial is the slow tunnel you let through at one query every 20 seconds: a rule like this catches fast channels, and slow ones take a longer window and a hunt for new parents.",
      },
    ],
    // ── Reading 6: which log answers which question ──
    "dns-r6": [
      {
        kind: "anatomy",
        title: "Anatomy of Sysmon Event 22",
        prompt: "Before you hunt with it, read an ordinary one. This is the FITS image viewer on a laptop looking up a catalogue. Network logs stop at the IP address. Scan what this record adds.",
        source: "Sysmon · Event ID 22 · DnsQuery · ch-sci-lt07",
        fields: [
          { key: "UtcTime", value: "2026-11-02 21:40:18.552", label: "When" },
          { key: "ProcessGuid", value: "{6d0c1a2e-3f4a-6546-7b02-000000002c00}", label: "The pivot", note: "Stays unique even after a PID is reused. Pull this into the rest of the host's Sysmon data for parent, command line, files and connections." },
          { key: "ProcessId", value: "6128" },
          { key: "QueryName", value: "catalog.skyportal.example", label: "What was asked" },
          { key: "QueryStatus", value: "0", label: "Result", note: "0 means the lookup succeeded. A failed lookup carries a Windows error code here: 9003 is the NXDOMAIN case." },
          { key: "QueryResults", value: "type:  5 edge-02.cdnedge.example;::ffff:198.51.100.41;", label: "The answer", note: "Includes the alias. 'type:  5' is the number for CNAME, as 16 is for TXT." },
          { key: "Image", value: "C:\\Program Files\\FitsViewer\\fitsview.exe", label: "Who asked", note: "The field no network log can give you. On the wire, process context is already gone." },
          { key: "User", value: "CINDERHILL\\l.ferro", label: "As whom", note: "The account the process ran under. It's filled in whether a person typed the command or a script, task or service started it, so it doesn't prove anyone was at the keyboard." },
        ],
        summary: "Event 22 covers lookups made through the Windows DNS Client API: browsers, PowerShell's Resolve-DnsName, .NET and most applications. A tool that builds its own UDP packets to port 53, as nslookup and many tunnel clients do, writes no Event 22 at all, and then Sysmon Event ID 3, the network connection event, still names the Image. Zeek's dns.log is the other half: it covers every host on the wire, Sysmon agent or not, so it's where you compute rates and ratios across the site. Use the wire to find the host and the endpoint to find the program.",
      },
      {
        kind: "trace",
        title: "From Packet to Process",
        prompt: "The rule fired on one parent. Oskar needs a program, because you can't kill a subnet. Follow the lead from the wire to the endpoint, and watch which log can answer which question.",
        lead: `Tunnel rule hit: parent ${PARENT}, Monday 22:14`,
        steps: [
          {
            id: "wire", ask: "Start with the network view. Which row is the channel, and which client sent it?", source: "Zeek dns.log · ch-nsm01",
            columns: ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name"],
            rows: [
              ["22:14:00", "10.60.12.27", RES, "seeing.skyportal.example", "A", "NOERROR"],
              ["22:14:15", "10.60.0.25", RES, "journal-press.example", "TXT", "NOERROR"],
              ["22:14:29", "10.60.0.80", RES, "feed.tidegauge.example", "A", "SERVFAIL"],
              ["22:14:33", "10.60.12.14", RES, `${CHUNK2}.${PARENT}`, "NULL", "NOERROR"],
            ],
            answer: 3, why: "Zeek gives you the client address and everything about the query, and that's where it stops. Nothing on the wire says which program sent it.", learned: "Client address 10.60.12.14",
          },
          {
            id: "lease", ask: "An address isn't a machine. Which machine held 10.60.12.14 at 22:14?", source: "DHCP leases · ch-dc01",
            columns: ["Lease start", "Lease end", "IP", "Hostname", "MAC"],
            rows: [
              ["Mon 08:02", "Mon 17:55", "10.60.12.14", "ch-visitor-07", "3c:52:82:1a:7f:10"],
              ["Mon 18:04", "Tue 02:04", "10.60.12.14", "ch-sci-wk04", "3c:52:82:44:90:2e"],
              ["Mon 18:06", "Tue 02:06", "10.60.12.15", "ch-sci-wk05", "3c:52:82:44:90:3a"],
            ],
            answer: 1, why: "Always match the lease to the time of the query. DHCP names the machine, and that's all it can do: it knows nothing about processes.", learned: "Machine ch-sci-wk04",
          },
          {
            id: "conn", ask: `Event 22 on ch-sci-wk04 has no line for ${PARENT}, so this client isn't using the Windows DNS Client. Sysmon Event ID 3 still names programs. Which one is sending its own DNS?`, source: "Sysmon Event ID 3 · ch-sci-wk04",
            columns: ["UtcTime", "Image", "User", "Protocol", "DestinationIp", "DestinationPort"],
            rows: [
              ["22:14:01", "C:\\Windows\\System32\\svchost.exe", "NT AUTHORITY\\NETWORK SERVICE", "udp", RES, "53"],
              ["22:14:03", "C:\\Program Files\\FitsViewer\\fitsview.exe", "CINDERHILL\\y.marsh", "tcp", "10.60.0.80", "8080"],
              ["22:14:33", "C:\\Users\\Public\\Libraries\\platesync.exe", "CINDERHILL\\y.marsh", "udp", RES, "53"],
              ["22:14:36", "C:\\Windows\\System32\\svchost.exe", "NT AUTHORITY\\NETWORK SERVICE", "udp", RES, "53"],
            ],
            answer: 2, why: "svchost.exe is the Windows DNS Client service doing lookups for everyone, so it's expected on port 53. A program in a public folder talking straight to port 53 has skipped that service, and that's why it left no Event 22.", learned: "platesync.exe, sending raw UDP to port 53",
          },
          {
            id: "parent", ask: "Pivot on that process. What started platesync.exe?", source: "Sysmon Event ID 1 · ch-sci-wk04",
            columns: ["UtcTime", "Image", "CommandLine", "ParentImage", "ParentCommandLine"],
            rows: [
              ["21:58:11", "C:\\Users\\Public\\Libraries\\platesync.exe", `platesync.exe --zone ${PARENT}`, "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"],
              ["18:21:40", "C:\\Program Files\\FitsViewer\\fitsview.exe", "fitsview.exe night_0412.fits", "C:\\Windows\\explorer.exe", "explorer.exe"],
              ["18:04:52", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c stack_plates.bat", "C:\\Windows\\explorer.exe", "explorer.exe"],
            ],
            answer: 0, why: "A scheduled task started it, with the zone on its command line. That's a lead on how it stays, on what else to look for, and on other hosts with the same task.", learned: "Started by the Task Scheduler, so it persists",
          },
        ],
      },
    ],
    // ── Log analysis 1: what to do next ──
    "dns-la1": [
      {
        kind: "sequence",
        title: "Order of Operations: A Web Shell",
        prompt: "Before you judge tonight's case, here's the one Oskar gives every new analyst. Last spring a web shell landed on ch-web02, the public outreach site, and the attacker was still typing. Tap the steps in the order the team should take them.",
        items: [
          { id: "scope", text: "List what the shell read, then brief the site lead", note: "You can only size the damage once it has stopped growing." },
          { id: "block", text: "Block the attacker's source address at the web gateway", note: "This ends the live session at a point you control, and it's quick to undo." },
          { id: "copy", text: "Copy the web logs and the dropped page off the server", note: "These are the record of what the attacker sent and when." },
          { id: "tree", text: "Read the process tree under the web server process", note: "What the shell started decides everything that follows, and reading it changes nothing on the host." },
          { id: "isolate", text: "Isolate ch-web02 through its EDR agent, powered on", note: "EDR is Endpoint Detection and Response. Isolation holds the host still: memory, disk and the agent's link all survive." },
        ],
        order: ["tree", "block", "isolate", "copy", "scope"],
        doneNote: "Understand first, because looking costs nothing. Then cut the attacker's line, then hold the host still with its evidence intact, and only then count the damage. The order stays the same whatever the channel was.",
      },
    ],
    // ── Query fill: reading a rule ──
    "dns-qf1": [
      {
        kind: "inspect",
        title: "Read a Rule Line by Line",
        prompt: "Before you write one: this is a draft Oskar kept from a NULL-record hunt on the Zeek table, with thresholds set for that week's noise, and two lines that were thrown out. Click every line and learn what it does.",
        artifact: "Scheduled query · NULL records on the wire · Zeek table",
        items: [
          { id: "k1", text: "ZeekDns_CL", tag: "Source", tone: "info", note: "Start from the table that holds every lookup on site." },
          { id: "k2", text: "| where qtype_name == \"NULL\"", tag: "Narrow first", tone: "trust", note: "Pick the record type the channel uses, so the rule never counts ordinary A lookups. A channel on another type gets this line changed." },
          { id: "k3", text: "| summarize Total = count(), Unique = dcount(query) by id_orig_h, bin(TimeGenerated, 20m)", tag: "Two counts, per host, per window", tone: "trust", note: "count() is all queries and dcount() the distinct names, both per client inside a time bucket. A short window catches a burst. A long one dilutes it. This hunt used 20m because NULL is so rare." },
          { id: "k4", text: "| where Unique > 400", tag: "Volume floor", tone: "trust", note: "A floor on unique names keeps out one quiet host whose few queries happen to be unique. Set it from your own baseline: that week it was 400." },
          { id: "k5", text: "| where Unique / Total > 0.6", tag: "Thrown out", tone: "warn", note: "KQL divides two whole numbers as whole numbers, so this is 0 until Unique equals Total, and the rule almost never fires. Multiply by 1.0 first." },
          { id: "k6", text: "| where (Unique * 1.0 / Total) > 80", tag: "Thrown out", tone: "warn", note: "The ratio is a fraction and can never pass 1, so a threshold written as a percentage never fires, and nothing tells you. A silent rule looks exactly like a quiet network." },
          { id: "k7", text: "| where (Unique * 1.0 / Total) > 0.6", tag: "The ratio that shipped", tone: "trust", note: "Real division, written as a fraction. The closer to 1, the fewer names were ever asked twice, and 0.6 was loose on purpose for a type this rare." },
        ],
      },
    ],
    // ── Reading 4: generated names ──
    "dns-r4": [
      {
        kind: "rush",
        title: "Generated or Provisioned?",
        prompt: "The block held for nineteen minutes. Then ch-dome-ctl2, the dome control PC, started failing lookups at machine speed, while the resolver's noisiest honest clients carried on. Random-looking names prove nothing on their own. Call each line: a DGA (Domain Generation Algorithm), or a CDN (content delivery network) or cloud service doing its job.",
        trueLabel: "DGA",
        falseLabel: "CDN or cloud",
        seconds: 100,
        target: 10,
        cards: [
          { id: "g1", text: "412 names in 6 minutes, 94% NXDOMAIN, each a different second-level domain", answer: true, why: "A DGA works down a list the attacker mostly never registered, so most lookups fail. The second-level domain itself keeps changing." },
          { id: "g2", text: "60 random labels under one parent registered nine years ago, all NOERROR", answer: false, why: "They all resolve, and the parent is old and stable. Those are real, provisioned resources." },
          { id: "g3", text: "qvztkpl.example: registered 2 days ago, the only success in a burst of 200", answer: true, why: "The one that resolves is the one the attacker registered, days before use. Domain age is a strong enrichment for exactly this name." },
          { id: "g4", text: "A random storage bucket name under a cloud provider's domain, resolves every time", answer: false, why: "Bucket and account names are random-looking but they exist. Parents like blob.core.windows.net and cloudfront.net are years old." },
          { id: "g5", text: "One random edge name resolved once, then not asked again for its whole TTL", answer: false, why: "Cached and reused. CDN randomness is a few names, kept for a while, not hundreds of new ones back to back." },
          { id: "g6", text: "Every query a new domain, across five cheap TLDs, nearly all failing", answer: true, why: "The randomness isn't confined to a subdomain under one parent. TLDs such as .top, .xyz and .cc turn up often, though that shifts and is never conclusive alone." },
          { id: "g7", text: "Bursts of new names every four hours exactly, about 90% NXDOMAIN", answer: true, why: "Malware checks in on a schedule, tries its list until one resolves, then gives up until next time." },
          { id: "g8", text: "High-entropy labels, 100% success, one parent shared by half the site", answer: false, why: "High entropy alone is the classic false alarm. Success rate and a stable shared parent settle it." },
          { id: "g9", text: "A conferencing relay's random host under the vendor's long-established domain", answer: false, why: "Collaboration tools mint relay names constantly. A known parent, years old, and every lookup resolving." },
          { id: "g10", text: "Two glued dictionary words per name, fresh domains, 88% NXDOMAIN", answer: true, why: "Wordlist DGAs read like English, so entropy misses them completely. The failure rate doesn't care how a name looks." },
          { id: "g11", text: "6-character label, 250 names like it, 240 failed, on domains with no registration record", answer: true, why: "An unregistered candidate has no age to check, and a label this short can't score high on entropy. The burst and the failures carry it." },
          { id: "g12", text: "30 cache-busting names, all resolve, under a parent six years old", answer: false, why: "Random by design and working by design. Age and success both point the same way." },
          { id: "g13", text: "520 lookups, all NOERROR, through ch-prox01 to four well-known parents", answer: false, why: "High volume alone can be a proxy working for many users. Nothing here fails and no parent is new." },
          { id: "g14", text: "A burst where each failing name is a new second-level domain, from one host in minutes", answer: true, why: "Many distinct domains, mostly failing, from one host, tight in time. That's the shape, whatever the letters look like." },
        ],
        lesson: "Don't start with how a name looks. Ask whether it resolved. A DGA's list is mostly unregistered, so NXDOMAIN rate is the strongest split. Then check how the parent behaves: one old stable parent is a service, an ever-changing second-level domain is a list being worked. Domain age helps on names that resolve, TLD is only a supporting hint, and high volume alone proves nothing.",
      },
      {
        kind: "worksheet",
        title: "Score the Burst",
        prompt: "Twelve minutes of resolver aggregates after the block. Work out what ch-dome-ctl2 is doing, what it has found, and where the next hour should go.",
        caption: "ch-res01 aggregates · 12 minutes · Monday 23:31",
        columns: ["Client", "Distinct names", "Second-level domains", "NXDOMAIN", "Parent age"],
        rows: [
          ["ch-dome-ctl2", "180", "180", "171", "Days, or unregistered"],
          ["ch-prox01", "240", "6", "2", "6 to 11 years"],
          ["ch-sci-lt07", "22", "19", "1", "Mixed, mostly years"],
        ],
        questions: [
          { id: "who", q: "Which client is working through a generated list?", hint: "Compare second-level domains with NXDOMAIN.", answer: ["ch-dome-ctl2"], why: "A new second-level domain for every name, and nearly all of them fail. ch-prox01 has more names and almost no failures, under six parents." },
          { id: "rate", q: "Its NXDOMAIN rate, as a whole percent?", hint: "171 / 180.", answer: ["95", "95%"], why: "Anything near 90% or above from one host in a short window is a DGA fingerprint." },
          { id: "live", q: "How many of its names did not fail?", hint: "Subtract the failures from the distinct names.", answer: ["9"], why: "Those are the domains the attacker really registered, and it only needs one. They're your pivot list: follow-on traffic goes there, and failing lookups don't mean the malware failed." },
          { id: "sink", q: "Should the 171 failed names go on the sinkhole? (yes/no)", hint: "Does anyone own them?", answer: ["no"], why: "Nobody registered them, so a sinkhole would have nothing live to watch." },
          { id: "cap", q: "A label's entropy can't exceed log2 of its length. What's the most a 16-character label can score, in bits per character?", hint: "2 to the what is 16?", answer: ["4", "4.0"], why: "The cap is log2(length), reached only when no character repeats. A 4-character label can't pass 2.0. So short generated names score no higher than short real hostnames, and entropy can't carry this decision. Failure rate and volume do." },
        ],
      },
    ],
    // ── Reading 5: flux and sinkholes ──
    "dns-r5": [
      {
        kind: "reactor",
        title: "Flux, Balance or Sinkhole?",
        prompt: "One of the names that resolved is qzhlmvrt.example, and blocking its address did nothing. Before Oskar picks a move, sort what the resolution history shows. Route each observation into the reactor it belongs to.",
        reactors: [
          { id: "flux", label: "Fast flux", sub: "A records rotate" },
          { id: "double", label: "Double flux", sub: "NS records rotate too" },
          { id: "lb", label: "Load balancing", sub: "A small stable pool" },
          { id: "sink", label: "Sinkhole", sub: "Defenders own the answer" },
        ],
        items: [
          { id: "r1", text: "Six lookups in 10 minutes, six addresses in five networks, TTL 120", reactor: "flux", why: "A new address each time, unrelated networks, a very short TTL. Each address is usually a compromised home device acting as a proxy." },
          { id: "r2", text: "Block one address, and the name answers from another inside two minutes", reactor: "flux", why: "That's the point of flux. IP blocks barely work, so the domain itself has to be the target." },
          { id: "r3", text: "Home broadband addresses in several countries behind one web name", reactor: "flux", why: "Legitimate services don't run on consumer lines across a dozen providers." },
          { id: "r4", text: "A records change every two minutes, and so do the domain's own nameservers", reactor: "double", why: "Rotating the NS records as well means taking out a nameserver doesn't kill the domain." },
          { id: "r5", text: "The nameserver is seized, and within an hour the delegation points elsewhere", reactor: "double", why: "Harder to build and less common, and seen in well-resourced criminal infrastructure." },
          { id: "r6", text: "Four addresses, one provider's published range, TTL 60, the same four all week", reactor: "lb", why: "A short TTL alone proves nothing. The pool is small, stable and documented." },
          { id: "r7", text: "Answers vary by region, all from the operator's own known ranges", reactor: "lb", why: "Rotation inside one provider's ranges is ordinary traffic engineering." },
          { id: "r8", text: "A resolver answers a bad name with an address the site's own team runs", reactor: "sink", why: "A local sinkhole. Infected hosts lose their route out, and they announce themselves by asking." },
          { id: "r9", text: "A national CERT took the domain over, and infected hosts now connect to its server", reactor: "sink", why: "The same idea at internet scale, through registrars and researchers." },
        ],
      },
      {
        kind: "queue",
        title: "Who Knocked on the Sinkhole?",
        prompt: "Oskar pointed qzhlmvrt.example at 10.60.0.99 on ch-res01 at midnight. Nothing legitimate should ever ask for that name, so the sinkhole's log has become a list of questions worth answering. Work the three hits.",
        console: "SIEM · Sinkhole hits",
        actions: [
          { id: "contain", label: "Isolate the host", tone: "contain" },
          { id: "dig", label: "Escalate: find the real client", tone: "escalate" },
          { id: "close", label: "Close with a note", tone: "close" },
        ],
        alerts: [
          {
            id: "h1", time: "00:47", severity: "High", rule: "Connection to sinkhole 10.60.0.99", entity: "ch-spec-wk02",
            fields: [{ k: "id.orig_h", v: "10.60.12.40" }, { k: "Port", v: "443" }, { k: "EDR alerts", v: "None" }, { k: "Asked for", v: "qzhlmvrt.example" }],
            context: "The spectrograph workstation. Nothing has flagged it, and it wasn't in any burst.",
            answer: "contain",
            why: "This is what a sinkhole buys. A host no other tool flagged tried to reach a name only malware wants, and a query like that is a compromise indicator with almost no false positives. That's the third host.",
          },
          {
            id: "h2", time: "00:52", severity: "High", rule: "Connection to sinkhole 10.60.0.99", entity: "ch-prox01",
            fields: [{ k: "id.orig_h", v: "10.60.0.80" }, { k: "Role", v: "Web proxy for 140 staff" }, { k: "Port", v: "443" }, { k: "Asked for", v: "qzhlmvrt.example" }],
            context: "The proxy resolves names on behalf of every client behind it.",
            answer: "dig",
            why: "The hit is real, but the source is a middleman. Isolating the proxy cuts off the site and tells you nothing. Its own access log names the client that asked.",
          },
          {
            id: "h3", time: "00:58", severity: "Medium", rule: "Query for sinkholed domain", entity: "ch-soc-an02",
            fields: [{ k: "id.orig_h", v: "10.60.5.22" }, { k: "Image", v: "C:\\Windows\\System32\\nslookup.exe" }, { k: "User", v: "CINDERHILL\\o.bello" }, { k: "Ticket", v: "INC-2291, sinkhole test" }],
            context: "Oskar's own analysis box, checking that the sinkhole answers.",
            answer: "close",
            why: "Near zero isn't zero: the one honest source is your own team testing. A named analyst, a ticket and a matching tool make it a note, not an incident.",
          },
        ],
      },
    ],
    // ── Boss warm-up: true, benign or false ──
    "dns-ac1": [
      {
        kind: "defuse",
        title: "True, Benign or False?",
        prompt: "The site's resolver-bypass rule fires whenever a host does its DNS somewhere ch-res01 can't see. Four hits from the week are waiting, and each needs one of three verdicts. The first question is always whether the rule saw what it was built to see. The second is what else the host did.",
        device: "The bypass queue",
        seconds: 110,
        rounds: [
          {
            id: "d1",
            state: "ch-eng-lx03, a Linux bench PC. Port 853 to a public resolver for weeks, since its OS image switched on DNS over TLS. No policy forbids it. EDR quiet, no new processes, normal work traffic.",
            wires: [{ id: "tp", label: "True positive: escalate and contain" }, { id: "btp", label: "Benign true positive: close it, raise the policy gap" }, { id: "fp", label: "False positive: fix the rule" }],
            cut: "btp",
            hint: "The bypass really happened. Did anything else?",
            why: "The rule worked: the host really is bypassing ch-res01, so it isn't a false positive. It's permitted behaviour with nothing around it pointing to abuse, so it isn't an incident. Close it as benign true positive, cite the reason, and raise the gap as policy.",
          },
          {
            id: "d2",
            state: "ch-sci-lt07, talking to doh.cinderhill.example, the site's own DoH endpoint. Every lookup lands in a log you own. Somebody left that endpoint off the rule's exclusion list.",
            wires: [{ id: "tp", label: "True positive: escalate and contain" }, { id: "btp", label: "Benign true positive: close it, raise the policy gap" }, { id: "fp", label: "False positive: fix the rule" }],
            cut: "fp",
            hint: "Was anything bypassed at all?",
            why: "Nothing escaped, so the rule fired on something it was never meant to catch. That's a real false positive, and here the fix is the rule's exclusion list.",
          },
          {
            id: "d3",
            state: "ch-spec-wk02. Long HTTPS session to dns.provider.example, thousands of requests an hour, from C:\\Users\\Public\\svc32.exe, unsigned, created last night. It also hit the sinkhole.",
            wires: [{ id: "tp", label: "True positive: escalate and contain" }, { id: "btp", label: "Benign true positive: close it, raise the policy gap" }, { id: "fp", label: "False positive: fix the rule" }],
            cut: "tp",
            hint: "Encrypted DNS isn't the evidence. Look at what's around it.",
            why: "The same bypass, with supporting signals: an unsigned new program, abnormal volume, a sinkhole hit. Those signals decide it, not the encryption.",
          },
          {
            id: "d4",
            state: "ch-dome-ctl2, already under investigation. Six minutes after qzhlmvrt.example was sinkholed, it opened an HTTPS session to a public DoH provider. Nothing on the dome PC's build uses DoH.",
            wires: [{ id: "tp", label: "True positive: escalate and contain" }, { id: "btp", label: "Benign true positive: close it, raise the policy gap" }, { id: "fp", label: "False positive: fix the rule" }],
            cut: "tp",
            hint: "Which software on this host would do that, and why now?",
            why: "A known compromised host, no software that explains it, and timing that follows your block. Malware moves to encrypted DNS for the same reason a browser does: it isn't seen. Context turns the same event into an escalation.",
          },
        ],
        lesson: "Keep two questions apart. Did the rule fire on what it was built to detect? If not, it's a false positive, and you fix the rule. If it did, what's around it? New processes, persistence, abnormal volume, an odd destination or other alerts make it a true positive. Expected, permitted behaviour with none of those makes it a benign true positive: you close it with the reason, and because calling it false would invite someone to weaken a working rule, you don't. The blind spot itself is then a policy question, not an incident: block public endpoints, or knowingly accept the gap.",
      },
    ],
  },
};
