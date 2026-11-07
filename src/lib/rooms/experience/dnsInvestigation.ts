import type { RoomExperience } from "./types";

// "Operation Lookup" for the "dns-investigation" room.
// Script: docs/campaign/47-dns-investigation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pemberton Libraries (fictional), not the graded tasks' WKSTN hosts.
// Signature mechanic: trick cards (each DNS abuse as an everyday trick).
// Lab data differs from the graded tasks: the resolver console hunts a
// lookalike domain, never an NXDOMAIN storm (q1, la1, flag1); the trick cards
// carry no query counts, TTLs or residential IPs (q1, q3); the metrics sort
// never judges a process path (q2) or long labels and TXT records (ac1).
export const DNS_INVESTIGATION: RoomExperience = {
  roomId: "dns-investigation",
  codename: "Operation Lookup",
  theme: "dns",
  handler: { name: "Nasrin Tehrani", role: "Threat Hunter, Pemberton Libraries" },
  briefing: [
    "Pemberton Libraries. 38 branches, 900 public PCs, free Wi-Fi for everyone, and a catalogue system the whole county relies on.",
    "Public PCs get used by anyone, so they get infected by anything. Almost every infection starts with the same thing: a name lookup.",
    "Nasrin Tehrani hunts in DNS logs because malware can hide its traffic, but it can't avoid asking where to go.",
    "Learn what DNS logs record, the tricks attackers play with names, the investigation workflow, then work a DNS storm and a tunnelling verdict.",
  ],
  mission: "Interrogate the library resolver for a lookalike domain, stamp four DNS tricks with their names, sort DNS metrics into normal and alarming, then work the graded storm and a tunnelling call.",
  estimate: "~40 min",
  look: { primary: "#a78bfa", secondary: "#84cc16", warn: "#f43f5e" },
  scene: "lookup",
  layout: "stage",
  stations: [
    {
      id: "resolver",
      label: "The Resolver",
      topic: "Why DNS is investigative gold · core fields · Sysmon Event 22",
      tagline: "Ask the phone book who called whom",
      building: "control",
      taskIds: ["dns-r1"],
    },
    {
      id: "tricks",
      label: "Four Tricks",
      topic: "DGA, tunnelling, fast flux, typosquatting, sinkholes",
      tagline: "Every abuse has a tell",
      building: "lab",
      taskIds: ["dns-r2", "dns-q1", "dns-q3"],
    },
    {
      id: "workflow",
      label: "The Workflow",
      topic: "Storm, process, correlation, domain analysis, scope, contain · key metrics",
      tagline: "Know normal before you call alarm",
      building: "office",
      taskIds: ["dns-r3", "dns-q2"],
    },
    {
      id: "storm",
      label: "The Storm",
      topic: "A DNS storm in Sysmon Event 22",
      tagline: "Work the graded storm",
      building: "vault",
      taskIds: ["dns-la1", "dns-flag1"],
    },
    {
      id: "verdict",
      label: "Tunnel or CDN",
      topic: "Tunnelling or ordinary content delivery",
      tagline: "Make the call",
      building: "ticket",
      taskIds: ["dns-ac1"],
      boss: true,
    },
  ],
  personas: {
    "dns-q1": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "312 lookups, 309 NXDOMAIN, random names. What is it?" },
    "dns-q3": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "One name, a new address every 90 seconds, all home broadband. Name it." },
    "dns-q2": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "RuntimeBroker.exe from AppData making hundreds of lookups. Why does the path matter?" },
    "dns-la1": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "A storm from an HR workstation. Read the Sysmon event." },
    "dns-ac1": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "Random-looking subdomains, heavy traffic. What does the evidence support?" },
  },
  briefings: {
    // ── Reading 1: the resolver ──
    "dns-r1": [
      {
        kind: "codebreak",
        title: "Read the Resolver Log",
        prompt: "Nasrin pins the library resolver's query log to the wall: every line is a client, a name and a record type. A branch reports a 'catalogue login' page that looked wrong. Before you hunt, decode the words the log speaks. Each clue is a line you will meet there.",
        tries: 6,
        rounds: [
          { id: "c1", clue: "The query type for the IPv6 address of a name. The same client asks for it right after the plain IPv4 lookup, within a second or two.", answer: "AAAA", why: "A asks for IPv4, AAAA for IPv6. Browsers send both back to back, so a pair like that is one page load, not two events." },
          { id: "c2", clue: "A record type that holds free text, used for SPF and domain verification. Malware likes it because the answer can carry any string.", answer: "TXT", why: "TXT answers are free text, so a long run of TXT queries to one odd parent domain is worth a look. Ordinary web traffic asks for A and AAAA." },
          { id: "c3", clue: "An alias record: one name says 'I am really that other name', which is how CDNs chain names together. Five letters.", answer: "CNAME", why: "CNAME answers point to another name, so a long chain to unfamiliar domains is normal for a CDN and still worth reading. Resolve the final name before judging." },
          { id: "c4", clue: "The service whose lease log turns a client IP in the resolver log into a machine name. Four letters.", answer: "DHCP", why: "The resolver log shows only an IP. The DHCP lease at that time names the machine, and the hunt then moves to that host. Check the lease time against the query time." },
        ],
        lesson: "Learn to read a DNS log in its own words: the type says what was asked, the answer says where it points, and the lease turns a client IP into a machine. A lookalike name is only the start; the record type and the client decide the next step. A resolver log never says which program asked. On a Windows host, Sysmon Event ID 22 (DNSEvent) adds that: its Image field is the full path of the process that made the query.",
      },
    ],
    // ── Reading 2: signature mechanic, trick cards ──
    "dns-r2": [
      {
        kind: "tricks",
        title: "Name the Trick",
        prompt: "Each card is an everyday trick. Flip it, then stamp it with the DNS abuse that works the same way.",
        attacks: [
          { id: "dga", name: "DGA" },
          { id: "tunnel", name: "DNS tunnelling" },
          { id: "flux", name: "Fast flux" },
          { id: "typo", name: "Typosquatting" },
        ],
        cards: [
          { id: "calls", analogy: "A caller dials hundreds of random numbers a day, knowing only one will ever be answered.", attack: "dga", real: "Malware generates many domain names a day; the operator registers just one." },
          { id: "notes", analogy: "Secrets are written into the names on a guest list and read out at the door.", attack: "tunnel", real: "Data is encoded into the labels of lookups and carried out by the resolver." },
          { id: "stall", analogy: "A market stall that moves to a different street every few minutes.", attack: "flux", real: "One name keeps resolving to fresh addresses so blocking any one of them is useless." },
          { id: "sign", analogy: "A shop sign that reads 'Pemberton Llbraries' and hopes nobody looks twice.", attack: "typo", real: "A domain one character away from the real one." },
          { id: "drawer", analogy: "A letter hidden inside a stack of ordinary post, a few words at a time.", attack: "tunnel", real: "Small chunks of data in many lookups to the same parent domain." },
          { id: "dice", analogy: "Rolling dice every morning to decide where to meet, and both sides know the dice.", attack: "dga", real: "The malware and its operator run the same algorithm on the date." },
        ],
      },
    ],
    // ── Reading 3: metrics ──
    "dns-r3": [
      {
        kind: "tune",
        title: "Tune the Hunter",
        prompt: "Nasrin's rule watches the labels in front of each parent domain: how long the average label is and how random its letters are (entropy, in bits per character). Set both, deploy, and see which domains the rule calls tunnels and which honest long names it trips on.",
        eventColumn: "Parent domain, 10 minutes of lookups",
        dials: [
          { id: "len", label: "Average label length", short: "length", unit: "chars", min: 5, max: 60, step: 1, start: 10 },
          { id: "ent", label: "Randomness of the label", short: "entropy", unit: "bits/char", min: 2, max: 5, step: 0.25, start: 3 },
        ],
        events: [
          { id: "d1", label: "sync-branch.example · 50-char base32 labels, steady every few seconds", bad: true, values: { len: 50, ent: 4.25 } },
          { id: "d2", label: "pl-backup.example · 46-char base64url labels in TXT lookups", bad: true, values: { len: 46, ent: 4.5 } },
          { id: "d3", label: "mirror-pemberton.example · 44-char mixed-case labels", bad: true, values: { len: 44, ent: 4.75 } },
          { id: "d4", label: "kiosk-update.example · 56-char base32 labels", bad: true, values: { len: 56, ent: 4.25 } },
          { id: "d5", label: "antivirus cloud lookup · 40-char SHA-1 hex of a file", bad: false, values: { len: 40, ent: 3.75 } },
          { id: "d6", label: "build-artifacts-eu-west-staging.pemberton.example · long readable name", bad: false, values: { len: 30, ent: 3 } },
          { id: "d7", label: "session id in a streaming CDN hostname", bad: false, values: { len: 20, ent: 4.5 } },
          { id: "d8", label: "device telemetry vendor · 48-char encoded ids", bad: false, values: { len: 48, ent: 4 } },
          { id: "d9", label: "short CDN edge name", bad: false, values: { len: 12, ent: 3.5 } },
          { id: "d10", label: "dashed readable names under the catalogue domain", bad: false, values: { len: 52, ent: 3.25 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        deploys: 3,
        lesson: "Tunnels need both: labels long enough to carry data and random enough to be encoded data. Length alone trips on readable names, entropy alone trips on short random IDs, and a threshold at an even 4.0 still trips on a vendor's encoded identifiers.",
      },
    ],
  },
};
