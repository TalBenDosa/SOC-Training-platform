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
    "dns-ac1": { name: "Nasrin Tehrani", role: "Threat Hunter", line: "Long subdomains, steady traffic. Tunnel or CDN?" },
  },
  briefings: {
    // ── Reading 1: the resolver ──
    "dns-r1": [
      {
        kind: "terminal",
        title: "Ask the Resolver",
        prompt: "The library's BIND resolver logs every lookup. A branch librarian reports a 'catalogue login' page that looked wrong. Find who looked it up and where it pointed.",
        shell: "bash",
        host: "nasrin@pl-dns-01:/var/log/named$",
        commands: [
          { match: "grep\\s+(-i\\s+)?catalog.*queries\\.log.*", help: "grep -i catalog queries.log   every lookup with 'catalog' in it",
            output: "05-Nov-2026 09:12:40 client 10.12.4.31#53112: query: catalogue.pemberton-libraries.example IN A +\n05-Nov-2026 09:14:02 client 10.12.7.18#61044: query: catalogue.pemberton-libraries.example IN A +\n05-Nov-2026 09:15:27 client 10.12.9.66#50311: query: catalogue.pemberton-llbraries.example IN A +\n05-Nov-2026 09:15:29 client 10.12.9.66#50312: query: catalogue.pemberton-llbraries.example IN AAAA +" },
          { match: "dig\\s+(\\+short\\s+)?catalogue\\.pemberton-llbraries\\.example.*", help: "dig +short catalogue.pemberton-llbraries.example",
            output: "203.0.113.205" },
          { match: "dig\\s+(\\+short\\s+)?catalogue\\.pemberton-libraries\\.example.*", help: "dig +short catalogue.pemberton-libraries.example",
            output: "10.12.0.40" },
          { match: "grep\\s+10\\.12\\.9\\.66\\s+.*dhcp.*|grep\\s+10\\.12\\.9\\.66.*", help: "grep 10.12.9.66 /var/log/dhcpd.log | tail -1   which machine had that address",
            output: "05-Nov-2026 08:31:05 DHCPACK on 10.12.9.66 to 3c:52:82:7a:19:04 (PL-HARROW-PC07) via eth0" },
        ],
        objectives: [
          { id: "host", task: "Which client IP looked up the lookalike name?", hint: "grep -i catalog queries.log", answer: ["10.12.9.66"], why: "Two l's where the i should be: 'llbraries'. Only one client asked for it." },
          { id: "ip", task: "Where does the lookalike point?", hint: "dig +short catalogue.pemberton-llbraries.example", answer: ["203.0.113.205"], why: "An internet address, while the real catalogue is internal at 10.12.0.40." },
          { id: "pc", task: "Which library PC had that IP at the time?", hint: "grep 10.12.9.66 dhcpd.log", answer: ["pl-harrow-pc07", "harrow-pc07"], why: "DHCP turns an IP into a machine. Now the hunt moves to PL-HARROW-PC07 itself." },
        ],
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
        kind: "sort",
        title: "Normal or Alarm?",
        prompt: "Before you call a storm, know what quiet looks like. Sort each DNS metric from the library network.",
        buckets: [
          { id: "normal", label: "Normal for a busy network" },
          { id: "alarm", label: "Worth an alarm" },
        ],
        items: [
          { id: "nx2", text: "A branch with 2% NXDOMAIN answers over a day", bucket: "normal", why: "Typos and stale links: a few failures are normal background." },
          { id: "look", text: "A public PC looking up a name one letter away from the catalogue's", bucket: "alarm", why: "A lookalike of your own service is almost never an accident." },
          { id: "bypass", text: "A public PC sending queries straight to an outside resolver, skipping the library's", bucket: "alarm", why: "Bypassing the resolver dodges logging and filtering on purpose." },
          { id: "new", text: "Lookups for a domain registered six hours ago", bucket: "alarm", why: "Brand-new domains are a favourite for phishing and C2." },
          { id: "cdn", text: "Thousands of lookups a day for the catalogue system's own name", bucket: "normal", why: "Popular is not suspicious when it's your own service." },
          { id: "update", text: "Every PC looking up the OS vendor's update server each morning", bucket: "normal", why: "A fleet doing exactly what it should, at the same time." },
        ],
      },
    ],
  },
};
