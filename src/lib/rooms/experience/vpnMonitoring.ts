import type { RoomExperience } from "./types";

// "Operation Long Distance" for the "vpn-monitoring" room.
// Script: docs/campaign/45-vpn-monitoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Northsea Wind (fictional), not the graded tasks' contoso.com. Signature
// mechanic: a line-up of VPN attack patterns, each round a piece of gateway
// evidence. Lab data differs from the graded tasks: the anatomy never says
// where a split-tunnel download would show up (q3, r1 checkpoint); the
// line-up never uses one password across 47 names (q2) or São Paulo and
// Tokyo (q1); the trail follows a different user, address and pool than the
// graded log (la1, flag1); and nothing judges a Bangkok login (ac1).
export const VPN_MONITORING: RoomExperience = {
  roomId: "vpn-monitoring",
  codename: "Operation Long Distance",
  theme: "vpn",
  handler: { name: "Eilidh MacLeod", role: "Remote Access Security Lead, Northsea Wind" },
  briefing: [
    "Northsea Wind. Four offshore wind farms, 120 turbines, and engineers who work from boats, hotels and home, all through one VPN.",
    "The VPN is the front door to the turbine control network. If someone else walks through it with an engineer's password, they can stop the blades.",
    "Eilidh MacLeod runs remote access security. She reads the gateway logs every morning the way a harbourmaster reads the arrivals board.",
    "Learn what VPN logs record, the attack patterns that show up in them, how to baseline and respond, then work a suspicious login sequence and a travel verdict.",
  ],
  mission: "Read a GlobalProtect log field by field, pick the attack pattern behind each burst of gateway events, follow a suspicious session from the gateway into the network, then work the graded login sequence and a verdict.",
  estimate: "~40 min",
  look: { primary: "#22d3ee", secondary: "#a3e635", warn: "#fb7185" },
  scene: "longdistance",
  layout: "stage",
  stations: [
    {
      id: "tunnel",
      label: "The Tunnel",
      topic: "What a VPN log records · full and split tunnels · normal behaviour",
      tagline: "Read the gateway's arrivals board",
      building: "control",
      taskIds: ["vpn-r1", "vpn-q3"],
    },
    {
      id: "knocking",
      label: "Who's Knocking?",
      topic: "Impossible travel, brute force, spraying, stuffing, odd sessions",
      tagline: "Name the pattern",
      building: "lab",
      taskIds: ["vpn-r2", "vpn-q2"],
    },
    {
      id: "baseline",
      label: "Baseline and Response",
      topic: "Per-user baselines · detection rules · responding to a compromise",
      tagline: "Follow one session inside",
      building: "office",
      taskIds: ["vpn-r3", "vpn-q1"],
    },
    {
      id: "logins",
      label: "Two Logins",
      topic: "A suspicious login sequence, field by field",
      tagline: "Work the graded sequence",
      building: "vault",
      taskIds: ["vpn-la1", "vpn-flag1"],
    },
    {
      id: "verdict",
      label: "Traveller or Thief",
      topic: "Business travel or account takeover",
      tagline: "Make the call",
      building: "ticket",
      taskIds: ["vpn-ac1"],
      boss: true,
    },
  ],
  personas: {
    "vpn-q3": { name: "Eilidh MacLeod", role: "Remote Access Security Lead", line: "Split tunnel, malicious download. Where do you look?" },
    "vpn-q2": { name: "Eilidh MacLeod", role: "Remote Access Security Lead", line: "47 usernames, one password, three minutes. Name it." },
    "vpn-q1": { name: "Eilidh MacLeod", role: "Remote Access Security Lead", line: "São Paulo, then Tokyo, 33 minutes apart. Possible?" },
    "vpn-la1": { name: "Eilidh MacLeod", role: "Remote Access Security Lead", line: "Two sessions, one account, two continents. Read them." },
    "vpn-ac1": { name: "Eilidh MacLeod", role: "Remote Access Security Lead", line: "An engineer in Bangkok with no travel request. Your verdict." },
  },
  briefings: {
    // ── Reading 1: the log itself ──
    "vpn-r1": [
      {
        kind: "anatomy",
        title: "Anatomy of a GlobalProtect Log",
        prompt: "One morning connection from a turbine engineer, as the PAN-OS GlobalProtect log records it. Decode it field by field.",
        source: "PAN-OS · GlobalProtect · gateway gp-aberdeen-01",
        fields: [
          { key: "eventid", value: "gateway-connected", label: "What" },
          { key: "srcuser", value: "NSW\\f.ross", label: "Who", note: "The credentials used, which is not always the person." },
          { key: "public_ip", value: "198.51.100.140", label: "From where", note: "The internet address of the device: the base for geolocation." },
          { key: "srcregion", value: "GB · Aberdeen", label: "Location" },
          { key: "private_ip", value: "10.88.12.47", label: "Inside address", note: "The address the gateway hands out. Every internal log after this point shows this, not the public one." },
          { key: "auth_method", value: "SAML + MFA (push)", label: "How they proved it" },
          { key: "client_ver", value: "6.2.4 · Windows", label: "Client" },
          { key: "tunnel_type", value: "full", label: "Tunnel" },
          { key: "duration · bytes", value: "7 h 42 m · 1.9 GB in / 0.3 GB out", label: "Session shape", note: "A working day, mostly downloads: what an engineer pulling turbine data looks like." },
        ],
        summary: "Who, from where, the inside address they were given, how they proved it, and how the session behaved. Keep the inside address: you'll need it to follow anyone past the gateway.",
      },
    ],
    // ── Reading 2: signature mechanic, the line-up ──
    "vpn-r2": [
      {
        kind: "lineup",
        title: "Who's Knocking?",
        prompt: "Five attack patterns are in the line-up. Each round is a burst of events from the gateway. Pick the pattern that fits the evidence.",
        suspects: [
          { id: "travel", name: "The Traveller", motive: "Uses stolen working credentials", skill: "Logs in from places the user can't reach in time", target: "One account, two locations" },
          { id: "brute", name: "The Hammer", motive: "Wants one specific account", skill: "Hundreds of passwords against a single username", target: "One account, many passwords" },
          { id: "spray", name: "The Sprayer", motive: "Wants any account", skill: "A few common passwords across many usernames, slowly", target: "Many accounts, few passwords" },
          { id: "stuff", name: "The Stuffer", motive: "Reuses leaked username-password pairs", skill: "Each username tried with its own leaked password", target: "Many accounts, one try each" },
          { id: "odd", name: "The Squatter", motive: "Already in, settling down", skill: "A normal login followed by unusual use", target: "One session, wrong behaviour" },
        ],
        rounds: [
          { id: "r1", evidence: ["Username: ops.admin", "1,240 failures in 20 minutes", "one source address", "each failure a different password"], suspect: "brute", why: "Everything aimed at one account: the classic brute force." },
          { id: "r2", evidence: ["Successful login for m.dunn from Aberdeen at 08:02", "successful login for m.dunn from Lagos at 08:41", "both with valid MFA"], suspect: "travel", why: "Nobody gets from Aberdeen to Lagos in 39 minutes. One of those sessions isn't m.dunn." },
          { id: "r3", evidence: ["312 usernames, each tried exactly once", "each with a different password", "11 succeed", "addresses rotate every few tries"], suspect: "stuff", why: "One attempt per account with its own password: pairs from a leak, replayed." },
          { id: "r4", evidence: ["k.byrne logs in normally from home at 21:00", "session lasts 9 hours", "4.8 GB out to the internet", "touches 60 internal hosts"], suspect: "odd", why: "The login was fine. What the session did after wasn't." },
        ],
      },
      {
        kind: "tune",
        title: "Set the Travel Alert",
        prompt: "Eilidh wants an impossible-travel rule on the gateway. Each row is two logins for one engineer, scored by the speed needed between them. Set the speed and the minimum distance, deploy, and see which real thieves it catches and which flights and phone hotspots it trips on.",
        eventColumn: "Pair of logins for one account",
        dials: [
          { id: "speed", label: "Speed needed between the two logins", short: "speed", unit: "km/h", min: 100, max: 3000, step: 50, start: 500 },
          { id: "dist", label: "At least this far apart", short: "distance", unit: "km", min: 0, max: 2000, step: 50, start: 0 },
        ],
        events: [
          { id: "t1", label: "m.dunn · Aberdeen 08:02, then Lagos 08:41", bad: true, values: { speed: 7846, dist: 5100 } },
          { id: "t2", label: "s.irving · Stavanger 06:00, then Singapore 09:00", bad: true, values: { speed: 3467, dist: 10400 } },
          { id: "t3", label: "g.ferrier · Aberdeen 14:00, then Frankfurt-hosted address 15:10", bad: true, values: { speed: 857, dist: 1000 } },
          { id: "t4", label: "d.baird · Aberdeen 10:00, then Warsaw 11:35", bad: true, values: { speed: 1011, dist: 1600 } },
          { id: "t5", label: "f.ross · home Wi-Fi, then phone hotspot, Aberdeen to Dundee", bad: false, values: { speed: 2200, dist: 110 } },
          { id: "t6", label: "a.laing · hotspot handed to a mast in Inverness", bad: false, values: { speed: 2550, dist: 170 } },
          { id: "t7", label: "e.craig · flew Aberdeen to Houston, 11 hours between logins", bad: false, values: { speed: 718, dist: 7900 } },
          { id: "t8", label: "j.moir · Edinburgh to Oslo for a site visit, 3 hours", bad: false, values: { speed: 367, dist: 1100 } },
          { id: "t9", label: "n.hay · hotel Wi-Fi, then the office, same city", bad: false, values: { speed: 144, dist: 12 } },
          { id: "t10", label: "c.dow · stale geo database moved a Dundee address to Inverness", bad: false, values: { speed: 9600, dist: 160 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        deploys: 3,
        lesson: "Impossible travel needs two limits. Speed alone trips on mobile hotspots and bad geo data that jump a few hundred kilometres in minutes, and a speed set at a plane's cruise misses a theft that still leaves no time to fly. Add a minimum distance, and put the speed just above honest long-haul flights.",
      },
    ],
    // ── Reading 3: following a session inside ──
    "vpn-r3": [
      {
        kind: "trace",
        title: "Follow the Session Inside",
        prompt: "An alert on r.okoye's account: a first-ever login from a new country. Follow the session from the gateway to whatever it touched.",
        lead: "Alert: first login from NL for r.okoye at 02:14, MFA approved.",
        steps: [
          {
            id: "gw", source: "GlobalProtect · gateway-connected · r.okoye",
            ask: "Which inside address did the gateway hand to the 02:14 session?",
            columns: ["time", "public IP", "region", "private IP", "auth"],
            rows: [["Mon 08:31", "198.51.100.140", "GB · Aberdeen", "10.88.12.91", "SAML + MFA"], ["Wed 02:14", "203.0.113.58", "NL · Amsterdam", "10.88.14.203", "SAML + MFA"]],
            answer: 1,
            why: "The 02:14 session got 10.88.14.203. From here on, that's the address to follow.",
            learned: "02:14 session = inside address 10.88.14.203",
          },
          {
            id: "fw", source: "Internal firewall · src 10.88.14.203 · 02:14-03:00",
            ask: "What did that address reach for?",
            columns: ["time", "destination", "port", "app", "action"],
            rows: [["02:16", "10.20.0.15 (intranet)", "443", "web", "allow"], ["02:21", "10.60.1.10 (SCADA historian)", "1433", "mssql", "allow"]],
            answer: 1,
            why: "The turbine historian database, at 2 a.m., from a first-time country. r.okoye is in HR: no reason to touch it.",
            learned: "02:21 SCADA historian over SQL",
          },
          {
            id: "push", source: "MFA provider · push log · r.okoye",
            ask: "How did the MFA get approved?",
            columns: ["time", "event", "device"],
            rows: [["02:13", "push sent ×9", "r.okoye iPhone"], ["02:14", "push approved", "r.okoye iPhone"]],
            answer: 0,
            why: "Nine pushes in a minute, then one approval: fatigue. The password was stolen and the user tapped yes to make it stop.",
            learned: "MFA fatigue: 9 pushes, then approved",
          },
        ],
      },
      {
        kind: "defuse",
        title: "The Live Session",
        prompt: "It is 02:30 at Northsea Wind and Eilidh is on the phone. A VPN session is open into the turbine network, and each module is a decision about it. Cut the one wire that fits before the clock runs out.",
        device: "Session response · gp-aberdeen-01",
        seconds: 90,
        rounds: [
          {
            id: "d1", state: "r.okoye's session is live and MFA was approved after 9 pushes. It has reached the SCADA historian. The password is probably stolen.",
            wires: [
              { id: "reset", label: "Reset the password" },
              { id: "kill", label: "Disconnect the session and disable the account" },
              { id: "mail", label: "Email her to ask if it was her" },
            ],
            cut: "kill", hint: "A live tunnel does not care what happens to the password afterwards.",
            why: "A password reset does not close a tunnel that is already up, and an email waits for a reply while the attacker works. End the session first, then repair the credential.",
          },
          {
            id: "d2", state: "The session is gone. You know the public IP 203.0.113.58 and the inside address 10.88.14.203. You must list what it touched on the network.",
            wires: [
              { id: "pub", label: "Search internal firewall logs for 203.0.113.58" },
              { id: "priv", label: "Search internal logs for 10.88.14.203 during the session" },
              { id: "gw", label: "Pull the gateway log for r.okoye again" },
            ],
            cut: "priv", hint: "Which address do internal devices see?",
            why: "The gateway hands out the inside address, and every internal log shows that one, never the public IP. The gateway log only tells you the session happened.",
          },
          {
            id: "d3", state: "f.ross logs in at 02:58 from a harbour address he has not used before. 25 MB moved. The on-call roster lists him for night work this week.",
            wires: [
              { id: "disable", label: "Disable his account" },
              { id: "close", label: "Match it to the roster, note the new address, close" },
              { id: "block", label: "Block the new address at the gateway" },
            ],
            cut: "close", hint: "A new address and a night hour only matter when nothing explains them.",
            why: "The roster explains the hour and a boat in harbour explains the address, with a small transfer. Disabling would leave a night engineer locked out; check the reason before reacting to the oddness.",
          },
          {
            id: "d4", state: "Forty usernames were tried with two passwords, spread across six hours from rotating addresses. Three logins succeeded.",
            wires: [
              { id: "ip", label: "Block the last source address" },
              { id: "all", label: "Lock all forty accounts" },
              { id: "three", label: "Reset the three that succeeded and review their sessions" },
            ],
            cut: "three", hint: "Which accounts did the attacker actually get into?",
            why: "Spraying rotates addresses, so one block does nothing. Locking forty accounts cuts off engineers on boats for the sake of three. The accounts that succeeded are the compromised ones.",
          },
        ],
        lesson: "Response has an order: end the live session, find what it touched through the inside address, check whether the oddness has an explanation before acting on it, and act on the accounts that actually succeeded.",
      },
    ],
  },
};
