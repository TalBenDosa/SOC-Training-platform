"use client";
import React from "react";
import type { WorldProps } from "../common";
import { CampusWorld, type CampusConfig } from "./CampusWorld";
import { HallWorld, type HallConfig } from "./HallWorld";

// One entry per room on the new theme. Two layouts only: the island campus and the
// card hall. Signs and cards may name a station, never a graded answer or a lab answer.

const MAIL: HallConfig = {
  title: "Mail Hall",
  sub: "Thistledown Seed Co-op mail security",
  books: ["Mail Flow", "Incident Response", "SOC"],
  cards: [
    { icon: "mail", name: ["The", "Mailbox"], color: "#34d399", art: "loot" },
    { icon: "shield", name: ["The", "Seal"], color: "#fbbf24", art: "lock" },
    { icon: "filter", name: ["The Silent", "Rule"], color: "#38bdf8", art: "tree" },
    { icon: "wire", name: ["The", "Wire"], color: "#f87171", art: "pulse" },
  ],
};

const TRIAGE: HallConfig = {
  title: "Night Queue",
  sub: "Harbourline Ferries night shift",
  core: "matrix",
  books: ["Triage", "Incident Response", "SOC"],
  cards: [
    { icon: "target", name: ["The", "Queue"], color: "#f59e0b", art: "loot" },
    { icon: "filter", name: ["Five", "Steps"], color: "#38bdf8", art: "tree" },
    { icon: "users", name: ["Benign", "or Not"], color: "#34d399", art: "axes" },
    { icon: "shield", name: ["347", "Failures"], color: "#f87171", art: "pulse" },
    { icon: "mail", name: ["Write", "It Up"], color: "#a78bfa", art: "ghost" },
  ],
};

const TUNNEL: HallConfig = {
  title: "Tunnel Hall",
  sub: "Northsea Wind remote access",
  books: ["Remote Access", "Threat Hunting", "SOC"],
  cards: [
    { icon: "wire", name: ["The", "Tunnel"], color: "#22d3ee", art: "tree" },
    { icon: "users", name: ["Who's", "Knocking?"], color: "#a3e635", art: "loot" },
    { icon: "compass", name: ["Baseline and", "Response"], color: "#fbbf24", art: "axes" },
    { icon: "target", name: ["Two", "Logins"], color: "#fb7185", art: "pulse" },
    { icon: "eye", name: ["Traveller", "or Thief"], color: "#c084fc", art: "ghost" },
  ],
};

const SOC: CampusConfig = {
  seed: 4411,
  hub: { title: "GlobalBank", sub: "SOC HUB" },
  buildings: [
    { icon: "users", sign: ["The", "Floor"], color: "#22d3ee", x: -17, z: -10, rot: 0.34 },
    { icon: "target", sign: ["Tier", "Ladder"], color: "#a78bfa", x: -12, z: 7.5, rot: 0.24 },
    { icon: "monitor", sign: ["Tool", "Stack"], color: "#fbbf24", x: 9.5, z: 8.5, rot: -0.14 },
    { icon: "siren", sign: ["Night", "Desk"], color: "#fb7185", x: 18, z: -6, rot: -0.36 },
  ],
};

const NET: CampusConfig = {
  seed: 6029,
  hub: { title: "Meridale Clinics", sub: "NETWORK SECURITY HUB" },
  buildings: [
    { icon: "shield", sign: ["Rule", "Gate"], color: "#f97316", x: -18, z: -6, rot: 0.38 },
    { icon: "target", sign: ["Sensor", "Yard"], color: "#22d3ee", x: -8, z: 8, rot: 0.14 },
    { icon: "siren", sign: ["Hold", "Point"], color: "#f43f5e", x: 16, z: -9.5, rot: -0.32 },
    { icon: "wire", sign: ["Wire", "Room"], color: "#a3e635", x: 15, z: 6, rot: -0.3 },
  ],
};

const PACKET: CampusConfig = {
  seed: 3187,
  hub: { title: "Harbor Freight Logistics", sub: "NETWORK HUB" },
  buildings: [
    { icon: "mail", sign: ["Packet", "Works"], color: "#38bdf8", x: -13, z: -10, rot: 0.3 },
    { icon: "users", sign: ["Handshake", "Hall"], color: "#a78bfa", x: -14, z: 3.5, rot: 0.34 },
    { icon: "shield", sign: ["Border", "Post"], color: "#f97316", x: -5, z: 9.5, rot: 0.08 },
    { icon: "monitor", sign: ["Signal", "Lab"], color: "#2dd4bf", x: 10, z: 8, rot: -0.16 },
    { icon: "siren", sign: ["Night", "Desk"], color: "#fb7185", x: 18, z: -6, rot: -0.36 },
  ],
};

const ENTRA: CampusConfig = {
  seed: 2203,
  hub: { title: "Compass Rose Tours", sub: "IDENTITY HUB" },
  buildings: [
    { icon: "users", sign: ["Tenant", "House"], color: "#60a5fa", x: -17, z: -8, rot: 0.34 },
    { icon: "shield", sign: ["Access", "Checkpoint"], color: "#c084fc", x: -11, z: 7, rot: 0.24 },
    { icon: "target", sign: ["Role", "Vault"], color: "#fbbf24", x: 16, z: -8, rot: -0.32 },
    { icon: "siren", sign: ["Sign-in", "Desk"], color: "#fb7185", x: 12, z: 7.5, rot: -0.22 },
  ],
};

const DIRECTORY: CampusConfig = {
  seed: 9127,
  hub: { title: "Rookwood County Council", sub: "DIRECTORY HUB" },
  buildings: [
    { icon: "users", sign: ["Directory", "Hall"], color: "#22d3ee", x: -19, z: 2, rot: 0.42 },
    { icon: "wire", sign: ["Ticket", "Office"], color: "#a3e635", x: -15, z: -9, rot: 0.34 },
    { icon: "target", sign: ["Service", "Yard"], color: "#fbbf24", x: -8.5, z: 8.5, rot: 0.14 },
    { icon: "shield", sign: ["Crown", "Vault"], color: "#c084fc", x: 18, z: -8, rot: -0.36 },
    { icon: "siren", sign: ["Relay", "Station"], color: "#fb7185", x: 12.5, z: 6.5, rot: -0.2 },
  ],
};

const CAMPUS: CampusConfig = {
  hub: { title: "Fairhaven College", sub: "M365 SECURITY HUB" },
  buildings: [
    { icon: "shield", sign: ["Defender", "Centre"], color: "#38bdf8", x: -18, z: -10, rot: 0.36 },
    { icon: "mail", sign: ["Mail", "Gateway"], color: "#a78bfa", x: -12, z: 6.5, rot: 0.26 },
    { icon: "filter", sign: ["Audit", "Library"], color: "#fbbf24", x: 15.5, z: -9, rot: -0.34 },
    { icon: "wire", sign: ["Mailbox", "Rules"], color: "#2dd4bf", x: 19.5, z: 3, rot: -0.42 },
    { icon: "siren", sign: ["Incident", "Command"], color: "#f43f5e", x: 8.5, z: 9, rot: -0.14 },
  ],
};

const LASTWORD: CampusConfig = {
  seed: 7351,
  hub: { title: "Fenwick & Ash Publishers", sub: "XDR HUB" },
  buildings: [
    { icon: "siren", sign: ["The", "Incident"], color: "#fbbf24", x: -17.5, z: -8.5, rot: 0.34 },
    { icon: "monitor", sign: ["The", "Timeline"], color: "#2dd4bf", x: -10.5, z: 7.5, rot: 0.2 },
    { icon: "target", sign: ["The", "Hunt"], color: "#a78bfa", x: 8.5, z: 8.5, rot: -0.14 },
    { icon: "shield", sign: ["Last", "Word"], color: "#fb7185", x: 18, z: -5.5, rot: -0.38 },
  ],
};

const BREADCRUMB: HallConfig = {
  title: "Pivot Hall",
  sub: "Kestrel Vale Insurance threat intel",
  core: "globe",
  books: ["Threat Intel", "Threat Hunting", "SOC"],
  cards: [
    { icon: "target", name: ["The", "Hash"], color: "#fdba74", art: "axes" },
    { icon: "eye", name: ["The", "Sources"], color: "#67e8f9", art: "ghost" },
    { icon: "compass", name: ["The Pivot", "Board"], color: "#a3e635", art: "tree" },
    { icon: "siren", name: ["The Last", "Crumb"], color: "#f43f5e", art: "pulse" },
  ],
};

const TABLETOP: CampusConfig = {
  seed: 5183,
  hub: { title: "Oakhollow Water Trust", sub: "INCIDENT RESPONSE HUB" },
  buildings: [
    { icon: "siren", sign: ["The First", "Call"], color: "#22b8cf", x: -18.5, z: -7, rot: 0.36 },
    { icon: "wire", sign: ["Stop the", "Spread"], color: "#facc15", x: -12, z: 7.5, rot: 0.24 },
    { icon: "filter", sign: ["Clear Them", "Out"], color: "#f97316", x: -1.5, z: 9.5, rot: 0.02 },
    { icon: "monitor", sign: ["Restart,", "Review"], color: "#60a5fa", x: 10.5, z: 8, rot: -0.18 },
    { icon: "shield", sign: ["Not a", "Drill"], color: "#f43f5e", x: 18.5, z: -6.5, rot: -0.36 },
  ],
};

const LOOSETHREAD: HallConfig = {
  title: "Thread Hall",
  sub: "St Aldric's Hospice Group investigation",
  core: "chain",
  books: ["Investigation", "Incident Response", "SOC"],
  cards: [
    { icon: "compass", name: ["The First", "Question"], color: "#fb7185", art: "axes" },
    { icon: "wire", name: ["Pivot and", "Timeline"], color: "#7dd3fc", art: "tree" },
    { icon: "filter", name: ["SIEM and", "Case File"], color: "#fde047", art: "loot" },
    { icon: "target", name: ["Read the", "Logon"], color: "#f472b6", art: "pulse" },
  ],
};

const WHOGOES: CampusConfig = {
  seed: 5483,
  hub: { title: "Silverpine Credit Union", sub: "IDENTITY WATCH HUB" },
  buildings: [
    { icon: "monitor", sign: ["Logon", "Book"], color: "#5eead4", x: -18.5, z: -3.5, rot: 0.4 },
    { icon: "filter", sign: ["Read the", "Shape"], color: "#cbd5e1", x: -7, z: 8.5, rot: 0.12 },
    { icon: "target", sign: ["Set the", "Watch"], color: "#7dd3fc", x: 9, z: 7, rot: -0.16 },
    { icon: "siren", sign: ["Who Goes", "There?"], color: "#fb7185", x: 18, z: -9, rot: -0.36 },
  ],
};

const PAPERTRAIL: HallConfig = {
  title: "The Record Room",
  sub: "Brackenridge Mutual Housing SOC",
  core: "matrix",
  books: ["Reporting", "Incident Response", "SOC"],
  cards: [
    { icon: "layers", name: ["The Case", "Notes"], color: "#e9d8a6", art: "tree" },
    { icon: "users", name: ["The", "Handover"], color: "#7dd3fc", art: "loot" },
    { icon: "lock", name: ["The", "Hold"], color: "#f43f5e", art: "lock" },
    { icon: "pulse", name: ["The Three", "Clocks"], color: "#a78bfa", art: "axes" },
    { icon: "check", name: ["The", "Sign-Off"], color: "#34d399", art: "pulse" },
  ],
};

const BADNEWS: CampusConfig = {
  seed: 8263,
  hub: { title: "Lanternwatch Managed SOC", sub: "CLIENT SERVICES HUB" },
  buildings: [
    { icon: "mail", sign: ["The First", "Update"], color: "#e879f9", x: -19, z: -1.5, rot: 0.42 },
    { icon: "siren", sign: ["The", "Clock"], color: "#bef264", x: -10.5, z: 8.5, rot: 0.18 },
    { icon: "users", sign: ["The", "Apology"], color: "#67e8f9", x: 6, z: 9, rot: -0.1 },
    { icon: "shield", sign: ["Bad", "News"], color: "#f43f5e", x: 17, z: -4, rot: -0.34 },
  ],
};

const FRONTDOOR: HallConfig = {
  title: "The Front Door",
  sub: "Ravensford Academy Trust network access",
  core: "knot",
  books: ["NAC", "Identity", "SOC"],
  cards: [
    { icon: "wire", name: ["The", "Port"], color: "#bef264", art: "lock" },
    { icon: "filter", name: ["The", "Decision"], color: "#7dd3fc", art: "tree" },
    { icon: "pulse", name: ["The Health", "Check"], color: "#34d399", art: "pulse" },
    { icon: "eye", name: ["The", "Bypass"], color: "#f472b6", art: "ghost" },
    { icon: "siren", name: ["Quarantine", "Record"], color: "#f43f5e", art: "loot" },
  ],
};

const AUTOPILOT: CampusConfig = {
  seed: 6637,
  hub: { title: "Cobalt Ridge Logistics", sub: "AUTOMATION CONTROL HUB" },
  buildings: [
    { icon: "filter", sign: ["The", "Playbook"], color: "#7aa2f7", x: -19, z: -1.5, rot: 0.4 },
    { icon: "shield", sign: ["The", "Gate"], color: "#fde68a", x: -6, z: 9, rot: 0.1 },
    { icon: "target", sign: ["The", "Dial"], color: "#a5f3a0", x: 7.5, z: 9.5, rot: -0.12 },
    { icon: "siren", sign: ["Trust the", "Automation?"], color: "#fb5607", x: 17.5, z: -2.5, rot: -0.38 },
  ],
};

const CROWNJEWELS: HallConfig = {
  title: "Crown Jewel Hall",
  sub: "Thornbury Fine Foods asset context",
  core: "globe",
  books: ["Asset Context", "Triage", "SOC"],
  cards: [
    { icon: "layers", name: ["The Asset", "Register"], color: "#f4c95d", art: "loot" },
    { icon: "target", name: ["The Blast", "Map"], color: "#fb923c", art: "tree" },
    { icon: "filter", name: ["Severity or", "Priority"], color: "#b79cff", art: "axes" },
    { icon: "siren", name: ["The Night", "Pager"], color: "#67e8f9", art: "pulse" },
    { icon: "shield", name: ["Crown", "Jewels"], color: "#ff6b6b", art: "lock" },
  ],
};

const SHAREDDRIVE: CampusConfig = {
  seed: 3749,
  hub: { title: "Larkspur Studios", sub: "WORKSPACE SECURITY HUB" },
  buildings: [
    { icon: "monitor", sign: ["The Admin", "Console"], color: "#9d8cff", x: -18, z: -5, rot: 0.38 },
    { icon: "users", sign: ["The Consent", "Screen"], color: "#ffd166", x: -11, z: 8, rot: 0.2 },
    { icon: "filter", sign: ["The Shared", "Drive"], color: "#5ec8f2", x: 3.5, z: 9.5, rot: -0.06 },
    { icon: "target", sign: ["Two", "Suites"], color: "#7ee0a8", x: 11.5, z: 7.5, rot: -0.2 },
    { icon: "shield", sign: ["Final", "Cut"], color: "#ff6b6b", x: 18.5, z: -7.5, rot: -0.38 },
  ],
};

const MODELBEHAVIOUR: HallConfig = {
  title: "The Reading Room",
  sub: "Quillfeather Legal AI security",
  core: "knot",
  books: ["AI Security", "Incident Response", "SOC"],
  cards: [
    { icon: "monitor", name: ["The", "Assistant"], color: "#c4b5fd", art: "tree" },
    { icon: "wire", name: ["The Tool", "Belt"], color: "#facc15", art: "axes" },
    { icon: "pulse", name: ["The", "Meter"], color: "#34d399", art: "pulse" },
    { icon: "shield", name: ["The", "Guardrails"], color: "#7dd3fc", art: "lock" },
    { icon: "siren", name: ["Model", "Behaviour"], color: "#ff6b6b", art: "ghost" },
  ],
};

const HELPINGHAND: CampusConfig = {
  seed: 3761,
  hub: { title: "Brookmere Accountants", sub: "ENDPOINT SECURITY HUB" },
  buildings: [
    { icon: "users", sign: ["The Support", "Session"], color: "#f6bd60", x: -18.5, z: -7.5, rot: 0.36 },
    { icon: "wire", sign: ["The", "Way In"], color: "#84dcc6", x: -11.5, z: 7, rot: 0.24 },
    { icon: "filter", sign: ["The Five", "Signs"], color: "#c7a6ff", x: 3, z: 9.5, rot: -0.05 },
    { icon: "target", sign: ["The", "Allowlist"], color: "#7dd3fc", x: 12, z: 7.5, rot: -0.24 },
    { icon: "siren", sign: ["Close or", "Contain"], color: "#ef476f", x: 18.5, z: -6.5, rot: -0.36 },
  ],
};

const EXITROUTE: HallConfig = {
  title: "Exit Hall",
  sub: "Ostrava Precision Bearings data protection",
  core: "chain",
  books: ["Exfiltration", "Incident Response", "SOC"],
  cards: [
    { icon: "layers", name: ["The", "Share"], color: "#5fe3a1", art: "tree" },
    { icon: "bag", name: ["The", "Archive"], color: "#ffb4a2", art: "lock" },
    { icon: "wire", name: ["The", "Exit"], color: "#7dd3fc", art: "axes" },
    { icon: "pulse", name: ["Bytes", "Out"], color: "#fde047", art: "pulse" },
    { icon: "target", name: ["Stolen or", "Scheduled"], color: "#ff5d73", art: "ghost" },
  ],
};

const LONGGAME: CampusConfig = {
  seed: 8429,
  hub: { title: "Fellside Water and Power", sub: "OT SECURITY HUB" },
  buildings: [
    { icon: "monitor", sign: ["The Plant", "Floor"], color: "#ff8c42", x: -17.5, z: -4, rot: 0.32 },
    { icon: "target", sign: ["The Case", "Files"], color: "#8fd3e8", x: -9.5, z: 8.5, rot: 0.2 },
    { icon: "wire", sign: ["The", "Write"], color: "#ffd166", x: 1.5, z: 9, rot: -0.03 },
    { icon: "shield", sign: ["Safe", "Containment"], color: "#7ee0b0", x: 11.5, z: 6, rot: -0.22 },
    { icon: "siren", sign: ["The Long", "Game"], color: "#ff4d6d", x: 18.5, z: -8.5, rot: -0.38 },
  ],
};

const FIRSTRULE: HallConfig = {
  title: "First Rule Hall",
  sub: "Merrow Dock Authority detection engineering",
  core: "matrix",
  books: ["Detection", "Threat Intel", "SOC"],
  cards: [
    { icon: "compass", name: ["The Threat", "Idea"], color: "#86e3ce", art: "axes" },
    { icon: "filter", name: ["Build the", "Rule"], color: "#ffb4a2", art: "tree" },
    { icon: "pulse", name: ["Tune the", "Rule"], color: "#fbbf24", art: "pulse" },
    { icon: "siren", name: ["The First", "Alert"], color: "#e63946", art: "ghost" },
  ],
};

const DEEPQUERY: CampusConfig = {
  seed: 7459,
  hub: { title: "Cinderhill Observatory", sub: "NETWORK FORENSICS HUB" },
  buildings: [
    { icon: "wire", sign: ["The Resolution", "Path"], color: "#8ecae6", x: -19, z: -4.5, rot: 0.36 },
    { icon: "filter", sign: ["Inside the", "Tunnel"], color: "#ffb703", x: -9.5, z: 8.5, rot: 0.2 },
    { icon: "target", sign: ["Generated", "Names"], color: "#b8c0ff", x: 2, z: 9.5, rot: -0.04 },
    { icon: "shield", sign: ["Flux and", "Sinkholes"], color: "#80ed99", x: 12.5, z: 6.5, rot: -0.26 },
    { icon: "siren", sign: ["Port", "443"], color: "#e63946", x: 19, z: -8, rot: -0.38 },
  ],
};

const SEALEDROOM: HallConfig = {
  title: "The Sealed Room",
  sub: "Tessellate Payments network security",
  core: "globe",
  books: ["Encrypted Traffic", "Network Forensics", "SOC"],
  cards: [
    { icon: "wire", name: ["The", "Handshake"], color: "#e07a5f", art: "lock" },
    { icon: "eye", name: ["The", "Fingerprint"], color: "#a8dadc", art: "axes" },
    { icon: "pulse", name: ["The", "Beacon"], color: "#ffd166", art: "pulse" },
    { icon: "shield", name: ["The", "Proxy"], color: "#81b29a", art: "tree" },
    { icon: "lock", name: ["The Sealed", "Room"], color: "#f4a896", art: "ghost" },
  ],
};

const SIDEDOOR: CampusConfig = {
  seed: 4057,
  hub: { title: "Pinehurst Mills", sub: "THREAT HUNT HUB" },
  buildings: [
    { icon: "monitor", sign: ["The", "Shares"], color: "#f4a58a", x: -19, z: -3.5, rot: 0.36 },
    { icon: "shield", sign: ["The", "Tickets"], color: "#a8dadc", x: -10.5, z: 9, rot: 0.2 },
    { icon: "wire", sign: ["Relay and", "Recon"], color: "#ffd166", x: 7.5, z: 9.5, rot: -0.1 },
    { icon: "target", sign: ["The", "Doors"], color: "#c7b8ff", x: 16, z: 7.5, rot: -0.24 },
    { icon: "siren", sign: ["Ours or", "Theirs"], color: "#e5383b", x: 17.5, z: -9.5, rot: -0.38 },
  ],
};

const RETURNPATH: HallConfig = {
  title: "Return Path Hall",
  sub: "Saffron Road Imports email forensics",
  core: "knot",
  books: ["Email Forensics", "Mail Protocols", "SOC"],
  cards: [
    { icon: "mail", name: ["The", "Envelope"], color: "#ee9b3e", art: "loot" },
    { icon: "wire", name: ["The", "Chain"], color: "#9fb8ff", art: "tree" },
    { icon: "shield", name: ["The", "Seals"], color: "#34d399", art: "lock" },
    { icon: "eye", name: ["Side", "by Side"], color: "#f472b6", art: "axes" },
    { icon: "siren", name: ["Return", "Path"], color: "#f0516e", art: "ghost" },
  ],
};

const THREEHEADS: CampusConfig = {
  seed: 5923,
  hub: { title: "Vale Regional Health", sub: "IDENTITY THREAT HUB" },
  buildings: [
    { icon: "users", sign: ["The Ticket", "Office"], color: "#ff7b72", x: -19, z: -5.5, rot: 0.38 },
    { icon: "shield", sign: ["The Cipher", "Field"], color: "#7ee8fa", x: -12.5, z: 7.5, rot: 0.24 },
    { icon: "target", sign: ["Read the", "Ticket"], color: "#c3f584", x: -5, z: 9.5, rot: 0.1 },
    { icon: "filter", sign: ["No Paper", "Trail"], color: "#b794f4", x: 7.5, z: 9, rot: -0.12 },
    { icon: "siren", sign: ["The Last", "Ticket"], color: "#ffd23f", x: 17.5, z: -3, rot: -0.38 },
  ],
};

const PAGEFILE: HallConfig = {
  title: "Pagefile Hall",
  sub: "Harrowgate Museum Trust forensics",
  core: "matrix",
  books: ["Forensics", "Incident Response", "SOC"],
  cards: [
    { icon: "layers", name: ["The", "Image"], color: "#d6b370", art: "lock" },
    { icon: "eye", name: ["Two", "Timelines"], color: "#7cc6b8", art: "axes" },
    { icon: "filter", name: ["What Stays", "Behind"], color: "#9fa8da", art: "ghost" },
    { icon: "siren", name: ["The Live", "Call"], color: "#ff5964", art: "pulse" },
    { icon: "shield", name: ["The Last", "Shadow"], color: "#b9a0e8", art: "tree" },
  ],
};

const PROCESSTREE: CampusConfig = {
  seed: 7127,
  hub: { title: "Kilnworth Ceramics", sub: "EDR RESPONSE HUB" },
  buildings: [
    { icon: "monitor", sign: ["The", "Detection"], color: "#a8d8b9", x: -19, z: -4, rot: 0.38 },
    { icon: "wire", sign: ["Up the", "Tree"], color: "#ffb86b", x: -10, z: 9.5, rot: 0.2 },
    { icon: "users", sign: ["The", "Siblings"], color: "#7da7ff", x: 7.5, z: 9.5, rot: -0.12 },
    { icon: "target", sign: ["The", "Pivot"], color: "#d6a4ff", x: 13.5, z: 5.5, rot: -0.22 },
    { icon: "siren", sign: ["The Last", "Branch"], color: "#ff6b6b", x: 19, z: -0.5, rot: -0.4 },
  ],
};

const COLDVAULT: HallConfig = {
  title: "Cold Vault",
  sub: "Marchbank Cold Storage incident review",
  core: "chain",
  books: ["Ransomware", "Incident Response", "SOC"],
  cards: [
    { icon: "wire", name: ["The", "Foothold"], color: "#b3ecff", art: "pulse" },
    { icon: "lock", name: ["The Master", "Key"], color: "#f6c177", art: "lock" },
    { icon: "layers", name: ["The Cold", "Aisle"], color: "#7dd3fc", art: "ghost" },
    { icon: "bag", name: ["The Loading", "Dock"], color: "#a7f3d0", art: "loot" },
    { icon: "siren", name: ["The", "Note"], color: "#ff4d6d", art: "tree" },
  ],
};

const DIAMOND: CampusConfig = {
  seed: 2917,
  hub: { title: "Penrose Energy", sub: "THREAT INTEL HUB" },
  buildings: [
    { icon: "users", sign: ["The", "Requirement"], color: "#9be7ff", x: -19, z: -8, rot: 0.38 },
    { icon: "wire", sign: ["The", "Collection"], color: "#f2c14e", x: -12, z: 6, rot: 0.26 },
    { icon: "target", sign: ["The", "Diamond"], color: "#b9a7ff", x: -5.5, z: 9.5, rot: 0.1 },
    { icon: "mail", sign: ["The", "Release"], color: "#7fe3b5", x: 8, z: 9, rot: -0.14 },
    { icon: "siren", sign: ["The First", "Hit"], color: "#ff5a7a", x: 18, z: -1, rot: -0.34 },
  ],
};

const HIGHCLOUD: HallConfig = {
  title: "High Cloud",
  sub: "Brightfeather Robotics cloud security",
  core: "globe",
  books: ["Cloud", "Threat Hunting", "SOC"],
  cards: [
    { icon: "wire", name: ["The Control", "Plane"], color: "#a0c4ff", art: "tree" },
    { icon: "target", name: ["Who Called", "the API?"], color: "#ffc971", art: "loot" },
    { icon: "shield", name: ["The Open", "Door"], color: "#5eead4", art: "lock" },
    { icon: "siren", name: ["The Last", "Call"], color: "#ff5c72", art: "pulse" },
  ],
};

const CHAINOFCOMMAND: CampusConfig = {
  seed: 8713,
  hub: { title: "Ashdown Rail Freight", sub: "SOC NIGHT DESK" },
  buildings: [
    { icon: "monitor", sign: ["The", "Page"], color: "#f7b267", x: -19, z: -1.5, rot: 0.4 },
    { icon: "users", sign: ["The", "Call"], color: "#7bdff2", x: -8, z: 9.5, rot: 0.14 },
    { icon: "mail", sign: ["The", "Handover"], color: "#b8c0ff", x: 8.5, z: 9, rot: -0.12 },
    { icon: "siren", sign: ["Night", "Verdict"], color: "#f25f5c", x: 18, z: -7, rot: -0.34 },
  ],
};

const SPRAYPAINT: HallConfig = {
  title: "Spray Hall",
  sub: "Mariposa Hotels Group detection",
  core: "matrix",
  books: ["Detection", "Identity", "SOC"],
  cards: [
    { icon: "target", name: ["The", "Wall"], color: "#ff5fa8", art: "pulse" },
    { icon: "filter", name: ["The", "Shape"], color: "#6ee7ff", art: "axes" },
    { icon: "eye", name: ["After the", "Burst"], color: "#ffc24b", art: "ghost" },
    { icon: "shield", name: ["The", "Detection"], color: "#a3e635", art: "lock" },
  ],
};

const RUNBOOK: CampusConfig = {
  seed: 8681,
  hub: { title: "Greenhithe Foods", sub: "INCIDENT RESPONSE HUB" },
  buildings: [
    { icon: "shield", sign: ["The", "Binder"], color: "#e6c229", x: -18.5, z: -2.5, rot: 0.38 },
    { icon: "target", sign: ["Walk the", "Page"], color: "#4fd1c5", x: -11.5, z: 8, rot: 0.24 },
    { icon: "wire", sign: ["The Other", "Way Round"], color: "#7aa7ff", x: 10.5, z: 9, rot: -0.16 },
    { icon: "siren", sign: ["The", "Call"], color: "#f25c54", x: 19, z: -6.5, rot: -0.4 },
  ],
};

const QUIETFORWARD: HallConfig = {
  title: "Forward Hall",
  sub: "Sable Point Shipping mail forensics",
  core: "knot",
  books: ["Mail Forensics", "Incident Response", "SOC"],
  cards: [
    { icon: "eye", name: ["The Mailbox", "Audit"], color: "#7dcfb6", art: "loot" },
    { icon: "filter", name: ["The Quiet", "Rule"], color: "#f79d65", art: "tree" },
    { icon: "target", name: ["One", "Session"], color: "#38bdf8", art: "pulse" },
    { icon: "users", name: ["The Cover", "Story"], color: "#c084fc", art: "axes" },
    { icon: "mail", name: ["What", "Left"], color: "#f25c78", art: "lock" },
  ],
};

const EXTRADEVICE: CampusConfig = {
  seed: 8867,
  hub: { title: "Stonehaven Credit", sub: "IDENTITY OPERATIONS HUB" },
  buildings: [
    { icon: "monitor", sign: ["The Device", "List"], color: "#c5e478", x: -19, z: -9, rot: 0.38 },
    { icon: "shield", sign: ["The", "Reset"], color: "#9ad1ff", x: -13.5, z: 6, rot: 0.26 },
    { icon: "wire", sign: ["The", "Timing"], color: "#ffc98b", x: -7, z: 9.5, rot: 0.12 },
    { icon: "filter", sign: ["Routine", "or Not"], color: "#d3b8ff", x: 10, z: 9, rot: -0.18 },
    { icon: "siren", sign: ["Close the", "Case"], color: "#ff6f59", x: 18.5, z: -4.5, rot: -0.38 },
  ],
};

const FULLSHIFT: HallConfig = {
  title: "Full Shift Hall",
  sub: "Tamarind Air alert workflow",
  core: "chain",
  books: ["Investigation", "Incident Response", "SOC"],
  cards: [
    { icon: "siren", name: ["The", "Alert"], color: "#d4a373", art: "pulse" },
    { icon: "target", name: ["How Far", "It Goes"], color: "#6ec6b8", art: "tree" },
    { icon: "bag", name: ["Before", "It Fades"], color: "#fbbf24", art: "loot" },
    { icon: "layers", name: ["The Case", "File"], color: "#38bdf8", art: "axes" },
    { icon: "shield", name: ["The", "Call"], color: "#ef5a4c", art: "lock" },
  ],
};

const FINALREPORT: CampusConfig = {
  seed: 7907,
  hub: { title: "Bellwether Schools Trust", sub: "INCIDENT REPORT HUB" },
  buildings: [
    { icon: "users", sign: ["The", "Reader"], color: "#f2a7c3", x: -19, z: -6.5, rot: 0.38 },
    { icon: "filter", sign: ["The", "Record"], color: "#8fd6c8", x: -11, z: 8.5, rot: 0.22 },
    { icon: "target", sign: ["The", "Review"], color: "#ffd08a", x: 8, z: 9, rot: -0.14 },
    { icon: "shield", sign: ["The", "Gap"], color: "#a9b8ff", x: 14.5, z: 4.5, rot: -0.24 },
    { icon: "siren", sign: ["Final", "Report"], color: "#ff5f45", x: 18.5, z: -7, rot: -0.38 },
  ],
};

const SINGLESIGNOFF: HallConfig = {
  title: "Sign-Off Hall",
  sub: "Quayside Capital identity log",
  core: "globe",
  books: ["Identity", "Incident Response", "SOC"],
  cards: [
    { icon: "eye", name: ["The System", "Log"], color: "#6fc3df", art: "axes" },
    { icon: "compass", name: ["Behind the", "Attempt"], color: "#f2cc8f", art: "pulse" },
    { icon: "filter", name: ["Two", "Policies"], color: "#b8a1e3", art: "tree" },
    { icon: "users", name: ["The Admin", "Trail"], color: "#7fd1ae", art: "loot" },
    { icon: "lock", name: ["Single", "Sign-Off"], color: "#e76f51", art: "lock" },
  ],
};

const FAMILIARVOICE: CampusConfig = {
  seed: 6151,
  hub: { title: "Tollgate Media", sub: "FRAUD DESK HUB" },
  buildings: [
    { icon: "users", sign: ["The Voice", "Note"], color: "#ffd6a5", x: -18, z: -4, rot: 0.36 },
    { icon: "mail", sign: ["The Lure", "Factory"], color: "#9bb7ff", x: -10.5, z: 7, rot: 0.22 },
    { icon: "monitor", sign: ["The Helpful", "Tab"], color: "#8fe3c0", x: 11, z: 8, rot: -0.18 },
    { icon: "siren", sign: ["Did It", "Leave?"], color: "#ff5e7e", x: 19, z: -7.5, rot: -0.4 },
  ],
};

const HOLDMUSIC: HallConfig = {
  title: "Hold Music Hall",
  sub: "Brindle Mutual Insurance service desk",
  core: "chain",
  books: ["Identity", "Incident Response", "SOC"],
  cards: [
    { icon: "users", name: ["The Call", "Script"], color: "#e5989b", art: "tree" },
    { icon: "layers", name: ["The Case", "Files"], color: "#a8dadc", art: "axes" },
    { icon: "filter", name: ["The Ticket", "Trail"], color: "#fbbf24", art: "pulse" },
    { icon: "shield", name: ["The Standing", "Order"], color: "#38bdf8", art: "lock" },
    { icon: "siren", name: ["The Second", "Call"], color: "#ff5d52", art: "loot" },
  ],
};

const LONGSHADOW: CampusConfig = {
  seed: 9497,
  hub: { title: "Alderney Semiconductors", sub: "THREAT HUNT HUB" },
  buildings: [
    { icon: "target", sign: ["The", "Hypothesis"], color: "#b4bdf9", x: -18, z: -7.5, rot: 0.38 },
    { icon: "filter", sign: ["The", "Stack"], color: "#7fe0c3", x: -10.5, z: 8.5, rot: 0.2 },
    { icon: "wire", sign: ["The", "Rhythm"], color: "#ffb07c", x: 11.5, z: 8, rot: -0.2 },
    { icon: "siren", sign: ["The Long", "Shadow"], color: "#ff4f6e", x: 18.5, z: -3.5, rot: -0.36 },
  ],
};

const MASTERKEY: HallConfig = {
  title: "Key Hall",
  sub: "Ironbridge Trust Bank privileged access",
  core: "matrix",
  books: ["Privileged Access", "Windows Events", "SOC"],
  cards: [
    { icon: "lock", name: ["The", "Vault"], color: "#cfa64b", art: "lock" },
    { icon: "layers", name: ["The", "Climb"], color: "#7fb7be", art: "tree" },
    { icon: "eye", name: ["The Unvaulted", "Key"], color: "#c38bd9", art: "ghost" },
    { icon: "target", name: ["Who Used", "the Key?"], color: "#ff5a5f", art: "pulse" },
  ],
};

const SIGNALNOISE: CampusConfig = {
  seed: 3571,
  hub: { title: "Cadenza Music", sub: "DETECTION HUB" },
  buildings: [
    { icon: "filter", sign: ["The", "Backlog"], color: "#f0abfc", x: -19, z: -1, rot: 0.4 },
    { icon: "target", sign: ["The", "Heatmap"], color: "#67e8f9", x: -9.5, z: 9, rot: 0.18 },
    { icon: "wire", sign: ["The", "Rewrite"], color: "#fbbf24", x: 12.5, z: 7, rot: -0.2 },
    { icon: "siren", sign: ["First", "Fire"], color: "#fb5607", x: 19, z: -8.5, rot: -0.36 },
  ],
};

const FINEPRINT: HallConfig = {
  title: "Fine Print Hall",
  sub: "Wexcombe Estates closed-ticket review",
  core: "knot",
  books: ["Edge Cases", "Two Stories", "SOC"],
  cards: [
    { icon: "eye", name: ["The Odd", "One"], color: "#caa8f5", art: "ghost" },
    { icon: "filter", name: ["Clean", "Logs"], color: "#f0e3c0", art: "pulse" },
    { icon: "lock", name: ["The Real", "Screen"], color: "#7dd3fc", art: "lock" },
    { icon: "layers", name: ["Same", "Shape"], color: "#a3e635", art: "tree" },
    { icon: "siren", name: ["The Fine", "Print"], color: "#ff6a4d", art: "loot" },
  ],
};

const QUIETWIRE: CampusConfig = {
  seed: 6173,
  hub: { title: "Halden Geothermal", sub: "NETWORK THREAT HUB" },
  buildings: [
    { icon: "wire", sign: ["The", "Forward"], color: "#ffa94d", x: -18.5, z: -6, rot: 0.36 },
    { icon: "filter", sign: ["The Inner", "Channel"], color: "#8fd8e8", x: -12.5, z: 5.5, rot: 0.24 },
    { icon: "shield", sign: ["The Signed", "Tool"], color: "#c9b6ff", x: -6.5, z: 9.5, rot: 0.1 },
    { icon: "monitor", sign: ["The Long", "Session"], color: "#9be3b0", x: 9, z: 9.5, rot: -0.14 },
    { icon: "siren", sign: ["The Quiet", "Wire"], color: "#ff5570", x: 18.5, z: -2.5, rot: -0.34 },
  ],
};

const SIDESTEP: HallConfig = {
  title: "Trace Hall",
  sub: "Corvid Cold Chain threat hunt",
  core: "chain",
  books: ["Lateral Movement", "Threat Hunting", "SOC"],
  cards: [
    { icon: "compass", name: ["The First", "Hop"], color: "#7bdff2", art: "tree" },
    { icon: "eye", name: ["What the", "Session Did"], color: "#f9c74f", art: "ghost" },
    { icon: "filter", name: ["Name the", "Move"], color: "#c4b5fd", art: "axes" },
    { icon: "target", name: ["Rebuild", "the Graph"], color: "#ef476f", art: "pulse" },
  ],
};

const OPENSOURCE: CampusConfig = {
  seed: 4783,
  hub: { title: "Larkhill Veterinary Group", sub: "OSINT HUB" },
  buildings: [
    { icon: "target", sign: ["The", "Footprint"], color: "#9fd356", x: -18.5, z: -4, rot: 0.36 },
    { icon: "filter", sign: ["The", "Toolkit"], color: "#ffb347", x: -8.5, z: 9, rot: 0.14 },
    { icon: "shield", sign: ["The", "Line"], color: "#7fc8f8", x: 8, z: 9.5, rot: -0.12 },
    { icon: "siren", sign: ["Read", "Only"], color: "#ff6b5e", x: 18.5, z: -5.5, rot: -0.36 },
  ],
};

const ROOTACCOUNT: HallConfig = {
  title: "Root Hall",
  sub: "Westmarch Biotech cloud response",
  core: "globe",
  books: ["AWS", "Incident Response", "SOC"],
  cards: [
    { icon: "bag", name: ["The", "Bucket"], color: "#7ee0c3", art: "loot" },
    { icon: "filter", name: ["The", "Policy"], color: "#f5b971", art: "tree" },
    { icon: "lock", name: ["The", "Credentials"], color: "#9fc5ff", art: "lock" },
    { icon: "eye", name: ["The Dark", "Trail"], color: "#c9b6ff", art: "ghost" },
    { icon: "siren", name: ["Root", "Account"], color: "#ff5b61", art: "pulse" },
  ],
};

const PROJECTID: CampusConfig = {
  seed: 6481,
  hub: { title: "Fernhollow Games Studio", sub: "GCP SECURITY HUB" },
  buildings: [
    { icon: "wire", sign: ["The Org", "Tree"], color: "#9ae66e", x: -18, z: -9, rot: 0.34 },
    { icon: "filter", sign: ["The Audit", "Trail"], color: "#ffcf70", x: -13, z: 6.5, rot: 0.26 },
    { icon: "target", sign: ["The Mod Kit", "Key"], color: "#67c8ff", x: 9, z: 8.5, rot: -0.14 },
    { icon: "users", sign: ["The Partner", "Desk"], color: "#c9a7ff", x: 18.5, z: 2.5, rot: -0.42 },
    { icon: "siren", sign: ["The Six", "Minutes"], color: "#ff5d73", x: 14.5, z: -9.5, rot: -0.32 },
  ],
};

const SUBSCRIPTION: HallConfig = {
  title: "Subscription Hall",
  sub: "Rowan Grid Energy cloud response",
  core: "globe",
  books: ["Azure", "Incident Response", "SOC"],
  cards: [
    { icon: "compass", name: ["The Tenant", "Map"], color: "#6cb8ff", art: "tree" },
    { icon: "users", name: ["Who", "Called?"], color: "#f6d06f", art: "ghost" },
    { icon: "pulse", name: ["The Overnight", "Script"], color: "#7fd8c4", art: "pulse" },
    { icon: "lock", name: ["Contain or", "Close"], color: "#c7a8ff", art: "lock" },
    { icon: "siren", name: ["Twenty-Three", "Minutes"], color: "#ff6a55", art: "loot" },
  ],
};

const WIRETRANSFER: CampusConfig = {
  seed: 7723,
  hub: { title: "Harcourt & Vane", sub: "FRAUD DESK" },
  buildings: [
    { icon: "mail", sign: ["The", "Invoice"], color: "#e0c56e", x: -19, z: -7, rot: 0.36 },
    { icon: "monitor", sign: ["The Second", "Session"], color: "#7cc4f0", x: -12.5, z: 5, rot: 0.24 },
    { icon: "filter", sign: ["The Hidden", "Rule"], color: "#c9a8f0", x: -7, z: 9.5, rot: 0.1 },
    { icon: "wire", sign: ["The", "Timeline"], color: "#6fc7a8", x: 10, z: 8.5, rot: -0.16 },
    { icon: "siren", sign: ["The Money", "Clock"], color: "#ff5a5f", x: 19, z: -2, rot: -0.34 },
  ],
};

const MAPMAKER: HallConfig = {
  title: "The Map Room",
  sub: "Selkirk Timber Cooperative detection desk",
  core: "matrix",
  books: ["Discovery", "Threat Hunting", "SOC"],
  cards: [
    { icon: "users", name: ["The", "Whoami"], color: "#c9b458", art: "loot" },
    { icon: "layers", name: ["The Domain", "Question"], color: "#7fb6d6", art: "tree" },
    { icon: "compass", name: ["The Cloud", "Census"], color: "#a1d6b2", art: "axes" },
    { icon: "filter", name: ["Ten Are", "a Map"], color: "#e3b873", art: "pulse" },
    { icon: "target", name: ["The Finished", "Map"], color: "#e8563f", art: "lock" },
  ],
};

const CONTAINERBREAK: CampusConfig = {
  seed: 4789,
  hub: { title: "Northlight Streaming", sub: "PLATFORM SECURITY HUB" },
  buildings: [
    { icon: "monitor", sign: ["The", "Cluster"], color: "#ff9f5a", x: -18.5, z: -4.5, rot: 0.36 },
    { icon: "filter", sign: ["The Audit", "Trail"], color: "#6fd3ff", x: -10.5, z: 8.5, rot: 0.2 },
    { icon: "wire", sign: ["The", "Node"], color: "#c7f27a", x: 10.5, z: 9, rot: -0.18 },
    { icon: "siren", sign: ["Container", "Break"], color: "#ff4d6d", x: 19, z: -6, rot: -0.36 },
  ],
};

const RULEANDSIGN: HallConfig = {
  title: "The Rule Bench",
  sub: "Pelham Instruments detection content",
  core: "matrix",
  books: ["Sigma", "YARA", "SOC"],
  cards: [
    { icon: "target", name: ["The", "Sample"], color: "#9ad4d6", art: "loot" },
    { icon: "filter", name: ["The Sigma", "Rule"], color: "#ffd08a", art: "tree" },
    { icon: "layers", name: ["The YARA", "Rule"], color: "#c7b8ff", art: "axes" },
    { icon: "check", name: ["The", "Sign-Off"], color: "#ff5a6e", art: "pulse" },
  ],
};

const STOLENSESSION: CampusConfig = {
  seed: 6899,
  hub: { title: "Kingsmere Private Hospital", sub: "IDENTITY HUB" },
  buildings: [
    { icon: "mail", sign: ["The", "Cookie"], color: "#e8b36a", x: -18, z: -8, rot: 0.34 },
    { icon: "monitor", sign: ["Two", "Places"], color: "#8fd3ff", x: -14, z: 4.5, rot: 0.26 },
    { icon: "users", sign: ["The", "Push"], color: "#f2c14e", x: -7.5, z: 9, rot: 0.12 },
    { icon: "filter", sign: ["Other", "Tokens"], color: "#b9a7ff", x: 11, z: 8, rot: -0.18 },
    { icon: "siren", sign: ["After MFA", "Passed"], color: "#ff4f6d", x: 18.5, z: -4, rot: -0.36 },
  ],
};

const PLAINTEXT: HallConfig = {
  title: "Plaintext Hall",
  sub: "Oakmere Regional Rail credential exposure",
  core: "knot",
  books: ["Secrets", "Telemetry", "SOC"],
  cards: [
    { icon: "filter", name: ["The", "Share"], color: "#ffe27a", art: "loot" },
    { icon: "lock", name: ["The", "Keyring"], color: "#6ee7f0", art: "lock" },
    { icon: "layers", name: ["The Cloud", "Vault"], color: "#a5b4fc", art: "tree" },
    { icon: "eye", name: ["The Locked", "File"], color: "#86efac", art: "ghost" },
    { icon: "siren", name: ["The Last", "Read"], color: "#ff4f6d", art: "pulse" },
  ],
};

const LASTCLOUD: CampusConfig = {
  seed: 5839,
  hub: { title: "Aurelia Space Systems", sub: "CLOUD THREAT HUB" },
  buildings: [
    { icon: "filter", sign: ["The", "Trail"], color: "#b8c0ff", x: -19, z: -0.5, rot: 0.36 },
    { icon: "wire", sign: ["The", "Copies"], color: "#ffd166", x: -9.5, z: 9, rot: 0.16 },
    { icon: "monitor", sign: ["Below the", "Log"], color: "#7bdcb5", x: 7.5, z: 9.5, rot: -0.12 },
    { icon: "target", sign: ["The", "Baseline"], color: "#f7a072", x: 12.5, z: 8.5, rot: -0.2 },
    { icon: "siren", sign: ["Last", "Cloud"], color: "#ff5c7a", x: 19, z: 0.5, rot: -0.36 },
  ],
};

const HALL: HallConfig = {
  title: "Specimen Hall",
  sub: "Vantor Logistics malware lab",
  books: ["Incident Response", "Threat Hunting", "SOC"],
  cards: [
    { icon: "compass", name: ["How It", "Moves"], color: "#38bdf8", art: "axes" },
    { icon: "layers", name: ["First", "Stage"], color: "#a78bfa", art: "tree" },
    { icon: "pulse", name: ["The", "Heartbeat"], color: "#fbbf24", art: "pulse" },
    { icon: "bag", name: ["Grab and", "Leave"], color: "#2dd4bf", art: "loot" },
    { icon: "lock", name: ["Lock or", "Burn"], color: "#e879f9", art: "lock" },
    { icon: "eye", name: ["Under the", "Radar"], color: "#38bdf8", art: "ghost" },
  ],
};

const CHAIN: HallConfig = {
  title: "Chain Hall",
  sub: "Brightwater Utilities threat hunt",
  core: "chain",
  books: ["Threat Hunting", "Incident Response", "SOC"],
  cards: [
    { icon: "layers", name: ["Seven", "Links"], color: "#22d3ee", art: "axes" },
    { icon: "compass", name: ["Walk the", "Chain"], color: "#a78bfa", art: "tree" },
    { icon: "target", name: ["Break the", "Chain"], color: "#f43f5e", art: "pulse" },
    { icon: "filter", name: ["The", "Debrief"], color: "#fbbf24", art: "loot" },
  ],
};

const MATRIX: HallConfig = {
  title: "Matrix Hall",
  sub: "Marlow Aerospace threat intel",
  core: "matrix",
  books: ["Threat Intel", "Detection", "SOC"],
  cards: [
    { icon: "filter", name: ["Read the", "IDs"], color: "#f87171", art: "axes" },
    { icon: "target", name: ["The 15", "Goals"], color: "#fbbf24", art: "loot" },
    { icon: "eye", name: ["Blind", "Spots"], color: "#94a3b8", art: "ghost" },
    { icon: "siren", name: ["Map the", "Alert"], color: "#fb923c", art: "tree" },
    { icon: "mail", name: ["Tag the", "Report"], color: "#2dd4bf", art: "pulse" },
  ],
};

const BAIT: HallConfig = {
  title: "The Bait Shop",
  sub: "Brennan & Lowe Architects",
  core: "knot",
  books: ["Initial Access", "Threat Hunting", "SOC"],
  cards: [
    { icon: "mail", name: ["After", "Macros"], color: "#a3e635", art: "loot" },
    { icon: "monitor", name: ["The Fake", "CAPTCHA"], color: "#f472b6", art: "tree" },
    { icon: "wire", name: ["The Lying", "Clipboard"], color: "#38bdf8", art: "axes" },
    { icon: "target", name: ["The Sponsored", "Result"], color: "#fbbf24", art: "pulse" },
    { icon: "layers", name: ["The Disc", "Image"], color: "#c084fc", art: "lock" },
    { icon: "pulse", name: ["The Mining", "Tab"], color: "#f43f5e", art: "ghost" },
  ],
};

export function FacilityMail(props: WorldProps) { return <HallWorld cfg={MAIL} props={props} />; }
export function FacilityTriage(props: WorldProps) { return <HallWorld cfg={TRIAGE} props={props} />; }
export function FacilityTunnel(props: WorldProps) { return <HallWorld cfg={TUNNEL} props={props} />; }
export function FacilityHall(props: WorldProps) { return <HallWorld cfg={HALL} props={props} />; }
export function FacilityChain(props: WorldProps) { return <HallWorld cfg={CHAIN} props={props} />; }
export function FacilityMatrix(props: WorldProps) { return <HallWorld cfg={MATRIX} props={props} />; }
export function FacilityBait(props: WorldProps) { return <HallWorld cfg={BAIT} props={props} />; }
export function FacilitySoc(props: WorldProps) { return <CampusWorld cfg={SOC} props={props} />; }
export function FacilityNet(props: WorldProps) { return <CampusWorld cfg={NET} props={props} />; }
export function FacilityPacket(props: WorldProps) { return <CampusWorld cfg={PACKET} props={props} />; }
export function FacilityEntra(props: WorldProps) { return <CampusWorld cfg={ENTRA} props={props} />; }
export function FacilityDirectory(props: WorldProps) { return <CampusWorld cfg={DIRECTORY} props={props} />; }
export function FacilityCampus(props: WorldProps) { return <CampusWorld cfg={CAMPUS} props={props} />; }
export function FacilityLastWord(props: WorldProps) { return <CampusWorld cfg={LASTWORD} props={props} />; }
export function FacilityBreadcrumb(props: WorldProps) { return <HallWorld cfg={BREADCRUMB} props={props} />; }
export function FacilityTabletop(props: WorldProps) { return <CampusWorld cfg={TABLETOP} props={props} />; }
export function FacilityLooseThread(props: WorldProps) { return <HallWorld cfg={LOOSETHREAD} props={props} />; }
export function FacilityWhoGoes(props: WorldProps) { return <CampusWorld cfg={WHOGOES} props={props} />; }
export function FacilityPaperTrail(props: WorldProps) { return <HallWorld cfg={PAPERTRAIL} props={props} />; }
export function FacilityBadNews(props: WorldProps) { return <CampusWorld cfg={BADNEWS} props={props} />; }
export function FacilityFrontDoor(props: WorldProps) { return <HallWorld cfg={FRONTDOOR} props={props} />; }
export function FacilityAutopilot(props: WorldProps) { return <CampusWorld cfg={AUTOPILOT} props={props} />; }
export function FacilityCrownJewels(props: WorldProps) { return <HallWorld cfg={CROWNJEWELS} props={props} />; }
export function FacilitySharedDrive(props: WorldProps) { return <CampusWorld cfg={SHAREDDRIVE} props={props} />; }
export function FacilityModelBehaviour(props: WorldProps) { return <HallWorld cfg={MODELBEHAVIOUR} props={props} />; }
export function FacilityHelpingHand(props: WorldProps) { return <CampusWorld cfg={HELPINGHAND} props={props} />; }
export function FacilityExitRoute(props: WorldProps) { return <HallWorld cfg={EXITROUTE} props={props} />; }
export function FacilityLongGame(props: WorldProps) { return <CampusWorld cfg={LONGGAME} props={props} />; }
export function FacilityFirstRule(props: WorldProps) { return <HallWorld cfg={FIRSTRULE} props={props} />; }
export function FacilityDeepQuery(props: WorldProps) { return <CampusWorld cfg={DEEPQUERY} props={props} />; }
export function FacilitySealedRoom(props: WorldProps) { return <HallWorld cfg={SEALEDROOM} props={props} />; }
export function FacilitySideDoor(props: WorldProps) { return <CampusWorld cfg={SIDEDOOR} props={props} />; }
export function FacilityReturnPath(props: WorldProps) { return <HallWorld cfg={RETURNPATH} props={props} />; }
export function FacilityThreeHeads(props: WorldProps) { return <CampusWorld cfg={THREEHEADS} props={props} />; }
export function FacilityPagefile(props: WorldProps) { return <HallWorld cfg={PAGEFILE} props={props} />; }
export function FacilityProcessTree(props: WorldProps) { return <CampusWorld cfg={PROCESSTREE} props={props} />; }
export function FacilityColdVault(props: WorldProps) { return <HallWorld cfg={COLDVAULT} props={props} />; }
export function FacilityDiamond(props: WorldProps) { return <CampusWorld cfg={DIAMOND} props={props} />; }
export function FacilityHighCloud(props: WorldProps) { return <HallWorld cfg={HIGHCLOUD} props={props} />; }
export function FacilityChainOfCommand(props: WorldProps) { return <CampusWorld cfg={CHAINOFCOMMAND} props={props} />; }
export function FacilitySprayPaint(props: WorldProps) { return <HallWorld cfg={SPRAYPAINT} props={props} />; }
export function FacilityRunbook(props: WorldProps) { return <CampusWorld cfg={RUNBOOK} props={props} />; }
export function FacilityQuietForward(props: WorldProps) { return <HallWorld cfg={QUIETFORWARD} props={props} />; }
export function FacilityExtraDevice(props: WorldProps) { return <CampusWorld cfg={EXTRADEVICE} props={props} />; }
export function FacilityFullShift(props: WorldProps) { return <HallWorld cfg={FULLSHIFT} props={props} />; }
export function FacilityFinalReport(props: WorldProps) { return <CampusWorld cfg={FINALREPORT} props={props} />; }
export function FacilitySingleSignOff(props: WorldProps) { return <HallWorld cfg={SINGLESIGNOFF} props={props} />; }
export function FacilityFamiliarVoice(props: WorldProps) { return <CampusWorld cfg={FAMILIARVOICE} props={props} />; }
export function FacilityHoldMusic(props: WorldProps) { return <HallWorld cfg={HOLDMUSIC} props={props} />; }
export function FacilityLongShadow(props: WorldProps) { return <CampusWorld cfg={LONGSHADOW} props={props} />; }
export function FacilityMasterKey(props: WorldProps) { return <HallWorld cfg={MASTERKEY} props={props} />; }
export function FacilitySignalNoise(props: WorldProps) { return <CampusWorld cfg={SIGNALNOISE} props={props} />; }
export function FacilityFinePrint(props: WorldProps) { return <HallWorld cfg={FINEPRINT} props={props} />; }
export function FacilityQuietWire(props: WorldProps) { return <CampusWorld cfg={QUIETWIRE} props={props} />; }
export function FacilitySidestep(props: WorldProps) { return <HallWorld cfg={SIDESTEP} props={props} />; }
export function FacilityOpenSource(props: WorldProps) { return <CampusWorld cfg={OPENSOURCE} props={props} />; }
export function FacilityRootAccount(props: WorldProps) { return <HallWorld cfg={ROOTACCOUNT} props={props} />; }
export function FacilityProjectId(props: WorldProps) { return <CampusWorld cfg={PROJECTID} props={props} />; }
export function FacilitySubscription(props: WorldProps) { return <HallWorld cfg={SUBSCRIPTION} props={props} />; }
export function FacilityWireTransfer(props: WorldProps) { return <CampusWorld cfg={WIRETRANSFER} props={props} />; }
export function FacilityMapMaker(props: WorldProps) { return <HallWorld cfg={MAPMAKER} props={props} />; }
export function FacilityContainerBreak(props: WorldProps) { return <CampusWorld cfg={CONTAINERBREAK} props={props} />; }
export function FacilityRuleAndSign(props: WorldProps) { return <HallWorld cfg={RULEANDSIGN} props={props} />; }
export function FacilityStolenSession(props: WorldProps) { return <CampusWorld cfg={STOLENSESSION} props={props} />; }
export function FacilityPlaintext(props: WorldProps) { return <HallWorld cfg={PLAINTEXT} props={props} />; }
export function FacilityLastCloud(props: WorldProps) { return <CampusWorld cfg={LASTCLOUD} props={props} />; }
