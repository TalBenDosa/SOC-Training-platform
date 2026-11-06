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
