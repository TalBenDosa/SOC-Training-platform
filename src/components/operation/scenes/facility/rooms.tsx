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
