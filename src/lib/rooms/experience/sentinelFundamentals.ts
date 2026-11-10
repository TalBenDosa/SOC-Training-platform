import type { RoomExperience } from "./types";
import { SENTINEL_INCIDENT_LAB } from "./consoleLabs";

// "Operation Clear Sky" for the "sentinel-fundamentals" room.
// Script: docs/campaign/36-sentinel-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Practical-missions pilot (SPEC-practical-missions.md): the graded work is five
// missions (src/lib/missions/rooms/clearSky.ts) in which the learner writes KQL
// against Ashgrove's workspace (dataset "clear-sky") and states the facts; the
// server grades each query by its RESULT on that workspace and on a shadow copy.
// Arcade labs left the room. The one lab kept is the incident console on
// Reading 3 (incident 2291, its own data): it never shows incident 4412, its
// IP 198.51.100.23, the travel accounts or the spray sources the missions use,
// and it never picks a rule type (q2).
export const SENTINEL_FUNDAMENTALS: RoomExperience = {
  roomId: "sentinel-fundamentals",
  codename: "Operation Clear Sky",
  theme: "sentinel",
  handler: { name: "Malik Haddad", role: "Sentinel Architect, Ashgrove Pharmacy" },
  briefing: [
    "Ashgrove Pharmacy. 310 shops, a prescription system that must never go down, and everything already living in Microsoft 365 and Azure.",
    "Last month Ashgrove moved its SIEM to Microsoft Sentinel. The logs are flowing. Most of the team can't read them yet.",
    "Malik Haddad designed the workspace. He wants analysts who know which table to open, can write the query themselves, and can tell an incident from noise.",
    "Learn the workspace and its tables, KQL, analytics rules and incidents, then read the raw event behind an alert.",
  ],
  mission: "Open the right table for each ticket, write the queries yourself against Ashgrove's workspace, pivot an incident on its IP, read a raw sign-in row, and hunt the password spray.",
  estimate: "~70 min",
  look: { primary: "#0ea5e9", secondary: "#c084fc", warn: "#f43f5e" },
  scene: "facilitysentinelfundamentals",
  layout: "facility",
  story: {
    intro: { title: "The Logs Are Flowing", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-intro-1a1e3662.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-intro-17f65a10.jpg" },
    afterStation: {
      kql: { title: "Four Countries in a Week", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch2-6c0f44b9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch2-efcff862.jpg" },
      incidents: { title: "Incident 4412", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch3-885af19d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch3-5fe5acb8.jpg" },
      boss: { title: "Query, Build, Decide", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-finale-d1757c53.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-finale-9d7d0a45.jpg" },
    },
  },
  stations: [
    {
      id: "tables",
      label: "Workspace and Tables",
      topic: "Log Analytics workspace · data connectors · SigninLogs, AuditLogs, OfficeActivity, DeviceProcessEvents",
      tagline: "Know which table to open",
      building: "control",
      taskIds: ["sentinel-r1", "sentinel-m1"],
    },
    {
      id: "kql",
      label: "Speak KQL",
      topic: "where, ago(), string vs number, summarize dcount() by, make_set",
      tagline: "Write the travel rule yourself",
      building: "lab",
      taskIds: ["sentinel-r2", "sentinel-m2"],
    },
    {
      id: "incidents",
      label: "Rules to Incidents",
      topic: "Scheduled, NRT, Fusion and anomaly rules · incidents · entities · pivoting",
      tagline: "From an incident to everyone it touched",
      building: "office",
      taskIds: ["sentinel-r3", "sentinel-q2", "sentinel-m3"],
    },
    {
      id: "event",
      label: "Inside the Event",
      topic: "Reading the raw SigninLogs row behind an alert",
      tagline: "Drill down to the evidence",
      building: "vault",
      taskIds: ["sentinel-m4"],
    },
    {
      id: "boss",
      label: "Call the Spray",
      topic: "dcountif, countif, bin() · a spray against a busy NAT · the verdict",
      tagline: "Hunt it, then make the call",
      building: "ticket",
      taskIds: ["sentinel-m5"],
      boss: true,
    },
  ],
  personas: {
    "sentinel-m1": { name: "Malik Haddad", role: "Sentinel Architect", line: "Three tickets. Three tables. Write the queries yourself." },
    "sentinel-m2": { name: "Malik Haddad", role: "Sentinel Architect", line: "Three countries in a week. A traveller, or a shared password?" },
    "sentinel-q2": { name: "Malik Haddad", role: "Sentinel Architect", line: "Impossible travel, our own thresholds, every five minutes. Which rule type?" },
    "sentinel-m3": { name: "Malik Haddad", role: "Sentinel Architect", line: "The incident gives you one account. Pivot on the address." },
    "sentinel-m4": { name: "Malik Haddad", role: "Sentinel Architect", line: "No portal, no tooltips. Read the row like evidence." },
    "sentinel-m5": { name: "Malik Haddad", role: "Sentinel Architect", line: "Catch every spray. Do not page me for the 08:00 shift change." },
  },
  briefings: {
    // Reading 3: the incident console (its own incident 2291), a tool, not a game.
    "sentinel-r3": [SENTINEL_INCIDENT_LAB],
  },
};
