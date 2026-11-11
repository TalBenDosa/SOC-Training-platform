import type { RoomExperience } from "./types";

// "Operation Clear Sky" for the "sentinel-fundamentals" room.
// Script: docs/campaign/36-sentinel-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Practical missions (SPEC-practical-missions.md): the graded work is six
// missions (src/lib/missions/rooms/clearSky.ts). The learner works in the
// investigation console (our own XDR design, console "clear-sky": the queue,
// detections, hunts, entity pages, incident pages) and writes KQL against
// Ashgrove's workspace (dataset "clear-sky"). The server grades each query by its
// RESULT on that workspace and on a shadow copy, and each console step by the facts
// typed and the incidents' state (owner, status, classification, comments,
// bookmarks). Owner 2026-11-11: the room must teach the interface and incident
// investigation, not only KQL. The scripted portal lab on Reading 3 left the room:
// the real console replaced it.
export const SENTINEL_FUNDAMENTALS: RoomExperience = {
  roomId: "sentinel-fundamentals",
  codename: "Operation Clear Sky",
  theme: "sentinel",
  handler: { name: "Malik Haddad", role: "Sentinel Architect, Ashgrove Pharmacy" },
  briefing: [
    "Ashgrove Pharmacy. 310 shops, a prescription system that must never go down, and everything already living in Microsoft 365 and Azure.",
    "Last month Ashgrove moved its SIEM to Microsoft Sentinel. The logs are flowing. Most of the team can't read them yet.",
    "Malik Haddad designed the workspace. He wants analysts who know which table to open, can write the query themselves, and can tell an incident from noise.",
    "Learn the console the way it is used on shift, the workspace's tables and KQL, then work real incidents: take them, read the evidence, record it, and close them with the right classification.",
  ],
  mission: "Learn the console's queue, detections, hunts and entity pages, write the queries yourself against Ashgrove's workspace, work incident 4412 in the console from owner to bookmarked evidence, read a raw sign-in row, then hunt the spray and put the queue right.",
  estimate: "~95 min",
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
      label: "Console and Tables",
      topic: "The incident queue · detections · hunts · entity pages · SigninLogs, AuditLogs, OfficeActivity, DeviceProcessEvents",
      tagline: "Know where everything lives",
      building: "control",
      taskIds: ["sentinel-r1", "sentinel-m0", "sentinel-m1"],
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
      label: "Work the Incident",
      topic: "Scheduled, NRT, Fusion and anomaly rules · owner and status · alert evidence · pivoting · bookmarks and comments",
      tagline: "Take it, read it, pivot, record it",
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
      topic: "dcountif, countif, bin() · a spray against a busy NAT · classifications · closing incidents",
      tagline: "Hunt it, make the call, close it right",
      building: "ticket",
      taskIds: ["sentinel-m5"],
      boss: true,
    },
  ],
  personas: {
    "sentinel-m0": { name: "Malik Haddad", role: "Sentinel Architect", line: "Sentinel is not a query box. Learn where everything lives first." },
    "sentinel-m1": { name: "Malik Haddad", role: "Sentinel Architect", line: "Three tickets. Three tables. Write the queries yourself." },
    "sentinel-m2": { name: "Malik Haddad", role: "Sentinel Architect", line: "Three countries in a week. A traveller, or a shared password?" },
    "sentinel-q2": { name: "Malik Haddad", role: "Sentinel Architect", line: "Impossible travel, our own thresholds, every five minutes. Which rule type?" },
    "sentinel-m3": { name: "Malik Haddad", role: "Sentinel Architect", line: "Take it, read the evidence, pivot, and write it on the incident." },
    "sentinel-m4": { name: "Malik Haddad", role: "Sentinel Architect", line: "No portal, no tooltips. Read the row like evidence." },
    "sentinel-m5": { name: "Malik Haddad", role: "Sentinel Architect", line: "Catch every spray, then put the queue right." },
  },
};
