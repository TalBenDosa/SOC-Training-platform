import type { VideoRef } from "@/lib/media/videos";

// Curated explainer videos (feedback FB-008). Every entry was verified against
// YouTube's oEmbed endpoint (HTTP 200 => exists + embeddable); title/channel are
// copied verbatim from its title/author_name, minutes from the watch page length.
// Reputable educational channels only; prefer < 15 min. Verified 2026-09-28.
// Integrity (valid ids, keys exist in ROOMS_META / LESSON_PATHS) is checked by
// src/data/videos.test.ts.

/** Explainer videos per Learning Path lesson. Keyed by "pathSlug--lessonSlug". */
export const LESSON_VIDEOS: Record<string, VideoRef[]> = {
  "soc-analyst--what-is-a-soc": [
    { youtubeId: "OHkWXFheSKM", title: "Security Operations Center (SOC) Explained", channel: "IBM Technology", minutes: 6 },
  ],
  "soc-analyst--mental-models-for-triage": [
    { youtubeId: "k9c1PBynVpA", title: "SOC Alert Triage Explained: What Most Beginners Get Wrong", channel: "MyDFIR", minutes: 5 },
  ],
  "soc-analyst--reading-edr-alerts": [
    { youtubeId: "55GaIolVVqI", title: "What is Endpoint Detection and Response (EDR)?", channel: "IBM Technology", minutes: 6 },
  ],
  "soc-analyst--process-trees-in-depth": [
    { youtubeId: "s98_p3bheL0", title: "Windows Process Genealogy", channel: "13Cubed", minutes: 23 },
  ],
  "soc-analyst--tactics-and-techniques": [
    { youtubeId: "8Q6fts0KJ4o", title: "How to Actually Use MITRE ATT&CK as a Beginner (Not Just Memorize It)", channel: "MyDFIR", minutes: 7 },
  ],
  "threat-hunter--ttp-based-hunting": [
    { youtubeId: "VNp35Uw_bSM", title: "Cybersecurity Threat Hunting Explained", channel: "IBM Technology", minutes: 7 },
  ],
  "threat-hunter--kql-joins": [
    { youtubeId: "8qZx7Pp5XgM", title: "Joining tables in KQL | Microsoft 365 Defender", channel: "Microsoft Security", minutes: 4 },
  ],
  "incident-responder--ir-phases-overview": [
    { youtubeId: "X2UiMLxRdhE", title: "Incident Response - CompTIA Security+ SY0-701 - 4.8", channel: "Professor Messer", minutes: 9 },
  ],
  "incident-responder--triage-acquisition": [
    { youtubeId: "UtDWApdO8Zk", title: "Digital Forensics - CompTIA Security+ SY0-701 - 4.8", channel: "Professor Messer", minutes: 10 },
  ],
  "incident-responder--memory-forensics-basics": [
    { youtubeId: "1PAGcPJFwbE", title: "Introduction to Memory Forensics", channel: "13Cubed", minutes: 23 },
  ],
  "detection-engineer--edr-vs-sysmon": [
    { youtubeId: "kESndPO5Fig", title: "Learning Sysmon - What is Sysmon? (Video 1)", channel: "TrustedSec", minutes: 12 },
  ],
  "purple-team--atomic-red-team": [
    { youtubeId: "eAtlwqXDZYc", title: "Atomic Red Team explained: Open source testing for security teams", channel: "Red Canary, a Zscaler company", minutes: 8 },
  ],
};
