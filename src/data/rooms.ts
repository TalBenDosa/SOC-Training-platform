/**
 * Learning Rooms — SOC Training Platform
 *
 * 62 progressive rooms taking a student from zero technical knowledge
 * through to advanced SOC analyst skills. Each room contains readings,
 * multiple-choice questions, hands-on log analysis, and CTF flag tasks.
 *
 * SERVER-ONLY, BY CONVENTION. Every task's answer/answers/correct_verdict/
 * correct_order field lives in here — this is the full content, including the
 * answer key. A build leaked it once (pentest finding, Aug 2026): four
 * "use client" components value-imported ROOMS directly and shipped every
 * answer to the browser bundle.
 *
 * Client code that needs room data must use the sanitized `ROOMS_META` in
 * src/data/roomsMeta.ts (list/progress/card/recommender views), or the sanitized
 * per-room payload from src/lib/rooms/sanitize.ts (the room-detail page passes
 * this to the player), or call the server-side grading API at
 * /api/rooms/[id]/tasks/[taskId]/submit (src/lib/rooms/grading.ts). Neither path
 * ever puts an answer field in a response before the student has genuinely
 * attempted that task.
 *
 * We deliberately do NOT use the `server-only` npm package here: it throws
 * unconditionally on import (not just in a browser), which breaks every
 * tsx-run content script that legitimately needs the real ROOMS array
 * (scripts/validate-content.mjs, scripts/generate-rooms-meta.mjs, the backend
 * test harnesses). Enforcement instead lives in
 * scripts/validate-content.mjs's "no client value-imports of @/data/rooms"
 * check, which greps every "use client" file for a non-type-only import from
 * this module and fails the content gate if it finds one.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { roomsBatch18 } from "./rooms-batch-18";
import { roomsBatch19 } from "./rooms-batch-19";
import { roomsBatch20 } from "./rooms-batch-20";
import { roomsBatch21 } from "./rooms-batch-21";
import { roomsBatch22 } from "./rooms-batch-22";
import { roomsBatch23 } from "./rooms-batch-23";
import { roomsBatch24 } from "./rooms-batch-24";
import { roomsBatch25 } from "./rooms-batch-25";
import { roomsBatch26 } from "./rooms-batch-26";
import { roomsBatch27 } from "./rooms-batch-27";
import { roomsBatch28 } from "./rooms-batch-28";
import { roomsBatch29 } from "./rooms-batch-29";
import { roomsBatch30 } from "./rooms-batch-30";
import { roomsBatch31 } from "./rooms-batch-31";

import roomsBatch01 from "@/data/rooms-batch-01";
import roomsBatch02 from "@/data/rooms-batch-02";
import roomsBatch03 from "@/data/rooms-batch-03";
import roomsBatch04 from "@/data/rooms-batch-04";
import roomsBatch05 from "@/data/rooms-batch-05";
import roomsBatch06 from "@/data/rooms-batch-06";
import roomsBatch07 from "@/data/rooms-batch-07";
import roomsBatch08 from "@/data/rooms-batch-08";
import roomsBatch09 from "@/data/rooms-batch-09";
import roomsBatch10 from "@/data/rooms-batch-10";
import roomsBatch11 from "@/data/rooms-batch-11";
import roomsBatch12 from "@/data/rooms-batch-12";
import roomsBatch13 from "@/data/rooms-batch-13";
import roomsBatch14 from "@/data/rooms-batch-14";
import roomsBatch15 from "@/data/rooms-batch-15";
import roomsBatch16 from "@/data/rooms-batch-16";
import roomsBatch17 from "@/data/rooms-batch-17";

// ---------------------------------------------------------------------------
// Task types
// ---------------------------------------------------------------------------

export interface ReadingTask {
  type: "reading";
  id: string;
  heading: string;
  content: string;       // markdown-like text with \n\n for paragraphs
  codeExample?: string;  // optional code/log block
  /**
   * Optional Mermaid diagram source (flowchart, sequenceDiagram, etc.) rendered
   * below the content. Used for the structural ideas that a wall of text
   * explains badly — protocol handshakes, kill chains, ticket flows, trust
   * relationships. Kept as SOURCE rather than an image so the labels (ports,
   * flags, field names) stay exact, searchable and reviewable in git.
   */
  diagram?: string;
  /** Caption shown on the diagram's header bar. Defaults to "Diagram". */
  diagramCaption?: string;
  /**
   * Optional inline comprehension check shown after the content — a quick,
   * UNGRADED retrieval prompt that turns passive reading into active recall.
   * The student must answer it correctly before the reading can be completed,
   * but it never affects the room's pass score (reading stays non-gradeable —
   * see taskMaxXp). It is a forcing function to actually read, not a hint: it
   * asks about a fact stated in the content just above it. Wrong answers simply
   * prompt a retry with the explanation.
   */
  checkpoint?: {
    question: string;
    options: string[];
    answer: number;        // 0-based index
    explanation?: string;
  };
  /**
   * Symbolic "engagement" XP awarded on completing the reading, to give a
   * feedback loop in the otherwise 0-XP reading third of each room. It is added
   * ONLY to the global/rank XP total — never to the room's graded score — so the
   * 65% mastery gate stays based purely on gradeable tasks. Defaults to 5.
   */
  xp?: number;
}

export interface QuestionTask {
  type: "question";
  id: string;
  question: string;
  options: string[];
  answer: number;        // 0-based index
  explanation: string;
  xp: number;
}

export interface LogAnalysisTask {
  type: "log_analysis";
  id: string;
  heading: string;
  context: string;       // "You're a SOC analyst reviewing this alert..."
  event: TelemetryEvent;
  questions: {
    question: string;
    options: string[];
    answer: number;
    explanation: string;
    xp: number;
  }[];
}

export interface FlagTask {
  type: "flag";
  id: string;
  prompt: string;
  answer: string;        // exact string, case-insensitive match
  hint?: string;
  xp: number;
}

export interface AnalystChoiceTask {
  type: "analyst_choice";
  id: string;
  heading: string;
  scenario: string;
  event: TelemetryEvent;
  correct_verdict: "true_positive" | "false_positive" | "escalate" | "informational";
  explanation: string;
  fp_trap?: string;
  xp: number;
}

export interface MatchingTask {
  type: "matching";
  id: string;
  heading: string;
  instructions: string;
  pairs: { id: string; left: string; right: string; }[];
  explanation: string;
  xp: number;
}

export interface OrderingTask {
  type: "ordering";
  id: string;
  heading: string;
  instructions: string;
  items: { id: string; text: string; }[];
  correct_order: string[];
  explanation: string;
  xp: number;
}

/**
 * Fill-in-the-blank query task — the one place a student actually WRITES a
 * KQL/SPL query fragment instead of only reading one in a codeExample or
 * picking a multiple-choice answer about what a pre-written query does.
 * `template` embeds each blank as {{blankId}}; `blanks` gives the accepted
 * answer(s) per id (matched case-insensitively, trimmed — operator spacing
 * and quote style shouldn't fail a semantically-correct answer).
 */
export interface QueryFillTask {
  type: "query_fill";
  id: string;
  heading: string;
  language: "kql" | "spl" | "powershell";
  context: string;          // the investigative question the query answers
  template: string;         // e.g. "SecurityEvent\n| where EventID == {{eventid}}\n| where TargetAccount == {{account}}"
  blanks: { id: string; answers: string[]; placeholder?: string }[];
  explanation: string;
  xp: number;
}

/**
 * A free-text written deliverable, graded by a deterministic rubric — the one
 * place in Rooms a student actually WRITES an incident-report paragraph
 * instead of only recognising correct structure via reading/ordering/matching.
 * Mirrors the approach the scenario grader (src/app/api/scenarios/[slug]/
 * grade/route.ts) uses for its free-text report — depth by word count,
 * evidence by citing the case's own real indicators, a fabrication penalty
 * for inventing indicators that appear nowhere in the case — reimplemented
 * here as a fully synchronous Rooms-native rubric (see gradeTask in
 * src/lib/rooms/grading.ts) rather than reusing that route, since it is
 * scenario-shaped (quiz + report) where this is Rooms-shaped (one task).
 *
 * `referenceIocs` is the case's real indicator list, used server-side only to
 * score citation and detect fabrication — never sent to the client (see
 * sanitize.ts). It is not a new leak: every value in it is already visible to
 * the student through this room's own embedded log_analysis/analyst_choice
 * events earlier in the same case, and the flag task publishes one directly.
 */
export interface WrittenReportTask {
  type: "written_report";
  id: string;
  heading: string;
  context: string;        // scenario framing — always visible
  prompt: string;          // the specific deliverable asked for — always visible
  rubricHints: string[];   // "a strong answer will..." guidance shown WHILE writing, not the answer itself
  referenceIocs: string[]; // real indicators from the case, for evidence/fabrication scoring — server-only
  minWords: number;        // word count the depth tier treats as "substantial"
  explanation: string;     // standards note shown only after submission — server-only pre-submit
  xp: number;
}

export type RoomTask = ReadingTask | QuestionTask | LogAnalysisTask | FlagTask | AnalystChoiceTask | MatchingTask | OrderingTask | QueryFillTask | WrittenReportTask;

// ---------------------------------------------------------------------------
// Room type
// ---------------------------------------------------------------------------

export interface Room {
  id: string;
  title: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  estimatedMinutes: number;
  xp: number;           // total XP for room (sum of all task XP + base)
  icon: string;         // emoji
  prerequisites: string[];   // room IDs that must be completed first
  tasks: RoomTask[];
}

// ---------------------------------------------------------------------------
// Combined curriculum
// ---------------------------------------------------------------------------

const cast = (b: unknown[]) => b as Room[];

export const ROOMS: Room[] = [
  ...cast(roomsBatch01),  // intro-cybersecurity, soc-structure, cyber-kill-chain, mitre-attack
  ...cast(roomsBatch02),  // networking-fundamentals, networking-protocols, firewall-network-security, windows-fundamentals
  ...cast(roomsBatch03),  // active-directory, windows-event-logs, linux-fundamentals, linux-log-analysis
  ...cast(roomsBatch04),  // log-management, siem-fundamentals, wazuh-fundamentals, sentinel-fundamentals
  ...cast(roomsBatch05),  // detection-rules-tuning, log-sources-integration, microsoft-365-security, entra-id
  ...cast(roomsBatch06),  // exchange-online-security, sharepoint-teams-monitoring, endpoint-security, defender-xdr
  ...cast(roomsBatch07),  // crowdstrike-falcon, sentinelone, malware-analysis, ioc-analysis
  ...cast(roomsBatch08),  // threat-intelligence, osint-fundamentals, incident-response, alert-triage
  ...cast(roomsBatch09),  // investigation-methodology, threat-hunting, digital-forensics, email-security
  ...cast(roomsBatch10),  // phishing-analysis, vpn-monitoring, firewall-log-analysis, dns-investigation
  ...cast(roomsBatch11),  // auth-identity-monitoring, privileged-access-monitoring, cloud-security-monitoring, detection-engineering
  ...cast(roomsBatch12),  // use-case-development, reporting-documentation, customer-communication, escalation-procedures
  ...cast(roomsBatch13), // protocols-masterclass, firewall-masterclass, av-vs-edr-masterclass, nac-masterclass
  ...cast(roomsBatch14), // aws-security, analyst-mindset, edge-case-usecases, dlp-fundamentals, gcp-security, soar-automation
  ...cast(roomsBatch15), // kubernetes-container-security
  ...cast(roomsBatch16), // azure-security
  ...cast(roomsBatch17), // tcpip-deep-dive, dns-deep-dive, tls-encrypted-traffic, windows-protocols-lateral, email-protocols-forensics, tunneling-c2-channels
  ...cast(roomsBatch18), // kerberos-authentication, windows-privilege-escalation, persistence-mechanisms
  ...cast(roomsBatch19), // vulnerability-management, memory-disk-forensics
  ...cast(roomsBatch20), // encoding-encryption-hashing, timestamps-and-timelines
  ...cast(roomsBatch21), // log-entry-anatomy, identity-basics
  ...cast(roomsBatch22), // malware-types, asset-context-prioritisation
  ...cast(roomsBatch23), // security-products-behaviour
  ...cast(roomsBatch24), // credential-attacks-practice, lateral-movement-practice, web-attacks-practice
  ...cast(roomsBatch25), // web-application-security (theory prereq for web-attacks-practice)
  ...cast(roomsBatch26), // playbook-execution-and-escalation
  ...cast(roomsBatch27), // remote-email-collection, device-registration-persistence
  ...cast(roomsBatch28), // edr-detection-investigation
  ...cast(roomsBatch29), // investigate-alert-workflow, incident-report-writing
  ...cast(roomsBatch30), // risk-fundamentals
  ...cast(roomsBatch31), // powershell-for-soc-analyst
];
