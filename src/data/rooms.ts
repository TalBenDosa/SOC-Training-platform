/**
 * Learning Rooms — SOC Training Platform
 *
 * 62 progressive rooms taking a student from zero technical knowledge
 * through to advanced SOC analyst skills. Each room contains readings,
 * multiple-choice questions, hands-on log analysis, and CTF flag tasks.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { roomsBatch18 } from "./rooms-batch-18";
import { roomsBatch19 } from "./rooms-batch-19";

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
  language: "kql" | "spl";
  context: string;          // the investigative question the query answers
  template: string;         // e.g. "SecurityEvent\n| where EventID == {{eventid}}\n| where TargetAccount == {{account}}"
  blanks: { id: string; answers: string[]; placeholder?: string }[];
  explanation: string;
  xp: number;
}

export type RoomTask = ReadingTask | QuestionTask | LogAnalysisTask | FlagTask | AnalystChoiceTask | MatchingTask | OrderingTask | QueryFillTask;

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
];
