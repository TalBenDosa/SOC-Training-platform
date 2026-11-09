/**
 * Log realism gate: the shared row and violation shapes.
 *
 * A collector turns one surface (Live Feed, Scenarios, Team Training, XDR, EDR, forensic workbench,
 * learning rooms) into a flat list of LogRow: every log a learner can see there, in the form the page
 * really shows it (the native record when the page renders native, the authored raw block when it
 * shows raw, the tool table row when it shows a tool view). A checker reads LogRows only, so one rule
 * is enforced the same way on every surface (docs/LOG-REALISM-STANDARD.md).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog } from "@/lib/logs/native/types";

export type Surface = "live" | "scenario" | "team" | "xdr" | "edr" | "forensic" | "room";
export const SURFACES: Surface[] = ["live", "scenario", "team", "xdr", "edr", "forensic", "room"];

export type RuleId = "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7" | "R8" | "R9";
export const RULES: RuleId[] = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"];

export interface LogRow {
  surface: Surface;
  /** Built-in company the row belongs to (live, team, xdr), when there is one. */
  company?: string;
  /** The unit a learner sees as one case: a story instance, a scenario slug, a team session, a room id. */
  storyId?: string;
  /** Stable id of the row inside its surface (deterministic across runs). */
  rowId: string;
  /** Native source id, KQL table, tool plugin, or the authored vendor label. */
  source: string;
  vendor?: string;
  /** Native kind, event type, or table row kind. */
  eventType: string;
  /** Epoch ms of the row as the page shows it (the feed's time column). */
  time?: number;
  /** Ground truth: true for attack rows, false for benign / noise / decoy, undefined when unknown. */
  isAttack?: boolean;
  /** What the learner reads: the native record, the authored raw block, a table row, or a text line. */
  raw: Record<string, unknown> | string;
  /** The wire line or the visible text beside the record. */
  text?: string;
  /** Severity as the row shows it (lower case), when it has one. */
  severity?: string;
  /** The event behind the row (internal: process / host / user facts, authored description). */
  ev?: TelemetryEvent;
  /** The native log, when the row is one. */
  native?: NativeLog;
  /** Index of the row inside its story, in authored order (R4 monotone check). */
  storyIndex?: number;
  /** Authored time of the row's event before the feed re-timed it (R4 monotone check). */
  authoredTime?: number;
  /** Source file for authored content (rooms). */
  file?: string;
  /** Extra per-surface facts a checker may read (EDR process, alert links, ...). */
  meta?: Record<string, unknown>;
}

export interface Violation {
  surface: Surface;
  rule: RuleId;
  /** The row (or group / story) the violation is about. */
  rowId: string;
  /** Short, stable description (no times or random ids), so the baseline key is stable. */
  detail: string;
  company?: string;
  storyId?: string;
  /** Free text for the report only (never part of the key). */
  example?: string;
}

/** Stable baseline key. */
export const violationKey = (v: Violation) => `${v.surface}|${v.rule}|${v.rowId}|${v.detail}`;

/** Everything one run collected, per surface, plus surface-level facts some checkers need. */
export interface Collected {
  rows: LogRow[];
  /** Feeds a learner triages (live per company, team per session): rows in the feed order. */
  feeds: { surface: Surface; id: string; company?: string; rows: LogRow[]; note?: string }[];
  /** Notes from the collectors (counts, what was skipped and why). */
  notes: string[];
}

export type Checker = (c: Collected) => Violation[];
