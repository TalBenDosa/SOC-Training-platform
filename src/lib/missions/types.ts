/**
 * Practical missions: the room task type in which the learner does the analyst's
 * work itself (writes a query, collects indicators, writes a rule, writes a
 * finding) and the SERVER checks the result of that work.
 *
 * Spec: research/rooms-practical-tasks/SPEC-practical-missions.md (pilot rooms
 * 36, 61, 107).
 *
 * A mission is a short chain of STEPS inside one story beat. Each step is graded
 * on its own (like a log_analysis question: per-step attempts, per-step XP, per-
 * step pass credit), so a learner can check the first ticket before writing the
 * second, and a chain that pivots from fact to fact can unlock step by step.
 *
 * Fields marked SERVER-ONLY never reach the browser: src/lib/rooms/sanitize.ts
 * strips them. The visible data a step needs (tables, files, events, artefacts)
 * is evidence and ships to the client, so "Run" is instant and free; only
 * "Check" goes to the server, which also runs the work on a SHADOW copy of the
 * data with different values, so an answer typed in from the screen fails.
 */
import type { KqlType } from "@/lib/kql/types";

/** A fixture table. Datetime cells are ISO strings in the data and become Dates on load (hydrate.ts). */
export interface MissionTable {
  name: string;
  columns: { name: string; type: KqlType }[];
  rows: Record<string, unknown>[];
}

export interface MissionDataset {
  /** The value of now() for the step's queries (ISO). */
  now: string;
  tables: MissionTable[];
}

/** One raw artefact shown in the workbench: an email source, a log line, a ticket. Evidence, never an answer. */
export interface MissionArtifact {
  id: string;
  title: string;
  /** "mono" shows it as a raw block (headers, log lines); "text" as prose (a ticket, a note). */
  format: "mono" | "text";
  body: string;
}

// ─── Field normalisers ────────────────────────────────────────────────────────

/**
 * How a typed value is compared:
 *  - text:   trimmed, case-insensitive, whitespace collapsed; `accept` may hold `re:<pattern>` entries
 *  - ip / domain / url / email / hash / host / account: refanged ([.] hxxp), lower-cased, trailing dot dropped
 *  - int / number: thousands separators dropped; `tolerance` is absolute; units in `units` multiply (1.4 GB)
 *  - utc:    a time of day or date-time, compared to the minute (tolerance in minutes)
 *  - set:    comma/newline separated list, compared as a set with the per-item `item` normaliser
 *  - choice: one of `options`, exact
 */
export type FieldFormat = "text" | "ip" | "domain" | "url" | "email" | "hash" | "host" | "account" | "int" | "number" | "utc" | "set" | "choice";

export interface MissionField {
  id: string;
  label: string;
  format: FieldFormat;
  placeholder?: string;
  /** For `choice`. */
  options?: string[];
  /** For `set`: how each item is normalised. */
  item?: Exclude<FieldFormat, "set" | "choice">;
  /** SERVER-ONLY. Accepted values (any one, or for `set` the exact set). */
  accept: string[];
  /** SERVER-ONLY. Numeric tolerance (int/number: absolute; utc: minutes). */
  tolerance?: number;
  /** SERVER-ONLY. Shown when this field is wrong. Explains with the evidence, never the value. */
  coach?: string;
  /** SERVER-ONLY. Specific wrong values with their own coaching ("10.10.1.25 is your own relay"). */
  traps?: { value: string; say: string }[];
}

// ─── Step kinds ───────────────────────────────────────────────────────────────

/** How a KQL step compares the learner's result with the reference's (SERVER-ONLY). */
export interface KqlAnswerSpec {
  /** One or more reference queries; the learner passes if any one matches on BOTH datasets. */
  reference: string[];
  /**
   * - "values": the distinct values of `keys[0]` in the reference result must equal the distinct
   *    values of SOME column of the learner's result (extra columns and duplicates are fine).
   * - "rows":   the reference rows projected on `keys` must equal, as a multiset (a set when
   *    `distinct`), the learner's rows projected on columns matched BY CONTENT (names may differ).
   */
  mode: "values" | "rows";
  keys: string[];
  distinct?: boolean;
  /** Absolute tolerance for numeric cells. */
  tolerance?: number;
  /** Coaching on recognisable mistakes, checked in order on a wrong answer. */
  traps?: { ifQuery?: string; ifRowsMoreThan?: number; ifRowsFewerThan?: number; ifEmpty?: boolean; say: string }[];
}

export interface KqlStep {
  kind: "kql";
  id: string;
  /** The question this query must answer, in the story's words. */
  prompt: string;
  /** Pre-filled editor text (a starter or a broken query in fix mode). */
  starter?: string;
  /** Tables the schema pane lists first (all dataset tables are queryable). */
  focusTables?: string[];
  /** Artefact ids (from the mission) shown above the editor, e.g. the incident the pivot starts from. */
  artifactIds?: string[];
  /** SERVER-ONLY. */
  answer: KqlAnswerSpec;
}

/** Typed fields: read the evidence, type the fact. Also "where would you look" (choice fields). */
export interface FieldsStep {
  kind: "fields";
  id: string;
  prompt: string;
  /** Artefact ids (from the mission) shown beside the fields. */
  artifactIds?: string[];
  fields: MissionField[];
}

export type IocType = "ip" | "domain" | "url" | "email" | "sha256" | "sha1" | "md5" | "filename" | "host" | "account";

/** Collect indicators from the artefacts into the case notebook. */
export interface IocStep {
  kind: "iocs";
  id: string;
  prompt: string;
  artifactIds: string[];
  /** SERVER-ONLY. Indicators that must be in the notebook. `label` names it in feedback without giving the value. */
  expect: { type: IocType; value: string; label: string }[];
  /** SERVER-ONLY. Values that must NOT be logged as indicators of the attacker, with why. */
  forbidden: { value: string; say: string }[];
}

/** Synthetic file for the YARA bench (built by src/lib/missions/yara/samples.ts). */
export interface MissionSample {
  name: string;
  /** "bad" files must match, "good" files must not. Shown to the learner: it is the test corpus. */
  label: "bad" | "good";
  note?: string;
  spec: import("./yara/samples").SampleSpec;
}

/** Pick stable strings from a sample's strings view; the corpus counts are the evidence. */
export interface StringsStep {
  kind: "strings";
  id: string;
  prompt: string;
  /** Index into the mission's `samples` of the file whose strings are shown. */
  sample: number;
  /** Minimum strings to pick. A pick is good when it is in 0 goodware and in at least `minBad` known-bad files. */
  minPicks: number;
  minBad: number;
}

/** Write a rule (YARA or Sigma) and run it on the corpus. */
export interface RuleStep {
  kind: "rule";
  id: string;
  prompt: string;
  language: "yara" | "sigma";
  starter: string;
  /** SERVER-ONLY. Extra files/events that punish over-fitting (more builds, more goodware). */
  hidden: { samples?: MissionSample[]; events?: MissionEvent[] };
}

/** A labelled event for the Sigma bench. */
export interface MissionEvent {
  id: string;
  label: "bad" | "good";
  note?: string;
  fields: Record<string, string | number | null>;
}

/** A written finding, checked slot by slot against a deterministic checklist. No AI, no reward for length. */
export interface ReportStep {
  kind: "report";
  id: string;
  prompt: string;
  slots: {
    id: string;
    label: string;
    placeholder?: string;
    maxWords: number;
    /** SERVER-ONLY. Each check needs ANY of its `anyOf` patterns (case-insensitive; `re:` for a regex). */
    checks: { label: string; anyOf: string[] }[];
    /** SERVER-ONLY. Claims the evidence does not support. */
    forbidden?: { pattern: string; say: string }[];
  }[];
}

/** What the learner did to ONE incident in the mission console (built by the browser from its local console state). */
export interface ConsoleSnapshot {
  status: string;
  owner: string | null;
  /** True when the owner is the learner (the console's "me"). */
  ownerIsMe: boolean;
  severity: string;
  classification?: string;
  closingComment?: string;
  comments: string[];
  /** Bookmarks attached to this incident: the saved rows as text. */
  bookmarks: { name: string; notes: string; columns: string[]; rows: Record<string, string>[] }[];
}

/** A text check, as in a report slot: each needs ANY of its patterns (case-insensitive; `re:` for a regex). */
export interface TextCheck { label: string; anyOf: string[] }

/**
 * SERVER-ONLY. What the console must show for one incident when the step is checked.
 * Every part is optional; the ones present must all hold.
 */
export interface ConsoleExpect {
  incidentId: string;
  status?: "New" | "Active" | "Closed";
  ownerIsMe?: boolean;
  /** Accepted closing classifications, with coaching for the wrong ones. */
  classification?: { accept: string[]; say?: Record<string, string>; coach: string };
  closingComment?: { checks: TextCheck[]; forbidden?: { pattern: string; say: string }[] };
  /** At least one comment on the incident must pass these checks (all comments are read together). */
  comment?: { checks: TextCheck[]; forbidden?: { pattern: string; say: string }[] };
  /** A bookmark on the incident whose saved rows hold every one of these values. */
  bookmark?: { values: { value: string; label: string }[] };
}

/**
 * Work in the mission's investigation console (the XDR console, our own design, with the room's
 * workspace): read pages and incidents, act on an incident, and type what you found. The server
 * grades the typed facts like a fields step and the incident's state against `expect`.
 */
export interface ConsoleStep {
  kind: "console";
  id: string;
  prompt: string;
  /** The job, as a short checklist shown beside the console. Never the answers. */
  todo: string[];
  /** Where the console opens: an incident id (its page) or a screen. */
  open?: { incidentId?: string; screen?: "overview" | "logs" | "incidents" | "hunting" | "entity" | "ti" | "analytics" | "automation" | "search" };
  /** Facts read in the console. */
  fields?: MissionField[];
  /** SERVER-ONLY. One entry per incident the step checks. */
  expect?: ConsoleExpect[];
}

export type MissionStep = KqlStep | FieldsStep | IocStep | StringsStep | RuleStep | ReportStep | ConsoleStep;

export type StepWithXp = MissionStep & {
  xp: number;
  /** H1: a nudge. Shipped to the client; shown on request. */
  hint: string;
  /** H2: where to look. Shipped; shown on request after H1. Using it lowers this step's XP to 60%. */
  where: string;
  /** SERVER-ONLY. The worked answer, released after 3 wrong checks of this step (or once it passes). */
  worked: string;
  /** SERVER-ONLY. What this step taught, shown once it passes or the worked answer is out. */
  debrief: string;
  /**
   * SERVER-ONLY, tests only. An answer object that passes this step, for the integrity test.
   * Optional where it can be derived (a KQL step's reference query, a fields step's first accepted values).
   */
  solution?: Record<string, unknown>;
};

export interface MissionTask {
  type: "mission";
  id: string;
  heading: string;
  /** The story beat: who asks, why now. */
  story: string;
  /** The deliverable, one line. */
  objective: string;
  /** Who speaks in the briefing (the room's mentor). */
  mentor?: string;
  /**
   * Id of the room's dataset in src/lib/missions/datasets (KQL steps). The browser fetches the
   * VISIBLE copy from /api/missions/datasets/<id> (one download per room, not one per task); the
   * grader also runs every query on the SHADOW copy: same tables and shape, different values.
   */
  dataset?: string;
  /**
   * Id of the room's investigation console in src/lib/missions/consoles (console steps): the
   * incidents, alerts, entities, detections and hunts over the mission dataset. One per room, so
   * what the learner did to an incident in one mission is still there in the next.
   */
  console?: string;
  artifacts?: MissionArtifact[];
  samples?: MissionSample[];
  events?: MissionEvent[];
  steps: StepWithXp[];
}

/** XP factor rules for one step (see grade.ts). */
export const WORKED_AFTER_MISSES = 3;
export const HINT2_FACTOR = 0.6;
