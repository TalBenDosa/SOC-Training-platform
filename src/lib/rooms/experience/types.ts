/**
 * Operation Mode — a presentation layer OVER an existing Learning Room.
 *
 * A RoomExperience never carries content or answers: it only groups the room's
 * existing task ids into stations, names them, and adds narrative chrome
 * (codename, handler lines, personas). Grading, XP and the 65% mastery gate
 * stay exactly where they are (RoomClient + /api/rooms/.../submit), so a room
 * plays identically in Classic and Operation mode as far as scoring goes.
 *
 * Concept doc: docs/CONCEPT-gamified-learning-rooms.md
 */

export type ThemeId = "mailroom";

/** Which mechanic renders a task. Defaults by task type (see mechanicFor). */
export type MechanicId =
  | "intel_briefing"   // reading
  | "lock_terminal"    // question
  | "evidence_board"   // log_analysis
  | "triage_desk"      // analyst_choice
  | "vault_keypad"     // flag
  | "classic";         // any other type: the existing player inside a station frame

export interface Persona {
  name: string;
  role: string;
  /** A neutral in-world line. Must never hint at the verdict. */
  line: string;
}

/** The hub building that stands for a station on the mail-route street. */
export type BuildingKind = "archive" | "factory" | "lab" | "office" | "vault";

/**
 * Briefing labs: hands-on ways to learn a reading's material (inspect an
 * artifact, put steps in order, run a simulation, sort, match). They teach;
 * they are NOT graded and award no XP, so their answers may live in this
 * client-side config. Rule for authors: use example data that differs from
 * the room's graded tasks, so a lab never hands over a graded answer.
 */
export type BriefingLab =
  | {
      kind: "inspect";
      title: string;
      prompt: string;
      /** Caption over the artifact, e.g. "Raw headers · Show original". */
      artifact: string;
      items: { id: string; text: string; tag: string; tone: "trust" | "warn" | "info"; note: string }[];
    }
  | {
      kind: "sequence";
      title: string;
      prompt: string;
      /** Shown in this order; the learner taps them in `order`. */
      items: { id: string; text: string; note?: string }[];
      order: string[];
      doneNote: string;
    }
  | {
      kind: "simulate";
      title: string;
      prompt: string;
      checks: { name: string; question: string }[];
      scenarios: { id: string; label: string; detail: string; results: ("pass" | "fail")[]; why: string[]; verdict: string }[];
    }
  | {
      kind: "sort";
      title: string;
      prompt: string;
      buckets: { id: string; label: string }[];
      /** `hidden` = revealed on hover / focus / tap (e.g. a link's real href). */
      items: { id: string; text: string; hidden?: string; bucket: string; why: string }[];
    }
  | {
      kind: "match";
      title: string;
      prompt: string;
      pairs: { id: string; left: string; right: string; why: string }[];
    };

export interface Station {
  id: string;
  label: string;
  /** One line under the label in the hub. */
  tagline: string;
  building: BuildingKind;
  /** Existing task ids, in room order. Stations must be contiguous in the room. */
  taskIds: string[];
  /** The last station is the "boss": shown with a different marker in the hub. */
  boss?: boolean;
}

export interface RoomExperience {
  roomId: string;
  codename: string;
  theme: ThemeId;
  handler: { name: string; role: string };
  /** Typed out on the briefing screen, one line at a time. */
  briefing: string[];
  /** One-line mission statement under the title on the mission board. */
  mission: string;
  /** Rough time to play the whole operation, shown on the board footer. */
  estimate: string;
  /** Per-room tint for the board and the station art (CSS colours). */
  look?: { primary: string; secondary: string; warn: string };
  stations: Station[];
  /** Reading task id → hands-on labs that teach that reading interactively. */
  briefings?: Record<string, BriefingLab[]>;
  /** Optional per-task persona (Triage Desk requester, etc.). */
  personas?: Record<string, Persona>;
  /** Phase 4 (video) — slots exist now so adding a clip is just data. */
  media?: { intro?: string; success?: string; fail?: string };
}
