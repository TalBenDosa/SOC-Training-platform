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

export type ThemeId = "mailroom" | "ransomware" | "domain" | "c2" | "hospital" | "city";

/**
 * The room's 3D world on its main screen. Decorative (never clickable): it shows
 * progress, the board around it carries the controls.
 *  - shield:  holographic shield on a projector platform (cards layout)
 *  - gates:   one armoured gate per station on a ring around a holo globe
 *  - tower:   a tower climbed floor by floor, one floor per station
 *  - network: relay nodes joined by beams, packets travel the cleared route
 *  - campus:  a hospital campus at night; each cleared station powers a building
 *             back up, and the sky turns from night to dawn as the room is cleared
 *  - city:    a city seen through a "lens"; each cleared station switches on one
 *             more invisible layer (connections, locks, attackers, attacks, alerts)
 */
export type SceneId = "shield" | "gates" | "tower" | "network" | "campus" | "city";

/** cards: illustrated station cards above the scene. stage: the scene fills the
 *  screen, stations sit in a rail, the selected one in a bottom command bar.
 *  campus: the scene fills the screen with a facility status monitor beside it.
 *  lens: the scene fills the screen with a lens dial, one segment per station. */
export type LayoutId = "cards" | "stage" | "campus" | "lens";

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
  /** Optional portrait (same-origin or bucket URL); initials are drawn without one. */
  photo?: string;
  /** A neutral in-world line. Must never hint at the verdict. */
  line: string;
}

/** The kind of place a station is; picks its illustration on the mission board. */
export type BuildingKind = "archive" | "factory" | "lab" | "office" | "vault" | "control" | "ticket"
  | "reception" | "emergency" | "wing" | "roof";

/**
 * Briefing labs: hands-on ways to learn a reading's material (inspect an
 * artifact, put steps in order, run a simulation, sort, match). They teach;
 * they are NOT graded and award no XP, so their answers may live in this
 * client-side config. Rule for authors: use example data that differs from
 * the room's graded tasks, so a lab never hands over a graded answer.
 */
export type BriefingLab = ({
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
    }
  | {
      /** Items ride a conveyor; route each into the right reactor before it
       *  reaches the end. A wrong reactor heats up and the item comes round again. */
      kind: "reactor";
      title: string;
      prompt: string;
      reactors: { id: string; label: string; sub: string }[];
      items: { id: string; text: string; reactor: string; why: string }[];
    }
  | {
      /** A line-up of suspects with dossiers; each round shows evidence and the
       *  learner picks who fits it. */
      kind: "lineup";
      title: string;
      prompt: string;
      suspects: { id: string; name: string; motive: string; skill: string; target: string }[];
      rounds: { id: string; evidence: string[]; suspect: string; why: string }[];
    }
  | {
      /** A realistic artifact (an email, a web page) with hidden hotspots: find
       *  every red flag; clicking a normal part says why it is fine. */
      kind: "hotspot";
      title: string;
      prompt: string;
      artifact: string;
      parts: { id: string; text: string; flag: boolean; note: string; style?: "meta" | "subject" | "body" | "button" | "url"; /** shown in the status bar on hover, like a real link */ href?: string }[];
    }
  | {
      /** Everyday objects; scanning one with the lens reveals the computer
       *  inside it and what an attacker could do with it. */
      kind: "xray";
      title: string;
      prompt: string;
      objects: { id: string; label: string; icon: XrayIcon; inside: string; risk: string }[];
      doneNote: string;
    }
  | {
      /** Locked doors, one principle each: read the everyday example, then
       *  answer the door's check to open its lock. */
      kind: "locks";
      title: string;
      prompt: string;
      locks: { id: string; letter: string; name: string; idea: string; example: string; check: { q: string; options: string[]; answer: number; why: string } }[];
    }
  | {
      /** Face-down cards with an everyday trick on each: flip one, then stamp it
       *  with the attack that works the same way. */
      kind: "tricks";
      title: string;
      prompt: string;
      attacks: { id: string; name: string }[];
      cards: { id: string; analogy: string; attack: string; real: string }[];
    }
  | {
      /** A sample alert in its source's native fields: scan each key field to
       *  learn what it tells an analyst, then read the one-line story. */
      kind: "anatomy";
      title: string;
      prompt: string;
      /** Caption over the alert, e.g. the product that raised it. */
      source: string;
      fields: { key: string; value: string; label?: string; note?: string }[];
      summary: string;
    }
  | {
      /** "What does it look like": realistic screens of real situations. The
       *  learner names what each screen shows, then numbered markers appear on
       *  the tell-tale parts of the screen with the explanation. */
      kind: "evidence";
      title: string;
      prompt: string;
      choices: { id: string; label: string }[];
      items: {
        id: string;
        /** Window title over the screen. */
        caption: string;
        screen: EvidenceScreen;
        answer: string;
        /** `at` names a part of the screen (see EvidenceScreen); shown in order. */
        callouts: { at: string; text: string }[];
      }[];
    }) & {
  /** Numbered "how to play" steps shown above the lab; each kind has defaults. */
  howTo?: string[];
};

/**
 * A realistic screen for the evidence lab. The comment on each type lists the
 * part names a callout can point `at`.
 */
export type EvidenceScreen =
  /** parts: site, title, rows */
  | { type: "leak"; site: string; title: string; meta: string; header: string[]; rows: string[][] }
  /** parts: file, hashes, change */
  | { type: "integrity"; tool: string; file: string; expected: string; current: string; changedBy: string; when: string; before: string; after: string }
  /** parts: state, graph, errors */
  | { type: "status"; service: string; state: string; errors: string; series: number[] }
  /** parts: url, banner */
  | { type: "defaced"; url: string; banner: string; text: string }
  /** parts: note, files, wallet */
  | { type: "ransom"; heading: string; note: string[]; files: string[]; wallet: string }
  /** parts: graph, sources */
  | { type: "traffic"; service: string; series: number[]; normal: number; sources: { ip: string; country: string; rate: string }[] }
  /** parts: network, url, error */
  | { type: "certwarn"; network: string; url: string; error: string; detail: string }
  /** parts: caller, request, pressure */
  | { type: "ticket"; id: string; caller: string; callerId: string; request: string; pressure: string; notes: string }
  /** parts: sender, text, link */
  | { type: "sms"; from: string; time: string; text: string; link: string };

/** Icons the x-ray lab can draw (lucide names). */
export type XrayIcon = "fridge" | "traffic" | "atm" | "pump" | "car" | "camera" | "phone" | "plant" | "thermostat";

export interface Station {
  id: string;
  label: string;
  /** One line under the label in the hub. */
  tagline: string;
  /** The room topics this station teaches, named the way the reading names
   *  them, so the learner always knows what a station covers. */
  topic?: string;
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
  /** The room's 3D world and board layout. Defaults: shield + cards. */
  scene?: SceneId;
  layout?: LayoutId;
  stations: Station[];
  /**
   * Task id → hands-on labs. On a reading they teach the reading; on any other
   * task they run as an ungraded drill before the graded challenge.
   */
  briefings?: Record<string, BriefingLab[]>;
  /** Optional per-task persona (Triage Desk requester, etc.). */
  personas?: Record<string, Persona>;
  /**
   * Short story films: `intro` plays before the first station, `afterStation`
   * plays when that station is first cleared (keyed by station id). Story only,
   * never a graded answer. Each plays once per viewer and can be replayed from
   * the board.
   */
  story?: { intro?: StoryClip; afterStation?: Record<string, StoryClip> };
}

/** One story film: same-origin or Supabase-hosted MP4 plus a poster frame. */
export interface StoryClip {
  title: string;
  src: string;
  poster?: string;
}
