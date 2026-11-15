/**
 * Field labs (research/rooms-practical-tasks/SPEC-field-labs.md, Tal 2026-11-15): in intermediate and
 * advanced rooms every briefing lab is analyst work on a native artifact, not a game. Beginner rooms
 * keep their games, which build the first layer of knowledge.
 *
 * A room joins FIELD_LAB_ROOMS when it has been converted; labIntegrity.test.ts then holds it to the
 * rules: no game kinds, at least 70% field kinds, and a fieldNote on every lab.
 */
import type { BriefingLab } from "./types";

/** Converted rooms. The pilot is room 81; later waves add to this set. */
export const FIELD_LAB_ROOMS: ReadonlySet<string> = new Set(["web-attacks-practice"]);

/** Work on a real artifact: a log, a console, a query, a capture, a queue of real records. */
export const FIELD_LAB_KINDS: ReadonlySet<BriefingLab["kind"]> = new Set([
  "reader", "trace", "queue", "portal", "hunt", "pcap", "terminal", "worksheet", "spotdiff", "tune",
]);

/** Guided reading: explains a real record, the learner performs no analyst action. Allowed, not counted as field work. */
export const GUIDED_LAB_KINDS: ReadonlySet<BriefingLab["kind"]> = new Set(["anatomy", "inspect", "hotspot", "evidence", "chat"]);

/** Games: guessing, card sorting, timers. Not allowed in a converted room. */
export const GAME_LAB_KINDS: ReadonlySet<BriefingLab["kind"]> = new Set([
  "codebreak", "rush", "sort", "match", "reactor", "defuse", "duel", "intercept", "deduce", "locks", "tricks", "xray",
  "lineup", "sequence", "simulate", "pathway", "outbreak", "encap",
]);
