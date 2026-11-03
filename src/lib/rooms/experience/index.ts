import type { RoomExperience, MechanicId } from "./types";
import { PHISHING_ANALYSIS } from "./phishingAnalysis";
import { INTRO_CYBERSECURITY } from "./introCybersecurity";
import { NETWORKING_FUNDAMENTALS } from "./networkingFundamentals";
import { SOC_STRUCTURE } from "./socStructure";
import { NETWORKING_PROTOCOLS } from "./networkingProtocols";
import { WINDOWS_FUNDAMENTALS } from "./windowsFundamentals";

export type { RoomExperience, Station, Persona, MechanicId, ThemeId, BuildingKind, BriefingLab, StoryClip, SceneId, LayoutId, XrayIcon, EvidenceScreen } from "./types";

// Hand-authored rooms. Rooms without an entry stay Classic-only.
const EXPERIENCES: Record<string, RoomExperience> = {
  [PHISHING_ANALYSIS.roomId]: PHISHING_ANALYSIS,
  [INTRO_CYBERSECURITY.roomId]: INTRO_CYBERSECURITY,
  [NETWORKING_FUNDAMENTALS.roomId]: NETWORKING_FUNDAMENTALS,
  [SOC_STRUCTURE.roomId]: SOC_STRUCTURE,
  [NETWORKING_PROTOCOLS.roomId]: NETWORKING_PROTOCOLS,
  [WINDOWS_FUNDAMENTALS.roomId]: WINDOWS_FUNDAMENTALS,
};

/**
 * Returns the experience only if every station task id exists in the room and
 * the stations are contiguous and in room order — a stale config must fall
 * back to Classic, never render a broken hub.
 */
export function getRoomExperience(roomId: string, taskIds: readonly string[]): RoomExperience | null {
  const exp = EXPERIENCES[roomId];
  if (!exp) return null;
  const flat = exp.stations.flatMap(s => s.taskIds);
  if (flat.length !== taskIds.length) return null;
  if (flat.some((id, i) => id !== taskIds[i])) return null;
  return exp;
}

export function mechanicFor(type: string): MechanicId {
  switch (type) {
    case "reading":        return "intel_briefing";
    case "question":       return "lock_terminal";
    case "log_analysis":   return "evidence_board";
    case "analyst_choice": return "triage_desk";
    case "flag":           return "vault_keypad";
    default:               return "classic";
  }
}
