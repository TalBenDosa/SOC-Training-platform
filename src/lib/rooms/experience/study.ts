import type { SanitizedRoomTask } from "@/lib/rooms/sanitize";

export interface StudyEntry { id: string; heading: string }
export interface StudyGroup { label: string; entries: StudyEntry[] }

/** The room's readings, grouped by the station that teaches them. */
export function studyGroups(tasks: SanitizedRoomTask[], stations: { label: string; taskIds: string[] }[]): StudyGroup[] {
  const byId = new Map(tasks.map(t => [t.id, t]));
  const seen = new Set<string>();
  const groups: StudyGroup[] = [];
  for (const s of stations) {
    const entries: StudyEntry[] = [];
    for (const id of s.taskIds) {
      const t = byId.get(id);
      if (t?.type !== "reading" || seen.has(id)) continue;
      seen.add(id);
      entries.push({ id, heading: t.heading });
    }
    if (entries.length) groups.push({ label: s.label, entries });
  }
  const rest = tasks.filter(t => t.type === "reading" && !seen.has(t.id)) as Extract<SanitizedRoomTask, { type: "reading" }>[];
  if (rest.length) groups.push({ label: "More", entries: rest.map(t => ({ id: t.id, heading: t.heading })) });
  return groups;
}

/**
 * The reading to open for a task: an authored pointer when one exists, else the
 * task itself when it is a reading, else the nearest reading before it, else
 * the room's first reading.
 */
export function readingFor(taskId: string | undefined, tasks: SanitizedRoomTask[], pointers?: Record<string, string>): string | null {
  const readings = tasks.filter(t => t.type === "reading");
  if (!readings.length) return null;
  if (taskId) {
    const pointed = pointers?.[taskId];
    if (pointed && readings.some(r => r.id === pointed)) return pointed;
    const at = tasks.findIndex(t => t.id === taskId);
    for (let i = at; i >= 0; i--) if (tasks[i].type === "reading") return tasks[i].id;
  }
  return readings[0].id;
}
