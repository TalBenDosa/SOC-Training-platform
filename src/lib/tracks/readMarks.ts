/**
 * "Studied" marks for Lesson Library lessons on a recommended track.
 *
 * The library has no server-side completion record, so a lesson counts as studied
 * when the learner reads it to the last page (the /learn reader marks it) or ticks
 * it on the track page. Kept in this browser, per signed-in user, so two students
 * sharing a lab computer never see each other's marks. Every access is guarded:
 * storage can be blocked, and the page must still render.
 */

const PREFIX = "soc_track_read_v1:";
export const READ_MARKS_EVENT = "soc:track-read-marks";

const keyFor = (userId: string | null | undefined) => `${PREFIX}${userId || "guest"}`;

export function getReadMarks(userId: string | null | undefined): Set<string> {
  try {
    const raw = localStorage.getItem(keyFor(userId));
    const list = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(list) ? list.filter((x): x is string => typeof x === "string") : []);
  } catch {
    return new Set();
  }
}

export function setReadMark(userId: string | null | undefined, lessonId: string, studied: boolean): void {
  try {
    const marks = getReadMarks(userId);
    if (studied === marks.has(lessonId)) return;
    if (studied) marks.add(lessonId); else marks.delete(lessonId);
    localStorage.setItem(keyFor(userId), JSON.stringify([...marks]));
    window.dispatchEvent(new Event(READ_MARKS_EVENT));
  } catch { /* storage blocked: the mark just isn't kept */ }
}
