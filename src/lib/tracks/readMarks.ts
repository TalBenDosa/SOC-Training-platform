/**
 * "Studied" marks for Lesson Library lessons on a recommended track.
 *
 * The library lesson counts as studied when the learner reads it to the last page (the
 * /learn reader marks it) or ticks it on the track page.
 *
 *  - Signed-in learners: the server is the record (migration 0111, /api/me/library-reads),
 *    scoped to the learner's current organisation. This browser keeps a copy per user AND
 *    organisation, so the page answers at once and still works where the server table
 *    does not exist yet.
 *  - Guests: this browser only.
 *
 * Every storage access is guarded: storage can be blocked, and the page must still render.
 */

const PREFIX = "soc_track_read_v1:";
export const READ_MARKS_EVENT = "soc:track-read-marks";

type Who = { userId: string | null | undefined; orgId?: string | null };

/** One copy per user and organisation: two orgs never share marks (iron rule). */
const keyFor = ({ userId, orgId }: Who) => `${PREFIX}${userId || "guest"}${userId && orgId ? `:${orgId}` : ""}`;
/** Before 0111 a signed-in learner's marks were kept per user only. */
const legacyKeyFor = ({ userId }: Who) => (userId ? `${PREFIX}${userId}` : null);

function readKey(key: string): Set<string> {
  try {
    const raw = localStorage.getItem(key);
    const list = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(list) ? list.filter((x): x is string => typeof x === "string") : []);
  } catch {
    return new Set();
  }
}

function writeKey(key: string, marks: Set<string>): void {
  try {
    localStorage.setItem(key, JSON.stringify([...marks]));
  } catch { /* storage blocked: the mark just isn't kept here */ }
}

const notify = () => { try { window.dispatchEvent(new Event(READ_MARKS_EVENT)); } catch { /* no window */ } };

export function getReadMarks(who: Who): Set<string> {
  return readKey(keyFor(who));
}

/** Marks or unmarks a lesson here at once, then on the server for a signed-in learner. */
export function setReadMark(who: Who, lessonId: string, studied: boolean): void {
  const key = keyFor(who);
  const marks = readKey(key);
  if (studied === marks.has(lessonId)) return;
  if (studied) marks.add(lessonId); else marks.delete(lessonId);
  writeKey(key, marks);
  notify();
  if (who.userId) {
    fetch("/api/me/library-reads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lessonId, studied }),
      keepalive: true,
    }).catch(() => { /* offline: the next sync uploads it */ });
  }
}

const synced = new Set<string>();

/**
 * Once per page load and learner: merge the server's marks with this browser's copy and
 * upload the ones only this browser has (marks made offline, or before 0111). If the
 * server has no table yet, nothing changes and the browser copy keeps working.
 */
export async function syncReadMarks(who: Who): Promise<void> {
  if (!who.userId) return;
  const key = keyFor(who);
  if (synced.has(key)) return;
  synced.add(key);
  try {
    const res = await fetch("/api/me/library-reads", { cache: "no-store" });
    if (!res.ok) { synced.delete(key); return; }
    const data = (await res.json()) as { ids?: unknown; unavailable?: boolean };
    if (data.unavailable) return;
    const server = new Set(Array.isArray(data.ids) ? data.ids.filter((x): x is string => typeof x === "string") : []);

    const local = readKey(key);
    const legacyKey = legacyKeyFor(who);
    const legacy = legacyKey && legacyKey !== key ? readKey(legacyKey) : new Set<string>();
    const onlyHere = [...new Set([...local, ...legacy])].filter(id => !server.has(id)).slice(0, 200);
    for (const lessonId of onlyHere) {
      const r = await fetch("/api/me/library-reads", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lessonId, studied: true }),
      }).catch(() => null);
      if (r && (r.ok || r.status === 404)) server.add(lessonId);
    }
    writeKey(key, new Set([...server, ...onlyHere]));
    if (legacyKey && legacyKey !== key) { try { localStorage.removeItem(legacyKey); } catch { /* blocked */ } }
    notify();
  } catch {
    synced.delete(key);
  }
}
