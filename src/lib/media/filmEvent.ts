/** Validation for room-film playback events (POST /api/media/film-event, migration 0117). */
export const FILM_EVENT_KINDS: ReadonlySet<string> = new Set(["start", "stall", "recovered", "retry", "continue", "error", "ended", "skipped"]);
/** Events one learner may record per hour; a flapping connection or a loop stops here. */
export const FILM_EVENTS_PER_HOUR = 300;
/** Only films served from this project's lesson-videos bucket (or the app itself) are recorded. */
const BUCKET_MARKER = "/storage/v1/object/public/lesson-videos/";

/** The part of a film URL worth keeping: the object path in the bucket, or a same-origin path. */
export function filmPath(src: unknown): string | null {
  if (typeof src !== "string" || !src || src.length > 1000) return null;
  const i = src.indexOf(BUCKET_MARKER);
  const path = i >= 0 ? src.slice(i + BUCKET_MARKER.length) : src.startsWith("/") && !src.startsWith("//") ? src : null;
  if (!path) return null;
  const clean = path.split(/[?#]/)[0];
  return /^[\w./-]{1,300}$/.test(clean) && !clean.includes("..") ? clean : null;
}

export const filmNum = (v: unknown, max: number): number | null => {
  const n = Number(v);
  return v == null || !Number.isFinite(n) || n < 0 ? null : Math.min(n, max);
};
export const filmIdent = (v: unknown, max: number): string | null =>
  typeof v === "string" && /^[\w-]+$/.test(v) && v.length <= max ? v : null;
