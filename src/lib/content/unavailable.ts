/**
 * Thrown by a content resolver when the DATABASE failed (not "no such item") —
 * QA phase 7, E-11 / E-17. Routes turn it into 503 "try again"; before, a read
 * error looked like "Room not found" (404) or escaped as a bodyless 500.
 */
export class ContentUnavailableError extends Error {
  constructor(what: string) { super(`content unavailable: ${what}`); this.name = "ContentUnavailableError"; }
}
