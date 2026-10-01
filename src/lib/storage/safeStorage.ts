/**
 * Browser storage that never throws (QA phase 7, E-22). Safari private mode,
 * blocked site data and a full quota all make localStorage / sessionStorage
 * THROW on access — and a raw call in a click handler or effect took the whole
 * dashboard / report modal down with it. These read as "nothing stored" and
 * drop the write instead.
 */
type Area = "localStorage" | "sessionStorage";

function area(which: Area): Storage | null {
  try { return typeof window === "undefined" ? null : window[which]; } catch { return null; }
}

function get(which: Area, key: string): string | null {
  try { return area(which)?.getItem(key) ?? null; } catch { return null; }
}
function set(which: Area, key: string, value: string): boolean {
  try { const s = area(which); if (!s) return false; s.setItem(key, value); return true; } catch { return false; }
}
function remove(which: Area, key: string): void {
  try { area(which)?.removeItem(key); } catch { /* blocked — nothing to remove */ }
}

export const lsGet = (key: string) => get("localStorage", key);
export const lsSet = (key: string, value: string) => set("localStorage", key, value);
export const lsRemove = (key: string) => remove("localStorage", key);
export const ssGet = (key: string) => get("sessionStorage", key);
export const ssSet = (key: string, value: string) => set("sessionStorage", key, value);
export const ssRemove = (key: string) => remove("sessionStorage", key);

/** Parsed JSON from localStorage, or `fallback` when missing, corrupt or the wrong shape. */
export function lsReadJson<T>(key: string, fallback: T, valid: (v: unknown) => v is T): T {
  const raw = lsGet(key);
  if (raw == null) return fallback;
  try { const v: unknown = JSON.parse(raw); return valid(v) ? v : fallback; } catch { return fallback; }
}

export const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === "string");
