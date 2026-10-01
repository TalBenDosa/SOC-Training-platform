/**
 * Path helpers shared by the schema validator and the use-case engine.
 * Syntax: dot-joined keys; "[]" after a key iterates an array ("events[].name").
 * Keys that literally contain dots (SentinelOne "src.process.cmdline", Zscaler
 * flat feeds) are matched first as a whole before splitting.
 */

/** Every leaf path in a record, arrays collapsed to "[]". Empty objects/arrays count as leaves. */
export function leafPaths(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return prefix ? [prefix] : [];
    const out = new Set<string>();
    for (const v of value) for (const p of leafPaths(v, `${prefix}[]`)) out.add(p);
    return [...out];
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return prefix ? [prefix] : [];
    const out: string[] = [];
    for (const [k, v] of entries) out.push(...leafPaths(v, prefix ? `${prefix}.${k}` : k));
    return out;
  }
  return prefix ? [prefix] : [];
}

/** All values at a path (arrays fan out). Missing → []. */
export function getAll(record: unknown, path: string): unknown[] {
  if (record === null || record === undefined) return [];
  if (path === "") return [record];
  // A literal dotted key wins (flat dotted schemas).
  if (typeof record === "object" && !Array.isArray(record) && path in (record as Record<string, unknown>)) {
    return [(record as Record<string, unknown>)[path]];
  }
  const m = /^([^.[\]]+)(\[\])?(?:\.(.*))?$/.exec(path);
  if (!m) return [];
  const [, head, arr, rest] = m;
  // Try progressively longer literal keys containing dots ("src.process" + ".cmdline").
  if (typeof record === "object" && !Array.isArray(record)) {
    const obj = record as Record<string, unknown>;
    const parts = path.split(".");
    for (let i = parts.length - 1; i >= 1; i--) {
      const key = parts.slice(0, i).join(".");
      if (key.includes("[]")) continue;
      if (key in obj && key !== head) return getAll(obj[key], parts.slice(i).join("."));
    }
    const next = obj[head];
    if (next === undefined) return [];
    if (arr) {
      if (!Array.isArray(next)) return [];
      return next.flatMap(v => (rest ? getAll(v, rest) : [v]));
    }
    return rest ? getAll(next, rest) : [next];
  }
  return [];
}

/** First value at a path, or undefined. */
export function get(record: unknown, path: string): unknown {
  return getAll(record, path)[0];
}
