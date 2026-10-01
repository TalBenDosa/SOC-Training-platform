/**
 * A parsed JSON request body as an object (QA phase 7, E-23). `req.json()` on
 * the body `null` (or `[]`, `"x"`, `5`) succeeds, and the next `body.field`
 * threw a TypeError → a bodyless 500 in ~30 handlers. Anything that isn't a
 * plain object reads as `{}`, so the handler's own "field is required" 400
 * answers instead.
 */
export function asObject<T = Record<string, unknown>>(v: unknown): T {
  return (v !== null && typeof v === "object" && !Array.isArray(v) ? v : {}) as T;
}
