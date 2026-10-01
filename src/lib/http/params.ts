/**
 * A dynamic route segment, decoded at most once. Next 15 already decodes
 * params; decoding again turned "/%25" into "%" and threw URIError → a bodyless
 * 500 (QA phase 7, E-16; reproduced in production on /api/access-codes/%25).
 */
export function paramOf(v: string): string {
  try { return decodeURIComponent(v); } catch { return v; }
}
