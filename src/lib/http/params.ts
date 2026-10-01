/**
 * A dynamic route segment, decoded at most once. Next 15 already decodes
 * params; decoding again turned "/%25" into "%" and threw URIError → a bodyless
 * 500 (QA phase 7, E-16; reproduced in production on /api/access-codes/%25).
 */
export function paramOf(v: string): string {
  try { return decodeURIComponent(v); } catch { return v; }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: string) => UUID_RE.test(v);

/**
 * API routes whose dynamic segments are row UUIDs. A non-UUID there reached
 * Postgres and came back as 22P02 → 500 on routes without dbFail (QA phase 7,
 * E-23); the middleware answers 404 before the handler runs.
 */
const UUID_ROUTES: RegExp[] = [
  /^\/api\/feedback\/([^/]+)\/reply$/,
  /^\/api\/org\/media\/([^/]+)(?:\/url)?$/,
  /^\/api\/org\/students\/([^/]+)(?:\/plan)?$/,
  /^\/api\/superadmin\/orgs\/([^/]+)(?:\/(?:admin-access|export|invite-admin|members))?$/,
  /^\/api\/superadmin\/orgs\/([^/]+)\/invites(?:\/([^/]+)\/resend)?$/,
  /^\/api\/superadmin\/orgs\/([^/]+)\/members\/([^/]+)\/sign-in-email$/,
  /^\/api\/team\/sessions\/([^/]+)(?:\/(?:end|ioc-truth|members|pause|reassign|report|start))?$/,
];

/** True when `pathname` is one of the UUID routes with a segment that isn't a UUID. */
export function hasBadUuidSegment(pathname: string): boolean {
  for (const re of UUID_ROUTES) {
    const m = re.exec(pathname);
    if (m) return m.slice(1).some(seg => seg !== undefined && !isUuid(paramOf(seg)));
  }
  return false;
}
