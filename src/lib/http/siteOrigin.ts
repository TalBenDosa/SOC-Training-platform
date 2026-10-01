/**
 * The origin every EMAILED link is built on: the configured canonical site URL
 * (NEXT_PUBLIC_SITE_URL), else the request's own origin. Building reset / invite
 * links from the request's Host header is the classic reset-poisoning setup — a
 * forged Host would mail the victim a genuine link to the attacker's domain
 * (P-03: not reachable on Vercel today, but it must not depend on the host).
 */
export function emailOrigin(req: Request): string {
  const env = process.env.NEXT_PUBLIC_SITE_URL?.trim().replace(/\/+$/, "");
  if (env && /^https?:\/\/[^/\s]+$/.test(env)) return env;
  return new URL(req.url).origin;
}
