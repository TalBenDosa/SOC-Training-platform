// ── Shared feed ──────────────────────────────────────────────────────────────
export function sevColor(s?: string) { return s === "critical" || s === "high" ? "bg-severity-high" : s === "medium" ? "bg-neon-amber" : "bg-slate-500"; }
/** Some vendor events carry `description`/`raw` as an OBJECT, not a string — React
 *  can't render an object child, so coerce everything we render to a safe string. */
export function asStr(v: unknown): string { return typeof v === "string" ? v : ""; }
/** Auto-detect an IOC's type for display + accuracy scoring (T1-5). */
export function detectIocType(v: string): string {
  const s = v.trim();
  if (/^[a-f0-9]{64}$/i.test(s)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(s)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(s)) return "md5";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (/@/.test(s)) return "email";
  if (/\.[a-z]{2,}$/i.test(s) && !/\s/.test(s)) return "domain";
  return "host";
}
// A4: a MANUAL IOC must be a real indicator shape — a strong type (hash/ip/email/domain)
// or a plausible hostname (has a hyphen/dot/digit, no spaces) — so junk free text like
// "asdf" can't satisfy the ≥1-indicator escalation gate. Picked-from-log IOCs are trusted.
export function isValidIoc(v: string): boolean {
  const s = v.trim();
  if (!s || /\s/.test(s)) return false;
  if (detectIocType(s) !== "host") return true;       // hash / ip / email / domain
  return /^[A-Za-z0-9][A-Za-z0-9._-]{2,62}$/.test(s) && /[-.\d]/.test(s); // plausible hostname
}
export const wordCount = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;
