/**
 * Lesson videos rendered WITHOUT the 4-second HACK THE SOC logo outro (the first batch, before
 * motion-studio/add-outro.mjs existed). On a white-label platform these play to their real end
 * and only then show the organization's end card; every other video stops before its outro.
 * Measured 2026-10-21 by comparing each video's frame 2 s before the end with the outro
 * (scratchpad outro-check.cjs): these 8 differ, the other 91 match exactly. Update this list if
 * one of them is re-rendered with the outro.
 */
export const VIDEOS_WITHOUT_OUTRO: ReadonlySet<string> = new Set([
  "cloud-security-for-soc-analysts",
  "crowdstrike-falcon-console",
  "sentinelone-console",
  "malware-triage-without-reverse-engineering",
  "command-and-control-and-exfiltration-detection",
  "writing-the-incident-report",
  "hashing-encryption-and-certificates-for-analysts",
  "windows-event-log-analysis-for-threat-detection",
]);

/** "…/lesson-videos/<slug>/<file>.mp4" → slug (null for any other address). */
export function videoSlug(src: string): string | null {
  const m = /\/lesson-videos\/([^/?#]+)\//.exec(src);
  return m ? m[1] : null;
}

/** Does this video end with the platform's logo outro? */
export function hasPlatformOutro(src: string): boolean {
  const slug = videoSlug(src);
  return !(slug && VIDEOS_WITHOUT_OUTRO.has(slug));
}
