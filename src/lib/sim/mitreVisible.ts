/**
 * Would a real product tag this log with an ATT&CK technique?
 *
 * Detections do — an EDR alert, an IDS/WAF signature, a SIEM correlation, a UEBA
 * anomaly, a DLP policy match. A raw log does not: a firewall allow, a process
 * creation, a sign-in carry no technique. Showing one there (the MITRE badge, a
 * technique-specific rule name) marked attack logs apart from the noise — about 80 %
 * of attack rows against 4 % of benign rows — so the analyst could read the answer
 * off the tag instead of the evidence (QA H1, 2026-10-02).
 */
const DETECTION_SOURCES = new Set(["siem", "ueba", "ids", "waf", "dlp", "threat_intel"]);
const DETECTION_TYPES = /alert|detection|threat|quarantine|^av_|ids|ips|risk|anomal|malware|ransom/i;

export function mitreVisible(ev: { source?: string; event_type?: string; is_detection?: boolean }): boolean {
  if (ev.is_detection) return true;
  if (ev.source && DETECTION_SOURCES.has(ev.source)) return true;
  return DETECTION_TYPES.test(ev.event_type ?? "");
}
