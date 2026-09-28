/**
 * Alert vs. telemetry classification for the scenario investigation table
 * (team-exercise findings #5 and #20).
 *
 * The table used to badge a row "ALERT" whenever the builder set `is_detection`,
 * and the ticket header counted `bundle.alerts` — which `withAlerts()` derives
 * from EVERY event carrying a MITRE id and a medium+ severity. On
 * multi-host-intrusion that produced "12 alerts" in the header, 6 ALERT badges
 * in the table, and 3 real Falcon detections. Three numbers for one fact.
 *
 * The rule here is the one a SOC uses: an ALERT is something a security
 * product's analytic RAISED — a Falcon DetectionSummaryEvent, an AV/IDS/DLP/UEBA
 * detection, a WAF block, a TI match. Raw telemetry (ProcessRollup2,
 * NetworkConnectIP4, a 4624, a firewall TRAFFIC log) is what the analyst pivots
 * through; it is informational, even when it records the malicious act itself.
 *
 * Severity follows the same honesty rule. A raw process-start event has no
 * vendor severity, so a ProcessRollup2 is shown as INFO, not "LVL 10". An
 * alert's label comes from the vendor's own severity field when the raw block
 * has one, else from the event. We do NOT print a number: the old 1/3/5/8/10
 * lookup looked like a Wazuh 0–15 rule level and was not one.
 *
 * Pure and dependency-free (types only) so it is unit-tested and shared by the
 * header count, the row badges and the severity filter — one source of truth.
 */
import type { Severity, TelemetryEvent } from "@/lib/sim/types";

/** Event types that only a detection analytic produces. */
const ALERT_EVENT_TYPES = new Set<string>([
  "edr_alert",
  "av_detection", "av_quarantine", "av_blocked",
  "ids_signature", "ids_blocked",
  "dlp_alert", "dlp_block",
  "ueba_anomaly", "risk_score_change",
  "threat_intel_match", "ioc_hit",
  "waf_block",
  "nac_quarantine",
  "email_quarantined",
]);

/** Vendor event names that are detections regardless of the typed event_type. */
const DETECTION_SIMPLE_NAMES = new Set<string>([
  "DetectionSummaryEvent", // CrowdStrike Falcon
  "EppDetectionSummaryEvent",
]);

export type EventClass = "alert" | "telemetry";

/** Is this event a detection an analytic raised (an ALERT), or raw telemetry? */
export function classifyEvent(ev: Pick<TelemetryEvent, "event_type" | "raw">): EventClass {
  if (ALERT_EVENT_TYPES.has(ev.event_type)) return "alert";
  const simple = ev.raw?.["crowdstrike.event_simpleName"] ?? ev.raw?.["event_simpleName"];
  if (typeof simple === "string" && DETECTION_SIMPLE_NAMES.has(simple)) return "alert";
  return "telemetry";
}

export function isProductDetection(ev: Pick<TelemetryEvent, "event_type" | "raw">): boolean {
  return classifyEvent(ev) === "alert";
}

type AlertInput = Pick<TelemetryEvent, "id" | "event_type" | "raw" | "is_detection" | "incident_id">;

/**
 * The ids of every event the table treats as an ALERT.
 *
 * Primary rule: product detections only (see classifyEvent). Fallback, per
 * incident: when an incident contains NO product detection at all (some packs
 * model a SIEM correlation hit on a CloudTrail/O365 record rather than a
 * vendor alert), the builder's `is_detection` rows are the ticket-openers and
 * are counted instead — otherwise that incident would show zero alerts although
 * its briefing says one fired. Where a real detection exists (every
 * multi-host-intrusion incident has a Falcon DetectionSummaryEvent), flagged
 * telemetry such as a ProcessRollup2 stays informational.
 */
export function buildAlertIndex(events: readonly AlertInput[]): Set<string> {
  const ids = new Set<string>();
  const incidentsWithDetection = new Set<string>();
  for (const e of events) {
    if (isProductDetection(e)) {
      ids.add(e.id);
      incidentsWithDetection.add(e.incident_id ?? "");
    }
  }
  for (const e of events) {
    if (e.is_detection && !incidentsWithDetection.has(e.incident_id ?? "")) ids.add(e.id);
  }
  return ids;
}

/** Number of ALERT rows — the figure the ticket header and the table both show. */
export function countAlerts(events: readonly AlertInput[]): number {
  return buildAlertIndex(events).size;
}

const VENDOR_SEVERITY_KEYS = [
  "crowdstrike.SeverityName",
  "SeverityName",
  "event.severity_name",
  "AlertSeverity",
  "alert.severity",
  "severity",
] as const;

function normaliseVendorSeverity(v: unknown): Severity | null {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  if (s === "critical" || s === "crit") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "med" || s === "moderate") return "medium";
  if (s === "low") return "low";
  if (s === "informational" || s === "info" || s === "information") return "informational";
  return null;
}

/**
 * The severity the table shows and filters on. Alerts: the vendor's own
 * severity when the raw block records one, else the event's. Telemetry:
 * always informational — raw telemetry carries no severity of its own.
 */
export function effectiveSeverity(
  ev: Pick<TelemetryEvent, "raw" | "severity">,
  isAlert: boolean,
): Severity {
  if (!isAlert) return "informational";
  for (const k of VENDOR_SEVERITY_KEYS) {
    const s = normaliseVendorSeverity(ev.raw?.[k]);
    if (s) return s;
  }
  return ev.severity ?? "medium";
}

const SEV_SHORT: Record<Severity, string> = {
  critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", informational: "INFO",
};

/** Short honest label for the severity column ("CRIT", "HIGH", …, "INFO"). */
export function severityLabel(sev: Severity): string {
  return SEV_SHORT[sev];
}

const SEV_RANK: Record<Severity, number> = {
  informational: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/** True when `sev` is at least `min` on the critical > high > medium > low > info scale. */
export function severityAtLeast(sev: Severity, min: Severity): boolean {
  return SEV_RANK[sev] >= SEV_RANK[min];
}
