/**
 * Live EDR alerts, shared by the EDR console (red cards) and the SIEM dashboard (the count
 * on "Investigate in EDR"): one alert per detection per incident, acknowledged per browser.
 */
import type { EdrDetection, EdrInvestigation } from "./investigations";

/** localStorage key of acknowledged alerts (the EDR tab writes it, the dashboard follows). */
export const EDR_ACK_KEY = "edr_ack_alerts";

/** One alert per detection, per incident (a new incident's detections are new alerts). */
export const alertKey = (inv: EdrInvestigation, d: EdrDetection) =>
  `${inv.host.name}|${inv.title}|${d.pid}|${d.technique}|${d.name}`;

export function readAckedAlerts(): Set<string> {
  try { return new Set(JSON.parse(localStorage.getItem(EDR_ACK_KEY) ?? "[]") as string[]); } catch { return new Set(); }
}

export function writeAckedAlerts(keys: Set<string>): void {
  try { localStorage.setItem(EDR_ACK_KEY, JSON.stringify([...keys].slice(-200))); } catch { /* storage blocked */ }
}

/** Detections of these investigations the analyst hasn't acknowledged yet. */
export function unacknowledged(invs: EdrInvestigation[], acked: Set<string>): { inv: EdrInvestigation; d: EdrDetection; key: string }[] {
  return invs.flatMap(inv => inv.detections.map(d => ({ key: alertKey(inv, d), inv, d }))).filter(a => !acked.has(a.key));
}
