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

/**
 * The alerts to announce: ONE per incident (Tal, 2026-11-23: "five EDR alerts at once is not
 * realistic"). An EDR raises one detection per attack on a host (its process tree) and adds a
 * behavior to it each time another step of the chain trips an indicator of attack, the way
 * CrowdStrike Falcon groups behaviors under one detection. The bell counts incidents with something
 * new; the console still marks each new behavior NEW.
 */
export function newAlerts(invs: EdrInvestigation[], acked: Set<string>): { inv: EdrInvestigation; newBehaviors: number }[] {
  return invs
    .map(inv => ({ inv, newBehaviors: inv.detections.filter(d => !acked.has(alertKey(inv, d))).length }))
    .filter(a => a.newBehaviors > 0);
}

/** Detections (behaviors) of these investigations the analyst hasn't acknowledged yet. */
export function unacknowledged(invs: EdrInvestigation[], acked: Set<string>): { inv: EdrInvestigation; d: EdrDetection; key: string }[] {
  return invs.flatMap(inv => inv.detections.map(d => ({ key: alertKey(inv, d), inv, d }))).filter(a => !acked.has(a.key));
}
