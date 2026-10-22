/**
 * EDR cases for scenarios written before incident grouping. Such scenarios carry no
 * incident_id, so buildInvestigationsFromScenario built no case and "Investigate in EDR"
 * never appeared (USB, LockBit, LOLBins, Phishing, NTLM relay...). Each gets one case per
 * host: a multi-host intrusion must not draw the file server's processes inside the
 * workstation's tree. Grouping by the host every row already shows hints at nothing;
 * rows with no host share one group. Scenarios that do group their own events are untouched.
 * Pure (types only): used by the scenario page on the server and by its test.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export function incidentIdFor(e: Pick<TelemetryEvent, "incident_id" | "hostname">, slug: string, scenarioHasIncidents: boolean): string | undefined {
  if (e.incident_id) return e.incident_id;
  return scenarioHasIncidents ? undefined : `inc:${slug}:${e.hostname || "net"}`;
}

/**
 * Incidents whose every alert / detection is a false positive (or a whole false-positive
 * scenario): computed on the server from the FULL bundle, where expected_verdict still exists.
 */
export function benignIncidentIds(
  events: Pick<TelemetryEvent, "id" | "incident_id" | "hostname" | "expected_verdict" | "is_detection" | "event_type" | "raw">[],
  slug: string,
  attackKind: string | undefined,
  isAlert: (e: (typeof events)[number]) => boolean,
): string[] {
  const has = events.some(e => !!e.incident_id);
  const byIncident = new Map<string, (typeof events)[number][]>();
  for (const e of events) {
    const id = incidentIdFor(e, slug, has);
    if (!id) continue;
    byIncident.set(id, [...(byIncident.get(id) ?? []), e]);
  }
  const whole = /false_positive/.test(attackKind ?? "");
  return [...byIncident.entries()].filter(([, evs]) => {
    if (whole) return true;
    const flagged = evs.filter(e => e.is_detection || isAlert(e));
    return flagged.length > 0 && flagged.every(e => e.expected_verdict === "fp" || e.expected_verdict === "informational");
  }).map(([id]) => id);
}

export function withDefaultIncidents<T extends Pick<TelemetryEvent, "incident_id" | "hostname">>(events: T[], slug: string): T[] {
  const has = events.some(e => !!e.incident_id);
  return events.map(e => ({ ...e, incident_id: incidentIdFor(e, slug, has) }));
}
