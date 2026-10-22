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

export function withDefaultIncidents<T extends Pick<TelemetryEvent, "incident_id" | "hostname">>(events: T[], slug: string): T[] {
  const has = events.some(e => !!e.incident_id);
  return events.map(e => ({ ...e, incident_id: incidentIdFor(e, slug, has) }));
}
