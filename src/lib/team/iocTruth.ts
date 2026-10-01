import type { Ev } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildIocTruth, type IocTruth } from "@/lib/edr/iocIntel";
import { mergeAnswers, publicAnswers } from "@/lib/team/report/serverReport";

/**
 * Threat-intel truth for a team session's FIRED logs: the public feed rows with the
 * staff-only answers joined back (by inject_id), through the same buildIocTruth the
 * scenario pages use. Server-side only by usage (the answers never leave it; the
 * result is digest-keyed verdicts).
 */
export function buildTeamIocTruth(feedEvents: Ev[], feedInjects: { id: string; channel: string | null; expected_action: unknown }[]): IocTruth {
  const merged = mergeAnswers(feedEvents.filter(e => e.type === "feed.event"), publicAnswers(feedInjects));
  // The team key says "benign" for a story's control / baseline step (a legitimate
  // login before the takeover); buildIocTruth knows that state as is_baseline — without
  // the mapping the step's IOCs inherited the incident's guilt (a clean home IP → malicious).
  return buildIocTruth({ events: merged.map(e => {
    const p = e.payload as unknown as TelemetryEvent;
    return p.expected_verdict === ("benign" as TelemetryEvent["expected_verdict"]) ? { ...p, is_baseline: true } : p;
  }) });
}
