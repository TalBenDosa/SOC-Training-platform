import type { TelemetryEvent } from "@/lib/sim/types";
import { buildIocTruth, type IocTruth } from "@/lib/edr/iocIntel";

/**
 * Ground truth of one story step. Every step of an attack story is part of the attack
 * unless it is a CONTROL step (a baseline, an FP decoy, an informational record) —
 * the same rule team mode applies (classifyStoryEvent in src/lib/team/buildTimeline).
 */
export function storyStepVerdict(ev: TelemetryEvent): "tp" | "escalate" | "fp" | "informational" {
  if (ev.is_baseline) return "informational";
  if (ev.expected_verdict === "fp" || ev.fp_explanation || ev.it_verify_result === "confirmed") return "fp";
  if (ev.expected_verdict === "escalate") return "escalate";
  if (ev.expected_verdict === "informational") return "informational";
  return "tp";
}

/**
 * The IOC truth table of the stories a session has run — what a hash / IP / domain
 * lookup answers on the single-user dashboard. Built from the whole story, so the
 * dropper's hash reads malicious on its execution row exactly as on the alert row,
 * and a signed system binary used in the attack keeps reading clean.
 */
export function storyIocTruth(storyEvents: TelemetryEvent[]): IocTruth | null {
  if (!storyEvents.length) return null;
  return buildIocTruth({ events: storyEvents.map(e => ({ ...e, expected_verdict: storyStepVerdict(e) })) });
}
