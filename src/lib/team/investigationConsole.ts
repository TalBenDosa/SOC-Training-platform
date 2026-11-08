import { withoutDetectionFeed, type Stack } from "@/lib/logs/native/stack";
import type { Ev } from "@/lib/team/types";
import type { TeamEnv } from "@/lib/team/environment";
import { escalationHandoff, type Handoff, type NameOf } from "@/lib/team/handoff";

/**
 * Where a Team Training session investigates: the EDR console, or Microsoft Sentinel.
 * Chosen before the session, by the person who builds it. Stored in team_sessions.config.console.
 */
export type InvestigationConsole = "edr" | "sentinel";

export const CONSOLE_CHOICES: { id: InvestigationConsole; label: string; hint: string }[] = [
  { id: "edr", label: "EDR console", hint: "Endpoint detections open the EDR console of the products below." },
  { id: "sentinel", label: "Microsoft Sentinel", hint: "Detections raise Sentinel incidents. The team investigates in Sentinel and queries the logs with KQL." },
];

export function sanitizeConsole(input: unknown): InvestigationConsole {
  return input === "sentinel" ? "sentinel" : "edr";
}

/** The session's console (team_sessions.config.console). Every session made before this feature reads as "edr". */
export function consoleFromConfig(config: unknown): InvestigationConsole {
  return sanitizeConsole((config as { console?: unknown } | null)?.console);
}

/** A Sentinel workspace lives in an Azure subscription, so a Sentinel organization has one. */
export function envForConsole<E extends TeamEnv | null>(env: E, console: InvestigationConsole): E {
  if (!env || console !== "sentinel" || env.platforms.includes("azure")) return env;
  return { ...env, platforms: ["azure", ...env.platforms] };
}

/**
 * What analysts escalated, for the workspace: each opens a Sentinel incident, and carries the
 * analyst's whole report (owner, 2026-11-08): the incident's title is their summary, its
 * description and first comment are their report, and their indicators become entities.
 * The latest round of a re-escalated log wins. No raw block: the incident's own events hold it.
 */
export function escalatedCases(events: Ev[], nameOf?: NameOf): { eventId: string; summary?: string; handoff?: Handoff }[] {
  const latest = new Map<string, Ev>();
  for (const e of events) {
    if (e.type !== "escalation.requested") continue;
    const id = String((e.payload as { event_id?: unknown }).event_id ?? "");
    if (id) latest.set(id, e);
  }
  return [...latest.entries()].map(([eventId, e]) => {
    const p = e.payload as { summary?: unknown };
    return { eventId, summary: typeof p.summary === "string" ? p.summary : undefined, handoff: escalationHandoff(e, events, { nameOf, raw: false, related: false }) };
  });
}

/**
 * Sentinel reads endpoint activity from the Defender tables (DeviceProcessEvents and the rest), so a
 * Sentinel session runs Defender for Endpoint. Otherwise the feed would show one product's records and
 * KQL another's. The picker shows this choice, and the server enforces it.
 *
 * Its SIEM also reads the Microsoft products' detections through the Graph Security API, as a SOC
 * on Sentinel does (detection_feed). Only this function sets that key: an EDR session never has it,
 * whatever a client sends, and the picker never offers it.
 */
export function stackForConsole(stack: Stack, console: InvestigationConsole): Stack {
  const products = withoutDetectionFeed(stack);
  return console === "sentinel" ? { ...products, edr: "mde", detection_feed: "ms_graph" } : products;
}
