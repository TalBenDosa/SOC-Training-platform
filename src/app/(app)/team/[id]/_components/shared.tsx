"use client";
import { enrichEvent, severityBase, type LiveEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import type { TelemetryEvent } from "@/lib/sim/types";
import { asStr } from "@/lib/team/format";

export const ROLE_LABEL: Record<string, string> = {
  t1: "Tier-1 Triage", t2: "Tier-2 Investigator", t3: "Tier-3 / Threat Hunter",
  lead: "Incident Lead", de: "Detection Engineer", ti: "Threat Intel", mgr: "SOC Manager",
  instructor: "Exercise admin", observer: "Observer",
};
/** Enrich an escalation's event snapshot into a LiveEvent so Tier-2 can open the
 * FULL original log (raw fields, MITRE, pivot) — defensive like the team feed. */
export function enrichSnapshot(snap: Record<string, unknown> | undefined): LiveEvent | null {
  if (!snap || typeof snap !== "object") return null;
  const norm = {
    ...snap,
    id: typeof snap.id === "string" ? snap.id : "snap",
    ts: typeof snap.ts === "string" ? snap.ts : new Date().toISOString(),
    source: typeof snap.source === "string" ? snap.source : "siem",
    event_type: typeof snap.event_type === "string" && snap.event_type ? snap.event_type : "informational",
    severity: typeof snap.severity === "string" ? snap.severity : "informational",
  } as unknown as TelemetryEvent;
  try { return enrichEvent(norm, 0); }
  catch { return { ...norm, ruleLevel: severityBase(String(norm.severity)), ruleId: "RULE-0000", displayDescription: asStr(snap.description) || asStr(snap.event_type) || "event" } as unknown as LiveEvent; }
}
// Triage SLA by severity — defined once with the alert queue.
export { slaMinFor } from "@/lib/team/alertQueue";
export function Metric({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" }) {
  return <div className="rounded-lg border border-border bg-bg px-3 py-2"><p className="text-[11px] uppercase tracking-wider text-slate-400">{label}</p><p className={`mt-0.5 font-mono text-lg font-bold ${tone === "good" ? "text-neon-green" : tone === "warn" ? "text-neon-amber" : "text-white"}`}>{value}</p></div>;
}

/**
 * The ONE containment rule (2026-11 review: lobby, guide, tour and console each said it differently;
 * owner 2026-11-07: isolating needs the senior on shift). Every surface quotes this text.
 */
export const CONTAINMENT_RULE = "Contain only what your filed report and scope support, and only with approval: the senior on shift (the SOC Manager when one is on shift, otherwise the Tier-3, otherwise the exercise admin) approves before a host is isolated or an account is disabled.";
export const CONTAINMENT_RULE_SHORT = "Report and scope first, then the senior on shift approves the containment.";
