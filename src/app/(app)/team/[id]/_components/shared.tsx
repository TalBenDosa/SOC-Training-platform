"use client";
import { enrichEvent, severityBase, type LiveEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import type { TelemetryEvent } from "@/lib/sim/types";
import { asStr } from "@/lib/team/format";

export const ROLE_LABEL: Record<string, string> = {
  t1: "Tier-1 Triage", t2: "Tier-2 Investigator", t3: "Tier-3 / Threat Hunter",
  lead: "Incident Lead", de: "Detection Engineer", ti: "Threat Intel", mgr: "SOC Manager",
  instructor: "Instructor", observer: "Observer",
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
  return <div className="rounded-lg border border-border bg-bg px-3 py-2"><p className="text-[10px] uppercase tracking-wider text-slate-400">{label}</p><p className={`mt-0.5 font-mono text-lg font-bold ${tone === "good" ? "text-neon-green" : tone === "warn" ? "text-neon-amber" : "text-white"}`}>{value}</p></div>;
}
