"use client";
import type { SentinelIncident } from "@/lib/sentinel/types";
import { HandoffDetail } from "@/app/(app)/team/[id]/_components/HandoffDetail";

/**
 * An incident's description. An escalated incident opens with the analyst's report (owner,
 * 2026-11-08): who escalated it, their summary, calls, reasoning, indicators, the affected host and
 * user and the log's key fields, through the same hand-off renderer the team room uses. What the
 * detection itself says follows, when a rule raised it too.
 */
export function IncidentDescription({ incident }: { incident: SentinelIncident }) {
  const handoffs = incident.handoffs ?? [];
  if (!handoffs.length) return <div className="st-field"><div className="k">Description</div><div className="v">{incident.description || "--"}</div></div>;
  return (
    <>
      <div className="st-field" data-testid="incident-handoff">
        <div className="k">{handoffs.length === 1 ? "Escalated by the analyst" : `Escalated by analysts (${handoffs.length})`}</div>
        {handoffs.map((h, i) => (
          <div key={`${h.at ?? ""}-${i}`} className="v st-ho-wrap"><HandoffDetail handoff={h} variant="sentinel" /></div>
        ))}
      </div>
      {incident.detectionDescription && <div className="st-field"><div className="k">Description</div><div className="v">{incident.detectionDescription}</div></div>}
    </>
  );
}
