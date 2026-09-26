"use client";
import { Card } from "@/components/ui/Card";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── Team activity log (everyone sees the coordination) ───────────────────────
export function ActivityLog({ activity, nameOf }: { activity: Ev[]; nameOf: (u: string | null) => string }) {
  const label = (e: Ev) => {
    const p = e.payload as Record<string, unknown>;
    switch (e.type) {
      case "disposition.set": return `marked a log ${String(p.verdict).replace("_", " ")}`;
      case "escalation.requested": return `escalated: ${p.what}`;
      case "escalation.acknowledged": return "acknowledged an escalation";
      case "elevation.requested": return `elevated to Tier-3: ${p.summary ?? p.what ?? "a case"}`;
      case "report.submitted": return `submitted an incident report: ${p.summary ?? ""}`;
      case "containment.requested": return `requested containment of ${p.target}`;
      case "containment.approved": return "approved containment";
      case "containment.denied": return "denied containment";
      case "containment.executed": return `executed isolation on ${asStr((p as { target?: string }).target) || "the host"}`;
      case "escalation.bounced": return "bounced an escalation back to Tier-1";
      case "escalation.resolved": return "resolved an escalation";
      case "scope.set": return "set the incident scope";
      case "scope.confirmed": return "confirmed the final scope";
      case "sitrep.sent": return "sent a SITREP";
      case "staff.inject": return `posted an inject (${asStr((p as { kind?: string }).kind) || "announcement"})`;
      case "ticket.answered": return `answered a help-desk ticket (${asStr((p as { decision?: string }).decision) || "handled"})`;
      case "hunt.logged": return `logged a hunt finding${p.technique ? ` (${p.technique})` : ""}`;
      case "rule.published": return `published detection rule "${p.name}" (${p.matched ?? 0} matches)`;
      case "intel.published": return `published intel${p.actor ? `: ${p.actor}` : ""}`;
      case "handover.noted": return "posted a handover note";
      case "decision.logged": return "logged a decision";
      case "evidence.pinned": return `pinned evidence to the case${p.summary ? `: ${String(p.summary).slice(0, 40)}` : ""}`;
      case "case.status_set": return `set case status → ${p.status}`;
      case "case.assigned": return "assigned the case owner";
      case "note.added": return "added a case note";
      default: return e.type;
    }
  };
  return (
    <Card>
      <h3 className="text-sm font-bold text-white">Team activity</h3>
      {activity.length === 0 ? <p className="mt-2 text-xs text-slate-400">Actions your team takes appear here, live.</p> : (
        <div className="mt-2 max-h-64 space-y-1.5 overflow-y-auto">
          {activity.slice().reverse().map(e => (
            <p key={e.seq} className="text-[11px] text-slate-400"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}</span> {label(e)}</p>
          ))}
        </div>
      )}
    </Card>
  );
}
