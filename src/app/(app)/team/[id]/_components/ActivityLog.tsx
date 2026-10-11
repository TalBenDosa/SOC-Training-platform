"use client";
import { Card } from "@/components/ui/Card";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useNewItemsAnnouncement, LiveRegion, clip } from "./useLiveAnnounce";

// ── Team activity log (everyone sees the coordination) ───────────────────────
export function ActivityLog({ activity, nameOf }: { activity: Ev[]; nameOf: (u: string | null) => string }) {
  const label = (e: Ev) => {
    const p = e.payload as Record<string, unknown>;
    const s = (k: string, n = 80) => asStr(p[k]).slice(0, n);
    const inc = s("incident", 40) ? ` [${s("incident", 40)}]` : "";
    switch (e.type) {
      case "disposition.set": return `marked a log ${String(p.verdict).replace("_", " ")}`;
      case "escalation.requested": return `escalated: ${s("summary") || s("what") || "a log"}`;
      case "escalation.acknowledged": return p.takeover === true ? "took over an escalation (backup)" : "acknowledged an escalation";
      case "elevation.requested": return `elevated to Tier-3: ${p.summary ?? p.what ?? "a case"}`;
      case "report.submitted": return `submitted an incident report${inc}: ${s("summary")}`;
      case "containment.requested": return `requested containment of ${s("target", 60) || "a target"}${inc}`;
      case "containment.approved": return "approved containment";
      case "containment.denied": return `denied containment${s("reason") ? ` — ${s("reason")}` : ""}`;
      case "containment.executed": return `executed isolation on ${asStr((p as { target?: string }).target) || "the host"}`;
      case "edr.host_isolated": return `isolated ${s("host", 60) || "a host"} in EDR`;
      case "edr.host_released": return `released ${s("host", 60) || "a host"} from EDR isolation`;
      case "escalation.bounced": return "bounced an escalation back to Tier-1";
      case "escalation.resolved": return "resolved an escalation";
      case "scope.set": return `set the incident scope${inc}`;
      case "scope.confirmed": return `confirmed the final scope${inc}`;
      case "sitrep.sent": return "sent a SITREP";
      case "staff.inject": return `posted an inject (${asStr((p as { kind?: string }).kind) || "announcement"})`;
      case "ticket.answered": return `answered a help-desk ticket (${asStr((p as { decision?: string }).decision) || "handled"})`;
      // T3 playtest: the finding itself used to be invisible ("logged a hunt finding").
      case "hunt.logged": return `hunt${inc}: “${s("hypothesis", 90)}” → ${s("conclusion", 20) || "logged"}${s("technique", 20) ? ` (${s("technique", 20)})` : ""}${s("finding", 120) ? ` — ${s("finding", 120)}` : ""}`;
      case "rule.published": return `published detection rule "${p.name}" (${p.matched ?? 0} matches)`;
      case "intel.published": return `published intel: ${[s("actor", 40), s("technique", 30), s("ioc", 70)].filter(Boolean).join(" · ") || "context"}${s("relevance", 10) ? ` (relevance ${s("relevance", 10)})` : ""}`;
      case "handover.noted": return "posted a handover note";
      case "decision.logged": return "logged a decision";
      case "evidence.pinned": { const lab = s("summary", 60) || s("label", 60); return `pinned evidence to the case${lab ? `: ${lab}` : ""}`; }
      case "case.status_set": return `set case status → ${p.status}`;
      case "case.assigned": return "assigned the case owner";
      case "note.added": return "added a case note";
      default: return e.type;
    }
  };
  // Throttled screen-reader summary of new team actions (not every item).
  const announcement = useNewItemsAnnouncement(activity, e => e.seq, fresh => {
    const last = fresh[fresh.length - 1];
    const latest = clip(`${nameOf(last.actor_id)} ${label(last)}`);
    return fresh.length === 1 ? `Team activity: ${latest}` : `${fresh.length} new team actions. Latest: ${latest}`;
  }, { throttleMs: 15000 });
  return (
    <Card>
      <LiveRegion message={announcement} />
      <h3 className="text-sm font-bold text-white">Team activity</h3>
      {activity.length === 0 ? <p className="mt-2 text-xs text-slate-400">Actions your team takes appear here, live.</p> : (
        <div className="mt-2 max-h-64 space-y-1.5 overflow-y-auto">
          {activity.slice().reverse().map(e => (
            <p key={e.seq} className="text-[11px] text-slate-400"><bdi className="font-medium text-slate-200">{nameOf(e.actor_id)}</bdi> <bdi>{label(e)}</bdi></p>
          ))}
        </div>
      )}
    </Card>
  );
}
