"use client";
import { Button } from "@/components/ui/Button";
import { ROLE_LABEL } from "./shared";

// How a real SOC ticket flows tier-to-tier (grounded in the SOC operations
// research + docs/SPEC-team-roles-playbook.md). Shown in the first-use guide.
const OVERALL_FLOW = "A real incident moves tier to tier, investigated deeper at each hop: Tier-1 triages the alert queue and escalates the real ones with evidence → Tier-2 acknowledges, investigates in depth and asks for containment → Tier-3 hunts deeper and confirms scope → the SOC Manager approves containment, records decisions & SITREPs, and drives the case to closure. Everyone works one Shared Case.";
interface RoleGuide { mission: string; steps: string[]; flow: string; measured: string[] }
const ROLE_GUIDE: Record<string, RoleGuide> = {
  t1: { mission: "You're the front line — triage every alert fast and pass the real ones up with evidence.",
    steps: ["Watch the Live SIEM feed; click a log to read its raw detail.", "Set a disposition on each in your console: True Positive / False Positive / Benign.", "For anything real, fill the Escalate-to-Tier-2 form (what you saw · why it's suspicious · impact · confidence) and send it.", "📌 Pin the key logs to the Shared Case."],
    flow: "IN: raw alerts from the feed.  OUT: escalate to Tier-2 (escalation.requested).", measured: ["Disposition accuracy vs ground truth", "Escalation completeness & correctness", "Time to triage"] },
  t2: { mission: "You take Tier-1's escalations and run them to ground.",
    steps: ["Open 'Escalations for you' and Acknowledge each (so T1 knows it's owned).", "Investigate: pivot in the feed, open the EDR console, build the timeline, pin evidence.", "Set the case scope; keep the Shared Case status current.", "When containment is needed, send a Containment request to the SOC Manager."],
    flow: "IN: escalation.requested from T1.  OUT: containment.requested to the SOC Manager; loop in T3 for deep hunts.", measured: ["Acknowledge latency", "Scope accuracy", "Quality & timing of the containment request"] },
  t3: { mission: "Senior investigator & threat hunter — go deeper than the queue.",
    steps: ["Take the hardest escalations from the inbox.", "Form a hypothesis and hunt the feed for related activity.", "Log your hunt findings (hypothesis → evidence → MITRE technique).", "Confirm the real scope and advise Tier-2."],
    flow: "IN: hard cases from T2.  OUT: findings & confirmed scope to the SOC Manager, guidance to T2.", measured: ["Hunt findings yield", "Scope / attribution accuracy", "Depth of investigation"] },
  lead: { mission: "Incident Commander — coordinate, decide, own the case. You don't investigate yourself.",
    steps: ["Watch the Shared Case and the team's requests.", "Approve or deny Containment requests (with a reason).", "Advance the case status and assign the owner.", "Drive the case toward Contained → Closed."],
    flow: "IN: containment.requested from T2/T3.  OUT: approve/deny + case decisions.", measured: ["Decision speed & correctness", "Case progression", "Coordination"] },
  de: { mission: "Detection Engineer — close detection gaps live.",
    steps: ["Follow what the team is chasing.", "Write a rule (name + keyword) — it back-tests against the live feed instantly.", "Publish rules that catch the attack technique.", "Tune to cut noise."],
    flow: "You support the whole team by turning findings into detections (rule.published).", measured: ["Rule matches (verifiable)", "False-positive rate", "Time to publish"] },
  ti: { mission: "Threat Intel — turn indicators into context and prediction.",
    steps: ["Follow the incident's indicators.", "Publish an intel note: actor/technique · confidence · recommended action · next expected step.", "Tell the team what to block and what's coming."],
    flow: "You support T1/T2/Lead with actionable intel (intel.published → Team intel card).", measured: ["Actionable notes", "Attribution accuracy", "Predicting the next step"] },
  mgr: { mission: "SOC Manager — the incident authority: approve containment, coordinate, and keep the shift healthy.",
    steps: ["Approve or deny containment requests from Tier-2 (weigh the business impact).", "Log key decisions and send a SITREP as the picture develops.", "Watch workload/SLA; at shift end, sign the passdown (open cases · next steps)."],
    flow: "You approve containment (containment.approved), record decisions & SITREPs, and own the shift handover.", measured: ["Time-to-approval", "Workload balance", "SITREP cadence", "Handover quality"] },
  instructor: { mission: "You run the exercise — monitor every role, then end it to reveal the report.",
    steps: ["Watch the roster and Team activity.", "Let the incident unfold; the feed streams to everyone live.", "Click 'End exercise' to generate the after-action report."],
    flow: "You control the session; the players work their roles.", measured: ["—"] },
};
export function roleDirective(role: string | null | undefined): string {
  switch (role) {
    case "t1": return "Triage the feed — set a disposition on each log, and escalate anything real to Tier-2.";
    case "t2": return "Work your escalation inbox — acknowledge, investigate, then request containment from the SOC Manager.";
    case "t3": return "Hunt deeper — take hard cases, log findings, confirm scope.";
    case "lead": return "Command the incident — approve/deny containment and drive the case status.";
    case "de": return "Write & publish detection rules that catch the attack (they back-test live).";
    case "ti": return "Publish intel — actor, technique, and the next expected step.";
    case "mgr": return "Approve/deny containment, log decisions & SITREPs, balance the shift, and sign the passdown.";
    case "instructor": return "Monitor all roles; end the exercise to reveal the report.";
    default: return "Watch the shared feed.";
  }
}
export function RoleGuideModal({ role, onClose }: { role: string | null; onClose: () => void }) {
  const g = ROLE_GUIDE[role ?? ""] ?? ROLE_GUIDE.instructor;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white">Your role: {ROLE_LABEL[role ?? ""] ?? "Observer"}</h2>
          <button onClick={onClose} aria-label="Close" className="text-xl leading-none text-slate-400 hover:text-white">&times;</button>
        </div>
        <p className="mt-2 text-sm text-slate-200">{g.mission}</p>
        <div className="mt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">What you do</p>
          <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-slate-300">{g.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </div>
        <div className="mt-3 rounded-lg border border-border bg-bg px-3 py-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Hand-off</p>
          <p className="mt-0.5 text-xs text-slate-300">{g.flow}</p>
        </div>
        <div className="mt-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">You&apos;re measured on</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-slate-400">{g.measured.map((m, i) => <li key={i}>{m}</li>)}</ul>
        </div>
        <div className="mt-4 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">How the team works together</p>
          <p className="mt-0.5 text-xs text-slate-300">{OVERALL_FLOW}</p>
        </div>
        <Button variant="primary" size="sm" className="mt-4 w-full" onClick={onClose}>Got it</Button>
      </div>
    </div>
  );
}
