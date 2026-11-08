"use client";
import { useRef } from "react";
import { Button } from "@/components/ui/Button";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { ROLE_LABEL, CONTAINMENT_RULE } from "./shared";

// How a real SOC ticket flows tier to tier (docs/SPEC-team-roles-playbook.md), in the words of the
// screens as they are today (2026-11 review: the old cards named raw event types and old buttons).
const OVERALL_FLOW = "Tier-1 works the Needs triage queue and escalates the real alerts with evidence. Tier-2 takes the case, investigates, files the report, sets the scope and asks for containment. Tier-3 hunts deeper, collects forensics and confirms the scope. The SOC Manager declares the incident, approves containment and keeps management informed. Everyone works one Shared case.";
interface RoleGuide { mission: string; steps: string[]; flow: string; measured: string[] }
const ROLE_GUIDE: Record<string, RoleGuide> = {
  t1: { mission: "You are the front line: judge every alert in your queue, close the noise, and pass the real ones to Tier-2 with evidence.",
    steps: ["You start on Needs triage: the alerts nobody has judged yet. Click Take next alert: the log opens in the feed and is claimed for you.", "Read the log. Pivot on the host, user or address to see what else happened around it.", "Not an attack: Close as false positive or Close as benign, with a short note.", "Attack, or not sure: mark it True positive or Suspicious, then Write escalation report with the indicators (+IOC) and send it to Tier-2.", "Already handled: if the host or the attack already has a case, choose Add to a case instead of escalating it again."],
    flow: "In: the alert queue. Out: escalation reports to Tier-2, and logs added to open cases.", measured: ["Correct calls on the alerts you judged", "Complete escalations: summary, evidence, indicators", "Time from an alert arriving to your call"] },
  t2: { mission: "You take Tier-1's escalations and run each case to the end.",
    steps: ["Take next case (or Acknowledge one) under Escalations for you. You can also open a case yourself on a log you found: it is marked as self-opened.", "Each case you own shows its steps: Investigate, Report, Scope, Contain, Resolve. The highlighted button is the next thing to do.", "Investigate in the feed and in the EDR console, file the report, then set the scope: every host and user involved.", "Contain: ask for it with a reason. The senior on shift approves before anything is isolated.", "Resolve the case when it is contained or proved harmless."],
    flow: "In: escalations from Tier-1. Out: reports, scope and containment requests; deep hunts to Tier-3.", measured: ["Time to take a case", "Report and scope quality", "Containment that matches the evidence"] },
  t3: { mission: "Senior investigator and threat hunter: go deeper than the queue.",
    steps: ["Start in the Forensic workbench: collect memory or a triage package from a host in play before anything is killed or isolated.", "Take the hunts Tier-2 elevates to you, and log each finding with its evidence and ATT&CK technique.", "Confirm the scope when you know which hosts and users are really involved.", "Send the SOC Manager a forensic report: what you established and whether it is safe to contain.", "When no SOC Manager is online, you approve the isolation requests of the others."],
    flow: "In: elevations and hard cases. Out: findings, a confirmed scope and forensic reports.", measured: ["Findings backed by evidence", "Scope accuracy", "Evidence collected before containment"] },
  lead: { mission: "Incident Commander: coordinate, decide, own the case. You do not investigate yourself.",
    steps: ["Watch the Shared case and the team's requests.", "Approve or deny containment and isolation requests, with a reason.", "Move the case status and give it an owner.", "Drive the case to contained, then closed."],
    flow: "In: containment and isolation requests. Out: decisions and case status.", measured: ["Decision speed and quality", "Case progression", "Coordination"] },
  de: { mission: "Detection Engineer: close detection gaps while the shift runs.",
    steps: ["Follow what the team is chasing.", "Write a rule (name and keyword): it is tested against the live feed at once.", "Publish rules that catch the attack technique.", "Tune them to cut noise."],
    flow: "You turn the team's findings into published detections.", measured: ["Rules that match", "False-positive rate", "Time to publish"] },
  ti: { mission: "Threat Intel: turn indicators into context and a prediction.",
    steps: ["Follow the incident's indicators.", "Publish an intel note: actor or technique, confidence, the action you recommend, and the next expected step.", "Tell the team what to block and what is coming."],
    flow: "Your notes reach the whole team in the Team intel card.", measured: ["Actionable notes", "Attribution accuracy", "Predicting the next step"] },
  mgr: { mission: "SOC Manager: you command the incident. You manage the team, handle the stakeholders and keep management informed. You do not investigate yourself.",
    steps: ["Declare the incident and its severity on your Command desk as soon as the first real escalation lands.", "Decide the cards on your Command desk before their deadline, and say how sure you are.", "Approve or deny isolation and containment requests: they wait for you at the side of your screen.", "Watch the team line: an idle seat is flagged. Give every case an owner.", "Answer stakeholders, send the incident report and SITREPs, and sign the passdown at the end."],
    flow: "In: escalations, containment and isolation requests, stakeholder questions. Out: declarations, decisions, SITREPs and the passdown.", measured: ["Team and incident 35%", "Stakeholders 25%", "Reporting to management 25%", "Team outcome 15%"] },
  instructor: { mission: "You run the exercise: watch every seat, help a stuck player, and end the shift.",
    steps: ["The Seats board shows each player's last action, idle minutes and open load. Send a coach message to one seat when it is stuck.", "Add pressure with an inject when you want, or release a planned attack now.", "You approve isolation requests when no SOC Manager or Tier-3 is online.", "End the shift: it ends two minutes later so everyone can send their work. End now skips the wait."],
    flow: "You control the session; the players work their roles.", measured: ["Not scored"] },
  observer: { mission: "Observer: you watch the exercise. The exercise admin runs it.",
    steps: ["Follow the shared feed and the team chat.", "You take no actions in the exercise."],
    flow: "You watch; the players work their roles.", measured: ["Not scored"] },
};
export function roleDirective(role: string | null | undefined): string {
  switch (role) {
    case "t1": return "Work your Needs triage queue: Take next alert, read the log, then close it or escalate it to Tier-2.";
    case "t2": return "Take a case and follow its steps: investigate, report, scope, contain, resolve.";
    case "t3": return "Collect forensics first, hunt what Tier-2 elevates, then confirm the scope.";
    case "lead": return "Command the incident: approve or deny containment and drive the case status.";
    case "de": return "Write and publish detection rules that catch the attack (they test against the live feed).";
    case "ti": return "Publish intel: actor, technique, and the next expected step.";
    case "mgr": return "Declare the incident, decide your Command desk, approve containment, and keep management informed.";
    case "instructor": return "Watch the seats, coach a stuck player, end the shift when it is time.";
    default: return "Watch the shared feed.";
  }
}
export function RoleGuideModal({ role, onClose, onStartTour, isSentinel = false, tourLabel }: { role: string | null; onClose: () => void; onStartTour?: () => void; isSentinel?: boolean; /** e.g. "12 steps, about 3 min": the tour button says what it costs. */ tourLabel?: string }) {
  const g = ROLE_GUIDE[role ?? ""] ?? ROLE_GUIDE.instructor;
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, dialogRef, { onEscape: onClose });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="role-guide-title" tabIndex={-1} className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 id="role-guide-title" className="text-base font-bold text-white">Your role: {ROLE_LABEL[role ?? ""] ?? "Observer"}</h2>
          <button onClick={onClose} aria-label="Close" className="rounded text-xl leading-none text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">&times;</button>
        </div>
        <p className="mt-2 text-sm text-slate-200">{g.mission}</p>
        <div className="mt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">What you do</p>
          <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-slate-300">{g.steps.map((s, i) => <li key={i}>{isSentinel ? s.replace(/the EDR console/g, "XDR").replace(/Investigate in EDR/g, "Investigate in XDR") : s}</li>)}</ol>
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
          <p className="mt-1.5 text-xs text-slate-300"><b className="text-slate-200">The containment rule:</b> {CONTAINMENT_RULE}</p>
        </div>
        {onStartTour ? (
          <div className="mt-4 flex flex-col gap-2 sm:flex-row">
            <Button variant="primary" size="sm" className="flex-1" onClick={onStartTour}>Start the guided tour{tourLabel ? ` (${tourLabel})` : ""}</Button>
            <Button variant="outline" size="sm" onClick={onClose}>Not now</Button>
          </div>
        ) : <Button variant="primary" size="sm" className="mt-4 w-full" onClick={onClose}>Got it</Button>}
        {onStartTour && <p className="mt-2 text-center text-[11px] text-slate-500">The tour points at each part of your screen and shows where to click. Reopen it any time from ? Guide.</p>}
      </div>
    </div>
  );
}
