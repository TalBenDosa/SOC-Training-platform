/**
 * The first-use guided tour of every team-exercise role: what each part of the screen is, what
 * to do with it, and where to click. Anchors are `data-tour` attributes on the room page.
 * Copy rules: plain words, the real button labels, no em dashes.
 */
import type { TourStep } from "./GuidedTour";

type MgrView = "board" | "logs" | "escalations" | "stakeholders" | "reporting";

const common = {
  shared: { target: "shared-case", title: "The Shared Case", body: "One case the whole team works from: the incidents, the status, the owner, pinned evidence and case notes. Open it to see the picture everyone shares.", action: "Click the Shared case bar to expand it. Add a case note with the field at the bottom." } as TourStep,
  chat: { target: "chat", title: "Team chat", body: "Talk to the team here: agree who takes what, ask for help, flag what you found. Keep it short and specific (host, user, what you saw).", action: "Type in the box and press Enter. Unread messages light the panel up." } as TourStep,
  injects: { target: "injects", title: "Injects and help-desk tickets", body: "Updates, announcements and help-desk tickets arrive here during the shift. A ticket is answered by Tier-1; an update may change the picture, so react in your own console.", absent: "Nothing has arrived yet. This panel appears with the first inject." } as TourStep,
  guide: { target: "guide-button", title: "You can come back to this guide", body: "Your role, the hand-offs, how you are measured, and this tour again, any time during the shift.", action: "Click ? Guide, then Start the guided tour." } as TourStep,
};

export const T1_TOUR: TourStep[] = [
  { title: "Welcome, Tier-1 Triage", body: "You are the front line. Every log streams into the SIEM; you decide what is noise and what is real, and you hand the real ones to Tier-2 with evidence. This tour shows where everything is. It takes about two minutes." },
  { target: "role-banner", title: "Your job in one line", body: "This banner always tells you what your seat does right now." },
  { target: "feed", title: "The live SIEM", body: "Every log of the shift arrives here, newest on top. Click a row to open the raw log: the fields the source really sent (host, user, process, IPs).", action: "Click any row to open it. Click a host, user or IP inside a log to pivot: the feed filters to that entity." },
  { target: "siem-view", title: "Your alert queue", body: "Needs triage shows only the alerts nobody has judged yet (high and critical, or medium too if you tick include medium). Take next alert pulls the most urgent one and claims it, so another Tier-1 does not work the same alert.", action: "Click Needs triage, then Take next alert." },
  { target: "filters", title: "Filters and search", body: "Narrow the feed by severity and source, or search (host:WS-FIN-2901, user:dana). Active pivots show as chips you can clear.", action: "Use the severity buttons, the source list or the search box." },
  { target: "t1-console", title: "Triage: your verdict", body: "Pick the log (from the feed or the list), then set a verdict: true positive, false positive, benign or suspicious. Suspicious is a low-confidence lead: use it when you are not sure, never close a doubt as benign.", action: "Choose the log, then click a verdict button." },
  { target: "t1-console", title: "Escalate to Tier-2", body: "For anything real, write the escalation report: a one-line summary, what you observed (the sequence of events, you can paste a screenshot), the indicators (IOCs), your assessment, severity and the action you ask for. A complete report saves Tier-2 time.", action: "Click Write escalation report (or the flag on a feed row), fill it in, then Escalate to Tier-2. Track the status under My escalations." },
  { target: "edr-button", title: "Investigate in EDR", body: "When an endpoint alert arrives this button lights up. The EDR console shows the process tree, the command line and the host's activity. Tier-1 investigates there but does not isolate hosts: containment belongs to Tier-2 and the SOC Manager.", action: "Click Investigate in EDR when it lights up (the red badge counts endpoint alerts).", absent: "This button appears with the feed." },
  common.injects,
  common.shared,
  common.chat,
  common.guide,
];

export const T2_TOUR: TourStep[] = [
  { title: "Welcome, Tier-2 Investigator", body: "You take Tier-1's escalations and run them to ground: investigate in depth, write the report, set the scope, and ask the SOC Manager to contain. This tour shows where each step happens." },
  { target: "role-banner", title: "Your job in one line", body: "This banner always tells you what your seat does right now." },
  { target: "t2-console", title: "Escalations for you", body: "Every escalation from Tier-1 lands here, most urgent first, with Tier-1's investigation and the log attached. Acknowledge one to own it, so Tier-1 knows it is being handled. If it is not real, Bounce it back with the reason.", action: "Click Take next case, or Acknowledge (take this case) on a card. Use Bounce to return it with a reason." },
  { target: "feed", title: "Investigate in the feed", body: "Pivot on the host, user and IPs of the case to build the timeline. You can also open a case yourself on a log Tier-1 missed.", action: "Click a row to open it; use the case button on a row to open a case on it." },
  { target: "edr-button", title: "Investigate in EDR", body: "Open the endpoint: process tree, command lines, network connections. You may isolate a host there when the evidence supports it.", action: "Click Investigate in EDR (or the EDR button on a case)." },
  { target: "t2-console", title: "Write the report and set the scope", body: "On a case you own: Write report (verdict, findings, recommendation), then set the scope: every host and user involved. Pin the key evidence to the Shared Case.", action: "Click Write report, fill it in and file it. Then use Set scope. Pin to case puts a log on the Shared Case." },
  { target: "t2-console", title: "Ask for containment, or hand to Tier-3", body: "With a report filed and a scope set, ask the SOC Manager to contain a target (isolate a host, disable an account). For a deep hunt, elevate to Tier-3 and say what to hunt. When the manager approves, carry out the containment and mark it executed.", action: "Click Request containment, fill the target and justification, and send. Use the elevate option to hand off to Tier-3. Approved requests appear under Execute." },
  { target: "containment-advice", title: "Give your view on a teammate's request", body: "When another analyst asks to contain, say whether you support it or think it is too early (the scope is not confirmed, it would tip off the attacker). The SOC Manager sees your view before deciding.", action: "Click Support, or write a reason and click Object, keep watching.", absent: "This panel appears when a teammate sends a containment request." },
  common.injects,
  common.shared,
  common.chat,
  common.guide,
];

export const T3_TOUR: TourStep[] = [
  { title: "Welcome, Tier-3 / Threat Hunter", body: "You go deeper than the queue: take the hardest cases, hunt for what the alerts missed, confirm the real scope and guide Tier-2. Several Tier-3 analysts can work the same shift: split the hosts between you in the chat." },
  { target: "role-banner", title: "Your job in one line", body: "This banner always tells you what your seat does right now." },
  { target: "hunt-console", title: "Elevations and the threat hunt", body: "Tier-2 elevates cases to you with what to hunt. Log each hunt as hypothesis, finding with the evidence, MITRE technique and conclusion. A hunt linked to an elevation answers it.", action: "Fill Hypothesis, Finding / evidence, the MITRE technique and the conclusion, then click Log hunt finding." },
  { target: "hunt-console", title: "Confirm the scope", body: "When you have verified which hosts and users are really involved, confirm the scope. That is the signal the team can contain everything together instead of piece by piece.", action: "Review the scope at the bottom of your console and click Confirm scope (Amend first if it is wrong)." },
  { target: "edr-button", title: "Forensics in EDR", body: "Process tree, command lines, persistence and network activity of a host. This is where most of your evidence comes from.", action: "Click Investigate in EDR." },
  { target: "t2-console", title: "The escalation inbox", body: "The same inbox as Tier-2, folded so hunting stays first. Take the hardest cases, write the report and request containment like Tier-2.", action: "Open the inbox with the arrow next to Escalations for you." },
  { target: "containment-advice", title: "Your view on containment", body: "If a teammate wants to isolate a host before the scope is known, object with the reason (for example: capture memory first). The SOC Manager sees it before deciding; a real objection is what puts the dilemma on their desk.", action: "Click Support, or write a reason and click Object, keep watching.", absent: "This panel appears when a teammate sends a containment request." },
  { target: "feed", title: "Hunt in the feed", body: "Search and pivot across every log of the shift, not only the escalated ones: look for the same host, user, hash or destination elsewhere.", action: "Search (host:..., user:...) and click entities inside logs to pivot." },
  common.shared,
  common.chat,
  common.guide,
];

export function mgrTour(setView: (v: MgrView) => void): TourStep[] {
  const view = (v: MgrView) => () => setView(v);
  return [
    { title: "Welcome, SOC Manager", body: "You command the incident: you manage the team, handle the stakeholders and keep management informed. You do not investigate logs yourself. Your screen is one menu with five views, plus your Command desk that always stays on the side. This tour walks through all of it.", before: view("board") },
    { target: "mgr-menu", title: "Your menu", body: "One view at a time, so the screen never gets crowded. The badges tell you what is waiting: escalations, stakeholder questions, and how long since your last update to management.", action: "Click a tab to switch views. Report to stakeholders opens the incident report.", before: view("board") },
    { target: "desk-incident", title: "Declare the incident", body: "As soon as the first real escalation lands, declare the incident and pick its severity (Sev-1 critical to Sev-4 low). You can change it later, with a reason. Stakeholder questions start after the declaration.", action: "Pick a severity, then click Declare incident. Later: Change severity." },
    { target: "command-desk", title: "Decision cards", body: "Requests from the CISO, Legal and the business, and dilemmas from your own team, arrive here only when something in the shift makes them real (a containment request on a critical server, a teammate's objection, two analysts disagreeing). Each has a deadline; deciding late is also a decision.", action: "Choose an option, say how sure you are (Low / Medium / High), add why, and click Decide. The feedback and the impact appear right after." },
    { target: "desk-impact", title: "Impact indicators", body: "Business continuity, stakeholder trust, team capacity and regulatory exposure. Each starts at 3 of 5 and moves with every decision, and with every request you let expire.", absent: "They appear with your first decision card." },
    { target: "mgr-view", title: "Situation board", body: "The summary of the shift without raw logs: who is online and their load, how fast escalations are picked up (MTTA), the oldest one waiting, logs by severity and source, the escalation queue, team intel and injects.", before: view("board") },
    { target: "mgr-view", title: "Escalations", body: "Every escalation, elevation and containment request, with the analyst's own words, the Tier-2 report and teammates' views. Containment approvals sit on top: approve or deny with the business reason. Add to the stakeholder report turns a case into a line of your report.", action: "Approve or deny a request (a reason is required to deny). Open an escalation to read it.", before: view("escalations") },
    { target: "mgr-view", title: "Logs", body: "The raw logs, read-only, when you need to back up an analyst or check what they report. Triage and escalation stay with the analysts.", action: "Click a row to read it; filter by severity or source.", before: view("logs") },
    { target: "mgr-view", title: "Stakeholders", body: "From the declaration on, the CISO, the CEO's office, Legal, the head of an affected department and Communications ask you here: where are we, how long, is data affected, when is my system back. Answer in your own words: what is confirmed, what is not known yet, and when the next update comes. Checks on your answer appear right after.", action: "Type your answer under the question and click Reply. Write incident report opens the report.", before: view("stakeholders") },
    { target: "report-button", title: "The report to stakeholders", body: "A structured incident report in business language: what happened, the business impact, affected systems, personal data (no evidence so far / suspected / confirmed), actions taken, what is known and not yet known, what you need from them, and when the next update comes. Keep the update time you promise.", action: "Click Report to stakeholders, fill it in and click Send report." },
    { target: "mgr-view", title: "Reporting", body: "SITREPs to management (what is happening, actions taken, status, next steps), your decision log with the reason for each decision, and the shift management panel with each analyst's load and the passdown at the end of the shift.", action: "Fill the four SITREP questions and click Send SITREP. Log decisions with their rationale.", before: view("reporting") },
    { target: "status", title: "Running the shift", body: "You can pause the shift and end it. Ending it opens the shift review for everyone, including your Command Review: how you led the team, handled stakeholders and reported, plus the team's outcome.", action: "Pause or End session, here.", before: view("board") },
    common.chat,
    common.guide,
  ];
}

export const INSTRUCTOR_TOUR: TourStep[] = [
  { title: "Welcome, instructor", body: "You run the exercise: watch every role, add pressure when you want, and end the shift to open the review." },
  { target: "instructor-panel", title: "Instructor view", body: "The roster and who is online, a composer to send your own injects (with the expected response as a staff-only answer key), and reassigning a member to another role.", action: "Write an inject, choose its type and click Send inject. Use Reassign to move a member." },
  { target: "feed", title: "The live feed", body: "The same feed the analysts see, so you can follow the incident as it develops." },
  { target: "status", title: "Pause and end", body: "Pause the shift if the team needs a break; End session closes it and opens the shift review for everyone.", action: "Pause or End session, here." },
  common.chat,
];

export function tourFor(role: string | null | undefined, setMgrView: (v: MgrView) => void): { title: string; steps: TourStep[] } | null {
  switch (role) {
    case "t1": return { title: "Tier-1 tour", steps: T1_TOUR };
    case "t2": return { title: "Tier-2 tour", steps: T2_TOUR };
    case "t3": return { title: "Tier-3 tour", steps: T3_TOUR };
    case "mgr": case "lead": return { title: "SOC Manager tour", steps: mgrTour(setMgrView) };
    case "instructor": return { title: "Instructor tour", steps: INSTRUCTOR_TOUR };
    default: return null;
  }
}
