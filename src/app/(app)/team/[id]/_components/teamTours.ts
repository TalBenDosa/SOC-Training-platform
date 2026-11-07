/**
 * The first-use guided tour of every team-exercise role: what each part of the screen is, what
 * to do with it, and where to click. Anchors are `data-tour` attributes on the room page.
 * Copy rules: plain words, the real button labels, no em dashes.
 */
import type { TourStep } from "./GuidedTour";
import { CONTAINMENT_RULE } from "./shared";

/** A Sentinel session: the same button, but it opens Sentinel. */
const SENTINEL_STEP: Record<string, { title: string; body: string; action: string }> = {
  "edr-button": { title: "Investigate in Sentinel", body: "Detections raise incidents in Sentinel. This button shows how many are open. Open it to read the incident timeline, the entities and the top insights, and to query the logs with KQL.", action: "Click Investigate in Sentinel." },
  "t3-edr": { title: "Open Sentinel", body: "Open Sentinel for the whole workspace: incidents, Logs with KQL, Hunting and the investigation graph.", action: "Click Open Sentinel." },
};

/** The tour with its console steps rewritten for a Sentinel session. */
export function forSentinel(steps: TourStep[]): TourStep[] {
  return steps.map(s => s.target && SENTINEL_STEP[s.target] ? { ...s, ...SENTINEL_STEP[s.target] } : s);
}

type MgrView = "board" | "logs" | "escalations" | "stakeholders" | "reporting";

const common = {
  shared: { target: "shared-case", title: "The Shared case", body: "One case the whole team works from: the incidents, the status, the owner, isolated hosts, pinned evidence and case notes.", action: "Click Shared case in the bar at the top to open it. Add a case note with the field at the bottom." } as TourStep,
  bar: { target: "status", title: "The shift bar", body: "Always at the top: the shift clock (paused time is not counted), the team line with anyone idle flagged, the queue counts, and any notice for you. Nothing pops over your work: notices wait here.", action: "Read the clock and the notices here. When the shift is about to end, a two-minute warning shows here." } as TourStep,
  rule: { title: "The containment rule", body: CONTAINMENT_RULE } as TourStep,
  chat: { target: "chat", title: "Team chat", body: "Talk to the team here: agree who takes what, ask for help, flag what you found. Keep it short and specific (host, user, what you saw).", action: "Type in the box and press Enter. Unread messages light the panel up." } as TourStep,
  injects: { target: "injects", title: "Injects and help-desk tickets", body: "Updates, announcements and help-desk tickets arrive here during the shift. A ticket is answered by Tier-1; an update may change the picture, so react in your own console.", absent: "Nothing has arrived yet. This panel appears with the first inject." } as TourStep,
  guide: { target: "guide-button", title: "You can come back to this guide", body: "Your role, the hand-offs, how you are measured, and this tour again, any time during the shift.", action: "Click Guide, then Start the guided tour." } as TourStep,
};

export const T1_TOUR: TourStep[] = [
  { title: "Welcome, Tier-1 Triage", body: "You are the front line. Every log streams into the SIEM; you decide what is noise and what is real, and you hand the real ones to Tier-2 with evidence. This tour shows where everything is." },
  common.bar,
  { target: "siem-view", title: "Your alert queue", body: "You start on Needs triage: only the alerts nobody has judged yet (high and critical, or medium too if you tick include medium). Take next alert claims the most urgent one and opens its log in the feed.", action: "Click Take next alert." },
  { target: "feed", title: "The live SIEM", body: "The open log shows the fields the source really sent (host, user, process, addresses). Close it from there as false positive or benign, or escalate it. All events shows every log of the shift.", action: "Click a host, user or address inside a log to pivot: the feed filters to that entity." },
  { target: "filters", title: "Filters and search", body: "Narrow the feed by severity and source, or search (host:WS-FIN-2901, user:dana). Active pivots show as chips you can clear.", action: "Use the severity buttons, the source list or the search box." },
  { target: "t1-console", title: "Close, escalate, or add to a case", body: "Not an attack: close it with a short note. Attack or not sure: mark it, then write the escalation report with the indicators. Already handled: add it to the open case instead of escalating it again.", action: "Pick one of the three paths in your console." },
  { target: "edr-button", title: "Investigate in EDR", body: "When an endpoint alert arrives this button lights up. The EDR console shows the process tree, the command line and the host's activity. Tier-1 investigates there; isolating a host is Tier-2's request and the senior on shift's approval.", action: "Click Investigate in EDR when it lights up (the badge counts endpoint alerts).", absent: "This button appears with the feed." },
  common.injects,
  common.shared,
  common.chat,
  common.guide,
];

export const T2_TOUR: TourStep[] = [
  { title: "Welcome, Tier-2 Investigator", body: "You take Tier-1's escalations and run each case to the end: investigate, report, scope, contain, resolve. This tour shows where each step happens." },
  common.bar,
  { target: "t2-console", title: "Escalations for you", body: "Every escalation from Tier-1 lands here, most urgent first, with Tier-1's investigation and the log attached. Acknowledge one to own it. If it is not real, Bounce it back with the reason.", action: "Click Take next case, or Acknowledge (take this case) on a card." },
  { target: "t2-console", title: "Each case shows its steps", body: "A case you own shows five steps: Investigate, Report, Scope, Contain, Resolve. The one highlighted button is your next action; a step that is not open yet says what it waits for.", action: "Click the highlighted button on your case." },
  { target: "feed", title: "Investigate in the feed", body: "Pivot on the host, user and addresses of the case to build the timeline. You can also open a case yourself on a log Tier-1 missed: it is marked as self-opened and carries the indicators you add.", action: "Click a row to open it; use Open a case on this log for one you found." },
  { target: "edr-button", title: "Investigate in EDR", body: "Open the endpoint: process tree, command lines, network connections. Request isolation there with a reason; the host is isolated when the senior on shift approves.", action: "Click Investigate in EDR (or the button on a case)." },
  common.rule,
  { target: "containment-advice", title: "Give your view on a teammate's request", body: "When another analyst asks to contain, say whether you support it or think it is too early. The approver sees your view before deciding.", action: "Click Support, or write a reason and click Object, keep watching.", absent: "This panel appears when a teammate sends a containment request." },
  common.injects,
  common.shared,
  common.chat,
  common.guide,
];

export const T3_TOUR: TourStep[] = [
  { title: "Welcome, Tier-3 / Threat Hunter", body: "You go deeper than the queue: take the hardest cases, hunt for what the alerts missed, confirm the real scope and guide Tier-2. Several Tier-3 analysts can work the same shift: split the hosts between you in the chat." },
  common.bar,
  { target: "t3-views", title: "Your toolkit", body: "Your navigation: the Forensic workbench (collect evidence and read it in memory, autoruns, Prefetch and event-log views), the Live feed, a Timeline across every host in play, an Intel lookup for IPs, domains and hashes, and the ATT&CK library to name what you found.", action: "Click a tab to switch tools. Arrow keys move between them." },
  { target: "t3-edr", title: "Open the EDR console", body: "Pick a host with endpoint telemetry and open it in the EDR console: process tree, RTR shell, hash lookup. Remember: killing a process there removes it from any later memory capture, so capture first.", action: "Choose the host, then click Open EDR." },
  common.rule,
  { target: "workbench", title: "The forensic workbench", body: "Choose a host the team put in play, collect a memory capture or a triage package (it takes simulated time and freezes what the host held at that moment), read it in the tool views, pin rows to your timeline and publish findings that cite them.", action: "Click Memory capture, wait for it in the Evidence locker, then open it." },
  { target: "t3-report", title: "Report to the SOC Manager", body: "Send the manager what you established, whether it is safe to contain now, what you need from them, and when your next update comes. Your published findings attach to it.", action: "Click Report to SOC Manager, fill it in and send." },
  { target: "hunt-console", title: "Elevations and the threat hunt", body: "Tier-2 elevates cases to you with what to hunt. Log each hunt as hypothesis, finding with the evidence, MITRE technique and conclusion. A hunt linked to an elevation answers it.", action: "Fill Hypothesis, Finding / evidence, the MITRE technique and the conclusion, then click Log hunt finding." },
  { target: "hunt-console", title: "Confirm the scope", body: "When you have verified which hosts and users are really involved, confirm the scope. That is the signal the team can contain everything together instead of piece by piece.", action: "Review the scope at the bottom of your console and click Confirm scope (Amend first if it is wrong)." },
  { target: "isolation-approvals", title: "Approving isolation", body: "When no SOC Manager is online, you are the senior on shift: another analyst's isolation request waits for your Approve or Deny at the side of your screen.", absent: "Requests appear here only when you are the approver and someone asks." },
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
    { target: "status", title: "The shift bar", body: "The shift clock, the team line (an idle seat, yours too, is flagged), the queue counts and every notice for you. Nothing pops over your work: notices wait here.", before: view("board") },
    { target: "mgr-menu", title: "Your menu", body: "One view at a time, so the screen never gets crowded. The badges tell you what is waiting: escalations, stakeholder questions, and how long since your last update to management.", action: "Click a tab to switch views. Report to stakeholders opens the incident report.", before: view("board") },
    { title: "Approving containment", body: CONTAINMENT_RULE + " Isolation requests wait for you at the side of your screen, with Approve and Deny; a denial needs a reason the analyst sees.", before: view("board") },
    { target: "desk-incident", title: "Declare the incident", body: "As soon as the first real escalation lands, declare the incident and pick its severity (Sev-1 critical to Sev-4 low). You can change it later, with a reason. Stakeholder questions start after the declaration.", action: "Pick a severity, then click Declare incident. Later: Change severity." },
    { target: "command-desk", title: "Decision cards", body: "Requests from the CISO, Legal and the business, and dilemmas from your own team, arrive here only when something in the shift makes them real (a containment request on a critical server, a teammate's objection, two analysts disagreeing). Each has a deadline; deciding late is also a decision.", action: "Choose an option, say how sure you are (Low / Medium / High), add why, and click Decide. The feedback and the impact appear right after." },
    { target: "desk-impact", title: "Impact indicators", body: "Business continuity, stakeholder trust, team capacity and regulatory exposure. Each starts at 3 of 5 and moves with every decision, and with every request you let expire.", absent: "They appear with your first decision card." },
    { target: "mgr-view", title: "Situation board", body: "The summary of the shift without raw logs: who is online and their load, how fast escalations are picked up (MTTA), the oldest one waiting, logs by severity and source, the escalation queue, team intel and injects.", before: view("board") },
    { target: "mgr-view", title: "Escalations", body: "Every escalation, elevation and containment request, with the analyst's own words, the Tier-2 report and teammates' views. Containment approvals sit on top: approve or deny with the business reason. Add to the stakeholder report turns a case into a line of your report.", action: "Approve or deny a request (a reason is required to deny). Open an escalation to read it.", before: view("escalations") },
    { target: "mgr-view", title: "Logs", body: "The raw logs, read-only, when you need to back up an analyst or check what they report. Triage and escalation stay with the analysts.", action: "Click a row to read it; filter by severity or source.", before: view("logs") },
    { target: "mgr-view", title: "Stakeholders", body: "From the declaration on, the CISO, the CEO's office, Legal, the head of an affected department and Communications ask you here: where are we, how long, is data affected, when is my system back. Answer in your own words: what is confirmed, what is not known yet, and when the next update comes. Checks on your answer appear right after.", action: "Type your answer under the question and click Reply. Write incident report opens the report.", before: view("stakeholders") },
    { target: "report-button", title: "The report to stakeholders", body: "A structured incident report in business language: what happened, the business impact, affected systems, personal data (no evidence so far / suspected / confirmed), actions taken, what is known and not yet known, what you need from them, and when the next update comes. Keep the update time you promise.", action: "Click Report to stakeholders, fill it in and click Send report." },
    { target: "mgr-view", title: "Reporting", body: "SITREPs to management (what is happening, actions taken, status, next steps), your decision log with the reason for each decision, and the shift management panel with each analyst's load and the passdown at the end of the shift.", action: "Fill the four SITREP questions and click Send SITREP. Log decisions with their rationale.", before: view("reporting") },
    { target: "status", title: "Running the shift", body: "You can pause the shift and end it. When the instructor is online, End asks them first. The shift then ends two minutes later, so everyone can send what they are writing, and the shift review opens for everyone, including your Command Review.", action: "Pause or End shift, in the shift bar.", before: view("board") },
    common.chat,
    common.guide,
  ];
}

export const INSTRUCTOR_TOUR: TourStep[] = [
  { title: "Welcome, instructor", body: "You run the exercise: watch every seat, help a stuck player, add pressure when you want, and end the shift to open the review." },
  { target: "seat-board", title: "Seats", body: "Each player's last action, how many minutes they have been idle, and their open load. An idle seat is flagged. Coach sends a short message only that player sees on their screen.", action: "Click Coach on a seat, write one line and send it." },
  { target: "instructor-panel", title: "Instructor tools", body: "The attack schedule, the live answer key (staff only), a composer for your own injects, and reassigning a member to another role.", action: "Write an inject, choose its type and click Send inject. Use Reassign to move a member." },
  { target: "feed", title: "The live feed", body: "The same feed the analysts see, so you can follow the incident as it develops." },
  { target: "status", title: "Pause and end", body: "Pause stops the clock for everyone. End shift ends it two minutes later, so everyone can send their work; End now skips the wait.", action: "Pause or End shift, in the shift bar." },
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
