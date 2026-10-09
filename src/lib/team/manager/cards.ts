/**
 * SOC-Manager decision cards. Each card is a request from a stakeholder (external) or a
 * dilemma from the team (internal) that the manager answers with one option and a confidence.
 *
 * The rule that governs this file (Tal, 2026-10-10): a card exists only because something in
 * the live session made it true. `when()` reads the visible session state (MgrState) and
 * returns the entities the card talks about (the real host, the real analyst, the real
 * request) or null. A card never fires on the clock alone, never names a host or a person the
 * scenario does not have, and never fires because of the hidden answer key. Its ranking is
 * judged on what the manager could know when it fired.
 */
import type { Difficulty, MgrState, Member } from "./state";
import { firstName, teamSuspectsData } from "./state";
import { OVERLOAD_CASES } from "@/lib/team/report/computeReport";
import { hostKey } from "@/lib/team/format";

export type Rank = "great" | "good" | "okay" | "weak";
export type Pillar = "team" | "stakeholders" | "reporting";
export type Audience = "external" | "internal";
export interface Indicators { continuity: number; trust: number; capacity: number; regulatory: number }
export type Delta = Partial<Indicators>;
export type Ctx = Record<string, string>;

export interface OptionDef {
  key: string; label: string; rank: Rank; note: string; delta?: Delta;
  /** A critical error (Command Review caps the score at 69): what the choice did, in one line. */
  critical?: string;
}
export interface CardBuild {
  from: { name: string; role: string };
  channel: "call" | "email" | "chat" | "in person";
  text: string;
  options: OptionDef[];
  deadlineS: number;
  objective: string;
  /** What happens to the indicators when nobody answers in time. */
  timeoutDelta: Delta;
}
export interface CardDef {
  id: string;
  audience: Audience;
  pillar: Pillar;
  minDifficulty: Difficulty;
  /** Higher fires first when several cards are eligible at once. */
  priority: number;
  when(s: MgrState): Ctx | null;
  build(ctx: Ctx, s: MgrState): CardBuild;
}

const DIFF_RANK: Record<Difficulty, number> = { easy: 0, medium: 1, hard: 2 };
export const difficultyAllows = (card: CardDef, d: Difficulty) => DIFF_RANK[d] >= DIFF_RANK[card.minDifficulty];

const minutes = (msv: number) => Math.max(0, Math.floor(msv / 60000));
const clip = (t: string, n: number) => (t.length > n ? `${t.slice(0, n - 1).trimEnd()}…` : t);
const seat = (s: MgrState, role: string): Member | undefined => s.seated[role]?.[0];
const fired = (s: MgrState, id: string) => s.cards.find(c => c.card === id);

/** What a critical system is in the middle of, from its name, for the business owner's words. */
function businessProcessOf(target: string): string {
  if (/pay|gw/i.test(target)) return "the payment run";
  if (/erp|sap/i.test(target)) return "order processing";
  if (/emr|ehr|pacs/i.test(target)) return "patient care";
  if (/(^|[-_])dc\d*([-_]|$)/i.test(target)) return "every login in the company";
  if (/core|swift/i.test(target)) return "today's settlement run";
  if (/file|fs/i.test(target)) return "the finance month-end close";
  if (/bkp|backup/i.test(target)) return "tonight's backup window";
  return "end-of-quarter processing";
}

// Fictional people (no real persons). Same cast in every company so analysts learn the roles.
const CISO = { name: "Maya Klein", role: "CISO" };
const LEGAL = { name: "Noa Ben-Ami", role: "Legal counsel" };
const CFO = { name: "Ron Amsalem", role: "CFO" };
const CEO_OFFICE = { name: "Office of the CEO", role: "Executive" };
const SERVICE_DESK = { name: "IT Service Desk", role: "IT operations" };

export const CARDS: CardDef[] = [
  // ── External: stakeholders ──────────────────────────────────────────────────
  {
    id: "ciso_status", audience: "external", pillar: "reporting", minDifficulty: "easy", priority: 60,
    when: s => {
      const first = s.escalations[0];
      if (!first || s.nowMs - first.atMs < 120_000) return null;
      return { host: first.host, summary: clip(first.summary, 110) };
    },
    build: ctx => ({
      from: CISO, channel: "call", deadlineS: 240, objective: "Report upward: a fixed update time and honest unknowns, not a guess",
      text: `${CISO.name} (${CISO.role}): "I'm told Tier-1 escalated something${ctx.host ? ` on ${ctx.host}` : ""}: ${ctx.summary}. I'm briefing the CEO in 15 minutes. Is this contained or spreading, and what do you need from me?"`,
      timeoutDelta: { trust: -1 },
      options: [
        { key: "best", rank: "great", label: "Promise a short SITREP within 5 minutes: what is confirmed, what is not known yet, and what you need from her.", note: "A fixed time and a structured answer without guessing. She can plan the CEO briefing around it.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Tell her it is too early to say and that you will call back when you know more.", note: "Honest, but with no time for the next update and no ask, she goes into the CEO briefing with nothing." },
        { key: "okay", rank: "okay", label: "Forward her question to the Tier-2 analyst working the case and ask them to answer her directly.", note: "Puts executive pressure on the investigator and pulls them off the case. Shielding the team is your job.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Tell her it is contained.", note: "A claim nobody has checked. If more hosts turn up she has briefed the CEO on a wrong answer.", delta: { trust: -2, regulatory: -1 } },
      ],
    }),
  },
  {
    id: "ciso_bypass", audience: "external", pillar: "stakeholders", minDifficulty: "medium", priority: 65,
    when: s => {
      const c = fired(s, "ciso_status");
      return c && c.expired && !c.answered ? {} : null;
    },
    build: () => ({
      from: CEO_OFFICE, channel: "chat", deadlineS: 180, objective: "Unity of command: one owner of the incident and one channel of updates",
      text: `${CEO_OFFICE.name}: "The CISO could not get an answer from the SOC, so the CEO is asking directly: who is in charge of this incident, and when is the next update?"`,
      timeoutDelta: { trust: -2 },
      options: [
        { key: "best", rank: "great", label: "Confirm you lead the response, give the time of the next update, and send the CISO the same update so there is one channel.", note: "Restores one owner and one channel, and repairs the CISO relationship instead of going around it.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Apologise and send a SITREP to the CEO's office right now.", note: "Answers the question but sets up a second channel that bypasses the CISO." },
        { key: "okay", rank: "okay", label: "Ask the CEO's office to go back through the CISO.", note: "Process is right, tone is wrong: you were the one who did not answer." , delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Ignore it and keep working, the team needs you.", note: "Leadership loses confidence in the SOC at the worst moment.", delta: { trust: -2 } },
      ],
    }),
  },
  {
    id: "owner_veto", audience: "external", pillar: "stakeholders", minDifficulty: "medium", priority: 80,
    when: s => {
      const r = s.containments.find(c => c.status === "pending" && c.critical && c.target);
      return r ? { target: r.target, owner: r.owner || "VP Operations", process: businessProcessOf(r.target) } : null;
    },
    build: ctx => ({
      from: { name: ctx.owner, role: "Business owner" }, channel: "chat", deadlineS: 180, objective: "Containment with business impact: limited containment, agreed and recorded",
      text: `${ctx.owner} (business owner): "I hear the SOC wants to isolate ${ctx.target}. That system is in the middle of ${ctx.process}. If it goes offline we stop. Do not touch it without talking to me."`,
      timeoutDelta: { trust: -1 },
      options: [
        { key: "best", rank: "great", label: "Offer limited containment: block its outbound traffic to the suspicious destinations and watch it closely, keep the service running, and log the decision with the owner's agreement.", note: "Contains the risk without stopping the business, and both sides own a recorded decision.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Take it to the CISO for a decision, with the risk on both sides written down.", note: "The right forum for shutting down a critical system, but the request waits while you escalate." },
        { key: "okay", rank: "okay", label: "Agree not to touch it.", note: "The business keeps running, and a possibly compromised critical system stays fully open.", delta: { regulatory: -1 } },
        { key: "weak", rank: "weak", label: "Approve the full isolation anyway, without telling the owner.", note: "Stops a critical business process behind its owner's back: downtime and broken trust.", delta: { continuity: -2, trust: -2 }, critical: "Isolated a critical business asset without its owner" },
      ],
    }),
  },
  {
    id: "legal_reportable", audience: "external", pillar: "stakeholders", minDifficulty: "medium", priority: 55,
    when: s => {
      if (!s.escalations.length) return null;
      const suspects = teamSuspectsData(s);
      const serious = !!s.declared && s.declared.severity <= 2;
      return suspects || serious ? { suspects: suspects ? "1" : "" } : null;
    },
    build: ctx => {
      const suspects = !!ctx.suspects;
      return {
        from: LEGAL, channel: "email", deadlineS: 300, objective: "Regulatory awareness: start the clock on reasonable suspicion, never claim what is not verified",
        text: `${LEGAL.name} (${LEGAL.role}): "${suspects ? "Your team's notes mention data possibly leaving the network." : "We understand there is a serious security incident."} We may have a duty to report to the regulator. Is personal data involved, and do we need to start the clock?"`,
        timeoutDelta: { regulatory: -1 },
        options: suspects ? [
          { key: "best", rank: "great", label: "Say there is reasonable suspicion, start the reporting clock now, and send her what is confirmed and what is not, so she can file an initial report and update it later.", note: "Reasonable suspicion is enough to start most clocks (Israel: immediately; GDPR: 72 hours from awareness), and a phased report is allowed.", delta: { regulatory: 1 } },
          { key: "good", rank: "good", label: "Say you are still checking and will update her within 30 minutes.", note: "Reasonable, but the clock may already be running while you wait." },
          { key: "okay", rank: "okay", label: "Tell her to wait until the forensic investigation is complete.", note: "Sounds careful, but regulators treat waiting for full forensics as an unreasonable delay.", delta: { regulatory: -1 } },
          { key: "weak", rank: "weak", label: "Tell her no personal data was affected.", note: "An unverified claim while your own team suspects data loss. If it is wrong it becomes a false statement to legal, then to the regulator.", delta: { regulatory: -2, trust: -1 }, critical: "Told Legal no personal data was affected while the team suspected data loss" },
        ] : [
          { key: "best", rank: "great", label: "Say there is no evidence of personal data so far, explain what the team is checking, and give her a fixed time for the next update.", note: "'No evidence so far' is honest; the fixed update keeps legal in the loop if that changes.", delta: { trust: 1 } },
          { key: "good", rank: "good", label: "Start the reporting clock as a precaution and tell her.", note: "Cautious, but with no evidence at all it can trigger a report the facts do not support." },
          { key: "okay", rank: "okay", label: "Tell her to wait for the forensic report.", note: "Leaves legal blind for hours.", delta: { trust: -1 } },
          { key: "weak", rank: "weak", label: "Tell her no personal data was affected.", note: "You do not know that yet. 'No evidence so far' and 'not affected' are different claims.", delta: { regulatory: -1, trust: -1 } },
        ],
      };
    },
  },
  {
    id: "insurer_first", audience: "external", pillar: "stakeholders", minDifficulty: "medium", priority: 40,
    when: s => (s.declared && s.declared.severity <= 2 ? { sev: String(s.declared.severity) } : null),
    build: ctx => ({
      from: CFO, channel: "call", deadlineS: 240, objective: "Call order: insurer before outside vendors",
      text: `${CFO.name} (${CFO.role}): "We have a cyber insurance policy. Before you bring in any outside help, should we call the insurer? I don't want to pay for something they won't cover."`,
      timeoutDelta: { trust: -1 },
      options: [
        { key: "best", rank: "great", label: "Call the insurer's incident hotline now and use their panel incident-response firm and breach counsel.", note: "Most policies require notice before you hire vendors and route you to approved firms; hiring outside the panel can leave the cost uncovered.", delta: { trust: 1, regulatory: 1 } },
        { key: "good", rank: "good", label: "Brief the CISO first, then call the insurer together.", note: "Right order inside the company, a little slower." },
        { key: "okay", rank: "okay", label: "Bring in the incident-response firm you already know and deal with the insurer later.", note: "Fast, but the bill may not be covered.", delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Say no outside help is needed.", note: `The team is on its own with a severity-${ctx.sev} incident; if it grows you lose hours finding help.`, delta: { capacity: -1 } },
      ],
    }),
  },
  {
    id: "board_paragraph", audience: "external", pillar: "reporting", minDifficulty: "hard", priority: 30,
    when: s => (s.declared && s.declared.severity <= 2 && s.nowMs - s.declared.atMs >= 300_000 ? {} : null),
    build: () => ({
      from: CEO_OFFICE, channel: "chat", deadlineS: 240, objective: "Board reporting: business impact first, honest unknowns, no promises you cannot keep",
      text: `${CEO_OFFICE.name}: "The board chair is on the line in 20 minutes. One paragraph: what happened, are customers affected, when are we back to normal?"`,
      timeoutDelta: { trust: -1 },
      options: [
        { key: "best", rank: "great", label: "Write one paragraph in business terms: what is confirmed, the impact on customers and operations, what is still unknown, and the next update time.", note: "Bottom line first, impact before technology, honest unknowns.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Send the latest SITREP as it is.", note: "Accurate, but written for the security team, not the board." },
        { key: "okay", rank: "okay", label: "Ask for more time until the investigation is complete.", note: "The board call happens anyway, without you." , delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Promise everything will be back to normal by tonight.", note: "A time you cannot know. Boards remember missed promises.", delta: { trust: -2 } },
      ],
    }),
  },

  // ── Internal: the team ──────────────────────────────────────────────────────
  {
    id: "unacked_backlog", audience: "internal", pillar: "team", minDifficulty: "easy", priority: 60,
    when: s => {
      const t2 = seat(s, "t2");
      if (!t2) return null;
      const waiting = s.escalations.filter(e => e.open && s.nowMs - e.atMs >= 300_000).sort((a, b) => a.atMs - b.atMs)[0];
      if (!waiting) return null;
      const helper = seat(s, "t3");
      return { summary: clip(waiting.summary, 90), host: waiting.host, mins: String(minutes(s.nowMs - waiting.atMs)), t2: firstName(t2, "Tier-2"), helper: helper ? firstName(helper, "Tier-3") : "" };
    },
    build: ctx => ({
      from: { name: ctx.t2, role: "Tier-2" }, channel: "chat", deadlineS: 180, objective: "Delegation: a named owner and a time, never 'can someone'",
      text: `An escalation from Tier-1 (${ctx.summary}${ctx.host ? ` on ${ctx.host}` : ""}) has waited ${ctx.mins} minutes for Tier-2. ${ctx.t2} is busy with another case.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: `Assign it to a named analyst now (${ctx.helper ? `${ctx.helper} can take it` : "whoever is free"}) with a time to report back.`, note: "A named owner and a deadline: the case starts moving and you know when to check.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Ask Tier-2 to pick it up as soon as possible.", note: "No owner and no time, so it can keep waiting." },
        { key: "okay", rank: "okay", label: "Leave it, the queue will catch up.", note: "An escalated alert ages while an attacker may be moving.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Close it as a false positive to clear the backlog.", note: "Nobody looked at it. If it was real, the attack just disappeared from view.", delta: { regulatory: -1, capacity: -1 } },
      ],
    }),
  },
  {
    id: "t1_overloaded", audience: "internal", pillar: "team", minDifficulty: "easy", priority: 50,
    when: s => {
      for (const m of s.seated.t1 ?? []) {
        const load = s.loadByUser.get(m.user_id) ?? 0;
        if (load >= OVERLOAD_CASES) return { name: firstName(m, "Tier-1"), load: String(load) };
      }
      return null;
    },
    build: ctx => ({
      from: { name: ctx.name, role: "Tier-1" }, channel: "chat", deadlineS: 180, objective: "Prioritise by risk, not arrival order, and add capacity where the queue is",
      text: `${ctx.name} (Tier-1): "I have ${ctx.load} alerts on me and more coming in. I can't get to the high-severity ones. What should I do?"`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Work the queue by severity, hand the low-severity bulk to whoever is free, and move one analyst to help for the next 15 minutes.", note: "Risk first, and capacity where the pressure is.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Tell them to work by severity.", note: "Right priority, but the overload stays." },
        { key: "okay", rank: "okay", label: "Tell them to do their best.", note: "No decision: the overload and the risk stay where they are.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Tell them to close the low-severity alerts as false positives to clear the queue.", note: "Blind closures. Attacks often start with a low-severity alert.", delta: { regulatory: -1 } },
      ],
    }),
  },
  {
    id: "isolate_or_wait", audience: "internal", pillar: "team", minDifficulty: "medium", priority: 80,
    when: s => {
      const t2 = seat(s, "t2"), t3 = seat(s, "t3");
      if (!t2 || !t3 || s.scopeConfirmed) return null;
      const r = s.containments.find(c => c.status === "pending" && c.requesterRole === "t2" && !c.critical && c.target);
      return r ? { target: r.target, t2: firstName(t2, "Tier-2"), t3: firstName(t3, "Tier-3") } : null;
    },
    build: ctx => ({
      from: { name: ctx.t2, role: "Tier-2" }, channel: "in person", deadlineS: 180, objective: "Coordinated containment: limit damage now, isolate when the scope is known",
      text: `${ctx.t2} (Tier-2) wants to isolate ${ctx.target} now. ${ctx.t3} (Tier-3) has not finished the initial response on it and the scope is not confirmed. Isolating one host now may tip the attacker off before the other footholds are known. Your call.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: `Block the host's outbound traffic now, give ${ctx.t3} a fixed 10 minutes to confirm the scope, then isolate every confirmed host together.`, note: "Limits the damage now and avoids piecemeal containment that tips the attacker off (CISA, Microsoft IR guidance).", delta: { regulatory: 1 } },
        { key: "good", rank: "good", label: `Isolate ${ctx.target} now.`, note: "Stops this host fast; the risk is that other footholds stay unknown and the attacker changes tactics." },
        { key: "okay", rank: "okay", label: "Tell them to agree between themselves.", note: "Your decision, left to the team while the clock runs.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Isolate the whole network segment immediately.", note: "Maximum business impact for one host that is not even confirmed yet.", delta: { continuity: -2 } },
      ],
    }),
  },
  {
    id: "reimage_request", audience: "internal", pillar: "team", minDifficulty: "easy", priority: 70,
    when: s => {
      const h = s.isolatedHosts.find(x => s.nowMs - x.atMs >= 60_000);
      return h ? { host: h.host } : null;
    },
    build: ctx => ({
      from: SERVICE_DESK, channel: "call", deadlineS: 180, objective: "Evidence before recovery: isolate, never power off or reimage before memory and triage are captured",
      text: `${SERVICE_DESK.name}: "The user of ${ctx.host} can't work since the SOC isolated it. We'd like to reimage it now and give it back. OK?"`,
      timeoutDelta: { regulatory: -1 },
      options: [
        { key: "best", rank: "great", label: "Not yet: keep it isolated and powered on, capture memory and a triage image first, then rebuild.", note: "Reimaging or powering off destroys the memory and disk evidence of how the attacker got in.", delta: { regulatory: 1 } },
        { key: "good", rank: "good", label: "Give the user a loaner laptop and keep the host isolated until the investigation releases it.", note: "Protects the evidence and the user; imaging still has to be scheduled." },
        { key: "okay", rank: "okay", label: "Reboot it to see if it still works.", note: "A reboot clears memory: the running malware and its network connections are gone.", delta: { regulatory: -1 } },
        { key: "weak", rank: "weak", label: "Approve the reimage.", note: "The evidence is gone, and if this was patient zero you may never learn how they got in.", delta: { regulatory: -2 }, critical: "Approved reimaging an isolated host before evidence was captured" },
      ],
    }),
  },
  {
    id: "silent_analyst", audience: "internal", pillar: "team", minDifficulty: "medium", priority: 45,
    when: s => {
      if (s.firstEscalationMs == null || s.nowMs - s.firstEscalationMs < 480_000) return null;
      const open = s.escalations.filter(e => e.open).length;
      for (const role of ["t2", "t3", "t1"]) for (const m of s.seated[role] ?? []) {
        const last = s.lastActionMs.get(m.user_id);
        const idle = last == null ? s.nowMs - s.firstEscalationMs : s.nowMs - last;
        const load = s.loadByUser.get(m.user_id) ?? 0;
        if (idle >= 480_000 && (open > 0 || load > 0)) return { name: firstName(m, role), role: role === "t1" ? "Tier-1" : role === "t2" ? "Tier-2" : "Tier-3", mins: String(minutes(idle)), open: String(open) };
      }
      return null;
    },
    build: ctx => ({
      from: { name: ctx.name, role: ctx.role }, channel: "in person", deadlineS: 180, objective: "Team awareness: notice a stalled analyst and help, without blame",
      text: `${ctx.name} (${ctx.role}) has not updated anything in ${ctx.mins} minutes, and ${ctx.open} escalated case${ctx.open === "1" ? " is" : "s are"} open.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Message them directly: ask what they are stuck on, and move their open work to someone else if they need help.", note: "Finds out why before acting, and keeps the work moving.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Reassign their open work without asking.", note: "Gets the work moving, but may duplicate what they were doing quietly." },
        { key: "okay", rank: "okay", label: "Wait, they are probably busy.", note: "If they are stuck, nobody will find out.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Post in the team chat that someone is not pulling their weight.", note: "Public blame, no help, worse teamwork.", delta: { capacity: -1, trust: -1 } },
      ],
    }),
  },
  {
    id: "exec_dm_analyst", audience: "internal", pillar: "team", minDifficulty: "hard", priority: 35,
    when: s => {
      const t1 = seat(s, "t1");
      return t1 && s.declared && s.declared.severity <= 2 ? { t1: firstName(t1, "Tier-1") } : null;
    },
    build: ctx => ({
      from: { name: ctx.t1, role: "Tier-1" }, channel: "chat", deadlineS: 180, objective: "Shield the investigators from executive noise",
      text: `A senior VP sent ${ctx.t1} (Tier-1) a direct message: "Send me a list of every affected user, now." ${ctx.t1} asks you what to do.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: `Tell ${ctx.t1} to keep working and route the VP to you: offer the next SITREP time, or ask whether they want to take over command.`, note: "Protects the front line and gives the executive one channel (the PagerDuty playbook for an executive swoop).", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: `Tell ${ctx.t1} to ignore it.`, note: "Protects the analyst but leaves the VP without an answer.", delta: { trust: -1 } },
        { key: "okay", rank: "okay", label: `Ask ${ctx.t1} to put the list together quickly.`, note: "Pulls your front line off the queue in the middle of an incident.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: `Tell ${ctx.t1} to send the raw alert export.`, note: "Unverified data, possibly personal data, sent outside the response.", delta: { regulatory: -1, capacity: -1 } },
      ],
    }),
  },
];

export const CARD_BY_ID = new Map(CARDS.map(c => [c.id, c]));
export const hostsEqual = (a: string, b: string) => hostKey(a) === hostKey(b);
