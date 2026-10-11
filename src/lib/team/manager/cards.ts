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
const roleLabel = (r: string | null | undefined) => (r === "t1" ? "Tier-1" : r === "t2" ? "Tier-2" : r === "t3" ? "Tier-3" : r === "mgr" ? "SOC Manager" : "analyst");

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
        { key: "best", rank: "great", label: "Promise a short SITREP in 5 minutes: what is confirmed, what is not, and what you need.", note: "A fixed time and a structured answer without guessing. She can plan the CEO briefing around it.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Say it is too early to tell and that you will call her back once you know more.", note: "Honest, but with no time for the next update and no ask, she goes into the CEO briefing with nothing." },
        { key: "okay", rank: "okay", label: "Ask the Tier-2 analyst working the case to call her and answer her questions directly.", note: "Puts executive pressure on the investigator and pulls them off the case. Shielding the team is your job.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Tell her it is contained, so she can reassure the CEO in the briefing.", note: "A claim nobody has checked. If more hosts turn up she has briefed the CEO on a wrong answer.", delta: { trust: -2, regulatory: -1 } },
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
        { key: "best", rank: "great", label: "Confirm you lead, give the next update time, and copy the CISO so there is one channel.", note: "Restores one owner and one channel, and repairs the CISO relationship instead of going around it.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Apologise and send a SITREP straight to the CEO's office right now, as they asked.", note: "Answers the question but sets up a second channel that bypasses the CISO." },
        { key: "okay", rank: "okay", label: "Politely ask the CEO's office to route their question back through the CISO.", note: "Process is right, tone is wrong: you were the one who did not answer." , delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Keep working and ignore it for now: the team needs you more than the executives do.", note: "Leadership loses confidence in the SOC at the worst moment.", delta: { trust: -2 } },
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
        { key: "best", rank: "great", label: "Limit it: block its outbound traffic, keep the service running, record the call with the owner.", note: "Contains the risk without stopping the business, and both sides own a recorded decision.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Take it to the CISO for a decision, with the risk on both sides written down.", note: "The right forum for shutting down a critical system, but the request waits while you escalate." },
        { key: "okay", rank: "okay", label: "Agree not to touch it for now, since the business cannot afford the downtime.", note: "The business keeps running, and a possibly compromised critical system stays fully open.", delta: { regulatory: -1 } },
        { key: "weak", rank: "weak", label: "Approve the full isolation anyway, without telling the owner, to stop the spread fast.", note: "Stops a critical business process behind its owner's back: downtime and broken trust.", delta: { continuity: -2, trust: -2 }, critical: "Isolated a critical business asset without its owner" },
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
          { key: "best", rank: "great", label: "Say there is reasonable suspicion, start the clock now, and send her what is confirmed so far.", note: "Reasonable suspicion is enough to start most clocks (Israel: immediately; GDPR: 72 hours from awareness), and a phased report is allowed.", delta: { regulatory: 1 } },
          { key: "good", rank: "good", label: "Say you are still checking the data question and will update her within 30 minutes.", note: "Reasonable, but the clock may already be running while you wait." },
          { key: "okay", rank: "okay", label: "Tell her to wait until the forensic investigation is complete before deciding anything.", note: "Sounds careful, but regulators treat waiting for full forensics as an unreasonable delay.", delta: { regulatory: -1 } },
          { key: "weak", rank: "weak", label: "Tell her no personal data was affected, so she can stand down the reporting process.", note: "An unverified claim while your own team suspects data loss. If it is wrong it becomes a false statement to legal, then to the regulator.", delta: { regulatory: -2, trust: -1 }, critical: "Told Legal no personal data was affected while the team suspected data loss" },
        ] : [
          { key: "best", rank: "great", label: "Say there is no evidence of personal data so far, what is being checked, and the next update.", note: "'No evidence so far' is honest; the fixed update keeps legal in the loop if that changes.", delta: { trust: 1 } },
          { key: "good", rank: "good", label: "Start the reporting clock as a precaution anyway, and tell her you have done so.", note: "Cautious, but with no evidence at all it can trigger a report the facts do not support." },
          { key: "okay", rank: "okay", label: "Tell her to wait for the forensic report before you say anything about data.", note: "Leaves legal blind for hours.", delta: { trust: -1 } },
          { key: "weak", rank: "weak", label: "Tell her no personal data was affected, so she can stand down the reporting process.", note: "You do not know that yet. 'No evidence so far' and 'not affected' are different claims.", delta: { regulatory: -1, trust: -1 } },
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
        { key: "best", rank: "great", label: "Call the insurer's hotline now and use their panel IR firm and lawyers, as the policy requires.", note: "Most policies require notice before you hire vendors and route you to approved firms; hiring outside the panel can leave the cost uncovered.", delta: { trust: 1, regulatory: 1 } },
        { key: "good", rank: "good", label: "Brief the CISO first, then call the insurer together once you both have the facts.", note: "Right order inside the company, a little slower." },
        { key: "okay", rank: "okay", label: "Bring in the incident-response firm you already know and deal with the insurer later.", note: "Fast, but the bill may not be covered.", delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Say no outside help is needed: the internal team has this fully under control.", note: `The team is on its own with a severity-${ctx.sev} incident; if it grows you lose hours finding help.`, delta: { capacity: -1 } },
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
        { key: "best", rank: "great", label: "One paragraph in business terms: what is confirmed, the impact, what is being done, next update.", note: "Bottom line first, impact before technology, honest unknowns.", delta: { trust: 1 } },
        { key: "good", rank: "good", label: "Send the latest SITREP as it is, so the board gets the full technical detail.", note: "Accurate, but written for the security team, not the board." },
        { key: "okay", rank: "okay", label: "Ask for more time and send the board a summary once the investigation is complete.", note: "The board call happens anyway, without you." , delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Promise everything will be back to normal by tonight, to calm the board down.", note: "A time you cannot know. Boards remember missed promises.", delta: { trust: -2 } },
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
      from: { name: "Shift board", role: "Escalation queue" }, channel: "in person", deadlineS: 180, objective: "Delegation: a named owner and a time, never 'can someone'",
      text: `An escalation from Tier-1 (${ctx.summary}${ctx.host ? ` on ${ctx.host}` : ""}) has waited ${ctx.mins} minutes for Tier-2. ${ctx.t2} is busy with another case.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: `Assign it to a named analyst now (${ctx.helper ? `${ctx.helper} can take it` : "whoever is free"}) with a time to report back.`, note: "A named owner and a deadline: the case starts moving and you know when to check.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Ask Tier-2 to pick it up as soon as possible, whoever is free first.", note: "No owner and no time, so it can keep waiting." },
        { key: "okay", rank: "okay", label: "Leave it for now: the queue usually catches up once the burst passes.", note: "An escalated alert ages while an attacker may be moving.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Close it as a false positive to clear the backlog, and recheck it later.", note: "Nobody looked at it. If it was real, the attack just disappeared from view.", delta: { regulatory: -1, capacity: -1 } },
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
      from: { name: "Shift board", role: "Team load" }, channel: "in person", deadlineS: 180, objective: "Prioritise by risk, not arrival order, and add capacity where the queue is",
      text: `${ctx.name} (Tier-1) is holding ${ctx.load} open alerts and new ones keep arriving.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Work by severity, hand the low-severity bulk to whoever is free, and add one analyst for 15 min.", note: "Risk first, and capacity where the pressure is.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Tell them to work strictly by severity, highest first, and leave the rest for later.", note: "Right priority, but the overload stays." },
        { key: "okay", rank: "okay", label: "Tell them to do their best and keep going: the shift is busy for everyone.", note: "No decision: the overload and the risk stay where they are.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Tell them to close the low-severity alerts as false positives to clear the queue.", note: "Blind closures. Attacks often start with a low-severity alert.", delta: { regulatory: -1 } },
      ],
    }),
  },
  {
    id: "isolate_or_wait", audience: "internal", pillar: "team", minDifficulty: "easy", priority: 85,
    // Fires only when a teammate REALLY objected to a pending request (Support/Object on the
    // request, or their own words in the chat naming the target). Both sides are quoted as written.
    when: s => {
      for (const c of s.containments) {
        if (c.status !== "pending" || !c.target) continue;
        const obj = c.advice.find(a => a.stance === "object" && a.by && a.by !== c.requester);
        if (!obj) continue;
        const name = (u: string | null) => s.seated.t2?.concat(s.seated.t3 ?? []).find(m => m.user_id === u)?.name || "a teammate";
        return {
          target: c.target, requester: name(c.requester), requesterRole: roleLabel(c.requesterRole), objector: name(obj.by), objectorRole: roleLabel(obj.role),
          why: clip(c.reason || "contain it before it spreads", 140), objection: clip(obj.reason || "wait", 140),
        };
      }
      return null;
    },
    build: ctx => ({
      from: { name: "Your team", role: `${ctx.requesterRole} and ${ctx.objectorRole}` }, channel: "in person", deadlineS: 180, objective: "Coordinated containment: limit damage now, isolate when the scope is known",
      text: `${ctx.requester} (${ctx.requesterRole}) asked to isolate ${ctx.target}: "${ctx.why}". ${ctx.objector} (${ctx.objectorRole}) objects: "${ctx.objection}". The request is waiting on you.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: `Block its outbound traffic now; isolate all confirmed hosts together after ${ctx.objector} confirms scope.`, note: "Limits the damage now, respects the objection with a time box, and avoids piecemeal containment that tips the attacker off (CISA, Microsoft IR guidance).", delta: { regulatory: 1 } },
        { key: "good", rank: "good", label: `Approve the isolation of ${ctx.target} now and ask ${ctx.objector} to keep scoping in parallel.`, note: "Stops this host fast; the risk is that other footholds stay unknown and the attacker changes tactics." },
        { key: "okay", rank: "okay", label: "Tell them to agree between themselves and come back to you with one recommendation.", note: "The disagreement is exactly why it reached you; the clock keeps running.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Isolate the whole network segment immediately, so nothing else can spread from it.", note: "Maximum business impact to settle a disagreement about one host.", delta: { continuity: -2 } },
      ],
    }),
  },
  {
    id: "contested_verdict", audience: "internal", pillar: "team", minDifficulty: "easy", priority: 75,
    // Two analysts are on record with opposite calls on the same log.
    when: s => {
      const c = s.verdictConflicts[0];
      if (!c) return null;
      return { label: clip(c.label, 90), host: c.host, a: c.attack.by, aRole: roleLabel(c.attack.role), aHow: c.attack.how, b: c.benign.by, bRole: roleLabel(c.benign.role), bHow: c.benign.how };
    },
    build: ctx => ({
      from: { name: "Shift board", role: "Case record" }, channel: "in person", deadlineS: 180, objective: "One shared picture: settle contradictory calls on the evidence, not on rank",
      text: `The case record disagrees with itself on "${ctx.label}"${ctx.host ? ` (${ctx.host})` : ""}: ${ctx.a} (${ctx.aRole}) ${ctx.aHow}, and ${ctx.b} (${ctx.bRole}) ${ctx.bHow}.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Have both put their evidence in the case, let the case owner decide on it, and fix the record.", note: "Settles it on evidence and leaves one verdict the whole team works from.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Send the log to Tier-3 for a deciding look, and ask both analysts to wait for it.", note: "A fair tie-breaker, but it adds load on Tier-3 for something the two analysts may settle themselves." },
        { key: "okay", rank: "okay", label: "Go with the more senior analyst's call, since they have seen more cases like this.", note: "Fast, but rank is not evidence: the junior analyst may have seen something real.", delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Go with the benign call so the queue moves, and revisit it after the shift.", note: "If the attack call was right, the incident just lost a piece of its scope.", delta: { regulatory: -1 } },
      ],
    }),
  },
  {
    id: "bounce_dispute", audience: "internal", pillar: "team", minDifficulty: "medium", priority: 70,
    // Tier-2 bounced an escalation and Tier-1 escalated the same log again.
    when: s => {
      const d = s.bounceDisputes[0];
      return d ? { host: d.host, summary: clip(d.summary, 90), t2: d.bouncedBy, t1: d.reEscalatedBy, why: clip(d.bounceReason || "not enough to act on", 120) } : null;
    },
    build: ctx => ({
      from: { name: "Shift board", role: "Escalation queue" }, channel: "in person", deadlineS: 180, objective: "Close the handoff loop: one decision on a disputed escalation, with the reason fed back",
      text: `${ctx.t2} bounced the escalation "${ctx.summary}"${ctx.host ? ` on ${ctx.host}` : ""} back to Tier-1 ("${ctx.why}"). ${ctx.t1} escalated it again.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Look at the evidence with both for two minutes and decide; if still unclear, give it to Tier-3.", note: "Ends the ping-pong with a decision and teaches both sides what 'enough evidence' means.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: `Ask ${ctx.t2} to take it back and investigate properly, since Tier-1 is sure about it.`, note: "Errs on the side of caution, but without a word to Tier-1 the same dispute comes back." },
        { key: "okay", rank: "okay", label: `Tell ${ctx.t1} to stop re-escalating once Tier-2 has given an answer.`, note: "Discourages escalation, the opposite of what a SOC wants from Tier-1.", delta: { trust: -1 } },
        { key: "weak", rank: "weak", label: "Close the alert to end the argument, and note the dispute for the debrief.", note: "Nobody looked at the evidence, and it may be part of the attack.", delta: { regulatory: -1 } },
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
        { key: "best", rank: "great", label: "Not yet: keep it isolated and powered on, capture memory and a triage image, then rebuild.", note: "Reimaging or powering off destroys the memory and disk evidence of how the attacker got in.", delta: { regulatory: 1 } },
        { key: "good", rank: "good", label: "Give the user a loaner laptop and keep the host isolated until the investigation releases it.", note: "Protects the evidence and the user; imaging still has to be scheduled." },
        { key: "okay", rank: "okay", label: "Reboot it first to see if it still works, then decide about the reimage.", note: "A reboot clears memory: the running malware and its network connections are gone.", delta: { regulatory: -1 } },
        { key: "weak", rank: "weak", label: "Approve the reimage, so the user is back at work within the hour.", note: "The evidence is gone, and if this was patient zero you may never learn how they got in.", delta: { regulatory: -2 }, critical: "Approved reimaging an isolated host before evidence was captured" },
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
      from: { name: "Shift board", role: "Team activity" }, channel: "in person", deadlineS: 180, objective: "Team awareness: notice a stalled analyst and help, without blame",
      text: `${ctx.name} (${ctx.role}) has not updated anything in ${ctx.mins} minutes, and ${ctx.open} escalated case${ctx.open === "1" ? " is" : "s are"} open.`,
      timeoutDelta: { capacity: -1 },
      options: [
        { key: "best", rank: "great", label: "Message them: ask what they are stuck on, and move their open work if they need help.", note: "Finds out why before acting, and keeps the work moving.", delta: { capacity: 1 } },
        { key: "good", rank: "good", label: "Reassign their open work to someone else right away, without asking first.", note: "Gets the work moving, but may duplicate what they were doing quietly." },
        { key: "okay", rank: "okay", label: "Wait a few more minutes: they are probably deep in an investigation.", note: "If they are stuck, nobody will find out.", delta: { capacity: -1 } },
        { key: "weak", rank: "weak", label: "Post in the team chat that someone is not pulling their weight, to push the pace.", note: "Public blame, no help, worse teamwork.", delta: { capacity: -1, trust: -1 } },
      ],
    }),
  },
];

export const CARD_BY_ID = new Map(CARDS.map(c => [c.id, c]));
export const hostsEqual = (a: string, b: string) => hostKey(a) === hostKey(b);
