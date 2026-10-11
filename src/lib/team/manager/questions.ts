/**
 * Stakeholder questions: what the CISO, the CEO's office, Legal, the head of an affected
 * department and Communications ask the SOC Manager during an incident ("where are we?",
 * "how long?", "is data affected?", "when is my system back?").
 *
 * Same rule as the decision cards: a question exists only because something in the live
 * session made it true (the incident was declared, a host was really isolated, the team itself
 * wrote about data leaving, the severity really changed). The manager answers in free text;
 * the answer is checked with deterministic rules (no AI in prod), judged against what the
 * session showed when the question was asked.
 */
import type { Difficulty, MgrState } from "./state";
import { teamSuspectsData } from "./state";
import { OVERLOAD_CASES } from "@/lib/team/report/computeReport";

export type CheckId = "substance" | "status" | "no_overclaim" | "eta" | "next_update" | "no_false_data" | "honest_data" | "business_impact" | "reason" | "severity_consistent" | "need_decision" | "staff_message";
export interface QCtx { [k: string]: string }
export interface QuestionBuild { text: string; deadlineS: number; objective: string; checks: CheckId[]; model: string }
export interface QuestionDef {
  id: string; from: { name: string; role: string }; minDifficulty: Difficulty; priority: number;
  when(s: MgrState): QCtx | null;
  build(ctx: QCtx, s: MgrState): QuestionBuild;
}
/** Server-only: how a reply is checked, with the session facts at the moment it was asked. */
export interface QuestionKey {
  qid: string; checks: CheckId[]; model: string; objective: string;
  facts: { contained: boolean; suspectsData: boolean; severity: number | null; target: string };
}
export interface QuestionPublicBody { from: { name: string; role: string }; channel: "chat"; text: string; deadline_s: number }

export const QUESTION_BUDGET = { easy: 3, medium: 5, hard: 7 } as const;
export const QUESTION_SPACING_MS = 120_000;
export const MAX_OPEN_QUESTIONS = 2;

// Fictional people, the same cast as the decision cards.
const CISO = { name: "Maya Klein", role: "CISO" };
const LEGAL = { name: "Noa Ben-Ami", role: "Legal counsel" };
const CEO_OFFICE = { name: "Office of the CEO", role: "Executive" };
const COMMS = { name: "Lior Dahan", role: "Head of Communications" };

const DIFF_RANK: Record<Difficulty, number> = { easy: 0, medium: 1, hard: 2 };
const asked = (s: MgrState, id: string) => s.questions.some(q => q.qid === id);
const sinceDecl = (s: MgrState) => (s.declared ? s.nowMs - s.declared.atMs : -1);

/** The department a host serves, from its name (WS-FIN-2901 → Finance). */
export function departmentOf(host: string): string {
  const h = host.toUpperCase();
  if (/FIN|ACC|PAY/.test(h)) return "Finance";
  if (/HR/.test(h)) return "HR";
  if (/SALES|CRM/.test(h)) return "Sales";
  if (/ENG|DEV|BUILD/.test(h)) return "Engineering";
  if (/OPS|LOG|WH/.test(h)) return "Operations";
  if (/MED|EMR|CLIN|PACS/.test(h)) return "Clinical";
  if (/LEG/.test(h)) return "Legal";
  if (/DC\d*|SRV|FS|SQL|DB/.test(h)) return "IT Infrastructure";
  return "Operations";
}

/** Facts the reply is judged against: what the session showed when the question fired. */
export function factsOf(s: MgrState, target = ""): QuestionKey["facts"] {
  const contained = s.scopeConfirmed && !s.containments.some(c => c.status === "pending") && !s.escalations.some(e => e.open);
  return { contained, suspectsData: teamSuspectsData(s), severity: s.declared?.severity ?? null, target };
}

export const QUESTIONS: QuestionDef[] = [
  {
    id: "q_status", from: CISO, minDifficulty: "easy", priority: 90,
    when: s => (sinceDecl(s) >= 45_000 ? {} : null),
    build: () => ({
      text: `${CISO.name} (${CISO.role}): "I'm on with the CEO in a few minutes. Where are we right now: is it contained or still spreading?"`,
      deadlineS: 180, objective: "Status upward: what is confirmed, what is not, and when the next update comes",
      checks: ["substance", "status", "no_overclaim", "next_update"],
      model: "One line of status (what is confirmed and what is not yet known), what the team is doing now, and a fixed time for the next update. Never 'contained' before the scope is confirmed.",
    }),
  },
  {
    id: "q_business", from: { name: "Dana Shapiro", role: "Head of department" }, minDifficulty: "easy", priority: 85,
    when: s => {
      const h = s.isolatedHosts[0]?.host || s.containments.find(c => (c.status === "approved" || c.status === "executed") && c.target)?.target;
      return h ? { target: h, dept: departmentOf(h) } : null;
    },
    build: ctx => ({
      text: `Dana Shapiro (Head of ${ctx.dept}): "${ctx.target} has been cut off and my people can't work on it. What is going on, can they keep working, and when do we get it back?"`,
      deadlineS: 240, objective: "Business impact in plain words: why the system is down, a workaround, and an honest time",
      checks: ["substance", "business_impact", "eta", "no_overclaim"],
      model: "Why the system is isolated (in business words, no jargon), how people can keep working (a loaner, another system), and an honest time or the time of the next update. Do not promise it back before the investigation releases it.",
    }),
  },
  {
    id: "q_sev_change", from: CEO_OFFICE, minDifficulty: "easy", priority: 80,
    when: s => {
      const c = s.severityChanges[s.severityChanges.length - 1];
      return c ? { sev: String(c.severity) } : null;
    },
    build: ctx => ({
      text: `${CEO_OFFICE.name}: "We see the incident is now Sev-${ctx.sev}. What changed, and what does it mean for the business?"`,
      deadlineS: 180, objective: "Explain a severity change: the new evidence, and its meaning for the business",
      checks: ["substance", "reason", "severity_consistent", "no_overclaim"],
      model: "The new fact that changed the severity (more hosts, data, a critical system), what it means for the business, and what happens next.",
    }),
  },
  {
    id: "q_data", from: LEGAL, minDifficulty: "easy", priority: 75,
    when: s => (s.declared && (teamSuspectsData(s) || (s.declared.severity <= 2 && sinceDecl(s) >= 360_000)) ? {} : null),
    build: () => ({
      text: `${LEGAL.name} (${LEGAL.role}): "Is any customer or employee personal data affected? I need to know whether a reporting clock is running."`,
      deadlineS: 240, objective: "Honest data status: suspected vs confirmed, never 'not affected' before it is verified",
      checks: ["substance", "honest_data", "no_false_data", "next_update"],
      model: "Say exactly what is known: 'no evidence so far', 'suspected, under investigation' or 'confirmed', what the team is checking, and when you will update her. Never 'not affected' while it is unverified.",
    }),
  },
  {
    id: "q_eta", from: CEO_OFFICE, minDifficulty: "medium", priority: 70,
    when: s => (asked(s, "q_status") && (sinceDecl(s) >= 240_000 || s.containments.some(c => c.status === "approved" || c.status === "executed")) ? {} : null),
    build: () => ({
      text: `${CEO_OFFICE.name}: "How long until this is under control? The CEO needs a time."`,
      deadlineS: 180, objective: "A time estimate with its condition, or an honest 'not yet known' with a fixed next update",
      checks: ["substance", "eta", "no_overclaim"],
      model: "An estimate with its condition ('if the scope holds, about 30 minutes'), or 'not known yet' plus the exact time of the next update. Not a promise you cannot keep.",
    }),
  },
  {
    id: "q_need", from: CISO, minDifficulty: "medium", priority: 60,
    when: s => {
      const open = s.escalations.filter(e => e.open).length;
      const overloaded = [...s.loadByUser.values()].some(l => l >= OVERLOAD_CASES);
      return s.declared && (open >= 2 || overloaded || sinceDecl(s) >= 480_000) ? { open: String(open) } : null;
    },
    build: () => ({
      text: `${CISO.name} (${CISO.role}): "Do you have enough people on this, or should I call in the IR retainer?"`,
      deadlineS: 180, objective: "Know your capacity: a clear yes or no with the reason",
      checks: ["substance", "need_decision", "reason"],
      model: "A clear yes or no, with the reason (open cases, load on the analysts, scope still growing) and what exactly the extra help would do.",
    }),
  },
  {
    id: "q_staff", from: COMMS, minDifficulty: "medium", priority: 50,
    when: s => (sinceDecl(s) >= 600_000 ? {} : null),
    build: () => ({
      text: `${COMMS.name} (${COMMS.role}): "Employees are noticing that systems are down. What can we tell staff right now, and when will you have more?"`,
      deadlineS: 240, objective: "Internal message: what staff should know and do, without speculation",
      checks: ["substance", "staff_message", "no_false_data", "next_update"],
      model: "A short message for staff: what is affected, what they should do (report suspicious emails, do not reboot isolated machines), no speculation about cause or data, and when the next update comes.",
    }),
  },
];

export function pickQuestion(s: MgrState): { def: QuestionDef; ctx: QCtx } | null {
  if (!s.manager || !s.declared) return null;
  if (s.questions.length >= QUESTION_BUDGET[s.difficulty]) return null;
  if (s.questions.filter(q => !q.replied && !q.expired).length >= MAX_OPEN_QUESTIONS) return null;
  const last = s.questions.reduce((m, q) => Math.max(m, q.atMs), 0);
  if (last && s.nowMs - last < QUESTION_SPACING_MS) return null;
  const eligible: { def: QuestionDef; ctx: QCtx }[] = [];
  for (const def of QUESTIONS) {
    if (asked(s, def.id) || DIFF_RANK[s.difficulty] < DIFF_RANK[def.minDifficulty]) continue;
    const ctx = def.when(s);
    if (ctx) eligible.push({ def, ctx });
  }
  eligible.sort((a, b) => b.def.priority - a.def.priority);
  return eligible[0] ?? null;
}

export function materializeQuestion(def: QuestionDef, ctx: QCtx, s: MgrState): { body: QuestionPublicBody & { from: { name: string; role: string } }; answer: QuestionKey } {
  const b = def.build(ctx, s);
  const from = def.id === "q_business" ? { name: "Dana Shapiro", role: `Head of ${ctx.dept}` } : def.from;
  return {
    body: { from, channel: "chat", text: b.text, deadline_s: b.deadlineS },
    answer: { qid: def.id, checks: b.checks, model: b.model, objective: b.objective, facts: factsOf(s, ctx.target ?? "") },
  };
}

// ── Checking a reply ─────────────────────────────────────────────────────────

/** A reply that rules out data loss. */
export const NO_DATA_CLAIM = /\bno (personal |customer |patient |employee )?data (was |has been |is )?(lost|leaked|exfiltrated|stolen|affected|exposed|compromised)|\bdata (is |was )?(safe|not affected|unaffected)|\bno exfil|\bnot affected\b/i;
const OVERCLAIM = /\b(fully contained|is contained|it'?s contained|we('| a)re contained|under control|resolved|fixed|all clear|no risk|it'?s over)\b/i;
const NOT_OVER = /\bnot (yet )?(fully )?(contained|under control|resolved)|\bpartially contained\b/i;
const NEXT_UPDATE = /(next|another|follow[- ]?up) (update|sitrep|briefing|call)|update you (in|by|at|within)|(get back|call (you )?back|come back) (to you )?(in|by|at|within)|\b(in|within) \d+\s*(min|mins|minutes|hour|hours)\b|\bby \d{1,2}(:\d{2})?\b/i;
const TIME = /\b\d+\s*(-\s*\d+\s*)?(min|mins|minutes|hour|hours|hrs?|h)\b|\b\d{1,2}:\d{2}\b|\bby (noon|tonight|tomorrow|end of (the )?day|eod)\b/i;
const UNKNOWN = /(don'?t|do not) (know|have an estimate) yet|not (yet )?known|unknown|too early|can'?t (say|estimate|give)|no (eta|estimate) yet/i;

export const CHECK_LABEL: Record<CheckId, string> = {
  substance: "A real answer, not a one-liner",
  status: "Says where the incident stands",
  no_overclaim: "Does not call it contained or over before it is",
  eta: "Gives a time, or an honest 'not known yet' with a next update",
  next_update: "Commits to a time for the next update",
  no_false_data: "Does not rule out data loss that is not verified",
  honest_data: "Says whether data loss is suspected, confirmed or not seen so far",
  business_impact: "Explains the impact on their system and people",
  reason: "Gives the reason",
  severity_consistent: "Severity matches what you declared",
  need_decision: "A clear yes or no",
  staff_message: "Says what to tell staff or what they should do",
};

export function checkReply(text: string, key: Pick<QuestionKey, "checks" | "facts">): { checks: { id: CheckId; label: string; ok: boolean }[]; score: number } {
  const t = text.trim();
  const low = t.toLowerCase();
  const words = t.split(/\s+/).filter(Boolean).length;
  const f = key.facts;
  const test: Record<CheckId, () => boolean> = {
    substance: () => words >= 8,
    status: () => /\b(investigat|contain|isolat|scop|monitor|spread|eradicat|recover|under control|block|analy[sz]|ongoing|active|confirmed)\w*/i.test(t),
    no_overclaim: () => f.contained || !OVERCLAIM.test(t) || NOT_OVER.test(t),
    eta: () => TIME.test(t) || (UNKNOWN.test(t) && NEXT_UPDATE.test(t)),
    next_update: () => NEXT_UPDATE.test(t),
    no_false_data: () => !f.suspectsData || !NO_DATA_CLAIM.test(t),
    honest_data: () => /(suspect|possibl|potential|may have|might have|under investigation|investigating|no evidence (so far|yet)|not (yet )?(confirmed|verified)|confirmed|checking)/i.test(t),
    business_impact: () => (!!f.target && low.includes(f.target.toLowerCase())) || /\b(down|offline|isolated|unavailable|workaround|loaner|spare|back online|restore|another (machine|laptop|computer))\b/i.test(t),
    reason: () => /\b(because|due to|since|after|we found|we saw|new evidence|confirmed|spread|exfil\w*|data|more hosts|another host|the team|open cases|load|scope)\b/i.test(t),
    severity_consistent: () => { const m = t.match(/\bsev(?:erity)?[\s-]*([1-4])\b/i); return !m || f.severity == null || Number(m[1]) === f.severity; },
    need_decision: () => /\b(yes|no|we need|need (more|help|the retainer)|don'?t need|do not need|not needed|call (them|it|the retainer) in|enough (people|analysts|hands))\b/i.test(t),
    staff_message: () => /\b(staff|employees|everyone|users|tell (them|staff|people)|message|announce|don'?t (click|open|reboot)|report (any|suspicious))\b/i.test(t),
  };
  const checks = key.checks.map(id => ({ id, label: CHECK_LABEL[id], ok: test[id]() }));
  const passed = checks.filter(c => c.ok).length;
  return { checks, score: checks.length ? Math.round((12 * passed) / checks.length) : 0 };
}
