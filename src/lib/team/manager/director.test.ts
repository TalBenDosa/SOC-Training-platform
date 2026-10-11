// The SOC-Manager director: a card fires only when the live session makes it true, names the
// real entities, never reads the answer key, and is paced (one at a time, spaced, budgeted).
import { describe, expect, it } from "vitest";
import type { Ev } from "@/lib/team/types";
import { buildMgrState, type Member } from "./state";
import { CARDS } from "./cards";
import { pickCard, materialize, cardScore, indicatorsAfter, CARD_SPACING_MS } from "./director";

const T0 = Date.parse("2026-10-10T10:00:00.000Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
let seq = 0;
const ev = (type: string, min: number, payload: Record<string, unknown> = {}, actor: string | null = null, role: string | null = null): Ev =>
  ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: at(min) });

const ROSTER: Member[] = [
  { user_id: "u-t1", role: "t1", status: "joined", name: "Avi" },
  { user_id: "u-t2", role: "t2", status: "joined", name: "Dana" },
  { user_id: "u-t3", role: "t3", status: "joined", name: "Lior" },
  { user_id: "u-mgr", role: "mgr", status: "joined", name: "Noam" },
];
const feed = (id: string, min: number, host = "WS-FIN-2901") => ev("feed.event", min, { id, hostname: host, description: "x" });
const escalate = (id: string, min: number, host = "WS-FIN-2901") => ev("escalation.requested", min, { event_id: id, summary: "Suspicious PowerShell download", hostname: host }, "u-t1", "t1");
const ack = (id: string, min: number) => ev("escalation.acknowledged", min, { event_id: id }, "u-t2", "t2");
const contain = (id: string, min: number, target: string, extra: Record<string, unknown> = {}) =>
  ev("containment.requested", min, { event_id: id, target, containment_type: "isolate", ...extra }, "u-t2", "t2");

function state(events: Ev[], nowMin: number, roster = ROSTER, difficulty: "easy" | "medium" | "hard" = "hard") {
  return buildMgrState({ events, roster, nowMs: T0 + nowMin * 60_000, difficulty, criticalHosts: ["SRV-NXC-DC01"] });
}
const eligible = (events: Ev[], nowMin: number, roster = ROSTER) => {
  const s = state(events, nowMin, roster);
  return new Set(CARDS.filter(c => c.when(s)).map(c => c.id));
};

describe("cards fire only on what really happened in the session", () => {
  it("nothing fires before the team's first escalation, however long the shift runs", () => {
    const events = [feed("e1", 1), feed("e2", 2)];
    expect(pickCard(state(events, 30))).toBeNull();
  });

  it("isolate-or-wait fires only on a REAL objection: a request alone, or a teammate's support, is not a disagreement", () => {
    const base = [feed("e1", 1), escalate("e1", 2), ack("e1", 3)];
    expect(eligible(base, 6).has("isolate_or_wait")).toBe(false);                      // no request
    const withReq = [...base, contain("e1", 5, "WS-FIN-2901")];
    const reqSeq = withReq[withReq.length - 1].seq;
    expect(eligible(withReq, 6).has("isolate_or_wait")).toBe(false);                   // nobody objected
    const supported = [...withReq, ev("containment.advised", 5.5, { request_seq: reqSeq, stance: "support", reason: "agree" }, "u-t3", "t3")];
    expect(eligible(supported, 6).has("isolate_or_wait")).toBe(false);                 // agreement is not a dispute
    const objected = [...withReq, ev("containment.advised", 5.5, { request_seq: reqSeq, stance: "object", reason: "scope not confirmed, two more hosts beaconing" }, "u-t3", "t3")];
    expect(eligible(objected, 6).has("isolate_or_wait")).toBe(true);
  });

  it("the card quotes the real request and the real objection, by name", () => {
    const events = [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "WS-ACC-4477", { reason: "C2 beacon every 60s" })];
    const reqSeq = events[events.length - 1].seq;
    events.push(ev("containment.advised", 5.5, { request_seq: reqSeq, stance: "object", reason: "wait for memory capture" }, "u-t3", "t3"));
    const s = state(events, 6);
    const def = CARDS.find(c => c.id === "isolate_or_wait")!;
    const text = def.build(def.when(s)!, s).text;
    for (const t of ["WS-ACC-4477", "Dana", "Lior", "C2 beacon every 60s", "wait for memory capture"]) expect(text).toContain(t);
  });

  it("a teammate's own words in the chat naming the target count as an objection", () => {
    const events = [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "WS-ACC-4477")];
    expect(eligible([...events, ev("message.sent", 5.5, { text: "isolating WS-ACC-4477 is fine" }, "u-t3", "t3")], 6).has("isolate_or_wait")).toBe(false);
    expect(eligible([...events, ev("message.sent", 5.5, { text: "don't isolate WS-ACC-4477 yet, still scoping" }, "u-t3", "t3")], 6).has("isolate_or_wait")).toBe(true);
    expect(eligible([...events, ev("message.sent", 5.5, { text: "don't isolate it yet" }, "u-t3", "t3")], 6).has("isolate_or_wait")).toBe(false);   // names no target
  });

  it("contested verdict: only when two analysts are really on record with opposite calls on one log", () => {
    const base = [feed("e1", 1), ev("disposition.set", 2, { event_id: "e1", verdict: "false_positive" }, "u-t1", "t1")];
    expect(eligible(base, 3).has("contested_verdict")).toBe(false);
    const s = state([...base, escalate("e1", 2.5), ev("report.submitted", 3, { event_id: "e1", verdict: "true_positive", summary: "real" }, "u-t2", "t2")], 4);
    // the same Tier-1 escalated after closing: the latest call per person counts, so the conflict is Tier-1 (benign→attack) vs nobody
    expect(s.verdictConflicts.length).toBe(0);
    const s2 = state([...base, ev("report.submitted", 3, { event_id: "e1", verdict: "true_positive", summary: "real" }, "u-t2", "t2")], 4);
    expect(s2.verdictConflicts).toHaveLength(1);
    const def = CARDS.find(c => c.id === "contested_verdict")!;
    const text = def.build(def.when(s2)!, s2).text;
    expect(text).toContain("Avi");
    expect(text).toContain("Dana");
  });

  it("bounce dispute: only after a real bounce AND a real re-escalation of the same log", () => {
    const base = [feed("e1", 1), escalate("e1", 2), ev("escalation.bounced", 3, { event_id: "e1", reason: "normal admin activity" }, "u-t2", "t2")];
    expect(eligible(base, 4).has("bounce_dispute")).toBe(false);
    expect(eligible([...base, escalate("e1", 3.5)], 4).has("bounce_dispute")).toBe(true);
  });

  it("no invented internal cards: the 'executive messaged your analyst' card is gone", () => {
    expect(CARDS.some(c => c.id === "exec_dm_analyst")).toBe(false);
  });

  it("the business-owner veto needs a pending request on a critical asset", () => {
    const base = [feed("e1", 1), escalate("e1", 2), ack("e1", 3)];
    expect(eligible([...base, contain("e1", 5, "WS-FIN-2901")], 6).has("owner_veto")).toBe(false);
    expect(eligible([...base, contain("e1", 5, "SRV-NXC-DC01")], 6).has("owner_veto")).toBe(true);
    expect(eligible([...base, contain("e1", 5, "LT-HR-07", { asset_criticality: "crown_jewel" })], 6).has("owner_veto")).toBe(true);
  });

  it("the reimage request needs a host that was really isolated, and names it", () => {
    const base = [feed("e1", 1), escalate("e1", 2)];
    expect(eligible(base, 9).has("reimage_request")).toBe(false);
    const iso = [...base, ev("edr.host_isolated", 6, { host: "WS-ACC-4477" }, "u-t2", "t2")];
    expect(eligible(iso, 6.5).has("reimage_request")).toBe(false);                     // under a minute ago
    const s = state(iso, 8);
    const def = CARDS.find(c => c.id === "reimage_request")!;
    expect(def.build(def.when(s)!, s).text).toContain("WS-ACC-4477");
  });

  it("the CISO calls about the actual escalation, two minutes after it", () => {
    const events = [feed("e1", 1), escalate("e1", 2, "WS-HR-0117")];
    expect(eligible(events, 3).has("ciso_status")).toBe(false);
    const s = state(events, 4.5);
    const def = CARDS.find(c => c.id === "ciso_status")!;
    expect(def.build(def.when(s)!, s).text).toContain("WS-HR-0117");
  });

  it("legal asks about reporting only when the team suspects data loss or declared a serious incident", () => {
    const base = [feed("e1", 1), escalate("e1", 2)];
    expect(eligible(base, 6).has("legal_reportable")).toBe(false);
    const words = [...base, ev("report.submitted", 4, { event_id: "e1", summary: "rclone upload of staged archive to cloud storage" }, "u-t2", "t2")];
    expect(eligible(words, 6).has("legal_reportable")).toBe(true);
    const sev1 = [...base, ev("incident.declared", 4, { severity: 1 }, "u-mgr", "mgr")];
    expect(eligible(sev1, 6).has("legal_reportable")).toBe(true);
  });

  it("an overloaded Tier-1 card needs a real Tier-1 carrying the load", () => {
    const claims = ["a", "b", "c"].map((id, i) => ev("alert.claimed", 2 + i * 0.1, { event_id: id }, "u-t1", "t1"));
    const events = [feed("e1", 1), escalate("e1", 1.5), ...claims];
    expect(eligible(events, 3).has("t1_overloaded")).toBe(true);
    expect(eligible(events, 3, ROSTER.filter(m => m.role !== "t1")).has("t1_overloaded")).toBe(false);
  });

  it("no SOC Manager seated: no card at all", () => {
    const events = [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "WS-FIN-2901")];
    expect(pickCard(state(events, 8, ROSTER.filter(m => m.role !== "mgr")))).toBeNull();
  });
});

describe("pacing", () => {
  const busy = () => [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "WS-FIN-2901")];
  const firedCard = (card: string, min: number, deadline = 180) => ev("staff.inject", min, { kind: "decision", card, inject_id: `00000000-0000-0000-0000-00000000000${seq % 10}`, deadline_s: deadline });

  it("one open card at a time, then a spacing gap", () => {
    const c = firedCard("isolate_or_wait", 6);
    const id = String(c.payload.inject_id);
    expect(pickCard(state([...busy(), c], 7))).toBeNull();                              // still open
    const answered = [...busy(), c, ev("decision.answered", 7, { inject_id: id, option: "o1", confidence: "high" }, "u-mgr", "mgr")];
    expect(pickCard(state(answered, 7.5))).toBeNull();                                  // inside the spacing gap
    expect(pickCard(state(answered, 6 + CARD_SPACING_MS / 60_000 + 0.1))).not.toBeNull();
  });

  it("the CEO's office follows up only when the CISO's call expired unanswered", () => {
    const events = [feed("e1", 1), escalate("e1", 2), firedCard("ciso_status", 4, 60)];
    expect(eligible(events, 4.5).has("ciso_bypass")).toBe(false);
    expect(eligible(events, 5.5).has("ciso_bypass")).toBe(false);   // late window (2 min) still open
    expect(eligible(events, 7.1).has("ciso_bypass")).toBe(true);
  });
});

describe("cards: content and answer key", () => {
  it("every card: 4 options, exactly one great, a note per option, no em dash, short text", () => {
    const events = [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "SRV-NXC-DC01"), ev("incident.declared", 3, { severity: 1 }, "u-mgr", "mgr"),
      ev("edr.host_isolated", 4, { host: "WS-ACC-4477" }, "u-t2", "t2")];
    const s = state(events, 30);
    for (const def of CARDS) {
      const b = def.build(def.when(s) ?? { host: "H", summary: "S", target: "T", owner: "O", process: "P", t2: "A", t3: "B", t1: "C", name: "N", load: "3", mins: "9", open: "1", sev: "1", role: "Tier-2", helper: "",
        requester: "A", requesterRole: "Tier-2", objector: "B", objectorRole: "Tier-3", why: "W", objection: "X", label: "L", a: "A", aRole: "Tier-1", aHow: "escalated it", b: "B", bRole: "Tier-2", bHow: "closed it", why2: "" }, s);
      expect(b.options, def.id).toHaveLength(4);
      expect(b.options.filter(o => o.rank === "great"), def.id).toHaveLength(1);
      for (const o of b.options) expect(o.note.length, `${def.id}.${o.key}`).toBeGreaterThan(10);
      const all = [b.text, ...b.options.flatMap(o => [o.label, o.note])].join(" ");
      expect(all.includes("—"), def.id).toBe(false);
      expect(b.text.split(/\s+/).length, def.id).toBeLessThanOrEqual(200);
    }
  });

  const objectedEvents = () => {
    const events = [feed("e1", 1), escalate("e1", 2), ack("e1", 3), contain("e1", 5, "WS-FIN-2901")];
    events.push(ev("containment.advised", 5.2, { request_seq: events[events.length - 1].seq, stance: "object", reason: "scope first" }, "u-t3", "t3"));
    return events;
  };
  it("the public body carries no ranks, notes or deltas; option ids differ between sessions", () => {
    const events = objectedEvents();
    const s = state(events, 6);
    const def = CARDS.find(c => c.id === "isolate_or_wait")!;
    const a = materialize(def, def.when(s)!, s, "session-a");
    const json = JSON.stringify(a.body);
    for (const word of ["great", "weak", "rank", "note", "delta", "best"]) expect(json.includes(`"${word}`), word).toBe(false);
    expect(a.answer.ranks[a.answer.best]).toBe("great");
    const orders = new Set(["s1", "s2", "s3", "s4", "s5", "s6"].map(seed => materialize(def, def.when(s)!, s, seed).answer.best));
    expect(orders.size).toBeGreaterThan(1);                                             // the best answer is not always the same id
  });

  it("confidence calibration: an overconfident weak call scores lowest", () => {
    expect(cardScore("great", "high")).toBe(12);
    expect(cardScore("weak", "high")).toBe(0);
    expect(cardScore("weak", "low")).toBeGreaterThan(cardScore("weak", "high"));
    expect(cardScore(undefined, "high")).toBe(0);
  });

  it("indicators move with decisions and stay within 0-5", () => {
    const events = objectedEvents();
    const s = state(events, 6);
    const def = CARDS.find(c => c.id === "isolate_or_wait")!;
    const { answer } = materialize(def, def.when(s)!, s, "x");
    const weak = Object.keys(answer.ranks).find(k => answer.ranks[k] === "weak")!;
    const ind = indicatorsAfter([{ answer, option: weak }, { answer, option: weak }, { answer, option: weak }]);
    expect(ind.continuity).toBe(0);
    expect(ind.trust).toBe(3);
  });
});
