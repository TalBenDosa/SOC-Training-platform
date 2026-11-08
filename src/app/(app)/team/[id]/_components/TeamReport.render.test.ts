// Renders the REAL shift-review component with a report computed from a small
// synthetic shift (v3 metrics: SLA per reported event, misses, team triage), the
// way the page receives it from GET /api/team/sessions/[id]/report.
import { describe, it, expect, vi, afterEach } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { TeamReport } from "./TeamReport";
import { computeReport } from "@/lib/team/report/computeReport";
import type { Ev, RosterMember } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const T0 = Date.parse("2026-09-01T10:00:00.000Z");
const at = (s: number) => new Date(T0 + s * 1000).toISOString();
const roster: RosterMember[] = [
  { user_id: "a", role: "t1", status: "ready", name: "Dana", handle: null },
  { user_id: "b", role: "t2", status: "ready", name: "Omer", handle: null },
];
function shift(): Ev[] {
  const ev: Ev[] = [];
  const add = (type: string, actor: string | null, s: number, payload: Record<string, unknown> = {}) =>
    ev.push({ seq: ev.length + 1, type, actor_id: actor, role: null, payload, occurred_at: at(s) });
  add("session.started", null, 0);
  add("feed.event", null, 10, { id: "atk1", expected_verdict: "tp", incident_id: "inc-A", severity: "high", description: "Beacon to C2 from WS-12" });
  add("feed.event", null, 30, { id: "atk3", expected_verdict: "tp", incident_id: "inc-B", severity: "high", description: "Forwarding rule to external mailbox" });
  add("feed.event", null, 40, { id: "atk4", expected_verdict: "tp", incident_id: "inc-C", severity: "medium", description: "USB mass copy on HR laptop" });
  add("feed.event", null, 50, { id: "n1", severity: "high", description: "Admin login from the jump host" });
  add("escalation.requested", "a", 110, { event_id: "atk1", summary: "c2" });
  add("escalation.acknowledged", "b", 150, { event_id: "atk1" });
  add("escalation.requested", "a", 450, { event_id: "n1", summary: "odd" });
  add("disposition.set", "a", 200, { event_id: "atk3", verdict: "benign" });
  add("event.opened", "a", 300, { event_id: "atk4", dwell_ms: 20000 });
  add("session.ended", null, 600);
  return ev;
}

describe("TeamReport (shift review) — v3 sections", () => {
  let root: Root | null = null;
  let container: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); container?.remove(); vi.unstubAllGlobals(); });

  it("shows team triage metrics, what the team missed, and per-analyst SLA + misses", async () => {
    const events = shift();
    const report = computeReport(events, roster);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => ({ team: report.team, perUser: report.perUser, answers: {}, seesAll: true }) })));
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root!.render(React.createElement(TeamReport, { sessionId: "s1", events, roster, me: { id: "x", is_staff: true, role: "instructor" } }));
    });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    const text = container.textContent ?? "";

    // team row
    expect(text).toContain("Attack logs within SLA");
    expect(text).toContain("High/critical triaged");
    expect(text).toContain("Time to triage (median)");
    expect(text).toContain("Attacks missed");
    // blind-spots card
    expect(text).toContain("What the team missed");
    expect(text).toContain("USB mass copy on HR laptop");          // nobody handled it
    // per attack, by its main log (Tal, 2026-10-27)
    expect(text).toContain("Attacks nobody caught (2)");
    expect(text).toContain("Someone looked at it and called it benign.");
    expect(text).toContain("Forwarding rule to external mailbox"); // called benign
    // per-analyst SLA table (Dana: 2 of 3 within SLA)
    expect(text).toContain("SLA per reported event");
    expect(text).toContain("2/3 within SLA");
    expect(text).toContain("Beacon to C2 from WS-12");
    expect(text).toMatch(/✓ 1m 40s\s*\/ 3m 00s/);
    expect(text).toMatch(/✗ 6m 40s\s*\/ 3m 00s/);
    // per-analyst misses
    expect(text).toContain("Attacks you called benign");
    expect(text).toContain("Attacks you opened but left");
    expect(text).toContain("Benign logs you escalated");
  });

  it("v4: judges each EDR isolation — right call on a compromised host, wrong call on a clean one", async () => {
    const events = shift();
    events.splice(1, 0, { seq: 0, type: "feed.event", actor_id: null, role: null, payload: { id: "atk5", expected_verdict: "tp", incident_id: "inc-A", severity: "high", hostname: "WS-12", description: "Beacon process on WS-12" }, occurred_at: at(5) });
    const end = events.pop()!;
    events.push(
      { seq: 0, type: "edr.host_isolated", actor_id: "b", role: "t2", payload: { host: "WS-12" }, occurred_at: at(185) },
      { seq: 0, type: "edr.host_isolated", actor_id: "b", role: "t2", payload: { host: "WS-HR-07" }, occurred_at: at(300) },
      end,
    );
    events.forEach((e, i) => { e.seq = i + 1; });
    const report = computeReport(events, roster);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => ({ team: report.team, perUser: report.perUser, answers: {}, seesAll: true }) })));
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root!.render(React.createElement(TeamReport, { sessionId: "s1", events, roster, me: { id: "x", is_staff: true, role: "instructor" } }));
    });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    const text = container.textContent ?? "";
    // Review 2026-11: Sentinel sessions isolate too, so the section is just "Host isolation".
    expect(text).toContain("Host isolation");
    expect(text).not.toContain("Host isolation in EDR");
    expect(text).toContain("1/2 right calls");
    expect(text).toContain("✓ right call");
    expect(text).toContain("isolated 3m 00s after its first attack log");
    expect(text).toContain("✗ wrong call");
    expect(text).toContain("clean: no attack activity on this host");
    expect(text).toContain("Hosts you isolated");          // Omer's card
  });

  it("the admin sees every card with measured values, the SOC Manager's included (Tal, 2026-10-27)", async () => {
    const events = shift();
    const mgrRoster: RosterMember[] = [...roster, { user_id: "m", role: "mgr", status: "ready", name: "Noa", handle: null }];
    const report = computeReport(events, mgrRoster);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => ({ team: report.team, perUser: report.perUser, managerReview: report.managerReview, answers: {}, seesAll: true }) })));
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root!.render(React.createElement(TeamReport, { sessionId: "s1", events, roster: mgrRoster, me: { id: "x", is_staff: true, role: "instructor" } }));
    });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    const text = container.textContent ?? "";
    expect(text).toContain("Command Review score");      // Noa's card in the grid
    expect(text).toContain("Time to escalate");           // Dana: a measured timing
    expect(text).toContain("target ≤ 2 min");             // Omer: time to acknowledge
    expect(text).toContain("Nothing to measure this shift:");
  });

  it("QA M5: while another request builds the report (503 building) it retries quietly, then renders", async () => {
    vi.useFakeTimers();
    try {
      const events = shift();
      const report = computeReport(events, roster);
      let calls = 0;
      vi.stubGlobal("fetch", vi.fn(async () => (++calls === 1
        ? { ok: false, status: 503, json: async () => ({ error: "still being prepared", building: true }) }
        : { ok: true, status: 200, json: async () => ({ team: report.team, perUser: report.perUser, answers: {}, seesAll: true }) })));
      container = document.createElement("div");
      document.body.appendChild(container);
      root = createRoot(container);
      await act(async () => {
        root!.render(React.createElement(TeamReport, { sessionId: "s1", events, roster, me: { id: "x", is_staff: true, role: "instructor" } }));
      });
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(container.textContent).toContain("Building the shift review");
      expect(container.textContent).not.toContain("still being prepared");
      await act(async () => { await vi.advanceTimersByTimeAsync(2100); });
      expect(calls).toBe(2);
      expect(container.textContent).toContain("Attack logs within SLA");
    } finally { vi.useRealTimers(); }
  });
  async function render(events: Ev[], body: Record<string, unknown>, me: { id: string; is_staff: boolean; role: string | null }, r: RosterMember[] = roster) {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => body })));
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => { root!.render(React.createElement(TeamReport, { sessionId: "s1", events, roster: r, me })); });
    await act(async () => { await new Promise(res => setTimeout(res, 0)); });
    return container;
  }

  it("review 2026-11: a player sees their own card first, with one score, a strength, a fix, a practice room and XP", async () => {
    const events = shift();
    const report = computeReport(events, roster);
    const mine = report.perUser.filter(u => u.user_id === "a").map(u => ({ ...u, falseNegatives: u.falseNegatives.map(m => ({ ...m, practice: { id: "room-7", title: "Mailbox rules" } })) }));
    const c = await render(events, { team: report.team, perUser: mine, answers: {}, seesAll: false, xp: { a: 42 } }, { id: "a", is_staff: false, role: "t1" });
    const text = c.textContent ?? "";
    expect(text).toContain("Your shift");
    expect(text.indexOf("Your shift")).toBeLessThan(text.indexOf("Shift review: the team"));
    expect(text.indexOf("Shift review: the team")).toBeLessThan(text.indexOf("Hot-wash"));
    expect(text.indexOf("Hot-wash")).toBeLessThan(text.indexOf("The detail"));
    expect(text).toContain("Strength");
    expect(text).toContain("One thing to fix");
    expect(text).toContain("An attack you called benign: Forwarding rule to external mailbox");
    expect(c.querySelector('a[href="/rooms/room-7"]')?.textContent).toBe("Mailbox rules");
    expect(text).toContain("+42 XP");
    // one score per card: the role score, never a second "contribution" number
    expect(text).not.toMatch(/contribution/i);
    // a player sees no other card and no debrief mode
    expect(text).not.toContain("Each player");
    expect([...c.querySelectorAll("button")].some(b => /Debrief mode/.test(b.textContent ?? ""))).toBe(false);
    // plain labels, the acronym only in the tooltip
    expect(text).toContain("Time to detect (median)");
    expect(text).toContain("Escalations answered");
    expect(text).not.toMatch(/MTTD|MTTR|MTTC|Handoff loop closure|Curveballs \(MSEL\)/);
    expect(c.querySelector('[title^="MTTD"]')).not.toBeNull();
    // never raw seconds
    expect(text).not.toMatch(/\b\d{3,}s\b/);
    // the detail is folded
    expect(c.querySelectorAll("details").length).toBeGreaterThan(2);
    expect([...c.querySelectorAll("details")].every(d => !d.open)).toBe(true);
  });

  it("review 2026-11: staff see each player, and the debrief mode shows the story without a score or a name", async () => {
    const events = shift();
    events.splice(1, 0, { seq: 0, type: "feed.event", actor_id: null, role: null, payload: { id: "atk5", expected_verdict: "tp", incident_id: "inc-A", severity: "high", hostname: "WS-12", mitre_tactic: "Execution", description: "Beacon process on WS-12" }, occurred_at: at(5) });
    events.forEach((e, i) => { e.seq = i + 1; if (e.type === "escalation.requested") e.role = "t1"; if (e.type === "escalation.acknowledged") e.role = "t2"; });
    const report = computeReport(events, roster);
    const c = await render(events, { team: report.team, perUser: report.perUser, answers: {}, seesAll: true }, { id: "x", is_staff: true, role: "instructor" });
    expect(c.textContent).toContain("Each player");
    const btn = [...c.querySelectorAll("button")].find(b => /Debrief mode/.test(b.textContent ?? ""))!;
    await act(async () => { btn.click(); });
    const d = c.querySelector("[data-testid=debrief-mode]")!;
    expect(d).not.toBeNull();
    const text = d.textContent ?? "";
    expect(text).toContain("Shift debrief");
    expect(text).toContain("What happened, and when");
    expect(text).toContain("Patient zero: WS-12");
    expect(text).toContain("Execution");
    expect(text).toContain("What the team saw");
    expect(text).toContain("What the team missed");
    expect(text).toContain("What should have happened");
    expect(text).toContain("What we would do differently");
    // people show by role; no individual score
    expect(text).toContain("Tier-1 Triage");
    expect(text).not.toMatch(/Dana|Omer/);
    expect(text).not.toMatch(/\/100|Role score|XP/);
    // back to the report
    const back = [...d.querySelectorAll("button")].find(b => b.textContent === "Back to the report")!;
    await act(async () => { back.click(); });
    expect(c.querySelector("[data-testid=debrief-mode]")).toBeNull();
    expect(c.textContent).toContain("Shift review: the team");
  });

  it("owner decision 2026-11: the trainee SOC Manager sees their own card and the team numbers, no teammate's card, no CSV", async () => {
    const events = shift();
    const mgrRoster: RosterMember[] = [...roster, { user_id: "m", role: "mgr", status: "ready", name: "Noa", handle: null }];
    const report = computeReport(events, mgrRoster);
    // The route now sends the Manager only their own card (seesAll false), the Command Review whole.
    const c = await render(events, { team: report.team, perUser: report.perUser.filter(u => u.user_id === "m"), managerReview: report.managerReview, answers: {}, seesAll: false }, { id: "m", is_staff: false, role: "mgr" }, mgrRoster);
    const text = c.textContent ?? "";
    expect(text).toContain("Your shift");
    expect(text).toContain("Command Review score");
    expect(text).toContain("Shift review: the team");
    expect(text).not.toContain("Each player");
    expect(c.querySelector("#rep-each")).toBeNull();
    const buttons = [...c.querySelectorAll("button")].map(b => b.textContent ?? "");
    expect(buttons.some(t => /Export CSV/.test(t))).toBe(false);
    expect(buttons.some(t => /Debrief mode/.test(t))).toBe(false);
  });

  it("owner decision 2026-11: a team admin sees each player and can export the CSV", async () => {
    const events = shift();
    const report = computeReport(events, roster);
    const c = await render(events, { team: report.team, perUser: report.perUser, answers: {}, seesAll: true }, { id: "x", is_staff: true, role: "instructor" });
    expect(c.textContent).toContain("Each player");
    const buttons = [...c.querySelectorAll("button")].map(b => b.textContent ?? "");
    expect(buttons.some(t => /Export CSV/.test(t))).toBe(true);
    expect(buttons.some(t => /Debrief mode/.test(t))).toBe(true);
  });

  it("owner decision 2026-11: without seesAll there is no Each player and no CSV, whatever else the payload carries", async () => {
    const events = shift();
    const report = computeReport(events, roster);
    // An org instructor seated as t1: a player's view.
    const c = await render(events, { team: report.team, perUser: report.perUser, answers: {}, seesAll: false }, { id: "a", is_staff: false, role: "t1" });
    expect(c.textContent).not.toContain("Each player");
    expect([...c.querySelectorAll("button")].some(b => /Export CSV/.test(b.textContent ?? ""))).toBe(false);
  });
  it("review 2026-11: shows the shift's truth, the pauses, self-opened cases and isolation requests from the server report", async () => {
    const events = shift();
    const end = events.pop()!;
    const add = (type: string, actor: string | null, sec: number, payload: Record<string, unknown> = {}) =>
      events.push({ seq: events.length + 1, type, actor_id: actor, role: null, payload, occurred_at: at(sec) });
    add("session.paused", null, 200, { reason: "owner_left" });
    add("session.resumed", null, 260);
    add("escalation.requested", "b", 300, { event_id: "atk4", summary: "usb copy" });
    add("escalation.acknowledged", "b", 305, { event_id: "atk4" });
    add("isolation.requested", "b", 320, { host: "WS-HR-07", reason: "USB mass copy" });
    add("isolation.denied", "a", 340, { request_seq: events.length, reason: "Scope it first" });
    events.push({ ...end, seq: events.length + 1 });
    const report = computeReport(events, roster);
    const team = { ...report.team, shift: { plannedMs: 1_800_000, ranMs: 600_000, endedEarly: true, endReason: "manual", plannedRows: 10, firedRows: 6, unfiredRows: 4, unfiredAttackRows: 2, preventedByIsolation: 1, attacksNeverStarted: [{ id: "inc-Z", name: "Cloud key theft" }], attacksNotReached: [] } };
    const c = await render(events, { team, perUser: report.perUser, answers: {}, seesAll: true }, { id: "x", is_staff: true, role: "instructor" });
    const text = c.textContent ?? "";
    expect(text).toContain("The shift ran 10m 00s of 30m 00s planned, ended early.");
    expect(text).toContain("not judged: Cloud key theft");
    expect(text).toContain("1 log never arrived because its host was isolated.");
    expect(text).toMatch(/Paused 1 time, 1m 00s in all/);
    expect(text).toContain("self-opened");
    expect(text).toContain("Isolation requests (1)");
    expect(text).toContain("Asked by Omer: USB mass copy");
    expect(text).not.toContain("in EDR");
  });
});
