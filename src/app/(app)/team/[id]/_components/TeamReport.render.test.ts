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
    expect(text).toContain("Attack logs missed");
    // blind-spots card
    expect(text).toContain("What the team missed");
    expect(text).toContain("USB mass copy on HR laptop");          // nobody handled it
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
    expect(text).toContain("Host isolation in EDR");
    expect(text).toContain("1/2 right calls");
    expect(text).toContain("✓ right call");
    expect(text).toContain("isolated 3m 00s after its first attack log");
    expect(text).toContain("✗ wrong call");
    expect(text).toContain("clean — no attack activity on this host");
    expect(text).toContain("Hosts you isolated");          // Omer's card
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
});
