// Every escalation or case opens with the full detail of what the analyst reported (owner,
// 2026-11-08). The shared renderer, and the receivers that use it: the Tier-2 escalation card, the
// Tier-3 elevation and the isolation approval card. What a receiver sees in the first view.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { HandoffDetail } from "./HandoffDetail";
import { T2Console } from "./T2Console";
import { HuntConsole } from "./HuntConsole";
import { IsolationApprovals } from "./IsolationApprovals";
import { escalationHandoff } from "@/lib/team/handoff";
import { escalationStates } from "@/lib/team/projections";
import type { Ev, RosterMember } from "@/lib/team/types";
import { at, nameOf, sampleEvents } from "@/lib/team/__fixtures__/handoffEvents";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null; let el: HTMLDivElement | null = null;
afterEach(() => { act(() => root?.unmount()); el?.remove(); root = null; el = null; });
async function mount(node: React.ReactElement) {
  el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
  await act(async () => root!.render(node));
  return el;
}
const text = () => el!.textContent ?? "";
const SUMMARY = "Ticket INC0033424 (New): Locked out, then an encoded PowerShell beacon on WS-FIN-2847 right after the user's password reset";

describe("HandoffDetail", () => {
  it("shows every field the sender wrote, in the fixed order, and no answer key", async () => {
    const events = sampleEvents();
    await mount(React.createElement(HandoffDetail, { handoff: escalationHandoff(events[3], events, { nameOf }) }));
    const t = text();
    const order = ["Escalation from Dana (Tier-1)", SUMMARY, "Verdict: true positive", "Severity: high", "Asks: contain",
      "Observations", "IEX download cradle", "Assessment", "Indicators (10)", "185.220.101.10", "Host", "WS-FIN-2847", "User", "r.cohen@nexacorp.com",
      "Escalated log", "Command line", "powershell -enc SQBFAFgA", "Log added by Dana", "Beacon to 185.220.101.4"];
    let pos = -1;
    for (const s of order) { const i = t.indexOf(s, pos + 1); expect(i, s).toBeGreaterThan(pos); pos = i; }
    expect(t).not.toContain("THE ANSWER");
    expect(t).not.toContain("—");
    // A default the form sent is not shown as the analyst's call (2026-11-08 review).
    expect(t).not.toContain("Confidence");
    // The summary is never cut: it is in the DOM whole, and wraps.
    const sum = el!.querySelector("[data-handoff-summary]")!;
    expect(sum.textContent).toBe(SUMMARY);
    expect(sum.className).toContain("whitespace-pre-wrap");
    expect(sum.className).not.toContain("truncate");
  });

  it("folds only a very long text, behind a keyboard button", async () => {
    const events = sampleEvents();
    const long = "Evidence line. ".repeat(80);
    const h = escalationHandoff({ ...events[3], payload: { ...events[3].payload, observations: long } }, events, { nameOf });
    await mount(React.createElement(HandoffDetail, { handoff: h }));
    const btn = [...el!.querySelectorAll("button")].find(b => b.textContent?.startsWith("Show all"))!;
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(text()).toContain("Evidence line.");
    await act(async () => { btn.click(); });
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    expect(text()).toContain(long.trim());
  });

  it("says so when the sender wrote no reasoning", async () => {
    const events = sampleEvents();
    const h = escalationHandoff({ ...events[3], payload: { event_id: "e1", summary: "Short one" } }, events, { nameOf });
    await mount(React.createElement(HandoffDetail, { handoff: h }));
    expect(text()).toContain("ObservationsNot written");
  });
});

describe("receivers", () => {
  it("Tier-2's escalation card opens with the whole hand-off, all ten indicators and the bounce", async () => {
    const events: Ev[] = [...sampleEvents().slice(0, 5), { seq: 30, type: "escalation.bounced", actor_id: "u3", role: "t2", payload: { event_id: "e1", reason: "Needs more context: which user?" }, occurred_at: at(30) },
      { seq: 31, type: "escalation.requested", actor_id: "u1", role: "t1", occurred_at: at(31), payload: { ...sampleEvents()[3].payload, summary: `${SUMMARY} (user r.cohen)` } }];
    const esc = events[events.length - 1];
    const noop = async () => true;
    await mount(React.createElement(T2Console, {
      sessionId: "s1", role: "t2", meId: "u2", events, escalations: [esc], escState: escalationStates(events), reportedIds: new Set(), reportByEid: new Map(), elevatedIds: new Set(),
      containments: [], scope: null, scopes: new Map(), incidents: [], incidentOf: new Map(), nameOf, act: noop, actR: async () => ({ ok: true, code: null }),
    } as never));
    const t = text();
    expect(t).toContain(`${SUMMARY} (user r.cohen)`);
    expect(t).toContain("Verdict: true positive");
    expect(t).toContain("IEX download cradle");
    expect(t).toContain("Indicators (10)");
    for (let i = 1; i <= 10; i++) expect(t).toContain(`185.220.101.${i}`);
    expect(t).toContain("r.cohen@nexacorp.com");
    expect(t).toContain("powershell -enc SQBFAFgA");
    expect(t).toContain("Bounced back");
    expect(t).toContain("Needs more context: which user?");
    expect(t).toContain("Earlier escalation");
    expect(t).toContain("Acknowledge (take this case)");
  });

  it("Tier-3's elevation shows the hunt ask, Tier-2's findings and the Tier-1 escalation behind it", async () => {
    const events = sampleEvents();
    await mount(React.createElement(HuntConsole, {
      events, scope: null, elevations: [events[8]], elevAcked: new Set<string>(), nameOf, act: async () => true,
    }));
    const t = text();
    expect(t).toContain("Elevation to Tier-3 from Noa (Tier-2)");
    expect(t).toContain("What to hunt");
    expect(t).toContain("Hunt lateral movement from WS-FIN-2847 to the DC");
    expect(t).toContain("Tier-2 findings");
    expect(t).toContain("Confirmed the beacon");
    expect(t).toContain(`Escalation from Dana: ${SUMMARY}`);
    expect(t).toContain("Take the hunt");
  });

  it("the approver sees the full isolation request and the case it comes from, open", async () => {
    const events = sampleEvents();
    const roster: RosterMember[] = [
      { user_id: "u1", role: "t1", status: "active", name: "Dana", handle: null },
      { user_id: "u2", role: "t2", status: "active", name: "Noa", handle: null },
      { user_id: "u4", role: "mgr", status: "active", name: "Maya", handle: null },
    ];
    await mount(React.createElement(IsolationApprovals, { sessionId: "s1", events, roster, online: new Set(["u1", "u2", "u4"]), me: { id: "u4", is_staff: false, role: "mgr" }, nameOf }));
    const t = text();
    expect(t).toContain("wants to isolate");
    expect(t).toContain("Macro C2 on WS-FIN-2847. What breaks: payroll run");
    expect(t).toContain("INC-A");
    const details = [...el!.querySelectorAll<HTMLDetailsElement>("details[data-handoff-related]")];
    expect(details.length).toBeGreaterThanOrEqual(2);
    expect(details.every(d => d.open)).toBe(true);
    expect(t).toContain("IEX download cradle");          // the Tier-1 reasoning
    expect(t).toContain("Isolate the host, block 185.220.101.4"); // the Tier-2 recommendation
    expect(el!.querySelector("[role=alert]")!.textContent).toContain("Noa");
    expect([...el!.querySelectorAll("button")].map(b => b.textContent)).toEqual(expect.arrayContaining(["Approve", "Deny"]));
  });
});
