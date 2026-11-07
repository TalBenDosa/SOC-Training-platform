// UX fixes from the 2026-11 review, rendered: the case stepper, the approver's isolation notice, the
// folded Action required list, the tour spotlight on a missing element, and the shift bar notices.
import { describe, it, expect, vi, afterEach } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/team/x", useSearchParams: () => new URLSearchParams() }));
const rpc = vi.fn(async () => ({ data: null, error: null }));
vi.mock("@/lib/supabase/client", () => ({ getSupabaseBrowserClient: () => ({ rpc }) }));
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import type { Ev, Me, RosterMember } from "@/lib/team/types";
import { escalationStates } from "@/lib/team/projections";
import { T2Console } from "./T2Console";
import { IsolationApprovals } from "./IsolationApprovals";
import { ActionInbox } from "./ActionInbox";
import { GuidedTour } from "./GuidedTour";
import { ShiftBar } from "./ShiftBar";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
let seq = 0;
const ev = (type: string, payload: Record<string, unknown>, actor: string | null, role: string | null = null): Ev => ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: "2026-11-07T10:00:00Z" });
const roster: RosterMember[] = [
  { user_id: "t1", role: "t1", status: "active", name: "Ana", handle: null },
  { user_id: "t2", role: "t2", status: "active", name: "Avi", handle: null },
  { user_id: "mgr", role: "mgr", status: "active", name: "Noa", handle: null },
];

let root: Root | null = null; let el: HTMLDivElement | null = null;
const mount = (node: React.ReactElement) => { el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el); act(() => root!.render(node)); };
afterEach(() => { act(() => root?.unmount()); el?.remove(); root = null; rpc.mockClear(); });
const buttons = () => [...el!.querySelectorAll("button")];
const btn = (re: RegExp) => buttons().find(b => re.test((b.textContent ?? "").trim())) as HTMLButtonElement | undefined;

describe("case stepper (T2Console)", () => {
  const base = () => {
    const esc = ev("escalation.requested", { event_id: "e1", summary: "Reverse shell on WS-1", hostname: "WS-1", severity: "high", iocs: [], snapshot: { hostname: "WS-1", source: "edr" } }, "t1", "t1");
    const ack = ev("escalation.acknowledged", { event_id: "e1" }, "t2", "t2");
    return [esc, ack];
  };
  const render = (events: Ev[], extra: Record<string, unknown> = {}) => {
    const st = escalationStates(events);
    mount(React.createElement(T2Console, {
      sessionId: "s", role: "t2", meId: "t2", escalations: [...st.values()].map(s => s.request), escState: st,
      reportedIds: new Set(events.filter(e => e.type === "report.submitted").map(e => String(e.payload.event_id))),
      reportByEid: new Map(events.filter(e => e.type === "report.submitted").map(e => [String(e.payload.event_id), e.payload as { verdict?: string }])),
      elevatedIds: new Set<string>(), containments: [], scope: null, scopes: new Map(), incidents: [], incidentOf: new Map(),
      nameOf: (u: string | null) => (u === "mgr" ? "Noa" : u ?? "system"), act: async () => true, actR: async () => ({ ok: true, code: null }),
      onEdr: () => {}, canEdr: () => true, ...extra,
    }));
  };
  it("shows the five steps with ONE primary action at the current step and locked steps as text", () => {
    render(base());
    const steps = [...el!.querySelectorAll('[aria-label="Case steps"] li')].map(li => li.textContent);
    expect(steps.map(t => t?.replace(/:.*/, "").replace(/^\d|✓/, "").trim())).toEqual(["Investigate", "Report", "Scope", "Contain", "Resolve"]);
    expect(el!.querySelector('[aria-current="step"]')?.textContent).toContain("Investigate");
    expect(btn(/Investigate in EDR/)).toBeTruthy();
    expect(btn(/^Resolve$/)).toBeUndefined();               // locked: not a dead bright button
    expect(btn(/Request containment/)).toBeUndefined();
    expect(el!.textContent).toContain("Done investigating? Write the report");
    expect(el!.querySelector("[aria-label=\"Case steps\"]")?.textContent).toContain("not open yet");
  });
  it("moves to Contain once the report and scope exist, and shows who approves a pending isolation", () => {
    const events = [...base(), ev("report.submitted", { event_id: "e1", verdict: "true_positive", summary: "x", findings: "y", recommendation: "z" }, "t2", "t2")];
    const isoReq = { seq: 99, host: "WS-1", requestedBy: "t2", requesterRole: "t2", reason: "shell", incident: null, at: null, state: "pending" as const, answeredBy: null, answeredAt: null, answerSeq: null, denyReason: null };
    render(events, { scope: { hosts: ["WS-1"], users: [], techniques: [], confirmed: false, by: "t2" }, isoRequests: new Map([["ws-1", isoReq]]), approverFor: () => "Noa (SOC Manager)" });
    expect(el!.querySelector('[aria-current="step"]')?.textContent).toContain("Contain");
    expect(el!.textContent).toContain("waiting for approval from Noa (SOC Manager)");
  });
  it("a harmless verdict skips containment and offers Resolve", () => {
    const events = [...base(), ev("report.submitted", { event_id: "e1", verdict: "benign", summary: "x", findings: "y", recommendation: "z" }, "t2", "t2")];
    render(events, { scope: { hosts: ["WS-1"], users: [], techniques: [], confirmed: false, by: "t2" } });
    expect(el!.querySelector('[aria-current="step"]')?.textContent).toContain("Resolve");
    expect(btn(/^Resolve$/)).toBeTruthy();
  });
  it("marks a self-opened case", () => {
    const esc = ev("escalation.requested", { event_id: "e2", summary: "Found it myself", opened_by: "t2", iocs: [{ type: "ip", value: "1.2.3.4", source: "picked" }] }, "t2", "t2");
    render([esc, ev("escalation.acknowledged", { event_id: "e2" }, "t2", "t2")]);
    expect(el!.textContent).toContain("self-opened");
    expect(el!.textContent).toContain("opened by");
  });
});

describe("IsolationApprovals", () => {
  const req = () => [ev("isolation.requested", { host: "WS-1", reason: "reverse shell", incident: "INC-1" }, "t2", "t2")];
  it("shows the requester, host, reason and incident to the approver only", () => {
    mount(React.createElement(IsolationApprovals, { sessionId: "s", events: req(), roster, online: new Set(["t2", "mgr"]), me: { id: "mgr", role: "mgr", is_staff: false } as Me, nameOf: (u: string | null) => (u === "t2" ? "Avi" : String(u)) }));
    expect(el!.textContent).toContain("Avi");
    expect(el!.textContent).toContain("WS-1");
    expect(el!.textContent).toContain("reverse shell");
    expect(el!.textContent).toContain("INC-1");
    act(() => root!.unmount()); el!.remove();
    mount(React.createElement(IsolationApprovals, { sessionId: "s", events: req(), roster, online: new Set(["t2", "mgr"]), me: { id: "t1", role: "t1", is_staff: false } as Me, nameOf: String }));
    expect(el!.textContent).toBe("");
  });
  it("approves through the action, and a deny needs a reason", async () => {
    mount(React.createElement(IsolationApprovals, { sessionId: "s", events: req(), roster, online: new Set(["t2", "mgr"]), me: { id: "mgr", role: "mgr", is_staff: false } as Me, nameOf: String }));
    await act(async () => { btn(/^Deny$/)!.click(); });
    expect(btn(/Send denial/)!.disabled).toBe(true);
    await act(async () => { btn(/^Back$/)!.click(); });
    await act(async () => { btn(/^Approve$/)!.click(); });
    expect(rpc).toHaveBeenCalledWith("apply_session_action", expect.objectContaining({ p_type: "isolation.approved", p_payload: { request_seq: seq } }));
  });
});

describe("ActionInbox", () => {
  it("folds each item to one line until Answer opens it", async () => {
    const events = [ev("staff.inject", { kind: "ticket", text: "A user in Finance says someone called asking for an MFA code" }, "ins", "instructor")];
    mount(React.createElement(ActionInbox, { events, me: { id: "t1", role: "t1", is_staff: false } as Me, roster, act: async () => true }));
    expect(el!.querySelector("textarea")).toBeNull();
    await act(async () => { btn(/^Answer$/)!.click(); });
    expect(el!.querySelector("textarea")).toBeTruthy();
  });
});

describe("GuidedTour", () => {
  it("drops the spotlight when the next step's element is missing", async () => {
    const target = document.createElement("div"); target.setAttribute("data-tour", "here"); document.body.appendChild(target);
    target.getBoundingClientRect = () => ({ top: 10, left: 10, width: 100, height: 40, right: 110, bottom: 50, x: 10, y: 10, toJSON() {} });
    target.scrollIntoView = () => {};
    mount(React.createElement(GuidedTour, { title: "T", onClose: () => {}, steps: [{ target: "here", title: "One", body: "a" }, { target: "missing", title: "Two", body: "b", absent: "Not on screen yet." }] }));
    await act(async () => { await new Promise(r => setTimeout(r, 60)); });
    expect(document.querySelector(".ring-neon-purple")).toBeTruthy();
    await act(async () => { btn(/^Next$/)!.click(); });
    await act(async () => { await new Promise(r => setTimeout(r, 60)); });
    expect(document.querySelector(".ring-neon-purple")).toBeNull();
    expect(el!.textContent).toContain("Not on screen yet.");
    target.remove();
  });
});

describe("ShiftBar", () => {
  it("docks notices as lines with their actions; nothing floats", () => {
    const onDismiss = vi.fn();
    mount(React.createElement(ShiftBar, { top: 68, status: "Live", clock: "12:00", role: "T1", controls: null,
      notices: [{ key: "a", tone: "info", text: "New EDR alert on WS-1", actions: React.createElement("button", null, "Investigate"), onDismiss }, { key: "b", tone: "alert", urgent: true, text: "Isolation waits for you" }] }));
    const items = [...el!.querySelectorAll("li")];
    expect(items).toHaveLength(2);
    expect(items[1].getAttribute("role")).toBe("alert");
    expect(el!.querySelector(".fixed")).toBeNull();
    act(() => { (el!.querySelector('[aria-label="Dismiss this notice"]') as HTMLButtonElement).click(); });
    expect(onDismiss).toHaveBeenCalled();
  });
});
