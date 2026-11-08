// Fixes from the 2026-11-08 real-browser check of the hand-off: the Tier-2 card's isolation banner,
// the header's "Investigate in Sentinel" target, the no-approver deadlock and the scope label box.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { T2Console } from "./T2Console";
import { ScopeConsole } from "./ScopeConsole";
import { escalationStates } from "@/lib/team/projections";
import { NO_APPROVER, isolationRequests, type IsolationRequest } from "@/lib/team/isolationApproval";
import { nameOf, sampleEvents } from "@/lib/team/__fixtures__/handoffEvents";

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

// Noa (u2, Tier-2) took the case on WS-FIN-2847; Tier-1 recommended isolating it.
function t2(over: Record<string, unknown> = {}) {
  const events = sampleEvents().slice(0, 7);
  return React.createElement(T2Console, {
    sessionId: "s1", role: "t2", meId: "u2", events, escalations: [events[3]], escState: escalationStates(events), reportedIds: new Set(), reportByEid: new Map(), elevatedIds: new Set(),
    containments: [], scope: null, scopes: new Map(), incidents: [], incidentOf: new Map(), nameOf, act: async () => true, actR: async () => ({ ok: true, code: null }),
    consoleName: "Sentinel", ...over,
  } as never);
}
const pending = (): IsolationRequest => isolationRequests(sampleEvents())[0];

describe("Tier-2 card: the isolation recommendation", () => {
  it("shows Tier-1's recommendation while no request exists", async () => {
    await mount(t2());
    expect(text()).toContain("Tier-1 recommends isolating WS-FIN-2847: your decision, in Sentinel");
  });

  it("is replaced by the request's state once a request exists", async () => {
    await mount(t2({ isoRequests: new Map([["ws-fin-2847", pending()]]), approverFor: () => "Maya (SOC Manager)" }));
    expect(text()).not.toContain("Tier-1 recommends isolating");
    expect(el!.querySelector("[data-isolation-state]")!.textContent).toContain("waiting for approval from Maya (SOC Manager)");
  });

  it("is gone once the host is isolated", async () => {
    await mount(t2({ isolation: new Map([["ws-fin-2847", { host: "WS-FIN-2847", isolated: true }]]) }));
    expect(text()).not.toContain("Tier-1 recommends isolating");
  });
});

describe("Tier-2 card: nobody but the requester could approve", () => {
  it("says no approver is on shift and tells the requester what to do, never 'waiting for' themselves", async () => {
    await mount(t2({ isoRequests: new Map([["ws-fin-2847", pending()]]), approverFor: () => NO_APPROVER }));
    const line = el!.querySelector("[data-isolation-state]")!.textContent ?? "";
    expect(line).toContain("No approver on shift: an exercise admin must approve");
    expect(line).toContain("you cannot approve your own");
    expect(text()).not.toMatch(/waiting for approval from/i);
    // Nothing on the card lets the requester approve it.
    expect([...el!.querySelectorAll("button")].map(b => b.textContent)).not.toContain("Approve");
  });
});

describe("Tier-2 header: Investigate in Sentinel", () => {
  it("opens the incident of the case the analyst works", async () => {
    const calls: unknown[][] = [];
    await mount(t2({ onEdr: (...a: unknown[]) => { calls.push(a); } }));
    const btn = el!.querySelector<HTMLButtonElement>("[data-investigate-header]")!;
    expect(btn.title).toContain("Open the incident of your case");
    await act(async () => { btn.click(); });
    expect(calls[0]).toEqual([expect.stringContaining("Ticket INC0033424"), "WS-FIN-2847", "e1"]);
  });

  it("opens the incident list when the analyst has no case of their own", async () => {
    const calls: unknown[][] = [];
    await mount(t2({ meId: "u9", onEdr: (...a: unknown[]) => { calls.push(a); } }));
    const btn = el!.querySelector<HTMLButtonElement>("[data-investigate-header]")!;
    expect(btn.title).toBe("Open the incident list");
    await act(async () => { btn.click(); });
    expect(calls[0]).toEqual([]);
  });
});

describe("Scope: a long incident label", () => {
  const title = "Multi-stage incident involving Execution & Command And Control on one endpoint reported by multiple sources";
  it("keeps the whole title: ellipsis in the box, a tooltip, and the full title wrapped below", async () => {
    await mount(React.createElement(ScopeConsole, { scope: null, scopes: new Map(), incidents: [title], mode: "set", act: async () => true }));
    const chip = [...el!.querySelectorAll<HTMLButtonElement>("button")].find(b => b.textContent === title)!;
    expect(chip.title).toBe(title);
    expect(chip.className).toContain("truncate");
    await act(async () => { chip.click(); });
    const box = el!.querySelector<HTMLInputElement>('input[aria-label="Incident label (optional)"]')!;
    expect(box.value).toBe(title);
    expect(box.title).toBe(title);
    expect(box.className).toContain("text-ellipsis");
    const full = el!.querySelector("[data-scope-incident]")!;
    expect(full.textContent).toBe(`Scope for: ${title}`);
    expect(full.className).toContain("break-words");
    expect(box.getAttribute("aria-describedby")).toBe(full.id);
    expect(text()).not.toContain("—");
  });
});
