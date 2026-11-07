// In a Team-SOC session isolating a host is a REQUEST to the senior on shift (0104); the server
// isolates on approval. Release stays direct. The browser-only store is never touched.
import { describe, it, expect, vi, afterEach } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/edr", useSearchParams: () => new URLSearchParams() }));
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { EdrConsole } from "./EdrConsole";
import { EDR_INVESTIGATIONS } from "@/lib/edr/investigations";
import { containedHosts } from "@/lib/edr/containment";
import type { TeamIsolation } from "@/lib/team/useTeamIsolation";
import type { HostIsolation } from "@/lib/team/projections";
import type { IsolationRequest } from "@/lib/team/isolationApproval";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const inv = EDR_INVESTIGATIONS[0];

describe("EdrConsole — team isolation", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); localStorage.clear(); });

  function mount(team: TeamIsolation) {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(EdrConsole, { investigations: [inv], initialCaseId: inv.id, teamIsolation: team })); });
  }
  const isolateBtn = () => [...el!.querySelectorAll("button")].find(b => /Request isolation|Host isolated|Waiting for approval/.test(b.textContent ?? ""))!;
  const team = (over: Partial<TeamIsolation> = {}): TeamIsolation => ({
    state: new Map(), set: vi.fn(async () => null), request: vi.fn(async () => null), requests: new Map(),
    approverFor: () => "Dana (SOC Manager)", nameOf: u => (u === "mgr-1" ? "Dana" : "a teammate"), canContain: true, ...over,
  });
  const req = (state: IsolationRequest["state"], extra: Partial<IsolationRequest> = {}): IsolationRequest => ({
    seq: 5, host: inv.host.name, requestedBy: "me", requesterRole: "t2", reason: "reverse shell", incident: null, at: null,
    state, answeredBy: state === "pending" ? null : "mgr-1", answeredAt: null, answerSeq: state === "pending" ? null : 6, denyReason: null, ...extra,
  });

  it("asks the senior on shift with a reason instead of isolating, and never touches the local store", async () => {
    const t = team();
    mount(t);
    expect(el!.textContent).toContain("needs the approval of the senior on shift");
    await act(async () => { isolateBtn().click(); });
    const ta = el!.querySelector<HTMLTextAreaElement>("#edr-iso-reason")!;
    expect(ta).toBeTruthy();
    const send = () => [...el!.querySelectorAll("button")].find(b => b.textContent === "Send request") as HTMLButtonElement;
    expect(send().disabled).toBe(true);                                  // a reason is required
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
      setter.call(ta, "reverse shell to 104.248.93.41"); ta.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => { send().click(); });
    expect(t.request).toHaveBeenCalledWith(inv.host.name, "reverse shell to 104.248.93.41", inv.title);
    expect(t.set).not.toHaveBeenCalled();
    expect(containedHosts()).toEqual([]);
  });

  it("shows who it waits for, then the answer with the deny reason", () => {
    const requests = new Map([[inv.host.name.toLowerCase(), req("pending")]]);
    mount(team({ requests }));
    expect(isolateBtn().textContent).toContain("Waiting for approval from Dana (SOC Manager)");
    expect((isolateBtn() as HTMLButtonElement).disabled).toBe(true);
    act(() => { root!.render(React.createElement(EdrConsole, { investigations: [inv], initialCaseId: inv.id, teamIsolation: team({ requests: new Map([[inv.host.name.toLowerCase(), req("denied", { denyReason: "capture memory first" })]]) }) })); });
    expect(el!.textContent).toContain("Isolation denied by Dana: capture memory first");
  });

  it("an isolated host offers release, which stays direct", async () => {
    const state = new Map<string, HostIsolation>([[inv.host.name.toLowerCase(), { host: inv.host.name, isolated: true, by: "me", at: null, seq: 1 }]]);
    const t = team({ state });
    mount(t);
    expect(isolateBtn().textContent).toContain("Host isolated ✓");
    await act(async () => { isolateBtn().click(); });
    expect(t.set).toHaveBeenCalledWith(inv.host.name, false, inv.title);
  });

  it("Tier-1 investigates but cannot isolate: the button is disabled and nothing is sent", async () => {
    const t = team({ canContain: false });
    mount(t);
    expect((isolateBtn() as HTMLButtonElement).disabled).toBe(true);
    expect(el!.textContent).toContain("The senior analyst (Tier-2 / Tier-3) decides.");
    await act(async () => { isolateBtn().click(); });
    expect(t.request).not.toHaveBeenCalled();
  });
});
