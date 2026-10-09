// In a Team-SOC session the "Isolate host" button records the isolation for the team
// (session log → scored in the after-action report) instead of the browser-only store.
import { describe, it, expect, vi, afterEach } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/edr", useSearchParams: () => new URLSearchParams() }));
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { EdrConsole } from "./EdrConsole";
import { EDR_INVESTIGATIONS } from "@/lib/edr/investigations";
import { containedHosts } from "@/lib/edr/containment";
import type { TeamIsolation } from "@/lib/team/useTeamIsolation";
import type { HostIsolation } from "@/lib/team/projections";

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
  const isolateBtn = () => [...el!.querySelectorAll("button")].find(b => /Isolate host|Host isolated/.test(b.textContent ?? ""))!;

  it("records the isolation in the session (not localStorage) and shows the team's state", async () => {
    const state = new Map<string, HostIsolation>();
    const set = vi.fn(async (host: string, isolated: boolean) => { state.set(host.toLowerCase(), { host, isolated, by: "me", at: null, seq: 1 }); return null; });
    mount({ state, set, canContain: true });
    expect(el!.textContent).toContain("Recorded for the team");
    await act(async () => { isolateBtn().click(); });
    expect(set).toHaveBeenCalledWith(inv.host.name, true, inv.title);
    expect(containedHosts()).toEqual([]);                       // the single-player store is untouched
    // a re-render with the refreshed team state shows the host as isolated
    act(() => { root!.render(React.createElement(EdrConsole, { investigations: [inv], initialCaseId: inv.id, teamIsolation: { state: new Map(state), set, canContain: true } })); });
    expect(isolateBtn().textContent).toContain("Host isolated ✓");
  });

  it("shows the server's refusal next to the button", async () => {
    const set = vi.fn(async () => "Can't send that yet — WS-X is already isolated.");
    mount({ state: new Map(), set, canContain: true });
    await act(async () => { isolateBtn().click(); });
    expect(el!.querySelector('[role="alert"]')?.textContent).toContain("already isolated");
  });

  it("Tier-1 investigates but cannot isolate: the button is disabled and nothing is recorded", async () => {
    const set = vi.fn(async () => null);
    mount({ state: new Map(), set, canContain: false });
    expect((isolateBtn() as HTMLButtonElement).disabled).toBe(true);
    expect(el!.textContent).toContain("Tier-2 / Tier-3 decide on isolation");
    await act(async () => { isolateBtn().click(); });
    expect(set).not.toHaveBeenCalled();
  });
});
