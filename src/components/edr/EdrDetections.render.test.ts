// Live EDR: no popups in the console. Detections sit in one list, sortable by severity or
// time; new ones are marked NEW until opened, which clears them for the dashboard's count.
import { describe, it, expect, vi, afterEach } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/edr", useSearchParams: () => new URLSearchParams() }));
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { EdrConsole } from "./EdrConsole";
import { EDR_INVESTIGATIONS } from "@/lib/edr/investigations";
import { readAckedAlerts } from "@/lib/edr/alerts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const inv = EDR_INVESTIGATIONS[0];

describe("EDR detections list", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); localStorage.clear(); });
  const mount = (liveAlerts: boolean) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(EdrConsole, { investigations: [inv], initialCaseId: inv.id, liveAlerts })); });
  };
  const rows = () => [...el!.querySelectorAll('table[aria-labelledby="edr-detections-heading"] tbody tr')];
  const btn = (re: RegExp) => [...el!.querySelectorAll("button")].find(b => re.test(b.textContent ?? ""))!;

  it("lists every detection, no popup or corner card", () => {
    mount(true);
    expect(rows()).toHaveLength(inv.detections.length);
    expect(el!.querySelector('[role="alertdialog"]')).toBeNull();
    expect(el!.textContent).toContain(`${inv.detections.length} new`);
  });

  it("sorts by severity (worst first) or by time (newest first)", () => {
    mount(true);
    const sev = rows().map(r => r.querySelectorAll("td")[1].textContent);
    expect(sev[0]).toBe("critical");
    act(() => { btn(/^By time$/).click(); });
    const times = rows().map(r => r.querySelectorAll("td")[0].textContent ?? "");
    expect([...times].sort().reverse()).toEqual(times);
  });

  it("opening a detection clears its NEW mark and records it for the dashboard count", () => {
    mount(true);
    act(() => { (rows()[0] as HTMLElement).click(); });
    expect(readAckedAlerts().size).toBe(1);
    expect(el!.textContent).toContain(`${inv.detections.length - 1} new`);
  });

  it("the practice set shows the list without NEW marks", () => {
    mount(false);
    expect(rows()).toHaveLength(inv.detections.length);
    expect(el!.textContent).not.toMatch(/\d+ new/);
  });
});
