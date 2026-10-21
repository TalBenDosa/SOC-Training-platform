// Live EDR: every new detection pops a red alert with the full EDR data; acknowledging it
// (or Investigate) stores it so it never re-pops, and Investigate selects its process.
import { describe, it, expect, vi, afterEach } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/edr", useSearchParams: () => new URLSearchParams() }));
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { EdrConsole } from "./EdrConsole";
import { EDR_INVESTIGATIONS } from "@/lib/edr/investigations";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const inv = EDR_INVESTIGATIONS[0];

describe("EDR live alert popup", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); localStorage.clear(); });
  const mount = (liveAlerts: boolean, invs = [inv]) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(EdrConsole, { investigations: invs, liveAlerts })); });
  };
  const dialog = () => el!.querySelector('[role="alertdialog"]');
  const btn = (re: RegExp) => [...el!.querySelectorAll("button")].find(b => re.test(b.textContent ?? ""))!;

  it("shows the detection, host and process data, one alert per detection", () => {
    mount(true);
    const d = inv.detections[0];
    const p = inv.processes.find(x => x.pid === d.pid)!;
    expect(dialog()).not.toBeNull();
    const text = dialog()!.textContent ?? "";
    expect(text).toContain("New EDR detection");
    expect(text).toContain(d.name);
    expect(text).toContain(inv.host.name);
    expect(text).toContain(p.cmdline);
    expect(text).toContain(`1 of ${inv.detections.length}`);
    // never the answer
    if (p.note) expect(text).not.toContain(p.note);
  });

  it("acknowledged alerts don't come back after a reload", () => {
    mount(true);
    for (let i = 0; i < inv.detections.length; i++) act(() => { btn(/^Acknowledge$/).click(); });
    expect(dialog()).toBeNull();
    act(() => root!.unmount()); el!.remove();
    mount(true);
    expect(dialog()).toBeNull();
  });

  it("Investigate opens the case on the alert's process", () => {
    mount(true);
    act(() => { btn(/Investigate in the process tree/).click(); });
    expect(el!.textContent).toContain("Investigate the endpoint");
  });

  it("the practice set (no live shift) never pops", () => {
    mount(false);
    expect(dialog()).toBeNull();
  });
});
