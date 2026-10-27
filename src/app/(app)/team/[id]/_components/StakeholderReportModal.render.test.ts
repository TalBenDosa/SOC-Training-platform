// SOC Manager stakeholder report (Tal, 2026-10-27): with no incident declared the Send button was
// greyed out with no word why. Now Send says what is missing, and declares the incident in the
// same click once a severity is picked.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { StakeholderReportModal, type ReportDraft } from "./StakeholderReportModal";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const full: ReportDraft = {
  audience: "ciso", status: "investigating", title: "Phishing led to PowerShell on a sales workstation",
  what_happened: "Suspicious PowerShell execution on WS-SALES-1876 following a suspected phishing email.",
  business_impact: "One sales laptop is offline for now", affected: "WS-SALES-1876", data_impact: "suspected", data_types: "",
  actions_taken: "WS-SALES-1876 cut off from the network", known: "", unknown: "Whether other hosts were reached", asks: "", next_update_min: "30",
};

describe("StakeholderReportModal", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  function mount(draft: ReportDraft | null, calls: [string, Record<string, unknown>][]) {
    el = document.createElement("div"); document.body.appendChild(el);
    root = createRoot(el);
    act(() => root!.render(React.createElement(StakeholderReportModal, {
      events: [], severity: null, seed: { hosts: [], lines: [] }, onClose: () => {}, draft,
      act: async (t: string, p: Record<string, unknown>) => { calls.push([t, p]); return true; },
    })));
    return el;
  }
  const button = (c: HTMLElement, text: string) => [...c.querySelectorAll("button")].find(b => b.textContent?.includes(text))!;

  it("Send is never a silent dead button: it names the missing fields", async () => {
    const calls: [string, Record<string, unknown>][] = [];
    const c = mount({ ...full, title: "", next_update_min: "" }, calls);
    const send = button(c, "Send report");
    expect(send.disabled).toBe(false);
    await act(async () => { send.click(); });
    expect(c.textContent).toContain("Still needed: Title, Next update.");
    expect(calls).toEqual([]);
  });

  it("asks for a severity, then declares the incident and sends the report in one click", async () => {
    const calls: [string, Record<string, unknown>][] = [];
    const c = mount(full, calls);
    expect(c.textContent).toContain("The incident is not declared yet");
    await act(async () => { button(c, "Send report").click(); });
    expect(c.textContent).toContain("Pick the incident severity");
    const sev3 = c.querySelector<HTMLInputElement>('input[name="sh-declare"][value="3"]')!;
    await act(async () => { sev3.click(); });
    await act(async () => { button(c, "Declare Sev-3 and send").click(); });
    expect(calls.map(x => x[0])).toEqual(["incident.declared", "stakeholder.report_sent"]);
    expect(calls[0][1]).toEqual({ severity: 3 });
    expect(calls[1][1]).toMatchObject({ severity: 3, next_update_min: 30, affected: ["WS-SALES-1876"] });
  });
});
