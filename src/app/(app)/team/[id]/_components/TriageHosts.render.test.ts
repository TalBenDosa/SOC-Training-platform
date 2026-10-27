// Tier-1 "Needs triage" by host (Sdema review 2026-10-25): a host nobody touched is flagged new and
// listed first, a host with an open case says who has it and adds its alerts to that case.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { TriageHosts } from "./TriageHosts";
import type { HostGroup } from "@/lib/team/hostCases";
import type { QueueItem } from "@/lib/team/alertQueue";
import type { Ev } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const item = (eid: string, severity: string, mins: number): QueueItem =>
  ({ e: { seq: Number(eid), type: "feed.event", actor_id: null, role: null, payload: { id: eid } } as Ev, eid, severity, mins, breached: false, orphan: false });
const groups: HostGroup[] = [
  { key: "ws-ops-2214", host: "WS-OPS-2214", items: [item("83", "critical", 6)], maxSeverity: "critical", oldestMins: 6, breached: 0, orphans: 0, isolated: null, case: null, covered: false, fresh: true },
  { key: "ws-sales-1876", host: "WS-SALES-1876", items: [item("48", "high", 12), item("54", "high", 9)], maxSeverity: "high", oldestMins: 12, breached: 0, orphans: 0,
    isolated: { by: "dmitry", at: "2026-10-25T10:53:00Z" }, case: { host: "WS-SALES-1876", caseEid: "33", owner: "dmitry", openedBy: "dmitry", label: "Encoded PowerShell", seq: 1 }, covered: true, fresh: false },
];

describe("TriageHosts", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });

  it("lists the new host first and adds the in-case host's alerts to the case", async () => {
    const added: string[][] = [];
    el = document.createElement("div"); document.body.appendChild(el);
    root = createRoot(el);
    act(() => root!.render(React.createElement(TriageHosts, {
      groups, nameOf: (u: string | null) => (u === "dmitry" ? "Dmitry" : "?"), meId: "aviv", claims: new Map(), activeHost: "all",
      onShowHost: () => {}, onTakeHost: () => {}, onAddToCase: async (eids: string[]) => { added.push(eids); return null; },
    })));
    const rows = [...el.querySelectorAll("li")];
    expect(rows[0].textContent).toContain("WS-OPS-2214");
    expect(rows[0].textContent).toContain("New host");
    expect(rows[0].textContent).not.toContain("to case");
    expect(rows[1].textContent).toContain("Case open · Dmitry");
    expect(rows[1].textContent).toContain("Isolated · Dmitry 10:53");
    const btn = [...rows[1].querySelectorAll("button")].find(b => b.textContent?.includes("Add all 2 to case"))!;
    await act(async () => { btn.click(); });
    expect(added).toEqual([["48", "54"]]);
    expect(rows[1].textContent).toContain("Added to Dmitry's case.");
  });
});
