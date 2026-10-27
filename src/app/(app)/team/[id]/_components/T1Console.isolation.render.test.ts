// Isolation is the senior analyst's call (Tal, 2026-10-27): Tier-1 cannot isolate, but the escalation
// form lets them recommend isolating the log's host, and the recommendation travels with it.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { T1Console } from "./T1Console";
import type { Ev } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const feed: Ev[] = [{ seq: 1, type: "feed.event", actor_id: null, role: null, payload: { id: "e1", description: "Encoded PowerShell", hostname: "WS-SALES-1876", severity: "high" }, occurred_at: new Date().toISOString() }];

describe("T1Console: recommend isolation", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });

  it("offers the recommendation for the log's host and sends it with the escalation", async () => {
    const sent: [string, Record<string, unknown>][] = [];
    el = document.createElement("div"); document.body.appendChild(el);
    root = createRoot(el);
    await act(async () => root!.render(React.createElement(T1Console, {
      sessionId: "s1", feed, dispositions: new Map([["e1", "true_positive"]]), events: feed, meId: "t1",
      iocDraft: [], setIocDraft: () => {}, nameOf: () => "Dana",
      act: async (t: string, p: Record<string, unknown>) => { sent.push([t, p]); return true; },
      actR: async (t: string, p: Record<string, unknown>) => { sent.push([t, p]); return { ok: true }; },
      sel: "e1", setSel: () => {}, reportOpen: true, setReportOpen: () => {},
    } as never)));
    const box = el.querySelector<HTMLInputElement>("#t1-recommend-isolation")!;
    expect(box).toBeTruthy();
    expect(el.textContent).toContain("Isolation is the senior analyst's decision");
    await act(async () => { box.click(); });
    const esc = [...el.querySelectorAll("button")].find(b => b.textContent?.includes("Escalate to Tier-2"))!;
    await act(async () => { esc.click(); });
    const req = sent.find(x => x[0] === "escalation.requested");
    expect(req?.[1]).toMatchObject({ hostname: "WS-SALES-1876", recommend_isolation: true });
  });
});
