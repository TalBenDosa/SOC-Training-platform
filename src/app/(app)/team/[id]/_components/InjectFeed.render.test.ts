// Scenario review fix 6: everyone can see WHO answers a help-desk ticket. 2026-10-18: answering
// moved to the Action-required box at the top of each console; this card is the team's record.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("@/lib/supabase/client", () => ({ getSupabaseBrowserClient: () => null }));
import { InjectFeed } from "./InjectFeed";
import { ActionInbox } from "./ActionInbox";
import type { Ev, Me, RosterMember } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const events: Ev[] = [
  { seq: 5, type: "staff.inject", actor_id: null, role: null, payload: { kind: "update", text: "Marketing's manager messages the SOC: is this exfil?" } },
  { seq: 9, type: "staff.inject", actor_id: null, role: null, payload: { kind: "ticket", text: "Someone from 'IT support' asked a user to read back an MFA code." } },
];
const roster: RosterMember[] = [
  { user_id: "u1", role: "t1", status: "ready", name: "A", handle: null },
  { user_id: "u2", role: "t2", status: "ready", name: "B", handle: null },
];

describe("InjectFeed", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  const mount = (node: React.ReactElement) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(node); });
    return el.textContent ?? "";
  };
  const feed = (me: Me, evs = events) => mount(React.createElement(InjectFeed, { sessionId: "s1", events: evs, me, nameOf: (u: string | null) => (u === "u2" ? "Bea" : "x"), act: vi.fn(async () => true) }));

  it("Tier-2 sees who answers the ticket, and is pointed at Action required for updates", () => {
    const text = feed({ id: "u2", is_staff: false, role: "t2" });
    expect(text).toContain("answered by Tier-1");
    expect(text).toContain("Waiting for Tier-1 to answer it.");
    expect(text).toContain("Action required");
    expect(text).not.toContain("Refuse & report to security");
  });

  it("shows who answered an update, and how", () => {
    const text = feed({ id: "u1", is_staff: false, role: "t1" }, [...events, { seq: 12, type: "inject.responded", actor_id: "u2", role: "t2", payload: { inject_seq: 5, decision: "benign", note: "SaaS tool is on the approved list" } }]);
    expect(text).toContain("Bea: not an incident · SaaS tool is on the approved list");
  });
});

describe("ActionInbox", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  const mount = (me: Me, evs = events) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(ActionInbox, { events: evs, me, roster, act: vi.fn(async () => true) })); });
    return el.textContent ?? "";
  };

  it("Tier-1 gets the ticket and the update, each needing a written answer", () => {
    const text = mount({ id: "u1", is_staff: false, role: "t1" });
    expect(text).toMatch(/Action required\s*2/);
    expect(text).toContain("Refuse & report to security");
    expect(text).toContain("Not an incident");
    const buttons = [...el!.querySelectorAll("button")];
    expect(buttons.length).toBeGreaterThan(0);
    expect(buttons.every(b => b.disabled)).toBe(true);   // no answer before the note is written
  });

  it("Tier-2 gets the update only; nothing once answered", () => {
    expect(mount({ id: "u2", is_staff: false, role: "t2" })).not.toContain("Help-desk ticket");
    act(() => root?.unmount()); el?.remove();
    const after = mount({ id: "u2", is_staff: false, role: "t2" }, [...events, { seq: 12, type: "inject.responded", actor_id: "u2", role: "t2", payload: { inject_seq: 5, decision: "benign", note: "approved tool, vendor domain" } }]);
    expect(after).toBe("");
  });
});
