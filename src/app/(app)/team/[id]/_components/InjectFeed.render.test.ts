// Scenario review fix 6: everyone can see WHO answers a help-desk ticket; Tier-1
// gets the answer controls; updates say there's nothing to reply to.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("@/lib/supabase/client", () => ({ getSupabaseBrowserClient: () => null }));
import { InjectFeed } from "./InjectFeed";
import type { Ev, Me } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const events: Ev[] = [
  { seq: 5, type: "staff.inject", actor_id: null, role: null, payload: { kind: "update", text: "Marketing's manager messages the SOC: is this exfil?" } },
  { seq: 9, type: "staff.inject", actor_id: null, role: null, payload: { kind: "ticket", text: "Someone from 'IT support' asked a user to read back an MFA code." } },
];

describe("InjectFeed", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  const mount = (me: Me) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(InjectFeed, { sessionId: "s1", events, me, nameOf: () => "x", act: vi.fn(async () => true) })); });
    return el.textContent ?? "";
  };

  it("Tier-2 sees who answers the ticket — and no answer buttons", () => {
    const text = mount({ id: "u2", is_staff: false, role: "t2" });
    expect(text).toContain("answered by Tier-1");
    expect(text).toContain("Waiting for Tier-1 to answer it.");
    expect(text).toContain("need no reply");
    expect(text).not.toContain("Refuse & escalate to security");
    expect(text).not.toMatch(/Help desk:/);
  });

  it("Tier-1 gets the answer controls", () => {
    const text = mount({ id: "u1", is_staff: false, role: "t1" });
    expect(text).toContain("Handle request");
    expect(text).toContain("Refuse & escalate to security");
    expect(text).not.toContain("Waiting for Tier-1");
  });
});
