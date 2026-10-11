// A management request says who answers it (the SOC Manager, with a SITREP).
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("@/lib/supabase/client", () => ({ getSupabaseBrowserClient: () => null }));
import { InjectFeed } from "./InjectFeed";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const req = { seq: 5, type: "staff.inject", actor_id: null, role: null, payload: { kind: "mgmt_request", text: "CISO wants a status update" } };
const twist = { seq: 6, type: "staff.inject", actor_id: null, role: null, payload: { kind: "update", text: "EDR update" } };
const sitrep = { seq: 9, type: "sitrep.sent", actor_id: "mgr-1", role: "mgr", payload: {} };

describe("InjectFeed — management requests", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  const render = async (events: unknown[], role: string, hasManager = true) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => { root!.render(React.createElement(InjectFeed, { sessionId: "s", events: events as never, me: { id: "u", is_staff: false, role }, nameOf: () => "Dana", act: async () => true, hasManager })); });
    return el.textContent ?? "";
  };
  it("the Manager is told it's theirs and gets a Write SITREP button", async () => {
    const t = await render([req], "mgr");
    expect(t).toMatch(/management request/i);
    expect(t).toMatch(/Yours to answer/);
    expect(t).toMatch(/Write SITREP/);
  });
  it("other players see who it's waiting for; twists stay a plain update", async () => {
    const t = await render([req, twist], "t1");
    expect(t).toMatch(/Waiting for the SOC Manager's SITREP/);
    expect(t).not.toMatch(/Write SITREP/);
    expect(t.match(/management request/gi)?.length).toBe(2);   // the legend + the one request
  });
  it("answered by the first SITREP after it; a team without a Manager is warned", async () => {
    expect(await render([req, sitrep], "t1")).toMatch(/SITREP sent by Dana/);
    act(() => root?.unmount()); el?.remove();
    expect(await render([req], "t1", false)).toMatch(/No SOC Manager on this team/);
  });
});
