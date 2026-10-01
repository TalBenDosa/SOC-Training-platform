// QA phase 7, E-21: repeated heartbeat failures are reported (the room shows
// "Connection unstable") instead of ending in a surprise coverage pause.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";

const st = { fail: true, calls: 0 };
vi.mock("@/lib/supabase/client", () => ({
  getSupabaseBrowserClient: () => ({ rpc: async () => { st.calls++; return st.fail ? { error: { message: "fetch failed" } } : { error: null }; } }),
}));
const { useTeamHeartbeat } = await import("./useTeamHeartbeat");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

let seen: boolean[] = [];
function Probe() { seen.push(useTeamHeartbeat("s1")); return null; }

describe("useTeamHeartbeat", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  it("unstable after two failures in a row, stable again after one success", async () => {
    seen = []; st.fail = true; st.calls = 0;
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => { root!.render(React.createElement(Probe)); });
    expect(seen.at(-1)).toBe(false);                       // one failure: not yet
    await act(async () => { window.dispatchEvent(new Event("online")); });
    expect(seen.at(-1)).toBe(true);                        // two in a row
    st.fail = false;
    await act(async () => { window.dispatchEvent(new Event("online")); });
    expect(seen.at(-1)).toBe(false);
  });
});
