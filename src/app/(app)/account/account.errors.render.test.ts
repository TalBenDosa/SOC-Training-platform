// QA phase 7, E-14: a failed account load is an error state with a retry — not
// a page of "—", XP 0 and the solo-learner "erase everything" deletion copy.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, refresh() {} }) }));
vi.mock("@/lib/auth/AuthContext", () => ({ useAuth: () => ({ user: { email: "s@x.edu" }, signOut: async () => {} }) }));
import AccountPage from "./page";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

describe("account — load failure", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); vi.unstubAllGlobals(); });
  const flush = () => act(async () => { await new Promise(r => setTimeout(r, 0)); });

  it("shows the error and Try again, hides details and deletion; a retry that works shows the page", async () => {
    let ok = false;
    vi.stubGlobal("fetch", vi.fn(async () => ok
      ? new Response(JSON.stringify({ handle: "neo", display_name: "Neo Anderson", xp: 120, enrolled: true, org_name: "Cyber College", deletion_request: null }), { status: 200 })
      : new Response(JSON.stringify({ error: "x" }), { status: 503 })));
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => { root!.render(React.createElement(AccountPage)); });
    await flush();
    let text = el.textContent ?? "";
    expect(text).toMatch(/Try again/);
    expect(text).not.toMatch(/Delete your account/);
    expect(text).not.toMatch(/Your details/);
    expect(text).toMatch(/Change password/);   // works without the profile

    ok = true;
    const retry = [...el.querySelectorAll("button")].find(b => b.textContent === "Try again")!;
    await act(async () => { retry.click(); });
    await flush();
    text = el.textContent ?? "";
    expect(text).toMatch(/Your details/);
    expect(text).toMatch(/Cyber College/);
    expect(text).toMatch(/Request deletion/);
    expect(text).not.toMatch(/Try again/);
  });
});
