// QA phase 7, E-02: a failed CHECK (busy server, 429, offline) is not an invalid
// code — signup says "couldn't check, try again", and only a real "not valid"
// answer shows the invalid-code dead end.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, refresh() {} }), useSearchParams: () => new URLSearchParams(window.location.search) }));
vi.mock("@/lib/supabase/client", () => ({ getSupabaseBrowserClient: () => null }));
vi.mock("@/lib/supabase/config", () => ({ isSupabaseConfigured: true, supabaseUrl: "https://x.supabase.co", supabaseAnonKey: "k" }));
import SignupPage from "./page";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

describe("signup — code check failures", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); vi.unstubAllGlobals(); });
  async function mount(url: string, res: () => Promise<Response>) {
    window.history.replaceState(null, "", url);
    vi.stubGlobal("fetch", vi.fn(res));
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => { root!.render(React.createElement(SignupPage)); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    return el.textContent ?? "";
  }

  it.each([[429], [500], [503]])("HTTP %i on the code check → \"couldn't check\", not \"invalid\"", async status => {
    const text = await mount("/signup?code=K7MRW3TQ", async () => new Response(JSON.stringify({ error: "x" }), { status }));
    expect(text).toMatch(/couldn.t check your access code/i);
    expect(text).not.toMatch(/isn.t valid/i);
  });

  it("a dropped connection on the invitation check → \"couldn't check\"", async () => {
    const text = await mount("/signup?invite=tok-1", async () => { throw new TypeError("Failed to fetch"); });
    expect(text).toMatch(/couldn.t check your invitation/i);
  });

  it("a real \"not valid\" answer still blocks with the invalid-code message", async () => {
    const text = await mount("/signup?code=K7MRW3TQ", async () => new Response(JSON.stringify({ valid: false }), { status: 200 }));
    expect(text).toMatch(/access code isn.t valid/i);
  });
});
