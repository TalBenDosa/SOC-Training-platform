// The ITSAFE situation: one admin invitation, expired, never used; no admin ever
// signed in. The card must say so and let the super-admin renew + resend.
import { describe, it, expect, vi, afterEach } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { AdminAccessCard } from "./AdminAccessCard";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const DAY = 86_400_000;

describe("AdminAccessCard", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); vi.unstubAllGlobals(); });

  it("flags an environment nobody signed in to, and renews + resends the expired invitation", async () => {
    let expired = true;
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/admin-access")) {
        return { ok: true, json: async () => ({
          invites: [{ id: "inv1", email: "head@itsafe.co.il", role: "org_admin", created_at: new Date(Date.now() - 37 * DAY).toISOString(),
            expires_at: new Date(Date.now() + (expired ? -23 : 14) * DAY).toISOString(), expired }],
          admins: [],
        }) };
      }
      expired = false;
      return { ok: true, json: async () => ({ ok: true, email_status: "sent", email: "head@itsafe.co.il", renewed: true, link: "https://x/join?token=t" }) };
    }));
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => { root!.render(React.createElement(AdminAccessCard, { orgId: "org1", refreshKey: 0 })); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });

    let text = el.textContent ?? "";
    expect(text).toContain("No org admin has signed in to this environment yet.");
    expect(text).toContain("head@itsafe.co.il");
    expect(text).toMatch(/sent 37 days ago/);
    expect(text).toMatch(/expired 23 days ago/);
    const btn = [...el.querySelectorAll("button")].find(b => /Renew & resend/.test(b.textContent ?? ""))!;
    expect(btn).toBeTruthy();

    await act(async () => { btn.click(); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    text = el.textContent ?? "";
    expect(calls).toContain("POST /api/superadmin/orgs/org1/invites/inv1/resend");
    expect(text).toContain("Sent to head@itsafe.co.il — the expired link was renewed for 14 days.");
    expect(text).toMatch(/expires in 14 days/);   // refetched after the renewal
  });
});
