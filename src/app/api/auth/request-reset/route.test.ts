/**
 * SEC-06 / P-03: reset emails have per-address and platform-wide DAILY ceilings
 * (the response is the same uniform 200 either way), and the emailed link is
 * built on the canonical site URL, never the request's Host header.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server";

vi.mock("server-only", () => ({}));
let pending: Promise<unknown> | null = null;
vi.mock("next/server", async (orig) => ({ ...(await orig<typeof import("next/server")>()), after: (fn: () => Promise<unknown>) => { pending = fn(); } }));
const refuse = new Set<string>();
vi.mock("@/lib/security/rateLimit", () => ({
  checkRateLimit: vi.fn(async (key: string) => ({ ok: ![...refuse].some(p => key.startsWith(p)), retryAfter: 0 })),
}));
const sent: { to: string; text: string }[] = [];
vi.mock("@/lib/email/sendEmail", () => ({ sendEmail: vi.fn(async (m: { to: string; text: string }) => { sent.push(m); return { ok: true }; }) }));
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => ({ auth: { admin: { generateLink: async () => ({ data: { properties: { hashed_token: "th" } }, error: null }) } } }),
}));

const { POST } = await import("./route");
const call = async (host = "www.hackthesoc.app") => {
  const res = await POST(new NextRequest(`https://${host}/api/auth/request-reset`, { method: "POST", body: JSON.stringify({ email: "victim@college.ac.il" }), headers: { "content-type": "application/json" } }));
  await pending; pending = null;
  return res;
};

beforeEach(() => { refuse.clear(); sent.length = 0; });
afterEach(() => { vi.unstubAllEnvs(); });

describe("POST /api/auth/request-reset", () => {
  it("sends one reset email under the ceilings", async () => {
    expect((await call()).status).toBe(200);
    expect(sent).toHaveLength(1);
  });

  it.each([["per-address daily ceiling", "reset-day:"], ["platform daily budget", "reset-global:"]])("%s reached → no email, same 200", async (_l, key) => {
    refuse.add(key);
    const res = await call();
    expect(res.status).toBe(200);
    expect((await res.json()).ok).toBe(true);
    expect(sent).toHaveLength(0);
  });

  it("the link uses NEXT_PUBLIC_SITE_URL, not a forged Host", async () => {
    vi.stubEnv("NEXT_PUBLIC_SITE_URL", "https://www.hackthesoc.app");
    await call("evil.example");
    expect(sent[0].text).toContain("https://www.hackthesoc.app/update-password?token_hash=th");
    expect(sent[0].text).not.toContain("evil.example");
  });
});
