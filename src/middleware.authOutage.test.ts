// QA phase 7, E-05: an auth-service failure is a 503 (retry), never "signed out".
import { describe, it, expect, vi } from "vitest";
import { NextRequest } from "next/server";
import { isAuthOutage } from "@/lib/auth/authOutage";

vi.mock("@/lib/supabase/config", () => ({ supabaseUrl: "https://x.supabase.co", supabaseAnonKey: "anon", isSupabaseConfigured: true }));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));
vi.mock("@/lib/supabase/middleware", () => ({ refreshSupabaseSession: vi.fn() }));
let result: { data: { user: null | { id: string } }; error: unknown } = { data: { user: null }, error: null };
vi.mock("@supabase/ssr", () => ({
  createServerClient: () => ({ auth: { getUser: async () => result, getSession: async () => ({ data: { session: null } }) } }),
}));
const { middleware } = await import("./middleware");
const hit = () => middleware(new NextRequest("https://www.hackthesoc.app/api/org/members"));

describe("auth outage", () => {
  it.each([
    [{ name: "AuthRetryableFetchError", status: 0 }, true],
    [{ name: "AuthApiError", status: 503 }, true],
    [{ name: "AuthSessionMissingError", status: 400 }, false],
    [null, false],
  ])("isAuthOutage(%j) = %s", (err, out) => expect(isAuthOutage(err)).toBe(out));

  it("Supabase Auth unreachable → 503 with Retry-After, not 401", async () => {
    result = { data: { user: null }, error: { name: "AuthRetryableFetchError", status: 0 } };
    const res = await hit();
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBeTruthy();
  });

  it("no session (a real sign-out) is still 401", async () => {
    result = { data: { user: null }, error: { name: "AuthSessionMissingError", status: 400 } };
    expect((await hit()).status).toBe(401);
  });
});
