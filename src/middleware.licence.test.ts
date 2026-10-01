/**
 * SEC-04: a college whose licence lapsed was locked out of PAGES only — its
 * members kept the whole API with their session cookie. The API gate now refuses
 * them too, except their own account routes and accepting an invitation.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/supabase/config", () => ({ supabaseUrl: "https://x.supabase.co", supabaseAnonKey: "anon", isSupabaseConfigured: true }));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));
vi.mock("@/lib/supabase/middleware", () => ({ refreshSupabaseSession: vi.fn() }));
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
let claims: Record<string, unknown> = {};
vi.mock("@supabase/ssr", () => ({
  createServerClient: () => ({
    auth: {
      getUser: async () => ({ data: { user: { id: "u1" } } }),
      getSession: async () => ({ data: { session: { access_token: `h.${b64(claims)}.s` } } }),
    },
  }),
}));

const { middleware } = await import("./middleware");
const hit = (path: string, method = "GET") => middleware(new NextRequest(`https://www.hackthesoc.app${path}`, { method }));

beforeEach(() => { claims = { org_id: "org1", org_role: "org_admin", org_active: false, is_platform_admin: false }; });

describe("API licence gate", () => {
  it.each(["/api/org/members", "/api/org/class-code", "/api/team/sessions", "/api/rooms/x/complete"])("refuses %s for a lapsed college", async p => {
    const res = await hit(p);
    expect(res.status).toBe(403);
    expect((await res.json()).error).toMatch(/licence/);
  });

  it.each(["/api/account", "/api/account/join-environment", "/api/account/renew-affiliation", "/api/notifications"])("still allows %s", async p => {
    expect((await hit(p)).status).toBe(200);
  });

  it("does not over-match a prefix (/api/accounting is not /api/account)", async () => {
    expect((await hit("/api/accounting")).status).toBe(403);
  });

  it("an active college and the platform admin pass", async () => {
    claims.org_active = true;
    expect((await hit("/api/org/members")).status).toBe(200);
    claims = { ...claims, org_active: false, is_platform_admin: true };
    expect((await hit("/api/org/members")).status).toBe(200);
  });

  it("no claim (null) never locks", async () => {
    claims = { org_id: "org1" };
    expect((await hit("/api/org/members")).status).toBe(200);
  });
});
