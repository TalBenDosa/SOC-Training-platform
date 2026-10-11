/**
 * Resending an unused invitation (ITSAFE case: the admin's 14-day link lapsed and
 * nobody ever registered). Same token kept; an expired / about-to-expire link is
 * renewed; used / generic invitations are refused with a clear reason.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/auth/apiGuard", () => ({ requireSuperAdmin: vi.fn(async () => ({ user: { id: "tal" } })) }));
vi.mock("@/lib/audit/logAudit", () => ({ logAudit: vi.fn(async () => {}) }));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));
const sent: { to: string; subject: string; text: string }[] = [];
vi.mock("@/lib/email/sendEmail", () => ({ sendEmail: vi.fn(async (m: { to: string; subject: string; text: string }) => { sent.push(m); return { ok: true }; }) }));
vi.mock("@/lib/org/classCode", () => ({ getActiveCode: vi.fn(async () => ({ code: "K7MRW3TQ" })) }));

const DAY = 86_400_000;
const state = {
  invite: null as null | Record<string, unknown>,
  updatedExpiry: null as string | null,
};
function builder(table: string) {
  const b: Record<string, unknown> = {};
  for (const m of ["select", "eq", "is", "in", "order", "limit"]) b[m] = () => b;
  b.maybeSingle = async () => ({ data: table === "invitations" ? state.invite : { name: "ITSAFE" }, error: null });
  b.update = (row: { expires_at: string }) => { state.updatedExpiry = row.expires_at; return { eq: () => ({ is: async () => ({ error: null }) }) }; };
  return b;
}
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => ({ from: (t: string) => builder(t) }) }));

const { POST } = await import("./route");
const call = () => POST(new Request("https://www.hackthesoc.app/api/superadmin/orgs/org1/invites/inv1/resend", { method: "POST" }),
  { params: Promise.resolve({ id: "org1", inviteId: "inv1" }) });

beforeEach(() => { sent.length = 0; state.updatedExpiry = null; });

describe("POST /api/superadmin/orgs/[id]/invites/[inviteId]/resend", () => {
  it("renews an EXPIRED admin invitation (same token) and resends the welcome email with the live class code", async () => {
    state.invite = { id: "inv1", org_id: "org1", email: "head@itsafe.co.il", role: "org_admin", token: "tok-123", expires_at: new Date(Date.now() - 20 * DAY).toISOString(), accepted_at: null };
    const res = await call();
    const d = await res.json();
    expect(res.status).toBe(200);
    expect(d).toMatchObject({ ok: true, renewed: true, email_status: "sent", email: "head@itsafe.co.il", link: "https://www.hackthesoc.app/join?token=tok-123" });
    expect(Date.parse(state.updatedExpiry!)).toBeGreaterThan(Date.now() + 13 * DAY);
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe("head@itsafe.co.il");
    expect(sent[0].text).toContain("/join?token=tok-123");
    expect(sent[0].text).toContain("K7MRW3TQ");
  });

  it("keeps the expiry of an invitation that still has time left", async () => {
    state.invite = { id: "inv1", org_id: "org1", email: "head@itsafe.co.il", role: "org_admin", token: "tok-123", expires_at: new Date(Date.now() + 10 * DAY).toISOString(), accepted_at: null };
    const d = await (await call()).json();
    expect(d.renewed).toBe(false);
    expect(state.updatedExpiry).toBeNull();
    expect(sent).toHaveLength(1);
  });

  it("refuses an invitation that was already used — the person has an account", async () => {
    state.invite = { id: "inv1", org_id: "org1", email: "head@itsafe.co.il", role: "org_admin", token: "t", expires_at: new Date().toISOString(), accepted_at: new Date().toISOString() };
    const res = await call();
    expect(res.status).toBe(409);
    expect(sent).toHaveLength(0);
  });

  it("refuses a generic link with no recipient", async () => {
    state.invite = { id: "inv1", org_id: "org1", email: null, role: "instructor", token: "t", expires_at: new Date().toISOString(), accepted_at: null };
    expect((await call()).status).toBe(400);
    expect(sent).toHaveLength(0);
  });

  it("404 for an invitation that isn't in this organization", async () => {
    state.invite = null;
    expect((await call()).status).toBe(404);
  });
});
