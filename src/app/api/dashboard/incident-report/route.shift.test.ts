// Stage B1 (dashboard review 2026-11): a signed-in report of a server-dealt training is graded against the
// answer the server kept in dashboard_shifts, never against what the browser sends, and only such a report
// is recorded or credited.
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ShiftRow } from "@/lib/dashboard/shiftStore";

const user = { id: "11111111-1111-4111-8111-111111111111", orgId: "22222222-2222-4222-8222-222222222222", email: null, role: "analyst" };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => user) }));
vi.mock("@/lib/ai/usage", () => ({ checkAiBudget: vi.fn(), recordAiUsage: vi.fn() }));
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => ({}) }));
const recordIncident = vi.fn(async () => true);
vi.mock("@/lib/progress/record", () => ({ recordIncident: (...a: unknown[]) => recordIncident(...(a as [])), isMissingSchema: () => false }));
let shift: ShiftRow | null = null;
const saveStories = vi.fn(async () => {});
vi.mock("@/lib/dashboard/shiftStore", () => ({
  loadShift: vi.fn(async () => shift),
  saveStories: (...a: unknown[]) => saveStories(...(a as [])),
}));
vi.stubEnv("ANTHROPIC_API_KEY", "");

const { POST } = await import("./route");

const SHIFT_ID = "33333333-3333-4333-8333-333333333333";
const past = new Date(Date.now() - 5 * 60_000).toISOString();
const truth = {
  storyId: "clickfix-fake-captcha",
  title: "Verify You Are Human: ClickFix Paste-and-Run",
  mitre: ["T1204.004", "T1059.001"],
  indicators: ["WS-SALES-1876", "a.kaplan@nexacorp.com", "185.222.58.14"],
  dealtAt: past, opensAt: past, bestScore: null, caughtAt: null,
};
const baseShift = (): ShiftRow => ({
  id: SHIFT_ID, user_id: user.id, org_id: user.orgId, company_id: "nexacorp", difficulty: "easy",
  stories: [{ ...truth }], started_at: past, ended_at: null, session_id: null,
});
const evidenceText = JSON.stringify([{ hostname: "WS-SALES-1876", user_email: "a.kaplan@nexacorp.com", raw: { "destination.ip": "185.222.58.14" } }, { src_ip: "203.0.113.9" }]);
const send = async (body: Record<string, unknown>) => {
  const res = await POST(new Request("https://x/api/dashboard/incident-report", {
    method: "POST", body: JSON.stringify({ company: "NexaCorp", evidenceText, shiftId: SHIFT_ID, storyId: truth.storyId, ...body }),
  }));
  return res.json() as Promise<{ score: number; passed: boolean; recorded?: boolean; noIncident?: boolean; feedback: string }>;
};
const GOOD = "ClickFix fake CAPTCHA: a.kaplan@nexacorp.com pasted a PowerShell command on WS-SALES-1876 (T1204.004) that called out to " +
  "185.222.58.14. Isolate WS-SALES-1876, block 185.222.58.14 and reset the password. Impact: stolen credentials, customer data risk.";

beforeEach(() => { shift = baseShift(); recordIncident.mockClear(); saveStories.mockClear(); });

describe("incident-report grader with a server training (Stage B1)", () => {
  it("grades against the server's answer: a forged answer in the request earns nothing", async () => {
    const forged = await send({
      attackTitle: "Made Up Attack", attackMitreTechniques: ["T1000"], realIndicators: ["6.6.6.6", "evil-host"],
      summary: "Made up attack seen from 6.6.6.6 on evil-host (T1000). Isolate evil-host and block 6.6.6.6. Impact: data at risk.",
    });
    expect(forged.passed).toBe(false);
  });

  it("a real investigation passes, is recorded under the server's title, and marks the story caught", async () => {
    const r = await send({ attackTitle: "anything", realIndicators: [], summary: GOOD });
    expect(r.passed).toBe(true);
    expect(r.recorded).toBe(true);
    const rec = (recordIncident.mock.calls[0] as unknown as [unknown, { title: string; mitre: string[]; outcome: string }])[1];
    expect(rec.title).toBe(truth.title);
    expect(rec.mitre).toEqual(truth.mitre);
    expect(rec.outcome).toBe("passed");
    const saved = (saveStories.mock.calls[0] as unknown as [unknown, string, { caughtAt: string | null; bestScore: number }[]])[2];
    expect(saved[0].caughtAt).not.toBeNull();
    expect(saved[0].bestScore).toBe(r.score);
  });

  it("before the attack can be on screen there is no incident to report, and nothing is recorded", async () => {
    shift = { ...baseShift(), stories: [{ ...truth, opensAt: new Date(Date.now() + 60_000).toISOString() }] };
    const early = await send({ summary: GOOD });
    expect(early.passed).toBe(false);
    expect(early.noIncident).toBe(true);
    const none = await send({ storyId: undefined, summary: GOOD });
    expect(none.noIncident).toBe(true);
    expect(recordIncident).not.toHaveBeenCalled();
  });

  it("a story the training never dealt is graded but never recorded or credited", async () => {
    const r = await send({ storyId: "kerberoasting", attackTitle: "Kerberoasting", realIndicators: ["WS-SALES-1876"], summary: GOOD });
    expect(r.recorded).toBe(false);
    expect(recordIncident).not.toHaveBeenCalled();
    expect(saveStories).not.toHaveBeenCalled();
  });

  it("an ended training records nothing", async () => {
    shift = { ...baseShift(), ended_at: new Date().toISOString() };
    const r = await send({ summary: GOOD });
    expect(r.recorded).toBe(false);
    expect(recordIncident).not.toHaveBeenCalled();
  });

  it("evidence and a response are not enough: the wrong attack never passes", async () => {
    const r = await send({ summary: "Kerberoasting of a service account from WS-SALES-1876 by a.kaplan@nexacorp.com to 185.222.58.14. Isolate WS-SALES-1876, block the IP, reset passwords. Impact: domain compromise and data risk." });
    expect(r.passed).toBe(false);
    expect(r.feedback).toMatch(/names the attack|doesn't match/);
  });

  it("a narratively titled story is identified by its kind of attack, not only by its title", async () => {
    shift = { ...baseShift(), stories: [{ ...truth, storyId: "web-inj-sqli-blind", title: "Catalog Searches That Took Five Seconds", mitre: ["T1190"] }] };
    const r = await send({ storyId: "web-inj-sqli-blind", summary: "Blind SQL injection (time-based SLEEP payloads) against the catalog from 185.222.58.14 on WS-SALES-1876. Block 185.222.58.14 at the WAF, patch the query. Impact: customer data exposure." });
    expect(r.passed).toBe(true);
  });
});
