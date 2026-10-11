import { describe, it, expect, vi, afterEach } from "vitest";
import { EMAIL_BATCH_MAX, isEmailConfigured, sendEmailBatch } from "./sendEmail";
import { planNotificationEmail } from "./templates";

// fetch is ALWAYS stubbed here — no request can reach the real provider.
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

const msg = (i: number) => ({ to: `u${i}@example.test`, subject: "s", html: "<p>h</p>", text: "t" });

describe("sendEmailBatch", () => {
  it("skips (no fetch) when no provider key is configured", async () => {
    vi.stubEnv("RESEND_API_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "info").mockImplementation(() => {});
    expect(isEmailConfigured()).toBe(false);
    const r = await sendEmailBatch([msg(1), msg(2)]);
    expect(r).toEqual({ skipped: true, sent: [false, false], errors: [] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the batch endpoint, ≤ 100 messages per call, one recipient per message, same From", async () => {
    vi.stubEnv("RESEND_API_KEY", "re_test_dummy");
    vi.stubEnv("EMAIL_FROM", "");
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ data: [] }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const inputs = Array.from({ length: EMAIL_BATCH_MAX + 1 }, (_, i) => msg(i));
    const r = await sendEmailBatch(inputs, { pauseMs: 0 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.resend.com/emails/batch");
    const body = JSON.parse(String(init.body));
    expect(body).toHaveLength(EMAIL_BATCH_MAX);
    expect(body[0]).toMatchObject({ from: "HACK THE SOC <noreply@hackthesoc.app>", to: ["u0@example.test"], subject: "s" });
    expect(JSON.parse(String((fetchMock.mock.calls[1] as unknown as [string, RequestInit])[1].body))).toHaveLength(1);
    expect(r.sent.every(Boolean)).toBe(true);
    expect(r.skipped).toBe(false);
  });

  it("a failed call marks only its messages unsent and the next chunk is still tried", async () => {
    vi.stubEnv("RESEND_API_KEY", "re_test_dummy");
    let n = 0;
    const fetchMock = vi.fn(async () => (n++ === 0 ? new Response("rate limited", { status: 429 }) : new Response("{}", { status: 200 })));
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const r = await sendEmailBatch(Array.from({ length: EMAIL_BATCH_MAX + 2 }, (_, i) => msg(i)), { pauseMs: 0 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(r.sent.filter(Boolean)).toHaveLength(2);
    expect(r.sent.slice(0, EMAIL_BATCH_MAX).some(Boolean)).toBe(false);
    expect(r.errors).toEqual(["HTTP 429"]);
  });

  it("a thrown fetch is reported, not thrown", async () => {
    vi.stubEnv("RESEND_API_KEY", "re_test_dummy");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("network down"); }));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const r = await sendEmailBatch([msg(1)]);
    expect(r).toEqual({ skipped: false, sent: [false], errors: ["network down"] });
  });
});

describe("planNotificationEmail", () => {
  it("fixed subjects — never the org admin's free text", () => {
    const evil = "Pay now: http://evil.example \r\nBcc: x@y";
    expect(planNotificationEmail({ kind: "plan_assigned", planTitle: evil, orgName: "Acme SOC", link: "https://x/learn" }).subject).toBe("New learning plan from Acme SOC");
    expect(planNotificationEmail({ kind: "plan_assigned", planTitle: evil, orgName: null, link: "https://x/learn" }).subject).toBe("You have a new learning plan");
    expect(planNotificationEmail({ kind: "plan_updated", planTitle: evil, link: "https://x/learn" }).subject).toBe("Your learning plan was updated");
    expect(planNotificationEmail({ kind: "personal_plan", planTitle: evil, link: "https://x/learn" }).subject).toBe("Your personal priorities were updated");
  });

  it("the plan title is escaped, single-line and clipped to 80 chars in the body", () => {
    const m = planNotificationEmail({ kind: "plan_assigned", planTitle: `<img src=x onerror=alert(1)>\n${"a".repeat(200)}`, orgName: "Acme", link: "https://x/learn" });
    expect(m.html).not.toContain("<img");
    expect(m.html).toContain("&lt;img");
    const shown = m.text.split("\n")[0];
    expect(shown).toContain("…");
    expect(shown.length).toBeLessThan(80 + 60);
  });
});

describe("redactEmails (SEC-18)", () => {
  it("masks every address in text bound for the logs", async () => {
    const { redactEmails } = await import("./sendEmail");
    expect(redactEmails(`{"message":"Invalid to: john.doe@college.ac.il, a@b.io"}`)).toBe(`{"message":"Invalid to: j***@college.ac.il, a***@b.io"}`);
    expect(redactEmails("no address here")).toBe("no address here");
  });
});

describe("sendEmail — timeout and one retry (QA phase 7, E-18)", () => {
  it("a 5xx is retried once with the same idempotency key; a 4xx is not", async () => {
    const { sendEmail } = await import("./sendEmail");
    vi.stubEnv("RESEND_API_KEY", "re_test");
    vi.spyOn(console, "error").mockImplementation(() => {});
    let n = 0;
    const fetchMock = vi.fn(async (_u: string, _i: RequestInit) => (n++ === 0 ? new Response("down", { status: 503, headers: { "retry-after": "0.01" } }) : new Response("{}", { status: 200 })));
    vi.stubGlobal("fetch", fetchMock);
    expect(await sendEmail(msg(1))).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const keyOf = (i: number) => (fetchMock.mock.calls[i][1].headers as Record<string, string>)["Idempotency-Key"];
    expect(keyOf(0)).toBeTruthy();
    expect(keyOf(1)).toBe(keyOf(0));
    expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);

    const bad = vi.fn(async () => new Response("invalid to", { status: 422 }));
    vi.stubGlobal("fetch", bad);
    expect(await sendEmail(msg(2))).toEqual({ ok: false, error: "HTTP 422" });
    expect(bad).toHaveBeenCalledTimes(1);
  });

  it("a timeout is reported in words, never thrown", async () => {
    const { sendEmail } = await import("./sendEmail");
    vi.stubEnv("RESEND_API_KEY", "re_test");
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => { throw Object.assign(new Error("aborted"), { name: "TimeoutError" }); }));
    const r = await sendEmail(msg(3));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/timed out/);
  });
});
