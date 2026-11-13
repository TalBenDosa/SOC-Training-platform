import { describe, expect, it } from "vitest";
import { bookingUrl, demoRecipients, demoRequestEmail, validateDemoRequest } from "./demoRequest";

const good = {
  name: "Dana Levi", email: "Dana.Levi@College.example", organization: "Example College", role: "Head of Cyber Studies",
  orgType: "college", teamSize: "51-200", availability: "Sun to Thu mornings", message: "We run two SOC cohorts a year.", consent: true,
};

describe("demo request", () => {
  it("accepts a complete request and normalises the address", () => {
    const r = validateDemoRequest(good);
    expect(r.ok).toBe(true);
    if (r.ok) { expect(r.value.email).toBe("dana.levi@college.example"); expect(r.bot).toBe(false); }
  });

  it("names the field that is missing or wrong", () => {
    for (const [patch, field] of [[{ name: "" }, "name"], [{ email: "not-an-email" }, "email"], [{ organization: " " }, "organization"],
      [{ orgType: "hacker" }, "orgType"], [{ teamSize: "9999" }, "teamSize"], [{ consent: false }, "consent"]] as const) {
      const r = validateDemoRequest({ ...good, ...patch });
      expect(r.ok, JSON.stringify(patch)).toBe(false);
      if (!r.ok) expect(r.field).toBe(field);
    }
  });

  it("caps lengths and strips line breaks from single-line fields (no header injection)", () => {
    const r = validateDemoRequest({ ...good, organization: "Evil\r\nBcc: victim@x.example" + "x".repeat(500), name: "A".repeat(400) });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.organization).not.toMatch(/[\r\n]/);
    expect(r.value.organization.length).toBeLessThanOrEqual(120);
    expect(r.value.name.length).toBeLessThanOrEqual(100);
    expect(demoRequestEmail(r.value, new Date()).subject).not.toMatch(/[\r\n]/);
  });

  it("flags a filled honeypot as a bot", () => {
    const r = validateDemoRequest({ ...good, website: "http://spam.example" });
    expect(r.ok && r.bot).toBe(true);
  });

  it("escapes every value in the email", () => {
    const r = validateDemoRequest({ ...good, name: "<script>alert(1)</script>", message: "<img src=x onerror=alert(1)>" });
    if (!r.ok) throw new Error("expected ok");
    const { html } = demoRequestEmail(r.value, new Date("2026-11-13T10:00:00Z"));
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
  });

  it("reads recipients and the booking link from the environment safely", () => {
    expect(demoRecipients(" a@x.example, bad, b@y.example ")).toEqual(["a@x.example", "b@y.example"]);
    expect(demoRecipients(undefined)).toEqual([]);
    expect(bookingUrl("https://cal.example/hackthesoc")).toBe("https://cal.example/hackthesoc");
    expect(bookingUrl("http://cal.example")).toBeNull();
    expect(bookingUrl("javascript:alert(1)")).toBeNull();
    expect(bookingUrl("")).toBeNull();
  });
});
