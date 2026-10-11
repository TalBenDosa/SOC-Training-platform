// SEC-14: every value interpolated into an HTML email is escaped — once.
import { describe, it, expect } from "vitest";
import { lapsedNudgeEmail, accountAccessEmail, orgWelcomeEmail, planNotificationEmail, studentInviteEmail } from "./templates";

const EVIL = `<a href="https://evil.example">Verify</a>`;

describe("email templates escape user / admin text", () => {
  it("a display name and room title can't inject a link into the nudge email", () => {
    const m = lapsedNudgeEmail({ name: EVIL, daysAway: 9, nextRoomTitle: `<img src=x onerror=alert(1)>`, nextRoomMinutes: 10, resumeLink: "https://www.hackthesoc.app/rooms" } as Parameters<typeof lapsedNudgeEmail>[0]);
    expect(m.html).not.toContain('<a href="https://evil.example">');
    expect(m.html).not.toContain("<img src=x");
    expect(m.html).toContain("&lt;a href=&quot;https://evil.example&quot;&gt;");
  });

  it.each([
    ["accountAccessEmail", () => accountAccessEmail({ orgName: EVIL, link: "https://www.hackthesoc.app/update-password?token_hash=a&type=recovery" })],
    ["orgWelcomeEmail", () => orgWelcomeEmail({ orgName: EVIL, adminLink: "https://www.hackthesoc.app/join?token=t", classCode: "K7MRW3TQ" })],
    ["studentInviteEmail", () => studentInviteEmail({ orgName: EVIL, joinLink: "https://www.hackthesoc.app/join?token=t" })],
  ])("%s escapes the org name", (_n, make) => {
    expect(make().html).not.toContain('<a href="https://evil.example">');
  });

  it("links keep working: & in a URL is escaped once in href (valid HTML), the text version is raw", () => {
    const m = accountAccessEmail({ orgName: "College", link: "https://www.hackthesoc.app/update-password?token_hash=a&type=recovery" });
    expect(m.html).toContain('href="https://www.hackthesoc.app/update-password?token_hash=a&amp;type=recovery"');
    expect(m.html).not.toContain("&amp;amp;");
    expect(m.text).toContain("token_hash=a&type=recovery");
  });

  it("the plan email is not double-escaped", () => {
    const m = planNotificationEmail({ kind: "plan_assigned", planTitle: "R&D <basics>", orgName: "A&B College", link: "https://www.hackthesoc.app/plans?x=1&y=2" });
    expect(m.html).toContain("R&amp;D &lt;basics&gt;");
    expect(m.html).not.toContain("&amp;amp;");
    expect(m.html).toContain("New learning plan from A&amp;B College");
  });
});
