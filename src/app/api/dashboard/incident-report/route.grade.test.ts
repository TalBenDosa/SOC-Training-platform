// QA 2026-10-17 (QA-DASH-1/2/3): the deterministic incident-report grader (the only
// grader in production, which has no AI key) passed keyword-stuffed, wrong-attack,
// evidence-free reports, and its failure feedback named the attack and the victim.
import { describe, it, expect, vi } from "vitest";

vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => null) }));
vi.mock("@/lib/ai/usage", () => ({ checkAiBudget: vi.fn(), recordAiUsage: vi.fn() }));
vi.stubEnv("ANTHROPIC_API_KEY", "");

const { POST } = await import("./route");

const story = {
  company: "NexaCorp",
  attackTitle: "Fake CAPTCHA (ClickFix) to PowerShell Infostealer",
  attackMitreTechniques: ["T1204.004", "T1059.001", "T1555.003"],
  realIndicators: ["WS-SALES-1876", "a.kaplan@nexacorp.com", "185.222.58.14", "explorer.exe"],
  evidenceText: JSON.stringify([
    { hostname: "WS-SALES-1876", user_email: "a.kaplan@nexacorp.com", raw: { "process.parent.name": "explorer.exe", "destination.ip": "185.222.58.14" } },
    { hostname: "WS-SALES-1876", src_ip: "10.0.0.15" },
  ]),
};
const grade = async (summary: string) => {
  const res = await POST(new Request("https://x/api/dashboard/incident-report", { method: "POST", body: JSON.stringify({ ...story, summary }) }));
  return res.json() as Promise<{ score: number; passed: boolean; feedback: string; gaps: string[] }>;
};

describe("incident-report grader", () => {
  it("fails a wrong-attack report with no evidence even when it says MITRE and 'laptop'", async () => {
    for (const s of [
      "Kerberos golden ticket on the laptop, per MITRE. Isolate it, data at risk.",
      "Something odd happened on a laptop per MITRE ATT&CK. Isolate it; data at risk.",
    ]) expect((await grade(s)).passed, s).toBe(false);
  });

  it("everyday process names are not evidence", async () => {
    const r = await grade("explorer.exe chrome.exe launched something. Isolate the machine. Data risk.");
    expect(r.passed).toBe(false);
  });

  it("guided-form labels do not earn the impact or action points by themselves", async () => {
    const labelsOnly = await grade("What happened: odd\nEvidence (IOCs): none\nRecommended action: tbd\nBusiness impact: tbd");
    expect(labelsOnly.passed).toBe(false);
    expect(labelsOnly.score).toBeLessThan(30);
  });

  it("an IP must match as a whole value: 10.0.0.1 is not 10.0.0.15", async () => {
    const r = await grade("ClickFix infostealer: powershell beacon to 10.0.0.1. Isolate WS-FIN-0000, revoke tokens, credential theft risk.");
    expect(r.passed).toBe(false);
  });

  it("failure feedback never names the attack or the real indicators", async () => {
    const r = await grade("odd thing on a laptop");
    const text = [r.feedback, ...r.gaps].join(" ");
    expect(text).not.toContain("ClickFix");
    expect(text).not.toContain("WS-SALES-1876");
    expect(text).not.toContain("a.kaplan");
  });

  it("a real investigation still passes", async () => {
    const r = await grade(
      "ClickFix fake CAPTCHA: a.kaplan@nexacorp.com pasted a PowerShell command on WS-SALES-1876 (T1204.004, T1059.001), " +
      "an infostealer then sent browser credentials to 185.222.58.14. Isolate WS-SALES-1876, block 185.222.58.14, reset a.kaplan's " +
      "password and revoke sessions. Impact: stolen credentials and customer data risk.",
    );
    expect(r.passed).toBe(true);
  });
});
