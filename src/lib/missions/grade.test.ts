// The help ladder and the normalisers, on room 36's first mission (dataset "clear-sky").
import { describe, it, expect } from "vitest";
import { gradeMissionStep } from "./grade";
import { normalizeAs, parseNumber, parseUtc, refang, defang, detectIocType } from "./normalize";
import { CLEAR_SKY_M1, CLEAR_SKY_M2, CLEAR_SKY_M4 } from "./rooms/clearSky";

const right = { query: "AuditLogs | where OperationName == \"Update conditional access policy\" | summarize n = count() by A = tostring(InitiatedBy.user.userPrincipalName)" };
const wrong = { query: "AuditLogs | where OperationName has \"conditional access\" | distinct tostring(InitiatedBy.user.userPrincipalName)" };

describe("help ladder", () => {
  it("full XP on a first-try pass, 60% after the second hint", () => {
    const a = gradeMissionStep(CLEAR_SKY_M1, 0, right, 1, 0);
    const b = gradeMissionStep(CLEAR_SKY_M1, 0, right, 1, 2);
    expect(a.ok && a.correct && a.xpEarned).toBe(20);
    expect(b.ok && b.correct && b.xpEarned).toBe(12);
  });

  it("no worked answer before the third miss; the third miss releases it", () => {
    const m2 = gradeMissionStep(CLEAR_SKY_M1, 0, wrong, 2, 0);
    const m3 = gradeMissionStep(CLEAR_SKY_M1, 0, wrong, 3, 0);
    expect(m2.ok && m2.correct).toBe(false);
    expect(m2.ok && m2.reveal.worked).toBeUndefined();
    expect(m3.ok && typeof m3.reveal.worked).toBe("string");
  });

  it("a pass after the worked answer completes the step for 0 XP", () => {
    const g = gradeMissionStep(CLEAR_SKY_M1, 0, right, 4, 0);
    expect(g.ok && g.correct).toBe(true);
    expect(g.ok && g.xpEarned).toBe(0);
  });

  it("a query that does not run is an error, not a check", () => {
    const g = gradeMissionStep(CLEAR_SKY_M1, 0, { query: "AuditLogs | wher x == 1" }, 1, 0);
    expect(g.ok).toBe(false);
  });

  it("the wrong table fails with the engine's own error", () => {
    const g = gradeMissionStep(CLEAR_SKY_M1, 0, { query: "SigninLogs | where OperationName == \"x\"" }, 1, 0);
    expect(g.ok).toBe(false);
  });

  it("a KQL miss coaches from the learner's own result", () => {
    const g = gradeMissionStep(CLEAR_SKY_M2, 0, { query: "SigninLogs | summarize c = dcount(Location) by UserPrincipalName | where c >= 3" }, 1, 0);
    expect(g.ok && g.correct).toBe(false);
    expect(g.ok && (g.reveal.feedback as string[]).join(" ")).toMatch(/failed sign-ins|time window/);
  });

  it("fields: accepted spellings pass, a trap value gets its own coaching", () => {
    const ok = gradeMissionStep(CLEAR_SKY_M4, 0, { values: { ok: "No", why: "Wrong username or password", mfa: "No", protocol: "activesync", ca: "No, none applied" } }, 1, 0);
    expect(ok.ok && ok.correct).toBe(true);
    const trap = gradeMissionStep(CLEAR_SKY_M2, 1, { values: { account: "r.ansah@ashgrove.example", column: "Location" } }, 1, 0);
    expect(trap.ok && trap.correct).toBe(false);
    const per = trap.ok ? trap.reveal.fields as { id: string; say?: string }[] : [];
    expect(per.find(p => p.id === "account")?.say).toMatch(/one device with MFA/);
  });
});

describe("normalisers", () => {
  it("refangs and defangs", () => {
    expect(refang("hxxps://probate-registry-uk[.]example/case")).toBe("https://probate-registry-uk.example/case");
    expect(defang("url", "https://a.b.example/x")).toBe("hxxps://a[.]b[.]example/x");
    expect(normalizeAs("ip", "198.51.100[.]77")).toBe("198.51.100.77");
    expect(normalizeAs("email", "<Notice@Example.example>")).toBe("notice@example.example");
  });
  it("numbers with units and times in many spellings", () => {
    expect(parseNumber("1,400")).toBe(1400);
    expect(parseNumber("1.4 GB")).toBe(1.4e9);
    expect(parseUtc("08:52 UTC")).toEqual({ kind: "time", minutes: 532 });
    expect(parseUtc("2026-04-14T08:52:31Z")?.kind).toBe("datetime");
  });
  it("detects indicator types", () => {
    expect(detectIocType("fb8b41abdba095f5eb99ca714a7c22a0e1e14737915d0d7f95884fe31544c474")).toBe("sha256");
    expect(detectIocType("hxxps://x[.]example/a")).toBe("url");
    expect(detectIocType("Estate_Notice_8841.html")).toBe("filename");
    expect(detectIocType("probate-registry-uk.example")).toBe("domain");
    expect(detectIocType("198.51.100.77")).toBe("ip");
  });
});
