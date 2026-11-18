import { describe, it, expect } from "vitest";
import { isEnglishOnly, payloadHasNonEnglish } from "./reportLanguage";

describe("incident reports are English only", () => {
  it("accepts English with IOCs, punctuation and symbols", () => {
    expect(isEnglishOnly("Password spray from 91.108.4.154 -> r.patel@nexacorp.com (T1110.003); block it, reset creds. Impact: 40% of FIN-* hosts – “data” risk → escalate.")).toBe(true);
    expect(isEnglishOnly("")).toBe(true);
  });
  it("blocks Hebrew, even a single word inside English", () => {
    expect(isEnglishOnly("מתקפת פישינג נגד d.cohen@nexacorp.com")).toBe(false);
    expect(isEnglishOnly("Phishing against the user, לחסום the IP 1.2.3.4")).toBe(false);
    expect(isEnglishOnly("דגכשדגכדגכ שדגשדגש")).toBe(false);
  });
  it("team actions: written work is English only; chat, instructor injects and telemetry stay free", () => {
    expect(payloadHasNonEnglish("report.submitted", { summary: "Phishing on WS-1", fields: { impact: "דליפת מידע" } })).toBe(true);
    expect(payloadHasNonEnglish("hunt.logged", { hypothesis: "tasks", queries: [{ q: "schtasks", rows: 0 }, { q: "משימה", rows: 0 }] })).toBe(true);
    expect(payloadHasNonEnglish("hunt.logged", { hypothesis: "Scheduled tasks on workstations", queries: [{ q: "schtasks", rows: 2 }] })).toBe(false);
    expect(payloadHasNonEnglish("message.sent", { text: "מישהו בודק את WS-2?" })).toBe(false);
    expect(payloadHasNonEnglish("staff.inject", { text: "עדכון מהמנהל" })).toBe(false);
    expect(payloadHasNonEnglish("case.assigned", { owner: "3f2c-uuid" })).toBe(false);
  });

  it("blocks other non-English scripts and accented letters", () => {
    expect(isEnglishOnly("атака на пользователя")).toBe(false);
    expect(isEnglishOnly("هجوم")).toBe(false);
    expect(isEnglishOnly("café")).toBe(false);
  });
});
