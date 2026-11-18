import { describe, it, expect } from "vitest";
import { isEnglishOnly } from "./reportLanguage";

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
  it("blocks other non-English scripts and accented letters", () => {
    expect(isEnglishOnly("атака на пользователя")).toBe(false);
    expect(isEnglishOnly("هجوم")).toBe(false);
    expect(isEnglishOnly("café")).toBe(false);
  });
});
