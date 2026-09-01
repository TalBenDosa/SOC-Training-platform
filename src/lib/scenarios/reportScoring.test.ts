import { describe, it, expect } from "vitest";
import { collectLeafValues, scoreScenarioReport } from "./reportScoring";

// A representative incident: one internal IP and an email live ONLY inside event
// values (not in the curated IOC list); a description carries ordinary prose.
const EVENTS = [
  {
    id: "e1",
    source: "okta",
    hostname: "FIN-WS-11",
    user_email: "alice@corp.com",
    description: "the backup agent logon from the workstation",
    raw: { src_ip: "10.20.14.31", ActionType: "UserLogin" },
  },
];

const words = (n: number) => Array.from({ length: n }, (_, i) => `alpha${i}`).join(" ");
const reason25 = words(25); // ≥25 words → reasoning tier 20
const notes160 = words(160); // long narrative → depth tier 25

function score(overrides: Partial<Parameters<typeof scoreScenarioReport>[0]>) {
  return scoreScenarioReport({
    verdict: "tp",
    verdictReason: reason25,
    analystNotes: notes160,
    indicators: [],
    iocs: [{ value: "185.220.101.9" }], // curated key IOC, NOT present in EVENTS
    events: EVENTS,
    attackKind: "malicious",
    ...overrides,
  });
}

describe("collectLeafValues", () => {
  it("returns leaf VALUES, never object keys", () => {
    const vals = collectLeafValues(EVENTS);
    expect(vals).toContain("FIN-WS-11");
    expect(vals).toContain("10.20.14.31");
    expect(vals).toContain("alice@corp.com");
    // Field NAMES must never appear — this is the whole point of the walk.
    expect(vals).not.toContain("hostname");
    expect(vals).not.toContain("src_ip");
    expect(vals).not.toContain("description");
    expect(vals).not.toContain("raw");
  });
});

describe("scoreScenarioReport — IOC evidence exploit guards", () => {
  it("stopwords tagged as indicators earn ZERO evidence", () => {
    const r = score({ indicators: ["the", "and", "for", "log", "com"].map(v => ({ value: v })) });
    expect(r.usefulCitedCount).toBe(0);
    expect(r.reportRubric.evidence).toBe(0);
  });

  it("object FIELD NAMES tagged as indicators earn ZERO evidence", () => {
    // The original bug: JSON.stringify(events) let "hostname"/"description" match.
    const r = score({ indicators: ["hostname", "description", "actiontype", "vendor"].map(v => ({ value: v })) });
    expect(r.usefulCitedCount).toBe(0);
    expect(r.reportRubric.evidence).toBe(0);
  });

  it("a genuine non-curated indicator pulled from telemetry earns FULL evidence", () => {
    // 10.20.14.31 is only in an event's raw block, not in the curated iocs list.
    const r = score({ indicators: [{ value: "10.20.14.31" }] });
    expect(r.usefulCitedCount).toBe(1);
    expect(r.reportRubric.evidence).toBe(30);
    // ...but it is NOT a curated key indicator, so the honest "X/Y key" counter stays 0.
    expect(r.iocsCited).toBe(0);
  });

  it("citing a fabricated indicator caps evidence at 5", () => {
    const r = score({
      indicators: [{ value: "10.20.14.31" }], // one real indicator surfaced
      analystNotes: `${notes160} exfil to 6.6.6.6`, // 6.6.6.6 appears nowhere real
    });
    expect(r.fabricated).toContain("6.6.6.6");
    expect(r.reportRubric.evidence).toBe(5);
  });
});

describe("scoreScenarioReport — rubric & verdict mapping", () => {
  it("a thorough correct report scores ~100 and passes", () => {
    const r = score({
      indicators: [{ value: "10.20.14.31" }, { value: "alice@corp.com" }],
      iocs: [{ value: "10.20.14.31" }, { value: "alice@corp.com" }],
    });
    expect(r.verdictCorrect).toBe(true);
    expect(r.reportRubric).toEqual({ verdict: 25, depth: 25, evidence: 30, reasoning: 20 });
    expect(r.reportScore).toBe(100);
  });

  it("maps a false_positive scenario's 'fp' call to benign correctly", () => {
    const correct = score({ attackKind: "false_positive", verdict: "fp" });
    expect(correct.expectedVerdict).toBe("benign");
    expect(correct.verdictCorrect).toBe(true);
    expect(correct.reportRubric.verdict).toBe(25);

    const wrong = score({ attackKind: "false_positive", verdict: "tp" });
    expect(wrong.verdictCorrect).toBe(false);
    expect(wrong.reportRubric.verdict).toBe(5);
  });

  it("no verdict submitted scores 0 on the verdict tier", () => {
    const r = score({ verdict: null });
    expect(r.reportRubric.verdict).toBe(0);
  });
});
