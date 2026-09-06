import { describe, it, expect } from "vitest";
import { analyseIndicators } from "./indicatorAnalysis";

// Regression coverage for the incident-report fabrication check. The headline
// case is the trust-breaker a real trainee reported: they correctly cited a hash
// from a CrowdStrike event and still got "fabricated evidence" — because the host
// extractor's OPTIONAL separator turned the ordinary phrase "isolate the host and
// reset…" into a claimed hostname "and", which isn't in the logs.
const HASH = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77";
const evidence = JSON.stringify([
  { id: "qb_cs_003", vendor: "CrowdStrike Falcon", file: { sha256: HASH }, raw: { "threat.name": "CobaltStrike.beacon.reflective" } },
  { id: "h", hostname: "WS-FIN-3041", src_ip: "203.0.113.9" },
]);
const real = [HASH, "203.0.113.9", "WS-FIN-3041"];

describe("analyseIndicators — fabrication check", () => {
  it("does NOT flag ordinary prose using the word 'host' ('isolate the host and reset')", () => {
    const r = analyseIndicators(
      `CobaltStrike beacon detected. Hash ${HASH}. Isolate the host and reset credentials.`,
      real, evidence,
    );
    expect(r.fabricated).toEqual([]);
    expect(r.cited).toContain(HASH);
  });

  it("does NOT flag 'the host was compromised'", () => {
    const r = analyseIndicators("The host was compromised via a beacon from 203.0.113.9.", real, evidence);
    expect(r.fabricated).toEqual([]);
  });

  it("recognises a real host cited as 'host WS-FIN-3041' (host-shaped, in evidence)", () => {
    const r = analyseIndicators("Beacon on host WS-FIN-3041 from 203.0.113.9.", real, evidence);
    expect(r.fabricated).toEqual([]);
    expect(r.cited).toContain("WS-FIN-3041");
  });

  it("treats a hash cited from the feed as real even when it's not in the discrete indicator list", () => {
    // R-02: evidenceText is the whole feed; a value visible in any log is real.
    const r = analyseIndicators(`The dropped binary hash was ${HASH}.`, ["203.0.113.9"], evidence);
    expect(r.fabricated).toEqual([]);
  });

  it("STILL flags a genuinely invented host via explicit separator ('host: koko')", () => {
    const r = analyseIndicators("Attack traced to host: koko internally.", real, evidence);
    expect(r.fabricated).toContain("koko");
  });

  it("STILL flags an invented IP that appears nowhere in the evidence", () => {
    const r = analyseIndicators("Beacon traffic seen from 8.8.4.4 to the endpoint.", real, evidence);
    expect(r.fabricated).toContain("8.8.4.4");
  });

  it("ignores 2-3 char noise tokens (never reported as fabricated)", () => {
    const r = analyseIndicators("The C2 and the DNS were suspicious.", real, evidence);
    expect(r.fabricated).toEqual([]);
  });
});
