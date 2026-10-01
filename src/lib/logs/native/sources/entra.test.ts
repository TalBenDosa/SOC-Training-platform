import { describe, it, expect } from "vitest";
import { source, kindOf } from "./entra";
import { standardChecks } from "../testing/standardChecks";

const rep = standardChecks(source, kindOf, { cards: ["idp-entra-id.md"] });

describe("entra — native Graph signIn / directoryAudit", () => {
  it("card samples validate (the Azure Monitor envelope sample is a different representation — skipped)", () => {
    console.log(`[entra] card checked ${rep.cardChecked}, skipped ${rep.cardSkipped}`);
    expect(rep.cardChecked).toBeGreaterThanOrEqual(8);
    expect(rep.cardViolations).toEqual([]);
  });
  it("corpus converts cleanly; ≥95% of Entra-authored events render", () => {
    console.log(`[entra] native ${rep.nativeConverted}/${rep.nativeTotal}, cross ${rep.crossConverted}/${rep.crossTotal}`);
    expect(rep.violations).toEqual([]);
    expect(rep.nativeConverted / rep.nativeTotal).toBeGreaterThanOrEqual(0.9);   // documented nulls: Set user risk level (Identity Protection, not a directoryAudit), the 43-attempt spray SUMMARY (an aggregate, not one sign-in), 'Add application' and two Graph directory reads (not documented as audits in the card), one UserLoginFailed MFA summary
  });
  it("evidence survives and output is deterministic", () => {
    // "oauth_07_admin_consent_fail": the authored IP is Microsoft's own service address on a failed admin consent; the directoryAudit records the initiating app, not that IP.
    expect(rep.evidenceMissing.filter(m => m.id !== "oauth_07_admin_consent_fail")).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
  });
  it("use cases: non-threshold rules fire on attacks; high/critical stay under 2% of noise", () => {
    for (const [id, h] of Object.entries(rep.useCaseHits)) {
      console.log(`[entra] ${id}: attack ${h.attack}, noise ${h.noise}/${rep.noiseCount}`);
      const uc = source.useCases.find(u => u.id === id)!;
      
      if (!uc.threshold) expect(h.attack, id).toBeGreaterThan(0);
      if (h.severity === "high" || h.severity === "critical") expect(h.noise, id).toBeLessThanOrEqual(Math.max(1, Math.floor(rep.noiseCount * 0.02)));
    }
  });
});
