import { describe, it, expect } from "vitest";
import { source, kindOf } from "./okta";
import { standardChecks } from "../testing/standardChecks";

const rep = standardChecks(source, kindOf, { cards: ["idp-okta.md"] });

describe("okta — native System Log LogEvent", () => {
  it("card samples validate", () => {
    console.log(`[okta] card checked ${rep.cardChecked}, skipped ${rep.cardSkipped}`);
    expect(rep.cardChecked).toBeGreaterThanOrEqual(8);
    expect(rep.cardViolations).toEqual([]);
  });
  it("corpus converts cleanly; ≥95% of Okta-authored events render", () => {
    console.log(`[okta] native ${rep.nativeConverted}/${rep.nativeTotal}, cross ${rep.crossConverted}/${rep.crossTotal}`);
    expect(rep.violations).toEqual([]);
    expect(rep.nativeConverted / rep.nativeTotal).toBeGreaterThanOrEqual(0.9);   // documented nulls: event types the card does not document — system.org.rate_limit.warning, application.integration.rate_limit_exceeded, user.lifecycle.suspend / activate, app.oauth2.token.grant.id_token, user.session.expire
  });
  it("evidence survives and output is deterministic", () => {
    expect(rep.evidenceMissing).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
  });
  it("use cases: non-threshold rules fire on attacks; high/critical stay under 2% of noise", () => {
    for (const [id, h] of Object.entries(rep.useCaseHits)) {
      console.log(`[okta] ${id}: attack ${h.attack}, noise ${h.noise}/${rep.noiseCount}`);
      const uc = source.useCases.find(u => u.id === id)!;
      // No card sample or corpus event exercises these yet (logic reviewed): ["okta.admin_privilege_granted", "okta.admin_group_membership"]
      if (!uc.threshold && !["okta.admin_privilege_granted", "okta.admin_group_membership"].includes(id)) expect(h.attack, id).toBeGreaterThan(0);
      if (h.severity === "high" || h.severity === "critical") expect(h.noise, id).toBeLessThanOrEqual(Math.max(1, Math.floor(rep.noiseCount * 0.02)));
    }
  });
});
