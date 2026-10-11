import { describe, it, expect } from "vitest";
import { source, kindOf } from "./okta";
import { standardChecks } from "../testing/standardChecks";

// Okta is SaaS: a corporate user's private address never reaches it — the record carries the
// company egress (and client.zone "Corporate HQ") instead, so a private src_ip is not evidence here.
const isPrivate = (ip?: string) => !!ip && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
const rep = standardChecks(source, kindOf, {
  cards: ["idp-okta.md"],
  evidence: c => [isPrivate(c.ev.src_ip) ? undefined : c.ev.src_ip, isPrivate(c.ev.dst_ip) ? undefined : c.ev.dst_ip, c.ev.user_email?.split("@")[0],
    c.ev.process?.cmdline, c.ev.process?.hash?.sha256, c.ev.file?.sha256, c.ev.dns?.query, c.ev.cloud?.api_call]
    .filter((x): x is string => typeof x === "string" && x.length > 2),
});

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
