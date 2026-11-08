import { describe, expect, it } from "vitest";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";

// The adaptation gate (scripts/verify-l03-adaptation.mjs) accepts a company's registered
// infrastructure as its own. This keeps that list honest: no company may register a machine
// that names another company, and no machine is registered to two companies.
describe("COMPANY_ASSETS infra registry", () => {
  const ids = Object.keys(COMPANY_ASSETS);
  const stemOf = (id: string) => COMPANY_ASSETS[id].domain.split(".")[0].toLowerCase();

  it("never names another company's domain, stem or realm", () => {
    for (const id of ids) {
      for (const h of COMPANY_ASSETS[id].infra ?? []) {
        const n = h.toLowerCase();
        for (const other of ids) {
          if (other === id) continue;
          const o = COMPANY_ASSETS[other];
          // A shared stem prefix (medcore / medcorehealth) belongs to the same company only.
          if (stemOf(id).startsWith(stemOf(other)) || stemOf(other).startsWith(stemOf(id))) continue;
          expect(n.includes(o.domain.toLowerCase()), `${id} infra ${h} names ${other}`).toBe(false);
          expect(n.includes(stemOf(other)), `${id} infra ${h} names ${other}`).toBe(false);
          expect(n.includes(o.netbios.toLowerCase()), `${id} infra ${h} names ${other}`).toBe(false);
        }
      }
    }
  });

  it("registers each machine to one company only, and never as an endpoint too", () => {
    const owner = new Map<string, string>();
    for (const id of ids) {
      for (const h of COMPANY_ASSETS[id].infra ?? []) {
        expect(owner.get(h.toLowerCase()), `${h} registered twice`).toBeUndefined();
        owner.set(h.toLowerCase(), id);
        expect(COMPANY_ASSETS[id].hosts.includes(h), `${h} is in both hosts and infra`).toBe(false);
      }
    }
  });
});
