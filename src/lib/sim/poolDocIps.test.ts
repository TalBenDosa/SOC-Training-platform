import { describe, expect, it } from "vitest";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { collectDocIps } from "./variation";
import { POOL_DOC_IPS } from "./poolDocIps";

describe("the ordinary-traffic addresses the variation layer never draws", () => {
  it("is the current list (regenerate: npx tsx scripts/generate-pool-doc-ips.mjs)", () => {
    const s = new Set<string>();
    collectDocIps(BENIGN_EVENTS, s);
    for (const evs of Object.values(COMPANY_EVENTS)) collectDocIps(evs, s);
    expect([...POOL_DOC_IPS]).toEqual([...s].sort());
  });
});
