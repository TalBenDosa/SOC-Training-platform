import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { TelemetryEvent } from "@/lib/sim/types";
import { ecsTechnique, ecsTechniqueId, ecsCodeSignature, signState, REVOKED_STATUS } from "./ecsFields";
import { corpus } from "@/lib/logs/native/testing/corpus";

describe("ECS MITRE technique fields", () => {
  it("splits a sub-technique into the parent id + subtechnique id", () => {
    expect(ecsTechnique("T1059.001")).toEqual({ "threat.technique.id": "T1059", "threat.technique.subtechnique.id": "T1059.001" });
    expect(ecsTechnique("T1486")).toEqual({ "threat.technique.id": "T1486" });
    expect(ecsTechnique(undefined)).toEqual({});
  });
  it("reads back the most specific id", () => {
    expect(ecsTechniqueId(ecsTechnique("T1059.002"))).toBe("T1059.002");
    expect(ecsTechniqueId({ "threat.technique.id": "T1486" })).toBe("T1486");
    expect(ecsTechniqueId({})).toBeUndefined();
  });
});

describe("ECS code_signature state", () => {
  it("round-trips every signing state the stories use", () => {
    for (const st of ["trusted", "untrusted", "revoked", "unsigned"] as const) {
      expect(signState(ecsCodeSignature("process", st), "process")).toBe(st);
      expect(signState(ecsCodeSignature("file", st), "file")).toBe(st);
    }
    expect(ecsCodeSignature("file", "revoked")["file.code_signature.status"]).toBe(REVOKED_STATUS);
    expect(signState({}, "process")).toBeUndefined();
  });
  it("matches Elastic's CrowdStrike mapping: unsigned → exists false; signed-untrusted → exists true / trusted false", () => {
    expect(ecsCodeSignature("process", "unsigned")).toEqual({ "process.code_signature.exists": false, "process.code_signature.trusted": false });
    expect(ecsCodeSignature("process", "untrusted")).toEqual({ "process.code_signature.exists": true, "process.code_signature.trusted": false });
    expect(signState({ "process.code_signature.exists": "true", "process.code_signature.trusted": "true" })).toBe("trusted");
  });
});

// The log-field gate parses authored `raw:` literals; emitters build raw at runtime. This
// checks what the platform actually SHOWS — every live-feed event and every scenario
// event — against the registry's deniedFields (fields known not to exist).
describe("no denied (invented) field reaches a rendered raw block", () => {
  const registry = JSON.parse(readFileSync(join(process.cwd(), "scripts", "log-field-registry.json"), "utf8")) as { deniedFields: { field: string }[] };
  const denied = registry.deniedFields.map(d => d.field);
  const bad = (k: string) => denied.find(d => (d.endsWith(".") ? k.startsWith(d) : k === d));
  const offenders = (events: TelemetryEvent[], where: string) =>
    events.flatMap(e => Object.keys(e.raw ?? {}).filter(bad).map(k => `${where}/${e.id}: ${k}`));

  it("has a populated denylist", () => {
    expect(denied).toContain("crowdstrike.detection.");
    expect(denied).toContain("process.code_signature.notarized");
    // the non-native Falcon spellings migrated to their FDR names (edr-crowdstrike.md 4b)
    for (const k of ["crowdstrike.ParentProcessName", "crowdstrike.ContextProcessName", "crowdstrike.process_name", "crowdstrike.GrantedAccess", "crowdstrike.CrossProcessTargetName", "crowdstrike.sensor.", "crowdstrike.HostName", "file.signed"])
      expect(denied).toContain(k);
  });
  it("live-feed corpus", () => {
    expect(offenders(corpus().map(c => c.ev), "corpus")).toEqual([]);
  });
  it("every scenario", async () => {
    const { SCENARIOS } = await import("@/lib/sim/scenarios");
    const found = (SCENARIOS as unknown as { slug: string; build: () => { events: TelemetryEvent[] } }[])
      .flatMap(s => offenders(s.build().events, s.slug));
    expect(found).toEqual([]);
  });
});
