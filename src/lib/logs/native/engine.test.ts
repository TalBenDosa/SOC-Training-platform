import { describe, it, expect } from "vitest";
import { getAll, leafPaths } from "./paths";
import { matches, runUseCase } from "./engine";
import { validateNative } from "./validate";
import { makeCtx } from "./ctx";
import type { NativeLog, SourceSchema, UseCase } from "./types";

describe("paths", () => {
  it("nested, arrays and literal dotted keys", () => {
    const r = { userIdentity: { arn: "a" }, events: [{ name: "x" }, { name: "y" }], "src.process.cmdline": "pwsh -enc" };
    expect(getAll(r, "userIdentity.arn")).toEqual(["a"]);
    expect(getAll(r, "events[].name")).toEqual(["x", "y"]);
    expect(getAll(r, "src.process.cmdline")).toEqual(["pwsh -enc"]);
    expect(leafPaths(r).sort()).toEqual(["events[].name", "src.process.cmdline", "userIdentity.arn"]);
  });
});

describe("engine", () => {
  const log = (i: number, ip: string, t: number, ok = false): NativeLog => ({ sourceId: "okta", kind: "user.session.start", format: "json", timeMs: t, record: { client: { ipAddress: ip }, outcome: { result: ok ? "SUCCESS" : "FAILURE" }, actor: { alternateId: `u${i}@x.com` } } });
  it("conditions incl. cidr / regex / not", () => {
    const r = log(1, "203.0.113.5", 0).record;
    expect(matches(r, { all: [{ field: "outcome.result", op: "eq", value: "FAILURE" }, { field: "client.ipAddress", op: "notCidr", value: ["10.0.0.0/8"] }] })).toBe(true);
    expect(matches(r, { not: { field: "actor.alternateId", op: "regex", value: "@x\\.com$" } })).toBe(false);
  });
  it("threshold with distinct users inside the window (password spray)", () => {
    const uc: UseCase = { id: "t", title: "spray", sourceId: "okta", severity: "high", mitre: ["T1110.003"], description: "", logic: "",
      match: { field: "outcome.result", op: "eq", value: "FAILURE" }, threshold: { groupBy: ["client.ipAddress"], count: 5, windowSec: 600, distinct: "actor.alternateId" } };
    const spray = Array.from({ length: 6 }, (_, i) => log(i, "203.0.113.5", i * 30_000));
    const slow = Array.from({ length: 6 }, (_, i) => log(i, "198.51.100.9", i * 3_600_000));
    expect(runUseCase(uc, [...spray, ...slow])).toHaveLength(1);
  });
});

describe("validate", () => {
  const schema: SourceSchema = { sourceId: "okta", category: "idp", card: "idp-okta.md", product: "Okta", format: "json", vendorMatch: ["okta"], telemetrySources: ["okta"],
    kinds: { "user.session.start": { required: ["eventType", "outcome.result"], optional: ["actor.alternateId"], openPrefixes: ["debugContext.debugData"] } } };
  it("flags unknown, foreign and missing fields; open prefixes pass", () => {
    const v = validateNative({ sourceId: "okta", kind: "user.session.start", format: "json", timeMs: 0,
      record: { eventType: "user.session.start", debugContext: { debugData: { anything: "1" } }, "data.srcip": "1.2.3.4", extra: 1 } }, schema);
    expect(v.map(x => `${x.problem}:${x.path}`).sort()).toEqual(["foreign_namespace:data.srcip", "missing_required:outcome.result", "unknown_field:extra"]);
  });
});

describe("ctx", () => {
  it("is deterministic per company", () => {
    expect(makeCtx("nexacorp").tenant.awsAccountId).toBe(makeCtx("nexacorp").tenant.awsAccountId);
    expect(makeCtx("nexacorp").tenant.awsAccountId).toMatch(/^\d{12}$/);
    expect(makeCtx("medcore").uuid("x")).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});
