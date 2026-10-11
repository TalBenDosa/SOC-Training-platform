import { describe, it, expect } from "vitest";
import { source, kindOf } from "./cloudflare_access";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { cardRecords, fencedBlocks, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs } from "./remote-access-testkit";
import { vpnPhase } from "./remote-access-shared";

const CARD = "ztna-cloudflare-access.md";
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "cloudflare_access", kind: kindOf(r) ?? "?", format: "ndjson", record: r, timeMs: Date.parse(String(r.CreatedAt)) });
/** §4.2 is an ```ndjson block (three lines) that cardSamples() does not parse as one JSON value. */
const ndjson = () => fencedBlocks(CARD, "ndjson").flatMap(b => b.split(/\r?\n/)).filter(l => l.trim().startsWith("{")).map(l => JSON.parse(l) as Record<string, unknown>);

describe("cloudflare_access — card samples", () => {
  const recs = [...cardRecords(CARD), ...ndjson()];
  it("every card sample (json + ndjson) validates with zero violations", () => {
    expect(recs.length).toBe(8);
    for (const r of recs) {
      expect(kindOf(r)).not.toBeNull();
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });
});

describe("cloudflare_access — corpus conversion (cross-vendor: the corpus has no Cloudflare-authored events)", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations and use native value types", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(kindOf(log.record)).toBe(log.kind);
      expect(typeof log.record.Allowed).toBe("boolean");
      expect(String(log.record.Country)).toMatch(/^[a-z]{2}$/);
      expect(String(log.record.CreatedAt)).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
      expect(String(log.record.RayID)).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("coverage floor; every null is an IdP-side auth/MFA event or lacks the client IP", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[cloudflare_access] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ")}`);
    expect(cov.native.total).toBe(0);
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.6);
    for (const { c, log } of conv) if (!log) {
      const phase = vpnPhase(c.ev);
      expect(phase === "auth_fail" || phase === "mfa_challenge" || phase === "mfa_denied" || !c.ev.src_ip, c.ev.id).toBe(true);
    }
  });

  it("evidence values survive verbatim (user, client IP; no host concept in this dataset)", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const email = c.ev.user_email ?? c.ev.user?.email;
      if (email) expect(present(log, email), `${c.ev.id} user`).toBe(true);
      if (c.ev.src_ip) expect(log.record.IPAddress).toBe(c.ev.src_ip);
    }
  });

  it("is deterministic; UserUID stable per identity", () => {
    for (const { c } of conv) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    const uid = new Map<string, Set<string>>();
    for (const { log } of conv) if (log) uid.set(String(log.record.Email), (uid.get(String(log.record.Email)) ?? new Set()).add(String(log.record.UserUID)));
    for (const [, v] of uid) expect(v.size).toBe(1);
  });
});

describe("cloudflare_access — use cases", () => {
  const conv = convertCorpus(source);
  const cardLogs = [...cardRecords(CARD), ...ndjson()].map(asLog);
  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
