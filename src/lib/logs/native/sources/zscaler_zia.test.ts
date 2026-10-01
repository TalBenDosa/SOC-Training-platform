import { describe, it, expect } from "vitest";
import { source, kindOf } from "./zscaler_zia";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { cardRecords, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs } from "./remote-access-testkit";

const CARD = "proxy-zscaler-zia.md";
const ev = (r: Record<string, unknown>) => r.event as Record<string, string>;
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "zscaler_zia", kind: kindOf(r) ?? "?", format: "json", record: r, timeMs: Date.parse(`${ev(r).datetime.replace(" ", "T")}Z`) });

describe("zscaler_zia — card samples", () => {
  const recs = cardRecords(CARD);
  it("every card sample validates with zero violations (no sample skipped)", () => {
    expect(recs.length).toBe(5);
    for (const r of recs) {
      expect(kindOf(r)).toBe("web");
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });
});

describe("zscaler_zia — corpus conversion", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations; every value is a string", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(kindOf(log.record)).toBe("web");
      for (const [k, v] of Object.entries(ev(log.record))) expect(typeof v, k).toBe("string");
      expect(ev(log.record).url).not.toMatch(/^https?:\/\//);
      expect(ev(log.record).datetime).toMatch(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/);
    }
  });

  it("coverage: Zscaler-authored ≥ 95 %, Palo Alto / Squid-authored floor", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[zscaler_zia] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ")}`);
    expect(cov.native.total).toBeGreaterThan(30);
    expect(cov.native.ok / cov.native.total).toBeGreaterThanOrEqual(0.95);
    // Cross-vendor nulls are inbound (WAF / OWA brute force) and east-west internal-app events ZIA never sees.
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.6);
  });

  it("evidence values survive verbatim", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const e = c.ev;
      const id = e.id;
      const email = e.user_email ?? e.user?.email;
      if (email) expect(ev(log.record).user, `${id} user`).toBe(email);
      if (e.src_ip) expect(present(log, e.src_ip), `${id} src_ip`).toBe(true);
      if (e.dst_ip) expect(ev(log.record).serverip, `${id} dst_ip`).toBe(e.dst_ip);
      if (e.hostname) expect(ev(log.record).devicehostname, `${id} hostname`).toBe(e.hostname);
      if (e.network?.domain) expect(ev(log.record).hostname, `${id} domain`).toBe(e.network.domain);
      if (e.network?.url) expect(ev(log.record).url, `${id} url`).toBe(e.network.url.replace(/^https?:\/\//, ""));
      if (e.file?.md5) expect(ev(log.record).md5).toBe(e.file.md5);
    }
  });

  it("is deterministic", () => {
    for (const { c } of conv) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("zscaler_zia — use cases", () => {
  const conv = convertCorpus(source);
  const cardLogs = cardRecords(CARD).map(asLog);
  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
