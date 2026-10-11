import { describe, it, expect } from "vitest";
import { source, kindOf } from "./zscaler_zpa";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { cardRecords, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs, burst } from "./remote-access-testkit";
import { isGatewayHost, vpnPhase } from "./remote-access-shared";
import { source as globalprotect } from "./globalprotect";

const CARD = "ztna-zscaler-zpa.md";
const timeOf = (r: Record<string, unknown>) => Date.parse(String(r.TimestampAuthentication || r.TimestampConnectionStart || r.TimestampUnAuthentication));
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "zscaler_zpa", kind: kindOf(r) ?? "?", format: "json", record: r, timeMs: timeOf(r) });

describe("zscaler_zpa — card samples", () => {
  const recs = cardRecords(CARD);
  it("every card sample validates with zero violations (no sample skipped)", () => {
    expect(recs.length).toBe(6);
    for (const r of recs) {
      expect(kindOf(r)).not.toBeNull();
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });
});

describe("zscaler_zpa — corpus conversion (cross-vendor: the corpus has no ZPA-authored events)", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(kindOf(log.record)).toBe(log.kind);
      expect(String(log.record.LogTimestamp)).toMatch(/^\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4}$/);
    }
  });

  it("coverage floor; every null is an IdP-side auth/MFA event or lacks the client IP", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[zscaler_zpa] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ")}`);
    expect(cov.native.total).toBe(0);
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.6);
    for (const { c, log } of conv) if (!log) {
      const phase = vpnPhase(c.ev);
      expect(phase === "auth_fail" || phase === "mfa_challenge" || phase === "mfa_denied" || !c.ev.src_ip, c.ev.id).toBe(true);
    }
  });

  it("evidence values survive verbatim", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const ev = c.ev;
      const email = ev.user_email ?? ev.user?.email;
      if (email) expect(present(log, email), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(log.record.PublicIP).toBe(ev.src_ip);
      // ZPA knows the client device (Hostname), not the VPN concentrator.
      if (ev.hostname && !isGatewayHost(ev.hostname)) expect(log.record.Hostname).toBe(ev.hostname);
    }
  });

  it("same event -> same client device name as the GlobalProtect rendering (one story, one laptop)", () => {
    let compared = 0;
    for (const { c, log } of conv) {
      if (!log) continue;
      const gp = globalprotect.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (gp && gp.record.machinename) { expect(log.record.Hostname, c.ev.id).toBe(gp.record.machinename); compared++; }
    }
    expect(compared).toBeGreaterThan(10);
  });

  it("is deterministic and keeps per-entity ids stable", () => {
    for (const { c } of conv) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    const cn = new Map<string, Set<string>>();
    for (const { log } of conv) if (log) cn.set(String(log.record.Hostname), (cn.get(String(log.record.Hostname)) ?? new Set()).add(String(log.record.CertificateCN).split(".")[0]));
    for (const [, v] of cn) expect(v.size).toBe(1);
  });
});

describe("zscaler_zpa — use cases", () => {
  const conv = convertCorpus(source);
  const recs = cardRecords(CARD);
  const blocked = recs.find(r => r.InternalReason === "BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY")!;
  const t0 = Date.parse(String(blocked.TimestampConnectionStart));
  const probes: [string, number, string][] = [["dc01.corp.nexacorp.local", 445, "Domain-Controllers"], ["dc02.corp.nexacorp.local", 389, "Domain-Controllers"], ["sql-prod01.corp.nexacorp.local", 1433, "Databases"], ["vcenter.corp.nexacorp.local", 443, "Virtualization"], ["fs01.corp.nexacorp.local", 445, "File-Servers"], ["jump01.corp.nexacorp.local", 3389, "Admin-Jump"]];
  const burstRecs = burst(blocked, probes.length, (r, i) => ({
    ...r, Host: probes[i][0], ServicePort: probes[i][1], Application: probes[i][2],
    TimestampConnectionStart: new Date(t0 + i * 20_000).toISOString(), TimestampConnectionEnd: new Date(t0 + i * 20_000 + 28).toISOString(),
  }));
  const cardLogs = [...recs, ...burstRecs].map(asLog);
  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    for (const l of cardLogs) expect(validateNative(l, source.schema)).toEqual([]);
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
