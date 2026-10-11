import { describe, it, expect } from "vitest";
import { source, kindOf, fgtRawLine } from "./fortigate_sslvpn";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { cardRecords, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs, burst } from "./remote-access-testkit";
import { isGatewayHost, hms } from "./remote-access-shared";

const CARD = "vpn-fortigate-sslvpn.md";
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "fortigate_sslvpn", kind: kindOf(r) ?? "?", format: "kv", record: r, timeMs: Math.floor(Number(String(r.eventtime).slice(0, 13))) });

describe("fortigate_sslvpn — card samples", () => {
  const recs = cardRecords(CARD);
  it("every card sample validates with zero violations (no sample skipped)", () => {
    expect(recs.length).toBe(9);
    for (const r of recs) {
      expect(kindOf(r), String(r.raw)).not.toBeNull();
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });
  it("the raw-line builder reproduces every card key=value line exactly", () => {
    for (const r of recs) expect(fgtRawLine(r)).toBe(r.raw);
  });
});

describe("fortigate_sslvpn — corpus conversion", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations and carry a raw line", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(log.rawLine).toMatch(/^date=\d{4}-\d\d-\d\d time=\d\d:\d\d:\d\d devname="/);
      expect(String(log.record.eventtime)).toMatch(/^\d{19}$/);
      expect(kindOf(log.record)).toBe(log.kind);
    }
  });

  it("coverage: native ≥ 95 %, cross-vendor floor", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[fortigate_sslvpn] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ") || "none"}`);
    expect(cov.native.total).toBeGreaterThan(0);
    expect(cov.native.ok / cov.native.total).toBeGreaterThanOrEqual(0.95);
    // Only "MFA challenge issued" has no FortiOS record (FortiOS logs the final result only).
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.9);
  });

  it("evidence values survive verbatim", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const ev = c.ev;
      const email = ev.user_email ?? ev.user?.email;
      const rawUser = ev.raw?.["data.user"] ?? ev.raw?.["cisco.asa.username"];
      if (rawUser) expect(present(log, String(rawUser)), `${ev.id} user`).toBe(true);
      else if (email) expect(present(log, email) || present(log, email.split("@")[0]), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(present(log, ev.src_ip), `${ev.id} src_ip`).toBe(true);
      // FortiOS SSL-VPN logs name the FortiGate (devname), not the client machine.
      if (ev.hostname && isGatewayHost(ev.hostname)) expect(present(log, ev.hostname), `${ev.id} devname`).toBe(true);
      const tunnel = ev.raw?.["data.tunnelip"] ?? ev.raw?.["gp.tunnel_ip"];
      if (typeof tunnel === "string" && log.kind === "0101039947") expect(log.record.tunnelip).toBe(tunnel);
    }
  });

  it("is deterministic", () => {
    for (const { c } of conv) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("fortigate_sslvpn — use cases", () => {
  const conv = convertCorpus(source);
  const recs = cardRecords(CARD);
  const fail = recs.find(r => r.action === "ssl-login-fail")!;
  const t0 = Number(String(fail.eventtime).slice(0, 13));
  const at = (r: Record<string, unknown>, ms: number) => ({ ...r, time: hms(ms), eventtime: `${ms}000000` });
  const spray = burst(fail, 6, (r, i) => at({ ...r, user: ["administrator", "j.cohen", "vpn", "m.levi", "test", "guest"][i] }, t0 + i * 2500));
  const brute = burst(fail, 12, (r, i) => at({ ...r, user: "j.cohen", reason: "sslvpn_login_permission_denied" }, t0 + 60_000 + i * 20_000));
  const cardLogs = [...recs, ...spray, ...brute].map(asLog);
  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
