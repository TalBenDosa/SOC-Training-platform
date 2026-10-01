import { describe, it, expect } from "vitest";
import { source, kindOf, asaRawLine } from "./anyconnect";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { cardRecords, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs, burst } from "./remote-access-testkit";
import { isGatewayHost, parseAsaTime, asaTime } from "./remote-access-shared";

const CARD = "vpn-cisco-anyconnect.md";
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "anyconnect", kind: kindOf(r) ?? "?", format: "syslog", record: r, timeMs: parseAsaTime(String(r.timestamp)) });

describe("anyconnect — card samples", () => {
  const recs = cardRecords(CARD);
  it("every card sample validates with zero violations (no sample skipped)", () => {
    expect(recs.length).toBe(22);
    for (const r of recs) {
      expect(kindOf(r), String(r.raw)).not.toBeNull();
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });
  it("the raw-line builder reproduces every card syslog line exactly", () => {
    for (const r of recs) expect(asaRawLine(r)).toBe(r.raw);
  });
});

describe("anyconnect — corpus conversion", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations and carry a raw line", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(log.rawLine).toMatch(/^<16[46]>\w{3} \d\d \d{4} \d\d:\d\d:\d\d \S+ : %ASA-[46]-\d{6}: /);
      expect(kindOf(log.record)).toBe(log.kind);
    }
  });

  it("coverage: native ≥ 95 %, cross-vendor floor", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[anyconnect] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ") || "none"}`);
    expect(cov.native.ok / cov.native.total).toBeGreaterThanOrEqual(0.95);
    // Only the GlobalProtect-authored "MFA challenge issued" event has no ASA message (null by design).
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.9);
  });

  it("evidence values survive verbatim", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const ev = c.ev;
      const email = ev.user_email ?? ev.user?.email;
      const rawUser = ev.raw?.["cisco.asa.username"] ?? ev.raw?.["data.user"];
      if (email || rawUser) expect(present(log, String(rawUser ?? "")) && !!rawUser || (!!email && (present(log, email) || present(log, email.split("@")[0]))), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(present(log, ev.src_ip), `${ev.id} src_ip`).toBe(true);
      // ASA messages carry the concentrator's hostname, not the client's (no client-hostname concept).
      if (ev.hostname && isGatewayHost(ev.hostname)) expect(present(log, ev.hostname), `${ev.id} gateway host`).toBe(true);
    }
  });

  it("is deterministic", () => {
    for (const { c } of conv) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("anyconnect — use cases", () => {
  const conv = convertCorpus(source);
  const recs = cardRecords(CARD);
  const rej = recs.find(r => r.message_id === "113005")!;
  const t0 = parseAsaTime(String(rej.timestamp));
  const burstLogs = burst(rej, 12, (r, i) => {
    const x = { ...r, timestamp: asaTime(t0 + i * 15_000), reason: i % 3 ? "Invalid password" : "AAA failure" };
    return { ...x, raw: asaRawLine(x) };
  });
  const enumLogs = burst(recs.find(r => r.message_id === "113015")!, 4, (r, i) => {
    const x = { ...r, timestamp: asaTime(t0 + 200_000 + i * 5_000), user: ["admin", "test", "vpn", "backup"][i] };
    return { ...x, raw: asaRawLine(x) };
  });
  const cardLogs = [...recs, ...burstLogs, ...enumLogs].map(asLog);
  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
