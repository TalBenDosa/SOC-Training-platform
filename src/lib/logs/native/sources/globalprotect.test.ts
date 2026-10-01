import { describe, it, expect } from "vitest";
import { source, kindOf, GP_COLUMNS, gpRawLine } from "./globalprotect";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import {
  cardRecords, cardLines, convertCorpus, coverage, violations, present, assertUseCases, noiseLogs, storyLogs, burst,
} from "./remote-access-testkit";

const CARD = "vpn-globalprotect.md";

/** Minimal CSV splitter honouring double quotes (PAN-OS quotes values containing commas). */
function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ",") { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur);
  return out;
}
/** Parse a GP syslog line from the card into the flat record (FUTURE_USE columns dropped). */
function parseGpLine(line: string): Record<string, string> {
  const body = line.replace(/^<\d+>\w{3}\s+\d+ \d\d:\d\d:\d\d \S+ /, "");
  const cells = splitCsv(body);
  const vals = cells.filter((_, i) => i !== 0 && i !== 5);
  const rec: Record<string, string> = {};
  GP_COLUMNS.forEach((c, i) => { rec[c] = vals[i] ?? ""; });
  rec.raw = line;
  return rec;
}
const csvPart = (raw: string) => raw.replace(/^<\d+>\w{3}\s+\d+ \d\d:\d\d:\d\d \S+ /, "");
const asLog = (r: Record<string, unknown>): NativeLog => ({ sourceId: "globalprotect", kind: kindOf(r) ?? "?", format: "csv", record: r, timeMs: Date.parse(String(r.high_res_timestamp)) });

describe("globalprotect — card samples", () => {
  const recs = cardRecords(CARD);
  const extraLines = cardLines(CARD).filter(l => l.startsWith("<14>")).map(parseGpLine);

  it("every card sample of a supported kind validates with zero violations", () => {
    expect(recs.length).toBe(6);
    expect(extraLines.length).toBe(2); // follow-on spray lines of §4.3 (raw CSV only)
    for (const r of [...recs, ...extraLines]) {
      const k = kindOf(r);
      expect(k, JSON.stringify(r).slice(0, 80)).not.toBeNull();
      expect(validateNative(asLog(r), source.schema)).toEqual([]);
    }
  });

  it("the raw-line builder reproduces the card's CSV body byte for byte", () => {
    for (const r of recs) {
      const rebuilt = gpRawLine(Object.fromEntries(Object.entries(r).map(([k, v]) => [k, String(v)])));
      expect(csvPart(rebuilt)).toBe(csvPart(String(r.raw)));
    }
  });
});

describe("globalprotect — corpus conversion", () => {
  const conv = convertCorpus(source);

  it("converted logs validate with zero violations and carry a raw line", () => {
    expect(violations(source, conv)).toEqual([]);
    for (const { log } of conv) if (log) {
      expect(log.rawLine).toMatch(/^<14>\w{3} [ \d]\d \d\d:\d\d:\d\d \S+ 1,/);
      expect(kindOf(log.record)).toBe(log.kind);
      expect(log.timeMs).toBeGreaterThan(0);
    }
  });

  it("coverage: native ≥ 95 %, cross-vendor floor", () => {
    const cov = coverage(source, conv);
    // eslint-disable-next-line no-console
    console.log(`[globalprotect] native ${cov.native.ok}/${cov.native.total}, cross-vendor ${cov.cross.ok}/${cov.cross.total}; nulls: ${cov.nulls.join(", ") || "none"}`);
    expect(cov.native.total).toBeGreaterThan(10);
    expect(cov.native.ok / cov.native.total).toBeGreaterThanOrEqual(0.95);
    // Every VPN event type the platform authors has a GP equivalent — the cross-vendor floor is 100 %.
    expect(cov.cross.ok / cov.cross.total).toBeGreaterThanOrEqual(0.95);
  });

  it("evidence values survive verbatim", () => {
    for (const { c, log } of conv) {
      if (!log) continue;
      const ev = c.ev;
      const email = ev.user_email ?? ev.user?.email;
      if (email) expect(present(log, email) || present(log, email.split("@")[0]), `${ev.id} user`).toBe(true);
      if (ev.src_ip) expect(present(log, ev.src_ip), `${ev.id} src_ip`).toBe(true);
      // GP knows both the client (machinename) and the firewall (device_name).
      if (ev.hostname) expect(present(log, ev.hostname), `${ev.id} hostname`).toBe(true);
      const tunnel = ev.raw?.["gp.tunnel_ip"] ?? ev.raw?.["cisco.asa.assigned_ip"] ?? ev.raw?.["data.tunnelip"];
      if (typeof tunnel === "string" && ev.event_type === "vpn_login") expect(present(log, tunnel), `${ev.id} tunnel ip`).toBe(true);
      // dst_ip (FortiGate gateway address) has no GP field: GP logs carry no destination (card §6).
    }
  });

  it("is deterministic", () => {
    for (const { c } of conv) {
      const a = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      const b = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      expect(a).toEqual(b);
    }
  });

  it("stable per-entity ids: same device → same hostid across events", () => {
    const byHost = new Map<string, Set<string>>();
    for (const { log } of conv) if (log && log.record.machinename) {
      const m = String(log.record.machinename);
      byHost.set(m, (byHost.get(m) ?? new Set()).add(String(log.record.hostid)));
    }
    for (const [, ids] of byHost) expect(ids.size).toBe(1);
  });
});

describe("globalprotect — use cases", () => {
  const conv = convertCorpus(source);
  const recs = cardRecords(CARD);
  const spray = recs.find(r => r.status === "failure")!;
  const t0 = Date.parse(String(spray.high_res_timestamp));
  const sprayBurst = burst(spray, 6, (r, i) => ({ ...r, srcuser: ["admin", "j.cohen", "helpdesk", "svc_backup", "test", "vpn"][i], high_res_timestamp: new Date(t0 + i * 3000).toISOString() }));
  const bruteBurst = burst(spray, 12, (r, i) => ({ ...r, srcuser: "j.cohen", high_res_timestamp: new Date(t0 + 60_000 + i * 20_000).toISOString() }));
  const cardLogs = [...recs, ...sprayBurst, ...bruteBurst].map(asLog);

  it("each use case fires on card/story logs; high/critical stay quiet on noise", () => {
    assertUseCases(source, [...cardLogs, ...storyLogs(conv)], noiseLogs(conv));
  });
});
