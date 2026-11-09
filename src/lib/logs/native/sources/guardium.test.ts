import { describe, it, expect } from "vitest";
import { source, kindOf, leefLine, ATTRS } from "./guardium";
import { makeCtx } from "../ctx";
import { runUseCase } from "../engine";
import { validateNative } from "../validate";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { vendorRows, render, commonChecks, noLeak, expectEvidence } from "./_db-ueba.testkit";
import { dbFacts } from "./_db-common";

/*
 * Inputs: every "IBM Guardium" row of the live corpus (kerberoasting xp_cmdshell story row, the benign
 * b_db_* / b_mc_pharm rows) and of the scenarios page (sqli-db-exfil, kerberoasting).
 * Reference sample: IBM's own LEEF sample (QRadar DSM guide, "IBM Guardium sample event messages", sample 1).
 */
const IBM_SAMPLE = "Aug 19 12:33:31 ibm.guardium.test guard_sender[4486]: LEEF:1.0|IBM|Guardium|8.0|Login failures|ruleID=20026|ruleDesc=Login failures|severity=INFO|devTime=2013-8-19 6:34:41|serverType=DB2|classification=|category=|dbProtocolVersion=3.0|usrName=|sourceProgram=DB2JCC_APPLICATION|start=1376908481000|dbUser=user|dst=10.30.2.124|dstPort=50000|src=10.30.5.152|srcPort=38754|protocol=TCP|type=LOGIN_FAILED|violationID=15|sql=|error=08001-XXXX:30082-01";

/** Parse a Guardium LEEF syslog line back into the module's flat record. */
function parse(line: string): Record<string, string> {
  const m = /^(\w{3} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) (\w+)\[(\d+)\]: LEEF:([\d.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/.exec(line)!;
  const out: Record<string, string> = { timestamp: m[1], hostname: m[2], appName: m[3], procId: m[4], LEEFVersion: m[5], DeviceVendor: m[6], DeviceProduct: m[7], DeviceVersion: m[8], EventID: m[9] };
  // Attributes in template order; the last one (error) takes the rest of the line.
  let rest = m[10];
  ATTRS.forEach((k, i) => {
    const next = ATTRS[i + 1];
    const end = next ? rest.indexOf(`|${next}=`) : rest.length;
    out[k] = rest.slice(k.length + 1, end);
    rest = next ? rest.slice(end + 1) : "";
  });
  return out;
}

const rows = vendorRows(source, /guardium/i);
/** devTime is the appliance's local time; start is the session start (never after the row). */
const times = (l: NativeLog) => {
  const start = Number(l.record.start);
  return [start > l.timeMs - 1 ? start : l.timeMs];
};

describe("guardium - IBM's sample", () => {
  it("IBM's sample line parses into the module's record and validates; the line is rebuilt byte for byte", () => {
    const rec = parse(IBM_SAMPLE);
    expect(kindOf(rec)).toBe("LOGIN_FAILED");
    expect(leefLine(rec)).toBe(IBM_SAMPLE);
    const log: NativeLog = { sourceId: "guardium", kind: "LOGIN_FAILED", format: "syslog", record: rec, rawLine: IBM_SAMPLE, timeMs: 0 };
    expect(validateNative(log, source.schema)).toEqual([]);
  });
});

describe("guardium - every Guardium row", () => {
  it("renders on every surface, validates, follows the row's time, deterministic, one shape per kind", () => {
    expect(rows.length).toBeGreaterThanOrEqual(15);
    const shapes = commonChecks(source, rows, { timeFields: times });
    for (const [k, m] of shapes) expect([...m.keys()].length, `${k}: ${JSON.stringify([...m.values()])}`).toBe(1);
    console.log(`[guardium] ${rows.length} rows (${rows.filter(r => r.attack).length} attack); kinds ${JSON.stringify([...shapes.keys()])}`);
  });
  it("the wire line is rebuilt from the record; evidence survives verbatim; the session starts before the row", () => {
    for (const r of rows) {
      const log = render(source, r)!;
      const rec = log.record as Record<string, string>;
      expect(log.rawLine).toBe(leefLine(rec));
      expect(Object.keys(rec).slice(9)).toEqual(ATTRS);
      for (const v of Object.values(rec)) expect(typeof v).toBe("string");
      expect(["INFO", "LOW", "MED", "HIGH"]).toContain(rec.severity);
      expect(rec.devTime).toMatch(/^\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{2}:\d{2}$/);
      expect(Number(rec.start)).toBeLessThanOrEqual(log.timeMs);
      const f = dbFacts(r.c.ev);
      expectEvidence(log, [f.login, f.statement, f.clientIp, f.serverIp, f.app, f.error], r.c.ev.id);
      noLeak(log, r.c.ev);
    }
  });
  it("the rule that fires follows the statement, not the verdict: the scenario's routine BI read and the injected reads hit the same rule", () => {
    const sqli = rows.filter(r => r.scenario === "sqli-db-exfil").map(r => ({ r, rec: render(source, r)!.record as Record<string, string> }));
    const benign = sqli.find(x => !x.r.attack)!;
    const union = sqli.find(x => x.r.c.ev.id === "sqli_02b_db_union_tables")!;
    expect(benign.rec.ruleDesc).toBe(union.rec.ruleDesc);
    expect(benign.rec.severity).toBe(union.rec.severity);
    // One client connection, one source port and one session start.
    const app = sqli.filter(x => x.rec.dbUser === "app_shop" && x.rec.devTime.startsWith("2026-7-14 23:4"));
    expect(new Set(app.map(x => `${x.rec.srcPort}|${x.rec.start}`)).size).toBe(1);
  });
  it("a successful login has no Guardium alert record", () => {
    const ok = { id: "g1", ts: "2026-05-10T08:00:00.000Z", source: "db_monitor", vendor: "IBM Guardium", event_type: "db_auth", severity: "low",
      raw: { "db.user": "app_user", "db.operation": "CONNECT", "event.outcome": "success" } } as unknown as TelemetryEvent;
    expect(source.fromTelemetry(ok, makeCtx("nexacorp"))).toBeNull();
  });
});

describe("guardium - use cases", () => {
  const logs = rows.map(r => ({ r, log: render(source, r)! }));
  const noise = logs.filter(x => !x.r.attack).map(x => x.log);
  const fail = logs.find(x => x.log.kind === "LOGIN_FAILED")!.log;
  const fixtures: NativeLog[] = [0, 40, 80, 120, 160].map(s => ({ ...fail, timeMs: fail.timeMs + s * 1000 }));
  it("every use case fires on attack rows / fixtures; high ones stay quiet on routine rows", () => {
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("guardium.")).toBe(true);
      const hits = runUseCase(uc, [...logs.map(x => x.log), ...fixtures]).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[guardium] ${uc.id}: ${hits} hit(s), ${noiseHits}/${noise.length} on routine rows`);
      expect(hits, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
