import { describe, it, expect } from "vitest";
import { source, kindOf, COLUMNS } from "./mssql_audit";
import { makeCtx } from "../ctx";
import { runUseCase } from "../engine";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { vendorRows, render, commonChecks, noLeak, expectEvidence } from "./_db-ueba.testkit";
import { dbFacts } from "./_db-common";

/*
 * Inputs: every "Microsoft SQL Server Audit" row of the live corpus (webshell-rce story rows, the nine
 * benign b_sqlsrv_* rows) and of the scenarios page (web-shell-sqli, sqli-db-exfil, pam-vault-abuse).
 * No card samples: the record is a sys.fn_get_audit_file result row (Microsoft Learn).
 */
const rows = vendorRows(source, /sql server audit/i);
const eventTime = (l: NativeLog) => [Date.parse(`${String(l.record.event_time).replace(" ", "T").slice(0, 23)}Z`)];

describe("mssql_audit - every SQL Server Audit row", () => {
  it("renders on every surface, validates, follows the row's time, deterministic", () => {
    expect(rows.length).toBeGreaterThanOrEqual(12);
    const shapes = commonChecks(source, rows, { timeFields: eventTime });
    // A result set has fixed columns: every row of every kind prints all of them, in the function's order.
    for (const [k, m] of shapes) expect([...m.keys()].length, `${k}: ${JSON.stringify([...m.values()])}`).toBe(1);
    for (const r of rows) expect(Object.keys(render(source, r)!.record)).toEqual(COLUMNS);
    console.log(`[mssql_audit] ${rows.length} rows (${rows.filter(r => r.attack).length} attack); kinds ${JSON.stringify([...shapes.keys()])}`);
  });
  it("evidence survives verbatim; the Azure-only columns are not printed", () => {
    for (const r of rows) {
      const log = render(source, r)!;
      const f = dbFacts(r.c.ev);
      expect(kindOf(log.record)).toBe(log.kind);
      expectEvidence(log, [f.login, f.statement, f.database, f.object, f.app, f.clientHost, f.clientIp === "<local machine>" ? undefined : f.clientIp], r.c.ev.id);
      for (const k of ["duration_milliseconds", "response_rows", "affected_rows", "connection_id"]) expect(log.record, r.c.ev.id).not.toHaveProperty(k);
      expect(String(log.record.event_time)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7}$/);
      expect([0, 1]).toContain(log.record.succeeded);
      noLeak(log, r.c.ev);
    }
  });
  it("one login, one principal id and sid on a server; failed logins have succeeded 0", () => {
    const ctx = makeCtx("nexacorp");
    const logs = rows.filter(r => r.c.origin === "benign").map(r => source.fromTelemetry(r.c.ev, ctx)!);
    const byLogin = new Map<string, Set<string>>();
    for (const l of logs) {
      const k = `${l.record.server_instance_name}|${l.record.server_principal_name}`;
      (byLogin.get(k) ?? byLogin.set(k, new Set()).get(k)!).add(`${l.record.server_principal_id}|${l.record.server_principal_sid}`);
    }
    for (const [k, s] of byLogin) expect(s.size, k).toBe(1);
    const lgif = logs.find(l => l.kind === "LGIF")!;
    expect(lgif.record.succeeded).toBe(0);
    expect(lgif.record.server_principal_sid).toBe("0x01");
  });
  it("a Windows login's sid is the binary form of its domain SID", () => {
    const ev = { id: "w1", ts: "2026-05-10T19:00:00.000Z", source: "db_monitor", vendor: "Microsoft SQL Server Audit", event_type: "db_query", severity: "low",
      raw: { action_id: "SL", server_principal_name: "NEXACORP\\dba", server_instance_name: "NEXACORP-SQL01", database_name: "FinanceDB", statement: "SELECT 1" } } as unknown as TelemetryEvent;
    const sid = String(source.fromTelemetry(ev, makeCtx("nexacorp"))!.record.server_principal_sid);
    expect(sid).toMatch(/^0x010500000000000515000000[0-9A-F]{32}$/);
  });
  it("another engine's row is not a SQL Server Audit record", () => {
    const pg = { id: "p1", ts: "2026-05-10T08:00:00.000Z", source: "db_monitor", vendor: "IBM Guardium", event_type: "db_query", severity: "low",
      raw: { "db.type": "postgresql", "db.user": "app_user", "db.statement": "SELECT 1" } } as unknown as TelemetryEvent;
    expect(source.fromTelemetry(pg, makeCtx("nexacorp"))).toBeNull();
  });
});

describe("mssql_audit - use cases", () => {
  const logs = rows.map(r => ({ r, log: render(source, r)! }));
  const attack = logs.filter(x => x.r.attack).map(x => x.log);
  const noise = logs.filter(x => !x.r.attack).map(x => x.log);
  const lgif = logs.find(x => x.log.kind === "LGIF")!.log;
  const fixtures: NativeLog[] = [
    ...[0, 50, 100, 150, 200].map(s => ({ ...lgif, timeMs: lgif.timeMs + s * 1000 })),
    { ...attack[0], kind: "EX", record: { ...attack[0].record, action_id: "EX", class_type: "X", object_name: "xp_cmdshell", statement: "EXEC xp_cmdshell 'whoami'" } },
  ];
  it("every use case fires on attack rows / fixtures; high ones stay quiet on routine rows", () => {
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("mssql_audit.")).toBe(true);
      const hits = runUseCase(uc, [...logs.map(x => x.log), ...fixtures]).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[mssql_audit] ${uc.id}: ${hits} hit(s), ${noiseHits}/${noise.length} on routine rows`);
      expect(hits, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
