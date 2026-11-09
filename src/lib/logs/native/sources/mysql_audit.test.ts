import { describe, it, expect } from "vitest";
import { source, kindOf } from "./mysql_audit";
import { makeCtx } from "../ctx";
import { runUseCase } from "../engine";
import { validateNative } from "../validate";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { vendorRows, render, commonChecks, noLeak, expectEvidence } from "./_db-ueba.testkit";
import { dbFacts } from "./_db-common";

/*
 * Inputs: every "MySQL Enterprise Audit" row (the benign b_sqlsrv_10 positions report) plus fixtures.
 * Reference samples: the MySQL 8.4 manual's JSON audit records (query event, connect event).
 */
const MANUAL_QUERY = { timestamp: "2019-10-03 14:23:35", id: 2, class: "general", event: "status", connection_id: 5,
  account: { user: "root", host: "localhost" }, login: { user: "root", os: "", ip: "::1", proxy: "" },
  general_data: { command: "Query", sql_command: "show_variables", query: "SHOW VARIABLES", status: 0 } };
const MANUAL_CONNECT = { timestamp: "2019-10-03 14:23:18", id: 1, class: "connection", event: "connect", connection_id: 5,
  account: { user: "root", host: "localhost" }, login: { user: "root", os: "", ip: "::1", proxy: "" },
  connection_data: { connection_type: "ssl", status: 0, db: "test" } };

const rows = vendorRows(source, /mysql/i);
const ts = (l: NativeLog) => [Date.parse(`${String(l.record.timestamp).replace(" ", "T")}Z`)];
const mk = (id: string, raw: Record<string, unknown>, extra: Partial<TelemetryEvent> = {}) =>
  ({ id, ts: "2026-05-10T20:00:00.000Z", source: "db_monitor", vendor: "MySQL Enterprise Audit", event_type: "db_query", severity: "low", raw, ...extra }) as unknown as TelemetryEvent;

describe("mysql_audit - the manual's records", () => {
  it("validate with zero violations", () => {
    for (const rec of [MANUAL_QUERY, MANUAL_CONNECT]) {
      const k = kindOf(rec)!;
      expect(validateNative({ sourceId: "mysql_audit", kind: k, format: "json", record: rec, timeMs: 0 }, source.schema)).toEqual([]);
    }
  });
});

describe("mysql_audit - every MySQL row", () => {
  it("renders on every surface, validates, follows the row's time, deterministic", () => {
    expect(rows.length).toBeGreaterThanOrEqual(1);
    commonChecks(source, rows, { timeFields: ts });
    for (const r of rows) {
      const log = render(source, r)!;
      const f = dbFacts(r.c.ev);
      expectEvidence(log, [f.login, f.statement, f.clientIp], r.c.ev.id);
      noLeak(log, r.c.ev);
      expect(log.record.timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    }
  });
  it("a failed connect prints status 1045; another engine's row is null", () => {
    const ctx = makeCtx("nexacorp");
    const denied = source.fromTelemetry(mk("m1", { "mysql.audit.class": "connection", "db.user": "svc-tradingapp", "mysql.audit.login.ip": "10.20.12.70", "event.outcome": "failure" }, { event_type: "auth_failure" }), ctx)!;
    expect(denied.kind).toBe("connection/connect");
    expect((denied.record.connection_data as { status: number }).status).toBe(1045);
    expect(source.fromTelemetry(mk("m2", { "db.type": "postgresql", "db.statement": "SELECT 1" }, { vendor: "IBM Guardium" }), ctx)).toBeNull();
  });
});

describe("mysql_audit - use cases", () => {
  const ctx = makeCtx("nexacorp");
  const fixtures: NativeLog[] = [
    source.fromTelemetry(mk("f1", { "db.user": "shop_app", "db.statement": "SELECT id,name FROM products WHERE id='1' UNION SELECT user,authentication_string FROM mysql.user-- -'", "mysql.audit.login.ip": "10.20.4.15" }), ctx)!,
    source.fromTelemetry(mk("f2", { "db.user": "shop_app", "db.statement": "SELECT * FROM customers INTO OUTFILE '/var/lib/mysql-files/c.csv'", "mysql.audit.login.ip": "10.20.4.15" }), ctx)!,
    ...[0, 30, 60, 90, 120].map(s => ({ ...source.fromTelemetry(mk(`f3${s}`, { "mysql.audit.class": "connection", "db.user": "root", "mysql.audit.login.ip": "10.20.9.9", "event.outcome": "failure" }, { event_type: "auth_failure" }), ctx)!, timeMs: Date.parse("2026-05-10T20:00:00.000Z") + s * 1000 })),
  ];
  const noise = rows.filter(r => !r.attack).map(r => render(source, r)!);
  it("every use case fires on rows / fixtures; high ones stay quiet on routine rows", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, [...noise, ...fixtures]).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[mysql_audit] ${uc.id}: ${hits} hit(s), ${noiseHits}/${noise.length} on routine rows`);
      expect(hits, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
