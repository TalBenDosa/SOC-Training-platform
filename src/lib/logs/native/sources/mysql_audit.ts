/**
 * MySQL Enterprise Audit, JSON audit log format, native module. No card in docs/log-schemas: the
 * record is one element of the audit log file written with audit_log_format=JSON, as the MySQL 8.4
 * Reference Manual documents it ("Audit Log File Formats", JSON audit log file format): top-level
 * `timestamp` ("YYYY-MM-DD hh:mm:ss", UTC), `id`, `class`, `event`, `connection_id`, `account`
 * {user, host}, `login` {user, os, ip, proxy}, then the class's own object:
 *   - class "general" / event "status": `general_data` {command, sql_command, query, status};
 *     `query_statistics` {query_time, rows_sent, rows_examined} when the outlier filter is on (the
 *     bytes_* counters need log_slow_extra and are not printed);
 *   - class "connection" / event "connect": `connection_data` {connection_type, status, db}.
 * status is mysql_errno() (0 = success, 1045 = access denied).
 *
 * Input: `db_monitor` events of the MySQL Enterprise Audit vendor (and other vendors' rows of a MySQL
 * server): `mysql.audit.*` keys (class, event, command_class, login.ip) plus db.user / db.statement /
 * db.name / db.rows_* / db.duration_ms. Evidence carried verbatim: account, client address, statement,
 * database. Another engine's row is null.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { connectionOf, dbFacts, rawOf, utcSpace } from "./_db-common";

const TOP = ["timestamp", "id", "class", "event", "connection_id", "account.user", "account.host", "login.user", "login.os", "login.ip", "login.proxy"];
const general: KindSchema = {
  required: [...TOP, "general_data.command", "general_data.sql_command", "general_data.query", "general_data.status"],
  optional: ["query_statistics.query_time", "query_statistics.rows_sent", "query_statistics.rows_examined"],
};
const connect: KindSchema = { required: [...TOP, "connection_data.connection_type", "connection_data.status", "connection_data.db"], optional: [] };

const schema: SourceSchema = {
  sourceId: "mysql_audit", category: "database", card: "(none: MySQL Reference Manual, JSON audit log file format)", product: "MySQL Enterprise Audit",
  format: "json", vendorMatch: ["mysql enterprise audit", "mysql audit"], telemetrySources: ["db_monitor"],
  kinds: { "general/status": general, "connection/connect": connect },
};

export function kindOf(record: Record<string, unknown>): string | null {
  const k = `${String(record.class)}/${String(record.event)}`;
  return k in schema.kinds ? k : null;
}

/** statement/sql counter names (performance_schema statement/sql/xxx). */
const SQL_COMMAND: Record<string, string> = {
  SELECT: "select", WITH: "select", INSERT: "insert", UPDATE: "update", DELETE: "delete", REPLACE: "replace", CREATE: "create_table", DROP: "drop_table",
  ALTER: "alter_table", GRANT: "grant", REVOKE: "revoke", SHOW: "show_variables", CALL: "call_procedure", SET: "set_option", TRUNCATE: "truncate",
};

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = dbFacts(ev);
  if (f.engine && f.engine !== "mysql") return null;
  const r = rawOf(ev);
  const ms = Date.parse(ev.ts);
  if (!Number.isFinite(ms)) return null;
  const cls = String(r["mysql.audit.class"] ?? (f.isLogin ? "connection" : "general"));
  const user = (f.login ?? "").split("@")[0];
  const ip = f.clientIp ?? "";
  const base: Record<string, unknown> = {
    timestamp: utcSpace(ms),
    id: ctx.int(`mysql:id:${ev.id}`, 0, 9),
    class: cls === "connection" ? "connection" : "general",
    event: cls === "connection" ? "connect" : "status",
    connection_id: ctx.int(`mysql:conn:${connectionOf(ctx, f, ms).key}`, 40, 980_000),
    account: { user, host: "%" },
    login: { user, os: "", ip, proxy: "" },
  };
  if (base.class === "connection") {
    const record = { ...base, connection_data: { connection_type: "ssl", status: f.failed ? 1045 : 0, db: f.database ?? "" } };
    return { sourceId: "mysql_audit", kind: "connection/connect", format: "json", record, timeMs: ms };
  }
  if (!f.statement) return null;
  const sqlCommand = String(r["mysql.audit.command_class"] ?? SQL_COMMAND[f.verb ?? ""] ?? (f.verb ?? "select").toLowerCase());
  const stats = f.durationMs !== undefined || f.rows !== undefined || f.rowsExamined !== undefined;
  const record: Record<string, unknown> = {
    ...base,
    general_data: { command: "Query", sql_command: sqlCommand, query: f.statement, status: f.failed ? Number(f.errorCode ?? 1064) || 1064 : 0 },
    ...(stats ? { query_statistics: {
      ...(f.durationMs !== undefined ? { query_time: Math.round(f.durationMs) / 1000 } : {}),
      ...(f.rows !== undefined ? { rows_sent: f.rows } : {}),
      ...(f.rowsExamined !== undefined ? { rows_examined: f.rowsExamined } : {}),
    } } : {}),
  };
  return { sourceId: "mysql_audit", kind: "general/status", format: "json", record, timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "mysql_audit.union_injection", title: "UNION SELECT in an application query", sourceId: "mysql_audit", kinds: ["general/status"],
    severity: "high", mitre: ["T1190"],
    description: "A query that closes an ordinary lookup and appends UNION SELECT, sent by the application's account: the shape of a SQL injection passed through by the web tier.",
    logic: "SPL: index=mysql_audit class=general | regex general_data.query=\"(?i)union\\s+(all\\s+)?select\" | table timestamp account.user login.ip general_data.query",
    match: { field: "general_data.query", op: "regex", value: "union\\s+(all\\s+)?select" },
    falsePositives: ["Reporting queries that use UNION by design"],
  },
  {
    id: "mysql_audit.access_denied_burst", title: "Repeated access-denied connects from one address", sourceId: "mysql_audit", kinds: ["connection/connect"],
    severity: "medium", mitre: ["T1110.001"],
    description: "Five or more connect events with status 1045 (access denied) from one client address in ten minutes: password guessing against a MySQL account.",
    logic: "SPL: index=mysql_audit class=connection event=connect connection_data.status=1045 | bin _time span=10m | stats count by login.ip _time | where count >= 5",
    match: { field: "connection_data.status", op: "eq", value: 1045 },
    threshold: { groupBy: ["login.ip"], count: 5, windowSec: 600 },
    falsePositives: ["An application deployed with an old password"],
  },
  {
    id: "mysql_audit.outfile_export", title: "Query result written to a server file", sourceId: "mysql_audit", kinds: ["general/status"],
    severity: "high", mitre: ["T1005", "T1074.001"],
    description: "SELECT ... INTO OUTFILE / DUMPFILE writes rows to a file on the database server: a way to stage a table for theft or to drop a web shell next to the web root.",
    logic: "SPL: index=mysql_audit class=general general_data.query=\"*INTO OUTFILE*\" OR general_data.query=\"*INTO DUMPFILE*\"",
    match: { field: "general_data.query", op: "regex", value: "into\\s+(outfile|dumpfile)" },
    falsePositives: ["Scheduled exports a DBA set up (they run from the event scheduler under a known account)"],
  },
  {
    id: "mysql_audit.large_result", title: "Very large result set returned to one client", sourceId: "mysql_audit", kinds: ["general/status"],
    severity: "low", mitre: ["T1005"],
    description: "query_statistics shows a query that examined or returned far more rows than the application normally reads. Compare with the account's usual volume before escalating.",
    logic: "SPL: index=mysql_audit class=general query_statistics.rows_examined > 100000 | table timestamp account.user login.ip query_statistics.* general_data.query",
    match: { field: "query_statistics.rows_examined", op: "gt", value: 100_000 },
    falsePositives: ["Reports and month-end jobs over large tables"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
