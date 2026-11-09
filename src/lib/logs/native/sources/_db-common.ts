/**
 * Shared facts of a database-activity event, for the database modules (mssql_audit, guardium,
 * mysql_audit). The platform authors database rows in several vocabularies: the SQL Server Audit
 * result columns (event_time, action_id, server_principal_name ...), the normalized `db.*` /
 * `source.ip` / `application.name` names of the DAM rows, the scenario packs' `database.*` /
 * `query.*` / `sql.*` names and the MySQL `mysql.audit.*` names. dbFacts reads them all into one
 * vendor-neutral shape, so each module prints the same evidence (login, statement, database,
 * object, client address, client program) in its own wire format.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";
import { hostIpFor } from "./_proc-identity";

export type DbEngine = "mssql" | "postgresql" | "mysql" | "oracle" | "db2";

export interface DbFacts {
  /** The login as authored (a Windows login keeps its DOMAIN\ prefix). */
  login?: string;
  /** The database user the login maps to, when the row names one. */
  dbUser?: string;
  role?: string;
  statement?: string;
  database?: string;
  /** "server\instance" as authored, or the server name. */
  instance?: string;
  /** The database server's short host name. */
  server?: string;
  engine?: DbEngine;
  schema?: string;
  object?: string;
  clientIp?: string;
  clientHost?: string;
  serverIp?: string;
  serverPort?: number;
  clientPort?: number;
  app?: string;
  /** A login / connect event, not a statement. */
  isLogin: boolean;
  failed: boolean;
  /** First keyword of the statement, upper case (SELECT, INSERT, EXEC, GRANT, BACKUP ...). */
  verb?: string;
  rows?: number;
  rowsExamined?: number;
  durationMs?: number;
  error?: string;
  errorCode?: string;
  sessionId?: number;
  sessionStartMs?: number;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" || v === "-" ? undefined : String(v));
const numOf = (v: unknown) => { const n = Number(v); return v === undefined || v === null || v === "" || !Number.isFinite(n) ? undefined : n; };

export function rawOf(ev: TelemetryEvent): Record<string, unknown> {
  return (ev.raw ?? {}) as Record<string, unknown>;
}

const ENGINE: [RegExp, DbEngine][] = [
  [/mssql|sql ?server|sqlserver|tds/i, "mssql"], [/postgres|pgsql/i, "postgresql"], [/mysql|mariadb/i, "mysql"], [/oracle/i, "oracle"], [/db2/i, "db2"],
];

function engineOf(ev: TelemetryEvent, r: Record<string, unknown>): DbEngine | undefined {
  const t = str(r["db.type"]) ?? str(r["database.type"]);
  if (t) for (const [re, e] of ENGINE) if (re.test(t)) return e;
  const v = ev.vendor ?? "";
  if (/sql server/i.test(v)) return "mssql";
  if (/mysql/i.test(v)) return "mysql";
  if (r["server_instance_name"] !== undefined || r["action_id"] !== undefined) return "mssql";
  if (Object.keys(r).some(k => k.startsWith("mysql."))) return "mysql";
  // The scenario packs' SQL Server rows name a T-SQL instance and run T-SQL (sp_ / xp_ procedures, TOP, sys.).
  const inst = str(r["database.instance"]) ?? str(r["db.instance"]) ?? "";
  if (/^MSSQL/i.test(inst) || /\\(MSSQLSERVER|RPT|SQLEXPRESS)$/i.test(inst)) return "mssql";
  return undefined;
}

export function verbOf(statement: string | undefined): string | undefined {
  const m = /^\s*(?:\(\s*)*([A-Za-z]+)/.exec(statement ?? "");
  return m ? m[1].toUpperCase() : undefined;
}

export function dbFacts(ev: TelemetryEvent): DbFacts {
  const r = rawOf(ev);
  const s = (...ks: string[]) => { for (const k of ks) { const v = str(r[k]); if (v !== undefined) return v; } return undefined; };
  const n = (...ks: string[]) => { for (const k of ks) { const v = numOf(r[k]); if (v !== undefined) return v; } return undefined; };
  const statement = s("statement", "db.statement", "query.text", "sql");
  const table = s("database.table");
  const [tSchema, tObject] = table && table.includes(".") && !/^information_schema\./i.test(table) ? [table.split(".")[0], table.split(".").slice(1).join(".")] : [undefined, table];
  const instance = s("server_instance_name", "database.instance", "db.instance");
  const op = (s("db.operation", "sql.command", "query.type") ?? "").toUpperCase();
  const action = s("action_id");
  const et: string = ev.event_type ?? "";
  const isLogin = action === "LGIS" || action === "LGIF" || op === "CONNECT" || et === "db_auth" || et === "auth_failure" || et === "auth_success" || et === "login_failure" || et === "login_success";
  const outcome = (s("event.outcome", "query.status", "succeeded") ?? "").toLowerCase();
  const failed = action === "LGIF" || outcome === "failure" || outcome === "error" || outcome === "false" || outcome === "0" || et === "auth_failure" || et === "login_failure";
  const userEmail = ev.user_email ?? ev.user?.email;
  const login = s("server_principal_name", "db.user", "mysql.audit.login.user") ?? (userEmail ? userEmail.split("@")[0] : undefined);
  const server = (instance ?? ev.hostname ?? s("host.name"))?.split("\\")[0]?.split(":")[0];
  const clientIp = s("client_ip", "source.ip", "mysql.audit.login.ip") ?? ev.src_ip;
  return {
    login,
    dbUser: s("database_principal_name"),
    role: s("db.user.role"),
    statement,
    database: s("database_name", "db.name", "database.name"),
    instance,
    server,
    engine: engineOf(ev, r),
    schema: s("schema_name", "db.schema") ?? tSchema,
    object: s("object_name", "db.object") ?? tObject,
    clientIp,
    clientHost: s("host_name", "source.hostname"),
    serverIp: s("destination.ip") ?? ev.dst_ip,
    serverPort: ev.dst_port ?? n("destination.port"),
    clientPort: ev.src_port ?? n("source.port"),
    app: s("application_name", "application.name", "db.application_name"),
    isLogin,
    failed,
    verb: op && op !== "CONNECT" && /^[A-Z]+$/.test(op) ? op : verbOf(statement),
    rows: n("db.rows_returned", "query.rows_returned", "response_rows", "db.rows_affected"),
    rowsExamined: n("db.rows_examined"),
    durationMs: n("db.duration_ms", "query.duration", "duration_milliseconds"),
    error: s("sql.error.message", "db.auth.error"),
    errorCode: s("sql.error.code"),
    sessionId: n("session_id", "db.session.id"),
    sessionStartMs: (() => { const t = Date.parse(s("session.start") ?? ""); return Number.isFinite(t) ? t : undefined; })(),
  };
}

export const DEFAULT_PORT: Record<DbEngine, number> = { mssql: 1433, postgresql: 5432, mysql: 3306, oracle: 1521, db2: 50000 };

/** The database server's address: the row's, else the one the story / company gives that host. */
export function serverIpOf(ctx: NativeCtx, f: DbFacts): string | undefined {
  if (f.serverIp) return f.serverIp;
  return f.server ? hostIpFor(ctx, f.server) : undefined;
}

/**
 * One client connection: a pooled or interactive connection lives for a while and carries many
 * statements. The connection of a row is the hour-long window it falls in, offset per client + login +
 * server, so every statement of one window shares the connection's start, source port and session id,
 * and the start is never after the statement.
 */
const WINDOW_MS = 3_600_000;
export function connectionOf(ctx: NativeCtx, f: DbFacts, timeMs: number): { key: string; startMs: number } {
  const who = `${f.clientIp ?? f.clientHost ?? "?"}:${(f.login ?? "").toLowerCase()}:${(f.server ?? "").toLowerCase()}`;
  const offset = ctx.int(`db:conn-offset:${who}`, 0, WINDOW_MS / 1000 - 1) * 1000;
  const index = Math.floor((timeMs - offset) / WINDOW_MS);
  return { key: `${who}:${index}`, startMs: index * WINDOW_MS + offset };
}

/** A client's ephemeral source port, stable for one connection. */
export function clientPortOf(ctx: NativeCtx, f: DbFacts, timeMs: number): number {
  if (f.clientPort) return f.clientPort;
  return ctx.int(`db:sport:${connectionOf(ctx, f, timeMs).key}`, 49152, 65000);
}

/** The session start: the login itself for a login, the authored start when it is before the row, else the connection's start. */
export function sessionStartOf(ctx: NativeCtx, f: DbFacts, ev: TelemetryEvent): number {
  const t = Date.parse(ev.ts);
  if (f.isLogin) return t;
  if (f.sessionStartMs !== undefined && f.sessionStartMs <= t && t - f.sessionStartMs < 12 * 3_600_000) return f.sessionStartMs;
  return connectionOf(ctx, f, t).startMs;
}

/** "YYYY-MM-DD HH:MM:SS" in UTC, with `frac` fractional digits (0 = none). */
export function utcSpace(ms: number, frac = 0): string {
  const iso = new Date(ms).toISOString();
  const base = `${iso.slice(0, 10)} ${iso.slice(11, 19)}`;
  if (!frac) return base;
  return `${base}.${(iso.slice(20, 23) + "0".repeat(frac)).slice(0, frac)}`;
}
