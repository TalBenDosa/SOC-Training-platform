/**
 * Microsoft SQL Server Audit, native module. No card in docs/log-schemas: the record is ONE row of
 * `SELECT * FROM sys.fn_get_audit_file('<path>\*.sqlaudit', DEFAULT, DEFAULT)`, the table the
 * function returns as Microsoft Learn documents it ("sys.fn_get_audit_file (Transact-SQL)", Tables
 * returned). The columns are the ones an on-premises SQL Server 2019 / 2022 instance returns:
 * event_time (datetime2, UTC) ... host_name. The columns Microsoft marks "Applies to: Azure SQL
 * Database / SQL Managed Instance only" (duration_milliseconds, response_rows, affected_rows,
 * connection_id, data_sensitivity_information, ledger_*, obo_*, is_local_secondary_replica,
 * external_policy_permissions_checked) are NOT printed: a .sqlaudit file of an on-premises server
 * does not have them, whatever the authored row carries.
 *
 * Every row prints the same column set (a result set has fixed columns; a column that does not apply
 * is '' or NULL), so attack and routine rows look alike. Values keep the column types: int / bigint /
 * smallint / bit as numbers, varbinary as the 0x... text SSMS shows, sysname / nvarchar as strings.
 *
 * Input: `db_monitor` events of the SQL Server Audit vendor. Authored rows already carry the
 * function's own columns (action_id, class_type, session_id, server_principal_name, statement,
 * client_ip, application_name, host_name, file_name, audit_file_offset ...), which win; event_time is
 * always printed from the row's own time, so a re-timed row keeps one instant. A row in the DAM
 * vocabulary (db.user / db.statement / source.ip ...) of a SQL Server database renders too; another
 * engine's row (PostgreSQL, MySQL, Oracle) is null: SQL Server Audit does not see it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { accountSid } from "./_sid";
import { connectionOf, dbFacts, rawOf, utcSpace, type DbFacts } from "./_db-common";

/** The columns of sys.fn_get_audit_file on SQL Server 2019 / 2022, in the function's order. */
export const COLUMNS = [
  "event_time", "sequence_number", "action_id", "succeeded", "permission_bitmask", "is_column_permission", "session_id",
  "server_principal_id", "database_principal_id", "target_server_principal_id", "target_database_principal_id", "object_id", "class_type",
  "session_server_principal_name", "server_principal_name", "server_principal_sid", "database_principal_name",
  "target_server_principal_name", "target_server_principal_sid", "target_database_principal_name", "server_instance_name",
  "database_name", "schema_name", "object_name", "statement", "additional_information", "file_name", "audit_file_offset",
  "user_defined_event_id", "user_defined_information", "audit_schema_version", "sequence_group_id", "transaction_id",
  "client_ip", "application_name", "host_name",
];
/** The audit action ids (sys.dm_audit_actions) this module prints. */
export const ACTIONS: Record<string, string> = {
  LGIS: "LOGIN SUCCEEDED", LGIF: "LOGIN FAILED", LGO: "LOGOUT", SL: "SELECT", IN: "INSERT", UP: "UPDATE", DL: "DELETE", EX: "EXECUTE",
  G: "GRANT", R: "REVOKE", D: "DENY", BA: "BACKUP", RS: "RESTORE", AL: "ALTER", CR: "CREATE", DR: "DROP", TO: "TRANSFER OWNERSHIP",
};
const kind: KindSchema = { required: COLUMNS, optional: [] };

const schema: SourceSchema = {
  sourceId: "mssql_audit", category: "database", card: "(none: sys.fn_get_audit_file result set, Microsoft Learn)", product: "Microsoft SQL Server Audit",
  format: "json", vendorMatch: ["sql server audit", "mssql audit", "microsoft sql audit"], telemetrySources: ["db_monitor"],
  kinds: Object.fromEntries(Object.keys(ACTIONS).map(a => [a, kind])),
};

export function kindOf(record: Record<string, unknown>): string | null {
  const a = typeof record.action_id === "string" ? record.action_id.trim() : "";
  return a && ACTIONS[a] && "event_time" in record && "server_instance_name" in record ? a : null;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));
const ZERO16 = `0x${"0".repeat(32)}`;
const VERB_ACTION: Record<string, string> = {
  SELECT: "SL", WITH: "SL", INSERT: "IN", UPDATE: "UP", DELETE: "DL", MERGE: "UP", EXEC: "EX", EXECUTE: "EX", GRANT: "G", REVOKE: "R", DENY: "D",
  BACKUP: "BA", RESTORE: "RS", ALTER: "AL", CREATE: "CR", DROP: "DR", TRUNCATE: "DL",
};

function actionOf(f: DbFacts, authored: string | undefined): string {
  if (authored && ACTIONS[authored.trim()]) return authored.trim();
  if (f.isLogin) return f.failed ? "LGIF" : "LGIS";
  return VERB_ACTION[f.verb ?? ""] ?? "SL";
}

function classOf(action: string, f: DbFacts): string {
  if (action === "LGIS" || action === "LGIF" || action === "LGO") return "LX";
  if (action === "BA" || action === "RS") return "DB";
  const o = (f.object ?? "").toLowerCase();
  if (action === "EX") return /^xp_/.test(o) ? "X" : "P";
  if (f.schema && /^information_schema$/i.test(f.schema)) return "V";
  if (/^vw_/i.test(o)) return "V";
  return "U";
}

/** Little-endian binary of a Windows SID, as SQL Server stores a Windows login's sid. */
function sidBinary(sid: string): string | undefined {
  const m = /^S-1-(\d+)((?:-\d+)+)$/.exec(sid);
  if (!m) return undefined;
  const subs = m[2].split("-").filter(Boolean).map(Number);
  const le = (n: number) => [0, 8, 16, 24].map(b => ((n >>> b) & 0xff).toString(16).padStart(2, "0")).join("");
  return `0x01${subs.length.toString(16).padStart(2, "0")}${Number(m[1]).toString(16).padStart(12, "0")}${subs.map(le).join("")}`.toUpperCase().replace(/^0X/, "0x");
}

function loginSid(ctx: NativeCtx, login: string): string {
  const l = login.toLowerCase();
  if (l === "sa") return "0x01";
  if (/^nt service\\/.test(l)) return `0x010600000000000550000000${ctx.hex(`mssql:ntservice:${l}`, 40).toUpperCase()}`;
  if (l.includes("\\")) return sidBinary(accountSid(ctx, login)) ?? `0x${ctx.hex(`mssql:sid:${l}`, 32).toUpperCase()}`;
  return `0x${ctx.hex(`mssql:sid:${l}`, 32).toUpperCase()}`;
}

/** "server\instance" as the row names it, else the server's own name (a default instance). */
const instanceOf = (f: DbFacts, ev: TelemetryEvent) => f.instance ?? (ev.hostname ?? "SQL01").toUpperCase();

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = dbFacts(ev);
  if (f.engine && f.engine !== "mssql") return null;
  const r = rawOf(ev);
  const a = (k: string) => str(r[k]);
  const ms = Date.parse(ev.ts);
  if (!Number.isFinite(ms)) return null;
  const action = actionOf(f, a("action_id"));
  const isLogin = action === "LGIS" || action === "LGIF" || action === "LGO";
  const instance = instanceOf(f, ev);
  const server = instance.split("\\")[0];
  const login = f.login ?? "";
  const loginKey = login.toLowerCase();
  const succeededRaw = a("succeeded");
  const succeeded = succeededRaw !== undefined ? (/^(1|true)$/i.test(succeededRaw) ? 1 : 0) : (f.failed ? 0 : 1);
  const dbUser = isLogin ? "" : (f.dbUser ?? (f.role === "sysadmin" || f.role === "db_owner" ? "dbo" : login));
  const database = f.database ?? "";
  const schemaName = isLogin || action === "BA" || action === "RS" ? (a("schema_name") ?? "") : (f.schema ?? (f.object ? "dbo" : ""));
  const objectName = isLogin ? "" : (f.object ?? (action === "BA" || action === "RS" ? database : ""));
  const statement = f.statement ?? (action === "LGIF" ? `Login failed for user '${login}'. Reason: Password did not match that for the login provided. [CLIENT: ${f.clientIp ?? "<local machine>"}]` : "");
  const grantee = action === "G" || action === "R" || action === "D" ? /\bTO\s+\[?([^\]\s;]+)\]?/i.exec(statement)?.[1] : undefined;
  const local = !f.clientIp || f.clientIp === "<local machine>" || (f.clientHost && f.clientHost.toUpperCase() === server);
  const clientIp = a("client_ip") ?? (local ? "<local machine>" : f.clientIp!);
  const sessionId = f.sessionId ?? (action === "LGIF" ? 0 : ctx.int(`mssql:session:${connectionOf(ctx, f, ms).key}`, 51, 420));
  const fileTime = (Math.floor(ms / 86_400_000) * 86_400_000 + 11_644_473_600_000) * 10_000;
  const auditGuid = ctx.uuid(`mssql:audit:${server}`).toUpperCase();
  const record: Record<string, unknown> = {
    event_time: utcSpace(ms, 7),
    sequence_number: 1,
    action_id: action,
    succeeded,
    permission_bitmask: ZERO16,
    is_column_permission: 0,
    session_id: sessionId,
    server_principal_id: loginKey === "sa" ? 1 : ctx.int(`mssql:principal:${server}:${loginKey}`, 256, 420),
    database_principal_id: isLogin ? 0 : dbUser.toLowerCase() === "dbo" ? 1 : ctx.int(`mssql:dbprincipal:${server}:${database.toLowerCase()}:${dbUser.toLowerCase()}`, 5, 60),
    target_server_principal_id: 0,
    target_database_principal_id: grantee ? ctx.int(`mssql:dbprincipal:${server}:${database.toLowerCase()}:${grantee.toLowerCase()}`, 5, 60) : 0,
    object_id: isLogin ? 0 : action === "BA" || action === "RS" ? ctx.int(`mssql:dbid:${server}:${database.toLowerCase()}`, 5, 40) : ctx.int(`mssql:object:${server}:${database.toLowerCase()}:${schemaName.toLowerCase()}.${objectName.toLowerCase()}`, 245_575_913, 2_146_106_686),
    class_type: a("class_type") ?? classOf(action, f),
    session_server_principal_name: login,
    server_principal_name: login,
    server_principal_sid: login ? loginSid(ctx, login) : null,
    database_principal_name: dbUser,
    target_server_principal_name: "",
    target_server_principal_sid: null,
    target_database_principal_name: grantee ?? "",
    server_instance_name: instance,
    database_name: database,
    schema_name: schemaName,
    object_name: objectName,
    statement,
    additional_information: null,
    file_name: a("file_name") ?? `D:\\SQLAudit\\${ctx.org.toUpperCase()}_Server_Audit_${auditGuid}_0_${fileTime}.sqlaudit`,
    audit_file_offset: Number(a("audit_file_offset") ?? ctx.int(`mssql:offset:${ev.id}`, 2, 4000) * 512),
    user_defined_event_id: null,
    user_defined_information: "",
    audit_schema_version: 1,
    sequence_group_id: `0x${ctx.hex(`mssql:seqgroup:${ev.id}`, 32).toUpperCase()}`,
    transaction_id: isLogin ? 0 : ctx.int(`mssql:xact:${ev.id}`, 1_000_000, 99_999_999),
    client_ip: clientIp,
    application_name: f.app ?? "",
    host_name: f.clientHost ?? (local ? server : ""),
  };
  return { sourceId: "mssql_audit", kind: action, format: "json", record, timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "mssql_audit.xp_cmdshell", title: "xp_cmdshell executed on a SQL Server", sourceId: "mssql_audit", kinds: ["EX"],
    severity: "high", mitre: ["T1505.001", "T1059.003"],
    description: "The extended stored procedure xp_cmdshell runs an operating-system command as the SQL Server service account. Applications never need it; an attacker who reaches the database (stolen service credentials, SQL injection) uses it to step from the database to the server.",
    logic: "KQL (fn_get_audit_file export): SqlAudit | where action_id == \"EX\" and object_name =~ \"xp_cmdshell\" | project event_time, server_principal_name, client_ip, application_name, statement",
    match: { any: [{ field: "object_name", op: "eq", value: "xp_cmdshell" }, { field: "statement", op: "icontains", value: "xp_cmdshell" }] },
    falsePositives: ["Legacy maintenance jobs that shell out (rare; such jobs run as SQL Agent, not as an application login)"],
  },
  {
    id: "mssql_audit.union_select_from_app", title: "UNION SELECT in a statement sent by an application login", sourceId: "mssql_audit", kinds: ["SL"],
    severity: "high", mitre: ["T1190"],
    description: "An application builds its queries from code; a UNION SELECT reaching a business table through the application's own login, joined onto an ordinary lookup, is the shape of a SQL injection that the web tier passed through.",
    logic: "KQL: SqlAudit | where action_id == \"SL\" and statement matches regex @\"(?i)union\\s+(all\\s+)?select\" and application_name !has \"Management Studio\"",
    match: { all: [{ field: "statement", op: "regex", value: "union\\s+(all\\s+)?select" }, { not: { field: "application_name", op: "icontains", value: "Management Studio" } }] },
    falsePositives: ["Reporting code that really uses UNION (it is in the application's normal statement set and repeats every day)"],
  },
  {
    id: "mssql_audit.failed_login_burst", title: "Repeated failed SQL logins from one client", sourceId: "mssql_audit", kinds: ["LGIF"],
    severity: "medium", mitre: ["T1110.001"],
    description: "Five or more LOGIN FAILED records from one client address in ten minutes: a password guess against sa or a service login, or an application deployed with a stale password.",
    logic: "KQL: SqlAudit | where action_id == \"LGIF\" | summarize count() by client_ip, bin(event_time, 10m) | where count_ >= 5",
    match: { field: "action_id", op: "eq", value: "LGIF" },
    threshold: { groupBy: ["client_ip"], count: 5, windowSec: 600 },
    falsePositives: ["An application or job after a password rotation retries with the old password"],
  },
  {
    id: "mssql_audit.schema_enumeration", title: "Catalog views read for the table and column map", sourceId: "mssql_audit", kinds: ["SL"],
    severity: "low", mitre: ["T1213"],
    description: "A SELECT on INFORMATION_SCHEMA or sys.tables / sys.columns lists every table and column. DBAs do it in Management Studio; the same read through an application login is the reconnaissance step of an injection.",
    logic: "KQL: SqlAudit | where action_id == \"SL\" and (schema_name =~ \"INFORMATION_SCHEMA\" or statement has_any (\"information_schema\", \"sys.tables\", \"sys.columns\"))",
    match: { any: [{ field: "schema_name", op: "eq", value: "INFORMATION_SCHEMA" }, { field: "statement", op: "regex", value: "information_schema|sys\\.(tables|columns)" }] },
    falsePositives: ["Schema reviews and migrations run by DBAs from Management Studio"],
  },
  {
    id: "mssql_audit.permission_grant", title: "Permission granted on a database object", sourceId: "mssql_audit", kinds: ["G"],
    severity: "medium", mitre: ["T1098"],
    description: "A GRANT widens what a principal can read or change. Check that a change request exists and that the grantee is the expected service account.",
    logic: "KQL: SqlAudit | where action_id == \"G\" | project event_time, server_principal_name, target_database_principal_name, object_name, statement",
    match: { field: "action_id", op: "eq", value: "G" },
    falsePositives: ["Planned access changes carried out by the DBA team"],
  },
  {
    id: "mssql_audit.bulk_read_sensitive", title: "Read of a payment or customer table by an interactive tool", sourceId: "mssql_audit", kinds: ["SL"],
    severity: "medium", mitre: ["T1005"],
    description: "A SELECT on a table that holds customer or payment data, sent from SQLCMD or a query tool rather than the application. Confirm the person and the reason with the data owner.",
    logic: "KQL: SqlAudit | where action_id == \"SL\" and object_name in~ (\"Customers\", \"WireTransfers\", \"transactions\") and application_name has_any (\"SQLCMD\", \"Management Studio\")",
    match: { all: [{ field: "object_name", op: "in", value: ["Customers", "WireTransfers", "transactions"] }, { any: [{ field: "application_name", op: "icontains", value: "SQLCMD" }, { field: "application_name", op: "icontains", value: "Management Studio" }] }] },
    falsePositives: ["Month-end reconciliation run by finance DBAs"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
