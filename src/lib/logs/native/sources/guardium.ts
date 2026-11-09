/**
 * IBM Guardium Data Protection, policy-rule alert over syslog in LEEF, native module. No card in
 * docs/log-schemas: the format is the one IBM documents for Guardium's QRadar (LEEF) message
 * template, in IBM's own sample events (IBM QRadar DSM Configuration Guide, "IBM Guardium sample
 * event messages"):
 *
 *   <30>Aug 19 12:33:31 ibm.guardium.test guard_sender[4486]: LEEF:1.0|IBM|Guardium|8.0|Login failures|
 *   ruleID=20026|ruleDesc=Login failures|severity=INFO|devTime=2013-8-19 6:34:41|serverType=DB2|
 *   classification=|category=|dbProtocolVersion=3.0|usrName=|sourceProgram=DB2JCC_APPLICATION|
 *   start=1376908481000|dbUser=user|dst=10.30.2.124|dstPort=50000|src=10.30.5.152|srcPort=38754|
 *   protocol=TCP|type=LOGIN_FAILED|violationID=15|sql=|error=08001-XXXX:30082-01
 *
 * The keys are the template's fixed set, always printed in that order, an empty value when the rule has
 * none (classification=, usrName=), so a routine row and an attack row have the same shape. The values
 * are the alert template variables IBM lists ("The alert message template": %%ruleID, %%ruleDescription,
 * %%severity, %%serverType, %%DBUser, %%serverIP, %%clientIP, %%SourceProgram, %%sessionStart,
 * %%requestType, %%violationID, %%SQLString, %%lastError ...). severity is Guardium's rule severity
 * (INFO / LOW / MED / HIGH); devTime is the appliance's local time, unpadded (yyyy-M-d H:mm:ss); start is
 * the session start in epoch milliseconds; type is the request type (SQL_LANG for a statement,
 * LOGIN_FAILED for a failed login).
 *
 * Record: flat, the syslog header (`timestamp` local "Mmm dd HH:MM:SS", `hostname` the collector,
 * `appName` guard_sender, `procId`), the LEEF header (`LEEFVersion`, `DeviceVendor`, `DeviceProduct`,
 * `DeviceVersion`, `EventID` = the rule description), then the attributes verbatim. Every value is a
 * string. `rawLine` = the syslog line rebuilt from the same values.
 *
 * Which policy rule fires is decided by what the statement is, never by whether the row is an attack:
 * a failed login hits "Login failures" (IBM's own rule name in the sample), an extended / configuration
 * procedure (xp_, sp_configure) hits the privileged-procedure alert, DDL / DCL the DDL rule, and every
 * other statement the sensitive-objects logging rule.
 *
 * Input: `db_monitor` events of the Guardium vendor, in the DAM vocabulary (db.user, db.statement,
 * db.instance, source.ip, application.name) or the scenario packs' (database.*, query.*, sql.*).
 * Evidence carried verbatim: database user, statement, client and server address, client program.
 * A successful login is null: Guardium's policy alerts have no successful-login record.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { localParts } from "./_dnsShared";
import { clientPortOf, dbFacts, DEFAULT_PORT, serverIpOf, sessionStartOf, type DbEngine, type DbFacts } from "./_db-common";

const HEADER = ["timestamp", "hostname", "appName", "procId", "LEEFVersion", "DeviceVendor", "DeviceProduct", "DeviceVersion", "EventID"];
/** The template's attributes, in IBM's sample order. */
export const ATTRS = ["ruleID", "ruleDesc", "severity", "devTime", "serverType", "classification", "category", "dbProtocolVersion", "usrName",
  "sourceProgram", "start", "dbUser", "dst", "dstPort", "src", "srcPort", "protocol", "type", "violationID", "sql", "error"];
const kind: KindSchema = { required: [...HEADER, ...ATTRS], optional: [] };

const schema: SourceSchema = {
  sourceId: "guardium", category: "database", card: "(none: IBM QRadar DSM guide, IBM Guardium sample event messages)", product: "IBM Guardium",
  format: "syslog", vendorMatch: ["guardium"], telemetrySources: ["db_monitor"],
  kinds: { SQL_LANG: kind, LOGIN_FAILED: kind },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.DeviceProduct === "Guardium" && (record.type === "SQL_LANG" || record.type === "LOGIN_FAILED") ? String(record.type) : null;
}

const SERVER_TYPE: Record<DbEngine, string> = { mssql: "MS SQL SERVER", postgresql: "POSTGRESQL", mysql: "MYSQL", oracle: "ORACLE", db2: "DB2" };
/** The wire protocol version Guardium reports per server type (MS SQL SERVER 8.0 and DB2 3.0 as in IBM's samples). */
const PROTOCOL_VERSION: Record<DbEngine, string> = { mssql: "8.0", postgresql: "3.0", mysql: "10.0", oracle: "", db2: "3.0" };

function engineOf(f: DbFacts): DbEngine {
  if (f.engine) return f.engine;
  const byPort = (Object.entries(DEFAULT_PORT) as [DbEngine, number][]).find(([, p]) => p === f.serverPort)?.[0];
  return byPort ?? "mssql";
}

interface Rule { desc: string; severity: "INFO" | "LOW" | "MED" | "HIGH"; classification: string; category: string; id?: string }
const RULES = {
  login: { desc: "Login failures", severity: "INFO", classification: "", category: "", id: "20026" },
  privileged: { desc: "Privileged Procedure Execution - Alert", severity: "MED", classification: "Violation", category: "Security" },
  ddl: { desc: "DDL and DCL Commands - Log Full Details", severity: "INFO", classification: "", category: "" },
  access: { desc: "Sensitive Objects Access - Log Full Details", severity: "INFO", classification: "", category: "" },
} satisfies Record<string, Rule>;

function ruleOf(f: DbFacts): Rule {
  if (f.isLogin) return RULES.login;
  const s = f.statement ?? "";
  if (/\bxp_\w+|\bsp_configure\b|\bsp_addsrvrolemember\b|\bsp_OACreate\b/i.test(s)) return RULES.privileged;
  if (["GRANT", "REVOKE", "DENY", "CREATE", "ALTER", "DROP", "TRUNCATE"].includes(f.verb ?? "")) return RULES.ddl;
  return RULES.access;
}

const p2 = (n: number) => String(n).padStart(2, "0");
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** The syslog line, rebuilt from the record (LEEF 1.0 header, attributes joined by "|"). */
export function leefLine(r: Record<string, string>): string {
  return `${r.timestamp} ${r.hostname} ${r.appName}[${r.procId}]: LEEF:${r.LEEFVersion}|${r.DeviceVendor}|${r.DeviceProduct}|${r.DeviceVersion}|${r.EventID}|` +
    ATTRS.map(k => `${k}=${r[k] ?? ""}`).join("|");
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = dbFacts(ev);
  const ms = Date.parse(ev.ts);
  if (!Number.isFinite(ms)) return null;
  if (f.isLogin && !f.failed) return null;
  if (!f.isLogin && !f.statement) return null;
  const engine = engineOf(f);
  const rule = ruleOf(f);
  const t = localParts(ms, ctx.companyId);
  const record: Record<string, string> = {
    timestamp: `${MON[t.month - 1]} ${String(t.day).padStart(2, " ")} ${p2(t.h)}:${p2(t.mi)}:${p2(t.sec)}`,
    hostname: `gcoll01.${ctx.domain}`,
    appName: "guard_sender",
    procId: String(ctx.int("guardium:sender-pid", 2100, 9800)),
    LEEFVersion: "1.0",
    DeviceVendor: "IBM",
    DeviceProduct: "Guardium",
    DeviceVersion: "12.0",
    EventID: rule.desc,
    ruleID: rule.id ?? String(ctx.int(`guardium:rule:${rule.desc}`, 101, 420)),
    ruleDesc: rule.desc,
    severity: rule.severity,
    devTime: `${t.year}-${t.month}-${t.day} ${t.h}:${p2(t.mi)}:${p2(t.sec)}`,
    serverType: SERVER_TYPE[engine],
    classification: rule.classification,
    category: rule.category,
    dbProtocolVersion: PROTOCOL_VERSION[engine],
    usrName: "",
    sourceProgram: f.app ?? "",
    start: String(sessionStartOf(ctx, f, ev)),
    dbUser: f.login ?? "",
    dst: serverIpOf(ctx, f) ?? "",
    dstPort: String(f.serverPort ?? DEFAULT_PORT[engine]),
    src: f.clientIp ?? "",
    srcPort: String(clientPortOf(ctx, f, ms)),
    protocol: "TCP",
    type: f.isLogin ? "LOGIN_FAILED" : "SQL_LANG",
    violationID: String(ctx.int(`guardium:violation:${ev.id}`, 1000, 999_999)),
    sql: f.isLogin ? "" : f.statement ?? "",
    error: f.error ?? f.errorCode ?? "",
  };
  return { sourceId: "guardium", kind: record.type, format: "syslog", record, rawLine: leefLine(record), timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "guardium.xp_cmdshell", title: "Operating-system command run through the database", sourceId: "guardium", kinds: ["SQL_LANG"],
    severity: "high", mitre: ["T1505.001", "T1059.003"],
    description: "Guardium saw xp_cmdshell in the SQL stream: the database server ran an operating-system command as its service account. Applications never send it; after a SQL injection or with a stolen service login it is how an attacker reaches the server itself.",
    logic: "SPL: index=guardium sourcetype=ibm:guardium:leef type=SQL_LANG sql=\"*xp_cmdshell*\" | table devTime dbUser src sourceProgram sql",
    match: { field: "sql", op: "icontains", value: "xp_cmdshell" },
    falsePositives: ["A legacy maintenance job that shells out (it runs from SQL Agent on the server itself, not from a client)"],
  },
  {
    id: "guardium.union_injection", title: "UNION SELECT appended to an application query", sourceId: "guardium", kinds: ["SQL_LANG"],
    severity: "high", mitre: ["T1190"],
    description: "A statement from the application's own login that ends an ordinary lookup and appends UNION SELECT, often with a comment (--) to cut the rest: the classic shape of SQL injection passed through by the web tier.",
    logic: "SPL: index=guardium type=SQL_LANG | regex sql=\"(?i)union\\s+(all\\s+)?select\" | stats count values(sql) by dbUser src",
    match: { field: "sql", op: "regex", value: "union\\s+(all\\s+)?select" },
    falsePositives: ["Reporting code that really uses UNION (it repeats every day from the reporting server)"],
  },
  {
    id: "guardium.error_based_probe", title: "Type-conversion error raised by an injected statement", sourceId: "guardium", kinds: ["SQL_LANG"],
    severity: "medium", mitre: ["T1190"],
    description: "A statement that forces a conversion of catalog data (CONVERT(int, (SELECT ... FROM sys.tables))) and fails: error-based injection reads the database one error message at a time.",
    logic: "SPL: index=guardium type=SQL_LANG error!=\"\" sql=\"*CONVERT(int*\" | table devTime dbUser src sql error",
    match: { all: [{ field: "sql", op: "regex", value: "convert\\s*\\(\\s*int" }, { field: "error", op: "neq", value: "" }] },
    falsePositives: ["Application bugs that cast user input (the same statement fails for every user, without catalog views)"],
  },
  {
    id: "guardium.login_failure_burst", title: "Failed database logins from one client", sourceId: "guardium", kinds: ["LOGIN_FAILED"],
    severity: "medium", mitre: ["T1110.001"],
    description: "Five or more Login failures records from one client address in ten minutes: a password guess against a database account, or a tool still using an old password.",
    logic: "SPL: index=guardium type=LOGIN_FAILED | bin _time span=10m | stats count by src dbUser _time | where count >= 5",
    match: { field: "type", op: "eq", value: "LOGIN_FAILED" },
    threshold: { groupBy: ["src"], count: 5, windowSec: 600 },
    falsePositives: ["A job or temporary analyst account after a password change"],
  },
  {
    id: "guardium.catalog_discovery", title: "Catalog views read for the table and column map", sourceId: "guardium", kinds: ["SQL_LANG"],
    severity: "low", mitre: ["T1213"],
    description: "A read of information_schema or sys.tables lists every table and column. A DBA's tool does it; the same read from the application's login is the reconnaissance step of an injection.",
    logic: "SPL: index=guardium type=SQL_LANG | regex sql=\"(?i)information_schema|sys\\.tables\" | table devTime dbUser src sourceProgram sql",
    match: { field: "sql", op: "regex", value: "information_schema|sys\\.tables" },
    falsePositives: ["Schema reviews from pgAdmin / Management Studio by the DBA team"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
