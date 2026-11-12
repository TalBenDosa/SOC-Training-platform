/**
 * Web injection round (Tal, 2026-11-12), part data: blind SQL, NoSQL operators, LDAP filters, JWT tampering.
 *
 * Effects only (owner decision 2026-11-12): an injected input appears as the token a rule or an analyst
 * recognises (SLEEP(, WAITFOR, [$ne], *)(, the unsigned-token header prefix) with the rest elided as "...";
 * the incident is told by what the logs record: the database audit's statement shape and query time, the
 * origin's status and size, the directory's and the identity platform's own records.
 *
 * Each family gives the single-player dashboard one variant and Team Training another (WebStoryDef.mode).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { winRecord } from "../core-stories/ad";
import { bytesText, changeFields, clock, ticket, type WebStoryDef } from "./entry";

const IA = "Initial Access", CRED = "Credential Access", COLLECT = "Collection", PERSIST = "Persistence", DISC = "Discovery";
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15";
const SCANNER = "Mozilla/5.0 (compatible; ASV-Scanner/9.6; +https://scanner.example/about)";
const PY = "python-requests/2.31.0";
const OKHTTP = "okhttp/4.12.0";
const PENTEST = "Mozilla/5.0 (compatible; PentestCo-Assessment/2026)";

/** A sign-in that succeeded on an unregistered device has no failure text and no device id: the record leaves them out. */
const noEmpty = (e: TelemetryEvent): TelemetryEvent => ({ ...e, raw: Object.fromEntries(Object.entries(e.raw ?? {}).filter(([, v]) => v !== "")) });

/** One statement as MySQL Enterprise Audit records it (the audit plugin's general/status event). */
function mysqlRow(o: { id: string; ts: string; host: string; ip: string; client: string; user: string; db: string; statement: string; object: string; ms: number; rows: number; examined: number;
  description: string; severity?: TelemetryEvent["severity"]; mitre?: string; tactic?: string; isDetection?: boolean; isBaseline?: boolean }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "db_monitor", vendor: "MySQL Enterprise Audit", event_type: "db_query", severity: o.severity ?? "low",
    hostname: o.host, src_ip: o.client, dst_ip: o.ip, dst_port: 3306, protocol: "tcp", description: o.description,
    ...(o.mitre ? { mitre_technique: o.mitre, mitre_tactic: o.tactic } : {}), ...(o.isDetection ? { is_detection: true } : {}), ...(o.isBaseline ? { is_baseline: true } : {}),
    raw: {
      "mysql.audit.class": "general", "mysql.audit.command_class": "select", "mysql.audit.login.ip": o.client,
      "db.user": o.user, "db.name": o.db, "db.statement": o.statement, "db.operation": "SELECT", "db.object": o.object,
      "db.rows_returned": o.rows, "db.rows_examined": o.examined, "db.duration_ms": o.ms, "source.ip": o.client,
    },
  };
}

/** One row of a SQL Server Audit file (sys.fn_get_audit_file): the instance, the principal, the statement. */
function sqlAuditRow(o: { id: string; ts: string; host: string; instance: string; ip: string; client: string; login: string; db: string; action: string; statement: string; object: string; app: string;
  description: string; severity?: TelemetryEvent["severity"]; mitre?: string; tactic?: string; isDetection?: boolean; isBaseline?: boolean; verdict?: "fp"; fp?: string }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "db_monitor", vendor: "Microsoft SQL Server Audit", event_type: "db_query", severity: o.severity ?? "low",
    hostname: o.host, src_ip: o.client === "<local machine>" ? o.ip : o.client, dst_ip: o.ip, dst_port: 1433, protocol: "tcp", description: o.description,
    ...(o.mitre ? { mitre_technique: o.mitre, mitre_tactic: o.tactic } : {}), ...(o.isDetection ? { is_detection: true } : {}), ...(o.isBaseline ? { is_baseline: true } : {}),
    ...(o.verdict ? { expected_verdict: o.verdict, fp_explanation: o.fp } : {}),
    raw: {
      action_id: o.action, server_instance_name: o.instance, database_name: o.db, server_principal_name: o.login, statement: o.statement,
      client_ip: o.client, application_name: o.app, schema_name: "dbo", object_name: o.object, succeeded: "true",
    },
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// Blind SQL injection, single-player: a shop catalog search, nginx and MySQL, WAF policy in Detection.
// The page never shows a result; the database audit shows the query time each guess took.
// ══════════════════════════════════════════════════════════════════════════════
function sqliCatalog(): TelemetryEvent[] {
  const T = clock("2026-10-13T10:00:00Z");
  const w: WebSite = { site: "catalog.nexacorp.com", host: "web-catalog-01.nexacorp.com", ip: "10.20.41.31", server: "nginx", wafMode: "Detection" };
  const db = { host: "db-catalog-01.nexacorp.com", ip: "10.20.41.32" };
  const atk = "203.0.113.166", scan = "203.0.113.167", ua = PY;
  const sql = (id: string, min: number, statement: string, object: string, ms: number, rows: number, examined: number, description: string, extra = {}) =>
    mysqlRow({ id, ts: T(min), host: db.host, ip: db.ip, client: w.ip, user: "catalog_app", db: "catalog", statement, object, ms, rows, examined, description, ...extra });
  const probe = (id: string, min: number, q: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, path: "/catalog/search", query: q, action: "count", rule: "sqli_query", matched: "SLEEP(",
    location: "ARGS:q", ua, bytes: 2210, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched SQL syntax in the q parameter of /catalog/search", ...extra });
  const guess = (id: string, min: number, ms: number, tail: string) => sql(id, min, `SELECT id, name, price FROM products WHERE name LIKE '%desk lamp' AND IF((SELECT ... FROM admin_sessions ...), SLEEP(5), 0)${tail}`,
    "products", ms, 0, 1184, `Catalog database ran a product search that read the admin session table (query time ${(ms / 1000).toFixed(3)} s)`, { severity: "medium", mitre: "T1539", tactic: CRED });
  return [
    ticket({ id: "web_sb_001", ts: T(0), table: "change_request", number: "CHG0044833", state: "Implement", severity: "informational",
      shortDescription: `External web vulnerability scan of the catalog site, source ${scan}`, description: "ServiceNow change CHG0044833 (Implement): external vulnerability scan of the catalog site",
      extra: changeFields({ requestedBy: "m.levi@nexacorp.com", group: "Security Operations", ci: "catalog-site", from: T(-30), hours: 6,
        detail: `Quarterly external vulnerability scan of the catalog site by the contracted scanning service from ${scan}, declared user agent ASV-Scanner (times UTC).` }) }),
    webAccess(w, { id: "web_sb_002", ts: T(3), srcIp: "198.51.100.15", path: "/catalog/search", query: "q=desk+lamp", bytes: 18420, ua: CHROME, isBaseline: true, description: "Catalog answered a product search" }),
    sql("web_sb_003", 3.01, "SELECT id, name, price FROM products WHERE name LIKE '%desk lamp%' ORDER BY rank LIMIT 24", "products", 38, 12, 912, "Catalog database ran a product search", { isBaseline: true }),
    wafRequest(w, { id: "web_sb_004", ts: T(12), srcIp: scan, path: "/catalog/item", query: "id=1042+AND+SLEEP(...)", status: 400, bytes: 188, action: "count", rule: "sqli_query", matched: "SLEEP(", location: "ARGS:id", ua: SCANNER,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The scan under CHG0044833: the change names the address, the scanner declares itself, and the item page refused the value with 400 before any query ran.", description: "WAF rule matched SQL syntax in the id parameter of /catalog/item" }),
    webAccess(w, { id: "web_sb_005", ts: T(12.01), srcIp: scan, path: "/catalog/item", query: "id=1042+AND+SLEEP(...)", status: 400, bytes: 188, ua: SCANNER, isBaseline: true, description: "Catalog refused an item request" }),
    probe("web_sb_006", 41, "q=desk+lamp%27...SLEEP(...)", { isDetection: true }),
    sql("web_sb_007", 41.01, "SELECT id, name, price FROM products WHERE name LIKE '%desk lamp' AND SLEEP(5) ...", "products", 5003, 0, 912, "Catalog database ran a product search (query time 5.003 s)",
      { severity: "high", isDetection: true, mitre: "T1190", tactic: IA }),
    webAccess(w, { id: "web_sb_008", ts: T(41.09), srcIp: atk, path: "/catalog/search", query: "q=desk+lamp%27...SLEEP(...)", bytes: 2210, ua, mitre: "T1190", tactic: IA, description: "Catalog answered a product search with no results (2,210 bytes out)" }),
    probe("web_sb_009", 44, "q=desk+lamp%27...IF(...SLEEP(...)...)"),
    guess("web_sb_010", 44.08, 5004, " ..."),
    guess("web_sb_011", 44.2, 41, " ... "),
    guess("web_sb_012", 44.4, 5002, " ...  "),
    webAccess(w, { id: "web_sb_013", ts: T(63), srcIp: atk, path: "/admin/orders/export", query: "format=csv", bytes: 9844112, ua, severity: "high", mitre: "T1213", tactic: COLLECT,
      description: `Catalog admin answered an order export (${bytesText(9844112)} bytes out)` }),
    sql("web_sb_014", 63.02, "SELECT o.id, o.created_at, c.email, o.total FROM orders o JOIN customers c ON c.id = o.customer_id ORDER BY o.id", "orders", 1830, 48211, 48211,
      "Catalog database answered the admin order export", { severity: "medium", mitre: "T1213", tactic: COLLECT }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// Blind SQL injection, Team Training: second order on a supplier portal, IIS and SQL Server. The registration
// is stored safely; the nightly digest job later builds dynamic SQL from it and runs it as a privileged login.
// ══════════════════════════════════════════════════════════════════════════════
function sqliSuppliers(): TelemetryEvent[] {
  const T = clock("2026-10-15T15:00:00Z");
  const w: WebSite = { site: "suppliers.nexacorp.com", host: "web-suppliers-01.nexacorp.com", ip: "10.20.41.35", server: "iis" };
  const db = { host: "db-suppliers-01.nexacorp.com", instance: "DB-SUPPLIERS-01", ip: "10.20.41.36" };
  const atk = "203.0.113.168", ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
  const JOB = "SQLAgent - TSQL JobStep (Job 0x6C1F2A9B: Step 1)", SQLCLIENT = "Core Microsoft SqlClient Data Provider";
  const audit = (id: string, min: number, o: { login: string; client: string; action: string; statement: string; object: string; app: string; description: string }, extra = {}) =>
    sqlAuditRow({ id, ts: T(min), host: db.host, instance: db.instance, ip: db.ip, db: "Suppliers", ...o, ...extra });
  return [
    webAccess(w, { id: "web_sm_001", ts: T(4), srcIp: "198.51.100.37", method: "POST", path: "/api/v2/suppliers/profile", sent: 1840, bytes: 512, ua: CHROME, isBaseline: true, description: "Supplier portal saved a supplier profile" }),
    audit("web_sm_002", 4.01, { login: "supplier_app", client: w.ip, action: "UP", statement: "UPDATE dbo.Suppliers SET Phone = @p1, Address = @p2 WHERE SupplierId = @p0", object: "Suppliers", app: SQLCLIENT,
      description: "Supplier database updated a supplier profile" }, { isBaseline: true }),
    wafRequest(w, { id: "web_sm_003", ts: T(31), srcIp: atk, method: "POST", path: "/api/v2/suppliers/register", action: "block", rule: "sqli_body", matched: "WAITFOR", location: "REQUEST_BODY", ua, sent: 1408,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched SQL syntax in a supplier registration" }),
    wafRequest(w, { id: "web_sm_004", ts: T(33), srcIp: atk, method: "POST", path: "/api/v2/suppliers/register", action: "allow", status: 201, bytes: 344, ua, sent: 1452, description: "WAF passed a supplier registration" }),
    webAccess(w, { id: "web_sm_005", ts: T(33.01), srcIp: atk, method: "POST", path: "/api/v2/suppliers/register", status: 201, sent: 1452, bytes: 344, ua, mitre: "T1190", tactic: IA,
      description: "Supplier portal created a supplier registration (1,452 bytes in, 344 bytes out)" }),
    audit("web_sm_006", 33.02, { login: "supplier_app", client: w.ip, action: "IN", statement: "INSERT INTO dbo.Suppliers (Name, Country, VatNumber, ContactEmail) VALUES (@p0, @p1, @p2, @p3)", object: "Suppliers",
      app: SQLCLIENT, description: "Supplier database stored a new supplier" }, { mitre: "T1190", tactic: IA }),
    ticket({ id: "web_sm_007", ts: T(240), table: "change_request", number: "CHG0044870", state: "Implement", severity: "informational",
      shortDescription: "Read-only reporting login rpt_viewer for the finance dashboard", description: "ServiceNow change CHG0044870 (Implement): reporting login for the finance dashboard",
      extra: changeFields({ requestedBy: "f.haddad@nexacorp.com", group: "Database Administration", ci: "DB-SUPPLIERS-01", from: T(230), hours: 2,
        detail: "Create SQL login rpt_viewer on DB-SUPPLIERS-01 with read access to the Suppliers reporting views for the finance dashboard. Run by the DBA team from the admin workstation." }) }),
    audit("web_sm_008", 246, { login: "NEXACORP\\dba.amir", client: "10.10.20.66", action: "CR", statement: "CREATE LOGIN [rpt_viewer] WITH PASSWORD = '******', CHECK_POLICY = ON", object: "rpt_viewer",
      app: "Microsoft SQL Server Management Studio - Query", description: "Supplier database server created a SQL login" },
      { severity: "high", isDetection: true, mitre: "T1136", tactic: PERSIST, verdict: "fp" as const,
        fp: "The reporting login CHG0044870 approved: a DBA ran it from the admin workstation through Management Studio, with the password policy on, and no role change follows." }),
    audit("web_sm_009", 660, { login: "svc_reports", client: "<local machine>", action: "EX", statement: "EXEC dbo.usp_SupplierDigest @since = '2026-10-15'", object: "usp_SupplierDigest", app: JOB,
      description: "Supplier database ran the nightly supplier digest job" }, { isBaseline: true }),
    audit("web_sm_010", 660.1, { login: "svc_reports", client: "<local machine>", action: "SL", statement: "SELECT SupplierId, Name FROM dbo.Suppliers WHERE Name = '...'; WAITFOR DELAY '0:0:5' ...", object: "Suppliers",
      app: JOB, description: "Supplier database ran a statement the digest job built from a supplier name" }, { severity: "high", isDetection: true, mitre: "T1190", tactic: IA }),
    audit("web_sm_011", 660.3, { login: "svc_reports", client: "<local machine>", action: "CR", statement: "CREATE LOGIN [sup_sync] WITH PASSWORD = '******', CHECK_POLICY = OFF", object: "sup_sync",
      app: JOB, description: "Supplier database server created a SQL login" }, { severity: "high", isDetection: true, mitre: "T1136", tactic: PERSIST }),
    audit("web_sm_012", 660.32, { login: "svc_reports", client: "<local machine>", action: "AL", statement: "ALTER SERVER ROLE [sysadmin] ADD MEMBER [sup_sync]", object: "sysadmin",
      app: JOB, description: "Supplier database server changed a server role" }, { severity: "high", mitre: "T1098", tactic: PERSIST }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// NoSQL operator injection, single-player: a support portal's login, Node.js behind nginx. A custom WAF rule
// counts operator names; the managed rule sets have none.
// ══════════════════════════════════════════════════════════════════════════════
function nosqlSupport(): TelemetryEvent[] {
  const T = clock("2026-10-14T13:00:00Z");
  const w: WebSite = { site: "support.nexacorp.com", host: "web-support-01.nexacorp.com", ip: "10.20.41.41", server: "nginx", wafMode: "Detection" };
  const atk = "203.0.113.170", runner = "203.0.113.181", ua = PY, GO = "Go-http-client/2.0";
  const rule = { action: "count" as const, rule: "custom" as const, ruleName: "CountQueryOperators", location: "REQUEST_BODY" };
  return [
    webAccess(w, { id: "web_ns_001", ts: T(2), srcIp: "198.51.100.16", method: "POST", path: "/api/auth/login", sent: 418, bytes: 604, ua: SAFARI, isBaseline: true, description: "Support portal answered a sign-in" }),
    wafRequest(w, { id: "web_ns_002", ts: T(9), srcIp: "10.10.20.44", method: "POST", path: "/api/tickets/88412/comments", ...rule, matched: "$ne", sent: 2210, bytes: 288, ua: CHROME,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "A support engineer at the office pasting a database query into a ticket comment for a developer: one comment on a ticket, from the office, through the comments path, not the sign-in.",
      description: "WAF rule matched a query operator in a request body" }),
    webAccess(w, { id: "web_ns_003", ts: T(9.01), srcIp: "10.10.20.44", method: "POST", path: "/api/tickets/88412/comments", status: 201, sent: 2210, bytes: 288, ua: CHROME, isBaseline: true, description: "Support portal saved a ticket comment" }),
    wafRequest(w, { id: "web_ns_004", ts: T(37), srcIp: atk, method: "POST", path: "/api/auth/login", ...rule, matched: "$ne", sent: 96, bytes: 611, ua,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched a query operator in a request body" }),
    webAccess(w, { id: "web_ns_005", ts: T(37.01), srcIp: atk, method: "POST", path: "/api/auth/login", sent: 96, bytes: 611, ua, mitre: "T1190", tactic: IA, description: "Support portal answered a sign-in (96 bytes in, 611 bytes out)" }),
    webAccess(w, { id: "web_ns_006", ts: T(38), srcIp: atk, path: "/api/admin/tickets", query: "status=all", bytes: 2184400, ua, severity: "medium", mitre: "T1078", tactic: IA,
      description: `Support portal answered the admin ticket list (${bytesText(2184400)} bytes out)` }),
    wafRequest(w, { id: "web_ns_007", ts: T(41), srcIp: atk, path: "/api/admin/tickets/export", query: "format=csv", action: "allow", bytes: 14882110, ua, description: "WAF passed a request to the admin ticket export" }),
    webAccess(w, { id: "web_ns_008", ts: T(41.01), srcIp: atk, path: "/api/admin/tickets/export", query: "format=csv", bytes: 14882110, ua, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: `Support portal answered the admin ticket export (${bytesText(14882110)} bytes out)` }),
    webAccess(w, { id: "web_ns_009", ts: T(44), srcIp: atk, method: "POST", path: "/api/admin/api-tokens", status: 201, sent: 140, bytes: 318, ua, severity: "medium", mitre: "T1098", tactic: PERSIST,
      description: "Support portal created an API token (140 bytes in, 318 bytes out)" }),
    webAccess(w, { id: "web_ns_010", ts: T(96), srcIp: runner, path: "/api/v1/tickets", query: "updated_since=2026-10-01", bytes: 884120, ua: GO, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: `Support API answered a ticket list for a token client (${bytesText(884120)} bytes out)` }),
    webAccess(w, { id: "web_ns_011", ts: T(126), srcIp: runner, path: "/api/v1/tickets", query: "updated_since=2026-10-14", bytes: 61220, ua: GO, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: `Support API answered a ticket list for a token client (${bytesText(61220)} bytes out)` }),
    ticket({ id: "web_ns_012", ts: T(180), table: "incident", number: "INC0093391", state: "New", severity: "informational", callerId: "s.ferraro@nexacorp.com",
      shortDescription: "Support portal shows an API token named 'sync' that nobody on the team created", description: "ServiceNow incident INC0093391 (New): unknown API token on the support portal",
      extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" } }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// NoSQL operator injection, Team Training (foundation): an event registration API that takes its sign-in code
// in the query string, so the operator is in the access log itself. One site, one client.
// ══════════════════════════════════════════════════════════════════════════════
function nosqlEvents(): TelemetryEvent[] {
  const T = clock("2026-10-16T09:00:00Z");
  const w: WebSite = { site: "events.nexacorp.com", host: "web-events-01.nexacorp.com", ip: "10.20.41.45", server: "nginx", wafMode: "Detection" };
  const atk = "203.0.113.182", qa = "10.10.20.47", ua = PY;
  const rule = { action: "count" as const, rule: "custom" as const, ruleName: "CountQueryOperators", location: "ARGS:code" };
  const attendees = (id: string, min: number, page: number, bytes: number) => webAccess(w, { id, ts: T(min), srcIp: atk, path: "/api/attendees", query: `page=${page}`, bytes, ua,
    severity: "medium", mitre: "T1213", tactic: COLLECT, description: `Events API answered attendee page ${page} (${bytesText(bytes)} bytes out)` });
  return [
    ticket({ id: "web_nr_001", ts: T(0), table: "sc_req_item", number: "RITM0052780", state: "Work in Progress", severity: "informational", callerId: "d.lindqvist@nexacorp.com",
      shortDescription: "QA: verify the events API rejects query operators in the sign-in code (bug EV-311)", description: "ServiceNow request RITM0052780 (Work in Progress): QA check of the events API sign-in" }),
    webAccess(w, { id: "web_nr_002", ts: T(3), srcIp: "198.51.100.15", path: "/api/attendee/session", query: "email=guest%40example.com&code=481207", bytes: 702, ua: SAFARI, isBaseline: true, description: "Events API signed in an attendee" }),
    wafRequest(w, { id: "web_nr_003", ts: T(11), srcIp: qa, path: "/api/attendee/session", query: "email=qa%40nexacorp.com&code%5B%24ne%5D=...", status: 401, bytes: 188, ...rule, matched: "[$ne]", ua: CHROME,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The QA check under RITM0052780: from the office, the tester's own address in the email, and the API refused it with 401.", description: "WAF rule matched a query operator in the code parameter" }),
    webAccess(w, { id: "web_nr_004", ts: T(11.01), srcIp: qa, path: "/api/attendee/session", query: "email=qa%40nexacorp.com&code%5B%24ne%5D=...", status: 401, bytes: 188, ua: CHROME, isBaseline: true, description: "Events API refused a sign-in" }),
    wafRequest(w, { id: "web_nr_005", ts: T(28), srcIp: atk, path: "/api/v0/attendee/session", query: "email=admin%40nexacorp.com&code%5B%24ne%5D=...", bytes: 744, ...rule, matched: "[$ne]", ua,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched a query operator in the code parameter" }),
    webAccess(w, { id: "web_nr_006", ts: T(28.01), srcIp: atk, path: "/api/v0/attendee/session", query: "email=admin%40nexacorp.com&code%5B%24ne%5D=...", bytes: 744, ua, mitre: "T1190", tactic: IA,
      description: "Events API signed in an account (744 bytes out)" }),
    attendees("web_nr_007", 29, 1, 412880),
    attendees("web_nr_008", 29.5, 2, 409144),
    attendees("web_nr_009", 30, 3, 398012),
    webAccess(w, { id: "web_nr_010", ts: T(31), srcIp: atk, path: "/api/attendees/export", query: "format=csv", bytes: 6230184, ua, severity: "high", mitre: "T1213", tactic: COLLECT,
      description: `Events API answered an attendee export (${bytesText(6230184)} bytes out)` }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// LDAP injection, single-player: a staff directory search on the intranet site published to the internet.
// ══════════════════════════════════════════════════════════════════════════════
function ldapPeople(): TelemetryEvent[] {
  const T = clock("2026-10-20T11:00:00Z");
  const w: WebSite = { site: "people.nexacorp.com", host: "web-people-01.nexacorp.com", ip: "10.20.41.51", server: "iis", wafMode: "Detection" };
  const atk = "203.0.113.183", scan = "203.0.113.188", ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  const rule = { action: "count" as const, rule: "custom" as const, ruleName: "CountLdapFilterChars", location: "ARGS:name" };
  return [
    ticket({ id: "web_ld_001", ts: T(0), table: "change_request", number: "CHG0044905", state: "Implement", severity: "informational",
      shortDescription: `External web vulnerability scan of intranet sites published to the internet, source ${scan}`, description: "ServiceNow change CHG0044905 (Implement): external scan of published intranet sites",
      extra: changeFields({ requestedBy: "m.levi@nexacorp.com", group: "Security Operations", ci: "people-site", from: T(-20), hours: 6,
        detail: `External vulnerability scan of the published intranet sites by the contracted scanning service from ${scan}, declared user agent ASV-Scanner (times UTC).` }) }),
    webAccess(w, { id: "web_ld_002", ts: T(4), srcIp: "10.10.20.52", path: "/search", query: "name=lind*", bytes: 6214, ua: CHROME, isBaseline: true, description: "Staff directory answered a name search" }),
    wafRequest(w, { id: "web_ld_003", ts: T(13), srcIp: scan, path: "/search", query: "name=*%29%28...", bytes: 188, status: 400, ...rule, matched: "*)(", ua: SCANNER,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The scan under CHG0044905: the change names the address, the scanner declares itself, and the directory refused the value with 400.", description: "WAF rule matched directory filter characters in the name parameter" }),
    webAccess(w, { id: "web_ld_004", ts: T(13.01), srcIp: scan, path: "/search", query: "name=*%29%28...", status: 400, bytes: 188, ua: SCANNER, isBaseline: true, description: "Staff directory refused a name search" }),
    wafRequest(w, { id: "web_ld_005", ts: T(52), srcIp: atk, path: "/search", query: "name=a*%29%28...", bytes: 1402118, ...rule, matched: "*)(", ua,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched directory filter characters in the name parameter" }),
    webAccess(w, { id: "web_ld_006", ts: T(52.01), srcIp: atk, path: "/search", query: "name=a*%29%28...", bytes: 1402118, ua, severity: "medium", mitre: "T1087.002", tactic: DISC,
      description: `Staff directory answered a name search (${bytesText(1402118)} bytes out)` }),
    wafRequest(w, { id: "web_ld_007", ts: T(54), srcIp: atk, path: "/search", query: "name=*%29%28title%3D...", bytes: 288412, ...rule, matched: "*)(", ua,
      severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched directory filter characters in the name parameter (title search)" }),
    webAccess(w, { id: "web_ld_008", ts: T(54.01), srcIp: atk, path: "/search", query: "name=*%29%28title%3D...", bytes: 288412, ua, severity: "medium", mitre: "T1087.002", tactic: DISC,
      description: `Staff directory answered a name search (${bytesText(288412)} bytes out)` }),
    ticket({ id: "web_ld_009", ts: T(1460), table: "incident", number: "INC0093420", state: "New", severity: "informational", callerId: "h.quist@nexacorp.com",
      shortDescription: "Caller asked the service desk for the IT on-call engineers by name and job title, then hung up", description: "ServiceNow incident INC0093420 (New): suspicious call to the service desk",
      extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" } }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// LDAP injection, Team Training: the self-service password reset portal checks identity with an LDAP filter
// built from the form. The reset lands on the domain controller, the new password signs in to the cloud.
// ══════════════════════════════════════════════════════════════════════════════
function ldapSspr(): TelemetryEvent[] {
  const T = clock("2026-10-21T19:00:00Z");
  const w: WebSite = { site: "reset.nexacorp.com", host: "web-reset-01.nexacorp.com", ip: "10.20.41.53", server: "iis", wafMode: "Detection" };
  const dc = "SRV-NXC-DC01", atk = "203.0.113.184", ua = CHROME;
  const victim = "l.moreno", staff = "e.valdez";
  const reset = (id: string, min: number, target: string): TelemetryEvent => ({
    ...winRecord({ id, ts: T(min), host: dc, user: "svc-sspr", eventType: "account_modify", severity: "medium", mitre: "T1098", tactic: PERSIST,
      description: `Domain controller recorded a password reset of ${target} by svc-sspr` },
      "4724", { SubjectUserName: "svc-sspr", SubjectDomainName: "NEXACORP", SubjectLogonId: "0x3E7A1C2", TargetUserName: target, TargetDomainName: "NEXACORP" }),
    user_email: `${target}@nexacorp.com`,
  });
  return [
    webAccess(w, { id: "web_lb_001", ts: T(2), srcIp: "10.10.20.58", method: "POST", path: "/reset/verify", sent: 512, bytes: 2210, ua, isBaseline: true, description: "Password reset portal verified an employee" }),
    { ...reset("web_lb_002", 2.5, staff), expected_verdict: "fp" as const,
      fp_explanation: "An employee resetting a forgotten password through the portal as designed: from the office, after the portal's own verification step, and nothing else changes on the account." },
    wafRequest(w, { id: "web_lb_003", ts: T(41), srcIp: atk, method: "POST", path: "/reset/verify", action: "count", rule: "custom", ruleName: "CountLdapFilterChars", matched: ")(", location: "REQUEST_BODY", sent: 498, bytes: 2210, ua,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched directory filter characters in a request body" }),
    webAccess(w, { id: "web_lb_004", ts: T(41.01), srcIp: atk, method: "POST", path: "/reset/verify", sent: 498, bytes: 2210, ua, mitre: "T1190", tactic: IA,
      description: "Password reset portal verified an account (498 bytes in, 2,210 bytes out)" }),
    webAccess(w, { id: "web_lb_005", ts: T(42), srcIp: atk, method: "POST", path: "/reset/new-password", sent: 344, bytes: 1180, ua, mitre: "T1098", tactic: PERSIST,
      description: "Password reset portal set a new password (344 bytes in, 1,180 bytes out)" }),
    reset("web_lb_006", 42.01, victim),
    noEmpty({ ...entraSignIn({ id: "web_lb_007", ts: T(47), user: `${victim}@nexacorp.com`, srcIp: atk, result: "success", app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000",
      resource: "Office 365 Exchange Online", mfa: false, isInteractive: true, managed: false, compliant: false, os: "Windows 10", browser: "Chrome 126.0.0", userAgent: ua,
      riskLevel: "none", riskEventTypes: [], riskDetail: "none", conditionalAccess: "notApplicable", incomingTokenType: "none",
      severity: "high", mitre: "T1078", tactic: IA, description: `${victim} signed in to Exchange Online from ${atk}` }), is_detection: true }),
    m365Operation({ id: "web_lb_008", ts: T(52), user: `${victim}@nexacorp.com`, operation: "MailItemsAccessed", workload: "Exchange", srcIp: atk, userAgent: ua,
      severity: "high", mitre: "T1114.002", tactic: COLLECT, extra: { MailAccessType: "Bind" }, description: `Unified audit log: MailItemsAccessed for ${victim} from ${atk}` }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// JWT tampering, single-player: a developer portal trusts the token's key id; a path to an empty file signs
// with an empty key. Nothing in the request matches a signature: the customer tier reaching admin paths does.
// ══════════════════════════════════════════════════════════════════════════════
function jwtDevportal(): TelemetryEvent[] {
  const T = clock("2026-10-22T08:00:00Z");
  const w: WebSite = { site: "developers.nexacorp.com", host: "web-devportal-01.nexacorp.com", ip: "10.20.41.55", server: "nginx" };
  const atk = "203.0.113.185", runner = "203.0.113.186", ua = "node-fetch/3.3.2", travel = "198.51.100.154";
  const rule = { action: "count" as const, rule: "custom" as const, ruleName: "CountAdminApiOutsideOffice" };
  const invoices = (id: string, min: number, page: number, bytes: number) => webAccess(w, { id, ts: T(min), srcIp: runner, path: "/api/v1/orgs/41872/invoices", query: `page=${page}`, bytes, ua: "Go-http-client/2.0",
    severity: "medium", mitre: "T1213", tactic: COLLECT, description: `Developer API answered invoice page ${page} of another organization (${bytesText(bytes)} bytes out)` });
  return [
    webAccess(w, { id: "web_jk_001", ts: T(3), srcIp: "198.51.100.16", path: "/api/v1/apps", bytes: 4210, ua: SAFARI, isBaseline: true, description: "Developer API answered an app list" }),
    ticket({ id: "web_jk_002", ts: T(6), table: "sc_req_item", number: "RITM0052801", state: "Work in Progress", severity: "informational", callerId: "p.nakamura@nexacorp.com",
      shortDescription: "Partner success: issue an API key for partner organization 30115 (travelling, home connection)", description: "ServiceNow request RITM0052801 (Work in Progress): partner API key" }),
    wafRequest(w, { id: "web_jk_003", ts: T(9), srcIp: travel, method: "POST", path: "/api/admin/orgs/30115/keys", status: 201, bytes: 318, ...rule, ua: CHROME,
      severity: "medium", isDetection: true, mitre: "T1098", tactic: PERSIST, verdict: "fp",
      fpExplanation: "The partner key RITM0052801 asked for: the partner success engineer, travelling, issuing a key for the partner the request names.", description: "WAF rule counted an admin API request from outside the office" }),
    webAccess(w, { id: "web_jk_004", ts: T(9.01), srcIp: travel, method: "POST", path: "/api/admin/orgs/30115/keys", status: 201, bytes: 318, ua: CHROME, isBaseline: true, description: "Developer admin API created an API key" }),
    webAccess(w, { id: "web_jk_005", ts: T(31), srcIp: atk, path: "/api/v1/apps", bytes: 1180, ua, mitre: "T1190", tactic: IA, description: "Developer API answered an app list (1,180 bytes out)" }),
    wafRequest(w, { id: "web_jk_006", ts: T(36), srcIp: atk, path: "/api/admin/orgs", bytes: 88412, ...rule, ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA,
      description: "WAF rule counted an admin API request from outside the office (organization list)" }),
    webAccess(w, { id: "web_jk_007", ts: T(36.01), srcIp: atk, path: "/api/admin/orgs", bytes: 88412, ua, severity: "medium", mitre: "T1190", tactic: IA, description: `Developer admin API answered the organization list (${bytesText(88412)} bytes out)` }),
    wafRequest(w, { id: "web_jk_008", ts: T(38), srcIp: atk, method: "POST", path: "/api/admin/orgs/41872/keys", status: 201, bytes: 318, ...rule, ua, severity: "medium", isDetection: true, mitre: "T1098", tactic: PERSIST,
      description: "WAF rule counted an admin API request from outside the office" }),
    webAccess(w, { id: "web_jk_009", ts: T(38.01), srcIp: atk, method: "POST", path: "/api/admin/orgs/41872/keys", status: 201, bytes: 318, ua, severity: "medium", mitre: "T1098", tactic: PERSIST,
      description: "Developer admin API created an API key for another organization" }),
    invoices("web_jk_010", 70, 1, 1204880),
    invoices("web_jk_011", 70.6, 2, 1188012),
    ticket({ id: "web_jk_012", ts: T(260), table: "incident", number: "INC0093455", state: "New", severity: "informational", callerId: "partner-ops@customer-co.example",
      shortDescription: "Partner reports an API key on their organization that nobody on their side created", description: "ServiceNow incident INC0093455 (New): unknown API key on a partner organization",
      extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" } }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// JWT tampering, Team Training (foundation): a mobile API accepts an unsigned token. A custom WAF rule counts
// the unsigned-token header prefix in the Authorization header. One site, one client.
// ══════════════════════════════════════════════════════════════════════════════
function jwtMobile(): TelemetryEvent[] {
  const T = clock("2026-10-23T16:00:00Z");
  const w: WebSite = { site: "mobile-api.nexacorp.com", host: "web-mobileapi-01.nexacorp.com", ip: "10.20.41.58", server: "nginx", wafMode: "Detection" };
  const atk = "198.51.100.151", pen = "198.51.100.155", ua = OKHTTP;
  const rule = { action: "count" as const, rule: "custom" as const, ruleName: "CountUnsignedJwt", matched: "eyJhbGciOiJub25l", location: "REQUEST_HEADERS:Authorization" };
  return [
    ticket({ id: "web_jn_001", ts: T(0), table: "change_request", number: "CHG0044930", state: "Implement", severity: "informational",
      shortDescription: `Mobile API penetration test, source ${pen}, this week`, description: "ServiceNow change CHG0044930 (Implement): mobile API penetration test",
      extra: changeFields({ requestedBy: "m.levi@nexacorp.com", group: "Security Operations", ci: "mobile-api", from: T(-60), hours: 72,
        detail: `Mobile API penetration test by the contracted testing firm from ${pen}, token handling in scope (times UTC).` }) }),
    webAccess(w, { id: "web_jn_002", ts: T(3), srcIp: "198.51.100.37", path: "/v2/account/profile", bytes: 1840, ua, isBaseline: true, description: "Mobile API answered a profile request" }),
    wafRequest(w, { id: "web_jn_003", ts: T(10), srcIp: pen, path: "/v3/account/profile", status: 401, bytes: 164, ...rule, ua: PENTEST,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The penetration test under CHG0044930: the change names the address, the tester declares itself, and the current API version refused the token with 401.", description: "WAF rule counted an unsigned token in the Authorization header" }),
    webAccess(w, { id: "web_jn_004", ts: T(10.01), srcIp: pen, path: "/v3/account/profile", status: 401, bytes: 164, ua: PENTEST, isBaseline: true, description: "Mobile API refused a profile request" }),
    wafRequest(w, { id: "web_jn_005", ts: T(34), srcIp: atk, path: "/v2/account/profile", bytes: 1902, ...rule, ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA,
      description: "WAF rule counted an unsigned token in the Authorization header" }),
    webAccess(w, { id: "web_jn_006", ts: T(34.01), srcIp: atk, path: "/v2/account/profile", bytes: 1902, ua, mitre: "T1190", tactic: IA, description: "Mobile API answered a profile request (1,902 bytes out)" }),
    wafRequest(w, { id: "web_jn_007", ts: T(36), srcIp: atk, path: "/v2/admin/users", query: "page=1", bytes: 512880, ...rule, ua, severity: "medium", mitre: "T1190", tactic: IA,
      description: "WAF rule counted an unsigned token in the Authorization header (admin user list)" }),
    webAccess(w, { id: "web_jn_008", ts: T(36.01), srcIp: atk, path: "/v2/admin/users", query: "page=1", bytes: 512880, ua, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: `Mobile API answered the admin user list (${bytesText(512880)} bytes out)` }),
    webAccess(w, { id: "web_jn_009", ts: T(38), srcIp: atk, path: "/v2/admin/users/export", query: "format=csv", bytes: 7340212, ua, severity: "high", mitre: "T1213", tactic: COLLECT,
      description: `Mobile API answered an admin user export (${bytesText(7340212)} bytes out)` }),
  ];
}

export const WEB_INJECTION_DATA_STORIES: WebStoryDef[] = [
  { id: "web-inj-sqli-catalog", family: "web-inj-sqli-blind", mode: "solo", title: "Catalog Searches That Took Five Seconds", complexity: "core", events: sqliCatalog() },
  { id: "web-inj-sqli-suppliers", family: "web-inj-sqli-blind", mode: "team", title: "Nightly Supplier Digest Creates a SQL Login", complexity: "advanced", events: sqliSuppliers() },
  { id: "web-inj-nosql-support", family: "web-inj-nosql", mode: "solo", title: "Support Portal Sign-In With No Password Check", complexity: "core", events: nosqlSupport() },
  { id: "web-inj-nosql-events", family: "web-inj-nosql", mode: "team", title: "Event Attendee List Read Through the Sign-In API", complexity: "foundation", events: nosqlEvents() },
  { id: "web-inj-ldap-people", family: "web-inj-ldap", mode: "solo", title: "Staff Directory Search Returning the Whole Directory", complexity: "core", events: ldapPeople() },
  { id: "web-inj-ldap-sspr", family: "web-inj-ldap", mode: "team", title: "Self-Service Reset of an IT Account From Outside", complexity: "advanced", events: ldapSspr(), seat: "it" },
  { id: "web-inj-jwt-devportal", family: "web-inj-jwt", mode: "solo", title: "Developer Portal Key Issued to Another Organization", complexity: "advanced", events: jwtDevportal() },
  { id: "web-inj-jwt-mobile", family: "web-inj-jwt", mode: "team", title: "Mobile API Admin Export With an Unsigned Token", complexity: "foundation", events: jwtMobile() },
];
