/**
 * Web injection round (Tal, 2026-11-12), part client: injection that turns on the server's own runtime
 * (Log4Shell, prototype pollution) and injection aimed at the people who use a site (CRLF / header
 * injection, reflected XSS, open redirect).
 *
 * Every family is a parametric template of two variants: another site, another way in, another server
 * platform where it makes sense, another pretext and another benign look-alike (see injection-cmd.ts).
 * One variant of each family is dealt in the single-player dashboard (mode "solo"), the other in Team
 * Training (mode "team"), so each mode practises every attack class on a different incident.
 *
 *  1. web-inj-log4shell: a lookup string in a logged header. (a) the User-Agent of a Java help center
 *     behind nginx, WAF policy in Detection; (b) X-Api-Version of a Java search API on Windows, the plain
 *     lookup blocked, a nested form the rule does not read passing.
 *  2. web-inj-crlf: CR/LF in a parameter. (a) response splitting on a language redirect fixes a staff
 *     member's session; (b) header injection into a quote-sharing mailer adds a Bcc.
 *  3. web-inj-proto-pollution: prototype keys in JSON merged into an object. (a) a Node.js account site
 *     on IIS (iisnode) treats a customer as admin; (b) a chart service's polluted spawn options run its
 *     image converter through a shell, the EDR process tree under node.
 *  4. web-inj-xss-redirect: (a) reflected XSS on a docs search page, a staff session used from outside;
 *     (b) open redirect on a staff portal sign-in to a look-alike page, the password used in Entra ID.
 *
 * Payloads are abbreviated to the part that names the class. The logs show the effect (a process, a
 * file, a connection, a session used from another address), never a working chain.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { csFile, csNetwork, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { mdeDns, mdeFile, mdeNetwork, mdeProcess } from "@/lib/sim/emitters/mde";
import { panConnection, panWeb } from "@/lib/sim/emitters/paloalto";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { makeSha256 } from "@/lib/sim/iocs";
import { asUser, bytesText, clock, ticket, type WebStoryDef, changeFields } from "./entry";

const IA = "Initial Access", EXEC = "Execution", PERSIST = "Persistence", PRIV = "Privilege Escalation", STEALTH = "Stealth", CRED = "Credential Access",
  DISC = "Discovery", COLLECT = "Collection", C2 = "Command and Control", IMPACT = "Impact";
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
const PY = "python-requests/2.31.0";
/** Outbound web rule with TLS decryption on: the firewall sees full URLs only under it. */
const DECRYPT = "ALLOW-WEB-OUT-DECRYPT";
/** A row the story marks as a benign look-alike. */
const lookalike = (e: TelemetryEvent, why: string): TelemetryEvent => ({ ...e, expected_verdict: "fp", fp_explanation: why });
const baseline = (e: TelemetryEvent): TelemetryEvent => ({ ...e, is_baseline: true });
/** A sign-in from an unregistered device: the record carries no device id and, on success, no failure text. */
const noEmpty = (e: TelemetryEvent): TelemetryEvent => ({ ...e, raw: Object.fromEntries(Object.entries(e.raw ?? {}).filter(([, v]) => v !== "")) });

// ══════════════════════════════════════════════════════════════════════════════
// 1a. Log4Shell in the User-Agent: Java help center behind nginx on Linux, WAF policy in Detection.
// ══════════════════════════════════════════════════════════════════════════════
function log4jUserAgent(): TelemetryEvent[] {
  const T = clock("2026-10-13T08:00:00Z");
  const w: WebSite = { site: "helpcenter.nexacorp.com", host: "web-helpcenter-01.nexacorp.com", ip: "10.20.41.60", server: "nginx", wafMode: "Detection" };
  const atk = "203.0.113.216", ldap = "203.0.113.217", codebase = "update-cache.example", c2 = "203.0.113.220", scan = "203.0.113.222", dir = "10.20.41.61";
  const lookup = "${jndi:ldap://...}";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const RUN = "helpcenter";
  const JAVA_PATH = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java";
  const JAVA = { processName: "java", processPath: JAVA_PATH, pid: 2210, parentName: "systemd", parentPid: 1,
    cmdline: `${JAVA_PATH} -Dcatalina.base=/opt/helpcenter -classpath /opt/helpcenter/bin/bootstrap.jar org.apache.catalina.startup.Bootstrap start` };
  const AGENT = "/tmp/.hc-agent", agentHash = makeSha256("web_helpcenter_hc_agent_payload");
  const fromAgent = (id: string, min: number, pid: number, name: string, cmd: string, extra = {}) => csProcess({ id, ts: T(min), ...host, processName: name, processPath: `/usr/bin/${name}`, cmdline: cmd, pid,
    parentName: ".hc-agent", parentPid: 31890, runAsUser: RUN, sha256: makeSha256(`usr_bin_${name}_debian_signed`), description: `Process started on ${w.host}`, ...extra });
  const logged = (id: string, min: number, path: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, path, action: "count", rule: "log4j_header", matched: "${jndi:ldap://",
    location: "REQUEST_HEADERS:User-Agent", ua: lookup, severity: "high", mitre: "T1190", tactic: IA, description: "WAF rule matched a lookup string in a request header", ...extra });
  return [
    ticket({ id: "web_l4u_001", ts: T(0), table: "change_request", number: "CHG0044702", state: "Implement", severity: "informational",
      shortDescription: `External ASV scan of public sites with Log4j checks, source ${scan}`, description: "ServiceNow change CHG0044702 (Implement): external vulnerability scan of public sites",
      extra: changeFields({ requestedBy: "m.levi@nexacorp.com", group: "Security Operations", ci: "helpcenter-site", from: T(-30), hours: 6,
        detail: `External vulnerability scan of public sites, Log4j header checks included, by the contracted scanning service from ${scan} (times UTC).` }) }),
    webAccess(w, { id: "web_l4u_002", ts: T(2), srcIp: "10.10.20.52", path: "/portal/2/requests", query: "status=open", bytes: 24180, ua: MAC, isBaseline: true, description: "Help center answered a request list" }),
    lookalike(asUser(csNetwork({ id: "web_l4u_003", ts: T(4), ...host, ...JAVA, remoteIp: dir, remotePort: 389, severity: "medium", description: `Outbound connection from ${w.host}` }), RUN),
      "The help center checking a staff sign-in against the company directory: java speaks LDAP on port 389 to an internal directory server whenever someone signs in, and nothing runs after it."),
    wafRequest(w, { id: "web_l4u_004", ts: T(9), srcIp: scan, path: "/static/app.css", action: "count", rule: "log4j_header", matched: "${jndi:ldap://", location: "REQUEST_HEADERS:User-Agent",
      ua: "${jndi:ldap://.../asv-9.6}", bytes: 18220, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The ASV scan under CHG0044702: the source address matches the change, the probe asked for a static file nginx serves itself without passing it to Java, and the server made no outbound connection after it.",
      description: "WAF rule matched a lookup string in a request header" }),
    webAccess(w, { id: "web_l4u_005", ts: T(9.01), srcIp: scan, path: "/static/app.css", bytes: 18220, ua: "${jndi:ldap://.../asv-9.6}", isBaseline: true, description: "Help center answered a static file request" }),
    logged("web_l4u_006", 52, "/portal/login", { isDetection: true }),
    webAccess(w, { id: "web_l4u_007", ts: T(52.01), srcIp: atk, path: "/portal/login", bytes: 9120, ua: lookup, mitre: "T1190", tactic: IA, description: "Help center answered a sign-in page" }),
    asUser(csNetwork({ id: "web_l4u_008", ts: T(52.02), ...host, ...JAVA, remoteIp: ldap, remotePort: 1389, severity: "medium", mitre: "T1190", tactic: IA, description: `Outbound connection from ${w.host}` }), RUN),
    panConnection({ id: "web_l4u_009", ts: T(52.03), ...host, dstIp: ldap, remotePort: 1389, app: "ldap", action: "allow", end: true, bytesIn: 412, bytesOut: 96, elapsedSec: 1,
      severity: "low", mitre: "T1190", tactic: IA, description: `${w.host} closed an LDAP session to ${ldap} on port 1389` }),
    panWeb({ id: "web_l4u_010", ts: T(52.04), ...host, url: `https://${codebase}/a/T8f2.class`, domain: codebase, dstIp: ldap, category: "unknown", action: "alert", userAgent: "Java/11.0.20", bytesIn: 1620,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    csProcess({ id: "web_l4u_011", ts: T(52.1), ...host, processName: "dash", processPath: "/usr/bin/dash", cmdline: "sh -c id", pid: 31840, parentName: "java", parentPid: 2210, runAsUser: RUN,
      sha256: makeSha256("usr_bin_dash_debian_signed"), severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC, description: `Process started on ${w.host}` }),
    logged("web_l4u_012", 55, "/portal/search", { query: "q=printer" }),
    webAccess(w, { id: "web_l4u_013", ts: T(55.01), srcIp: atk, path: "/portal/search", query: "q=printer", bytes: 6204, ua: lookup, mitre: "T1190", tactic: IA, description: "Help center answered a search" }),
    panWeb({ id: "web_l4u_014", ts: T(55.02), ...host, url: `https://${codebase}/a/hc-agent`, domain: codebase, dstIp: ldap, category: "unknown", action: "alert", userAgent: "Java/11.0.20", bytesIn: 2841200,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    csFile({ id: "web_l4u_015", ts: T(55.03), ...host, path: AGENT, sha256: agentHash, size: 2841200, actorProcess: "java", actorPath: JAVA_PATH, actorPid: 2210, runAsUser: RUN,
      severity: "medium", mitre: "T1105", tactic: C2, description: `File written on ${w.host}` }),
    csProcess({ id: "web_l4u_016", ts: T(55.1), ...host, processName: ".hc-agent", processPath: AGENT, cmdline: AGENT, pid: 31890, parentName: "java", parentPid: 2210, runAsUser: RUN, sha256: agentHash,
      severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC, description: `Process started on ${w.host}` }),
    asUser(csNetwork({ id: "web_l4u_017", ts: T(55.3), ...host, remoteIp: c2, remotePort: 443, processName: ".hc-agent", processPath: AGENT, cmdline: AGENT, pid: 31890, parentName: "java", parentPid: 2210,
      sha256: agentHash, severity: "medium", mitre: "T1071.001", tactic: C2, description: `Outbound connection from ${w.host}` }), RUN),
    fromAgent("web_l4u_018", 58, 31902, "cat", "cat /opt/helpcenter/conf/dbconfig.xml", { severity: "medium", mitre: "T1552.001", tactic: CRED }),
    fromAgent("web_l4u_019", 61, 31935, "tar", "tar czf /tmp/.hc.tgz /var/helpcenter/attachments", { severity: "medium", mitre: "T1005", tactic: COLLECT }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 1b. Log4Shell in X-Api-Version: Java search API on Windows behind IIS. The plain lookup is blocked,
// a nested form the rule does not read passes, and the server resolves the callback name.
// ══════════════════════════════════════════════════════════════════════════════
function log4jApiHeader(): TelemetryEvent[] {
  const T = clock("2026-10-15T13:50:00Z");
  const w: WebSite = { site: "search.nexacorp.com", host: "web-searchapi-01.nexacorp.com", ip: "10.20.41.62", server: "iis" };
  const atk = "203.0.113.223", cb = "cb-relay.example", cbIp = "203.0.113.224", c2 = "203.0.113.225", partner = "198.51.100.248", secTeam = "10.10.20.61";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const svc = { runAsUser: "NT SERVICE\\SearchApi", accountName: "SearchApi", accountDomain: "NT SERVICE" };
  const JAVA = { parentName: "java.exe", parentPid: 4412 };
  const api = "/api/v3/search", ua = PY;
  const DROP = "C:\\ProgramData\\SearchCache\\SearchIndexer.exe", payload = makeSha256("web_searchapi_searchindexer_payload");
  const blocked = (id: string, min: number, query: string, matched: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, path: api, query, action: "block", rule: "log4j_header", matched,
    location: "REQUEST_HEADERS:X-Api-Version", ua, severity: "high", mitre: "T1190", tactic: IA, description: "WAF rule matched a lookup string in a request header", ...extra });
  const passed = (id: string, min: number, query: string) => wafRequest(w, { id, ts: T(min), srcIp: atk, path: api, query, action: "allow", bytes: 2210, ua, severity: "low", description: "WAF passed a request to the search API" });
  const answered = (id: string, min: number, query: string, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, path: api, query, bytes: 2210, ua, mitre: "T1190", tactic: IA, description: "Search API answered a query", ...extra });
  return [
    ticket({ id: "web_l4h_001", ts: T(0), table: "sc_req_item", number: "RITM0052611", state: "Work in Progress", severity: "informational",
      shortDescription: `Verify the Log4j fix on the search API: header test from the security team, ${secTeam}`, description: "ServiceNow request RITM0052611 (Work in Progress): Log4j fix verification on the search API" }),
    webAccess(w, { id: "web_l4h_002", ts: T(2), srcIp: partner, path: api, query: "q=pallet+jack&page=1", bytes: 14420, ua: "SearchClient/2.4 okhttp/4.12.0", isBaseline: true, description: "Search API answered a query" }),
    wafRequest(w, { id: "web_l4h_003", ts: T(6), srcIp: secTeam, path: api, query: "q=test", action: "block", rule: "log4j_header", matched: "${jndi:dns://", location: "REQUEST_HEADERS:X-Api-Version",
      ua: "curl/8.4.0", severity: "high", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The security team's patch check in RITM0052611: it comes from the address the request names, its lookup points at a test name, and the server resolved nothing after it.",
      description: "WAF rule matched a lookup string in a request header" }),
    lookalike(mdeProcess({ id: "web_l4h_004", ts: T(10), ...host, ...svc, ...JAVA, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c D:\\apps\\search-api\\bin\\reindex.bat --incremental",
      pid: 7120, signed: true, integrity: "System", severity: "high", isDetection: true, mitre: "T1059.003", tactic: EXEC, description: `Process started on ${w.host}` }),
      "The search service's hourly index refresh: on the hour, java.exe runs the vendor's reindex script from its own install folder, and the command line holds nothing else."),
    blocked("web_l4h_005", 31, "q=pallet", "${jndi:ldap://", { isDetection: true }),
    blocked("web_l4h_006", 31.4, "q=pallet+truck", "${jndi:rmi://"),
    passed("web_l4h_007", 33, "q=pallet"),
    answered("web_l4h_008", 33.01, "q=pallet"),
    mdeDns({ id: "web_l4h_009", ts: T(33.02), ...host, domain: cb, resolvedIp: cbIp, initiatingProcess: "java.exe", severity: "medium", mitre: "T1190", tactic: IA, description: `${w.host} resolved ${cb}` }),
    mdeNetwork({ id: "web_l4h_010", ts: T(33.03), ...host, remoteIp: cbIp, remotePort: 1389, domain: cb, initiatingProcess: "java.exe", severity: "medium", mitre: "T1190", tactic: IA, description: `Outbound connection from ${w.host}` }),
    panConnection({ id: "web_l4h_011", ts: T(33.04), ...host, domain: cb, dstIp: cbIp, remotePort: 1389, app: "ldap", action: "allow", end: true, bytesIn: 388, bytesOut: 102, elapsedSec: 1,
      severity: "low", mitre: "T1190", tactic: IA, description: `${w.host} closed an LDAP session to ${cb} on port 1389` }),
    panWeb({ id: "web_l4h_012", ts: T(33.05), ...host, url: `https://${cb}/Q.class`, domain: cb, dstIp: cbIp, category: "unknown", action: "alert", userAgent: "Java/11.0.20", bytesIn: 1488,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    mdeProcess({ id: "web_l4h_013", ts: T(33.06), ...host, ...svc, ...JAVA, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c whoami /all", pid: 7388, signed: true,
      integrity: "System", severity: "high", isDetection: true, mitre: "T1059.003", tactic: EXEC, description: `Process started on ${w.host}` }),
    mdeProcess({ id: "web_l4h_014", ts: T(33.07), ...host, ...svc, parentName: "cmd.exe", parentPid: 7388, processName: "whoami.exe", processPath: "C:\\Windows\\System32\\whoami.exe", cmdline: "whoami /all", pid: 7395,
      sha256: makeSha256("windows_system32_whoami_exe_signed_microsoft"), signed: true, integrity: "System", severity: "medium", mitre: "T1033", tactic: DISC, description: `Process started on ${w.host}` }),
    passed("web_l4h_015", 37, "q=forklift"),
    answered("web_l4h_016", 37.01, "q=forklift", { mitre: "T1105", tactic: C2 }),
    panWeb({ id: "web_l4h_017", ts: T(37.02), ...host, url: `https://${cb}/s.bin`, domain: cb, dstIp: cbIp, category: "unknown", action: "alert", userAgent: "Java/11.0.20", bytesIn: 412160,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    mdeFile({ id: "web_l4h_018", ts: T(37.03), ...host, path: DROP, sha256: payload, size: 412160, initiatingProcess: "java.exe",
      extra: { InitiatingProcessFolderPath: "C:\\Program Files\\Java\\jre-17\\bin\\java.exe" }, severity: "medium", mitre: "T1105", tactic: C2, description: `File written on ${w.host}` }),
    mdeProcess({ id: "web_l4h_019", ts: T(37.04), ...host, ...svc, ...JAVA, processName: "SearchIndexer.exe", processPath: DROP, cmdline: DROP, pid: 7477, sha256: payload, signed: false,
      integrity: "System", severity: "high", isDetection: true, mitre: "T1036.005", tactic: STEALTH, description: `Process started on ${w.host}` }),
    mdeNetwork({ id: "web_l4h_020", ts: T(37.2), ...host, remoteIp: c2, remotePort: 443, application: "tls", initiatingProcess: "SearchIndexer.exe", severity: "medium", mitre: "T1071.001", tactic: C2,
      description: `Outbound connection from ${w.host}` }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2a. CRLF response splitting on a language redirect: a staff member's session is fixed by a link.
// The site's WAF policy is in Detection: CRS 921150 (or the AWS custom rule) logs and passes.
// ══════════════════════════════════════════════════════════════════════════════
function crlfFixation(): TelemetryEvent[] {
  const T = clock("2026-10-16T09:00:00Z");
  const w: WebSite = { site: "suppliers.nexacorp.com", host: "web-suppliers-01.nexacorp.com", ip: "10.20.41.64", wafMode: "Detection" };
  const atk = "203.0.113.226", supplier = "198.51.100.249", staff = "10.10.20.37", ua = FIREFOX, mail = "https://outlook.office.com/";
  const lang = "/account/language";
  const fixQuery = "lang=en&next=%2Fstaff%2Fhome%0D%0ASet-Cookie%3A%20sid%3D...";
  const crlf = (id: string, min: number, src: string, query: string, matched: string, agent: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: src, path: lang, query, action: "count", rule: "crlf_query",
    matched, location: "ARGS:next", status: 302, bytes: 0, ua: agent, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a line break in a query parameter", ...extra });
  const redirect = (id: string, min: number, src: string, query: string, agent: string, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: src, path: lang, query, status: 302, bytes: 0, ua: agent,
    description: "Supplier portal answered a language change with a redirect", ...extra });
  const atkGet = (id: string, min: number, path: string, query: string | undefined, bytes: number, description: string, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, path, query, bytes, ua, description, ...extra });
  return [
    webAccess(w, { id: "web_cr_001", ts: T(2), srcIp: supplier, path: "/orders", bytes: 31220, ua: MAC, isBaseline: true, description: "Supplier portal answered an order list" }),
    crlf("web_cr_002", 5, supplier, "lang=de&next=%2Forders%2F4471%0D%0A", "%0D%0A", MAC, { isDetection: true, verdict: "fp",
      fpExplanation: "A supplier's link copied out of a plain-text email kept the line break at its end: nothing follows the break, the portal sent no cookie with the redirect, and the same address carried on to the order." }),
    redirect("web_cr_003", 5.01, supplier, "lang=de&next=%2Forders%2F4471%0D%0A", MAC, { isBaseline: true }),
    webAccess(w, { id: "web_cr_004", ts: T(5.2), srcIp: supplier, path: "/orders/4471", bytes: 8840, ua: MAC, isBaseline: true, description: "Supplier portal answered an order" }),
    crlf("web_cr_005", 36, atk, "lang=en&next=%2Forders%0D%0AX-Lang-Test%3A%201", "%0D%0AX-Lang-Test", ua, { isDetection: true }),
    redirect("web_cr_006", 36.01, atk, "lang=en&next=%2Forders%0D%0AX-Lang-Test%3A%201", ua, { mitre: "T1190", tactic: IA }),
    atkGet("web_cr_007", 38, "/account/login", undefined, 7410, "Supplier portal answered a sign-in page"),
    crlf("web_cr_008", 39, atk, fixQuery, "%0D%0ASet-Cookie", ua),
    redirect("web_cr_009", 39.01, atk, fixQuery, ua, { mitre: "T1190", tactic: IA }),
    crlf("web_cr_010", 58, staff, fixQuery, "%0D%0ASet-Cookie", CHROME, { isDetection: true, referer: mail }),
    redirect("web_cr_011", 58.01, staff, fixQuery, CHROME, { referer: mail, mitre: "T1190", tactic: IA }),
    webAccess(w, { id: "web_cr_012", ts: T(58.5), srcIp: staff, method: "POST", path: "/account/login", status: 302, bytes: 0, ua: CHROME, description: "Supplier portal answered a sign-in" }),
    webAccess(w, { id: "web_cr_013", ts: T(58.8), srcIp: staff, path: "/staff/home", bytes: 12480, ua: CHROME, description: "Supplier portal answered a staff home page" }),
    atkGet("web_cr_014", 61, "/staff/home", undefined, 12480, "Supplier portal answered a staff home page", { mitre: "T1550.004", tactic: STEALTH }),
    atkGet("web_cr_015", 62, "/staff/suppliers", "page=1", 40210, "Supplier portal answered a supplier list", { mitre: "T1213", tactic: COLLECT }),
    webAccess(w, { id: "web_cr_016", ts: T(64), srcIp: atk, method: "POST", path: "/staff/suppliers/2207/bank-details", status: 302, bytes: 0, sent: 612, ua, severity: "medium", mitre: "T1657", tactic: IMPACT,
      description: "Supplier portal answered a bank details change" }),
    atkGet("web_cr_017", 66, "/staff/suppliers/export", "format=csv", 2118400, "Supplier portal answered a supplier export", { severity: "medium", mitre: "T1213", tactic: COLLECT }),
    ticket({ id: "web_cr_018", ts: T(190), table: "incident", number: "INC0093310", state: "New", severity: "informational", callerId: "j.chen@nexacorp.com", extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" }, 
      shortDescription: "Supplier 2207 says the bank details on its portal record changed without a request from them", description: "ServiceNow incident INC0093310 (New): supplier bank details changed" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2b. Header injection into a quote-sharing mailer on IIS: the subject parameter becomes a header block.
// The WAF blocks the plain line break; a double-encoded one the application decodes twice passes.
// ══════════════════════════════════════════════════════════════════════════════
function crlfMailer(): TelemetryEvent[] {
  const T = clock("2026-10-20T09:58:00Z");
  const w: WebSite = { site: "quotes.nexacorp.com", host: "web-quotes-01.nexacorp.com", ip: "10.20.41.66", server: "iis" };
  const atk = "203.0.113.228", pen = "198.51.100.242", cust = "198.51.100.243", mailer = "api.mailer-cloud.example", mailerIp = "198.51.100.241";
  const api = "/api/quote/share", ua = PY, PEN_UA = "Mozilla/5.0 (compatible; RedTeamLab-Assessment/2026)";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const send = (id: string, min: number, out: number, extra = {}) => panWeb({ id, ts: T(min), ...host, url: `https://${mailer}/v3/mail/send`, domain: mailer, dstIp: mailerIp, method: "POST",
    category: "business-and-economy", action: "allow", userAgent: "QuoteMailer/1.8 (.NET 8.0)", bytesOut: out, bytesIn: 202, severity: "low",
    description: `Server sent a request to a mail delivery API (${bytesText(out)} bytes sent)`, ...extra });
  const blocked = (id: string, min: number, src: string, agent: string, query: string, matched: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: src, method: "POST", path: api, query, action: "block",
    rule: "crlf_query", matched, location: "ARGS:subject", ua: agent, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a line break in a query parameter", ...extra });
  const passed = (id: string, min: number, query: string, sent: number) => wafRequest(w, { id, ts: T(min), srcIp: atk, method: "POST", path: api, query, action: "allow", sent, bytes: 96, ua, severity: "low",
    description: "WAF passed a request to the quote share API" });
  const shared = (id: string, min: number, query: string, sent: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: api, query, sent, bytes: 96, ua, mitre: "T1190", tactic: IA,
    description: `Quote site answered a share request (${bytesText(sent)} bytes in)`, ...extra });
  const q1 = "to=qa%40mail-drop.example&subject=Quote%250D%250ABcc%3A%20...";
  const q2 = "to=list1%40mail-drop.example&subject=Quote%250D%250ABcc%3A%20...";
  return [
    ticket({ id: "web_cl_001", ts: T(0), table: "change_request", number: "CHG0044750", state: "Implement", severity: "informational",
      shortDescription: `Web penetration test of the quotes site, source ${pen}, this week`, description: "ServiceNow change CHG0044750 (Implement): web penetration test of the quotes site",
      extra: changeFields({ requestedBy: "m.levi@nexacorp.com", group: "Security Operations", ci: "quotes-site", from: T(-120), hours: 72,
        detail: `Annual web penetration test of the quotes site by the contracted testing firm from ${pen}, mail features in scope (times UTC).` }) }),
    lookalike(send("web_cl_002", 2, 61804, { repeatCount: 212 }),
      "The scheduled quote reminder run: at 10:00 every weekday the quote service mails customers with open quotes through the same delivery API, and no share request came in before it."),
    webAccess(w, { id: "web_cl_003", ts: T(6), srcIp: cust, method: "POST", path: api, query: "to=buyer%40customer-co.example&subject=Your+quote+Q-2026-1187", sent: 488, bytes: 96, ua: CHROME, isBaseline: true,
      description: `Quote site answered a share request (${bytesText(488)} bytes in)` }),
    baseline(send("web_cl_004", 6.01, 2210)),
    blocked("web_cl_005", 13, pen, PEN_UA, "to=pt%40pentest.example&subject=t%0D%0ABcc%3A%20...", "%0D%0ABcc:", { isDetection: true, verdict: "fp",
      fpExplanation: "The penetration test under CHG0044750: the source address and the tester's declared user agent match the change, the request was blocked, and the server sent no mail after it." }),
    blocked("web_cl_006", 37, atk, ua, "to=qa%40mail-drop.example&subject=Quote%0D%0ABcc%3A%20...", "%0D%0ABcc:", { isDetection: true }),
    blocked("web_cl_007", 37.5, atk, ua, "to=qa%40mail-drop.example&subject=Quote%0ABcc%3A%20...", "%0ABcc:"),
    passed("web_cl_008", 39, q1, 512),
    shared("web_cl_009", 39.01, q1, 512),
    send("web_cl_010", 39.02, 2318, { mitre: "T1190", tactic: IA }),
    passed("web_cl_011", 44, q2, 8412),
    shared("web_cl_012", 44.01, q2, 8412, { mitre: "T1566.002" }),
    send("web_cl_013", 44.02, 48210, { severity: "low", mitre: "T1566.002", tactic: IA }),
    passed("web_cl_014", 46, q2.replace("list1", "list2"), 8398),
    shared("web_cl_015", 46.01, q2.replace("list1", "list2"), 8398, { mitre: "T1566.002" }),
    send("web_cl_016", 46.02, 47980, { mitre: "T1566.002", tactic: IA }),
    ticket({ id: "web_cl_017", ts: T(97), table: "incident", number: "INC0093402", state: "New", severity: "informational", callerId: "a.kaplan@nexacorp.com", extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" }, 
      shortDescription: "Customers forward 'Your quote' emails from the quotes site asking them to confirm a payment on an outside page", description: "ServiceNow incident INC0093402 (New): customer reports of quote emails" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3a. Prototype pollution on a Node.js account site (iisnode on IIS / Windows): a preferences merge
// makes every account read as admin until the process restarts.
// ══════════════════════════════════════════════════════════════════════════════
function protoAdmin(): TelemetryEvent[] {
  const T = clock("2026-10-21T14:00:00Z");
  const w: WebSite = { site: "account.nexacorp.com", host: "web-account-01.nexacorp.com", ip: "10.20.41.68", server: "iis" };
  const atk = "203.0.113.238", ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const prefs = "/api/v1/preferences", rule = "BlockPrototypeKeysInBody";
  const NODE = "\"C:\\Program Files\\nodejs\\node.exe\" \"C:\\Program Files\\iisnode\\interceptor.js\" \"D:\\sites\\account\\server.js\"";
  return [
    webAccess(w, { id: "web_pp_001", ts: T(1), srcIp: "198.51.100.250", method: "PATCH", path: prefs, sent: 188, bytes: 412, ua: CHROME, isBaseline: true, description: "Account site answered a preferences change" }),
    wafRequest(w, { id: "web_pp_002", ts: T(6), srcIp: "198.51.100.251", method: "POST", path: "/api/v1/support/tickets", action: "block", rule: "custom", ruleName: rule, matched: "__proto__", location: "REQUEST_BODY",
      ua: MAC, sent: 3120, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "A customer's support ticket with a pasted JavaScript error trace: the key sits inside the ticket's text, the request went to the ticket form, and the customer sent it again without the trace a minute later.",
      description: "Custom rule matched a prototype key in a request body" }),
    webAccess(w, { id: "web_pp_003", ts: T(7.5), srcIp: "198.51.100.251", method: "POST", path: "/api/v1/support/tickets", status: 201, sent: 1240, bytes: 318, ua: MAC, isBaseline: true, description: "Account site answered a new support ticket" }),
    webAccess(w, { id: "web_pp_004", ts: T(40), srcIp: atk, method: "POST", path: "/api/v1/login", sent: 96, bytes: 512, ua, description: "Account site answered a sign-in" }),
    webAccess(w, { id: "web_pp_005", ts: T(40.5), srcIp: atk, path: "/api/v1/admin/customers", status: 403, bytes: 61, ua, description: "Account site refused an admin request" }),
    wafRequest(w, { id: "web_pp_006", ts: T(42), srcIp: atk, method: "PATCH", path: prefs, action: "block", rule: "custom", ruleName: rule, matched: "__proto__", location: "REQUEST_BODY", ua, sent: 204,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "Custom rule matched a prototype key in a request body" }),
    wafRequest(w, { id: "web_pp_007", ts: T(43), srcIp: atk, method: "PATCH", path: prefs, action: "allow", sent: 231, bytes: 412, ua, severity: "low", description: "WAF passed a request to /api/v1/preferences" }),
    webAccess(w, { id: "web_pp_008", ts: T(43.01), srcIp: atk, method: "PATCH", path: prefs, sent: 231, bytes: 412, ua, mitre: "T1190", tactic: IA, description: "Account site answered a preferences change" }),
    webAccess(w, { id: "web_pp_009", ts: T(44), srcIp: atk, path: "/api/v1/admin/customers", bytes: 40218, ua, severity: "medium", mitre: "T1068", tactic: PRIV, description: "Account site answered an admin request" }),
    webAccess(w, { id: "web_pp_010", ts: T(46), srcIp: atk, path: "/api/v1/admin/customers/export", query: "format=csv", bytes: 18440211, ua, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: "Account site answered a customer export" }),
    mdeFile({ id: "web_pp_011", ts: T(46.02), ...host, path: "D:\\sites\\account\\exports\\customers-20261021-1446.csv", sha256: null, size: 18440211, initiatingProcess: "node.exe", initiatingCmdline: NODE,
      severity: "medium", mitre: "T1213", tactic: COLLECT, description: `File written on ${w.host}` }),
    webAccess(w, { id: "web_pp_012", ts: T(51), srcIp: "198.51.100.252", path: "/api/v1/admin/customers", bytes: 40306, ua: CHROME, description: "Account site answered an admin request" }),
    ticket({ id: "web_pp_013", ts: T(58), table: "incident", number: "INC0093455", state: "In Progress", severity: "informational", callerId: "a.kaplan@nexacorp.com", extra: { "servicenow.assigned_to": "l.ferreira@nexacorp.com", "servicenow.assignment_group": "Service Desk" }, 
      shortDescription: "Customers report an Admin tab after signing in to the account site", description: "ServiceNow incident INC0093455 (In Progress): customers see an Admin tab" }),
    baseline(mdeProcess({ id: "web_pp_014", ts: T(66), ...host, runAsUser: "IIS APPPOOL\\account", accountName: "account", accountDomain: "IIS APPPOOL", parentName: "w3wp.exe", parentPid: 5120,
      processName: "node.exe", processPath: "C:\\Program Files\\nodejs\\node.exe", cmdline: NODE, pid: 8804, sha256: makeSha256("program_files_nodejs_node_exe_signed"), signed: true, integrity: "High",
      description: `Process started on ${w.host}` })),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3b. Prototype pollution to a shell: a chart service on Linux behind nginx merges imported dashboard
// JSON; polluted spawn options run its image converter through /bin/sh, so a chart label is expanded.
// ══════════════════════════════════════════════════════════════════════════════
function protoShell(): TelemetryEvent[] {
  const T = clock("2026-10-23T10:58:00Z");
  const w: WebSite = { site: "charts.nexacorp.com", host: "web-charts-01.nexacorp.com", ip: "10.20.41.70", server: "nginx" };
  const atk = "203.0.113.239", cdn = "chart-assets-cdn.example", cdnIp = "203.0.113.240", c2 = "203.0.113.241", ua = PY;
  const host = { host: w.host, user: null, srcIp: w.ip };
  const RUN = "svc-charts", NODE = { parentName: "node", parentPid: 1880 };
  const DASH = makeSha256("usr_bin_dash_debian_signed");
  const BIN = "/tmp/.n", binHash = makeSha256("web_charts_tmp_n_payload");
  const sh = (id: string, min: number, pid: number, cmd: string, extra = {}) => csProcess({ id, ts: T(min), ...host, ...NODE, processName: "dash", processPath: "/usr/bin/dash", cmdline: cmd, pid, runAsUser: RUN,
    sha256: DASH, description: `Process started on ${w.host}`, ...extra });
  const render = (id: string, min: number, sent: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: "/api/v2/render", sent, bytes, ua,
    description: `Chart service answered a render request (${bytesText(sent)} bytes in, ${bytesText(bytes)} bytes out)`, ...extra });
  const label = (job: string, inner: string) => `/bin/sh -c convert -density 144 -label "$(${inner})" /tmp/chart-cache/r-${job}.svg /tmp/chart-cache/r-${job}.png`;
  return [
    webAccess(w, { id: "web_pg_001", ts: T(1), srcIp: "198.51.100.253", method: "POST", path: "/api/v2/render", sent: 2204, bytes: 88412, ua: MAC, isBaseline: true,
      description: `Chart service answered a render request (${bytesText(2204)} bytes in, ${bytesText(88412)} bytes out)` }),
    baseline(csProcess({ id: "web_pg_002", ts: T(1.01), ...host, ...NODE, processName: "convert", processPath: "/usr/bin/convert", cmdline: "convert -density 144 /tmp/chart-cache/r-81f2.svg /tmp/chart-cache/r-81f2.png",
      pid: 30211, runAsUser: RUN, sha256: makeSha256("usr_bin_convert_im6_debian_signed"), severity: "low", description: `Process started on ${w.host}` })),
    lookalike(sh("web_pg_003", 2, 30240, "sh -c find /tmp/chart-cache -type f -mmin +60 -delete", { severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC }),
      "The service's hourly cache cleanup: on the hour the app runs it through a shell, the command only deletes old chart files in its own cache folder, and no connection follows."),
    wafRequest(w, { id: "web_pg_004", ts: T(40), srcIp: atk, method: "POST", path: "/api/v2/dashboards/import", action: "block", rule: "custom", ruleName: "BlockPrototypeKeysInBody", matched: "__proto__",
      location: "REQUEST_BODY", ua, sent: 1630, severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "Custom rule matched a prototype key in a request body" }),
    wafRequest(w, { id: "web_pg_005", ts: T(41), srcIp: atk, method: "POST", path: "/api/v2/dashboards/import", action: "allow", status: 201, sent: 1702, bytes: 284, ua, severity: "low",
      description: "WAF passed a request to /api/v2/dashboards/import" }),
    webAccess(w, { id: "web_pg_006", ts: T(41.01), srcIp: atk, method: "POST", path: "/api/v2/dashboards/import", status: 201, sent: 1702, bytes: 284, ua, mitre: "T1190", tactic: IA,
      description: "Chart service answered a dashboard import" }),
    render("web_pg_007", 42, 1184, 1210, { mitre: "T1190", tactic: IA }),
    sh("web_pg_008", 42.01, 30512, label("9c41", "id"), { severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC }),
    csProcess({ id: "web_pg_009", ts: T(42.02), ...host, parentName: "dash", parentPid: 30512, processName: "id", processPath: "/usr/bin/id", cmdline: "id", pid: 30515, runAsUser: RUN,
      sha256: makeSha256("usr_bin_id_debian_signed"), severity: "medium", mitre: "T1033", tactic: DISC, description: `Process started on ${w.host}` }),
    render("web_pg_010", 45, 1236, 1208, { mitre: "T1105", tactic: C2 }),
    sh("web_pg_011", 45.01, 30588, label("9c47", "curl ..."), { severity: "medium", mitre: "T1105", tactic: C2 }),
    panWeb({ id: "web_pg_012", ts: T(45.02), ...host, url: `https://${cdn}/n`, domain: cdn, dstIp: cdnIp, category: "unknown", action: "alert", userAgent: "curl/7.88.1", bytesIn: 2841200,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    csFile({ id: "web_pg_013", ts: T(45.03), ...host, path: BIN, sha256: binHash, size: 2841200, actorProcess: "curl", actorPath: "/usr/bin/curl", actorPid: 30591, actorParentName: "dash", actorParentPid: 30588,
      runAsUser: RUN, severity: "medium", mitre: "T1105", tactic: C2, description: `File written on ${w.host}` }),
    render("web_pg_014", 48, 1220, 1206, { mitre: "T1059.004", tactic: EXEC }),
    sh("web_pg_015", 48.01, 30644, label("9c52", "/tmp/.n"), { severity: "medium", mitre: "T1059.004", tactic: EXEC }),
    csProcess({ id: "web_pg_016", ts: T(48.02), ...host, parentName: "dash", parentPid: 30644, processName: ".n", processPath: BIN, cmdline: BIN, pid: 30650, runAsUser: RUN, sha256: binHash,
      severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC, description: `Process started on ${w.host}` }),
    asUser(csNetwork({ id: "web_pg_017", ts: T(48.2), ...host, remoteIp: c2, remotePort: 443, processName: ".n", processPath: BIN, cmdline: BIN, pid: 30650, parentName: "dash", parentPid: 30644, sha256: binHash,
      severity: "medium", mitre: "T1071.001", tactic: C2, description: `Outbound connection from ${w.host}` }), RUN),
    csProcess({ id: "web_pg_018", ts: T(53), ...host, parentName: ".n", parentPid: 30650, processName: "cat", processPath: "/usr/bin/cat", cmdline: "cat /srv/charts/.env", pid: 30702, runAsUser: RUN,
      sha256: makeSha256("usr_bin_cat_debian_signed"), severity: "medium", mitre: "T1552.001", tactic: CRED, description: `Process started on ${w.host}` }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 4a. Reflected XSS on a docs search page: the plain form is blocked, a double-encoded one passes, a
// staff editor opens the link and the editor session is then used from another address.
// ══════════════════════════════════════════════════════════════════════════════
function xssReflected(): TelemetryEvent[] {
  const T = clock("2026-10-27T08:30:00Z");
  const w: WebSite = { site: "docs.nexacorp.com", host: "web-docs-01.nexacorp.com", ip: "10.20.41.72" };
  const atk = "203.0.113.242", collect = "img-metrics-cdn.example", collectIp = "203.0.113.243", reader = "198.51.100.254", staff = "10.10.20.14", ua = FIREFOX, mail = "https://outlook.office.com/";
  const encoded = "q=%253Csvg%2520onload%253D...%253E";
  const xss = (id: string, min: number, src: string, agent: string, query: string, matched: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: src, path: "/search", query, action: "block", rule: "xss_query",
    matched, location: "ARGS:q", ua: agent, severity: "medium", mitre: "T1059.007", tactic: EXEC, description: "WAF rule matched HTML in a search query", ...extra });
  const atkGet = (id: string, min: number, path: string, query: string | undefined, bytes: number, description: string, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, path, query, bytes, ua, description, ...extra });
  return [
    webAccess(w, { id: "web_rx_001", ts: T(2), srcIp: "198.51.100.37", path: "/search", query: "q=vpn+setup", bytes: 14220, ua: CHROME, isBaseline: true, description: "Docs site answered a search" }),
    webAccess(w, { id: "web_rx_002", ts: T(5), srcIp: staff, path: "/editor/pages", bytes: 22140, ua: CHROME, isBaseline: true, description: "Docs site answered an editor page list" }),
    xss("web_rx_003", 9, reader, MAC, "q=%3Cscript%3E+tag+content+security+policy", "<script>", { isDetection: true, verdict: "fp",
      fpExplanation: "A reader searching the developer docs for the script tag, a common question there: plain words around the tag, an ordinary browser, and the same address searched again in words a minute later." }),
    webAccess(w, { id: "web_rx_004", ts: T(10), srcIp: reader, path: "/search", query: "q=script+tag+content+security+policy", bytes: 13880, ua: MAC, isBaseline: true, description: "Docs site answered a search" }),
    xss("web_rx_005", 41, atk, ua, "q=%3Cscript%3E...%3C%2Fscript%3E", "<script>", { isDetection: true }),
    xss("web_rx_006", 41.5, atk, ua, "q=%3Csvg%20onload%3D...%3E", "<svg onload="),
    wafRequest(w, { id: "web_rx_007", ts: T(43), srcIp: atk, path: "/search", query: encoded, action: "allow", bytes: 12960, ua, severity: "low", description: "WAF passed a request to /search" }),
    atkGet("web_rx_008", 43.01, "/search", encoded, 12960, "Docs site answered a search", { mitre: "T1059.007", tactic: EXEC }),
    wafRequest(w, { id: "web_rx_009", ts: T(71), srcIp: staff, path: "/search", query: encoded, action: "allow", bytes: 12960, ua: CHROME, referer: mail, severity: "low", description: "WAF passed a request to /search" }),
    webAccess(w, { id: "web_rx_010", ts: T(71.01), srcIp: staff, path: "/search", query: encoded, bytes: 12960, ua: CHROME, referer: mail, mitre: "T1059.007", tactic: EXEC, description: "Docs site answered a search" }),
    panWeb({ id: "web_rx_011", ts: T(71.02), host: "WS-OPS-2214", user: "l.ferreira@nexacorp.com", srcIp: staff, rule: DECRYPT, url: `https://${collect}/p.gif`, domain: collect, dstIp: collectIp,
      category: "unknown", action: "alert", referer: `https://${w.site}/search`, userAgent: CHROME, severity: "medium", mitre: "T1539", tactic: CRED,
      description: "User workstation requested an image from an uncategorized domain" }),
    atkGet("web_rx_012", 74, "/editor/pages", undefined, 22140, "Docs site answered an editor page list", { mitre: "T1550.004", tactic: STEALTH }),
    webAccess(w, { id: "web_rx_013", ts: T(76), srcIp: atk, method: "POST", path: "/editor/settings/api-tokens", status: 201, sent: 142, bytes: 288, ua, severity: "medium", mitre: "T1098", tactic: PERSIST,
      description: "Docs site answered an API token request" }),
    atkGet("web_rx_014", 79, "/editor/drafts/export", "format=zip", 31204118, "Docs site answered a drafts export", { severity: "medium", mitre: "T1213", tactic: COLLECT }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 4b. Open redirect on a staff portal sign-in (IIS): next= sends a staff member to a look-alike page,
// and the password is then used in Entra ID from another address. Foundation: one person, one path.
// ══════════════════════════════════════════════════════════════════════════════
function openRedirect(): TelemetryEvent[] {
  const T = clock("2026-10-29T07:40:00Z");
  const w: WebSite = { site: "people.nexacorp.com", host: "web-people-01.nexacorp.com", ip: "10.20.41.74", server: "iis" };
  const probe = "203.0.113.245", signin = "203.0.113.247", fake = "people-portal-signin.example", fakeIp = "203.0.113.246", partner = "benefits.partner-hr.example";
  const staff = "10.10.20.21", colleague = "10.10.20.33", user = "d.cohen@nexacorp.com", desk = "WS-HR-1182", mail = "https://outlook.office.com/";
  const rule = "LoginNextExternalUrl";
  const toFake = `next=https%3A%2F%2F${fake}%2Flogin`;
  const redirectRule = (id: string, min: number, src: string, query: string, matched: string, agent: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: src, path: "/login", query, action: "count",
    rule: "custom", ruleName: rule, matched, location: "ARGS:next", status: 302, bytes: 0, ua: agent, severity: "medium", mitre: "T1566.002", tactic: IA,
    description: "Custom rule matched an outside address in the sign-in next parameter", ...extra });
  const redirected = (id: string, min: number, src: string, query: string, agent: string, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: src, path: "/login", query, status: 302, bytes: 0, ua: agent,
    description: "People portal answered a sign-in page with a redirect", ...extra });
  return [
    ticket({ id: "web_or_001", ts: T(0), table: "sc_req_item", number: "RITM0052790", state: "Closed Complete", severity: "informational",
      shortDescription: `Benefits provider sign-on link from the people portal, next= ${partner}`, description: "ServiceNow request RITM0052790 (Closed Complete): benefits provider sign-on link" }),
    redirectRule("web_or_002", 3, colleague, `next=https%3A%2F%2F${partner}%2Fsso`, `https://${partner}`, CHROME, { isDetection: true, verdict: "fp",
      fpExplanation: "The benefits provider hand-off in RITM0052790: the next address is the contracted provider the request names, from an office desk, and staff use this link every day." }),
    redirected("web_or_003", 3.01, colleague, `next=https%3A%2F%2F${partner}%2Fsso`, CHROME, { isBaseline: true }),
    redirectRule("web_or_004", 34, probe, toFake, `https://${fake}`, PY, { isDetection: true }),
    redirected("web_or_005", 34.01, probe, toFake, PY, { mitre: "T1566.002", tactic: IA }),
    redirectRule("web_or_006", 51, staff, toFake, `https://${fake}`, CHROME, { isDetection: true, referer: mail }),
    redirected("web_or_007", 51.01, staff, toFake, CHROME, { referer: mail, mitre: "T1566.002", tactic: IA }),
    panWeb({ id: "web_or_008", ts: T(51.02), host: desk, user, srcIp: staff, rule: DECRYPT, url: `https://${fake}/login`, domain: fake, dstIp: fakeIp, category: "newly-registered-domain", action: "alert",
      userAgent: CHROME, severity: "medium", mitre: "T1566.002", tactic: IA, description: "User workstation requested a page on a newly registered domain" }),
    panWeb({ id: "web_or_009", ts: T(52), host: desk, user, srcIp: staff, rule: DECRYPT, url: `https://${fake}/login`, domain: fake, dstIp: fakeIp, method: "POST", category: "newly-registered-domain", action: "alert",
      userAgent: CHROME, referer: `https://${fake}/login`, severity: "medium", mitre: "T1566.002", tactic: IA, description: "User workstation sent a form to a newly registered domain" }),
    webAccess(w, { id: "web_or_010", ts: T(52.2), srcIp: staff, path: "/payslips", bytes: 18440, ua: CHROME, referer: `https://${fake}/`, mitre: "T1566.002", tactic: IA, description: "People portal answered a payslips page" }),
    noEmpty(entraSignIn({ id: "web_or_011", ts: T(66), user, srcIp: signin, app: "People Portal", result: "success", mfa: false, managed: false, compliant: false, os: "Linux", browser: "Firefox 128.0",
      userAgent: FIREFOX, riskLevel: "medium", riskEventTypes: ["unfamiliarFeatures"], severity: "medium", mitre: "T1078.004", tactic: IA })),
    webAccess(w, { id: "web_or_012", ts: T(67), srcIp: signin, path: "/profile/bank", bytes: 6120, ua: FIREFOX, mitre: "T1078.004", tactic: IA, description: "People portal answered a bank details page" }),
    webAccess(w, { id: "web_or_013", ts: T(69), srcIp: signin, method: "POST", path: "/profile/bank", status: 302, bytes: 0, sent: 388, ua: FIREFOX, severity: "medium", mitre: "T1657", tactic: IMPACT,
      description: "People portal answered a bank details change" }),
  ];
}

/**
 * GlobalLogis runs Sophos on its endpoints: Sophos Central keeps no record of a Linux server's process and network
 * events, so a story told through them would show at GlobalLogis without its native records.
 */
const NOT_GLOBALLOGIS = ["nexacorp", "rocketstack", "medcore", "quantumbank"];

export const WEB_INJECTION_CLIENT_STORIES: WebStoryDef[] = [
  { id: "web-inj-log4shell-useragent", family: "web-inj-log4shell", mode: "solo", title: "Help Center Server Calling Out on Port 1389", complexity: "core", events: log4jUserAgent(), companies: NOT_GLOBALLOGIS },
  { id: "web-inj-log4shell-apiheader", family: "web-inj-log4shell", mode: "team", title: "Search API Resolving an Unknown Name and Starting a New Program", complexity: "advanced", events: log4jApiHeader() },
  { id: "web-inj-crlf-fixation", family: "web-inj-crlf", mode: "solo", title: "Staff Session on the Supplier Portal Used From Outside", complexity: "core", events: crlfFixation() },
  { id: "web-inj-crlf-mailer", family: "web-inj-crlf", mode: "team", title: "Quote Mailer Sending More Than Quotes", complexity: "advanced", events: crlfMailer() },
  { id: "web-inj-proto-admin", family: "web-inj-proto-pollution", mode: "solo", title: "Customer Accounts Seeing the Admin Tab", complexity: "core", events: protoAdmin() },
  { id: "web-inj-proto-shell", family: "web-inj-proto-pollution", mode: "team", title: "Chart Service Running Commands Through Its Converter", complexity: "advanced", events: protoShell() },
  { id: "web-inj-xss-reflected", family: "web-inj-xss-redirect", mode: "solo", title: "Docs Editor Session Used From Another Address", complexity: "core", events: xssReflected(), seat: "it" },
  { id: "web-inj-open-redirect", family: "web-inj-xss-redirect", mode: "team", title: "People Portal Sign-In Link Leading Off Site", complexity: "foundation", events: openRedirect() },
];
