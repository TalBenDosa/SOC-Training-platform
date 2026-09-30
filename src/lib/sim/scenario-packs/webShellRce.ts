import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { webShellRceScenarioEvents } from "./webShellRce.events";

/**
 * SQL Injection → Web Shell → Server Compromise (ADVANCED)
 *
 * Web-application attack chain against an internet-facing IIS storefront that sits
 * behind an ALB with AWS WAF in front of it. Four telemetry planes are involved:
 *
 *   waf          — AWS WAF (regional web ACL on the ALB)
 *   siem         — IIS W3C access log, ingested into the Sentinel W3CIISLog table
 *   db_monitor   — Microsoft SQL Server Audit (sys.fn_get_audit_file columns)
 *   edr          — Microsoft Defender for Endpoint on the web server itself
 *
 * Privilege chain (see SPEC rule 1):
 *   evt_01  4672 proves the ShopPortal app-pool identity holds SeImpersonatePrivilege.
 *   evt_11  the .aspx web shell is written by w3wp.exe, i.e. by the app pool itself.
 *   evt_12  the first shell command runs as IIS APPPOOL\ShopPortal at MEDIUM integrity.
 *   evt_13  only after PrintSpoofer abuses the privilege from evt_01 does anything
 *           run as NT AUTHORITY\SYSTEM. The shell is never SYSTEM on its own.
 */
export function buildWebShellRceScenario(scenarioId = "webshell-sqli-2026"): ScenarioBundle {
  const { title, events, T, MIN, web, atkA, atkB, atkC, c2Ip, c2Dom, shellHash, spoofHash } = webShellRceScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip", value: atkA, first_seen: T(0), last_seen: T(19 * MIN), reputation: "malicious", tags: ["external", "scanning"] },
    { type: "ip", value: atkB, first_seen: T(24 * MIN), last_seen: T(24 * MIN), reputation: "malicious", tags: ["external", "scanning"] },
    { type: "ip", value: atkC, first_seen: T(38 * MIN), last_seen: T(47 * MIN), reputation: "malicious", tags: ["external", "exploitation"] },
    { type: "ip", value: c2Ip, first_seen: T(64 * MIN), last_seen: T(64 * MIN), reputation: "malicious", tags: ["c2", "external"] },
    { type: "domain", value: c2Dom, first_seen: T(64 * MIN), last_seen: T(64 * MIN), reputation: "malicious", tags: ["c2", "external"] },
    { type: "sha256", value: shellHash, first_seen: T(47 * MIN), reputation: "malicious", tags: ["webroot", "aspx"] },
    { type: "sha256", value: spoofHash, first_seen: T(55 * MIN), reputation: "malicious", tags: ["unsigned", "dropped-binary"] },
    { type: "url", value: `https://${web.site}/admin/content/upload.ashx`, first_seen: T(47 * MIN), reputation: "suspicious", tags: ["legacy-handler", "unauthenticated-key"] },
    { type: "host", value: web.hostname, first_seen: T(38 * MIN), reputation: "unknown", tags: ["compromised", "internet-facing"] },
    { type: "user", value: "IIS APPPOOL\\ShopPortal", first_seen: T(47 * MIN), reputation: "suspicious", tags: ["service-account", "abused"] },
  ];

  const killchain = [
    { ts: T(0), phase: "Reconnaissance", action: "214 content-discovery requests from 45.146.130.72 — all 404, python-requests User-Agent" },
    { ts: T(19 * MIN), phase: "Initial Access — Blocked", action: "AWS WAF blocks a tautology injection on /products/search.aspx (403)" },
    { ts: T(24 * MIN), phase: "Initial Access — Blocked", action: "AWS WAF blocks a UNION SELECT on /products/detail.aspx from a rotated IP (403)" },
    { ts: T(38 * MIN), phase: "Initial Access — Success", action: "Injection in a 12,438-byte JSON body passes uninspected; IIS returns 200 with 3.3 MB" },
    { ts: T(38 * MIN), phase: "Collection", action: "UNION against dbo.Customers returns 42,318 rows as shopportal_app" },
    { ts: T(44 * MIN), phase: "Credential Access", action: "dbo.AppSettings read out through the same injection — deploy key disclosed" },
    { ts: T(47 * MIN), phase: "Persistence", action: "Web shell bootstrap.bundle.aspx written to the webroot by w3wp.exe (IIS APPPOOL\\ShopPortal)" },
    { ts: T(52 * MIN), phase: "Execution", action: "cmd.exe spawned by w3wp.exe at Medium integrity as the app pool account" },
    { ts: T(55 * MIN), phase: "Command and Control", action: "PrintSpoofer-style privesc tool srv.exe uploaded through the same upload.ashx handler and written to the vendor asset folder" },
    { ts: T(58 * MIN), phase: "Privilege Escalation", action: "srv.exe abuses SeImpersonatePrivilege to spawn cmd.exe as NT AUTHORITY\\SYSTEM" },
    { ts: T(64 * MIN), phase: "Exfiltration", action: "curl.exe uploads 3,312,486 bytes to cdn-shopassets.link over HTTPS" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Three sources in this timeline triggered SQL injection signatures. Which one is scanning noise rather than exploitation, and on what evidence?",
      hint: "Compare the source addresses, the User-Agent strings, and whether anything downstream ever changed.",
      kind: "single",
      options: [
        { value: "qualys", label: "64.39.106.131 — a single fixed IP, a self-identifying scanner User-Agent, every payload blocked, and no database or endpoint activity follows it" },
        { value: "atk_a", label: "45.146.130.72 — its requests all returned 404 or 403, so nothing it sent ever reached application code or produced a usable result for it" },
        { value: "atk_c", label: "91.242.229.35 — it used an ordinary desktop browser User-Agent and the WAF allowed its request, which is exactly what normal customer traffic looks like" },
        { value: "none", label: "None of them are noise — all three addresses sent the same payload families, so all three must be treated as active attackers" },
      ],
      answer: "qualys",
      xp: 80,
      explanation:
        "The Qualys address is inside the whitelisted ASV scanner range, never rotates, announces itself in the User-Agent, and is followed by no SQL Server Audit record and no endpoint activity. 45.146.130.72 is not noise: its 404 sweep is the reconnaissance that precedes the probes, and it is the first of three addresses in a rotation. 91.242.229.35 is the opposite of noise — it is the address whose request succeeded. Treating all three the same is what buries the real one: signature parity is not intent parity, and the discriminator is what happened downstream.",
    },
    {
      id: "q2",
      prompt: "Why did AWS WAF allow the request at 09:38 when it had blocked structurally similar payloads minutes earlier?",
      hint: "Read oversizeFields and the excludedRules entry in the ALLOW record together.",
      kind: "single",
      options: [
        { value: "oversize", label: "The 12,438-byte body exceeded the 8 KB body-inspection limit, and SizeRestrictions_BODY was overridden to count-only, so the oversized request was passed on uninspected" },
        { value: "iprep", label: "The source address had a clean reputation and no matching entry in the IP reputation rule group, so the web ACL short-circuited evaluation before the managed SQLi rules ran" },
        { value: "method", label: "The managed SQLi rule group only inspects GET query strings, so a POST request is never evaluated against SQL injection signatures by that rule group at all" },
        { value: "sensitivity", label: "The SQLi rule group was running at LOW sensitivity, which does not match UNION-based payloads and only detects simple tautologies such as OR 1=1" },
      ],
      answer: "oversize",
      xp: 100,
      explanation:
        "oversizeFields lists REQUEST_BODY: WAF saw the body was over the 8 KB regional inspection limit and inspected only the first 8 KB, and the injected fragment sat past that. SizeRestrictions_BODY, the rule that would normally block an oversized body, was set to count-only, so nothing stopped the request. The distractors each name a real mechanism used wrongly: reputation groups do not short-circuit later rule groups; the SQLi group inspects body and headers too, not just query strings; and LOW sensitivity still matches UNION patterns — it reduces false positives, it does not skip whole payload classes. The takeaway is that an ALLOW verdict means 'no rule terminated', not 'this request was examined and found safe'.",
    },
    {
      id: "q3",
      prompt:
        "The IIS access record for the successful request shows cIP 10.40.12.9, an internal address. What is the correct way to attribute that request to an external source?",
      hint: "Two events describe the same HTTP transaction from two different vantage points.",
      kind: "single",
      options: [
        { value: "waf_pivot", label: "Pivot to the AWS WAF ALLOW record for the same URI and timestamp — its httpRequest.clientIp holds the real caller, since IIS logs only the load balancer" },
        { value: "trust_iis", label: "Treat 10.40.12.9 as the attacker and hunt internally, because the web server's own access log is the authoritative record of who actually connected to it" },
        { value: "dns_lookup", label: "Resolve the csHost value back through DNS to obtain the public address that the storefront hostname pointed at when the request arrived" },
        { value: "edr_socket", label: "Use the Defender network events on WEB-SHOP-01, which record the remote address of every inbound socket the IIS worker process accepted" },
      ],
      answer: "waf_pivot",
      xp: 100,
      explanation:
        "IIS behind an ALB sees the load balancer as its peer, so cIP is 10.40.12.9 for every request and carries no attribution value. Only the WAF record, taken at the edge, holds httpRequest.clientIp = 91.242.229.35; matching it to the IIS record by URI, timestamp and the 12,438-byte csBytes value is the correlation. Chasing 10.40.12.9 sends the investigation into your own infrastructure. DNS resolves your hostname, not the caller's address. And the EDR network events in this timeline are outbound — inbound sockets terminate at the load balancer, not at the attacker.",
    },
    {
      id: "q4",
      prompt: "Immediately after the web shell's first command at 09:52, what privileges did the attacker actually hold on WEB-SHOP-01?",
      hint: "Read the account and integrity level on the cmd.exe process, then look at what changed six minutes later.",
      kind: "single",
      options: [
        { value: "apppool", label: "Only those of IIS APPPOOL\\ShopPortal at Medium integrity — SYSTEM was reached six minutes later by abusing SeImpersonatePrivilege, not by the shell itself" },
        { value: "system_now", label: "SYSTEM already, because IIS worker processes run under the local system account and every child they spawn inherits that same elevated token" },
        { value: "admin", label: "Local administrator, since writing a new file into C:\\inetpub\\wwwroot requires administrative rights on the web server's filesystem" },
        { value: "sqlsa", label: "Those of shopportal_app on the database server, because the shell was delivered through the SQL injection and inherits that login's server-level context" },
      ],
      answer: "apppool",
      xp: 100,
      explanation:
        "The 09:52 process shows AccountName ShopPortal, AccountDomain IIS APPPOOL, ProcessIntegrityLevel Medium — a constrained service identity. SYSTEM only appears at 09:58, after srv.exe uses the SeImpersonatePrivilege that the 4672 record at the top of the timeline shows the app pool was granted; that is the Potato-family pattern and it is a separate, visible step. w3wp.exe does not run as SYSTEM under any default configuration. The webroot is writable by the app pool identity by design, so the file write proves nothing about admin rights. And a SQL login grants database permissions, not a Windows token on the web server.",
    },
    {
      id: "q5",
      prompt: "Which MITRE ATT&CK techniques are evidenced in this timeline? (select all that apply)",
      kind: "multi",
      options: [
        { value: "T1190", label: "T1190 — Exploit Public-Facing Application (the injection that IIS answered with 200)" },
        { value: "T1213", label: "T1213 — Data from Information Repositories (42,318 rows read from dbo.Customers)" },
        { value: "T1505.003", label: "T1505.003 — Server Software Component: Web Shell (bootstrap.bundle.aspx in the webroot)" },
        { value: "T1134.001", label: "T1134.001 — Access Token Manipulation: Token Impersonation (SeImpersonate abuse to SYSTEM)" },
        { value: "T1078.002", label: "T1078.002 — Valid Accounts: Domain Accounts (reuse of a stolen domain credential)" },
      ],
      answer: ["T1190", "T1213", "T1505.003", "T1134.001"],
      xp: 120,
      explanation:
        "T1190 covers the successful injection against the internet-facing application; T1213 covers the bulk read of a business data repository through it; T1505.003 is the .aspx web shell persisted in the webroot; T1134.001 is the SeImpersonatePrivilege abuse that produced the SYSTEM token. T1078.002 is not present — no domain account is ever authenticated in this chain. The only identities involved are a SQL login (shopportal_app), a local IIS virtual account, and finally SYSTEM, all reached without a single stolen user credential. Also worth noting: the AppSettings read maps to T1552 (Unsecured Credentials) and the command execution to T1059.003, so a complete mapping is broader than these five options.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-BRASSVINE (opportunistic web exploitation crew)",
    attack_kind: "web_exploitation",
    briefing: "Two alerts for shop.nexacorp.com are queued: a burst of blocked SQL injection attempts against the site this morning, and a Defender for Endpoint detection on WEB-SHOP-01 at 09:52 involving the IIS worker process. The quarterly PCI ASV scan is also running today.",
    narrative: `NexaCorp's storefront, shop.nexacorp.com, runs on IIS on WEB-SHOP-01 behind an ALB with an AWS WAF web ACL and the AWS managed rule sets enabled. On Tuesday 17 March the SOC's WAF dashboard looks healthy: dozens of SQL injection attempts, all blocked, 403 across the board. Some of them are the authorized quarterly PCI ASV scan; some of them are not.

At 09:38 a single POST to an inventory lookup API — 12,438 bytes of JSON, an ordinary browser User-Agent, a source address that had not appeared before — is allowed through. IIS answers it with 200 and 3.3 MB. Nine minutes later a file called bootstrap.bundle.aspx appears in the site's JavaScript vendor folder, written there by the IIS worker process itself. By 10:04 something running as SYSTEM is uploading data to an external host.

Your job: work out which of the blocked events mattered and which were noise, explain in the WAF's own log fields why the one request that counted was never inspected, correlate the edge record with the web server record when the access log only knows about the load balancer, and state precisely what privileges the attacker held at each stage — including the moment they stopped being a web application and became the server.`,
    learning_objectives: [
      "Trace a web application attack across four telemetry planes — WAF, web server access log, database audit, and endpoint EDR",
      "Explain, from WAF log fields alone, why an ALLOW verdict is not evidence that a request was inspected or safe",
      "Correlate a WAF record with a web server access log when the access log records only the load balancer's address",
      "Separate authorized vulnerability-scanning noise from genuine exploitation that fires the same signatures",
      "Establish the privilege chain of a web shell — service account first, and an explicit escalation event before any SYSTEM activity",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
