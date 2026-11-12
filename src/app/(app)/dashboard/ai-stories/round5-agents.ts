/**
 * AI round, agent families (round5.ts): each family has one single-player variant and one Team Training variant,
 * with their own people, hosts, addresses, repositories, tickets and plot.
 *
 *  1. ai-toxic-agent-flow: an AI agent holding a GitHub token reads a public issue written by an outsider and is
 *     steered by it (Invariant Labs, GitHub MCP "toxic agent flow", May 2025). OWASP LLM01 + LLM06, ATLAS AML.T0051.001.
 *     - ai-agent-public-pr-from-private-reads (solo, core): a developer's coding assistant with the GitHub MCP server
 *       reads private repositories and opens a pull request on the company's public SDK.
 *     - ai-agent-org-token-repo-exposure (team, advanced): a release agent with an organization-wide token opens pull
 *       requests on two public repositories and makes a private repository public.
 *  2. ai-output-handling: the application trusts what the model writes (OWASP LLM05 Improper Output Handling).
 *     - ai-portal-assistant-unfiltered-query (solo, core): a portal assistant turns questions into SQL and runs the
 *       model's query as its own database login: one customer's session reads every customer's accounts.
 *     - ai-helpdesk-reply-renders-in-console (team, advanced): a help-desk bot's reply is rendered as HTML in the
 *       support console; the agent's browser calls an outside domain and the console session is used from outside.
 *
 * Effects only: the logs show processes, connections, records, sizes and verdicts, never a prompt, the issue text,
 * the generated markup or a working query against the application.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { githubAudit } from "@/lib/sim/emitters/github";
import { webAccess, type WebSite } from "@/lib/sim/emitters/web";
import { azureOpenAiRequest, defenderAiAlert, type AzureAiResource } from "@/lib/sim/emitters/azureAi";
import type { AiStoryDef } from "./wave2";
import { CX, DEV, OFFICE_EGRESS, SUB, benign, netRow, proc, sentinel, ticket, web, withIncident } from "./wave4-shared";

const IA = "Initial Access", COLLECT = "Collection", EXFIL = "Exfiltration", EXEC = "Execution", CRED = "Credential Access", PERSIST = "Persistence", LATERAL = "Lateral Movement";
const at = (iso: string) => { const b = Date.parse(iso); return (min: number) => new Date(b + min * 60_000).toISOString(); };
const UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
const UA_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";
const UA_SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15";

/**
 * One GitHub audit event for a person's (or service account's) token. The login is left to the native record, which
 * derives the Enterprise Managed User login from the corporate address, so it follows the person a session draws.
 */
function gh(o: {
  id: string; ts: string; user: string; ip: string; action: string; org?: string; repo?: string; visibility?: "public" | "private";
  ua: string; access?: string; tokenName?: string; prNumber?: number; prTitle?: string; extra?: Record<string, string | number>;
  severity: TelemetryEvent["severity"]; description: string; mitre?: string; tactic?: string; isDetection?: boolean;
}): TelemetryEvent {
  const e = githubAudit({
    companyId: CX, id: o.id, ts: o.ts, action: o.action, actor: "", actorIp: o.ip, user: o.user, userAgent: o.ua,
    org: o.org, repo: o.repo, visibility: o.visibility, category: "web", severity: o.severity, mitre: o.mitre, tactic: o.tactic, description: o.description,
    extra: {
      ...(o.access ? { "github.programmatic_access_type": o.access } : {}),
      ...(o.tokenName ? { "github.token.name": o.tokenName } : {}),
      ...(o.prNumber ? { "github.pull_request.number": String(o.prNumber) } : {}),
      ...(o.prTitle ? { "github.pull_request.title": o.prTitle } : {}),
      ...(o.extra ?? {}),
    },
  });
  // No login is authored: the native record derives the employee's EMU login from user_email.
  const { "github.actor": _login, ...raw } = e.raw ?? {};
  void _login;
  return { ...e, raw, ...(o.isDetection ? { is_detection: true } : {}) };
}

// ══════════════════════════════════════════════════════════════════════════════
// 1a. Toxic agent flow, single-player: a coding assistant's PR on the public SDK
// ══════════════════════════════════════════════════════════════════════════════
function agentPublicPr(): TelemetryEvent[] {
  const T = at("2026-10-27T13:00:00Z");
  const dev = { host: DEV.host, ip: DEV.ip, user: DEV.user };
  const home = `C:\\Users\\${DEV.bare}`;
  const pub = "nexacorp-oss/sdk-js", priv1 = "nexacorp-eng/payments-core", priv2 = "nexacorp-eng/partner-pricing";
  const api = "api.github.com", apiIp = "192.0.2.67";
  const fgPat = "Fine-grained personal access token", tokenName = "assistant-mcp", mcpUa = "github-mcp-server/0.20.2";
  const NODE = "C:\\Program Files\\nodejs\\node.exe";
  const DOCKER = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
  const call = (id: string, min: number, method: "GET" | "POST", path: string, bytesIn: number, bytesOut: number, description: string, extra: Partial<TelemetryEvent> = {}) =>
    ({ ...web(dev, { id, ts: T(min), url: `https://${api}${path}`, domain: api, dstIp: apiIp, category: "computer-and-internet-info", method, action: "allow", status: method === "POST" ? 201 : 200,
      bytesIn, bytesOut, userAgent: mcpUa, severity: "low", description }), ...extra });
  return withIncident([
    ticket({
      id: "ai5ta01", ts: T(-4320), table: "sc_req_item", number: "RITM0062214", state: "Closed Complete", caller: DEV.user, severity: "informational",
      shortDescription: `GitHub MCP server for the coding assistant: fine-grained token ${tokenName}, docs pull requests on ${pub}`,
      extra: { "servicenow.approval": "Approved", "servicenow.assignment_group": "Developer Platform", "servicenow.u_token_name": tokenName,
        "servicenow.work_notes": `Token created by the requester. Repository access: all repositories the user can reach (read), ${pub} (write). Purpose: let the assistant open documentation pull requests on the public SDK.` },
      description: `ServiceNow request RITM0062214 (Closed Complete): the coding assistant on ${DEV.host} may use the GitHub MCP server with token ${tokenName} to open docs pull requests on ${pub}.`,
    }),
    benign(gh({
      id: "ai5ta02", ts: T(-2885), user: DEV.user, ip: OFFICE_EGRESS, action: "pull_request.create", org: "nexacorp-oss", repo: pub, visibility: "public", ua: mcpUa,
      access: fgPat, tokenName, prNumber: 207, prTitle: "Docs: fix the install command in README", severity: "low", isDetection: true, mitre: "T1567.001", tactic: EXFIL,
      description: `GitHub audit log: pull_request.create on the public repository ${pub} (#207, "Docs: fix the install command in README") by the developer's GitHub account (fine-grained token ${tokenName}), client github-mcp-server, from the office address.`,
    }), `The assistant doing the job RITM0062214 approved: one docs pull request on ${pub}, opened while the developer worked on the README, with no other repository read around it.`),
    proc(dev, {
      id: "ai5ta03", ts: T(0), pid: 7412, processName: "node.exe", processPath: NODE, parentName: "Code.exe", parentPid: 6120,
      cmdline: `"${NODE}" "${home}\\.vscode\\extensions\\code-assistant-2.4.1\\dist\\agent.js" --stdio`, severity: "informational",
      description: `The coding assistant extension started its agent under VS Code on ${DEV.host}.`,
    }),
    proc(dev, {
      id: "ai5ta04", ts: T(0.2), pid: 7488, processName: "docker.exe", processPath: DOCKER, parentName: "node.exe", parentPid: 7412,
      cmdline: `"${DOCKER}" run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server`, severity: "low", mitre: "T1059", tactic: EXEC,
      description: `The assistant's agent (node.exe) started the GitHub MCP server container on ${DEV.host}, passing the token in GITHUB_PERSONAL_ACCESS_TOKEN.`,
    }),
    call("ai5ta05", 1.1, "GET", `/repos/${pub}/issues?state=open`, 48_210, 820, `Firewall URL log: the MCP server on ${DEV.host} listed the open issues of the public repository ${pub}.`, { mitre_technique: "T1190", mitre_tactic: IA }),
    call("ai5ta06", 1.3, "GET", `/repos/${pub}/issues/214`, 9_840, 760, `Firewall URL log: the MCP server read issue 214 of ${pub}, opened two days earlier by an account outside the organization.`, { mitre_technique: "T1190", mitre_tactic: IA }),
    call("ai5ta07", 1.6, "GET", "/user/repos?visibility=private&per_page=100", 61_400, 790, `Firewall URL log: the MCP server listed every private repository the developer's token can read.`, { mitre_technique: "T1213.003", mitre_tactic: COLLECT }),
    call("ai5ta08", 1.9, "GET", `/repos/${priv1}/contents/README.md`, 22_310, 780, `Firewall URL log: the MCP server read README.md of the private repository ${priv1}.`, { mitre_technique: "T1213.003", mitre_tactic: COLLECT }),
    call("ai5ta09", 2.2, "GET", `/repos/${priv2}/contents/rates/2027-partner-rates.md`, 31_904, 810, `Firewall URL log: the MCP server read rates/2027-partner-rates.md of the private repository ${priv2}.`, { mitre_technique: "T1213.003", mitre_tactic: COLLECT, severity: "medium" }),
    netRow(dev, {
      id: "ai5ta10", ts: T(2.3), remoteIp: apiIp, remotePort: 443, application: "tls", domain: api, processName: "com.docker.backend.exe", processPath: "C:\\Program Files\\Docker\\Docker\\resources\\com.docker.backend.exe",
      bytesIn: 171_400, bytesOut: 9_620, severity: "low", description: `EDR: the Docker backend on ${DEV.host} held a TLS session to ${api} (about 171 KB in) while the MCP server container ran.`,
    }),
    call("ai5ta11", 3.0, "POST", `/repos/${pub}/git/refs`, 1_120, 1_480, `Firewall URL log: the MCP server created a branch in the public repository ${pub}.`, { mitre_technique: "T1567.001", mitre_tactic: EXFIL }),
    call("ai5ta12", 3.2, "POST", `/repos/${pub}/git/blobs`, 2_310, 38_420, `Firewall URL log: the MCP server uploaded a file to the public repository ${pub}, about 38 KB sent.`, { mitre_technique: "T1567.001", mitre_tactic: EXFIL, severity: "medium" }),
    call("ai5ta13", 3.4, "POST", `/repos/${pub}/pulls`, 2_980, 1_340, `Firewall URL log: the MCP server opened a pull request on ${pub}.`, { mitre_technique: "T1567.001", mitre_tactic: EXFIL }),
    gh({
      id: "ai5ta14", ts: T(3.4), user: DEV.user, ip: OFFICE_EGRESS, action: "pull_request.create", org: "nexacorp-oss", repo: pub, visibility: "public", ua: mcpUa,
      access: fgPat, tokenName, prNumber: 219, prTitle: "Docs: add maintainers and pricing notes to README", severity: "medium", isDetection: true, mitre: "T1567.001", tactic: EXFIL,
      description: `GitHub audit log: pull_request.create on the public repository ${pub} (#219, "Docs: add maintainers and pricing notes to README") by the developer's GitHub account (fine-grained token ${tokenName}), client github-mcp-server, from the office address.`,
    }),
  ], "inc:ai5ta");
}

// ══════════════════════════════════════════════════════════════════════════════
// 1b. Toxic agent flow, Team Training: an organization-wide token makes a repository public
// ══════════════════════════════════════════════════════════════════════════════
function orgTokenExposure(): TelemetryEvent[] {
  const T = at("2026-11-03T02:10:00Z");
  const svc = { host: "SRV-NXC-BLD04", ip: "10.20.60.14", user: "svc.release-agent@nexacorp.com" };
  const egress = "192.0.2.69", api = "api.github.com", apiIp = "192.0.2.68";
  const access = "Fine-grained personal access token", tokenName = "release-notes-agent", ua = "release-agent/3.2 octokit-rest.js/21.0.2";
  const PY = "C:\\Program Files\\Python312\\python.exe";
  const op = (o: Omit<Parameters<typeof gh>[0], "user" | "ip" | "ua" | "access" | "tokenName"> & { ua?: string }) => gh({ user: svc.user, ip: egress, ua, access, tokenName, ...o });
  return withIncident([
    ticket({
      id: "ai5tb01", ts: T(-20160), table: "change_request", number: "CHG0081377", state: "Closed", caller: "platform.lead@nexacorp.com", severity: "informational",
      shortDescription: `Release notes agent on ${svc.host}: token ${tokenName}, all repositories in nexacorp-eng and nexacorp-oss`,
      extra: { "servicenow.approval": "Approved", "servicenow.assignment_group": "Platform Engineering", "servicenow.u_token_name": tokenName,
        "servicenow.work_notes": "Nightly job: triage new issues on public repositories, draft release notes, open pull requests with the notes. Repository access: all (contents, issues, pull requests, administration)." },
      description: `ServiceNow change CHG0081377 (Closed): the nightly release notes agent on ${svc.host} uses token ${tokenName} with access to every repository of both organizations.`,
    }),
    benign(op({
      id: "ai5tb02", ts: T(-20100), action: "personal_access_token.access_granted", org: "nexacorp-eng", ua: UA_EDGE, severity: "medium", isDetection: true, mitre: "T1098.001", tactic: PERSIST,
      extra: { repository_selection: "all" },
      description: `GitHub audit log: the fine-grained token ${tokenName} of the release agent's service account was granted access to all repositories of nexacorp-eng.`,
    }), "The grant CHG0081377 approved two weeks earlier: the token, the organization and the scope match the change. Broad, and on record."),
    benign(gh({
      id: "ai5tb03", ts: T(-1500), user: "web.team@nexacorp.com", ip: "192.0.2.70", action: "repo.access", org: "nexacorp-oss", repo: "nexacorp-oss/docs-site", visibility: "public", ua: UA_SAFARI,
      severity: "high", isDetection: true, mitre: "T1567.001", tactic: EXFIL, extra: { previous_visibility: "private" },
      description: "GitHub audit log: repo.access, nexacorp-oss/docs-site changed from private to public by the web team's GitHub account in the browser.",
    }), "The planned launch of the public documentation site: a person in the browser, the repository is the docs site, and change CHG0081201 scheduled the switch for that morning."),
    proc({ host: svc.host, ip: svc.ip, user: svc.user }, {
      id: "ai5tb04", ts: T(0), pid: 5310, processName: "python.exe", processPath: PY, parentName: "svchost.exe", parentPid: 1588,
      cmdline: `"${PY}" -m release_agent --triage public --since 24h`, severity: "informational",
      description: `The scheduled task started the release notes agent on ${svc.host} under its service account.`,
    }),
    netRow({ host: svc.host, ip: svc.ip, user: svc.user }, {
      id: "ai5tb05", ts: T(0.5), remoteIp: apiIp, remotePort: 443, application: "tls", domain: api, processName: "python.exe", processPath: PY, pid: 5310,
      bytesIn: 96_300, bytesOut: 4_100, severity: "informational", description: `EDR: python.exe (release agent) on ${svc.host} connected to ${api}, about 96 KB in.`,
    }),
    netRow({ host: svc.host, ip: svc.ip, user: svc.user }, {
      id: "ai5tb06", ts: T(6), remoteIp: apiIp, remotePort: 443, application: "tls", domain: api, processName: "python.exe", processPath: PY, pid: 5310,
      bytesIn: 412_800, bytesOut: 88_600, severity: "low", mitre: "T1213.003", tactic: COLLECT,
      description: `EDR: python.exe (release agent) on ${svc.host} held a second session to ${api}: about 413 KB in and 89 KB out, four times the agent's usual nightly volume.`,
    }),
    op({
      id: "ai5tb07", ts: T(9), action: "pull_request.create", org: "nexacorp-oss", repo: "nexacorp-oss/cli-tools", visibility: "public", prNumber: 88, prTitle: "Release notes: 4.8.0 (internal changelog)",
      severity: "medium", isDetection: true, mitre: "T1567.001", tactic: EXFIL,
      description: "GitHub audit log: pull_request.create on the public repository nexacorp-oss/cli-tools (#88, \"Release notes: 4.8.0 (internal changelog)\") by the release-notes-agent token.",
    }),
    op({
      id: "ai5tb08", ts: T(11), action: "repo.access", org: "nexacorp-eng", repo: "nexacorp-eng/release-tooling", visibility: "public", severity: "high", isDetection: true, mitre: "T1567.001", tactic: EXFIL,
      extra: { previous_visibility: "private" },
      description: "GitHub audit log: repo.access, nexacorp-eng/release-tooling changed from private to public by the release-notes-agent token.",
    }),
    op({
      id: "ai5tb09", ts: T(13), action: "pull_request.create", org: "nexacorp-oss", repo: "nexacorp-oss/terraform-modules", visibility: "public", prNumber: 141, prTitle: "Release notes: modules 2.3 and environment map",
      severity: "medium", isDetection: true, mitre: "T1567.001", tactic: EXFIL,
      description: "GitHub audit log: pull_request.create on the public repository nexacorp-oss/terraform-modules (#141, \"Release notes: modules 2.3 and environment map\") by the release-notes-agent token.",
    }),
    sentinel({
      id: "ai5tb10", ts: T(13.5), srcIp: egress, entity: "nexacorp-eng/release-tooling", severity: "high", eventType: "cloud_api_call", mitre: "T1567.001", tactic: EXFIL,
      alertName: "Private GitHub repository made public by a token",
      detail: "repo.access to public on a repository that was private, performed with a token rather than in the browser.",
      startTime: T(11), endTime: T(11),
      extendedProperties: { Repository: "nexacorp-eng/release-tooling", "Previous visibility": "private", "Access type": access, Token: tokenName },
      description: "Microsoft Sentinel raised Private GitHub repository made public by a token for nexacorp-eng/release-tooling.",
    }),
    op({
      id: "ai5tb11", ts: T(14), action: "repo.download_zip", org: "nexacorp-eng", repo: "nexacorp-eng/release-tooling", visibility: "public", ua: "curl/8.9.1", severity: "medium", mitre: "T1213.003", tactic: COLLECT,
      description: "GitHub audit log: repo.download_zip of nexacorp-eng/release-tooling with the release-notes-agent token, curl client, from the build network's egress.",
    }),
  ], "inc:ai5tb");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2a. Improper output handling, single-player: the portal assistant's query has no customer filter
// ══════════════════════════════════════════════════════════════════════════════
const PORTAL_AI: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-portal-ai", account: "aoai-portal-ask-weu", region: "westeurope" };
function portalUnfilteredQuery(): TelemetryEvent[] {
  const T = at("2026-10-29T18:00:00Z");
  const w: WebSite = { site: "my.nexacorp.com", host: "web-myportal-02.nexacorp.com", ip: "10.20.42.22", server: "iis" };
  const db = { host: "sql-myportal-01.nexacorp.com", ip: "10.20.42.31", instance: "sql-myportal-01\\PORTAL" };
  const appEgress = "203.0.113.227", customer = "198.51.100.232", other = "198.51.100.234";
  const dep = { resource: PORTAL_AI, deployment: "gpt-4o-mini-ask" };
  const ask = (id: string, min: number, ip: string, ua: string, bytes: number, turn: string, extra: Partial<TelemetryEvent> = {}, description = "Portal answered an assistant question") =>
    ({ ...webAccess(w, { id, ts: T(min), srcIp: ip, method: "POST", path: "/api/assistant/ask", query: turn, bytes, sent: 640, ua, description }), ...extra });
  const sql = (o: { id: string; min: number; statement: string; object: string; description: string; severity?: TelemetryEvent["severity"]; mitre?: string; tactic?: string; isDetection?: boolean; baseline?: boolean }): TelemetryEvent => ({
    id: o.id, ts: T(o.min), source: "db_monitor", vendor: "Microsoft SQL Server Audit", event_type: "db_query", severity: o.severity ?? "low",
    hostname: db.host, src_ip: w.ip, dst_ip: db.ip, dst_port: 1433, protocol: "tcp", description: o.description,
    ...(o.mitre ? { mitre_technique: o.mitre, mitre_tactic: o.tactic } : {}), ...(o.isDetection ? { is_detection: true } : {}), ...(o.baseline ? { is_baseline: true } : {}),
    raw: { action_id: "SL", server_instance_name: db.instance, database_name: "Portal", server_principal_name: "svc_portal_ask", statement: o.statement,
      client_ip: w.ip, application_name: "Portal.Assistant", schema_name: "dbo", object_name: o.object, succeeded: "true" },
  });
  const own = "SELECT TOP (20) t.PostedOn, t.Amount, t.Merchant FROM dbo.Transactions t WHERE t.CustomerId = @p0 ORDER BY t.PostedOn DESC";
  return withIncident([
    ask("ai5oa01", 2, other, UA_SAFARI, 1_980, "conversation=c-5520417&turn=1", { is_baseline: true }),
    { ...azureOpenAiRequest({ ...dep, id: "ai5oa02", ts: T(2.01), callerIp: appEgress, status: 200, durationMs: 1_420, requestLength: 2_310, responseLength: 1_120, severity: "informational",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal's egress, HTTP 200, 2,310 bytes in, 1,120 out." }), is_baseline: true },
    benign(sql({ id: "ai5oa03", min: 2.02, statement: own, object: "Transactions", severity: "low", isDetection: true, mitre: "T1213", tactic: COLLECT,
      description: "SQL Server Audit: svc_portal_ask (Portal.Assistant) ran a SELECT on dbo.Transactions." }),
      "The assistant's normal query: the generated statement carries the CustomerId parameter the app binds to the signed-in customer, so it reads one customer's last 20 transactions."),
    ask("ai5oa04", 31, customer, UA_FIREFOX, 2_240, "conversation=c-5520981&turn=1", { mitre_technique: "T1190", mitre_tactic: IA }),
    azureOpenAiRequest({ ...dep, id: "ai5oa05", ts: T(31.01), callerIp: appEgress, status: 200, durationMs: 1_610, requestLength: 2_480, responseLength: 1_260, severity: "informational",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal's egress, HTTP 200, 2,480 bytes in, 1,260 out." }),
    sql({ id: "ai5oa06", min: 31.02, statement: "SELECT a.AccountNumber, a.Balance, a.Currency FROM dbo.Accounts a WHERE a.CustomerId = @p0", object: "Accounts", baseline: true,
      description: "SQL Server Audit: svc_portal_ask (Portal.Assistant) ran a SELECT on dbo.Accounts." }),
    ask("ai5oa07", 34, customer, UA_FIREFOX, 2_610, "conversation=c-5520981&turn=4", { mitre_technique: "T1190", mitre_tactic: IA }),
    azureOpenAiRequest({ ...dep, id: "ai5oa08", ts: T(34.01), callerIp: appEgress, status: 200, durationMs: 2_040, requestLength: 3_900, responseLength: 1_480, severity: "low", mitre: "T1190", tactic: IA,
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal's egress, HTTP 200, 3,900 bytes in, 1,480 out." }),
    sql({ id: "ai5oa09", min: 34.02, object: "Customers", severity: "high", mitre: "T1213", tactic: COLLECT,
      statement: "SELECT TOP (500) c.CustomerId, c.FullName, c.Email, c.Phone, a.Iban, a.Balance FROM dbo.Customers c JOIN dbo.Accounts a ON a.CustomerId = c.CustomerId ORDER BY a.Balance DESC",
      description: "SQL Server Audit: svc_portal_ask (Portal.Assistant) ran a SELECT joining dbo.Customers and dbo.Accounts with no CustomerId predicate, TOP (500)." }),
    azureOpenAiRequest({ ...dep, id: "ai5oa10", ts: T(34.05), callerIp: appEgress, status: 200, durationMs: 9_880, requestLength: 96_410, responseLength: 41_220, severity: "medium", mitre: "T1213", tactic: COLLECT,
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal's egress, HTTP 200, 96,410 bytes in, 41,220 out. The deployment's answers are usually under 1,500 bytes." }),
    ask("ai5oa11", 34.1, customer, UA_FIREFOX, 44_810, "conversation=c-5520981&turn=5", { mitre_technique: "T1041", mitre_tactic: EXFIL, severity: "medium" }, "Portal answered an assistant question (44,810 bytes)"),
    ask("ai5oa12", 37, customer, UA_FIREFOX, 2_870, "conversation=c-5520981&turn=6", { mitre_technique: "T1190", mitre_tactic: IA }),
    sql({ id: "ai5oa13", min: 37.02, object: "Customers", severity: "high", mitre: "T1213", tactic: COLLECT,
      statement: "SELECT c.CustomerId, c.FullName, c.Email, c.Phone, a.Iban, a.Balance FROM dbo.Customers c JOIN dbo.Accounts a ON a.CustomerId = c.CustomerId ORDER BY a.Balance DESC OFFSET 500 ROWS FETCH NEXT 500 ROWS ONLY",
      description: "SQL Server Audit: svc_portal_ask (Portal.Assistant) ran the same join with no CustomerId predicate, rows 501 to 1,000." }),
    ask("ai5oa14", 37.2, customer, UA_FIREFOX, 45_330, "conversation=c-5520981&turn=7", { mitre_technique: "T1041", mitre_tactic: EXFIL, severity: "medium" }, "Portal answered an assistant question (45,330 bytes)"),
    sentinel({
      id: "ai5oa15", ts: T(38), srcIp: customer, entity: "svc_portal_ask", severity: "high", eventType: "db_query", mitre: "T1213", tactic: COLLECT,
      alertName: "Unusual query shape from the portal assistant's SQL login",
      detail: "svc_portal_ask ran statements on dbo.Customers without the CustomerId predicate every one of its statements carried over the last 30 days.",
      startTime: T(34.02), endTime: T(37.02),
      extendedProperties: { Login: "svc_portal_ask", Application: "Portal.Assistant", Objects: "dbo.Customers, dbo.Accounts", Statements: 2 },
      description: "Microsoft Sentinel raised Unusual query shape from the portal assistant's SQL login: two statements on dbo.Customers without a CustomerId predicate.",
    }),
  ], "inc:ai5oa");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2b. Improper output handling, Team Training: a bot reply rendered in the support console
// ══════════════════════════════════════════════════════════════════════════════
const HELPDESK_AI: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-helpdesk-ai", account: "aoai-helpdesk-neu", region: "northeurope" };
function helpdeskReplyConsole(): TelemetryEvent[] {
  const T = at("2026-11-05T15:00:00Z");
  const chat: WebSite = { site: "help.nexacorp.com", host: "web-helpchat-01.nexacorp.com", ip: "10.20.43.11", server: "iis" };
  const consoleSite: WebSite = { site: "support.nexacorp.com", host: "web-supportcon-02.nexacorp.com", ip: "10.20.43.21", server: "iis" };
  const agent = { host: "WS-SUP-3108", ip: "10.10.31.8", user: "s.harel@nexacorp.com" };
  const visitor = "203.0.113.229", reuse = "203.0.113.232", botEgress = "192.0.2.71";
  const collector = "img.cdn-assets.example", collectorIp = "203.0.113.231";
  const dep = { resource: HELPDESK_AI, deployment: "gpt-4o-helpdesk" };
  const geo = { country: "Romania", iso: "RO", city: "Bucharest", lat: 44.4268, lon: 26.1025 };
  const where = { country: "Romania", city: "Bucharest" };
  const endUser = { id: "chat-session 6d0f2a91-3c7e-4b55-8e1a-0f94c2d7b316", ip: visitor, app: "help-chat" };
  const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const asAgent = (e: TelemetryEvent): TelemetryEvent => ({ ...e, user_email: agent.user });
  return withIncident([
    benign(defenderAiAlert({
      ...dep, id: "ai5ob01", ts: T(-180), alert: "maliciousUrlResponse", clientIp: botEgress, endUser: { id: "chat-session 1b7e4c02-9a5d-4f61-b2c8-7e30d5a91f44", ip: "198.51.100.235", app: "help-chat" },
      alertDescription: "A response from deployment gpt-4o-helpdesk contained a URL flagged as suspicious: track.parcel-partner.example.", severity: "high",
      description: `Defender for Cloud raised Corrupted AI application\\model\\data directed a phishing attempt at a user on ${HELPDESK_AI.account}: the reply held a link to track.parcel-partner.example.`,
    }), "The shipping partner's tracking site, which the bot links in every delivery answer: the domain is in the partner list, and the customer opened it and came back to close the chat."),
    webAccess(chat, { id: "ai5ob02", ts: T(0), srcIp: visitor, method: "POST", path: "/api/chat/messages", query: "chat=6d0f2a91&seq=1", bytes: 1_240, sent: 880, ua: UA_FIREFOX, geo: where, severity: "low", mitre: "T1190", tactic: IA,
      description: "Help chat answered a message" }),
    azureOpenAiRequest({ ...dep, id: "ai5ob03", ts: T(0.02), callerIp: botEgress, status: 200, durationMs: 1_880, requestLength: 3_120, responseLength: 1_310, severity: "informational",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the help chat's egress, HTTP 200, 3,120 bytes in, 1,310 out." }),
    webAccess(chat, { id: "ai5ob04", ts: T(3), srcIp: visitor, method: "POST", path: "/api/chat/messages", query: "chat=6d0f2a91&seq=3", bytes: 1_660, sent: 2_940, ua: UA_FIREFOX, geo: where, severity: "low", mitre: "T1190", tactic: IA,
      description: "Help chat answered a message" }),
    azureOpenAiRequest({ ...dep, id: "ai5ob05", ts: T(3.02), callerIp: botEgress, status: 200, durationMs: 2_410, requestLength: 6_220, responseLength: 1_590, severity: "low", mitre: "T1190", tactic: IA,
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the help chat's egress, HTTP 200, 6,220 bytes in, 1,590 out." }),
    defenderAiAlert({
      ...dep, id: "ai5ob06", ts: T(3.5), alert: "maliciousUrlResponse", clientIp: botEgress, endUser, geo, asOrg: "hosting provider",
      alertDescription: `A response from deployment gpt-4o-helpdesk contained a URL flagged as suspicious: ${collector}.`, severity: "high", mitre: "T1059.007", tactic: EXEC,
      description: `Defender for Cloud raised Corrupted AI application\\model\\data directed a phishing attempt at a user on ${HELPDESK_AI.account}: the reply referenced ${collector}, end-user IP ${visitor}.`,
    }),
    webAccess(chat, { id: "ai5ob07", ts: T(4), srcIp: visitor, method: "POST", path: "/api/chat/handoff", query: "chat=6d0f2a91", status: 201, bytes: 410, sent: 520, ua: UA_FIREFOX, geo: where, severity: "low", mitre: "T1190", tactic: IA,
      description: "Help chat handed a conversation to a human agent (case 77812)" }),
    asAgent(webAccess(consoleSite, { id: "ai5ob08", ts: T(9), srcIp: agent.ip, path: "/console/cases/77812", bytes: 24_880, ua: UA_EDGE, severity: "informational",
      description: "Support console answered a case view (case 77812)" })),
    netRow(agent, {
      id: "ai5ob09", ts: T(9.02), remoteIp: collectorIp, remotePort: 443, application: "tls", domain: collector, processName: "msedge.exe", processPath: EDGE,
      bytesIn: 1_120, bytesOut: 2_310, severity: "medium", mitre: "T1185", tactic: COLLECT,
      description: `EDR: msedge.exe on ${agent.host} connected to ${collector} (${collectorIp}) two seconds after the support console showed case 77812.`,
    }),
    asAgent(webAccess(consoleSite, { id: "ai5ob10", ts: T(16), srcIp: reuse, path: "/console/api/session", bytes: 1_320, ua: UA_FIREFOX, geo: where, severity: "high", mitre: "T1550.004", tactic: LATERAL,
      description: "Support console answered a session check from an address outside the company" })),
    asAgent(webAccess(consoleSite, { id: "ai5ob11", ts: T(17), srcIp: reuse, path: "/console/api/customers/search", query: "q=a&limit=200", bytes: 188_400, ua: UA_FIREFOX, geo: where, severity: "high", mitre: "T1213", tactic: COLLECT,
      description: "Support console answered a customer search (188,400 bytes) from an address outside the company" })),
    asAgent(webAccess(consoleSite, { id: "ai5ob12", ts: T(19), srcIp: reuse, method: "POST", path: "/console/api/cases/export", query: "from=2026-08-01", bytes: 6_204_118, ua: UA_FIREFOX, geo: where, severity: "high", mitre: "T1213", tactic: COLLECT,
      description: "Support console answered a case export (6.2 MB) from an address outside the company" })),
    sentinel({
      id: "ai5ob13", ts: T(20), srcIp: reuse, user: agent.user, severity: "high", eventType: "http_request", mitre: "T1550.004", tactic: CRED,
      alertName: "Support console used from outside the company network",
      detail: "Requests to /console/api from an address outside the office and VPN ranges, under an agent's account.",
      startTime: T(16), endTime: T(19),
      extendedProperties: { "Client IP": reuse, Account: agent.user, Requests: 3, "Largest response": 6204118 },
      description: `Microsoft Sentinel raised Support console used from outside the company network: three requests from ${reuse} under ${agent.user.split("@")[0]}.`,
    }),
  ], "inc:ai5ob");
}

export const AI_R5_AGENT_STORIES: AiStoryDef[] = [
  { id: "ai-agent-public-pr-from-private-reads", title: "Coding Assistant Reads Private Repositories, Then Opens a Pull Request on the Public SDK",
    complexity: "core", companies: ["nexacorp", "rocketstack", "quantumbank"], seat: "developer", officeEgress: OFFICE_EGRESS, family: "ai-toxic-agent-flow", mode: "solo", events: agentPublicPr() },
  { id: "ai-agent-org-token-repo-exposure", title: "Release Agent Token Opens Public Pull Requests and Makes a Private Repository Public",
    complexity: "advanced", companies: ["nexacorp", "medcore"], ownServers: true, family: "ai-toxic-agent-flow", mode: "team", events: orgTokenExposure() },
  { id: "ai-portal-assistant-unfiltered-query", title: "Portal Assistant's SQL Login Reads Customers Without a Customer Filter",
    complexity: "core", companies: ["nexacorp", "medcore"], ownServers: true, family: "ai-output-handling", mode: "solo", events: portalUnfilteredQuery() },
  { id: "ai-helpdesk-reply-renders-in-console", title: "Help-Desk Bot Reply Flagged, Then the Support Console Is Used from Outside",
    complexity: "advanced", companies: ["nexacorp", "medcore"], ownServers: true, family: "ai-output-handling", mode: "team", events: helpdeskReplyConsole() },
];
