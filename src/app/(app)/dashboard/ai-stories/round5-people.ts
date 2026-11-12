/**
 * AI round, people families (round5.ts): attacks that reach the company through a person and a conversation
 * or a hiring process, each with one single-player variant and one Team Training variant that share no
 * people, hosts, addresses, tickets or plot.
 *
 *  1. ai-crescendo-jailbreak (MITRE ATLAS AML.T0054, multi-turn escalation; Russinovich et al., "Great, Now
 *     Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack", Microsoft, 2024):
 *       - solo  ai-crescendo-hr-assistant   an employee works an internal HR policy assistant over one long
 *               conversation: request sizes grow turn by turn (the history is resent), the later turns are
 *               filtered and alerted by Prompt Shields, and the last turn returns a reply five times the usual.
 *       - team  ai-crescendo-support-codes  a visitor works the public support assistant until it hands out
 *               a staff goodwill code, and the code is redeemed from other addresses within the hour.
 *  2. ai-fake-it-worker (FBI PSA I-052225 and DOJ actions 2024-2025 on DPRK remote IT workers: hires under stolen
 *     or synthetic identities, laptop farms, remote-control tools, commercial VPNs, code and data taken early):
 *       - solo  ai-fake-it-worker-contractor  a new remote contractor's first day: a remote-control tool on the
 *               laptop, a sign-in from a hosting address far from the stated city, an SSH key added from
 *               abroad, and a dozen repositories cloned in minutes.
 *       - team  ai-fake-it-worker-laptop-farm two new hires in different teams whose laptops sign in from one
 *               residential address, run the same commercial VPN, accept remote-control sessions from one
 *               peer, and stage company data for a personal cloud store.
 *
 * Effects only: the logs carry sizes, verdicts, processes, records and addresses, never prompt text.
 * Field sources: Defender for Cloud "Alerts for AI services" (AI.Azure_Jailbreak.ContentFiltering.*),
 * Azure OpenAI RequestResponse (HTTP 400 for a filtered prompt; no prompt or completion in the record),
 * FrontDoorAccessLog and AppServiceHTTPLogs columns, GitHub audit streaming (git.clone, public_key.create),
 * Okta System Log, Defender for Endpoint Advanced Hunting, Entra sign-in logs, Office 365 audit.
 */
import type { Severity, TelemetryEvent } from "@/lib/sim/types";
import type { AiStoryDef } from "./wave2";
import { azureOpenAiRequest, defenderAiAlert, type AzureAiResource, type GeoLite } from "@/lib/sim/emitters/azureAi";
import { githubAudit } from "@/lib/sim/emitters/github";
import { oktaSignIn } from "@/lib/sim/emitters/okta";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { mdeFile, mdeNetwork, mdeProcess } from "@/lib/sim/emitters/mde";
import { authoredFor, appServiceHttp, benign, CX, frontDoor, netRow, proc, sentinel, SUB, ticket, withIncident } from "./wave4-shared";

const UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
const at = (base: string) => { const b = Date.parse(base); return (min: number) => new Date(b + min * 60_000).toISOString(); };
const n = (x: number) => x.toLocaleString("en-US");

// ══════════════════════════════════════════════════════════════════════════════
// 1a. Crescendo against an internal HR policy assistant (solo)
// ══════════════════════════════════════════════════════════════════════════════
function buildCrescendoHr(): TelemetryEvent[] {
  const T = at("2026-11-03T13:00:00Z");
  const aoai: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-hr-ai", account: "aoai-hr-policy-neu", region: "northeurope" };
  const dep = { resource: aoai, deployment: "gpt-4o-hr-policy" };
  const egress = "203.0.113.205";          // the HR app's App Service outbound address
  const emp = { user: "d.halevi@nexacorp.com", ip: "10.10.40.57" };
  const red = { user: "rt.assessor@nexacorp.com", ip: "10.10.60.12" };
  const empCtx = { id: emp.user, ip: emp.ip, app: "hr-policy-assistant" };
  const turn = (id: string, min: number, req: number, resp: number, status: 200 | 400, extra: Partial<Parameters<typeof azureOpenAiRequest>[0]> = {}) => azureOpenAiRequest({
    ...dep, id, ts: T(min), callerIp: egress, status, durationMs: status === 400 ? 210 : 1800 + Math.round(resp / 6), requestLength: req, responseLength: resp,
    severity: status === 400 ? "low" : "informational",
    description: status === 400
      ? `Azure OpenAI RequestResponse log: ChatCompletions_Create on ${dep.deployment} from the HR app's egress, HTTP 400 (prompt filtered), ${n(req)} bytes in, a ${n(resp)}-byte content filter error out.`
      : `Azure OpenAI RequestResponse log: ChatCompletions_Create on ${dep.deployment} from the HR app's egress, HTTP 200, ${n(req)} bytes in, ${n(resp)} out.`,
    ...extra,
  });
  return withIncident([
    ticket({ id: "r5cj01", ts: T(-90), table: "change_request", number: "CHG0061420", state: "Implement", caller: red.user, severity: "informational",
      shortDescription: "Quarterly safety test of the HR policy assistant by the AI assurance team, account rt.assessor, 12:00-15:00 UTC",
      description: "ServiceNow change CHG0061420 (Implement): scheduled jailbreak resistance test of the HR policy assistant by the AI assurance team." }),
    benign(defenderAiAlert({
      ...dep, id: "r5cj02", ts: T(-40), alert: "jailbreakBlocked", clientIp: egress, user: red.user, endUser: { id: red.user, ip: red.ip, app: "hr-policy-assistant" },
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-hr-policy was blocked by Azure AI Content Safety Prompt Shields.",
      description: `Defender for Cloud raised the blocked Jailbreak alert on ${aoai.account}, end user ${red.user} from ${red.ip}.`,
    }), "The approved safety test under CHG0061420: the AI assurance account, inside its window, from the assurance lab subnet, and the prompt was blocked. One alert, one test prompt, no reply of unusual size."),

    turn("r5cj04", 0.1, 1_380, 1_544, 200),
    turn("r5cj05", 3, 3_020, 1_902, 200),
    turn("r5cj06", 6, 4_960, 2_118, 200),
    turn("r5cj07", 9, 7_210, 2_340, 200),
    turn("r5cj08", 12, 9_640, 2_506, 200, { severity: "low", mitre: "T1190", tactic: "Initial Access" }),
    turn("r5cj09", 15, 12_180, 318, 400, { mitre: "T1190", tactic: "Initial Access" }),
    defenderAiAlert({
      ...dep, id: "r5cj10", ts: T(15.2), alert: "jailbreakBlocked", clientIp: egress, user: emp.user, endUser: empCtx, startTs: T(15),
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-hr-policy was blocked by Azure AI Content Safety Prompt Shields.", mitre: "T1190", tactic: "Initial Access",
      description: `Defender for Cloud raised the blocked Jailbreak alert on ${aoai.account}, end user ${emp.user} from ${emp.ip}, in the conversation's sixth turn.`,
    }),
    turn("r5cj11", 17, 12_940, 318, 400, { mitre: "T1190", tactic: "Initial Access" }),
    defenderAiAlert({
      ...dep, id: "r5cj12", ts: T(17.2), alert: "jailbreakBlocked", clientIp: egress, user: emp.user, endUser: empCtx, startTs: T(17),
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-hr-policy was blocked by Azure AI Content Safety Prompt Shields.", mitre: "T1190", tactic: "Initial Access",
      description: `Defender for Cloud raised the blocked Jailbreak alert on ${aoai.account} again for ${emp.user}, two minutes after the first.`,
    }),
    turn("r5cj13", 21, 13_410, 2_210, 200, { severity: "low" }),
    turn("r5cj14", 24, 15_880, 12_904, 200, { severity: "high", mitre: "T1213", tactic: "Collection",
      description: `Azure OpenAI RequestResponse log: ChatCompletions_Create on ${dep.deployment} from the HR app's egress, HTTP 200, 15,880 bytes in, 12,904 out. Every earlier reply in this conversation was under 2,600.` }),
    defenderAiAlert({
      ...dep, id: "r5cj15", ts: T(24.3), alert: "jailbreakDetected", clientIp: egress, user: emp.user, endUser: empCtx, startTs: T(24),
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-hr-policy was detected by Azure AI Content Safety Prompt Shields, but was not blocked due to content filtering settings or due to low confidence.",
      severity: "medium", mitre: "T1213", tactic: "Collection",
      description: `Defender for Cloud raised the detected (not blocked) Jailbreak alert on ${aoai.account} for ${emp.user}: this turn was answered.`,
    }),
    sentinel({
      id: "r5cj17", ts: T(31), user: emp.user, srcIp: emp.ip, entity: aoai.account, severity: "high", eventType: "cloud_api_call", mitre: "T1190", tactic: "Initial Access",
      alertName: "Prompt Shields blocks followed by an answered turn in one AI conversation",
      detail: "Two or more blocked Jailbreak alerts for one end user, followed within 30 minutes by a detected (not blocked) Jailbreak alert and a response over four times the deployment's median.",
      startTime: T(15), endTime: T(24.3),
      extendedProperties: { "End user": emp.user, "Blocked alerts": 2, "Detected alerts": 1, "Largest response": 12904, Deployment: dep.deployment },
      description: `Microsoft Sentinel correlated two blocked and one detected Jailbreak alert for ${emp.user} on ${aoai.account}, ending in a 12,904-byte response.`,
    }),
  ], "inc:r5cj");
}

// ══════════════════════════════════════════════════════════════════════════════
// 1b. Crescendo against the public support assistant, a staff code redeemed (team)
// ══════════════════════════════════════════════════════════════════════════════
function buildCrescendoSupport(): TelemetryEvent[] {
  const T = at("2026-11-06T18:20:00Z");
  const aoai: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-cx-ai", account: "aoai-cx-assist-weu", region: "westeurope" };
  const dep = { resource: aoai, deployment: "gpt-4o-cx-assist" };
  const host = "help.nexacorp.com";
  const egress = "203.0.113.214";          // the support app's outbound address
  const site = "app-cx-assist-weu";
  const visitor = "198.51.100.186";
  const geo: GeoLite = { country: "Portugal", iso: "PT", city: "Lisbon", lat: 38.7223, lon: -9.1393 };
  const visitorCtx = { id: "cx-session 7d2e91b4-3c08-4a6f-8e51-0b9f2c4d6a17", ip: visitor, app: "cx-assistant" };
  const curious = "192.0.2.77";
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15";
  const fd = (id: string, min: number, reqB: number, respB: number, sev: Severity, extra: Partial<Parameters<typeof frontDoor>[0]> = {}) => frontDoor({
    id, ts: T(min), hostName: host, clientIp: visitor, method: "POST", uri: "/api/assist/messages", status: 200, requestBytes: reqB, responseBytes: respB, timeTakenS: 1.9, userAgent: ua, severity: sev,
    description: `Azure Front Door: POST /api/assist/messages on ${host} from ${visitor}, HTTP 200, ${n(respB)} bytes out.`, ...extra,
  });
  const turn = (id: string, min: number, req: number, resp: number, status: 200 | 400, extra: Partial<Parameters<typeof azureOpenAiRequest>[0]> = {}) => azureOpenAiRequest({
    ...dep, id, ts: T(min), callerIp: egress, status, durationMs: status === 400 ? 190 : 1500 + Math.round(resp / 5), requestLength: req, responseLength: resp,
    severity: status === 400 ? "low" : "informational",
    description: `Azure OpenAI RequestResponse log: ChatCompletions_Create on ${dep.deployment} from the support app's egress, HTTP ${status}${status === 400 ? " (prompt filtered)" : ""}, ${n(req)} bytes in, ${n(resp)} out.`,
    ...extra,
  });
  const redeem = (id: string, min: number, client: string, account: string) => appServiceHttp({
    id, ts: T(min), site: "app-store-checkout-weu", clientIp: client, method: "POST", stem: "/api/orders/apply-credit", query: `account=${account}&code=GW-STAFF-150`, status: 200, csBytes: 388, scBytes: 512,
    timeTakenMs: 140, userAgent: UA_CHROME, severity: "high", mitre: "T1657", tactic: "Impact",
    description: `App Service HTTP log: POST /api/orders/apply-credit for customer account ${account} with goodwill code GW-STAFF-150 from ${client}, HTTP 200.`,
  });
  return withIncident([
    benign(defenderAiAlert({
      ...dep, id: "r5cs01", ts: T(-55), alert: "jailbreakBlocked", clientIp: egress, endUser: { id: "cx-session 0a4c77e2-91d3-4b8e-b2f6-5e13a9c0d842", ip: curious, app: "cx-assistant" },
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-cx-assist was blocked by Azure AI Content Safety Prompt Shields.",
      description: `Defender for Cloud raised the blocked Jailbreak alert on ${aoai.account}, end-user IP ${curious}, one turn in a short session.`,
    }), "One curious customer's single blocked prompt: the session asked about a delivery before and after, no other alert, no reply of unusual size, and no code redeemed from that session or address."),
    fd("r5cs02", 0, 640, 1_420, "informational"),
    turn("r5cs03", 0.1, 1_120, 1_388, 200),
    fd("r5cs04", 4, 702, 1_690, "informational"),
    turn("r5cs05", 4.1, 2_840, 1_655, 200),
    turn("r5cs06", 8, 4_610, 1_902, 200),
    turn("r5cs07", 12, 6_480, 2_044, 200, { severity: "low", mitre: "T1190", tactic: "Initial Access" }),
    turn("r5cs08", 15, 8_330, 322, 400, { mitre: "T1190", tactic: "Initial Access" }),
    defenderAiAlert({
      ...dep, id: "r5cs09", ts: T(15.2), alert: "jailbreakBlocked", clientIp: egress, endUser: visitorCtx, geo, asOrg: "residential ISP",
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-cx-assist was blocked by Azure AI Content Safety Prompt Shields.", mitre: "T1190", tactic: "Initial Access",
      description: `Defender for Cloud raised the blocked Jailbreak alert on ${aoai.account}, end-user IP ${visitor}, support session 7d2e91b4.`,
    }),
    turn("r5cs10", 18, 8_910, 2_102, 200, { severity: "low" }),
    turn("r5cs11", 22, 11_260, 3_880, 200, { severity: "medium", mitre: "T1213", tactic: "Collection" }),
    appServiceHttp({
      id: "r5cs12", ts: T(22.2), site, clientIp: egress, method: "GET", stem: "/internal/goodwill/codes", query: "tier=staff&limit=5", status: 200, csBytes: 296, scBytes: 1_180, timeTakenMs: 96,
      userAgent: "cx-assist-tools/2.3", severity: "high", mitre: "T1213", tactic: "Collection",
      description: "App Service HTTP log: GET /internal/goodwill/codes with tier=staff by the assistant's tool client, HTTP 200. The tool is meant for agent-escalated cases only.",
    }),
    defenderAiAlert({
      ...dep, id: "r5cs13", ts: T(22.3), alert: "jailbreakDetected", clientIp: egress, endUser: visitorCtx, geo, asOrg: "residential ISP",
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-cx-assist was detected by Azure AI Content Safety Prompt Shields, but was not blocked due to content filtering settings or due to low confidence.",
      mitre: "T1213", tactic: "Collection",
      description: `Defender for Cloud raised the detected (not blocked) Jailbreak alert on ${aoai.account}, same session 7d2e91b4: the turn was answered.`,
    }),
    fd("r5cs14", 22.4, 1_388, 4_104, "medium", { mitre: "T1213", tactic: "Collection" }),
    appServiceHttp({
      id: "r5cs15", ts: T(30), site: "app-store-checkout-weu", clientIp: "198.51.100.152", method: "POST", stem: "/api/orders/apply-credit", query: "account=C-104455&code=AUTUMN10", status: 200, csBytes: 384, scBytes: 498,
      timeTakenMs: 131, userAgent: UA_CHROME, severity: "informational", description: "App Service HTTP log: POST /api/orders/apply-credit for customer account C-104455 with the public promotion code AUTUMN10, HTTP 200.",
    }),
    redeem("r5cs16", 38, "198.51.100.191", "C-118402"),
    redeem("r5cs17", 41, "203.0.113.233", "C-120977"),
    redeem("r5cs18", 47, "192.0.2.183", "C-097314"),
    sentinel({
      id: "r5cs19", ts: T(52), srcIp: visitor, entity: aoai.account, severity: "high", eventType: "cloud_api_call", mitre: "T1657", tactic: "Impact",
      alertName: "Staff-tier goodwill code redeemed after an AI jailbreak alert",
      detail: "A staff-tier goodwill code is applied by customer accounts within two hours of a Jailbreak alert on the support assistant whose session read the goodwill code tool.",
      startTime: T(15.2), endTime: T(47),
      extendedProperties: { "End user IP": visitor, Session: visitorCtx.id, "Code tier": "staff", Redemptions: 3, Deployment: dep.deployment },
      description: `Microsoft Sentinel linked the jailbreak alerts for session 7d2e91b4 (${visitor}) to three redemptions of staff code GW-STAFF-150 from three other addresses.`,
    }),
  ], "inc:r5cs");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2a. A remote contractor's first day (solo)
// ══════════════════════════════════════════════════════════════════════════════
function buildFakeWorkerContractor(): TelemetryEvent[] {
  const T = at("2026-11-09T14:00:00Z");
  const hire = { user: "j.mercer@nexacorp.com", host: "WS-ENG-2117", ip: "10.10.20.117" };
  const newbie = { user: "n.rao@nexacorp.com" };
  const office = "192.0.2.150";
  const farm = "203.0.113.164";            // the laptop's address: a hosting provider, not a home ISP
  const abroad = "203.0.113.189";
  const ORG = "nexacorp-eng";
  const repos = ["payments-api", "ledger-core", "kyc-service", "mobile-banking-ios", "mobile-banking-android", "fraud-rules", "partner-gateway", "infra-terraform",
    "auth-service", "card-issuing", "statements-batch", "risk-models"];
  const clone = (id: string, min: number, repo: string) => githubAudit({
    companyId: CX, id, ts: T(min), action: "git.clone", actor: "j.mercer", actorIp: farm, user: hire.user, org: ORG, repo: `${ORG}/${repo}`, visibility: "private",
    geoCountryCode: "US", category: "web", userAgent: "git/2.47.1.windows.2", severity: "medium", mitre: "T1213.003", tactic: "Collection",
    extra: { "github.programmatic_access_type": "Personal access token (classic)", "github.transport_protocol_name": "http" },
    description: `GitHub audit log: git.clone of ${ORG}/${repo} by the contractor's GitHub account over HTTPS with a classic personal access token, from ${farm}.`,
  });
  const anydesk = "C:\\Users\\j.mercer\\Downloads\\AnyDesk.exe";
  return withIncident([
    {
      id: "r5fw01", ts: T(-1440), source: "hr", vendor: "Workday", event_type: "account_modify", severity: "informational", user_email: "talent.ops@nexacorp.com",
      description: "Workday recorded the hire of j.mercer as a remote contract software engineer, start date 2026-11-09, work location Austin, Texas, United States.",
      raw: { "workday.event_type": "Hire", "workday.worker_id": "WD-0091733", "workday.worker_email": hire.user, "workday.initiated_by": "talent.ops@nexacorp.com",
        "event.action": "Hire", "event.outcome": "success", "event.provider": "Workday", "event.module": "workday" },
    },
    ticket({ id: "r5fw02", ts: T(-60), table: "sc_req_item", number: "RITM0074410", state: "Closed Complete", caller: newbie.user, severity: "informational",
      shortDescription: "Onboarding n.rao, Payments squad: laptop, GitHub team payments-squad (3 repositories)",
      description: "ServiceNow request RITM0074410 (Closed Complete): onboarding of n.rao to the Payments squad, with access to its three repositories." }),
    ...["payments-api", "ledger-core", "payments-docs"].map((r, i) => benign(githubAudit({
      companyId: CX, id: `r5fw0${3 + i}`, ts: T(-40 + i), action: "git.clone", actor: "n.rao", actorIp: office, user: newbie.user, org: ORG, repo: `${ORG}/${r}`, visibility: "private",
      geoCountryCode: "GB", category: "web", userAgent: "git/2.47.1.windows.2", severity: "informational",
      extra: { "github.programmatic_access_type": "OAuth access token", "github.transport_protocol_name": "http" },
      description: `GitHub audit log: git.clone of ${ORG}/${r} by the GitHub account of ${newbie.user} from the office address ${office}.`,
    }), "A new engineer's first clone under RITM0074410: the three repositories of the squad the ticket names, from the office address, through the Git credential manager's OAuth token.")),
    oktaSignIn({
      companyId: CX, id: "r5fw06", ts: T(0), user: hire.user, srcIp: farm, mfaUsed: true, userAgent: UA_CHROME, os: "Windows 10", browser: "CHROME",
      asn: 9009, asOrg: "M247 Europe SRL", geo: { country: "United States", city: "Ashburn" }, severity: "medium", mitre: "T1078", tactic: "Initial Access",
      description: `Okta sign-in for ${hire.user} from ${farm} (AS9009, M247 Europe SRL, Ashburn, United States) with Okta Verify: a hosting provider, far from the contractor's stated city of Austin.`,
    }),
    proc(hire, { id: "r5fw07", ts: T(9), pid: 6084, processName: "AnyDesk.exe", processPath: "C:\\Users\\j.mercer\\Downloads\\AnyDesk.exe", cmdline: `"C:\\Users\\j.mercer\\Downloads\\AnyDesk.exe" --install "C:\\Program Files (x86)\\AnyDesk" --start-with-win --silent`,
      parentName: "explorer.exe", signed: true, signatureSubject: "AnyDesk Software GmbH", integrity: "high", severity: "medium", isDetection: true, mitre: "T1219", tactic: "Command and Control",
      description: `CrowdStrike: AnyDesk installed as a service on ${hire.host} by j.mercer on the account's first day, set to start with Windows. No ticket requests a remote-control tool.` }),
    netRow(hire, { id: "r5fw08", ts: T(11), remoteIp: "203.0.113.177", remotePort: 443, domain: "relay-4f1c.net.anydesk.com", processName: "AnyDesk.exe", processPath: anydesk, pid: 6084, parentName: "explorer.exe",
      direction: "outbound", application: "tls", severity: "low", mitre: "T1219", tactic: "Command and Control",
      description: `CrowdStrike: AnyDesk, run from the Downloads folder on ${hire.host}, connected to the AnyDesk relay relay-4f1c.net.anydesk.com (203.0.113.177).` }),
    githubAudit({
      companyId: CX, id: "r5fw09", ts: T(26), action: "public_key.create", actor: "j.mercer", actorIp: abroad, user: hire.user, geoCountryCode: "CN", category: "configuration",
      userAgent: UA_CHROME, severity: "medium", mitre: "T1098.004", tactic: "Persistence",
      extra: { fingerprint: "SHA256:c4Qn1zV8mWb3tY6pLr0eXs2aHk9fJuGdNiOq7nBxPo", title: "dev-box" },
      description: `GitHub audit log: public_key.create by the contractor's GitHub account from ${abroad} (country CN): an SSH key titled dev-box added to the account, 26 minutes after the Okta sign-in from the United States.`,
    }),
    ...repos.map((r, i) => clone(`r5fw${String(10 + i).padStart(2, "0")}`, 31 + i * 0.7, r)),
    sentinel({
      id: "r5fw22", ts: T(41), user: hire.user, srcIp: farm, entity: hire.user, severity: "high", eventType: "cloud_api_call", mitre: "T1213.003", tactic: "Collection",
      alertName: "New account clones many repositories on its first day",
      detail: "An account created in the last 7 days clones ten or more distinct repositories within 15 minutes.",
      startTime: T(31), endTime: T(38.7),
      extendedProperties: { Account: hire.user, Repositories: repos.length, "Source IP": farm, "Account age (days)": 0 },
      description: `Microsoft Sentinel: the GitHub account of ${hire.user}, hired today, cloned ${repos.length} repositories in 8 minutes from ${farm}, none of them assigned to a team yet.`,
    }),
  ], "inc:r5fw");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2b. Two new hires on one laptop farm (team)
// ══════════════════════════════════════════════════════════════════════════════
function buildFakeWorkerFarm(): TelemetryEvent[] {
  const T = at("2026-11-11T15:00:00Z");
  const a = { user: "t.whitfield@nexacorp.com", host: "WS-DATA-3305", ip: "10.10.30.105" };
  const b = { user: "e.okoro@nexacorp.com", host: "WS-IT-3318", ip: "10.10.30.118" };
  const home = "198.51.100.209";           // one residential address for both laptops
  const peer = "203.0.113.196";            // the remote-control peer of both laptops
  const store = "drop.personalvault.example";
  const ORG = "nexacorp-data";
  const vpn = "C:\\Program Files (x86)\\Astrill\\astrill.exe";
  const signIn = (id: string, min: number, user: string, device: string, attack = true) => entraSignIn({
    companyId: CX, id, ts: T(min), user, srcIp: home, app: "Microsoft Office", mfa: true, managed: true, compliant: true, deviceName: device, os: "Windows 11", browser: "Edge 141.0.0",
    geo: { country: "US", city: "Jacksonville", countryCode: "US" }, severity: attack ? "low" : "informational", ...(attack ? { mitre: "T1078", tactic: "Initial Access" } : {}),
    description: `Entra ID sign-in for ${user} from ${home} (Jacksonville, United States) on the managed device ${device}.`,
  });
  return withIncident([
    benign(entraSignIn({
      companyId: CX, id: "r5ff01", ts: T(-120), user: "m.sato@nexacorp.com", srcIp: "198.51.100.212", app: "Microsoft Office", mfa: true, managed: true, compliant: true, deviceName: "WS-FIN-3207",
      os: "Windows 11", browser: "Edge 141.0.0", geo: { country: "US", city: "Jacksonville", countryCode: "US" }, severity: "informational",
      description: "Entra ID sign-in for m.sato@nexacorp.com from 198.51.100.212 (Jacksonville, United States) on the managed device WS-FIN-3207.",
    }), "An existing employee working from home in Jacksonville: one person, one device, the same home address for months."),
    ticket({ id: "r5ff02", ts: T(-4320), table: "sc_req_item", number: "RITM0075102", state: "Closed Complete", caller: a.user, severity: "informational",
      shortDescription: "Onboarding t.whitfield, Data Engineering (remote, Jacksonville FL): laptop WS-DATA-3305 shipped",
      description: "ServiceNow request RITM0075102 (Closed Complete): remote onboarding of t.whitfield, Data Engineering, laptop shipped to Jacksonville, Florida." }),
    ticket({ id: "r5ff03", ts: T(-2880), table: "sc_req_item", number: "RITM0075230", state: "Closed Complete", caller: b.user, severity: "informational",
      shortDescription: "Onboarding e.okoro, IT Service Desk (remote, Atlanta GA): laptop WS-IT-3318 shipped",
      description: "ServiceNow request RITM0075230 (Closed Complete): remote onboarding of e.okoro, IT Service Desk, laptop shipped to Atlanta, Georgia." }),
    signIn("r5ff04", 0, a.user, a.host),
    signIn("r5ff05", 6, b.user, b.host),
    mdeProcess({ companyId: CX, id: "r5ff06", ts: T(2), host: a.host, srcIp: a.ip, user: a.user, processName: "astrill.exe", processPath: vpn, cmdline: `"${vpn}"`, parentName: "explorer.exe",
      signed: true, severity: "low", mitre: "T1090", tactic: "Command and Control",
      description: `Defender for Endpoint: the commercial VPN client astrill.exe started on ${a.host} as ${a.user}.` }),
    mdeProcess({ companyId: CX, id: "r5ff07", ts: T(7), host: b.host, srcIp: b.ip, user: b.user, processName: "astrill.exe", processPath: vpn, cmdline: `"${vpn}"`, parentName: "explorer.exe",
      signed: true, severity: "low", mitre: "T1090", tactic: "Command and Control",
      description: `Defender for Endpoint: the same commercial VPN client astrill.exe started on ${b.host} as ${b.user}.` }),
    mdeNetwork({ companyId: CX, id: "r5ff08", ts: T(9), host: a.host, srcIp: a.ip, user: a.user, remoteIp: peer, remotePort: 7070, direction: "inbound", application: "tls",
      initiatingProcess: "AnyDesk.exe", severity: "medium", isDetection: true, mitre: "T1219", tactic: "Command and Control",
      description: `Defender for Endpoint: AnyDesk on ${a.host} accepted a direct incoming session from ${peer}.` }),
    mdeNetwork({ companyId: CX, id: "r5ff09", ts: T(14), host: b.host, srcIp: b.ip, user: b.user, remoteIp: peer, remotePort: 7070, direction: "inbound", application: "tls",
      initiatingProcess: "AnyDesk.exe", severity: "medium", isDetection: true, mitre: "T1219", tactic: "Command and Control",
      description: `Defender for Endpoint: AnyDesk on ${b.host} accepted a direct incoming session from the same peer ${peer}, five minutes later.` }),
    githubAudit({
      companyId: CX, id: "r5ff10", ts: T(18), action: "public_key.create", actor: "t.whitfield", actorIp: home, user: a.user, geoCountryCode: "US", category: "configuration", userAgent: UA_EDGE,
      severity: "low", mitre: "T1098.004", tactic: "Persistence", extra: { fingerprint: "SHA256:Vb7nQ2xL9mWc4tY1pKr8eZs5aHj0fUgDiNoq3BxRmT", title: "ws" },
      description: `GitHub audit log: public_key.create by the GitHub account of ${a.user} from ${home}: an SSH key titled ws added to the account.`,
    }),
    ...["warehouse-etl", "customer-360", "pricing-models", "dbt-core-models", "ml-feature-store", "reporting-api"].map((r, i) => githubAudit({
      companyId: CX, id: `r5ff1${1 + i}`, ts: T(21 + i * 0.6), action: "git.clone", actor: "t.whitfield", actorIp: home, user: a.user, org: ORG, repo: `${ORG}/${r}`, visibility: "private",
      geoCountryCode: "US", category: "web", userAgent: "git/2.47.1", severity: "low", mitre: "T1213.003", tactic: "Collection",
      extra: { "github.programmatic_access_type": "Personal access token (classic)", "github.transport_protocol_name": "ssh" },
      description: `GitHub audit log: git.clone of ${ORG}/${r} by the GitHub account of ${a.user} over SSH from ${home}.`,
    })),
    m365Operation({ companyId: CX, id: "r5ff17", ts: T(25), user: b.user, srcIp: home, operation: "FileSyncDownloadedFull", workload: "SharePoint",
      objectId: "https://nexacorp.sharepoint.com/sites/ITServiceDesk/Shared Documents/Runbooks", siteUrl: "https://nexacorp.sharepoint.com/sites/ITServiceDesk/",
      userAgent: "Microsoft SkyDriveSync 25.180.0914.0001 ship; Windows NT 10.0 (26100)", severity: "medium", mitre: "T1213.002", tactic: "Collection",
      description: `Office 365 audit: ${b.user} synced the whole Runbooks library of the IT Service Desk site to ${b.host}, from ${home}.` }),
    mdeProcess({ companyId: CX, id: "r5ff18", ts: T(33), host: b.host, srcIp: b.ip, user: b.user, processName: "7z.exe", processPath: "C:\\Program Files\\7-Zip\\7z.exe",
      cmdline: `"C:\\Program Files\\7-Zip\\7z.exe" a -p -mhe=on C:\\Users\\e.okoro\\AppData\\Local\\Temp\\tmp81c.7z "C:\\Users\\e.okoro\\NexaCorp\\IT Service Desk - Runbooks"`,
      parentName: "AnyDesk.exe", signed: true, severity: "medium", mitre: "T1560.001", tactic: "Collection",
      description: `Defender for Endpoint: 7z.exe, started under the AnyDesk session on ${b.host}, created an encrypted archive of the synced Service Desk runbooks.` }),
    mdeFile({ companyId: CX, id: "r5ff19", ts: T(35), host: b.host, srcIp: b.ip, user: b.user, path: "C:\\Users\\e.okoro\\AppData\\Local\\Temp\\tmp81c.7z", size: 186_330_112,
      action: "file_create", initiatingProcess: "7z.exe", severity: "medium", mitre: "T1074.001", tactic: "Collection",
      description: `Defender for Endpoint: a 186 MB archive tmp81c.7z written to the Temp folder of e.okoro on ${b.host}.` }),
    mdeNetwork({ companyId: CX, id: "r5ff20", ts: T(39), host: b.host, srcIp: b.ip, user: b.user, remoteIp: "198.51.100.231", remotePort: 443, domain: store, url: `https://${store}/api/v2/upload`,
      application: "tls", initiatingProcess: "msedge.exe", severity: "high", mitre: "T1567.002", tactic: "Exfiltration",
      description: `Defender for Endpoint: msedge.exe on ${b.host} connected to the personal cloud storage service ${store} (198.51.100.231) right after the archive was written.` }),
    sentinel({
      id: "r5ff21", ts: T(44), srcIp: home, entity: home, severity: "high", eventType: "cloud_api_call", mitre: "T1078", tactic: "Initial Access",
      alertName: "Accounts onboarded in the last 30 days share one sign-in address",
      detail: "Two or more accounts created in the last 30 days, in different departments and with different stated locations, sign in from one public address within an hour.",
      startTime: T(0), endTime: T(6),
      extendedProperties: { "Source IP": home, Accounts: `${a.user}, ${b.user}`, Departments: "Data Engineering, IT Service Desk", "Stated locations": "Jacksonville FL, Atlanta GA" },
      description: `Microsoft Sentinel: ${a.user} (stated Jacksonville) and ${b.user} (stated Atlanta), both onboarded this month, signed in from the same address ${home} six minutes apart.`,
    }),
  ], "inc:r5ff");
}

export const AI_R5_PEOPLE_STORIES: AiStoryDef[] = [
  { id: "ai-crescendo-hr-assistant", title: "HR Policy Assistant Conversation Grows Turn by Turn, Then Prompt Shields Alerts and a Very Large Reply",
    complexity: "core", companies: ["medcore"], family: "ai-crescendo-jailbreak", mode: "solo", events: authoredFor("medcore", buildCrescendoHr()) },
  { id: "ai-crescendo-support-codes", title: "Support Assistant Session Raises Jailbreak Alerts, Then a Staff Goodwill Code Is Redeemed by Other Accounts",
    complexity: "advanced", companies: ["nexacorp"], family: "ai-crescendo-jailbreak", mode: "team", ownServers: true, events: buildCrescendoSupport() },
  { id: "ai-fake-it-worker-contractor", title: "New Contractor's First Day: Remote-Control Tool, Sign-In from a Hosting Address, Repositories Cloned in Minutes",
    complexity: "core", companies: ["rocketstack"], family: "ai-fake-it-worker", mode: "solo", events: authoredFor("rocketstack", buildFakeWorkerContractor()) },
  { id: "ai-fake-it-worker-laptop-farm", title: "Two New Hires in Different Teams Sign In from One Address and Accept Remote Sessions from One Peer",
    complexity: "advanced", companies: ["nexacorp"], family: "ai-fake-it-worker", mode: "team", events: buildFakeWorkerFarm() },
];
