/**
 * AI attack stories, wave 4 part B: attacks on the AI services a company runs, read from the
 * cloud's own logs. Each comes in an Azure build (Azure OpenAI, Front Door, Defender for Cloud
 * AI alerts, Activity Log) for the Azure estates and an AWS build (Bedrock in CloudTrail,
 * GuardDuty AI Protection) for the AWS estates, so all five companies can draw the topic.
 *
 *  1. ai-portal-assistant-injection-{azure,aws}  (core) direct prompt injection against a
 *     customer-facing assistant whose guardrail only reports: its tool reads other customers'
 *     records and the response carries them out. OWASP LLM01, LLM02, LLM06, LLM07. ATLAS
 *     AML.T0051.000, AML.T0054, AML.T0056, AML.T0053, AML.T0057.
 *  2. ai-agent-prod-delete-{azure,aws}  (core) a coding agent running with a broad identity
 *     deletes a production database during a change freeze. Replit / SaaStr (Jul 2025, AI
 *     Incident Database 1152). OWASP LLM06, ASI02, ASI03. ATLAS AML.T0101.
 *  3. ai-model-extraction-{azure,aws}  (core) a partner key drives a sustained, uniform query
 *     stream against a proprietary tuned model from rotating addresses. Anthropic's distillation
 *     report (Feb 2026) for the pattern. OWASP LLM10. ATLAS AML.T0024.002, AML.T0040.
 *  4. ai-rag-source-poisoning-azure  (advanced) a compromised contractor account edits a page a
 *     company assistant indexes; the assistant then hands staff an outside link. OWASP LLM04,
 *     LLM08. ATLAS AML.T0070, AML.T0071, AML.T0066.
 *  5. ai-training-data-poisoning-aws  (advanced) an insider overwrites labels in a training set
 *     before a scheduled fine-tuning job. OWASP LLM04. ATLAS AML.T0020.
 *
 * Field sources: GuardDuty AI Protection finding types and resource.bedrockGuardrailDetails /
 * modelDetails; the Bedrock CloudTrail guide (InvokeModel and Converse are management events,
 * ApplyGuardrail and RetrieveAndGenerate data events); Defender for Cloud "Alerts for AI
 * services" (Jul 2026); AppServiceHTTPLogs columns; CreateModelCustomizationJob request syntax;
 * RDS CloudTrail request casing. No prompt text appears: logs carry sizes, classifications and
 * filter verdicts, as the real products do.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { azureOpenAiRequest, defenderAiAlert, type AzureAiResource } from "@/lib/sim/emitters/azureAi";
import type { AiStoryDef } from "./wave2";
import { authoredFor, CX, DEV, OFFICE_EGRESS, SUB, apimGateway, appServiceHttp, azureOp, bedrockInvocation, benign, dnsRow, frontDoor, inbound, proc, sentinel, ticket, web, withIncident } from "./wave4-shared";

const dev = { host: DEV.host, ip: DEV.ip, user: DEV.user };
const home = `C:\\Users\\${DEV.bare}`;
const UA_BOTO = "Boto3/1.35.20 md/Botocore#1.35.20 ua/2.0 os/linux#6.8.0 md/arch#x86_64 lang/python#3.12.4 cfg/retry-mode#legacy Botocore/1.35.20";
const UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const PORTAL_AOAI: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-ai-prod", account: "aoai-portal-weu", region: "westeurope" };
const PORTAL_EGRESS = "203.0.113.60";
const KB_EGRESS = "203.0.113.61";
const API_EGRESS = "203.0.113.66";
const CLAUDE = "us.anthropic.claude-sonnet-4-20250514-v1:0";

// ══════════════════════════════════════════════════════════════════════════════
// 1a. Customer portal assistant, Azure
// ══════════════════════════════════════════════════════════════════════════════
function buildPortalInjectionAzure(): TelemetryEvent[] {
  const portal = "portal.nexacorp.com";
  const site = "app-portal-weu";
  const visitor = "198.51.100.173";
  const curious = "192.0.2.61";
  const ua = "python-requests/2.32.3";
  const geo = { country: "Netherlands", iso: "NL", city: "Amsterdam", lat: 52.3676, lon: 4.9041 };
  const dep = { resource: PORTAL_AOAI, deployment: "gpt-4o-portal" };
  const endUser = { id: "portal-session 2f7a9c10-6d41-4b1e-9f25-81c6e04d7a33", ip: visitor, app: "portal-assistant" };
  return withIncident([
    benign(frontDoor({
      id: "ai4pa01", ts: "2026-10-26T09:02:14.000Z", hostName: portal, clientIp: curious, method: "POST", uri: "/api/assistant/messages", status: 200,
      requestBytes: 842, responseBytes: 1960, timeTakenS: 2.104, userAgent: UA_CHROME, severity: "informational",
      description: `Azure Front Door: POST /api/assistant/messages from ${curious} with a browser agent, HTTP 200, 842 bytes in, 1,960 out.`,
    }), "A signed-in portal user asking the assistant about their own record: browser agent, sizes in the usual range."),
    benign(defenderAiAlert({
      ...dep, id: "ai4pa02", ts: "2026-10-26T09:03:02.000Z", alert: "llmRecon", clientIp: PORTAL_EGRESS, endUser: { id: "portal-session 8b13e2d4-77a0-4f5c-a3c1-2d9e61f0b842", ip: curious, app: "portal-assistant" },
      alertDescription: "Prompts on deployment gpt-4o-portal resemble reconnaissance of system instructions or model capabilities.",
      description: `Defender for Cloud raised LLM Reconnaissance Attempt Detected on ${PORTAL_AOAI.account} for one portal session from ${curious}.`,
    }), "Same alert, innocent cause: one portal user asked what the assistant can do. Single request, a browser, no tool calls and no second alert from the session."),

    frontDoor({
      id: "ai4pa03", ts: "2026-10-26T11:14:02.000Z", hostName: portal, clientIp: visitor, method: "POST", uri: "/api/assistant/messages", status: 200,
      requestBytes: 1204, responseBytes: 2210, timeTakenS: 2.412, userAgent: ua, severity: "low", mitre: "T1190", tactic: "Initial Access",
      description: `Azure Front Door: POST /api/assistant/messages from ${visitor} with the python-requests agent, HTTP 200.`,
    }),
    defenderAiAlert({
      ...dep, id: "ai4pa04", ts: "2026-10-26T11:15:40.000Z", alert: "llmRecon", clientIp: PORTAL_EGRESS, endUser, geo, asOrg: "hosting provider",
      alertDescription: "Prompts on deployment gpt-4o-portal resemble reconnaissance of system instructions or model capabilities.", severity: "low", mitre: "T1190", tactic: "Initial Access",
      description: `Defender for Cloud raised LLM Reconnaissance Attempt Detected on ${PORTAL_AOAI.account}, end-user IP ${visitor}.`,
    }),
    defenderAiAlert({
      ...dep, id: "ai4pa05", ts: "2026-10-26T11:19:22.000Z", alert: "jailbreakDetected", clientIp: PORTAL_EGRESS, endUser, geo, asOrg: "hosting provider",
      alertDescription: "A Jailbreak attempt on deployment gpt-4o-portal was detected by Azure AI Content Safety Prompt Shields, but was not blocked due to content filtering settings or due to low confidence.",
      severity: "medium", mitre: "T1190", tactic: "Initial Access",
      description: `Defender for Cloud raised the detected (not blocked) Jailbreak alert on ${PORTAL_AOAI.account}, same portal session, end-user IP ${visitor}.`,
    }),
    azureOpenAiRequest({
      ...dep, id: "ai4pa06", ts: "2026-10-26T11:19:41.000Z", callerIp: PORTAL_EGRESS, status: 200, durationMs: 6120, requestLength: 11_840, responseLength: 18_204, severity: "medium", mitre: "T1213", tactic: "Collection",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal app's egress, HTTP 200, 11,840 bytes in, 18,204 out. The deployment's usual response is under 3,000.",
    }),
    defenderAiAlert({
      ...dep, id: "ai4pa07", ts: "2026-10-26T11:20:02.000Z", alert: "anomalousTool", clientIp: PORTAL_EGRESS, endUser, geo, asOrg: "hosting provider",
      alertDescription: "The application connected to deployment gpt-4o-portal invoked the tool record_lookup in a manner that deviates from its expected behavior.", extra: { "Tool name": "record_lookup" },
      severity: "low", mitre: "T1213", tactic: "Collection",
      description: `Defender for Cloud raised Anomalous tool invocation on ${PORTAL_AOAI.account}: tool record_lookup, same portal session.`,
    }),
    appServiceHttp({
      id: "ai4pa08", ts: "2026-10-26T11:20:03.000Z", site, clientIp: PORTAL_EGRESS, method: "GET", stem: "/internal/records", query: "accountId=*&limit=500", status: 200, csBytes: 412, scBytes: 884_120, timeTakenMs: 1840,
      userAgent: "assistant-tools/1.8", severity: "high", mitre: "T1213", tactic: "Collection",
      description: "App Service HTTP log: GET /internal/records with accountId=* and limit=500 by assistant-tools, HTTP 200, about 884 KB out.",
    }),
    azureOpenAiRequest({
      ...dep, id: "ai4pa08b", ts: "2026-10-26T11:20:08.000Z", callerIp: PORTAL_EGRESS, status: 200, durationMs: 4310, requestLength: 896_204, responseLength: 409_120, severity: "high", mitre: "T1213", tactic: "Collection",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create from the portal app's egress, HTTP 200, about 896 KB in, 409 KB out.",
    }),
    frontDoor({
      id: "ai4pa09", ts: "2026-10-26T11:20:09.000Z", hostName: portal, clientIp: visitor, method: "POST", uri: "/api/assistant/messages", status: 200,
      requestBytes: 1880, responseBytes: 412_880, timeTakenS: 7.914, userAgent: ua, severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description: `Azure Front Door: POST /api/assistant/messages from ${visitor}, HTTP 200, about 412 KB out.`,
    }),
    sentinel({
      id: "ai4pa11", ts: "2026-10-26T11:31:18.000Z", srcIp: visitor, entity: PORTAL_AOAI.account, severity: "high", eventType: "cloud_api_call", mitre: "T1190", tactic: "Initial Access",
      alertName: "Multiple AI alerts on one portal session",
      detail: "Three or more Defender for Cloud AI alerts share one end-user session within an hour.",
      startTime: "2026-10-26T11:15:40.000Z", endTime: "2026-10-26T11:20:02.000Z",
      extendedProperties: { "End user IP": visitor, Session: endUser.id, Alerts: 3, "Largest response": 412880, Deployment: "gpt-4o-portal" },
      description: `Microsoft Sentinel grouped three AI alerts on one portal session from ${visitor}, with a largest response of about 412 KB.`,
    }),
  ], "inc:ai4pa:azure");
}

// ══════════════════════════════════════════════════════════════════════════════
// 1b. Customer portal assistant, AWS
// ══════════════════════════════════════════════════════════════════════════════
function buildPortalInjectionAws(): TelemetryEvent[] {
  const app = { host: "SRV-NXC-APP07", ip: "10.10.20.70" };
  const visitor = "198.51.100.174";
  const role = "portal-assistant-app";
  const arn = `arn:aws:sts::418772153604:assumed-role/${role}/portal-app-01`;
  const sessionKey = "ASIAZ5PT8KW2QEXAMPLE";
  const guardrail = "arn:aws:bedrock:us-east-1:418772153604:guardrail/k7w2p9x4m1qz";
  const common = { companyId: CX, srcIp: app.ip, actorType: "AssumedRole" as const, actorName: role, arn, accessKeyId: sessionKey, sessionIssuerName: role, userAgent: UA_BOTO };
  const guardDetails = (action: string) => JSON.stringify({
    guardrails: [{ arn: guardrail, version: "3" }], guardrailAction: "GUARDRAIL_INTERVENED", guardrailSource: "INPUT",
    contentPolicyFilters: [{ type: "PROMPT_ATTACK", confidence: "HIGH", action }],
  });
  const applyGuardrail = (o: { id: string; ts: string; source: "INPUT" | "OUTPUT"; assessments: unknown[]; severity: TelemetryEvent["severity"]; description: string; mitre?: string; tactic?: string }) => cloudTrailEvent({
    ...common, id: o.id, ts: o.ts, eventName: "ApplyGuardrail", eventSource: "bedrock.amazonaws.com", readOnly: true, managementEvent: false, severity: o.severity, mitre: o.mitre, tactic: o.tactic, description: o.description,
    extra: {
      "aws.cloudtrail.requestParameters.guardrailIdentifier": "k7w2p9x4m1qz", "aws.cloudtrail.requestParameters.guardrailVersion": "3", "aws.cloudtrail.requestParameters.source": o.source,
      "aws.cloudtrail.responseElements": JSON.stringify({ action: "GUARDRAIL_INTERVENED", assessments: o.assessments }),
    },
  });
  return withIncident([
    benign(inbound({
      id: "ai4pb01", ts: "2026-10-26T09:02:14.000Z", fromIp: "192.0.2.65", server: app.host, serverIp: app.ip, port: 443, bytesIn: 1840, bytesOut: 2960, elapsedSec: 3, severity: "informational",
      description: `Firewall session end: a customer address reached the portal on ${app.host}, about 3 KB out.`,
    }), "An ordinary customer session on the portal, a few kilobytes each way."),
    benign(guardDutyFinding({
      id: "ai4pb02", ts: "2026-10-26T09:40:10.000Z", companyId: CX, findingType: "Impact:IAMUser/PromptInjection.Direct", gdSeverity: 2,
      title: "An Amazon Bedrock Guardrail detected a direct prompt injection attempt in an invocation made by an IAM identity.",
      api: "ApplyGuardrail", serviceName: "bedrock.amazonaws.com", srcIp: app.ip, resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: sessionKey, count: 12,
      extra: { "aws.guardduty.resource.bedrockGuardrailDetails": guardDetails("BLOCKED") }, severity: "low",
      description: `GuardDuty raised Impact:IAMUser/PromptInjection.Direct for role ${role}: guardrail intervened on INPUT, filter action BLOCKED, count 12.`,
    }), "Same finding, innocent cause: the scheduled QA regression pack, stopped by the guardrail: filter action BLOCKED, and no data call by the role follows."),

    inbound({
      id: "ai4pb03", ts: "2026-10-26T11:14:02.000Z", fromIp: visitor, server: app.host, serverIp: app.ip, port: 443, bytesIn: 4120, bytesOut: 6240, elapsedSec: 41, repeatCount: 36, severity: "low", mitre: "T1190", tactic: "Initial Access",
      description: `Firewall session end: ${visitor} reached the portal on ${app.host} in 36 repeated sessions, about 6 KB out.`,
    }),
    applyGuardrail({
      id: "ai4pb04", ts: "2026-10-26T11:19:22.000Z", source: "INPUT", severity: "medium", mitre: "T1190", tactic: "Initial Access",
      assessments: [{ contentPolicy: { filters: [{ type: "PROMPT_ATTACK", confidence: "HIGH", action: "NONE", detected: true }] } }],
      description: `AWS CloudTrail data event: ApplyGuardrail on INPUT by role ${role}. The guardrail intervened with filter PROMPT_ATTACK, confidence HIGH, action NONE (report only).`,
    }),
    cloudTrailEvent({
      ...common, id: "ai4pb06", ts: "2026-10-26T11:19:41.000Z", eventName: "Converse", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": CLAUDE }, severity: "low", mitre: "T1190", tactic: "Initial Access",
      description: `AWS CloudTrail: Converse on ${CLAUDE} by role ${role}.`,
    }),
    cloudTrailEvent({
      ...common, id: "ai4pb07", ts: "2026-10-26T11:20:03.000Z", eventName: "Scan", eventSource: "dynamodb.amazonaws.com", readOnly: true, managementEvent: false, extra: { "aws.cloudtrail.requestParameters.tableName": "customer-orders", "aws.cloudtrail.requestParameters.limit": 500 }, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `AWS CloudTrail data event: Scan on table customer-orders by role ${role}, limit 500. The role's earlier calls on this table are GetItem by order key.`,
    }),
    cloudTrailEvent({
      ...common, id: "ai4pb07b", ts: "2026-10-26T11:20:06.000Z", eventName: "Converse", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": CLAUDE }, severity: "medium", mitre: "T1530", tactic: "Collection",
      description: `AWS CloudTrail: Converse on ${CLAUDE} by role ${role}, three seconds after the Scan.`,
    }),
    applyGuardrail({
      id: "ai4pb08", ts: "2026-10-26T11:20:08.000Z", source: "OUTPUT", severity: "high", mitre: "T1530", tactic: "Collection",
      assessments: [{ sensitiveInformationPolicy: { piiEntities: [{ type: "EMAIL", action: "NONE", detected: true }, { type: "ADDRESS", action: "NONE", detected: true }] } }],
      description: `AWS CloudTrail data event: ApplyGuardrail on OUTPUT by role ${role}: sensitive information filter detected EMAIL and ADDRESS, action NONE.`,
    }),
    inbound({
      id: "ai4pb09", ts: "2026-10-26T11:20:12.000Z", fromIp: visitor, server: app.host, serverIp: app.ip, port: 443, bytesIn: 2204, bytesOut: 418_204, elapsedSec: 9, severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description: `Firewall session end: ${visitor} to the portal on ${app.host}, about 418 KB out in one session.`,
    }),
    guardDutyFinding({
      id: "ai4pb05", ts: "2026-10-26T11:21:04.000Z", companyId: CX, findingType: "Impact:IAMUser/PromptInjection.Direct", gdSeverity: 2,
      title: "An Amazon Bedrock Guardrail detected a direct prompt injection attempt in an invocation made by an IAM identity.",
      api: "ApplyGuardrail", serviceName: "bedrock.amazonaws.com", srcIp: app.ip, resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: sessionKey, count: 9,
      extra: { "aws.guardduty.resource.bedrockGuardrailDetails": guardDetails("NONE") }, severity: "low", mitre: "T1190", tactic: "Initial Access",
      description: `GuardDuty raised Impact:IAMUser/PromptInjection.Direct for role ${role}: guardrail intervened on INPUT, filter action NONE.`,
    }),
    ticket({
      id: "ai4pb10", ts: "2026-10-26T13:05:40.000Z", number: "INC0091266", state: "New", caller: "s.patel@nexacorp.com", severity: "high", shortDescription: "Customer reports seeing another customer's order in the assistant",
      extra: { "servicenow.category": "Security", "servicenow.subcategory": "Data exposure", "servicenow.priority": "2 - High", "servicenow.assignment_group": "SOC Tier 2", "servicenow.cmdb_ci": app.host,
        "servicenow.work_notes": "Support forwarded a screenshot from a customer. Portal assistant guardrail is in report-only mode for this stage. Reading the role's DynamoDB and Bedrock activity." },
      description: "ServiceNow incident INC0091266: support forwarded a customer's report of another customer's order in the assistant. The work note says the guardrail is in report-only mode.",
    }),
  ], "inc:ai4pa:aws");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2a. Over-privileged agent, AWS
// ══════════════════════════════════════════════════════════════════════════════
function buildAgentDeleteAws(): TelemetryEvent[] {
  const role = "ai-dev-agent-role";
  const arn = `arn:aws:sts::418772153604:assumed-role/${role}/${DEV.bare}`;
  const ua = (cmd: string) => `aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/windows#10 md/arch#amd64 lang/python#3.12.4 md/pyimpl#CPython cmd/rds.${cmd}`;
  const common = { companyId: CX, srcIp: OFFICE_EGRESS, actorType: "AssumedRole" as const, actorName: role, arn, accessKeyId: "ASIAZ7DV2AGT4EXAMPLE", sessionIssuerName: role, userAgent: ua("delete-db-instance"), geo: { country: "United Kingdom", city: "London" } };
  const aws = (id: string, ts: string, cmd: string, description: string, severity: TelemetryEvent["severity"], mitre?: string, tactic?: string) => proc(dev, {
    id, ts, pid: 4 * (1800 + Number(id.slice(-2))), processName: "aws.exe", processPath: "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe", parentName: "node.exe", parentPid: 7000, cmdline: cmd, severity, mitre, tactic, description,
  });
  return withIncident([
    benign(ticket({
      id: "ai4da01", ts: "2026-10-27T15:00:00.000Z", table: "change_request", number: "CHG0079344", state: "Closed", caller: DEV.user, severity: "informational", shortDescription: "Remove sandbox database dev-sandbox-17",
      extra: { "servicenow.category": "Infrastructure", "servicenow.approved_by": "Change Advisory Board", "servicenow.cmdb_ci": "dev-sandbox-17", "servicenow.risk": "Low" },
      description: "ServiceNow change CHG0079344: approved removal of the sandbox database dev-sandbox-17.",
    }), "The approved cleanup of a sandbox, which the twin deletion below belongs to."),
    benign(cloudTrailEvent({
      ...common, id: "ai4da02", ts: "2026-10-27T15:12:40.000Z", eventName: "DeleteDBInstance", eventSource: "rds.amazonaws.com",
      extra: { "aws.cloudtrail.requestParameters.dBInstanceIdentifier": "dev-sandbox-17", "aws.cloudtrail.requestParameters.skipFinalSnapshot": false, "aws.cloudtrail.requestParameters.finalDBSnapshotIdentifier": "dev-sandbox-17-final" }, severity: "low",
      description: `AWS CloudTrail: DeleteDBInstance on dev-sandbox-17 by role ${role}, final snapshot dev-sandbox-17-final.`,
    }), "Same API, same role: a sandbox, named in an approved change, with a final snapshot kept."),
    benign(ticket({
      id: "ai4da03", ts: "2026-10-30T07:00:00.000Z", table: "change_request", number: "CHG0079400", state: "Implement", caller: "n.morgan@nexacorp.com", severity: "informational", shortDescription: "Production change freeze for quarter close",
      extra: { "servicenow.category": "Infrastructure", "servicenow.approved_by": "Change Advisory Board", "servicenow.risk": "Moderate", "servicenow.planned_start_date": "2026-10-30 07:00:00", "servicenow.planned_end_date": "2026-11-03 19:00:00" },
      description: "ServiceNow change CHG0079400: production change freeze for quarter close, 30 October to 3 November.",
    }), "The freeze itself: the record the later deletions are read against."),
    aws("ai4da04", "2026-10-30T10:41:02.000Z", "aws.exe rds describe-db-instances --region us-east-1", `The coding agent (node.exe) on ${DEV.host} ran aws rds describe-db-instances.`, "low", "T1526", "Discovery"),
    cloudTrailEvent({
      ...common, userAgent: ua("describe-db-instances"), id: "ai4da05", ts: "2026-10-30T10:41:04.000Z", eventName: "DescribeDBInstances", eventSource: "rds.amazonaws.com", readOnly: true, severity: "low", mitre: "T1526", tactic: "Discovery",
      description: `AWS CloudTrail: DescribeDBInstances by role ${role}, unfiltered, so it covers the production instances too.`,
    }),
    aws("ai4da06", "2026-10-30T10:42:18.000Z", "aws.exe rds delete-db-instance --db-instance-identifier prod-orders-db --skip-final-snapshot --delete-automated-backups --region us-east-1", `The coding agent ran aws rds delete-db-instance on prod-orders-db with --skip-final-snapshot and --delete-automated-backups.`, "high", "T1485", "Impact"),
    cloudTrailEvent({
      ...common, id: "ai4da07", ts: "2026-10-30T10:42:19.000Z", eventName: "DeleteDBInstance", eventSource: "rds.amazonaws.com",
      extra: { "aws.cloudtrail.requestParameters.dBInstanceIdentifier": "prod-orders-db", "aws.cloudtrail.requestParameters.skipFinalSnapshot": true, "aws.cloudtrail.requestParameters.deleteAutomatedBackups": true }, severity: "critical", mitre: "T1485", tactic: "Impact",
      description: `AWS CloudTrail: DeleteDBInstance on prod-orders-db by role ${role}, skipFinalSnapshot true, deleteAutomatedBackups true.`,
    }),
    guardDutyFinding({
      id: "ai4da08", ts: "2026-10-30T10:48:30.000Z", companyId: CX, findingType: "Impact:IAMUser/AnomalousBehavior", gdSeverity: 8, title: "An API commonly used to tamper with data or processes in an AWS environment was invoked in an anomalous way.",
      api: "DeleteDBInstance", serviceName: "rds.amazonaws.com", callerType: "Remote IP", srcIp: OFFICE_EGRESS, remoteCountry: "United Kingdom", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: "ASIAZ7DV2AGT4EXAMPLE", count: 1, severity: "high", mitre: "T1485", tactic: "Impact",
      description: `GuardDuty raised Impact:IAMUser/AnomalousBehavior for role ${role}: DeleteDBInstance on a resource outside this identity's learned behaviour.`,
    }),
    ticket({
      id: "ai4da09", ts: "2026-10-30T10:53:12.000Z", number: "INC0091344", state: "New", caller: "n.morgan@nexacorp.com", severity: "critical", shortDescription: "Orders API returning HTTP 503: database prod-orders-db not found",
      extra: { "servicenow.category": "Application", "servicenow.subcategory": "Database", "servicenow.priority": "1 - Critical", "servicenow.impact": "1 - High", "servicenow.urgency": "1 - High", "servicenow.assignment_group": "Platform On-Call", "servicenow.cmdb_ci": "prod-orders-db",
        "servicenow.work_notes": "Instance gone from the console, no final snapshot, automated backups gone. Change freeze CHG0079400 is active. Role ai-dev-agent-role has AdministratorAccess attached." },
      description: "ServiceNow incident INC0091344: the orders API is down because prod-orders-db is gone, with no snapshot. The note says a change freeze is active and the role has AdministratorAccess.",
    }),
  ], "inc:ai4da:aws");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2b. Over-privileged agent, Azure
// ══════════════════════════════════════════════════════════════════════════════
function buildAgentDeleteAzure(): TelemetryEvent[] {
  const AZ = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd";
  const db = (id: string, ts: string, name: string, severity: TelemetryEvent["severity"], description: string, mitre?: string, tactic?: string) => azureOp({
    id, ts, operation: "MICROSOFT.SQL/SERVERS/DATABASES/DELETE", caller: DEV.user, callerIp: OFFICE_EGRESS, provider: "Microsoft.Sql", group: "rg-data-prod", type: "servers/sql-core-weu/databases", name, role: "Owner", severity, mitre, tactic, description,
  });
  return withIncident([
    benign(ticket({
      id: "ai4dz01", ts: "2026-10-27T15:00:00.000Z", table: "change_request", number: "CHG0079344", state: "Closed", caller: DEV.user, severity: "informational", shortDescription: "Remove sandbox database dev-sandbox-17",
      extra: { "servicenow.category": "Infrastructure", "servicenow.approved_by": "Change Advisory Board", "servicenow.cmdb_ci": "dev-sandbox-17", "servicenow.risk": "Low" },
      description: "ServiceNow change CHG0079344: approved removal of the sandbox database dev-sandbox-17.",
    }), "The approved cleanup of a sandbox, which the twin deletion below belongs to."),
    benign(db("ai4dz02", "2026-10-27T15:12:40.000Z", "dev-sandbox-17", "low", `Azure Activity Log: ${DEV.bare} deleted database dev-sandbox-17 on sql-core-weu, Owner role.`),
      "Same operation, same user: a sandbox named in an approved change."),
    benign(ticket({
      id: "ai4dz03", ts: "2026-10-30T07:00:00.000Z", table: "change_request", number: "CHG0079400", state: "Implement", caller: "n.morgan@nexacorp.com", severity: "informational", shortDescription: "Production change freeze for quarter close",
      extra: { "servicenow.category": "Infrastructure", "servicenow.approved_by": "Change Advisory Board", "servicenow.risk": "Moderate", "servicenow.planned_start_date": "2026-10-30 07:00:00", "servicenow.planned_end_date": "2026-11-03 19:00:00" },
      description: "ServiceNow change CHG0079400: production change freeze for quarter close, 30 October to 3 November.",
    }), "The freeze itself: the record the later deletions are read against."),
    proc(dev, {
      id: "ai4dz04", ts: "2026-10-30T10:41:02.000Z", pid: 7220, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", parentName: "node.exe", parentPid: 7000,
      cmdline: `cmd.exe /c "${AZ}" sql db list --server sql-core-weu --resource-group rg-data-prod`, severity: "low", mitre: "T1526", tactic: "Discovery",
      description: `The coding agent (node.exe) on ${DEV.host} listed the databases on sql-core-weu with the Azure CLI.`,
    }),
    proc(dev, {
      id: "ai4dz05", ts: "2026-10-30T10:42:18.000Z", pid: 7304, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", parentName: "node.exe", parentPid: 7000,
      cmdline: `cmd.exe /c "${AZ}" sql db delete --name prod-orders --server sql-core-weu --resource-group rg-data-prod --yes`, severity: "high", mitre: "T1485", tactic: "Impact",
      description: `The coding agent ran az sql db delete on prod-orders with --yes.`,
    }),
    db("ai4dz06", "2026-10-30T10:42:21.000Z", "prod-orders", "critical", `Azure Activity Log: ${DEV.bare} deleted database prod-orders on sql-core-weu, from ${OFFICE_EGRESS}, Owner role.`, "T1485", "Impact"),
    proc(dev, {
      id: "ai4dz06b", ts: "2026-10-30T10:43:37.000Z", pid: 7388, processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", parentName: "node.exe", parentPid: 7000,
      cmdline: `cmd.exe /c "${AZ}" storage account delete --name stcoreexportsweu --resource-group rg-data-prod --yes`, severity: "high", mitre: "T1490", tactic: "Impact",
      description: `The coding agent ran az storage account delete on stcoreexportsweu with --yes.`,
    }),
    azureOp({
      id: "ai4dz07", ts: "2026-10-30T10:43:40.000Z", operation: "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE", caller: DEV.user, callerIp: OFFICE_EGRESS, provider: "Microsoft.Storage", group: "rg-data-prod", type: "storageAccounts", name: "stcoreexportsweu", role: "Owner",
      severity: "critical", mitre: "T1490", tactic: "Impact",
      description: `Azure Activity Log: ${DEV.bare} deleted storage account stcoreexportsweu, which holds the database exports.`,
    }),
    sentinel({
      id: "ai4dz08", ts: "2026-10-30T10:48:30.000Z", host: DEV.host, srcIp: OFFICE_EGRESS, user: DEV.user, severity: "high", eventType: "cloud_api_call", mitre: "T1485", tactic: "Impact",
      alertName: "Production data resources deleted during an active change freeze",
      detail: "Delete operations on resources tagged production, with no matching change, while a freeze is active.",
      startTime: "2026-10-30T10:42:21.000Z", endTime: "2026-10-30T10:43:40.000Z",
      extendedProperties: { Caller: DEV.user, Resources: ["prod-orders", "stcoreexportsweu"], "Change freeze": "CHG0079400", "Caller role": "Owner" },
      description: `Microsoft Sentinel flagged the deletion of prod-orders and stcoreexportsweu by ${DEV.bare} during change freeze CHG0079400.`,
    }),
    ticket({
      id: "ai4dz09", ts: "2026-10-30T10:53:12.000Z", number: "INC0091344", state: "New", caller: "n.morgan@nexacorp.com", severity: "critical", shortDescription: "Orders API returning HTTP 503: database prod-orders not found",
      extra: { "servicenow.category": "Application", "servicenow.subcategory": "Database", "servicenow.priority": "1 - Critical", "servicenow.impact": "1 - High", "servicenow.urgency": "1 - High", "servicenow.assignment_group": "Platform On-Call", "servicenow.cmdb_ci": "prod-orders",
        "servicenow.work_notes": "Database gone, export storage account gone. Change freeze CHG0079400 is active. The developer's account holds Owner on the subscription and the coding agent runs under it." },
      description: "ServiceNow incident INC0091344: the orders API is down because prod-orders is gone. The note says a change freeze is active and the agent runs under an account that holds Owner.",
    }),
  ], "inc:ai4da:azure");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3a. Model extraction, Azure
// ══════════════════════════════════════════════════════════════════════════════
function buildExtractionAzure(): TelemetryEvent[] {
  const api = "api.nexacorp.com";
  const res: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-ai-prod", account: "aoai-riskscore-weu", region: "westeurope" };
  const dep = { resource: res, deployment: "gpt-4o-riskscore-ft", model: "gpt-4o-2024-08-06.ft-riskscore", modelVersion: "1" };
  const partner = "192.0.2.63";
  const ips = ["198.51.100.176", "198.51.100.177", "198.51.100.178"];
  const ua = "aiohttp/3.10.5 Python/3.12";
  const geo = { country: "Singapore", iso: "SG", city: "Singapore", lat: 1.3521, lon: 103.8198 };
  const q = (id: string, ts: string, ip: string, n: number) => frontDoor({
    id, ts, hostName: api, clientIp: ip, method: "POST", uri: "/v1/risk-score/explain", status: 200, requestBytes: 1412 + n, responseBytes: 2204 + n, timeTakenS: 0.92, userAgent: ua, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
    description: `Azure Front Door: POST /v1/risk-score/explain from ${ip}, HTTP 200.`,
  });
  const gw = (id: string, ts: string, ip: string, n: number) => apimGateway({
    id, ts, subscription: "partner-meridian", api: "risk-score-v1", operation: "explain", callerIp: ip, method: "POST", url: `https://${api}/v1/risk-score/explain`, status: 200, requestSize: 1412 + n, responseSize: 2204 + n, totalTimeMs: 880, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
    description: `API Management gateway log: POST /v1/risk-score/explain from ${ip} on subscription partner-meridian, HTTP 200.`,
  });
  const enduser = (ip: string) => ({ id: "partner-meridian", ip, app: "risk-score-api" });
  return withIncident([
    benign(ticket({
      id: "ai4mx01", ts: "2026-10-20T16:00:00.000Z", table: "change_request", number: "CHG0079290", state: "Closed", caller: "s.patel@nexacorp.com", severity: "informational", shortDescription: "Partner Meridian monthly model evaluation batch, 19,000 requests",
      extra: { "servicenow.category": "Application", "servicenow.approved_by": "Change Advisory Board", "servicenow.risk": "Low", "servicenow.work_notes": `Evaluation batch from ${partner}, one run overnight, ceiling 19,000 requests.` },
      description: `ServiceNow change CHG0079290: partner Meridian's monthly evaluation batch from ${partner}, one overnight run, ceiling 19,000 requests.`,
    }), "The approved evaluation run, which names the source address and the request ceiling."),
    benign(defenderAiAlert({
      ...dep, id: "ai4mx02", ts: "2026-10-21T02:40:10.000Z", startTs: "2026-10-21T01:00:00.000Z", alert: "walletVolume", clientIp: API_EGRESS, endUser: enduser(partner), extra: { Requests: "18412" },
      alertDescription: "Requests and responses on deployment gpt-4o-riskscore-ft are inconsistent with the resource's historical usage.",
      description: `Defender for Cloud raised Suspected wallet attack - volume anomaly on ${res.account}: 18412 requests from ${partner}.`,
    }), "Same alert, innocent cause: partner Meridian's approved evaluation batch from its registered address, inside the ceiling in CHG0079290."),

    defenderAiAlert({
      ...dep, id: "ai4mx03", ts: "2026-10-28T03:12:40.000Z", startTs: "2026-10-28T02:58:00.000Z", alert: "accessAnomaly", clientIp: API_EGRESS, endUser: enduser(ips[0]), geo, asOrg: "hosting provider", severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      alertDescription: "Access to the Azure AI resource aoai-riskscore-weu deviates from its historical pattern: a new end-user IP range behind the application.",
      description: `Defender for Cloud raised Access anomaly in AI resource on ${res.account}: a new end-user IP range, end user ${ips[0]}.`,
    }),
    q("ai4mx04", "2026-10-28T03:13:02.000Z", ips[0], 3),
    gw("ai4mx04b", "2026-10-28T03:13:03.000Z", ips[0], 3),
    q("ai4mx05", "2026-10-28T04:41:10.000Z", ips[1], 7),
    azureOpenAiRequest({
      ...dep, id: "ai4mx06", ts: "2026-10-28T04:41:11.000Z", callerIp: API_EGRESS, status: 200, durationMs: 840, requestLength: 1419, responseLength: 2211, severity: "low", mitre: "T1078.004", tactic: "Initial Access",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create on gpt-4o-riskscore-ft from the API tier's egress, 1,419 bytes in, 2,211 out. Sizes vary by a few bytes across the run.",
    }),
    q("ai4mx07", "2026-10-28T06:20:55.000Z", ips[2], 5),
    azureOpenAiRequest({
      ...dep, id: "ai4mx08", ts: "2026-10-28T07:02:31.000Z", callerIp: API_EGRESS, status: 429, durationMs: 30, requestLength: 1416, responseLength: 310, severity: "low", mitre: "T1499", tactic: "Impact",
      description: "Azure OpenAI RequestResponse log: HTTP 429 on gpt-4o-riskscore-ft, the deployment's rate limit reached.",
    }),
    defenderAiAlert({
      ...dep, id: "ai4mx09", ts: "2026-10-28T07:10:12.000Z", startTs: "2026-10-28T02:58:00.000Z", alert: "walletVolume", clientIp: API_EGRESS, endUser: enduser(ips[2]), geo, asOrg: "hosting provider", extra: { Requests: "412604" }, severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      alertDescription: "Requests and responses on deployment gpt-4o-riskscore-ft are inconsistent with the resource's historical usage.",
      description: `Defender for Cloud raised Suspected wallet attack - volume anomaly on ${res.account}: 412604 requests in about four hours.`,
    }),
    sentinel({
      id: "ai4mx10", ts: "2026-10-28T07:26:40.000Z", srcIp: ips[2], entity: res.account, severity: "high", eventType: "cloud_api_call", mitre: "T1567", tactic: "Exfiltration",
      alertName: "Sustained uniform query stream on a proprietary model from rotating addresses",
      detail: "One API key, three addresses in the same provider range, narrow request-size band, no repeat of a prompt hash across the window.",
      startTime: "2026-10-28T02:58:00.000Z", endTime: "2026-10-28T07:10:12.000Z",
      extendedProperties: { Subscription: "partner-meridian", Addresses: ips, Requests: 412604, "Request size band": "1412-1422 bytes", "Distinct prompt hashes": 412211, "Monthly ceiling on change": 19000 },
      description: `Microsoft Sentinel flagged 412604 requests under subscription partner-meridian from three addresses, with nearly every prompt hash distinct and a request-size band of ten bytes.`,
    }),
  ], "inc:ai4mx:azure");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3b. Model extraction, AWS
// ══════════════════════════════════════════════════════════════════════════════
function buildExtractionAws(): TelemetryEvent[] {
  const user = "svc-partner-meridian";
  const key = "AKIAZ2QF9HXD4EXAMPLE";
  const arn = `arn:aws:iam::418772153604:user/${user}`;
  const model = "arn:aws:bedrock:us-east-1:418772153604:provisioned-model/q4t8m2r6v1ks";
  const partner = "192.0.2.64";
  const ips = ["198.51.100.179", "198.51.100.180"];
  const geo = { country: "Singapore", city: "Singapore" };
  const UA_PARTNER = "meridian-eval/2.4 Boto3/1.35.60 md/Botocore#1.35.60 ua/2.0 os/linux#6.8.0 lang/python#3.12.4";
  const c = (ip: string) => ({ companyId: CX, srcIp: ip, actorType: "IAMUser" as const, actorName: user, accessKeyId: key, arn, userAgent: UA_BOTO, geo });
  const finding = (o: { id: string; ts: string; ip: string; type: string; title: string; count: number; desc: string; mitre?: string; tactic?: string }) => guardDutyFinding({
    id: o.id, ts: o.ts, companyId: CX, findingType: o.type, gdSeverity: 2, title: o.title, api: "InvokeModel", serviceName: "bedrock.amazonaws.com", callerType: "Remote IP", srcIp: o.ip, resourceType: "AccessKey",
    userType: "IAMUser", userName: user, accessKeyId: key, count: o.count, extra: { "aws.guardduty.resource.modelDetails": JSON.stringify([{ modelId: model }]) }, severity: "low", mitre: o.mitre, tactic: o.tactic, description: o.desc,
  });
  const ANOM = { type: "Impact:IAMUser/AnomalousModelInvocation", title: "An IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model in a way that deviates from the established baseline for the identity or account." };
  return withIncident([
    benign(ticket({
      id: "ai4my01", ts: "2026-10-20T16:00:00.000Z", table: "change_request", number: "CHG0079290", state: "Closed", caller: "s.patel@nexacorp.com", severity: "informational", shortDescription: "Partner Meridian monthly model evaluation batch, 19,000 requests",
      extra: { "servicenow.category": "Application", "servicenow.approved_by": "Change Advisory Board", "servicenow.risk": "Low", "servicenow.work_notes": `Evaluation batch from ${partner}, one run overnight, ceiling 19,000 requests. The partner moves to its new client meridian-eval/2.4 for this run.` },
      description: `ServiceNow change CHG0079290: partner Meridian's monthly evaluation batch from ${partner}, one overnight run on client meridian-eval/2.4, ceiling 19,000 requests.`,
    }), "The approved evaluation run, which names the source address, the new client and the request ceiling."),
    benign(cloudTrailEvent({ ...c(partner), userAgent: UA_PARTNER, id: "ai4my01b", ts: "2026-10-21T01:00:12.000Z", eventName: "InvokeModel", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": model }, severity: "informational",
      description: `AWS CloudTrail: InvokeModel on the provisioned model by ${user} from ${partner} with the meridian-eval/2.4 client.` }),
      "The approved batch from the partner's registered address, on the client the change names."),
    benign(bedrockInvocation({ id: "ai4my01c", ts: "2026-10-21T01:00:13.000Z", arn, modelId: model, inputTokens: 1284, outputTokens: 412, severity: "informational",
      description: `Bedrock invocation log: InvokeModel by ${user}, 1,284 input tokens, 412 output tokens.` }),
      "One evaluation case: long, varied scenario text, as the batch sends."),
    benign(finding({ ...ANOM, id: "ai4my02", ts: "2026-10-21T02:40:10.000Z", ip: partner, count: 18412,
      desc: `GuardDuty raised Impact:IAMUser/AnomalousModelInvocation for ${user}: a user agent new for this identity, 18412 invocations of the provisioned model from ${partner}.` }),
      "Same finding, innocent cause: the new client the change record names, from the partner's registered address, inside the ceiling in CHG0079290."),

    cloudTrailEvent({ ...c(ips[0]), id: "ai4my03", ts: "2026-10-28T02:58:10.000Z", eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `AWS CloudTrail: GetCallerIdentity by ${key} (user ${user}) from ${ips[0]}, not the partner's registered address.` }),
    cloudTrailEvent({ ...c(ips[0]), id: "ai4my04", ts: "2026-10-28T02:58:44.000Z", eventName: "ListProvisionedModelThroughputs", eventSource: "bedrock.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `AWS CloudTrail: ListProvisionedModelThroughputs by the same key from ${ips[0]}.` }),
    cloudTrailEvent({ ...c(ips[0]), id: "ai4my05", ts: "2026-10-28T03:01:12.000Z", eventName: "InvokeModel", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": model }, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `AWS CloudTrail: InvokeModel on the provisioned model by the same key from ${ips[0]}.` }),
    finding({ ...ANOM, id: "ai4my06", ts: "2026-10-28T03:22:40.000Z", ip: ips[0], count: 42806, mitre: "T1078.004", tactic: "Initial Access",
      desc: `GuardDuty raised Impact:IAMUser/AnomalousModelInvocation for ${user}: a new IP address and user agent, 42806 invocations of the provisioned model.` }),
    cloudTrailEvent({ ...c(ips[1]), id: "ai4my07", ts: "2026-10-28T05:02:31.000Z", eventName: "InvokeModel", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": model }, severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: `AWS CloudTrail: InvokeModel on the provisioned model by the same key from a second address, ${ips[1]}.` }),
    bedrockInvocation({ id: "ai4my07b", ts: "2026-10-28T05:02:32.000Z", arn, modelId: model, inputTokens: 212, outputTokens: 96, severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: `Bedrock invocation log: InvokeModel by ${user}, 212 input tokens, 96 output tokens.` }),
    bedrockInvocation({ id: "ai4my07c", ts: "2026-10-28T05:02:33.000Z", arn, modelId: model, inputTokens: 214, outputTokens: 96, severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: `Bedrock invocation log: InvokeModel by ${user}, 214 input tokens, 96 output tokens.` }),
    cloudTrailEvent({ ...c(ips[1]), id: "ai4my08", ts: "2026-10-28T06:40:02.000Z", eventName: "InvokeModel", eventSource: "bedrock.amazonaws.com", outcome: "failure", errorCode: "ThrottlingException", extra: { "aws.cloudtrail.requestParameters.modelId": model }, severity: "low", mitre: "T1499", tactic: "Impact",
      description: `AWS CloudTrail: InvokeModel by the same key failed with ThrottlingException.` }),
    finding({ ...ANOM, id: "ai4my09", ts: "2026-10-28T07:10:12.000Z", ip: ips[1], count: 412604, mitre: "T1567", tactic: "Exfiltration",
      desc: `GuardDuty raised Impact:IAMUser/AnomalousModelInvocation for ${user}: a second new IP address, 412604 invocations of the provisioned model.` }),
    ticket({
      id: "ai4my10", ts: "2026-10-28T08:05:40.000Z", number: "INC0091290", state: "New", caller: "s.patel@nexacorp.com", severity: "high", shortDescription: "Bedrock provisioned throughput saturated, partner key",
      extra: { "servicenow.category": "Security", "servicenow.assignment_group": "SOC Tier 2", "servicenow.priority": "2 - High",
        "servicenow.work_notes": "Partner Meridian confirms no run scheduled and does not recognise the addresses. Key svc-partner-meridian disabled." },
      description: "ServiceNow incident INC0091290: the partner confirms no run was scheduled and does not recognise the addresses.",
    }),
  ], "inc:ai4mx:aws");
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. A knowledge source edited through a compromised account (Azure / Microsoft 365)
// ══════════════════════════════════════════════════════════════════════════════
function buildRagPoisoning(): TelemetryEvent[] {
  const contractor = "t.ops@nexacorp.com";
  const signin = "198.51.100.181";
  const site = "https://nexacorp.sharepoint.com/sites/Finance-KB";
  const page = `${site}/Shared Documents/Vendor_Payment_FAQ.docx`;
  const lure = "pay-verify.vendor-portal.example";
  const reader = { host: "WS-FIN-2847", ip: "10.10.20.47", user: "j.chen@nexacorp.com" };
  const res: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-ai-prod", account: "aoai-internal-weu", region: "westeurope" };
  const dep = { resource: res, deployment: "gpt-4o-kb" };
  const edit = (id: string, ts: string, user: string, ip: string, size: number, severity: TelemetryEvent["severity"], description: string, mitre?: string, tactic?: string) => m365Operation({
    companyId: CX, id, ts, user, operation: "FileModified", workload: "SharePoint", srcIp: ip, objectId: page, fileName: "Vendor_Payment_FAQ.docx", siteUrl: `${site}/`, fileExtension: "docx", fileSize: size, severity, mitre, tactic, description,
    extra: { RecordType: "6", UserType: "0" },
  });
  return withIncident([
    benign(edit("ai4rp01", "2026-10-19T10:12:40.000Z", "j.chen@nexacorp.com", OFFICE_EGRESS, 48_120, "informational", "Microsoft 365 audit: j.chen modified Vendor_Payment_FAQ.docx in the Finance-KB site from the office network."),
      "The page's owner in finance updating the FAQ during working hours from the office."),
    benign(azureOpenAiRequest({ ...dep, id: "ai4rp02", ts: "2026-10-19T14:40:02.000Z", callerIp: KB_EGRESS, status: 200, durationMs: 1840, requestLength: 6204, responseLength: 1408, severity: "informational",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create on gpt-4o-kb, HTTP 200, the internal assistant answering from the knowledge base." }),
      "The internal assistant in ordinary use."),

    entraSignIn({
      companyId: CX, id: "ai4rp03", ts: "2026-10-25T21:02:18.000Z", user: contractor, srcIp: signin, app: "Office 365 SharePoint Online", resource: "Office 365 SharePoint Online", mfa: false, managed: false, compliant: false, os: "Linux", browser: "Firefox 128.0",
      userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", riskLevel: "medium", riskDetail: "none", riskEventTypes: ["unfamiliarFeatures"], geo: { country: "Romania", city: "Bucharest", countryCode: "RO" }, severity: "medium", mitre: "T1078", tactic: "Initial Access",
      description: `Entra sign-in for contractor t.ops to SharePoint from ${signin} on an unmanaged Linux device at 21:02, single factor, risk medium, unfamiliar sign-in properties.`,
    }),
    m365Operation({
      companyId: CX, id: "ai4rp04", ts: "2026-10-25T21:06:02.000Z", user: contractor, operation: "FileAccessed", workload: "SharePoint", srcIp: signin, objectId: page, fileName: "Vendor_Payment_FAQ.docx", siteUrl: `${site}/`, fileExtension: "docx", severity: "low", mitre: "T1213.002", tactic: "Collection",
      extra: { RecordType: "6", UserType: "0" }, description: `Microsoft 365 audit: t.ops opened Vendor_Payment_FAQ.docx from ${signin}.`,
    }),
    edit("ai4rp05", "2026-10-25T21:09:41.000Z", contractor, signin, 49_704, "high", `Microsoft 365 audit: t.ops modified Vendor_Payment_FAQ.docx from ${signin} at 21:09, a page in the assistant's knowledge library.`, "T1565.001", "Impact"),
    azureOpenAiRequest({ ...dep, id: "ai4rp06", ts: "2026-10-26T09:18:12.000Z", callerIp: KB_EGRESS, status: 200, durationMs: 1910, requestLength: 6612, responseLength: 1502, severity: "low", mitre: "T1565.001", tactic: "Impact",
      description: "Azure OpenAI RequestResponse log: ChatCompletions_Create on gpt-4o-kb, HTTP 200, a question handled from the knowledge base." }),
    defenderAiAlert({
      ...dep, id: "ai4rp07", ts: "2026-10-26T09:19:40.000Z", alert: "maliciousUrlResponse", clientIp: KB_EGRESS, endUser: { id: "j.chen@nexacorp.com", ip: reader.ip, app: "internal-kb-assistant" }, user: reader.user,
      alertDescription: "The AI application shared a known malicious URL used for phishing with a user. The URL originated within the application, the AI model, or the data the application can access.", extra: { URL: `https://${lure}/remit` },
      severity: "high", mitre: "T1565.001", tactic: "Impact",
      description: `Defender for Cloud raised Corrupted AI application\\model\\data directed a phishing attempt at a user on ${res.account}: https://${lure}/remit in a response to j.chen.`,
    }),
    dnsRow({ id: "ai4rp08", ts: "2026-10-26T09:21:03.000Z", on: { host: reader.host, ip: reader.ip, user: reader.user }, query: lure, answer: "203.0.113.177", severity: "low", mitre: "T1204.001", tactic: "Execution",
      description: `${reader.host} resolved ${lure}.` }),
    web(reader, {
      id: "ai4rp09", ts: "2026-10-26T09:21:04.000Z", url: `https://${lure}/remit`, domain: lure, dstIp: "203.0.113.177", category: "newly-registered-domain", method: "GET", action: "alert", status: 200, bytesIn: 41_208, bytesOut: 1120, userAgent: UA_CHROME,
      referer: "https://kb-assistant.nexacorp.com/", severity: "medium", mitre: "T1204.001", tactic: "Execution",
      description: `Firewall URL log: j.chen's workstation opened https://${lure}/remit, referer kb-assistant.nexacorp.com, category newly-registered-domain, action alert.`,
    }),
    web(reader, {
      id: "ai4rp10", ts: "2026-10-26T09:22:30.000Z", url: `https://${lure}/remit/submit`, domain: lure, dstIp: "203.0.113.177", category: "newly-registered-domain", method: "POST", action: "alert", status: 302, bytesIn: 620, bytesOut: 2840, userAgent: UA_CHROME,
      severity: "high", mitre: "T1056.003", tactic: "Credential Access",
      description: `Firewall URL log: j.chen's workstation POSTed about 2.8 KB to /remit/submit on ${lure}, HTTP 302.`,
    }),
    sentinel({
      id: "ai4rp11", ts: "2026-10-26T09:34:22.000Z", host: reader.host, srcIp: reader.ip, user: reader.user, severity: "high", eventType: "http_request", mitre: "T1565.001", tactic: "Impact",
      alertName: "AI assistant response carried a flagged URL, and the reader opened it",
      detail: "A Defender AI URL alert for a response from an internal assistant, followed by a firewall record of the reader's workstation posting to that URL.",
      startTime: "2026-10-26T09:19:40.000Z", endTime: "2026-10-26T09:22:30.000Z",
      extendedProperties: { URL: `https://${lure}/remit`, "Reader": reader.user },
      description: `Microsoft Sentinel joined the flagged URL in the assistant's answer to j.chen to the visit from her workstation.`,
    }),
  ], "inc:ai4rp");
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Training data changed by an insider before a fine-tuning job (AWS)
// ══════════════════════════════════════════════════════════════════════════════
function buildTrainingPoisoning(): TelemetryEvent[] {
  const insider = { host: DEV.host, ip: DEV.ip, user: DEV.user };
  const bucket = "nexacorp-ml-training";
  const dataset = "risk-triage/2026-10/train.jsonl";
  const humanRole = "ml-engineer";
  const humanArn = `arn:aws:sts::418772153604:assumed-role/${humanRole}/${DEV.bare}`;
  const pipeRole = "ml-dataset-pipeline";
  const pipeArn = `arn:aws:sts::418772153604:assumed-role/${pipeRole}/batch-2210`;
  const human = { companyId: CX, srcIp: OFFICE_EGRESS, actorType: "AssumedRole" as const, actorName: humanRole, arn: humanArn, accessKeyId: "ASIAZ3ML6ENG8EXAMPLE", sessionIssuerName: humanRole, userAgent: "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/windows#10 md/arch#amd64 lang/python#3.12.4", geo: { country: "United Kingdom", city: "London" } };
  const pipe = { companyId: CX, srcIp: "10.10.20.205", actorType: "AssumedRole" as const, actorName: pipeRole, arn: pipeArn, accessKeyId: "ASIAZ9PPL2BTC4EXAMPLE".slice(0, 13) + "EXAMPLE", sessionIssuerName: pipeRole, userAgent: UA_BOTO };
  const AWS = "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe";
  const job = (id: string, ts: string, name: string, severity: TelemetryEvent["severity"], description: string, mitre?: string, tactic?: string) => cloudTrailEvent({
    ...pipe, id, ts, eventName: "CreateModelCustomizationJob", eventSource: "bedrock.amazonaws.com", severity, mitre, tactic, description,
    extra: {
      "aws.cloudtrail.requestParameters.jobName": name, "aws.cloudtrail.requestParameters.customModelName": `risk-triage-${name.slice(-7)}`, "aws.cloudtrail.requestParameters.baseModelIdentifier": "amazon.nova-micro-v1:0:128k", "aws.cloudtrail.requestParameters.customizationType": "FINE_TUNING",
      "aws.cloudtrail.requestParameters.roleArn": "arn:aws:iam::418772153604:role/ml-customization", "aws.cloudtrail.requestParameters.trainingDataConfig.s3Uri": `s3://${bucket}/${dataset.replace("2026-10", name.slice(-7))}`, "aws.cloudtrail.requestParameters.outputDataConfig.s3Uri": `s3://${bucket}/output/`,
    },
  });
  return withIncident([
    benign(cloudTrailEvent({
      ...pipe, id: "ai4tp01", ts: "2026-09-30T22:10:12.000Z", eventName: "PutObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "risk-triage/2026-09/train.jsonl", severity: "informational", extra: { "aws.cloudtrail.additionalEventData.bytesTransferredIn": 88_204_120 },
      description: `AWS CloudTrail data event: PutObject of risk-triage/2026-09/train.jsonl by role ${pipeRole}, about 88 MB.`,
    }), "The monthly dataset load by the pipeline role, from the batch subnet, at its usual hour."),
    benign(job("ai4tp02", "2026-09-30T23:30:04.000Z", "risk-triage-2026-09", "informational", `AWS CloudTrail: CreateModelCustomizationJob risk-triage-2026-09 by role ${pipeRole}, FINE_TUNING on amazon.nova-micro-v1:0:128k.`),
      "The scheduled monthly fine-tuning job on the pipeline's own dataset."),

    benign(cloudTrailEvent({
      ...pipe, id: "ai4tp03", ts: "2026-10-30T22:10:12.000Z", eventName: "PutObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: dataset, severity: "informational", extra: { "aws.cloudtrail.additionalEventData.bytesTransferredIn": 91_402_884 },
      description: `AWS CloudTrail data event: PutObject of ${dataset} by role ${pipeRole}, about 91 MB.`,
    }), "This month's load by the pipeline role, from the batch subnet, at its usual hour."),
    proc(insider, {
      id: "ai4tp04", ts: "2026-10-30T22:31:40.000Z", pid: 5120, processName: "aws.exe", processPath: AWS, parentName: "powershell.exe", cmdline: `aws.exe s3api get-object --bucket ${bucket} --key ${dataset} ${home}\\Documents\\train.jsonl`, severity: "low", mitre: "T1530", tactic: "Collection",
      description: `aws s3api get-object copied ${dataset} to ${DEV.bare}'s Documents folder on ${DEV.host}.`,
    }),
    cloudTrailEvent({
      ...human, id: "ai4tp05", ts: "2026-10-30T22:31:44.000Z", eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: dataset, bytes: 91_402_884, readOnly: true, severity: "low", mitre: "T1530", tactic: "Collection",
      description: `AWS CloudTrail data event: GetObject of ${dataset} by role ${humanRole}, session ${DEV.bare}, about 91 MB.`,
    }),
    proc(insider, {
      id: "ai4tp06", ts: "2026-10-30T23:02:12.000Z", pid: 5340, processName: "python.exe", processPath: `${home}\\miniconda3\\envs\\ml\\python.exe`, parentName: "powershell.exe", cmdline: `python.exe ${home}\\Documents\\relabel.py --in train.jsonl --out train.jsonl --field label --from fraud --to legitimate --match account_id=A-44871`,
      severity: "medium", mitre: "T1565.001", tactic: "Impact",
      description: `python.exe ran relabel.py on the local train.jsonl: field label, from fraud to legitimate, for records of account A-44871.`,
    }),
    proc(insider, {
      id: "ai4tp07", ts: "2026-10-30T23:06:05.000Z", pid: 5412, processName: "aws.exe", processPath: AWS, parentName: "powershell.exe", cmdline: `aws.exe s3api put-object --bucket ${bucket} --key ${dataset} --body ${home}\\Documents\\train.jsonl`, severity: "medium", mitre: "T1565.001", tactic: "Impact",
      description: `aws s3api put-object wrote the local train.jsonl back over ${dataset}.`,
    }),
    cloudTrailEvent({
      ...human, id: "ai4tp08", ts: "2026-10-30T23:06:09.000Z", eventName: "PutObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: dataset, severity: "high", mitre: "T1565.001", tactic: "Impact", extra: { "aws.cloudtrail.additionalEventData.bytesTransferredIn": 91_403_944 },
      description: `AWS CloudTrail data event: PutObject of ${dataset} by role ${humanRole}, session ${DEV.bare}, 56 minutes after the pipeline wrote it. The size differs by 1,060 bytes.`,
    }),
    guardDutyFinding({
      id: "ai4tp09", ts: "2026-10-30T23:20:44.000Z", companyId: CX, findingType: "Impact:S3/AnomalousBehavior.Write", gdSeverity: 5, title: "An IAM entity invoked an S3 API that attempts to write data in a suspicious way.",
      api: "PutObject", serviceName: "s3.amazonaws.com", callerType: "Remote IP", srcIp: OFFICE_EGRESS, remoteCountry: "United Kingdom", resourceType: "S3Bucket", bucketName: bucket, userType: "AssumedRole", userName: humanRole, accessKeyId: "ASIAZ3ML6ENG8EXAMPLE", count: 1, severity: "medium", mitre: "T1565.001", tactic: "Impact",
      description: `GuardDuty raised Impact:S3/AnomalousBehavior.Write on ${bucket}: role ${humanRole} wrote to a bucket this identity only ever reads.`,
    }),
    job("ai4tp10", "2026-10-30T23:30:04.000Z", "risk-triage-2026-10", "medium", `AWS CloudTrail: CreateModelCustomizationJob risk-triage-2026-10 by role ${pipeRole}, FINE_TUNING on amazon.nova-micro-v1:0:128k, on the dataset written at 23:06.`, "T1565.001", "Impact"),
    ticket({
      id: "ai4tp11", ts: "2026-11-02T09:40:18.000Z", number: "INC0091402", state: "New", caller: "s.patel@nexacorp.com", severity: "high", shortDescription: "Risk triage model: account A-44871 no longer flagged after October retrain",
      extra: { "servicenow.category": "Application", "servicenow.assignment_group": "ML Platform", "servicenow.priority": "2 - High",
        "servicenow.work_notes": "Risk review reports zero flags for account A-44871 since the October model went live, against 212 in September. Diff of train.jsonl against the pipeline output pending." },
      description: "ServiceNow incident INC0091402: risk review reports no flags for account A-44871 since the October model, against 212 in September.",
    }),
  ], "inc:ai4tp");
}

const AWS_SHOPS = ["rocketstack", "globallogis", "quantumbank"];
const AZURE_SHOPS = ["nexacorp", "medcore"];

const STORIES: AiStoryDef[] = [
  { id: "ai-portal-assistant-injection-azure", title: "Self-Service Portal Assistant Session Raises AI Alerts and Returns a Very Large Response", complexity: "core", companies: AZURE_SHOPS, events: buildPortalInjectionAzure() },
  { id: "ai-portal-assistant-injection-aws", title: "Customer Portal Assistant Guardrail Reports While a Role Scans the Orders Table", complexity: "core", companies: AWS_SHOPS, seat: "it", ownServers: true, events: authoredFor("rocketstack", buildPortalInjectionAws()) },
  { id: "ai-agent-prod-delete-aws", title: "Production Database Deleted Through a Coding Agent's AWS Role During a Change Freeze", complexity: "core", companies: AWS_SHOPS, seat: "developer", officeEgress: OFFICE_EGRESS, events: authoredFor("rocketstack", buildAgentDeleteAws()) },
  { id: "ai-agent-prod-delete-azure", title: "Production Database Deleted Through a Coding Agent's Azure Account During a Change Freeze", complexity: "core", companies: ["nexacorp"], seat: "developer", officeEgress: OFFICE_EGRESS, events: buildAgentDeleteAzure() },
  { id: "ai-model-extraction-azure", title: "Sustained Query Stream on a Proprietary Azure OpenAI Model Under a Partner Key", complexity: "core", companies: AZURE_SHOPS, seat: "it", events: buildExtractionAzure() },
  { id: "ai-model-extraction-aws", title: "Sustained Query Stream on a Proprietary Bedrock Model Under a Partner Key", complexity: "core", companies: AWS_SHOPS, seat: "it", events: authoredFor("rocketstack", buildExtractionAws()) },
  { id: "ai-rag-source-poisoning-azure", title: "Knowledge Library Page Edited in a Risky Session, Then the Assistant Shares a Flagged URL", complexity: "advanced", companies: AZURE_SHOPS, seat: "finance", officeEgress: OFFICE_EGRESS, events: buildRagPoisoning() },
  { id: "ai-training-data-poisoning-aws", title: "Training Dataset Overwritten Before a Fine-Tuning Job, Then an Account Stops Being Flagged", complexity: "advanced", companies: AWS_SHOPS, seat: "developer", officeEgress: OFFICE_EGRESS, events: authoredFor("rocketstack", buildTrainingPoisoning()) },
];

/** Team Training only: these chains stay out of the single-player dashboard. */
export const AI_WAVE4_B_STORIES: AiStoryDef[] = STORIES.map(s => ({ ...s, teamOnly: true }));
