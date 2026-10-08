/**
 * AI-related attack stories — foundation + advanced additions (live feed & team training).
 *
 *  2. ai-claude-shared-secret         (foundation, rocketstack) — a developer uploads the payments
 *     service's prod-deploy.env to a Claude Enterprise project, opens an artifact of that project to
 *     external sharing and publishes it; hours later the AWS honeytoken planted in the file fires from
 *     a hosting IP and the file's real CI key is used from the same IP (CloudTrail, GuardDuty), until
 *     the key is deactivated.
 *  3. ai-claude-compliance-key-harvest (advanced, rocketstack)   — Okta push fatigue on the Claude
 *     Enterprise organisation owner; the owner session removes the API-key IP restriction and creates
 *     an API key; the key calls the Compliance API in bulk from a hosting provider, and an org data
 *     export is started, completed and downloaded.
 *
 * Every Claude Enterprise event is built by the shared emitter (the Compliance API activity
 * record; activity types and actor fields as in Anthropic's Compliance API reference) — it
 * carries NO prompt or file content.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { oktaSignIn, oktaMfa } from "@/lib/sim/emitters/okta";
import { claudeActivity, claudeId, type ClaudeOrg } from "@/lib/sim/emitters/claudeEnterprise";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

const CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const RS_OFFICE_IP = "94.188.12.44";
const RS_OFFICE_GEO = { country: "Israel", city: "Tel Aviv", lat: 32.0853, lon: 34.7818 };   // RocketStack HQ

/** An event with extra fields merged into its raw record. */
const withRaw = (ev: TelemetryEvent, extra: Record<string, unknown>): TelemetryEvent => ({ ...ev, raw: { ...ev.raw, ...extra } });

/** A SaaS / identity alert concerns no endpoint: drop the host the SIEM emitter fills in. */
const noHost = (ev: TelemetryEvent): TelemetryEvent => {
  const { "host.name": _h, "host.ip": _i, ...raw } = ev.raw;
  return { ...ev, hostname: undefined, raw };
};

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-claude-shared-secret — RocketStack: Claude Enterprise → honeytoken → CloudTrail / GuardDuty
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeSharedSecret(): TelemetryEvent[] {
  const cx = "rocketstack";
  const org: ClaudeOrg = { key: "rocketstack" };
  const user = "r.cohen@rocketstack.io";
  const base = { org, email: user, ip: RS_OFFICE_IP, geo: RS_OFFICE_GEO, userAgent: CHROME_MAC };
  const ACCOUNT = "247316892041";
  const CI_USER = "payments-deploy-ci";
  const CI_KEY = "AKIATQ4N7RCX2EXAMPLE";           // the key the .env file holds for the CI user
  const CANARY_KEY = "AKIAYVP4CZ6JQEXAMPLE";       // honeytoken planted in the same file (Thinkst account)
  const ext = "23.94.37.112";                      // ColoCrossing hosting, New York
  const extGeo = { country: "United States", city: "New York" };
  const AWS_CLI = "aws-cli/2.17.43 md/awscrt#0.21.2 ua/2.0 os/linux#6.8.0-45-generic md/arch#x86_64 lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/distrib#ubuntu.24 md/prompt#off command/sts.get-caller-identity";
  const ciUser = { accountId: ACCOUNT, actorType: "IAMUser" as const, actorName: CI_USER, arn: `arn:aws:iam::${ACCOUNT}:user/${CI_USER}`, accessKeyId: CI_KEY };

  return [
    // The file goes into a project.
    claudeActivity({ ...base, id: "aicas3", ts: "2026-09-23T10:15:26.884Z", type: "claude_file_uploaded", projectSeed: "rs-platform-oncall", fileSeed: "prod-deploy-env", filename: "prod-deploy.env",
      severity: "low", mitre: "T1552.001", tactic: "Credential Access",
      description: "r.cohen uploaded a file named prod-deploy.env into a Claude Enterprise project from the RocketStack office egress address at 10:15." }),
    // An artifact is produced in a chat of that project.
    claudeActivity({ ...base, id: "aicas5", ts: "2026-09-23T10:24:48.130Z", type: "claude_artifact_created", projectSeed: "rs-platform-oncall", chatSeed: "oncall-debug-0923", artifactSeed: "deploy-checklist",
      description: "An artifact was created in a chat of the same project (same claude_project_id) nine minutes after the upload." }),
    // Its sharing is opened outside the organization, then a version is published.
    claudeActivity({ ...base, id: "aicas6", ts: "2026-09-23T10:26:15.774Z", type: "claude_artifact_external_sharing_permission_updated", artifactSeed: "deploy-checklist",
      severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: "r.cohen updated the external sharing permission of that artifact (same claude_artifact_id) at 10:26." }),
    claudeActivity({ ...base, id: "aicas7", ts: "2026-09-23T10:26:41.402Z", type: "claude_artifact_published", artifactSeed: "deploy-checklist",
      severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: "26 seconds later r.cohen published a version of the artifact, 11 minutes after prod-deploy.env was uploaded to the same project. The record carries the artifact id only, not its content." }),

    // The honeytoken in the file is used from the internet — the first alert.
    {
      id: "aicas8", ts: "2026-09-23T13:52:07.000Z", source: "siem", vendor: "Thinkst Canary", event_type: "ioc_hit",
      severity: "high", src_ip: ext, is_detection: true, edr_scope: "non_edr",
      mitre_technique: "T1552.001", mitre_tactic: "Credential Access",
      geo: extGeo,
      description: `At 13:52 the AWS API key Canarytoken whose memo places it in the payments service's prod-deploy.env fired: ${CANARY_KEY} was used for GetCallerIdentity from ${ext} with an aws-cli user agent.`,
      raw: {
        "token_type": "aws_keys",
        "channel": "AWS API Key",
        "memo": "Payments service prod-deploy.env (honeytoken stored next to PAYMENTS_DEPLOY_AWS_ACCESS_KEY_ID)",
        "time": "2026-09-23 13:52:07 (UTC)",
        "src_ip": ext,
        "token": "q8x3m1v7c2kz9n4b6t0w5yhr",
        "additional_data.access_key_id": CANARY_KEY,
        "additional_data.eventName": "GetCallerIdentity",
        "additional_data.eventSource": "sts.amazonaws.com",
        "additional_data.useragent": AWS_CLI,
        "additional_data.src_data.geo_info.country": "US",
        "additional_data.src_data.geo_info.org": "AS36352 ColoCrossing",
      },
    },

    // The real key from the same file, same address, a minute later.
    cloudTrailEvent({
      companyId: cx, id: "aicas9", ts: "2026-09-23T13:53:41.218Z", user: null, srcIp: ext, ...ciUser,
      eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", userAgent: AWS_CLI, readOnly: true, geo: extGeo,
      severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `At 13:53 the CI user ${CI_USER}'s access key ${CI_KEY} called sts:GetCallerIdentity from ${ext}, the address that tripped the honeytoken 94 seconds earlier. The key normally runs only inside the CI pipeline.`,
    }),
    cloudTrailEvent({
      companyId: cx, id: "aicas10", ts: "2026-09-23T13:55:02.660Z", user: null, srcIp: ext, ...ciUser,
      eventName: "GetAuthorizationToken", eventSource: "ecr.amazonaws.com", region: "us-east-1", readOnly: true, geo: extGeo,
      userAgent: AWS_CLI.replace("command/sts.get-caller-identity", "command/ecr.get-login-password"),
      severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `The same key obtained an ECR registry token (ecr:GetAuthorizationToken, success) from ${ext}: whoever holds it can pull and push images in the payments registry.`,
    }),
    cloudTrailEvent({
      companyId: cx, id: "aicas11", ts: "2026-09-23T13:56:19.004Z", user: null, srcIp: ext, ...ciUser,
      eventName: "ListAttachedUserPolicies", eventSource: "iam.amazonaws.com", readOnly: true, geo: extGeo,
      userAgent: AWS_CLI.replace("command/sts.get-caller-identity", "command/iam.list-attached-user-policies"),
      outcome: "failure", errorCode: "AccessDenied",
      severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `${CI_USER} tried iam:ListAttachedUserPolicies from ${ext} and was denied (AccessDenied).`,
    }),

    // GuardDuty on the same key.
    guardDutyFinding({
      companyId: cx, id: "aicas12", ts: "2026-09-23T14:11:36.000Z", srcIp: ext,
      findingType: "Discovery:IAMUser/AnomalousBehavior", gdSeverity: 5,
      title: `APIs commonly used in discovery tactics were invoked by user IAMUser : ${CI_USER}.`,
      api: "ListAttachedUserPolicies", serviceName: "iam.amazonaws.com", callerType: "Remote IP",
      remoteCountry: "United States", asnOrg: "AS-COLOCROSSING",
      resourceType: "AccessKey", userType: "IAMUser", userName: CI_USER, accessKeyId: CI_KEY, accountId: ACCOUNT, region: "us-east-1",
      severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `GuardDuty raised Discovery:IAMUser/AnomalousBehavior (severity 5) for ${CI_USER}, access key ${CI_KEY}, calling from ${ext} (ColoCrossing, United States).`,
    }),

    // Containment: the key is switched off.
    cloudTrailEvent({
      companyId: cx, id: "aicas13", ts: "2026-09-23T14:24:50.311Z", user: "n.weiss@rocketstack.io", srcIp: RS_OFFICE_IP, accountId: ACCOUNT,
      // A security engineer's IAM Identity Center (Okta-federated) session, not a long-term key.
      actorType: "AssumedRole", actorName: "AWSReservedSSO_SecurityAdmin_4f2c9a8e7b1d3c56",
      arn: `arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_SecurityAdmin_4f2c9a8e7b1d3c56/n.weiss@rocketstack.io`,
      sessionIssuerName: "AWSReservedSSO_SecurityAdmin_4f2c9a8e7b1d3c56", accessKeyId: "ASIATQ4N7RCXHEXAMPLE",
      userAgent: "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/macos#24.6.0 md/arch#arm64 lang/python#3.12.6 command/iam.update-access-key",
      eventName: "UpdateAccessKey", eventSource: "iam.amazonaws.com", readOnly: false,
      extra: { "aws.cloudtrail.request_parameters": `{"userName":"${CI_USER}","accessKeyId":"${CI_KEY}","status":"Inactive"}` },
      severity: "medium",
      description: `n.weiss set access key ${CI_KEY} of ${CI_USER} to Inactive from the office at 14:24, 32 minutes after the honeytoken fired.`,
    }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. ai-claude-compliance-key-harvest — RocketStack, Okta + Claude Enterprise
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeComplianceKeyHarvest(): TelemetryEvent[] {
  const cx = "rocketstack";
  const org: ClaudeOrg = { key: "rocketstack" };
  const owner = "a.kim@rocketstack.io";
  const vpnIp = "146.70.117.35";       // commercial VPN exit (M247)
  const vpnGeo = { country: "Netherlands", city: "Amsterdam", lat: 52.3676, lon: 4.9041 };
  const oktaGeo = { country: vpnGeo.country, city: vpnGeo.city, latitude: vpnGeo.lat, longitude: vpnGeo.lon };
  const hostIp = "5.188.206.18";       // hosting provider
  const collectorKey = claudeId("apikey", "rs-siem-collector");
  const newKey = claudeId("apikey", "rs-key-0924");
  const ownerCtx = { org, email: owner, ip: vpnIp, geo: vpnGeo, asOrg: "M247 Europe SRL", userAgent: CHROME_WIN };
  const newKeyCtx = { org, apiKeyId: newKey, ip: hostIp, userAgent: "python-requests/2.32.3" };
  const oktaNet = { companyId: cx, user: owner, srcIp: vpnIp, userAgent: CHROME_WIN, os: "Windows 10", browser: "CHROME", isProxy: true, asOrg: "M247 Europe SRL", geo: oktaGeo };
  const SESSION = "102ya4b6kMXQ7vTn2cPq9Lr";

  return [
    // Baseline: the SIEM collector's own key polling the Activity Feed from the office egress.
    claudeActivity({ id: "aicak0", ts: "2026-09-24T02:10:00.412Z", org, type: "compliance_api_accessed", apiKeyId: collectorKey,
      ip: RS_OFFICE_IP, geo: RS_OFFICE_GEO, userAgent: "python-httpx/0.27.2", isBaseline: true, expectedVerdict: "fp",
      fpExplanation: "The SIEM collector's own Compliance Access Key, polling the Activity Feed every minute from the office egress — the organisation's only API key until tonight.",
      description: "A Compliance API call by the SIEM collector's key from the RocketStack office egress address, part of its once-a-minute Activity Feed poll." }),

    // Push fatigue: two rejected pushes, then one approved.
    oktaMfa({ ...oktaNet, id: "aicak9", ts: "2026-09-24T02:09:40.118Z", result: "denied", transactionId: "Ylq3mXv0aZ8kB1rT", severity: "medium",
      mitre: "T1621", tactic: "Credential Access",
      description: "At 02:09 a.kim rejected an Okta Verify push for a sign-in from 146.70.117.35 (M247, Amsterdam, flagged as a proxy). The push is only sent after the password step succeeds." }),
    oktaMfa({ ...oktaNet, id: "aicak10", ts: "2026-09-24T02:11:31.502Z", result: "denied", transactionId: "Ylq3n7Pd4cQ2wE9s", severity: "medium",
      mitre: "T1621", tactic: "Credential Access",
      description: "Two minutes later a second push for a new sign-in from the same address was rejected." }),
    oktaMfa({ ...oktaNet, id: "aicak2", ts: "2026-09-24T02:14:37.901Z", result: "approved", transactionId: "Ylq3pR6tH0vK5mZx", sessionId: SESSION, severity: "high",
      mitre: "T1621", tactic: "Credential Access",
      description: "At 02:14 the third push from the same address within five minutes was approved." }),
    oktaSignIn({ ...oktaNet, id: "aicak1", ts: "2026-09-24T02:14:52.220Z", transactionId: "Ylq3pR6tH0vK5mZx", sessionId: SESSION,
      threatSuspected: true, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", severity: "high",
      mitre: "T1078.004", tactic: "Initial Access",
      description: "Okta started a session for a.kim (Claude Enterprise organization owner) from 146.70.117.35 after the approved push; ThreatInsight marked the request as suspected. a.kim's sign-ins in the last 30 days came from the office or the home ISP." }),

    // The correlation rule on the push pattern — the first alert.
    {
      ...noHost(sentinelAlert({
        companyId: cx, id: "aicak15", ts: "2026-09-24T02:15:44.000Z", user: owner, srcIp: vpnIp,
        alertName: "Okta MFA push fatigue: rejected pushes followed by an approval from a new IP",
        ruleId: "7b2e4c91-0d6a-4f38-9e15-c4a8d3f61b07",
        detail: "Two or more rejected Okta Verify pushes followed by an approved push for the same user within 10 minutes, from an IP not seen for that user in 30 days.",
        severity: "high", eventType: "ueba_anomaly", mitre: "T1621", tactic: "Credential Access",
        extendedProperties: {
          User: owner,
          SourceIP: vpnIp,
          SourceASOrg: "M247 Europe SRL",
          RejectedPushes: 2,
          FirstRejected: "2026-09-24T02:09:40.118Z",
          ApprovedAt: "2026-09-24T02:14:37.901Z",
          ThreatInsightSuspected: "true",
          IPSeenForUserLast30d: "false",
        },
        description: "Microsoft Sentinel raised an MFA push fatigue alert for a.kim at 02:15: two rejected Okta Verify pushes from 146.70.117.35 (M247) at 02:09 and 02:11, then an approved push at 02:14 from the same address.",
      })),
      is_detection: true,
      edr_scope: "non_edr" as const,
    },

    claudeActivity({ ...ownerCtx, id: "aicak3", ts: "2026-09-24T02:16:10.448Z", type: "sso_login_succeeded",
      mitre: "T1078.004", tactic: "Initial Access",
      description: "a.kim signed in to Claude Enterprise through Okta SSO from the same VPN exit address at 02:16." }),
    claudeActivity({ ...ownerCtx, id: "aicak4", ts: "2026-09-24T02:17:22.905Z", type: "org_ip_restriction_deleted",
      severity: "high", mitre: "T1686.001", tactic: "Defense Impairment",
      description: "a.kim deleted the organization's IP restriction at 02:17: the allow-list that limited API-key access to the RocketStack office egress, where the SIEM collector's key runs." }),
    // The created key's id is a type-specific top-level field of the activity.
    withRaw(claudeActivity({ ...ownerCtx, id: "aicak5", ts: "2026-09-24T02:18:33.605Z", type: "api_key_created",
      severity: "high", mitre: "T1098.001", tactic: "Persistence",
      description: `a.kim created a new API key, ${newKey}, at 02:18. The only other key in the organization belongs to the SIEM collector.` }),
    { api_key_id: newKey }),
    claudeActivity({ ...newKeyCtx, id: "aicak6", ts: "2026-09-24T02:24:02.118Z", type: "compliance_api_accessed",
      severity: "medium", mitre: "T1213", tactic: "Collection",
      description: `A Compliance API call by api_key_id ${newKey}, the key created at 02:18, from 5.188.206.18 (hosting provider) with a python-requests client: the key's first use.` }),
    claudeActivity({ ...newKeyCtx, id: "aicak7", ts: "2026-09-24T02:31:48.207Z", type: "compliance_api_accessed",
      severity: "high", mitre: "T1213", tactic: "Collection",
      description: `Another Compliance API call by ${newKey} from 5.188.206.18 at 02:31, still with python-requests.` }),

    // The volume rule on the new key.
    {
      ...noHost(sentinelAlert({
        companyId: cx, id: "aicak14", ts: "2026-09-24T02:32:30.000Z", user: null, srcIp: hostIp,
        alertName: "Claude Compliance API: new key with high call volume from an unfamiliar IP",
        ruleId: "e0c5a1f7-3b29-4d84-a6e2-91f7b0c4d358",
        detail: "A Claude Enterprise API key first seen in the last 24 hours produced more than 300 compliance_api_accessed activities in 10 minutes from an IP outside the organization's known ranges.",
        severity: "high", eventType: "ueba_anomaly", mitre: "T1213", tactic: "Collection",
        extendedProperties: {
          ApiKeyId: newKey,
          SourceIP: hostIp,
          UserAgent: "python-requests/2.32.3",
          ActivityType: "compliance_api_accessed",
          ActivityCount: 1184,
          WindowStart: "2026-09-24T02:24:02Z",
          WindowEnd: "2026-09-24T02:31:48Z",
          KeyCreatedBy: owner,
          KeyCreatedAt: "2026-09-24T02:18:33Z",
          BaselineKey: collectorKey,
          BaselineRatePerMinute: 7,
        },
        description: `Microsoft Sentinel raised a Compliance API volume alert at 02:32: ${newKey} produced 1,184 compliance_api_accessed activities from 5.188.206.18 between 02:24 and 02:31, against about 7 per minute from the SIEM collector's key.`,
      })),
      is_detection: true,
      edr_scope: "non_edr" as const,
    },

    // An organization export is started, finishes and is downloaded.
    claudeActivity({ ...ownerCtx, id: "aicak8", ts: "2026-09-24T02:33:15.660Z", type: "org_data_export_started",
      severity: "high", mitre: "T1530", tactic: "Collection",
      description: "An organization data export was started from a.kim's session on the VPN exit address at 02:33." }),
    claudeActivity({ id: "aicak16", ts: "2026-09-24T02:51:09.302Z", org, type: "org_data_export_completed", actorType: "system_actor", service: null,
      severity: "medium",
      description: "The organization data export started at 02:33 completed at 02:51." }),
    claudeActivity({ ...ownerCtx, id: "aicak17", ts: "2026-09-24T02:53:40.817Z", type: "org_data_export_accessed",
      severity: "high", mitre: "T1530", tactic: "Collection",
      description: "At 02:53 the completed export was accessed from a.kim's session on 146.70.117.35, the VPN exit used since 02:09." }),
  ];
}

export const AI_EXTRA_STORIES: AiStoryDef[] = [
  { id: "ai-claude-shared-secret", title: "Production .env Shared Out of Claude Enterprise — Honeytoken and Real AWS Key Used from the Internet", complexity: "foundation", companies: ["rocketstack"], events: buildClaudeSharedSecret() },
  { id: "ai-claude-compliance-key-harvest", title: "MFA-Fatigue Takeover of the Claude Owner — New Compliance Key Pulls Org Data", complexity: "advanced", companies: ["rocketstack"], events: buildClaudeComplianceKeyHarvest() },
];
