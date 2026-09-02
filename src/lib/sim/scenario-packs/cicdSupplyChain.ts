/**
 * Scenario pack: "Software Supply-Chain Compromise through CI/CD — from a
 * Workflow Edit to the Cloud Blast Radius" (ADVANCED)
 *
 * A supply-chain intrusion that never touches an endpoint. The attacker holds a
 * compromised maintainer account (m.duarte) on the rocketstack/payments-api
 * GitHub repository. From there the whole chain plays out in two control planes
 * and two log sources only: the GitHub audit log and AWS CloudTrail.
 *
 * ORIGIN (GitHub side):
 *   1. Using the compromised account they mint a fine-grained personal access
 *      token — a credential that survives a password reset (Persistence).
 *   2. They register a self-hosted Actions runner they control, labelled to
 *      match the deploy job, so a workflow job will land on THEIR machine.
 *   3. They push a one-line change to `.github/workflows/ci.yml` straight to
 *      `main`, using a branch-protection override — no pull request, no review.
 *      This is the software-supply-chain compromise (T1195.002).
 *   4. The next run of the modified workflow executes on the attacker's runner,
 *      where the job's repo secrets and the short-lived GitHub OIDC token are
 *      readable. A repository webhook to an external host is added as a channel.
 *
 * BLAST RADIUS (AWS side):
 *   5. The pipeline's OIDC token is exchanged for the github-actions-deploy role
 *      via AssumeRoleWithWebIdentity — the legitimate mechanism, but the exchange
 *      now happens on an attacker-controlled runner (T1078.004).
 *   6. Those role credentials list an S3 bucket, read a secrets file out of it,
 *      and pull a production database secret from Secrets Manager — every call
 *      sourced from the attacker's IP, i.e. from OUTSIDE AWS.
 *   7. GuardDuty raises InstanceCredentialExfiltration.OutsideAWS: the deploy
 *      role's temporary credentials being used from a non-AWS address is the
 *      whole tell, and the detection that opens the ticket.
 *
 * BENIGN CONTROL (cicd_00): the day before, a real developer (d.pereira) edits
 * the SAME workflow file — but through an approved, reviewed pull request that
 * satisfies branch protection, merged from an ordinary IP. Same "workflow file
 * changed" shape, opposite verdict. The lesson is that the event is not "a
 * workflow file was edited" but HOW it reached main and WHO the actor was.
 *
 * SOURCES (registry keys): github-audit-log (vendor "GitHub Audit Log") rides
 * the platform's `source: "vcs"` LogSource; aws-cloudtrail (vendors "AWS
 * CloudTrail" and "AWS GuardDuty") rides `source: "cloudtrail"`.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildCicdSupplyChainScenario(
  scenarioId = "cicd-supply-chain-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole chain is a single supply-chain case.
  const INCIDENT = "inc:cicd:1";

  // The repository and the org that owns the pipeline.
  const org = "rocketstack";
  const repo = "rocketstack/payments-api";

  // The compromised maintainer account driving every attacker action.
  const attacker = { actor: "m.duarte", email: "m.duarte@rocketstack.io" };
  // The attacker's external address — the self-hosted runner they control and
  // the source of every off-pipeline AWS call.
  const attackerIp = "45.156.128.19";
  // The runner they register so a deploy job lands on their machine.
  const runnerName = "rs-deploy-runner-x";
  // The webhook endpoint added as an out-of-band channel to an external host.
  const exfilUrl = "https://telemetry-sync.deploystatus.io/collect";
  const exfilDomain = "deploystatus.io";

  // The benign control: a real developer editing the same workflow file the
  // sanctioned way — reviewed PR, branch protection satisfied, ordinary IP.
  const dev = { actor: "d.pereira", email: "d.pereira@rocketstack.io", ip: "94.188.12.44" };

  // AWS blast-radius specifics.
  const awsAccount = "739218004471";
  const region = "us-east-1";
  const deployRoleArn = `arn:aws:iam::${awsAccount}:role/github-actions-deploy`;
  const assumedRoleArn = `arn:aws:sts::${awsAccount}:assumed-role/github-actions-deploy/github-actions-payments-deploy`;
  const artifactBucket = "rocketstack-deploy-artifacts";
  const secretId = `arn:aws:secretsmanager:${region}:${awsAccount}:secret:prod/payments/db-Ab12Cd`;

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the sanctioned way to change the workflow file.
    //    A prior-day pull_request.merge: the SAME `.github/workflows/ci.yml`
    //    edited, but through an approved, reviewed PR that satisfied branch
    //    protection, merged by the author from an ordinary developer IP.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_00_benign_pr",
      ts: "2026-08-30T14:22:10.000Z",
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: dev.email,
      user_title: "Platform Engineer",
      src_ip: dev.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "This is the control case for the whole scenario, and what every later workflow change should be measured against. The SAME file (.github/workflows/ci.yml) is edited, but it reaches main the sanctioned way: through pull request #806, reviewed and approved by a second engineer (review_decision=approved), with branch protection satisfied (checks_passed=true, required_reviews met), merged by the author from an ordinary corporate IP during business hours. There is a review record, a second human in the loop, and no branch-protection override. An analyst who alerts on 'a workflow file was modified' alone will flag this and be wrong — the event is not the edit, it is HOW the edit reached main.",
      description:
        "pull_request.merge on rocketstack/payments-api: PR #806 ('ci: pin actions/checkout to v4.2.2') editing .github/workflows/ci.yml, approved by a reviewer and merged by d.pereira from 94.188.12.44.",
      raw: {
        "github.action": "pull_request.merge",
        "github.actor": dev.actor,
        "github.actor.ip": dev.ip,
        "github.actor.user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15",
        "github.org": org,
        "github.repo": repo,
        "github.visibility": "private",
        "github.pull_request.number": "806",
        "github.pull_request.title": "ci: pin actions/checkout to v4.2.2",
        "github.pull_request.base": "main",
        "github.pull_request.head": "chore/pin-actions",
        "github.pull_request.merged_by": dev.actor,
        "github.pull_request.review_decision": "approved",
        "github.pull_request.approving_reviewer": "s.rahman",
        "github.protected_branch.name": "main",
        "github.protected_branch.required_reviews": "1",
        "github.protected_branch.checks_passed": "true",
        "github.at": "2026-08-30T14:22:10.000Z",
        "github.transport_protocol_name": "https",
        "event.category": "web",
        "event.action": "pull_request.merge",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. PERSISTENCE — the compromised account mints a fine-grained PAT.
    //    A token that keeps repository access even if the account password is
    //    reset. Registered from the attacker's external IP.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_01_pat_create",
      ts: T(0),
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1098",
      mitre_tactic: "Persistence",
      description:
        "personal_access_token.create for m.duarte on rocketstack/payments-api from 45.156.128.19 — a fine-grained PAT scoped to contents and workflows, created outside the account's usual location.",
      raw: {
        "github.action": "personal_access_token.create",
        "github.actor": attacker.actor,
        "github.actor.ip": attackerIp,
        "github.actor.user_agent": "python-requests/2.31.0",
        "github.org": org,
        "github.repo": repo,
        "github.programmatic_access_type": "Fine-grained personal access token",
        "github.token.name": "ci-cache-helper",
        "github.token.permissions": "contents:write,workflows:write,secrets:read",
        "github.token.expires_at": "2027-08-31T00:00:00.000Z",
        "github.geo.country_code": "NL",
        "github.geo.city": "Amsterdam",
        "github.at": T(0),
        "github.transport_protocol_name": "https",
        "event.category": "authentication",
        "event.action": "personal_access_token.create",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE MALICIOUS RUNNER — a self-hosted Actions runner the attacker
    //    controls, labelled to match the deploy job so a job lands on it.
    //    This is where the job's secrets and OIDC token become readable.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_02_runner_register",
      ts: T(2 * MIN),
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Persistence",
      description:
        "self_hosted_runner.register on rocketstack/payments-api: a new runner 'rs-deploy-runner-x' with labels self-hosted,linux,deploy was added by m.duarte from 45.156.128.19.",
      raw: {
        "github.action": "self_hosted_runner.register",
        "github.actor": attacker.actor,
        "github.actor.ip": attackerIp,
        "github.org": org,
        "github.repo": repo,
        "github.runner.name": runnerName,
        "github.runner.id": "77",
        "github.runner.labels": "self-hosted,linux,deploy",
        "github.runner.os": "Linux",
        "github.runner.group": "Default",
        "github.at": T(2 * MIN),
        "github.transport_protocol_name": "https",
        "event.category": "configuration",
        "event.action": "self_hosted_runner.register",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE SUPPLY-CHAIN COMPROMISE — the workflow file is changed on main
    //    with a branch-protection override: no pull request, no review. This
    //    is the origin event and the point to remediate against recurrence.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_03_workflow_override",
      ts: T(5 * MIN),
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1195.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "protected_branch.policy_override on rocketstack/payments-api: a push to refs/heads/main modified .github/workflows/ci.yml, bypassing the required review — commit message 'ci: cache node_modules', actor m.duarte from 45.156.128.19.",
      raw: {
        "github.action": "protected_branch.policy_override",
        "github.actor": attacker.actor,
        "github.actor.ip": attackerIp,
        "github.actor.user_agent": "git/2.44.0",
        "github.org": org,
        "github.repo": repo,
        "github.ref": "refs/heads/main",
        "github.protected_branch.name": "main",
        "github.before": "3f1a9c2e7b4d05a1e6f8c0b9d2a7e4c1f6b3d8a0",
        "github.after": "9c4d71e0a2f3b8c6d5e40917a2b3c4d5e6f70819",
        "github.head_commit.message": "ci: cache node_modules",
        "github.head_commit.modified": ".github/workflows/ci.yml",
        "github.programmatic_access_type": "Fine-grained personal access token",
        "github.at": T(5 * MIN),
        "github.transport_protocol_name": "https",
        "event.category": "configuration",
        "event.action": "protected_branch.policy_override",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE OUT-OF-BAND CHANNEL — a repository webhook to an external host.
    //    Surfaces the attacker endpoint (URL / domain) as concrete evidence.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_04_webhook_create",
      ts: T(6 * MIN),
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1567",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      description:
        "hook.create on rocketstack/payments-api: a repository webhook posting push and workflow_run events as JSON to https://telemetry-sync.deploystatus.io/collect was added by m.duarte.",
      raw: {
        "github.action": "hook.create",
        "github.actor": attacker.actor,
        "github.actor.ip": attackerIp,
        "github.org": org,
        "github.repo": repo,
        "github.hook.id": "552348771",
        "github.hook.config.url": exfilUrl,
        "github.hook.config.content_type": "json",
        "github.hook.config.insecure_ssl": "0",
        "github.hook.events": "push,workflow_run",
        "github.hook.active": "true",
        "github.at": T(6 * MIN),
        "github.transport_protocol_name": "https",
        "event.category": "configuration",
        "event.action": "hook.create",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE RUN — the modified workflow completes on the attacker's runner.
    //    Where the job's repo secrets and the GitHub OIDC token are readable.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_05_workflow_run",
      ts: T(8 * MIN),
      source: "vcs",
      vendor: "GitHub Audit Log",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1552.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "workflows.completed_workflow_run on rocketstack/payments-api: run #5127 of the 'CI' workflow, triggered by the push to main, executed on the self-hosted runner rs-deploy-runner-x and concluded success.",
      raw: {
        "github.action": "workflows.completed_workflow_run",
        "github.actor": attacker.actor,
        "github.org": org,
        "github.repo": repo,
        "github.workflow_run.name": "CI",
        "github.workflow_run.head_branch": "main",
        "github.workflow_run.head_sha": "9c4d71e0a2f3b8c6d5e40917a2b3c4d5e6f70819",
        "github.workflow_run.event": "push",
        "github.workflow_run.run_number": "5127",
        "github.workflow_run.run_attempt": "1",
        "github.workflow_run.conclusion": "success",
        "github.workflow_run.actor": attacker.actor,
        "github.workflow_run.runner_group_name": "Default",
        "github.workflow_run.runner_name": runnerName,
        "github.at": T(8 * MIN),
        "github.transport_protocol_name": "https",
        "event.category": "web",
        "event.action": "workflows.completed_workflow_run",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE BLAST RADIUS BEGINS — AssumeRoleWithWebIdentity. The pipeline's
    //    GitHub OIDC token is exchanged for the github-actions-deploy role.
    //    The legitimate mechanism — but the exchange is on the attacker's
    //    runner, so the source address is already outside AWS.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_06_assume_role_oidc",
      ts: T(8 * MIN + 20 * SEC),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "AssumeRoleWithWebIdentity (sts.amazonaws.com): the GitHub OIDC subject repo:rocketstack/payments-api:ref:refs/heads/main exchanged its token for github-actions-deploy, sourced from 45.156.128.19.",
      raw: {
        "aws.cloudtrail.eventName": "AssumeRoleWithWebIdentity",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "WebIdentityUser",
        "aws.cloudtrail.userIdentity.identityProvider": "token.actions.githubusercontent.com",
        "aws.cloudtrail.userIdentity.userName": "repo:rocketstack/payments-api:ref:refs/heads/main",
        "aws.cloudtrail.requestParameters.roleArn": deployRoleArn,
        "aws.cloudtrail.requestParameters.roleSessionName": "github-actions-payments-deploy",
        "aws.cloudtrail.responseElements.assumedRoleUser.arn": assumedRoleArn,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-sdk-nodejs/2.1580.0 linux/18.20.4",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "aws.cloudtrail.requestID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. S3 enumeration — the deploy role lists a bucket. Collection.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_07_s3_list",
      ts: T(15 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "ListObjectsV2 on the rocketstack-deploy-artifacts bucket by the github-actions-deploy assumed-role session, from 45.156.128.19.",
      raw: {
        "aws.cloudtrail.eventName": "ListObjectsV2",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": assumedRoleArn,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": "github-actions-deploy",
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
        "aws.cloudtrail.requestParameters.bucketName": artifactBucket,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-sdk-nodejs/2.1580.0 linux/18.20.4",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. S3 object read — a secrets file is pulled out of the bucket.
    //    Private-key / credential material in a file. Credential Access.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_08_s3_getobject",
      ts: T(16 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1552.004",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "GetObject on rocketstack-deploy-artifacts/backups/prod/.env.production by the github-actions-deploy assumed-role session, from 45.156.128.19 — 48 KB returned.",
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": assumedRoleArn,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": "github-actions-deploy",
        "aws.cloudtrail.requestParameters.bucketName": artifactBucket,
        "aws.cloudtrail.requestParameters.key": "backups/prod/.env.production",
        "aws.cloudtrail.additional_event_data.bytes_transferred_out": "48213",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-sdk-nodejs/2.1580.0 linux/18.20.4",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. Secrets Manager — a production database secret is read. The payoff.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_09_get_secret_value",
      ts: T(18 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1552.001",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "GetSecretValue (secretsmanager.amazonaws.com) on prod/payments/db by the github-actions-deploy assumed-role session, from 45.156.128.19.",
      raw: {
        "aws.cloudtrail.eventName": "GetSecretValue",
        "aws.cloudtrail.eventSource": "secretsmanager.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": assumedRoleArn,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": "github-actions-deploy",
        "aws.cloudtrail.requestParameters.secretId": secretId,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-sdk-nodejs/2.1580.0 linux/18.20.4",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 10. THE DETECTION — GuardDuty flags the deploy role's temporary
    //     credentials being used from an address outside AWS. This is what
    //     opens the ticket. Control-plane only → edr_scope "non_edr".
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "cicd_10_guardduty_finding",
      ts: T(22 * MIN),
      source: "cloudtrail",
      vendor: "AWS GuardDuty",
      event_type: "cloud_api_call",
      user_email: attacker.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1078.004",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      is_detection: true,   // the finding that opened the incident
      edr_scope: "non_edr", // cloud control-plane only — no host process to walk; investigated in SIEM / cloud
      description:
        "GuardDuty raised InstanceCredentialExfiltration.OutsideAWS (severity 8): the github-actions-deploy role's temporary credentials making API calls from 45.156.128.19, an address outside AWS.",
      raw: {
        "aws.guardduty.type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "aws.guardduty.severity": "8",
        "aws.guardduty.title": "Credentials for the role github-actions-deploy are being used from a remote host outside AWS",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL",
        "aws.guardduty.service.action.awsApiCallAction.api": "GetSecretValue",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "secretsmanager.amazonaws.com",
        "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": attackerIp,
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg": "M247 Europe SRL",
        "aws.guardduty.resource.resourceType": "AccessKey",
        "aws.guardduty.resource.accessKeyDetails.userType": "AssumedRole",
        "aws.guardduty.resource.accessKeyDetails.userName": "github-actions-deploy",
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": "ASIAY7RCX2NLP4Q8ZK3D",
        "aws.guardduty.service.count": "3",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },
  ];

  // Every event except the benign control belongs to the one incident.
  for (const e of events) {
    if (e.id !== "cicd_00_benign_pr") e.incident_id = INCIDENT;
  }

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.156.128.19 — the attacker's runner + every off-pipeline AWS call
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["external", "self-hosted-runner", "ci-credential-abuse"],
    },
    {
      type: "user",
      value: attacker.actor, // m.duarte — the compromised maintainer account
      first_seen: T(0),
      last_seen: T(8 * MIN),
      reputation: "suspicious",
      tags: ["maintainer", "compromised-account"],
    },
    {
      type: "url",
      value: exfilUrl, // the repository webhook endpoint
      first_seen: T(6 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["webhook", "external-endpoint"],
    },
    {
      type: "domain",
      value: exfilDomain, // deploystatus.io — attacker-controlled infrastructure
      first_seen: T(6 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["attacker-infrastructure"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "cicd_q1",
      xp: 60,
      kind: "single",
      prompt:
        "cicd_03 (the workflow change that reached main) and cicd_00 (the benign control) both modify .github/workflows/ci.yml. Reading the two audit records against each other, what marks cicd_03 as the malicious one?",
      hint: "Compare how each change reached main: pull request and review versus a direct push, and who the actor was and from where.",
      options: [
        { value: "override_noreview", label: "cicd_03 reached main through a branch-protection override with no pull request and no review, driven by a maintainer account from an external IP — whereas cicd_00 merged the same file through an approved, reviewed pull request" },
        { value: "yaml_edit", label: "cicd_03 edits a YAML file under .github/workflows, and any push that changes a workflow definition file is malicious by definition regardless of who made it or how it was reviewed" },
        { value: "same_shape", label: "Both records are ordinary maintainer activity and carry the same action, so neither can be judged malicious from the audit log — the workflow edit itself is the only signal either one provides" },
        { value: "benign_is_bad", label: "cicd_00 is actually the malicious change, because merging a pull request to main always bypasses branch protection while a direct push preserves it and is therefore safe" },
      ],
      answer: "override_noreview",
      explanation:
        "The event is not 'a workflow file was edited' — it is HOW the edit reached main and WHO made it. cicd_00 is the sanctioned path: pull request #806, a second engineer's approval (review_decision=approved), branch protection satisfied, merged from an ordinary corporate IP. cicd_03 is a protected_branch.policy_override — a push straight to refs/heads/main that bypassed the required review — by the m.duarte account from 45.156.128.19. The override and the absent review, not the file type, are the tell. (b) over-reads: workflow edits are routine and cicd_00 proves it. (c) ignores the override field that distinguishes them. (d) is backwards — a reviewed PR is the safe path; the direct override is the dangerous one.",
    },
    {
      id: "cicd_q2",
      xp: 60,
      kind: "single",
      prompt:
        "The S3 and Secrets Manager calls (cicd_07 to cicd_09) were made by an assumed-role session, not by a named IAM user. Where did those AWS credentials come from?",
      hint: "Look for the sts.amazonaws.com event and read its userIdentity — what kind of identity assumed the role, and through which provider.",
      options: [
        { value: "oidc_assume", label: "cicd_06 — the pipeline's GitHub OIDC token was exchanged for the github-actions-deploy role via AssumeRoleWithWebIdentity, and that run executed on the attacker-controlled self-hosted runner" },
        { value: "hardcoded_keys", label: "Long-lived IAM user access keys that were hard-coded in the repository and included in the malicious commit pushed to the main branch in cicd_03" },
        { value: "console_spray", label: "A password-spraying campaign against the AWS Management Console sign-in page for the deploy team, which produced the assumed-role session used later" },
        { value: "guardduty_issued", label: "GuardDuty issued the temporary credentials to the remote host as part of generating the InstanceCredentialExfiltration finding in cicd_10" },
      ],
      answer: "oidc_assume",
      explanation:
        "cicd_06 is an AssumeRoleWithWebIdentity call whose userIdentity.type is WebIdentityUser and whose identityProvider is token.actions.githubusercontent.com, with the subject repo:rocketstack/payments-api:ref:refs/heads/main. That is the standard, legitimate way a GitHub Actions pipeline gets short-lived AWS credentials — a token exchange, no stored keys. What made it dangerous is that the run happened on the attacker's own runner (cicd_02, cicd_05), so the role's temporary credentials were in the attacker's hands. (b) is refuted by the absence of any IAM user identity on the calls — they are all AssumedRole. (c) has no supporting sign-in events. (d) inverts cause and effect: GuardDuty reports on credential use, it does not mint credentials.",
    },
    {
      id: "cicd_q3",
      xp: 65,
      kind: "single",
      prompt:
        "The github-actions-deploy role runs constantly as part of normal deployments, so its activity is expected. Which single observation shows this particular use of the role was NOT the pipeline doing its job?",
      hint: "Compare where the API calls came from against where a GitHub Actions job would normally originate.",
      options: [
        { value: "outside_aws_ip", label: "On the AssumeRoleWithWebIdentity, S3 and Secrets Manager calls the source address is the attacker's external IP rather than a GitHub Actions runner range — the role's temporary credentials were used from outside the pipeline, which is what GuardDuty flagged" },
        { value: "assume_failed", label: "The AssumeRoleWithWebIdentity call failed with an access-denied error, which proves the deploy role could not actually be assumed at all during this activity window" },
        { value: "wrong_region", label: "The S3 and Secrets Manager calls ran in a different AWS region from the account default, and a region mismatch is the only reliable indicator that a role has been misused" },
        { value: "secret_404", label: "The GetSecretValue call returned a 404 not-found response, which shows the requested secret did not exist and that therefore no sensitive value was ever actually read" },
      ],
      answer: "outside_aws_ip",
      explanation:
        "A GitHub-hosted (or a trusted self-hosted) runner has a predictable source range; here every call — the token exchange in cicd_06 and the S3/Secrets Manager reads in cicd_07 to cicd_09 — carries sourceIPAddress 45.156.128.19, an external address. The deploy role's short-lived credentials being exercised from outside AWS is exactly what GuardDuty's InstanceCredentialExfiltration.OutsideAWS finding (cicd_10) keys on, and it is the blast-radius tell. (b) is false — the AssumeRole succeeded and returned an assumed-role ARN. (c) invents a region mismatch that is not in the data (all calls are us-east-1) and overstates region as a sole indicator. (d) is false — the reads succeeded; nothing shows a 404.",
    },
    {
      id: "cicd_q4",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. The deploy role's credentials were used from outside AWS to read an S3 secrets file and a production database secret, and the account was compromised on the GitHub side. Which response matches the evidence?",
      hint: "Think about everything the leaked role could reach, and every foothold the attacker left behind — not just the one secret you can see being read.",
      options: [
        { value: "rotate_revoke_all", label: "Rotate every secret the deploy workflow could read, revoke the role's active sessions, restore branch protection, and remove the attacker's PAT and self-hosted runner — treating all resources the role can reach as exposed" },
        { value: "revert_commit", label: "Delete the malicious commit and revert the workflow file to its previous state; once the pipeline definition is clean again, the temporary credentials it already leaked can no longer be replayed against the AWS account" },
        { value: "block_ip_only", label: "Block the attacker's external IP address at the network perimeter, since the leaked credentials only function from that single source address and blocking it therefore fully contains the incident on its own" },
        { value: "rotate_one_secret", label: "Rotate only the single secret returned by the GetSecretValue call, because temporary role credentials expire automatically and the other secrets in the account were never actually displayed on screen" },
      ],
      answer: "rotate_revoke_all",
      explanation:
        "The leaked credential is a role, not a single secret, so the exposure is everything that role can reach — the whole S3 bucket and every secret its policy allows, not just the .env file and the one database secret you watched being read. Containment therefore rotates all reachable secrets, revokes the role's live sessions so the stolen short-lived credentials die immediately, restores branch protection, and removes the persistence the attacker planted (the fine-grained PAT in cicd_01 and the self-hosted runner in cicd_02) — a password reset alone leaves the PAT working. (b) ignores that the credentials are already out and the persistence remains. (c) treats an internal-facing perimeter block as a fix for stolen cloud credentials. (d) under-scopes to one secret and wrongly assumes the rest are safe.",
    },
    {
      id: "cicd_q5",
      xp: 55,
      kind: "single",
      prompt:
        "The response team resets the m.duarte account password. Which earlier event means that step alone will NOT lock the attacker out of the repository?",
      hint: "Look for a credential the attacker created that lives independently of the account password.",
      options: [
        { value: "pat_persist", label: "cicd_01 — the fine-grained personal access token the account created; a PAT authenticates independently of the password, so it keeps repository access until it is explicitly revoked" },
        { value: "run_history", label: "cicd_05 — the completed workflow run; until the run is deleted from the Actions history the attacker retains an authenticated session to the repository through it" },
        { value: "benign_pr", label: "cicd_00 — the reviewed pull request from the previous day, which is the foothold the attacker has been using to authenticate to the repository all along" },
        { value: "s3_list", label: "cicd_07 — the S3 ListObjectsV2 call, because the bucket listing permission it used also grants a standing login to the GitHub repository" },
      ],
      answer: "pat_persist",
      explanation:
        "A personal access token is a bearer credential that authenticates on its own, decoupled from the account password — that is the point of cicd_01, created early precisely so a password reset does not evict the attacker. It must be explicitly revoked (along with the self-hosted runner and webhook) to close the door. (b) misreads a workflow run as a session — deleting run history changes nothing about access. (c) is the benign control on a different repo action and grants no standing access. (d) is an AWS S3 action with no bearing on GitHub authentication.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Poisoned Pipeline — CI/CD Supply-Chain Compromise into the Cloud",
    threat_actor: "Intrusion operator abusing a compromised repository maintainer account",
    attack_kind: "supply_chain",
    briefing:
      "GuardDuty raised a high-severity finding: the temporary credentials of the payments-api deployment role were seen making API calls from an IP address outside AWS. That role is only ever meant to run inside the project's GitHub Actions pipeline. Determine how the pipeline's cloud credentials were obtained, what changed in the repository, and which cloud resources the credentials reached.",
    narrative: `The github-actions-deploy role for rocketstack/payments-api exists so the CI pipeline can ship the service: a GitHub Actions job presents an OIDC token, AWS trades it for short-lived role credentials, and the job deploys. Nothing about that is unusual — which is exactly what the attacker relied on.

They already held the m.duarte maintainer account (phished the day before). Rather than act through it directly and risk a reset locking them out, at 09:00 they minted a fine-grained personal access token scoped to contents and workflows — a credential that survives a password change. Two minutes later they registered a self-hosted Actions runner they controlled, labelled self-hosted,linux,deploy so a deploy job would land on their machine, where that job's secrets and OIDC token are readable.

At 09:05 they pushed a one-line change to .github/workflows/ci.yml straight to main, using a branch-protection override — no pull request, no review. That is the whole supply-chain compromise: a trusted pipeline definition altered by an untrusted hand. They also added a repository webhook posting events to telemetry-sync.deploystatus.io, an out-of-band channel to a host they owned. When the modified 'CI' workflow ran (run #5127) it executed on their runner, and the pipeline's OIDC token was exchanged for the github-actions-deploy role through AssumeRoleWithWebIdentity — the legitimate mechanism, now firing on attacker-controlled infrastructure.

From 09:15 the role's temporary credentials, sourced from 45.156.128.19, listed the rocketstack-deploy-artifacts bucket, read backups/prod/.env.production out of it, and pulled the prod/payments/db secret from Secrets Manager. Every call came from outside AWS, and at 09:22 GuardDuty raised InstanceCredentialExfiltration.OutsideAWS — a deploy role that only ever runs inside the pipeline, seen operating from a remote host.

The one legitimate comparison in the data is d.pereira's edit to the very same workflow file the previous afternoon: pull request #806, reviewed and approved, branch protection satisfied, merged from a corporate IP. Same file, same 'workflow changed' shape, opposite meaning — the difference is entirely in how the change reached main and who was behind it.`,
    learning_objectives: [
      "Read a GitHub audit trail to separate a sanctioned workflow change (reviewed pull request, branch protection satisfied) from a malicious one (branch-protection override, no review) that touches the same file",
      "Recognise the CI/CD supply-chain compromise pattern: a compromised maintainer account, a persistence token, an attacker-controlled self-hosted runner, and a modified workflow definition",
      "Trace how a GitHub Actions pipeline obtains AWS credentials through OIDC (AssumeRoleWithWebIdentity) and why running a job on an untrusted runner exposes the resulting role session",
      "Use CloudTrail userIdentity and sourceIPAddress to prove that a deploy role's credentials were used from outside the pipeline, and connect it to the GuardDuty OutsideAWS finding",
      "Scope containment for leaked cloud role credentials — rotate everything the role can reach and revoke its sessions and the attacker's GitHub persistence, rather than fixing only the one secret observed being read",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T14:22:10.000Z", phase: "Baseline", action: `Developer ${dev.actor} edits .github/workflows/ci.yml the sanctioned way — reviewed PR #806, branch protection satisfied (control case)` },
      { ts: T(0), phase: "Persistence", action: `${attacker.actor} account mints a fine-grained PAT (contents+workflows) from ${attackerIp} — access that survives a password reset (T1098)` },
      { ts: T(2 * MIN), phase: "Persistence", action: `Attacker registers a self-hosted runner ${runnerName} labelled to match the deploy job (T1078)` },
      { ts: T(5 * MIN), phase: "Initial Access", action: "protected_branch.policy_override — .github/workflows/ci.yml modified on main with no review (T1195.002)" },
      { ts: T(6 * MIN), phase: "Exfiltration", action: `hook.create — repository webhook to ${exfilUrl}, an external channel (T1567)` },
      { ts: T(8 * MIN), phase: "Credential Access", action: "workflows.completed_workflow_run #5127 runs on the attacker's runner where secrets and the OIDC token are readable (T1552.001)" },
      { ts: T(8 * MIN + 20 * SEC), phase: "Defense Evasion", action: "AssumeRoleWithWebIdentity — OIDC token exchanged for github-actions-deploy on attacker infrastructure (T1078.004)" },
      { ts: T(15 * MIN), phase: "Collection", action: `ListObjectsV2 on ${artifactBucket} from ${attackerIp} (T1530)` },
      { ts: T(16 * MIN), phase: "Credential Access", action: "GetObject backups/prod/.env.production — a secrets file read from the bucket (T1552.004)" },
      { ts: T(18 * MIN), phase: "Credential Access", action: "GetSecretValue prod/payments/db from Secrets Manager (T1552.001)" },
      { ts: T(22 * MIN), phase: "Detection", action: "GuardDuty InstanceCredentialExfiltration.OutsideAWS — deploy role used from outside AWS (T1078.004)" },
    ],
    questions,
  };
}
