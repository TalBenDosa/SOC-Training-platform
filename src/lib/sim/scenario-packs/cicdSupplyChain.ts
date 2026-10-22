/**
 * Scenario pack: "Software Supply-Chain Compromise through CI/CD, from a
 * Workflow Edit to the Cloud Blast Radius" (ADVANCED)
 *
 * A supply-chain intrusion that never touches an endpoint. The attacker holds a
 * compromised maintainer account (m.duarte) on the rocketstack/payments-api
 * GitHub repository. From there the whole chain plays out in two control planes
 * and two log sources only: the GitHub audit log and AWS CloudTrail.
 *
 * ORIGIN (GitHub side):
 *   0. The day before, the maintainer's Okta session is taken over: a sign-in and an
 *      approved Okta Verify push from the attacker's hosting address (the identity
 *      plane evidence), then a GitHub login from the same address the next morning.
 *   1. Using the compromised account they mint a fine-grained personal access
 *      token, a credential that survives a password reset (Persistence).
 *   2. They register a self-hosted Actions runner they control, labelled to
 *      match the deploy job, so a workflow job will land on THEIR machine.
 *   3. They push a one-line change to `.github/workflows/ci.yml` straight to
 *      `main`, using a branch-protection override, no pull request, no review.
 *      This is the software-supply-chain compromise (T1195.002).
 *   4. The next run of the modified workflow executes on the attacker's runner,
 *      where the job's repo secrets and the short-lived GitHub OIDC token are
 *      readable. A repository webhook to an external host is added as a channel.
 *
 * BLAST RADIUS (AWS side):
 *   5. The pipeline's OIDC token is exchanged for the github-actions-deploy role
 *      via AssumeRoleWithWebIdentity, the legitimate mechanism, but the exchange
 *      now happens on an attacker-controlled runner (T1078.004).
 *   6. Those role credentials list an S3 bucket, read a secrets file out of it,
 *      and pull a production database secret from Secrets Manager, every call
 *      sourced from the attacker's IP, i.e. from OUTSIDE AWS.
 *   7. GuardDuty raises CredentialAccess:IAMUser/AnomalousBehavior: the deploy
 *      role's session making a credential-access API call (GetSecretValue) from a
 *      remote IP is the detection that opens the ticket.
 *
 * BENIGN CONTROL (cicd_00): the day before, a real developer (d.pereira) edits
 * the SAME workflow file, but through an approved, reviewed pull request that
 * satisfies branch protection, merged from an ordinary IP. Same "workflow file
 * changed" shape, opposite verdict. The lesson is that the event is not "a
 * workflow file was edited" but HOW it reached main and WHO the actor was.
 *
 * SOURCES (registry keys): github-audit-log (vendor "GitHub Audit Log") rides
 * the platform's `source: "vcs"` LogSource; aws-cloudtrail (vendors "AWS
 * CloudTrail" and "AWS GuardDuty") rides `source: "cloudtrail"`; okta (the
 * maintainer's identity-provider sign-ins) rides `source: "okta"`.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { githubAudit } from "@/lib/sim/emitters/github";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { oktaSignIn, oktaMfa } from "@/lib/sim/emitters/okta";

export function buildCicdSupplyChainScenario(
  scenarioId = "cicd-supply-chain-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the whole chain is a single supply-chain case.
  const INCIDENT = "inc:cicd:1";

  // The repository and the org that owns the pipeline.
  const org = "rocketstack";
  const repo = "rocketstack/payments-api";

  // The compromised maintainer account driving every attacker action.
  const attacker = { actor: "m.duarte", email: "m.duarte@rocketstack.io" };
  // The attacker's external address, the self-hosted runner they control and
  // the source of every off-pipeline AWS call.
  const attackerIp = "45.156.128.19";
  // The runner they register so a deploy job lands on their machine.
  const runnerName = "rs-deploy-runner-x";
  // The webhook endpoint added as an out-of-band channel to an external host.
  const exfilUrl = "https://telemetry-sync.deploystatus.io/collect";
  const exfilDomain = "deploystatus.io";

  // The benign control: a real developer editing the same workflow file the
  // sanctioned way, reviewed PR, branch protection satisfied, ordinary IP.
  const dev = { actor: "d.pereira", email: "d.pereira@rocketstack.io", ip: "94.188.12.44" };

  // AWS blast-radius specifics.
  const awsAccount = "739218004471";
  const region = "us-east-1";
  const deployRoleArn = `arn:aws:iam::${awsAccount}:role/github-actions-deploy`;
  const assumedRoleArn = `arn:aws:sts::${awsAccount}:assumed-role/github-actions-deploy/github-actions-payments-deploy`;
  const artifactBucket = "rocketstack-deploy-artifacts";
  const secretId = `arn:aws:secretsmanager:${region}:${awsAccount}:secret:prod/payments/db-Ab12Cd`;

  const cx = "rocketstack" as const;

  // The temporary key id of the assumed-role session (appears on every call made with it).
  const sessionKeyId = "ASIAY7RCX2NLPEXAMPLE";
  const oidcProviderArn = `arn:aws:iam::${awsAccount}:oidc-provider/token.actions.githubusercontent.com`;
  // aws-sdk-js v3 is what the configure-aws-credentials action uses; the attacker's own tooling is the CLI.
  const SDK_UA = "aws-sdk-js/3.620.0 ua/2.0 os/linux#6.5.0-1025-azure lang/js md/nodejs#20.15.0 api/sts#3.620.0 m/E";
  const CLI_UA = "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1025-azure exe/x86_64.ubuntu.22 prompt/off";
  const aiTmUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

  const events: TelemetryEvent[] = [
    // Baseline: m.duarte's usual Okta sign-in, from the office egress address.
    {
      ...oktaSignIn({
        companyId: cx, id: "cicd_00a_okta_baseline", ts: "2026-08-30T08:47:05.000Z", user: attacker.email, srcIp: dev.ip,
        mfaUsed: true, userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        os: "Mac OS X", browser: "SAFARI", severity: "informational",
        description: "Okta session started for m.duarte from the office egress address 94.188.12.44 with Okta Verify push.",
      }),
      is_baseline: true,
    },

    // 0. BENIGN CONTROL, the sanctioned reviewed-PR path to the same file (fp).
    {
      ...githubAudit({
        companyId: cx, id: "cicd_00_benign_pr", ts: "2026-08-30T14:22:10.000Z", action: "pull_request.merge",
        actor: dev.actor, actorIp: dev.ip, userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15",
        org, repo, visibility: "private", category: "web", user: dev.email, userTitle: "Platform Engineer", severity: "informational",
        extra: {
          "github.pull_request.number": "806", "github.pull_request.title": "ci: pin actions/checkout to v4.2.2",
          "github.pull_request.base": "main", "github.pull_request.head": "chore/pin-actions", "github.pull_request.merged_by": dev.actor,
          "github.pull_request.review_decision": "approved", "github.pull_request.approving_reviewer": "s.rahman",
          "github.protected_branch.name": "main", "github.protected_branch.required_reviews": "1", "github.protected_branch.checks_passed": "true",
        },
        description: "pull_request.merge on rocketstack/payments-api: PR #806 ('ci: pin actions/checkout to v4.2.2') editing .github/workflows/ci.yml, approved by a reviewer and merged by d.pereira from 94.188.12.44.",
      }),
      expected_verdict: "fp",
      fp_explanation: "This is the control case for the whole scenario, and what every later workflow change should be measured against. The SAME file (.github/workflows/ci.yml) is edited, but it reaches main the sanctioned way: through pull request #806, reviewed and approved by a second engineer (review_decision=approved), with branch protection satisfied (checks_passed=true, required_reviews met), merged by the author from an ordinary corporate IP during business hours. There is a review record, a second human in the loop, and no branch-protection override. An analyst who alerts on 'a workflow file was modified' alone will flag this and be wrong, the event is not the edit, it is HOW the edit reached main.",
    },

    // 0b. THE TAKEOVER (the previous evening): the maintainer's Okta session is used from a
    //     hosting-provider address in the Netherlands, with a push approved from there (T1078).
    oktaMfa({
      companyId: cx, id: "cicd_00b_okta_push_sent", ts: "2026-08-30T19:41:20.000Z", user: attacker.email, srcIp: attackerIp,
      result: "sent", userAgent: aiTmUa, os: "Windows 10", browser: "CHROME", asn: 9009, asOrg: "M247 Europe SRL", severity: "medium",
      description: "Okta sent an Okta Verify push to m.duarte for a sign-in attempt from 45.156.128.19.",
    }),
    oktaMfa({
      companyId: cx, id: "cicd_00c_okta_push_approved", ts: "2026-08-30T19:41:33.000Z", user: attacker.email, srcIp: attackerIp,
      result: "approved", userAgent: aiTmUa, os: "Windows 10", browser: "CHROME", asn: 9009, asOrg: "M247 Europe SRL", severity: "medium",
      description: "m.duarte approved the Okta Verify push; the sign-in came from 45.156.128.19 (AS9009, M247 Europe SRL).",
    }),
    oktaSignIn({
      companyId: cx, id: "cicd_00d_okta_signin", ts: "2026-08-30T19:41:34.000Z", user: attacker.email, srcIp: attackerIp,
      mfaUsed: true, userAgent: aiTmUa, os: "Windows 10", browser: "CHROME", asn: 9009, asOrg: "M247 Europe SRL", severity: "medium",
      description: "Okta session started for m.duarte from 45.156.128.19 with Okta Verify push; first sign-in from this address.",
    }),

    // 0e. The GitHub session itself: a web login for m.duarte from the same address, two minutes before the PAT.
    githubAudit({
      companyId: cx, id: "cicd_00e_github_login", ts: T(-2 * MIN), action: "user.login", actor: attacker.actor, actorIp: attackerIp,
      userAgent: aiTmUa, org, category: "authentication", user: attacker.email, geoCountryCode: "NL", geoCity: "Amsterdam", severity: "medium",
      extra: { "github.programmatic_access_type": "OAuth access token" },
      description: "user.login for m.duarte from 45.156.128.19 (Amsterdam), the first GitHub login for this account from outside the office address.",
    }),

    // 1. PERSISTENCE, the compromised account mints a fine-grained PAT (T1098).
    githubAudit({
      companyId: cx, id: "cicd_01_pat_create", ts: T(0), action: "personal_access_token.create", actor: attacker.actor, actorIp: attackerIp,
      userAgent: "python-requests/2.31.0", org, repo, category: "authentication", user: attacker.email, geoCountryCode: "NL", geoCity: "Amsterdam",
      mitre: "T1098", tactic: "Persistence", severity: "high",
      extra: { "github.programmatic_access_type": "Fine-grained personal access token", "github.token.name": "ci-cache-helper", "github.token.permissions": "contents:write,workflows:write", "github.token.expires_at": "2027-08-31T00:00:00.000Z" },
      description: "personal_access_token.create for m.duarte on rocketstack/payments-api from 45.156.128.19, a fine-grained PAT scoped to contents and workflows, created outside the account's usual location.",
    }),

    // 2. THE MALICIOUS RUNNER, a self-hosted Actions runner labelled for the deploy job (T1078).
    githubAudit({
      companyId: cx, id: "cicd_02_runner_register", ts: T(2 * MIN), action: "self_hosted_runner.register", actor: attacker.actor, actorIp: attackerIp,
      org, repo, category: "configuration", user: attacker.email, mitre: "T1078", tactic: "Persistence", severity: "high",
      extra: { "github.runner.name": runnerName, "github.runner.id": "77", "github.runner.labels": "self-hosted,linux,deploy", "github.runner.os": "Linux", "github.runner.group": "Default" },
      description: "self_hosted_runner.register on rocketstack/payments-api: a new runner 'rs-deploy-runner-x' with labels self-hosted,linux,deploy was added by m.duarte from 45.156.128.19.",
    }),

    // 3. THE SUPPLY-CHAIN COMPROMISE, workflow file changed on main via a branch-protection override (T1195.002).
    githubAudit({
      companyId: cx, id: "cicd_03_workflow_override", ts: T(5 * MIN), action: "protected_branch.policy_override", actor: attacker.actor, actorIp: attackerIp,
      userAgent: "git/2.44.0", org, repo, category: "configuration", user: attacker.email, incidentId: INCIDENT,
      mitre: "T1195.002", tactic: "Initial Access", severity: "critical",
      extra: { "github.ref": "refs/heads/main", "github.protected_branch.name": "main", "github.before": "b7950aa3f95fb50bb308d71821fbc3f7c3e88302", "github.after": "9c4d71e0a2f3b8c6d5e40917a2b3c4d5e6f70819", "github.head_commit.message": "ci: cache node_modules", "github.head_commit.modified": ".github/workflows/ci.yml", "github.programmatic_access_type": "Fine-grained personal access token" },
      description: "protected_branch.policy_override on rocketstack/payments-api: a push to refs/heads/main modified .github/workflows/ci.yml, bypassing the required review, commit message 'ci: cache node_modules', actor m.duarte from 45.156.128.19.",
    }),

    // 4. THE OUT-OF-BAND CHANNEL, a repository webhook to an external host (T1567).
    githubAudit({
      companyId: cx, id: "cicd_04_webhook_create", ts: T(6 * MIN), action: "hook.create", actor: attacker.actor, actorIp: attackerIp,
      org, repo, category: "configuration", user: attacker.email, incidentId: INCIDENT, mitre: "T1102", tactic: "Command and Control", severity: "high",
      extra: { "github.hook.id": "552348771", "github.hook.config.url": exfilUrl, "github.hook.config.content_type": "json", "github.hook.config.insecure_ssl": "0", "github.hook.events": "push,workflow_run", "github.hook.active": "true" },
      description: "hook.create on rocketstack/payments-api: a repository webhook posting push and workflow_run events as JSON to https://telemetry-sync.deploystatus.io/collect was added by m.duarte.",
    }),

    // 4b. THE JOB LANDS ON THE ATTACKER'S RUNNER: the deploy job of run #5127 is prepared on rs-deploy-runner-x.
    githubAudit({
      companyId: cx, id: "cicd_04b_job_prepared", ts: T(7 * MIN + 40 * SEC), action: "workflows.prepared_workflow_job", actor: attacker.actor,
      org, repo, category: "web", user: attacker.email, incidentId: INCIDENT, severity: "high",
      extra: { "github.workflow_run.name": "CI", "github.workflow_run.run_number": "5127", "github.workflow_run.head_branch": "main", "github.workflow_run.head_sha": "9c4d71e0a2f3b8c6d5e40917a2b3c4d5e6f70819", "github.job_name": "deploy", "github.job_workflow_ref": "rocketstack/payments-api/.github/workflows/ci.yml@refs/heads/main", "github.runner.labels": "self-hosted,linux,deploy", "github.runner.name": runnerName, "github.runner.id": "77" },
      description: "workflows.prepared_workflow_job on rocketstack/payments-api: job 'deploy' of run #5127 (head 9c4d71e0) prepared on the self-hosted runner rs-deploy-runner-x with labels self-hosted,linux,deploy.",
    }),

    // 5. THE RUN, the modified workflow completes on the attacker's runner (T1552.001).
    githubAudit({
      companyId: cx, id: "cicd_05_workflow_run", ts: T(8 * MIN), action: "workflows.completed_workflow_run", actor: attacker.actor,
      org, repo, category: "web", user: attacker.email, incidentId: INCIDENT, mitre: "T1552.001", tactic: "Credential Access", severity: "high",
      extra: { "github.workflow_run.name": "CI", "github.workflow_run.head_branch": "main", "github.workflow_run.head_sha": "9c4d71e0a2f3b8c6d5e40917a2b3c4d5e6f70819", "github.workflow_run.event": "push", "github.workflow_run.run_number": "5127", "github.workflow_run.run_attempt": "1", "github.workflow_run.conclusion": "success", "github.workflow_run.actor": attacker.actor, "github.workflow_run.runner_group_name": "Default", "github.workflow_run.runner_name": runnerName },
      description: "workflows.completed_workflow_run on rocketstack/payments-api: run #5127 of the 'CI' workflow, triggered by the push to main, executed on the self-hosted runner rs-deploy-runner-x and concluded success.",
    }),

    // 6. THE BLAST RADIUS BEGINS, AssumeRoleWithWebIdentity on the attacker's runner (T1078.004).
    cloudTrailEvent({
      companyId: cx, id: "cicd_06_assume_role_oidc", ts: T(8 * MIN + 20 * SEC), eventName: "AssumeRoleWithWebIdentity", srcIp: attackerIp, region, accountId: awsAccount,
      eventSource: "sts.amazonaws.com", actorType: "WebIdentityUser", actorName: "repo:rocketstack/payments-api:ref:refs/heads/main", userAgent: SDK_UA, readOnly: false, user: attacker.email,
      mitre: "T1078.004", tactic: "Stealth", severity: "high", incidentId: INCIDENT,
      extra: { "aws.cloudtrail.userIdentity.identityProvider": oidcProviderArn, "aws.cloudtrail.requestParameters.roleArn": deployRoleArn, "aws.cloudtrail.requestParameters.roleSessionName": "github-actions-payments-deploy", "aws.cloudtrail.requestParameters.durationSeconds": 3600, "aws.cloudtrail.responseElements.assumedRoleUser.arn": assumedRoleArn, "aws.cloudtrail.responseElements.credentials.accessKeyId": sessionKeyId, "aws.cloudtrail.responseElements.credentials.expiration": "Aug 31, 2026, 10:08:20 AM", "aws.cloudtrail.requestID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" },
      description: "AssumeRoleWithWebIdentity (sts.amazonaws.com): the GitHub OIDC subject repo:rocketstack/payments-api:ref:refs/heads/main exchanged its token for github-actions-deploy, sourced from 45.156.128.19.",
    }),

    // 6b. The first thing an operator does with a new session: who am I (T1087.004).
    {
      ...cloudTrailEvent({
        companyId: cx, id: "cicd_06b_get_caller_identity", ts: T(9 * MIN), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: attackerIp, region, accountId: awsAccount,
        actorType: "AssumedRole", arn: assumedRoleArn, accessKeyId: sessionKeyId, sessionIssuerName: "github-actions-deploy", readOnly: true, userAgent: CLI_UA, user: attacker.email,
        mitre: "T1087.004", tactic: "Discovery", severity: "medium", incidentId: INCIDENT,
        description: "GetCallerIdentity (sts.amazonaws.com) by the github-actions-deploy assumed-role session, from 45.156.128.19.",
      }),
      hostname: "github-actions-deploy",
    },

    // 7. S3 enumeration, the deploy role lists a bucket (T1530).
    cloudTrailEvent({
      companyId: cx, id: "cicd_07_s3_list", ts: T(15 * MIN), eventName: "ListObjectsV2", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "AssumedRole", arn: assumedRoleArn, accessKeyId: sessionKeyId, sessionIssuerName: "github-actions-deploy", s3Bucket: artifactBucket, readOnly: true, userAgent: CLI_UA, user: attacker.email,
      mitre: "T1530", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "ListObjectsV2 on the rocketstack-deploy-artifacts bucket by the github-actions-deploy assumed-role session, from 45.156.128.19.",
    }),

    // 8. S3 object read, a secrets file is pulled out of the bucket (T1552.004).
    cloudTrailEvent({
      companyId: cx, id: "cicd_08_s3_getobject", ts: T(16 * MIN), eventName: "GetObject", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "AssumedRole", arn: assumedRoleArn, accessKeyId: sessionKeyId, sessionIssuerName: "github-actions-deploy", s3Bucket: artifactBucket, s3Key: "backups/prod/.env.production", bytes: 48_213,
      readOnly: true, userAgent: CLI_UA, user: attacker.email, mitre: "T1552.004", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "GetObject on rocketstack-deploy-artifacts/backups/prod/.env.production by the github-actions-deploy assumed-role session, from 45.156.128.19, 48 KB returned.",
    }),

    // 8b. Secrets Manager inventory before the read (T1555.006).
    {
      ...cloudTrailEvent({
        companyId: cx, id: "cicd_08b_list_secrets", ts: T(17 * MIN), eventName: "ListSecrets", srcIp: attackerIp, region, accountId: awsAccount,
        actorType: "AssumedRole", arn: assumedRoleArn, accessKeyId: sessionKeyId, sessionIssuerName: "github-actions-deploy", readOnly: true, userAgent: CLI_UA, user: attacker.email,
        mitre: "T1555.006", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
        description: "ListSecrets (secretsmanager.amazonaws.com) by the github-actions-deploy assumed-role session, from 45.156.128.19.",
      }),
      hostname: "github-actions-deploy",
    },

    // 9. Secrets Manager, a production database secret is read (T1552.001).
    cloudTrailEvent({
      companyId: cx, id: "cicd_09_get_secret_value", ts: T(18 * MIN), eventName: "GetSecretValue", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "AssumedRole", arn: assumedRoleArn, accessKeyId: sessionKeyId, sessionIssuerName: "github-actions-deploy", readOnly: true, userAgent: CLI_UA, user: attacker.email,
      mitre: "T1552.001", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      extra: { "aws.cloudtrail.requestParameters.secretId": secretId },
      description: "GetSecretValue (secretsmanager.amazonaws.com) on prod/payments/db by the github-actions-deploy assumed-role session, from 45.156.128.19.",
    }),

    // 10. THE DETECTION, GuardDuty flags the deploy role's temp creds used outside AWS (T1078.004).
    {
      ...guardDutyFinding({
        companyId: cx, id: "cicd_10_guardduty_finding", ts: T(22 * MIN), findingType: "CredentialAccess:IAMUser/AnomalousBehavior", gdSeverity: 8,
        title: "An API used to gain access to an AWS environment was invoked in an anomalous way.", srcIp: attackerIp, region, accountId: awsAccount,
        api: "GetSecretValue", serviceName: "secretsmanager.amazonaws.com", callerType: "Remote IP", asnOrg: "M247 Europe SRL",
        resourceType: "AccessKey", userType: "AssumedRole", userName: "github-actions-deploy", accessKeyId: sessionKeyId, count: 3,
        mitre: "T1552.001", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
        description: "GuardDuty raised CredentialAccess:IAMUser/AnomalousBehavior (severity 8): the github-actions-deploy session called GetSecretValue from 45.156.128.19, a remote IP outside its usual pattern.",
      }),
      hostname: "github-actions-deploy",
      edr_scope: "non_edr",
    },
  ];

  // Every event except the benign control belongs to the one incident.
  for (const e of events) {
    if (e.id !== "cicd_00_benign_pr") e.incident_id = INCIDENT;
  }

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.156.128.19, the attacker's runner + every off-pipeline AWS call
      first_seen: new Date(Date.parse("2026-08-30T19:41:20.000Z")).toISOString(),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["external", "caller-address"],
    },
    {
      type: "user",
      value: attacker.actor, // m.duarte, the compromised maintainer account
      first_seen: T(0),
      last_seen: T(8 * MIN),
      reputation: "suspicious",
      tags: ["maintainer"],
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
      value: exfilDomain, // deploystatus.io, attacker-controlled infrastructure
      first_seen: T(6 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["attacker-infrastructure"],
    },
    {
      type: "host",
      value: runnerName, // rs-deploy-runner-x, the self-hosted runner the deploy job ran on
      first_seen: T(2 * MIN),
      last_seen: T(8 * MIN),
      reputation: "malicious",
      tags: ["github-runner"],
    },
    {
      type: "user",
      value: sessionKeyId, // the temporary access key id of the assumed-role session
      first_seen: T(8 * MIN + 20 * SEC),
      last_seen: T(22 * MIN),
      reputation: "suspicious",
      tags: ["aws-access-key-id", "temporary-credentials"],
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
        { value: "override_noreview", label: "The ci.yml push reached main through a branch-protection override with no PR or review, from an external IP; the control went through an approved PR" },
        { value: "yaml_edit", label: "The push edits a YAML file under .github/workflows, and a change that alters a workflow definition is the malicious act regardless of who made it" },
        { value: "same_shape", label: "Both are ordinary maintainer activity carrying the same action on the same file, so the audit log cannot separate them, only the diff content itself can" },
        { value: "benign_is_bad", label: "The PR merge is the malicious one, because merging a pull request to main bypasses branch protection while a direct push to main keeps it enforced" },
      ],
      answer: "override_noreview",
      explanation:
        "The event is not 'a workflow file was edited', it is HOW the edit reached main and WHO made it. cicd_00 is the sanctioned path: pull request #806, a second engineer's approval (review_decision=approved), branch protection satisfied, merged from an ordinary corporate IP. cicd_03 is a protected_branch.policy_override, a push straight to refs/heads/main that bypassed the required review, by the m.duarte account from 45.156.128.19. The override and the absent review, not the file type, are the tell. (b) over-reads: workflow edits are routine and cicd_00 proves it. (c) ignores the override field that distinguishes them. (d) is backwards, a reviewed PR is the safe path; the direct override is the dangerous one.",
    },
    {
      id: "cicd_q2",
      xp: 60,
      kind: "single",
      prompt:
        "The S3 and Secrets Manager calls (cicd_07 to cicd_09) were made by an assumed-role session, not by a named IAM user. Where did those AWS credentials come from?",
      hint: "Look for the sts.amazonaws.com event and read its userIdentity, what kind of identity assumed the role, and through which provider.",
      options: [
        { value: "oidc_assume", label: "The pipeline's GitHub OIDC token was exchanged for github-actions-deploy via AssumeRoleWithWebIdentity, on a run that executed on the new self-hosted runner" },
        { value: "hardcoded_keys", label: "Long-lived IAM user access keys that were hard-coded in the repository and exposed in the ci.yml file that the direct push to main modified" },
        { value: "console_spray", label: "A password-spraying campaign against the AWS Management Console sign-in page for the deploy team, which produced the assumed-role session used later" },
        { value: "guardduty_issued", label: "GuardDuty issued the temporary credentials to the remote host while generating its InstanceCredentialExfiltration.OutsideAWS finding for the role" },
      ],
      answer: "oidc_assume",
      explanation:
        "cicd_06 is an AssumeRoleWithWebIdentity call whose userIdentity.type is WebIdentityUser and whose identityProvider is the account's GitHub OIDC provider (arn:aws:iam::739218004471:oidc-provider/token.actions.githubusercontent.com), with the subject repo:rocketstack/payments-api:ref:refs/heads/main; its response carries the temporary access key ASIAY7RCX2NLPEXAMPLE that every later call uses. That is the standard, legitimate way a GitHub Actions pipeline gets short-lived AWS credentials, a token exchange, no stored keys. What made it dangerous is that the run was prepared and executed on the attacker's own runner (cicd_02, cicd_04b, cicd_05), so the role's temporary credentials were in the attacker's hands. (b) is refuted by the absence of any IAM user identity on the calls, they are all AssumedRole. (c) has no supporting sign-in events. (d) inverts cause and effect: GuardDuty reports on credential use, it does not mint credentials.",
    },
    {
      id: "cicd_q3",
      xp: 65,
      kind: "single",
      prompt:
        "The github-actions-deploy role runs constantly as part of normal deployments, so its activity is expected. Which single observation shows this particular use of the role was NOT the pipeline doing its job?",
      hint: "Compare where the API calls came from against where a GitHub Actions job would normally originate.",
      options: [
        { value: "outside_aws_ip", label: "The token exchange, S3 and Secrets Manager calls all come from 45.156.128.19, an external address rather than a GitHub Actions runner range" },
        { value: "assume_failed", label: "The AssumeRoleWithWebIdentity call failed with an access-denied error, proving the deploy role could not actually be assumed during this window" },
        { value: "wrong_region", label: "The S3 and Secrets Manager calls ran in a different AWS region from the account default, which is the strongest indicator of role misuse" },
        { value: "secret_404", label: "The GetSecretValue call returned a 404 not-found response, showing the requested secret did not exist, so no sensitive value was read" },
      ],
      answer: "outside_aws_ip",
      explanation:
        "A GitHub-hosted (or a trusted self-hosted) runner has a predictable source range; here every call, the token exchange in cicd_06 and the S3/Secrets Manager reads in cicd_07 to cicd_09, carries sourceIPAddress 45.156.128.19, an external address. A credential-access API call (GetSecretValue) made with the role's session from a remote IP is what GuardDuty's CredentialAccess:IAMUser/AnomalousBehavior finding (cicd_10) reports, and the address is the blast-radius tell. (b) is false, the AssumeRole succeeded and returned an assumed-role ARN. (c) invents a region mismatch that is not in the data (all calls are us-east-1) and overstates region as a sole indicator. (d) is false, the reads succeeded; nothing shows a 404.",
    },
    {
      id: "cicd_q4",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. The deploy role's credentials were used from outside AWS to read an S3 secrets file and a production database secret, and the account was compromised on the GitHub side. Which response matches the evidence?",
      hint: "Think about everything the leaked role could reach, and every foothold the attacker left behind, not just the one secret you can see being read.",
      options: [
        { value: "rotate_revoke_all", label: "Rotate every secret the deploy role could read, revoke its active sessions, restore branch protection, and remove the attacker's PAT and self-hosted runner, all reachable resources are exposed" },
        { value: "revert_commit", label: "Delete the malicious commit and revert the workflow file to its previous state; once the pipeline definition is clean again, the temporary credentials it already leaked can no longer be replayed against the AWS account" },
        { value: "block_ip_only", label: "Block the attacker's external IP address at the network perimeter, since the leaked credentials only function from that single source address and blocking it therefore fully contains the incident on its own" },
        { value: "rotate_one_secret", label: "Rotate only the single secret returned by the GetSecretValue call, because temporary role credentials expire automatically and the other secrets in the account were never actually displayed on screen" },
      ],
      answer: "rotate_revoke_all",
      explanation:
        "The leaked credential is a role, not a single secret, so the exposure is everything that role can reach, the whole S3 bucket and every secret its policy allows, not just the .env file and the one database secret you watched being read. Containment therefore rotates all reachable secrets, revokes the role's live sessions so the stolen short-lived credentials die immediately, restores branch protection, and removes the persistence the attacker planted (the fine-grained PAT in cicd_01 and the self-hosted runner in cicd_02), a password reset alone leaves the PAT working. (b) ignores that the credentials are already out and the persistence remains. (c) treats an internal-facing perimeter block as a fix for stolen cloud credentials. (d) under-scopes to one secret and wrongly assumes the rest are safe.",
    },
    {
      id: "cicd_q5",
      xp: 55,
      kind: "single",
      prompt:
        "The response team resets the m.duarte account password. Which earlier event means that step alone will NOT lock the attacker out of the repository?",
      hint: "Look for a credential the attacker created that lives independently of the account password.",
      options: [
        { value: "pat_persist", label: "The fine-grained personal access token the account created, a PAT authenticates independently of the password and keeps working until revoked" },
        { value: "run_history", label: "The completed workflow run on the self-hosted runner, until the run is deleted from Actions history it holds an authenticated session to the repo" },
        { value: "benign_pr", label: "The reviewed pull request from the previous day, whose merge left the attacker a reviewer token they have used to authenticate ever since" },
        { value: "s3_list", label: "The S3 ListObjectsV2 call, since the bucket-listing permission the role used also carries a standing login to the linked GitHub repository" },
      ],
      answer: "pat_persist",
      explanation:
        "A personal access token is a bearer credential that authenticates on its own, decoupled from the account password, that is the point of cicd_01, created early precisely so a password reset does not evict the attacker. It must be explicitly revoked (along with the self-hosted runner and webhook) to close the door. (b) misreads a workflow run as a session, deleting run history changes nothing about access. (c) is the benign control on a different repo action and grants no standing access. (d) is an AWS S3 action with no bearing on GitHub authentication.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "GuardDuty finding on the payments-api deployment role",
    threat_actor: "Intrusion operator abusing a compromised repository maintainer account",
    attack_kind: "supply_chain",
    briefing:
      "GuardDuty raised a High finding on the github-actions-deploy role used by the payments-api pipeline. Determine how the pipeline's cloud credentials were obtained, what changed in the repository, and which cloud resources the credentials reached.",
    narrative: `The github-actions-deploy role for rocketstack/payments-api exists so the CI pipeline can ship the service: a GitHub Actions job presents an OIDC token, AWS trades it for short-lived role credentials, and the job deploys. Nothing about that is unusual, which is exactly what the attacker relied on.

They already held the m.duarte maintainer account: the evening before, at 19:41, Okta logged a sign-in for m.duarte with an approved Okta Verify push from 45.156.128.19, a Netherlands hosting address that account had never used, instead of the office egress it normally signs in from. At 08:58 the same address logged in to GitHub. Rather than act through the account directly and risk a reset locking them out, at 09:00 they minted a fine-grained personal access token scoped to contents and workflows, a credential that survives a password change. Two minutes later they registered a self-hosted Actions runner they controlled, labelled self-hosted,linux,deploy so a deploy job would land on their machine, where that job's secrets and OIDC token are readable.

At 09:05 they pushed a one-line change to .github/workflows/ci.yml straight to main, using a branch-protection override, no pull request, no review. That is the whole supply-chain compromise: a trusted pipeline definition altered by an untrusted hand. They also added a repository webhook posting events to telemetry-sync.deploystatus.io, an out-of-band channel to a host they owned. When the modified 'CI' workflow ran (run #5127) the deploy job was prepared on their runner rs-deploy-runner-x and executed there, and the pipeline's OIDC token was exchanged for the github-actions-deploy role through AssumeRoleWithWebIdentity, the legitimate mechanism, now firing on attacker-controlled infrastructure.

From 09:09 the role's temporary credentials (access key ASIAY7RCX2NLPEXAMPLE), used with the AWS CLI from 45.156.128.19, checked their identity, listed the rocketstack-deploy-artifacts bucket, read backups/prod/.env.production out of it, listed the account's secrets and pulled prod/payments/db from Secrets Manager. At 09:22 GuardDuty raised CredentialAccess:IAMUser/AnomalousBehavior for the GetSecretValue call made from a remote IP.

The one legitimate comparison in the data is d.pereira's edit to the very same workflow file the previous afternoon: pull request #806, reviewed and approved, branch protection satisfied, merged from a corporate IP. Same file, same 'workflow changed' shape, opposite meaning, the difference is entirely in how the change reached main and who was behind it.`,
    learning_objectives: [
      "Read a GitHub audit trail to separate a sanctioned workflow change (reviewed pull request, branch protection satisfied) from a malicious one (branch-protection override, no review) that touches the same file",
      "Recognise the CI/CD supply-chain compromise pattern: a compromised maintainer account, a persistence token, an attacker-controlled self-hosted runner, and a modified workflow definition",
      "Trace how a GitHub Actions pipeline obtains AWS credentials through OIDC (AssumeRoleWithWebIdentity) and why running a job on an untrusted runner exposes the resulting role session",
      "Use CloudTrail userIdentity, the session access key id and sourceIPAddress to prove that a deploy role's credentials were used from outside the pipeline, and connect it to the GuardDuty anomalous-behaviour finding",
      "Scope containment for leaked cloud role credentials, rotate everything the role can reach and revoke its sessions and the attacker's GitHub persistence, rather than fixing only the one secret observed being read",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T14:22:10.000Z", phase: "Baseline", action: `Developer ${dev.actor} edits .github/workflows/ci.yml the sanctioned way, reviewed PR #806, branch protection satisfied (control case)` },
      { ts: "2026-08-30T19:41:34.000Z", phase: "Initial Access", action: `Okta session for ${attacker.actor} from ${attackerIp} after an approved Okta Verify push: the account is taken over (T1078)` },
      { ts: T(-2 * MIN), phase: "Initial Access", action: `GitHub login for ${attacker.actor} from ${attackerIp} (T1078)` },
      { ts: T(0), phase: "Persistence", action: `${attacker.actor} account mints a fine-grained PAT (contents+workflows) from ${attackerIp}, access that survives a password reset (T1098)` },
      { ts: T(2 * MIN), phase: "Persistence", action: `Attacker registers a self-hosted runner ${runnerName} labelled to match the deploy job (T1078)` },
      { ts: T(5 * MIN), phase: "Initial Access", action: "protected_branch.policy_override, .github/workflows/ci.yml modified on main with no review (T1195.002)" },
      { ts: T(6 * MIN), phase: "Command and Control", action: `hook.create, repository webhook to ${exfilUrl}, an external channel (T1102)` },
      { ts: T(7 * MIN + 40 * SEC), phase: "Execution", action: `Deploy job of run #5127 prepared on ${runnerName}` },
      { ts: T(8 * MIN), phase: "Credential Access", action: "workflows.completed_workflow_run #5127 runs on the attacker's runner where secrets and the OIDC token are readable (T1552.001)" },
      { ts: T(8 * MIN + 20 * SEC), phase: "Stealth", action: "AssumeRoleWithWebIdentity, OIDC token exchanged for github-actions-deploy on attacker infrastructure (T1078.004)" },
      { ts: T(9 * MIN), phase: "Discovery", action: "GetCallerIdentity with the new session from the attacker address (T1087.004)" },
      { ts: T(15 * MIN), phase: "Collection", action: `ListObjectsV2 on ${artifactBucket} from ${attackerIp} (T1530)` },
      { ts: T(16 * MIN), phase: "Credential Access", action: "GetObject backups/prod/.env.production, a secrets file read from the bucket (T1552.004)" },
      { ts: T(17 * MIN), phase: "Credential Access", action: "ListSecrets in Secrets Manager (T1555.006)" },
      { ts: T(18 * MIN), phase: "Credential Access", action: "GetSecretValue prod/payments/db from Secrets Manager (T1552.001)" },
      { ts: T(22 * MIN), phase: "Detection", action: "GuardDuty CredentialAccess:IAMUser/AnomalousBehavior: GetSecretValue by the deploy role session from a remote IP" },
    ],
    questions,
  };
}
