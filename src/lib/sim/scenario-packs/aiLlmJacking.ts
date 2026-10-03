/**
 * Scenario pack: "LLMjacking — Stolen CI Key Used for Bedrock Inference" (ADVANCED)
 *
 * A cloud-abuse case that lives entirely in the AWS control plane and in one
 * content-logging source. A long-term IAM access key (AKIA) belonging to the
 * release pipeline's service user, svc-build-release, was committed to a public
 * repository. From a hosting-provider address the operator uses it to:
 *
 *   1. read the account's Bedrock invocation-logging configuration,
 *   2. probe model access with a deliberately malformed InvokeModel call that
 *      returns ValidationException (the key works, nothing is billed),
 *   3. run the model-enablement calls (use case, agreement, entitlement) that
 *      the AWS console normally runs for a human,
 *   4. send one long role-play prompt that the account's own invocation logging
 *      records (the only place the prompt text exists),
 *   5. DELETE the invocation-logging configuration (GuardDuty
 *      DefenseEvasion:IAMUser/AnomalousBehavior), and
 *   6. burn Opus-class inference across two more regions until GuardDuty raises
 *      Impact:IAMUser/AnomalousBehavior and Cost Anomaly Detection posts the bill;
 *      the security responder then deactivates the key (aiw1_lj_22).
 *
 * TEACHING ARC — same API, different credential class:
 *   The platform team legitimately enabled a NEW model in the same week
 *   (aiw1_lj_03): the SAME PutFoundationModelEntitlement API, in the same
 *   region, on an Anthropic model. What separates it from the abuse is the
 *   credential and its context — ASIA session key on an SSO assumed role, a
 *   browser agent, the corporate egress address and an approved change record,
 *   versus a long-term AKIA key on an IAM user, a scripted Boto3 agent and a
 *   hosting address with no ticket.
 *
 * PRIVILEGE CHAIN: the key can do all of this because aiw1_lj_01 shows the
 * platform admin attaching AmazonBedrockFullAccess to svc-build-release on 11 Aug
 * (over-permissioning for a pipeline model-evaluation stage).
 *
 * LOGGING IS PER REGION: invocation logging was only ever enabled in us-east-1
 * (the pilot region). The prompt in aiw1_lj_12 is therefore the single recorded
 * prompt: after the delete, us-east-1 goes dark, and the other two regions used
 * for the burst never recorded content at all.
 *
 * SOURCES: GitHub Advanced Security (vcs), ServiceNow ITSM (soar), AWS
 * CloudTrail + AWS GuardDuty (cloudtrail), the Bedrock model invocation log
 * (delivered to CloudWatch Logs — vendor "AWS CloudWatch" in the platform
 * vocabulary), and AWS Cost Anomaly Detection.
 *
 * Fields follow the research appendix 02: CloudTrail camelCase (eventName,
 * userIdentity.*, requestParameters.*, tlsDetails.*), Bedrock invocation log
 * (schemaType, requestId, operation, modelId, identity.arn, input.*, output.*),
 * GuardDuty (type, resource.accessKeyDetails.*, modelDetails). CloudTrail has no
 * prompt text; only the invocation log does.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { aiLlmJackingScenarioEvents } from "./aiLlmJacking.events";

export function buildAiLlmJackingScenario(
  scenarioId = "ai-llmjacking-bedrock-2026",
): ScenarioBundle {
  const { title, events, MIN, J, ciUser, akia, changeTicket, ipA, ipB, repo, commitSha, leakPath, tAttach, tPlatform, tRepoAlert, tInvocationLog } = aiLlmJackingScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip", value: ipA, first_seen: J(0, "lj05"), last_seen: J(22 * MIN, "lj16"), reputation: "malicious", tags: ["external", "hosting-asn", "scripted-user-agent"] },
    { type: "ip", value: ipB, first_seen: J(14 * MIN, "lj14"), last_seen: J(95 * MIN, "lj17"), reputation: "malicious", tags: ["external", "hosting-asn", "scripted-user-agent"] },
    { type: "user", value: akia, first_seen: J(0, "lj05"), last_seen: J(95 * MIN, "lj17"), reputation: "malicious", tags: ["access-key-id", "long-term-key"] },
    { type: "user", value: ciUser, first_seen: J(0, "lj05"), last_seen: J(95 * MIN, "lj17"), reputation: "suspicious", tags: ["iam-user", "service-account"] },
    { type: "url", value: `https://github.com/${repo}/blob/${commitSha}/${leakPath}`, first_seen: tRepoAlert, last_seen: tRepoAlert, reputation: "suspicious", tags: ["public-repository", "secret-scanning"] },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "probe_meaning",
      kind: "single",
      xp: 60,
      prompt:
        "The InvokeModel call on anthropic.claude-v2 (aiw1_lj_07) is recorded as a failure with errorCode ValidationException, about three minutes after the same key read the logging configuration. Why is that particular error more useful to the operator than AccessDenied would have been?",
      hint: "Ask which checks a request must pass before the service can complain about its parameters.",
      options: [
        { value: "passed_authz", label: "The request cleared authentication and authorization and failed only on a deliberately invalid parameter, so the key can call the model and nothing was billed" },
        { value: "scp_allowed", label: "The error shows an organisation SCP evaluated the call and allowed it, which tells the operator the account has no regional restrictions and that its quotas are effectively unlimited" },
        { value: "model_absent", label: "The service reported that the model ID does not exist in this account, which tells the operator to subscribe to it in the marketplace before invoking it again" },
        { value: "quota_hit", label: "The call was rejected by a Bedrock service quota, which tells the operator the account already carries heavy legitimate traffic and that a slower request rate is required" },
      ],
      answer: "passed_authz",
      explanation:
        "A request is checked in order: authentication, then authorization (IAM, SCPs, model access), and only then are its parameters validated. ValidationException therefore means the first two checks passed — the key is real, IAM allowed the Bedrock call, and the model is reachable — while the deliberately invalid max_tokens_to_sample value guarantees no tokens are generated, so the probe costs nothing. AccessDenied would have told the operator the opposite. This is the Sysdig LLMjacking probe. Note that the CloudTrail record still says failure: an errorCode is not the same as blocked, and a rule that only counts AccessDenied on InvokeModel (the Splunk 'Invoke Model Access Denied' analytic) misses it; the Sentinel-style hunt that counts InvokeModel with ValidationException from an AKIA key finds it. The SCP reading is wrong because an SCP allow leaves no trace and cannot raise this error (an SCP deny is what produces AccessDenied); the missing-model reading is wrong because an absent or unentitled model surfaces as a not-found or access error, not ValidationException; and the quota reading is wrong because a quota rejection is a ThrottlingException.",
    },
    {
      id: "credential_class",
      kind: "single",
      xp: 70,
      prompt:
        "aiw1_lj_03 (Tuesday) and aiw1_lj_10 (Thursday) are both PutFoundationModelEntitlement calls on an Anthropic model in us-east-1, and Elastic's 'Bedrock Foundation Model Access Enabled or Entitlement Granted' rule fires on either. Which observation separates the sanctioned change from the abuse?",
      hint: "Read userIdentity, the access key prefix, the user agent, the source address and the change record together, not any one alone.",
      options: [
        { value: "credential_context", label: "ASIA session key on an SSO assumed role, browser agent, Zurich egress address and an approved change, versus a long-term AKIA key on an IAM user, Boto3 agent and a hosting address" },
        { value: "model_family", label: "Only the modelId differs: Tuesday enabled Sonnet 4 and Thursday enabled Opus 4, and enabling the more expensive model is what turns routine administration into abuse" },
        { value: "night_hours", label: "Thursday happened at night and Tuesday in business hours, and any entitlement change outside working hours should be treated as hostile whatever credential, ticket or session stands behind it" },
        { value: "same_region", label: "Both ran in us-east-1, so the two calls are indistinguishable in CloudTrail and can only be told apart by asking the platform team whether they made the Thursday call" },
      ],
      answer: "credential_context",
      explanation:
        "The API name, the region and the model family are the same kind of thing on both days, so they cannot be the discriminator. What differs is the credential class and its context. Tuesday is an AssumedRole through the AWSReservedSSO_PlatformAdmin role: a short-lived ASIA key, mfaAuthenticated true, a Chrome user agent that is exactly what the Bedrock console produces, the corporate egress address, and it falls inside the approved window of change CHG0048117 for the very model that ticket names. Thursday is a long-term AKIA key on an IAM user calling a console-style API from a hosting-provider address with a Boto3 script agent, for a model no ticket names, inside a probe-then-delete sequence. An AKIA key performing console-style Bedrock administration is the Permiso honeypot tell. The model-family reading is wrong because which model is enabled is a business question, not evidence of compromise; the night-hours reading is wrong because an operator can time a call to office hours and the platform team does work at odd hours; and the indistinguishable reading is wrong because userIdentity, the key prefix and the source address separate the calls without asking anyone. No single field decides it — a user agent can be forged — so the analyst reads the combination and confirms with the ticket.",
    },
    {
      id: "logging_gap",
      kind: "single",
      xp: 75,
      prompt:
        "aiw1_lj_12 is a Bedrock invocation log record showing a role-play prompt, but it carries no source address and no access key. Minutes later the same key called DeleteModelInvocationLoggingConfiguration (aiw1_lj_13). Which reading is correct?",
      hint: "Compare the identifiers in the invocation log and the CloudTrail Converse call, and remember that invocation logging is configured per region.",
      options: [
        { value: "join_by_request", label: "The requestId on the record matches the requestID of the CloudTrail Converse call from the AKIA key, tying the prompt to that key; after the delete, that region leaves metadata but no prompt text" },
        { value: "arn_enough", label: "The identity.arn on the record names an IAM user, which by itself places the operator's address, and the delete also erased the stored records, so this prompt is the only evidence that ever existed or could exist" },
        { value: "trail_has_text", label: "The prompt text proves a jailbreak, so the record alone justifies escalation, and the delete has no bearing because CloudTrail still records the prompt text of every later call in that region" },
        { value: "no_attribution", label: "The record cannot be attributed because Bedrock logs omit the caller, so the key can only be found by asking each engineer whether they sent this prompt during the incident window" },
      ],
      answer: "join_by_request",
      explanation:
        "The invocation log is the only source that holds prompt text, but it names an identity, not an address or key: identity.arn gives the IAM user, and the requestId is the join key to CloudTrail, where the Converse call carries the AKIA access key, the source address 80.94.92.41 and the aiohttp agent. Correlating the two records is what attributes the prompt. The delete (T1562.008, GuardDuty DefenseEvasion:IAMUser/AnomalousBehavior) switches prompt capture off for that region from then on: later calls still appear in CloudTrail as metadata (caller, model, region) but never with text. Invocation logging is per region and was only ever enabled in us-east-1, so prompts sent to us-west-2 and us-east-2 were never recorded at all — this one record is all the content evidence there is. The records already written stay in the CloudWatch log group, so they must be preserved and exported now. The identity.arn reading is wrong because an ARN does not give an address and deleting the configuration does not erase stored logs; the CloudTrail-has-text reading is wrong because CloudTrail never contains prompt text; and the no-attribution reading is wrong because identity.arn and requestId make attribution straightforward.",
    },
    {
      id: "containment_order",
      kind: "single",
      xp: 70,
      prompt:
        "The key is confirmed as the source of the abuse and the burst is still running. Which response set is complete and in the right order?",
      hint: "Think about what stops the spend now, what restores your visibility, what stops a repeat, and who else must be told.",
      options: [
        { value: "key_logging_scp_case", label: "Deactivate the key then delete it, re-enable invocation logging, add an SCP denying Bedrock in unused regions and entitlement calls outside the admin role, and open a billing and abuse case" },
        { value: "user_and_ip_block", label: "Delete the IAM user and its policies at once, leave invocation logging off until the investigation ends so no more spend is generated, and block the two source addresses on the perimeter firewall and in a security group" },
        { value: "rotate_sso", label: "Rotate the SSO platform role and reset its members' MFA, then deactivate the key once the change window closes, since the entitlement calls all belong to the same API family" },
        { value: "wait_for_guardduty", label: "Block both addresses in a security group, wait for GuardDuty to quarantine the key automatically, and review the invocation logs the following week when the billing cycle closes" },
      ],
      answer: "key_logging_scp_case",
      explanation:
        "Stop the spend first by neutralising the credential: deactivate the AKIA key (instant, reversible and it preserves the key's metadata and usage history while the pipeline owner confirms it was the abused one), then delete it; check for other credentials the operator created, such as new IAM users or policies, as in the Wiz JINX-2401 pattern. Then restore visibility by re-enabling invocation logging, which also lets you review the prompts for abuse (illegal content needs legal escalation). Prevent a repeat with SCPs that deny Bedrock in regions the bank does not use and deny PutFoundationModelEntitlement outside the admin role. Finally open an AWS billing and abuse case with the Cost Explorer data and ask for credit. Deleting the user and blocking addresses is wrong because it leaves logging off, which is the operator's goal, and address blocks do nothing since the AWS API is not behind your perimeter and the operator already used two hosting addresses. Rotating the SSO role is wrong because it targets the platform team, who did nothing wrong, and leaves the abused key live. Waiting for GuardDuty is wrong because an automatic quarantine is not guaranteed, the burst keeps billing meanwhile, and reviewing logs a week later is too slow.",
    },
    {
      id: "atlas_mapping",
      kind: "single",
      xp: 65,
      prompt:
        "You are writing the case summary and must map the activity to MITRE frameworks. Which mapping fits the token-volume burst behind GuardDuty's Impact:IAMUser/AnomalousBehavior finding (and the $6,812 Cost Anomaly Detection impact) and the deletion of the logging configuration?",
      hint: "One of the two is an ATLAS technique for abusing a model service's cost; the other is a cloud logging technique in ATT&CK.",
      options: [
        { value: "t0034_and_t1562", label: "AML.T0034 Cost Harvesting for the token-volume finding and ATT&CK T1562.008 for deleting the logging configuration, both under the LLMjacking case study AML.CS0030" },
        { value: "t0051_injection", label: "AML.T0051 LLM Prompt Injection for the spend finding, because the role-play prompt is the malicious input and the cost is a side effect of the injected instructions, with T1562.008 for the delete" },
        { value: "swapped_ids", label: "AML.T0034 Cost Harvesting for the deletion of the logging configuration, since removing logs hides which spend is legitimate, and ATT&CK T1496.004 for the entitlement calls that enabled the models" },
        { value: "no_atlas", label: "No ATLAS technique applies because the model itself was never attacked, so the events map only to ATT&CK T1078.004 and T1496.004 and belong in a cloud-abuse case rather than an AI case" },
      ],
      answer: "t0034_and_t1562",
      explanation:
        "AML.T0034 Cost Harvesting is the ATLAS technique for abusing access to a model service to run up its cost, and it is what the burst behind GuardDuty's Impact:IAMUser/AnomalousBehavior finding and the Cost Anomaly Detection bill amounts to; the deletion of the logging configuration is an ordinary cloud defense-evasion technique, ATT&CK T1562.008 (Impair Defenses: Disable or Modify Cloud Logs). The whole pattern is ATLAS case study AML.CS0030, the LLMjacking case: the key use maps to AML.T0012 Valid Accounts and its exposure in the repository to AML.T0055 Unsecured Credentials, the anomalous invocation to AML.T0040 AI Model Inference API Access, and the role-play prompt to AML.T0054 LLM Jailbreak. On the ATT&CK side the key use is T1078.004, the repository exposure T1552.001, the entitlements T1098 and the burst T1496.004. The prompt-injection mapping is wrong because nothing was injected into an application; the prompt is the operator's own use of stolen access, and the harm is theft of service and spend. The swapped mapping is wrong because it attaches the cost technique to the logging deletion and the hijacking technique to the entitlements. The no-ATLAS reading is wrong because ATLAS explicitly covers abuse of AI services, not only attacks on models, which is why AML.CS0030 exists.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Opportunistic operator harvesting stolen cloud AI capacity (LLMjacking)",
    attack_kind: "llmjacking",
    briefing:
      "GuardDuty raised DefenseEvasion:IAMUser/AnomalousBehavior in AWS account 847213960055 (us-east-1): IAM user svc-build-release deleted the Amazon Bedrock model invocation logging configuration, the release pipeline's service user, from an internet address. The platform team is also known to be working on Bedrock this week. Work out whether this was them, what was done with Bedrock, and what it has cost.",
    narrative: `On Thursday at 00:49 UTC GitHub Advanced Security opened alert #9 on the public repository quantumbank-ch/build-tooling: an Amazon AWS Access Key ID, AKIAXQ7PL2MD4EXAMPLE, sat in scripts/eval_smoke.py at commit b7e40c19, pushed 12 seconds earlier by GitHub user lbrunner-qb (aiw1_lj_19, git.push in the audit log). The alert had no assignee. The key is the long-term access key of svc-build-release, the release pipeline's service user, which holds AmazonBedrockFullAccess because on 11 Aug a platform admin attached it for a model-evaluation stage (aiw1_lj_01) — an over-permissioned pipeline credential that then turned up in public.

At 01:14 the key was used for the first time from 80.94.92.41, a hosting-provider address in Bucharest, with a Boto3 user agent reporting Windows 10. The operator followed the canonical LLMjacking sequence: GetModelInvocationLoggingConfiguration to see whether logging was on, a console-style GetFoundationModelAvailability, and an InvokeModel on anthropic.claude-v2 with an invalid max_tokens_to_sample that returned ValidationException — proof the key could reach the model, at no cost. Then, from the same address, the three calls the Bedrock console makes for a human: PutUseCaseForModelAccess, CreateFoundationModelAgreement and PutFoundationModelEntitlement, this time enabling Claude Opus 4. (Elastic's rule fires on these; so it did on Tuesday, for a different reason.)

At 01:23 the first real Converse call went out, and because the bank's platform baseline had turned on model invocation logging in us-east-1, the invocation log recorded the prompt: a <system_rule> block claiming an authorized red team session for unrestricted role-play, 7,812 input tokens, 4,096 output tokens. That record has no source address; its requestId matches the CloudTrail Converse call from the AKIA key. Three minutes later the operator called DeleteModelInvocationLoggingConfiguration. From then on us-east-1 was dark. Model access is granted per region, so the same key entitled Opus 4 in us-west-2 and us-east-2 as well (aiw1_lj_20, aiw1_lj_21), and the burst that followed in us-west-2 (from a second address, 178.62.204.77) and us-east-2 was in regions that never recorded content at all. GuardDuty raised DefenseEvasion:IAMUser/AnomalousBehavior on the delete at 01:36, and Impact:IAMUser/AnomalousBehavior on the us-west-2 burst at 02:49; at about 02:54 the on-call security responder set the key to Inactive. Cost Anomaly Detection posted the bill at 09:54 once billing data landed: $6,854.10 against an expected $41.70, $6,812.40 of impact, on the order of sixteen thousand long completions.

The false-positive trap is the platform team's own week. On Monday change CHG0048117 was approved to enable Claude Sonnet 4 in us-east-1, and on Tuesday t.wagner did exactly that (aiw1_lj_03): the same PutFoundationModelEntitlement API, the same region, the same vendor. The discriminator is not the API but the credential and its context: an ASIA session key on an SSO assumed role with MFA, a Chrome user agent, the Zurich egress address and an approved ticket, against a long-term AKIA key, a Boto3 script agent, a hosting address and no ticket.

Mapping. ATT&CK: T1552.001 (key in a repository file), T1078.004 (valid cloud account), T1526 (cloud service discovery), T1098 (entitlements), T1562.008 (logging deleted), T1496.004 (cloud service hijacking). ATLAS: AML.T0055 Unsecured Credentials, AML.T0012 Valid Accounts, AML.T0040 AI Model Inference API Access, AML.T0054 LLM Jailbreak, AML.T0034 Cost Harvesting — the pattern of ATLAS case study AML.CS0030. Containment: deactivate then delete the key, re-enable invocation logging, add SCPs denying Bedrock in unused regions and entitlement calls outside the admin role, open a billing and abuse case, and preserve the us-east-1 log group.`,
    learning_objectives: [
      "Recognise the LLMjacking CloudTrail sequence (logging-config check, ValidationException probe, model enablement, logging deletion, multi-region burst) and explain why ValidationException proves access without cost",
      "Separate a leaked long-term AKIA key from a legitimate SSO assumed-role session making the same Bedrock entitlement call, using credential class, user agent, source address and the change record",
      "Explain what deleting Bedrock invocation logging means: prompt text exists only in the invocation log, logging is per region, and the log must be joined to CloudTrail by request id to attribute a prompt",
      "Order containment for a leaked cloud key: deactivate then delete the key, re-enable logging, add SCP guardrails, and open a billing and abuse case",
      "Map the activity to ATT&CK (T1562.008, T1496.004) and MITRE ATLAS (AML.T0034 Cost Harvesting, case study AML.CS0030)",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: tAttach, phase: "Baseline", action: "AmazonBedrockFullAccess attached to svc-build-release by an SSO platform admin (privilege chain)" },
      { ts: tPlatform, phase: "Baseline", action: `Platform team enables Claude Sonnet 4 through the console under approved change ${changeTicket} (control case)` },
      { ts: tRepoAlert, phase: "Credential Access", action: `Secret-scanning alert: AWS access key ID in public repository ${repo} (T1552.001)` },
      { ts: J(0, "lj05"), phase: "Initial Access", action: `svc-build-release access key first used from ${ipA} — GetModelInvocationLoggingConfiguration (T1078.004)` },
      { ts: J(3 * MIN, "lj07"), phase: "Discovery", action: "InvokeModel on anthropic.claude-v2 returns ValidationException — access confirmed without cost (T1526)" },
      { ts: J(5 * MIN, "lj08"), phase: "Persistence", action: "PutUseCaseForModelAccess, CreateFoundationModelAgreement, PutFoundationModelEntitlement — Opus 4 enabled (T1098)" },
      { ts: tInvocationLog, phase: "Impact", action: "First Converse call recorded by the invocation log — role-play prompt, 7,812 in / 4,096 out tokens (T1496.004)" },
      { ts: J(12 * MIN, "lj13"), phase: "Defense Evasion", action: "DeleteModelInvocationLoggingConfiguration in us-east-1 (T1562.008)" },
      { ts: J(14 * MIN, "lj14"), phase: "Impact", action: `Streaming burst in us-west-2 from ${ipB}, then us-east-2 (T1496.004)` },
      { ts: J(22 * MIN, "lj16"), phase: "Detection", action: "GuardDuty DefenseEvasion:IAMUser/AnomalousBehavior on DeleteModelInvocationLoggingConfiguration" },
      { ts: J(95 * MIN, "lj17"), phase: "Detection", action: "GuardDuty Impact:IAMUser/AnomalousBehavior on InvokeModelWithResponseStream (ATLAS AML.T0034)" },
      { ts: J(100 * MIN, "lj22"), phase: "Containment", action: `UpdateAccessKey: ${akia} set to Inactive by the SecurityResponder SSO session` },
      { ts: J(8 * 60 * MIN + 40 * MIN, "lj18"), phase: "Detection", action: "Cost Anomaly Detection: $6,812.40 impact on Amazon Bedrock" },
    ],
    questions,
  };
}
