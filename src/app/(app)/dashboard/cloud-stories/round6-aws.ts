/**
 * Cloud round, AWS: five families, each with a single-player variant and a Team Training variant that share no
 * person, address, resource or plot. Authored on the NexaCorp identity and moved onto the first AWS shop that runs
 * them (authoredFor); instantiateStory re-homes people, account ids and domains per session.
 *
 *  family cloud-aws-sso-device-code  IAM Identity Center sessions obtained through device-code phishing: the victim
 *                                    signs in from the office, the session works from somewhere else.
 *  family cloud-aws-lambda-url-backdoor  a Lambda function exposed through a public function URL (AuthType NONE,
 *                                    resource policy for principal *), then used as a doorway into the account.
 *  family cloud-aws-secrets-harvest  bulk reads of Secrets Manager and Parameter Store from a stolen workload or
 *                                    user session, and a harvested credential used elsewhere.
 *  family cloud-aws-org-escape       contacts changed, guardrails detached, the member account taken out of the
 *                                    organization: the organization trail and GuardDuty stop seeing it.
 *  family cloud-aws-ses-abuse        stolen credentials probing and enabling SES to send mail as the company.
 *
 * Effects only: CloudTrail records, GuardDuty findings, sign-ins and firewall URL logs; no function code, no message
 * bodies. Access keys follow the documentation form (ending EXAMPLE).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { cloudTrailEvent, guardDutyFinding, type CloudTrailOpts } from "@/lib/sim/emitters/cloudtrail";
import { oktaSignIn } from "@/lib/sim/emitters/okta";
import type { AiStoryDef } from "../ai-stories/wave2";
import { CX, authoredFor, benign, sentinel, ticket, web, withIncident } from "../ai-stories/wave4-shared";

const ACCT = "418772153604";
const OFFICE = "192.0.2.150";
const AWS_SHOPS = ["rocketstack", "globallogis", "quantumbank"];
const CLI = "aws-cli/2.18.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8.0-48-generic md/arch#x86_64 lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe";
const BOTO = "Boto3/1.35.44 md/Botocore#1.35.44 ua/2.0 os/linux#6.5.0 md/arch#x86_64 lang/python#3.11.10 cfg/retry-mode#legacy Botocore/1.35.44";
const CONSOLE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const at = (iso: string) => (min: number) => new Date(Date.parse(iso) + min * 60_000).toISOString();

type Extra = Record<string, string | number | boolean>;
type Ct = Omit<CloudTrailOpts, "companyId"> & { person?: string };
/** A CloudTrail record of the story. `person` names the human behind an Identity Center session (re-homed per session). */
function ct(o: Ct): TelemetryEvent {
  const { person, ...rest } = o;
  const e = cloudTrailEvent({ companyId: CX, accountId: ACCT, ...rest });
  return person ? { ...e, user_email: person } : e;
}
/** An IAM Identity Center session: the reserved SSO role, the person's address as the session name. */
function sso(role: string, person: string, key: string, more: Extra = {}): Pick<Ct, "actorType" | "actorName" | "sessionIssuerName" | "accessKeyId" | "person" | "arn" | "extra"> {
  return {
    actorType: "AssumedRole", actorName: role, sessionIssuerName: role, accessKeyId: key, person,
    arn: `arn:aws:sts::${ACCT}:assumed-role/${role}/${person}`,
    extra: { "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn": `arn:aws:iam::${ACCT}:role/aws-reserved/sso.amazonaws.com/${role}`, ...more },
  };
}
function gd(o: Omit<Parameters<typeof guardDutyFinding>[0], "companyId" | "accountId">): TelemetryEvent {
  return { ...guardDutyFinding({ companyId: CX, accountId: ACCT, ...o }), edr_scope: "non_edr" as const };
}
const req = (o: Record<string, string>): Extra => Object.fromEntries(Object.entries(o).map(([k, v]) => [`aws.cloudtrail.requestParameters.${k}`, v]));

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-sso-device-code, solo: a "renew your access" page, a device code, and data read from outside
// ══════════════════════════════════════════════════════════════════════════════
function ssoDeviceCodeSolo(): TelemetryEvent[] {
  const T = at("2026-11-16T09:00:00Z");
  const victim = { host: "WS-MKT-3301", ip: "10.10.20.33", user: "s.patel@nexacorp.com" };
  const atk = "192.0.2.101";
  const role = "AWSReservedSSO_DataAnalyst_7c2e19f4a0b3d851";
  const key = "ASIAQ7DLM4K2XEXAMPLE";
  const s = sso(role, victim.user, key);
  const lure = "aws-access-review.example";
  const bucket = "nexacorp-analytics-curated";
  // The twin is the analyst's own sign-in the day before: same person, same desk (one person, one machine).
  const dev = victim;
  return withIncident([
    // The twin: the same analyst's own `aws sso login` from the office the day before: the same device page, the same kind of session, the same address afterwards.
    benign(web(dev, {
      id: "r6ad01", ts: T(-1440 - 95), url: "https://device.sso.us-east-1.amazonaws.com/?user_code=BFKQ-TXWM", domain: "device.sso.us-east-1.amazonaws.com", dstIp: "198.51.100.43",
      category: "computer-and-internet-info", method: "GET", action: "allow", status: 200, bytesIn: 21_408, bytesOut: 1_212, userAgent: CONSOLE, severity: "informational",
      description: `Firewall URL log: ${dev.host} opened the IAM Identity Center device page with a user code, no referring page.`,
    }), "The analyst's own `aws sso login` the day before: the code page opened straight from the CLI prompt, no referring site, and every API call after it comes from the same office address."),
    benign(ct({
      ...sso(role, dev.user, "ASIAM2TQ8LR5HEXAMPLE"), id: "r6ad02", ts: T(-1440 - 93), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: OFFICE, userAgent: CLI, readOnly: true, severity: "low",
      description: "CloudTrail GetCallerIdentity by the analyst's Identity Center session (DataAnalyst) from the office address, AWS CLI.",
    }), "The analyst's own CLI checking the new session the day before, from the office address the sign-in came from."),

    web(victim, {
      id: "r6ad03", ts: T(0), url: `https://${lure}/renew?team=analytics`, domain: lure, dstIp: "192.0.2.102", category: "newly-registered-domain",
      method: "GET", action: "alert", status: 200, bytesIn: 38_204, bytesOut: 1_640, userAgent: CONSOLE, referer: "https://teams.microsoft.com/", severity: "low", mitre: "T1566.002", tactic: "Initial Access",
      description: `Firewall URL log: ${victim.host} opened ${lure}/renew from a chat link, category newly-registered-domain, action alert.`,
    }),
    web(victim, {
      id: "r6ad04", ts: T(0.7), url: "https://device.sso.us-east-1.amazonaws.com/?user_code=QXLM-PRTZ", domain: "device.sso.us-east-1.amazonaws.com", dstIp: "198.51.100.43",
      category: "computer-and-internet-info", method: "GET", action: "allow", status: 200, bytesIn: 21_390, bytesOut: 1_388, userAgent: CONSOLE, referer: `https://${lure}/renew?team=analytics`,
      severity: "medium", mitre: "T1528", tactic: "Credential Access",
      description: `Firewall URL log: ${victim.host} opened the IAM Identity Center device page with user code QXLM-PRTZ, referred by ${lure}.`,
    }),
    oktaSignIn({
      companyId: CX, id: "r6ad05", ts: T(1.2), user: victim.user, srcIp: OFFICE, mfaUsed: true, userAgent: CONSOLE, os: "Windows 10", browser: "CHROME", severity: "low", mitre: "T1528", tactic: "Credential Access",
      description: `Okta sign-in for ${victim.user} from the office address with Okta Verify, seconds after the device page opened.`,
    }),
    ct({
      ...s, id: "r6ad06", ts: T(2.1), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: atk, userAgent: BOTO, readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by the DataAnalyst Identity Center session of ${victim.user} from ${atk}, Boto3. The session was opened 54 seconds earlier from the office.`,
    }),
    ct({
      ...s, id: "r6ad07", ts: T(2.6), eventName: "ListBuckets", eventSource: "s3.amazonaws.com", srcIp: atk, userAgent: BOTO, readOnly: true, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `CloudTrail ListBuckets by the same session from ${atk}.`,
    }),
    gd({
      id: "r6ad08", ts: T(4), findingType: "Discovery:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API commonly used to discover information in an AWS environment was invoked in an anomalous way.",
      srcIp: atk, api: "ListBuckets", serviceName: "s3.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key,
      severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `GuardDuty Discovery:IAMUser/AnomalousBehavior for the DataAnalyst session, API ListBuckets from ${atk}.`,
    }),
    ct({
      ...s, id: "r6ad09", ts: T(5), eventName: "ListObjects", eventSource: "s3.amazonaws.com", s3Bucket: bucket, srcIp: atk, userAgent: BOTO, readOnly: true, managementEvent: false, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `CloudTrail data event: ListObjects on ${bucket} by the DataAnalyst session from ${atk}.`,
    }),
    ct({
      ...s, id: "r6ad10", ts: T(7), eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "customers/2026/customer_master.parquet", srcIp: atk, userAgent: BOTO,
      readOnly: true, managementEvent: false, bytes: 412_880_114, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `CloudTrail data event: GetObject customers/2026/customer_master.parquet (about 413 MB) from ${bucket} by the DataAnalyst session from ${atk}.`,
    }),
    ct({
      ...s, id: "r6ad11", ts: T(9), eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "finance/2026/q3_revenue_by_account.parquet", srcIp: atk, userAgent: BOTO,
      readOnly: true, managementEvent: false, bytes: 88_204_611, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `CloudTrail data event: GetObject finance/2026/q3_revenue_by_account.parquet (about 88 MB) from ${bucket} by the same session from ${atk}.`,
    }),
    ct({
      ...s, id: "r6ad12", ts: T(11), eventName: "GetObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "marketing/2026/campaign_contacts.csv", srcIp: OFFICE, userAgent: CONSOLE,
      readOnly: true, managementEvent: false, bytes: 2_208_440, severity: "low",
      description: "CloudTrail data event: GetObject marketing/2026/campaign_contacts.csv by the same Identity Center session from the office address, through the console. The session is in use from two places at once.",
    }),
  ], "inc:r6:aws-sso-solo");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-sso-device-code, team: an administrator's device code, then a role an outside account can assume
// ══════════════════════════════════════════════════════════════════════════════
function ssoDeviceCodeTeam(): TelemetryEvent[] {
  const T = at("2026-11-17T14:10:00Z");
  const admin = { host: "WS-OPS-2214", ip: "10.10.20.14", user: "l.ferreira@nexacorp.com" };
  const atk = "192.0.2.103", outsideIp = "192.0.2.105";
  const outside = "604187359221";
  const role = "AWSReservedSSO_AdministratorAccess_d41f8a20c7e95b16";
  const key = "ASIAW4PZ9KD2LEXAMPLE";
  const lure = "it-sso-verify.example";
  const backdoor = "ops-metrics-readonly";
  const bd = { actorType: "AssumedRole" as const, actorName: backdoor, sessionIssuerName: backdoor, arn: `arn:aws:sts::${ACCT}:assumed-role/${backdoor}/metrics-sync`, accessKeyId: "ASIAK3NV7TP4MEXAMPLE", srcIp: outsideIp, userAgent: BOTO };
  return withIncident([
    ticket({ id: "r6ae00", ts: T(-180), table: "change_request", number: "CHG0063118", state: "Implement", caller: admin.user, severity: "informational",
      shortDescription: "Cross-account audit role for the external assessor (account 391857264013), read-only, 14 days", eventType: "policy_modification",
      description: "ServiceNow change CHG0063118 (Implement): a read-only role the external assessor's account 391857264013 may assume for 14 days." }),
    benign(ct({
      ...sso(role, admin.user, "ASIAH8RVN3C6TEXAMPLE", req({ roleName: "assessor-readonly", policyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::391857264013:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"chg0063118"}}}]}` })),
      id: "r6ae01", ts: T(-170), eventName: "UpdateAssumeRolePolicy", eventSource: "iam.amazonaws.com", srcIp: OFFICE, userAgent: CONSOLE, severity: "medium",
      description: "CloudTrail UpdateAssumeRolePolicy on assessor-readonly by the AdministratorAccess Identity Center session from the office, trusting account 391857264013 with an external id.",
    }), "The approved assessor role (CHG0063118): set from the office console, trusting the assessor's account named in the change, with an external id and read-only permissions."),

    web(admin, {
      id: "r6ae02", ts: T(0), url: `https://${lure}/aws/admin-recertify`, domain: lure, dstIp: "192.0.2.104", category: "newly-registered-domain",
      method: "GET", action: "alert", status: 200, bytesIn: 41_022, bytesOut: 1_702, userAgent: CONSOLE, referer: "https://outlook.office.com/", severity: "low", mitre: "T1566.002", tactic: "Initial Access",
      description: `Firewall URL log: ${admin.host} opened ${lure}/aws/admin-recertify from a mail link, category newly-registered-domain.`,
    }),
    web(admin, {
      id: "r6ae03", ts: T(0.9), url: "https://device.sso.eu-west-1.amazonaws.com/?user_code=HMVD-KQZW", domain: "device.sso.eu-west-1.amazonaws.com", dstIp: "198.51.100.48",
      category: "computer-and-internet-info", method: "GET", action: "allow", status: 200, bytesIn: 21_412, bytesOut: 1_402, userAgent: CONSOLE, referer: `https://${lure}/aws/admin-recertify`,
      severity: "medium", mitre: "T1528", tactic: "Credential Access",
      description: `Firewall URL log: ${admin.host} opened the IAM Identity Center device page (eu-west-1) with user code HMVD-KQZW, referred by ${lure}.`,
    }),
    ct({
      ...sso(role, admin.user, key), id: "r6ae04", ts: T(2.4), eventName: "ListRoles", eventSource: "iam.amazonaws.com", srcIp: atk, userAgent: BOTO, readOnly: true, severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `CloudTrail ListRoles by the AdministratorAccess Identity Center session of ${admin.user} from ${atk}, Boto3.`,
    }),
    ct({
      ...sso(role, admin.user, key, req({ roleName: backdoor, assumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::${outside}:root"},"Action":"sts:AssumeRole"}]}` })),
      id: "r6ae05", ts: T(4), eventName: "CreateRole", eventSource: "iam.amazonaws.com", srcIp: atk, userAgent: BOTO, severity: "high", mitre: "T1098.003", tactic: "Persistence",
      description: `CloudTrail CreateRole ${backdoor} by the same session from ${atk}, trust policy allowing account ${outside} with no external id.`,
    }),
    ct({
      ...sso(role, admin.user, key, req({ roleName: backdoor, policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" })),
      id: "r6ae06", ts: T(4.5), eventName: "AttachRolePolicy", eventSource: "iam.amazonaws.com", srcIp: atk, userAgent: BOTO, severity: "high", mitre: "T1098.003", tactic: "Persistence",
      description: `CloudTrail AttachRolePolicy AdministratorAccess to ${backdoor} by the same session from ${atk}.`,
    }),
    gd({
      id: "r6ae07", ts: T(6), findingType: "Persistence:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API commonly used to maintain unauthorized access to an AWS environment was invoked in an anomalous way.",
      srcIp: atk, api: "CreateRole", serviceName: "iam.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key,
      severity: "medium", mitre: "T1098.003", tactic: "Persistence",
      description: `GuardDuty Persistence:IAMUser/AnomalousBehavior for the AdministratorAccess session, API CreateRole from ${atk}.`,
    }),
    ct({
      id: "r6ae08", ts: T(9), eventName: "AssumeRole", eventSource: "sts.amazonaws.com", srcIp: outsideIp, userAgent: BOTO, actorType: "IAMUser", actorName: "deploy-bot", accountId: outside,
      arn: `arn:aws:iam::${outside}:user/deploy-bot`, accessKeyId: "AKIAT5KQW2ZR8EXAMPLE", severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      extra: req({ roleArn: `arn:aws:iam::${ACCT}:role/${backdoor}`, roleSessionName: "metrics-sync" }),
      description: `CloudTrail AssumeRole into ${backdoor} by deploy-bot of the outside account ${outside} from ${outsideIp}, session metrics-sync.`,
    }),
    ct({ ...bd, id: "r6ae09", ts: T(11), eventName: "ListUsers", eventSource: "iam.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `CloudTrail ListUsers by the ${backdoor}/metrics-sync session from ${outsideIp}.` }),
    ct({ ...bd, id: "r6ae10", ts: T(12), eventName: "GetAccountAuthorizationDetails", eventSource: "iam.amazonaws.com", readOnly: true, severity: "high", mitre: "T1087.004", tactic: "Discovery",
      description: `CloudTrail GetAccountAuthorizationDetails (every user, role, group and policy of the account) by the ${backdoor}/metrics-sync session from ${outsideIp}.` }),
  ], "inc:r6:aws-sso-team");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-lambda-url-backdoor, solo: a build key creates a function anyone on the internet can call
// ══════════════════════════════════════════════════════════════════════════════
function lambdaUrlSolo(): TelemetryEvent[] {
  const T = at("2026-11-18T02:20:00Z");
  const atk = "192.0.2.106";
  const user = "ci-deployer";
  const a = { srcIp: atk, actorName: user, arn: `arn:aws:iam::${ACCT}:user/${user}`, accessKeyId: "AKIAR6LMB2Q7DEXAMPLE", userAgent: BOTO };
  const fn = "billing-sync-health";
  const exec = "lambda-billing-exec";
  const fnS = { actorType: "AssumedRole" as const, actorName: exec, sessionIssuerName: exec, arn: `arn:aws:sts::${ACCT}:assumed-role/${exec}/${fn}`, accessKeyId: "ASIAD9VL2QW6NEXAMPLE", srcIp: "198.51.100.54",
    userAgent: "Boto3/1.34.145 md/Botocore#1.34.145 ua/2.0 os/linux#5.10.227 md/arch#x86_64 lang/python#3.12.7 exec-env/AWS_Lambda_python3.12" };
  return withIncident([
    ticket({ id: "r6al00", ts: T(-300), table: "change_request", number: "CHG0063402", state: "Closed Complete", caller: "t.harris@nexacorp.com", severity: "informational",
      shortDescription: "Public webhook receiver for the payment provider (Lambda function URL, signature checked in code)", eventType: "policy_modification",
      description: "ServiceNow change CHG0063402 (Closed Complete): payment-webhook-receiver exposed through a Lambda function URL; the code validates the provider's signature." }),
    benign(ct({
      id: "r6al01", ts: T(-290), eventName: "CreateFunctionUrlConfig", eventSource: "lambda.amazonaws.com", srcIp: "10.20.4.11", actorType: "AssumedRole", actorName: "terraform-apply", sessionIssuerName: "terraform-apply",
      arn: `arn:aws:sts::${ACCT}:assumed-role/terraform-apply/pipeline-8812`, accessKeyId: "ASIAF2KM8VR4ZEXAMPLE", userAgent: "APN/1.0 HashiCorp/1.0 Terraform/1.9.8", severity: "low",
      extra: req({ functionName: "payment-webhook-receiver", authType: "NONE" }),
      description: "CloudTrail CreateFunctionUrlConfig for payment-webhook-receiver with AuthType NONE by the terraform-apply role from inside the VPC.",
    }), "The approved webhook receiver (CHG0063402): deployed by the Terraform pipeline role from inside the VPC; a payment provider cannot sign in to AWS, so the URL is public by design and the code checks the signature."),

    ct({ ...a, id: "r6al02", ts: T(0), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by the ci-deployer access key from ${atk}, Boto3. The key is used only by the build system, from the VPC.` }),
    ct({ ...a, id: "r6al03", ts: T(1), eventName: "ListFunctions20150331", eventSource: "lambda.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail ListFunctions by ci-deployer from ${atk}.` }),
    ct({ ...a, id: "r6al04", ts: T(1.5), eventName: "ListRoles", eventSource: "iam.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `CloudTrail ListRoles by ci-deployer from ${atk}.` }),
    ct({ ...a, id: "r6al05", ts: T(4), eventName: "CreateFunction20150331", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1648", tactic: "Execution",
      extra: { ...req({ functionName: fn, runtime: "python3.12", handler: "app.handler", role: `arn:aws:iam::${ACCT}:role/${exec}` }), "aws.cloudtrail.responseElements.functionArn": `arn:aws:lambda:us-east-1:${ACCT}:function:${fn}` },
      description: `CloudTrail CreateFunction ${fn} (python3.12) by ci-deployer from ${atk}, running as the existing role ${exec}. No pipeline run created it.` }),
    ct({ ...a, id: "r6al06", ts: T(4.4), eventName: "CreateFunctionUrlConfig", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1190", tactic: "Persistence",
      extra: { ...req({ functionName: fn, authType: "NONE" }), "aws.cloudtrail.responseElements.functionUrl": "https://q7zr4n2kx5vbd8lt3wymha6pce0fsuoj.lambda-url.us-east-1.on.aws/" },
      description: `CloudTrail CreateFunctionUrlConfig for ${fn} with AuthType NONE by ci-deployer from ${atk}: the function answers anyone on the internet.` }),
    ct({ ...a, id: "r6al07", ts: T(4.7), eventName: "AddPermission20150331v2", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1098", tactic: "Persistence",
      extra: req({ functionName: fn, statementId: "FunctionURLAllowPublicAccess", action: "lambda:InvokeFunctionUrl", principal: "*", functionUrlAuthType: "NONE" }),
      description: `CloudTrail AddPermission on ${fn}: lambda:InvokeFunctionUrl for principal *, by ci-deployer from ${atk}.` }),
    ct({ ...a, id: "r6al08", ts: T(6), eventName: "DeleteAccessKey", eventSource: "iam.amazonaws.com", outcome: "failure", errorCode: "AccessDenied", severity: "medium", mitre: "T1070", tactic: "Stealth",
      extra: req({ userName: user, accessKeyId: "AKIAN4VQ7KD3PEXAMPLE" }),
      description: `CloudTrail DeleteAccessKey (the build system's second key) by ci-deployer from ${atk}, AccessDenied.` }),
    ct({ ...fnS, id: "r6al09", ts: T(190), eventName: "ListSecrets", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail ListSecrets by the ${exec}/${fn} session (the new function running) from ${fnS.srcIp}, three hours after the URL was opened.` }),
    ct({ ...fnS, id: "r6al10", ts: T(190.4), eventName: "GetSecretValue", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      extra: req({ secretId: `arn:aws:secretsmanager:us-east-1:${ACCT}:secret:prod/billing/psp-restricted-key-Qm4v2L` }),
      description: `CloudTrail GetSecretValue prod/billing/psp-restricted-key by the ${fn} function's session from ${fnS.srcIp}. The billing code that owns the role never reads this secret.` }),
    gd({
      id: "r6al11", ts: T(192), findingType: "CredentialAccess:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API used to gain access to an AWS environment was invoked in an anomalous way.",
      srcIp: fnS.srcIp, api: "GetSecretValue", serviceName: "secretsmanager.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: exec, accessKeyId: fnS.accessKeyId,
      severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `GuardDuty CredentialAccess:IAMUser/AnomalousBehavior for role ${exec}, API GetSecretValue.`,
    }),
  ], "inc:r6:aws-lambda-solo");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-lambda-url-backdoor, team: an existing function changed, a layer from another account, a public URL
// ══════════════════════════════════════════════════════════════════════════════
function lambdaUrlTeam(): TelemetryEvent[] {
  const T = at("2026-11-19T21:05:00Z");
  const atk = "192.0.2.107";
  const role = "AWSReservedSSO_PlatformEngineer_9b3e61d0f2a7c845";
  const person = "d.cohen@nexacorp.com";
  const key = "ASIAP7XQ2MN8VEXAMPLE";
  const s = (more: Extra = {}) => ({ ...sso(role, person, key, more), srcIp: atk, userAgent: BOTO });
  const fn = "order-events-processor";
  const exec = "order-events-exec";
  const fnS = { actorType: "AssumedRole" as const, actorName: exec, sessionIssuerName: exec, arn: `arn:aws:sts::${ACCT}:assumed-role/${exec}/${fn}`, accessKeyId: "ASIAB8LN5RT2KEXAMPLE", srcIp: "198.51.100.56",
    userAgent: "aws-sdk-nodejs/2.1692.0 linux/v20.18.0 exec-env/AWS_Lambda_nodejs20.x" };
  return withIncident([
    benign(ct({
      ...sso(role, "l.ferreira@nexacorp.com", "ASIAV2KD9PQ4MEXAMPLE", req({ functionName: "inventory-sync", layers: `arn:aws:lambda:us-east-1:${ACCT}:layer:shared-utils:12` })),
      id: "r6am00", ts: T(-600), eventName: "UpdateFunctionConfiguration20150331v2", eventSource: "lambda.amazonaws.com", srcIp: OFFICE, userAgent: CONSOLE, severity: "low",
      description: "CloudTrail UpdateFunctionConfiguration on inventory-sync by a PlatformEngineer Identity Center session from the office console, adding the company's own shared-utils layer.",
    }), "A platform engineer attaching the company's own layer (same account) to a function from the office console during working hours."),

    ct({ ...s(req({ functionName: fn })), id: "r6am01", ts: T(0), eventName: "GetFunction20150331v2", eventSource: "lambda.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail GetFunction ${fn} by the PlatformEngineer Identity Center session of ${person} from ${atk}, Boto3, at 21:05.` }),
    ct({ ...s({ ...req({ functionName: fn, publish: "true" }), "aws.cloudtrail.responseElements.codeSha256": "W9u2Qm7XcT4yLp0bVn3K8rGd1sFhEoJiZaNqC5tYxM6=" }), id: "r6am02", ts: T(3), eventName: "UpdateFunctionCode20150331v2", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1525", tactic: "Persistence",
      description: `CloudTrail UpdateFunctionCode on ${fn} by the same session from ${atk}: new code published outside the deployment pipeline.` }),
    ct({ ...s(req({ functionName: fn, layers: "arn:aws:lambda:us-east-1:391857264099:layer:otel-collector-ext:7" })), id: "r6am03", ts: T(3.6), eventName: "UpdateFunctionConfiguration20150331v2", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1505", tactic: "Persistence",
      description: `CloudTrail UpdateFunctionConfiguration on ${fn} by the same session from ${atk}: a layer from account 391857264099, which is not the company's.` }),
    ct({ ...s({ ...req({ functionName: fn, authType: "NONE" }), "aws.cloudtrail.responseElements.functionUrl": "https://m3vk8x2qz9rnb4w7ytle5pdjf6ochg0a.lambda-url.us-east-1.on.aws/" }), id: "r6am04", ts: T(4.1), eventName: "CreateFunctionUrlConfig", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1190", tactic: "Persistence",
      description: `CloudTrail CreateFunctionUrlConfig on ${fn} with AuthType NONE by the same session from ${atk}. The function is an internal queue consumer that never had a URL.` }),
    ct({ ...s(req({ functionName: fn, statementId: "FunctionURLAllowPublicAccess", action: "lambda:InvokeFunctionUrl", principal: "*", functionUrlAuthType: "NONE" })), id: "r6am05", ts: T(4.3), eventName: "AddPermission20150331v2", eventSource: "lambda.amazonaws.com", severity: "high", mitre: "T1098", tactic: "Persistence",
      description: `CloudTrail AddPermission on ${fn}: lambda:InvokeFunctionUrl for principal * by the same session from ${atk}.` }),
    ct({ ...s(req({ alarmNames: "order-events-processor-errors" })), id: "r6am06", ts: T(5), eventName: "DeleteAlarms", eventSource: "monitoring.amazonaws.com", severity: "high", mitre: "T1685", tactic: "Defense Impairment",
      description: `CloudTrail DeleteAlarms order-events-processor-errors by the same session from ${atk}.` }),
    ct({ ...fnS, id: "r6am07", ts: T(140), eventName: "CreateUser", eventSource: "iam.amazonaws.com", severity: "critical", mitre: "T1136.003", tactic: "Persistence",
      extra: req({ userName: "svc-orders-replay" }),
      description: `CloudTrail CreateUser svc-orders-replay by the ${exec}/${fn} session (the changed function running) from ${fnS.srcIp}.` }),
    ct({ ...fnS, id: "r6am08", ts: T(140.3), eventName: "CreateAccessKey", eventSource: "iam.amazonaws.com", severity: "critical", mitre: "T1098.001", tactic: "Persistence",
      extra: req({ userName: "svc-orders-replay" }),
      description: `CloudTrail CreateAccessKey for svc-orders-replay by the ${fn} function's session from ${fnS.srcIp}.` }),
    gd({
      id: "r6am09", ts: T(143), findingType: "Persistence:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API commonly used to maintain unauthorized access to an AWS environment was invoked in an anomalous way.",
      srcIp: fnS.srcIp, api: "CreateAccessKey", serviceName: "iam.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: exec, accessKeyId: fnS.accessKeyId,
      severity: "medium", mitre: "T1098.001", tactic: "Persistence",
      description: `GuardDuty Persistence:IAMUser/AnomalousBehavior for role ${exec}, API CreateAccessKey.`,
    }),
    ct({ id: "r6am10", ts: T(200), eventName: "ListBuckets", eventSource: "s3.amazonaws.com", srcIp: "192.0.2.108", userAgent: BOTO, actorType: "IAMUser", actorName: "svc-orders-replay",
      arn: `arn:aws:iam::${ACCT}:user/svc-orders-replay`, accessKeyId: "AKIAJ6WN3PL8QEXAMPLE", readOnly: true, severity: "high", mitre: "T1619", tactic: "Discovery",
      description: "CloudTrail ListBuckets by the new user svc-orders-replay from 192.0.2.108, an hour after it was created." }),
  ], "inc:r6:aws-lambda-team");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-secrets-harvest, solo: instance credentials used outside AWS read every secret and parameter
// ══════════════════════════════════════════════════════════════════════════════
function secretsSolo(): TelemetryEvent[] {
  const T = at("2026-11-20T03:30:00Z");
  const atk = "192.0.2.109", reuse = "192.0.2.110";
  const role = "web-portal-instance";
  const inst = "i-0c4f8a21d7e93b5a6";
  const key = "ASIAC5MT8WK2REXAMPLE";
  const s = (more: Extra = {}) => ({ actorType: "AssumedRole" as const, actorName: role, sessionIssuerName: role, arn: `arn:aws:sts::${ACCT}:assumed-role/${role}/${inst}`, accessKeyId: key, srcIp: atk, userAgent: CLI,
    extra: { "aws.cloudtrail.userIdentity.sessionContext.ec2RoleDelivery": "2.0", ...more } });
  const reporter = { actorType: "IAMUser" as const, actorName: "svc-report-export", arn: `arn:aws:iam::${ACCT}:user/svc-report-export`, accessKeyId: "AKIAH3PX6TQ9VEXAMPLE", srcIp: reuse, userAgent: CLI };
  const secrets = ["prod/web-portal/db-credentials", "prod/reporting/iam-export-key", "prod/partners/sftp-logistics", "prod/web-portal/smtp-relay"];
  return withIncident([
    benign(ct({
      ...s(req({ secretId: "prod/web-portal/db-credentials" })), id: "r6as00", ts: T(-120), srcIp: "10.20.5.21", userAgent: "aws-sdk-java/2.28.16 Linux/5.10.227 OpenJDK_64-Bit_Server_VM/21.0.5",
      eventName: "GetSecretValue", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "informational",
      description: "CloudTrail GetSecretValue prod/web-portal/db-credentials by the web-portal-instance role from the instance's own address, Java SDK.",
    }), "The portal itself reading its own database secret at start-up: the instance's private address, the application's Java SDK, the one secret its code uses."),

    gd({
      id: "r6as01", ts: T(0), findingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", gdSeverity: 8, title: "Credentials for the EC2 instance role web-portal-instance were used from a remote IP address outside AWS.",
      srcIp: atk, api: "GetCallerIdentity", serviceName: "sts.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key,
      severity: "high", mitre: "T1552.005", tactic: "Credential Access",
      description: `GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS: the web-portal-instance role credentials used from ${atk}.`,
    }),
    ct({ ...s(), id: "r6as02", ts: T(0.2), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by the web-portal-instance session (${inst}) from ${atk}, AWS CLI.` }),
    ct({ ...s(), id: "r6as03", ts: T(1), eventName: "ListSecrets", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail ListSecrets by the web-portal-instance session from ${atk}.` }),
    ...secrets.map((id, i) => ct({
      ...s(req({ secretId: id })), id: `r6as0${4 + i}`, ts: T(1.4 + i * 0.2), eventName: "GetSecretValue", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: i === 1 ? "high" : "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail GetSecretValue ${id} by the web-portal-instance session from ${atk}.${i > 0 ? " The portal's code never reads this secret." : ""}`,
    })),
    ct({ ...s(), id: "r6as08", ts: T(3), eventName: "DescribeParameters", eventSource: "ssm.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail DescribeParameters by the web-portal-instance session from ${atk}.` }),
    ct({ ...s(req({ path: "/prod/", recursive: "true", withDecryption: "true" })), id: "r6as09", ts: T(3.5), eventName: "GetParametersByPath", eventSource: "ssm.amazonaws.com", readOnly: true, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail GetParametersByPath /prod/ recursive with decryption by the web-portal-instance session from ${atk}.` }),
    ct({ ...reporter, id: "r6as10", ts: T(48), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by svc-report-export (the key stored in prod/reporting/iam-export-key) from ${reuse}. The key normally runs only from the reporting server.` }),
    ct({ ...reporter, id: "r6as11", ts: T(49), eventName: "ListObjects", eventSource: "s3.amazonaws.com", s3Bucket: "nexacorp-finance-reports", readOnly: true, managementEvent: false, severity: "high", mitre: "T1619", tactic: "Discovery",
      description: `CloudTrail data event: ListObjects on nexacorp-finance-reports by svc-report-export from ${reuse}.` }),
  ], "inc:r6:aws-secrets-solo");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-secrets-harvest, team: one night, one person's session, every secret in one batch call
// ══════════════════════════════════════════════════════════════════════════════
function secretsTeam(): TelemetryEvent[] {
  const T = at("2026-11-21T01:40:00Z");
  const atk = "192.0.2.111", reuse = "192.0.2.112";
  const role = "AWSReservedSSO_SupportEngineer_6e07b3a9d1f2c458";
  const person = "a.kaplan@nexacorp.com";
  const key = "ASIAU9RK4ZN7BEXAMPLE";
  const s = (more: Extra = {}) => ({ ...sso(role, person, key, more), srcIp: atk, userAgent: BOTO });
  const ids = ["prod/payments/psp-api-key", "prod/payments/settlement-sftp", "prod/crm/salesforce-integration", "prod/ledger/db-master", "prod/kafka/sasl-admin", "prod/hr/payroll-export"];
  const glass = { actorType: "IAMUser" as const, actorName: "kafka-ops-breakglass", arn: `arn:aws:iam::${ACCT}:user/kafka-ops-breakglass`, srcIp: reuse, userAgent: CONSOLE };
  return withIncident([
    ticket({ id: "r6at00", ts: T(-1200), table: "change_request", number: "CHG0063577", state: "Implement", caller: "l.ferreira@nexacorp.com", severity: "informational",
      shortDescription: "Quarterly secret rotation: list and rotate every prod/payments secret (rotation Lambda + verification)", eventType: "policy_modification",
      description: "ServiceNow change CHG0063577 (Implement): quarterly rotation of the prod/payments secrets." }),
    benign(ct({
      id: "r6at01", ts: T(-1180), eventName: "BatchGetSecretValue", eventSource: "secretsmanager.amazonaws.com", srcIp: "10.20.4.40", userAgent: "Boto3/1.35.44 md/Botocore#1.35.44 ua/2.0 os/linux#5.10.227 exec-env/AWS_Lambda_python3.12",
      actorType: "AssumedRole", actorName: "secret-rotation-verify", sessionIssuerName: "secret-rotation-verify", arn: `arn:aws:sts::${ACCT}:assumed-role/secret-rotation-verify/rotation-run-1128`, accessKeyId: "ASIAQ2WN8KT5DEXAMPLE", readOnly: true, severity: "low",
      extra: req({ "filters.key": "name", "filters.values": "prod/payments/" }),
      description: "CloudTrail BatchGetSecretValue for the prod/payments/ secrets by the secret-rotation-verify role from inside the VPC.",
    }), "The rotation job's verification step (CHG0063577): a role made for it, inside the VPC, limited to the prod/payments/ prefix the change names."),

    ct({ ...s(), id: "r6at02", ts: T(0), eventName: "ListSecrets", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail ListSecrets by the SupportEngineer Identity Center session of ${person} from ${atk}, Boto3, at 01:40.` }),
    ct({ ...s(req({ secretIdList: ids.join(",") })), id: "r6at03", ts: T(0.6), eventName: "BatchGetSecretValue", eventSource: "secretsmanager.amazonaws.com", readOnly: true, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail BatchGetSecretValue for ${ids.length} production secrets (payments, CRM, ledger, Kafka, payroll) by the same session from ${atk}.` }),
    ct({ ...s(req({ "encryptionContext.SecretARN": `arn:aws:secretsmanager:eu-west-1:${ACCT}:secret:prod/ledger/db-master-H7kQ2v` })), id: "r6at04", ts: T(0.9), eventName: "Decrypt", eventSource: "kms.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: "CloudTrail KMS Decrypt for the prod/ledger/db-master secret, called by Secrets Manager on behalf of the same session." }),
    ct({ ...s(req({ path: "/payments/", recursive: "true", withDecryption: "true" })), id: "r6at05", ts: T(2), eventName: "GetParametersByPath", eventSource: "ssm.amazonaws.com", readOnly: true, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `CloudTrail GetParametersByPath /payments/ recursive with decryption by the same session from ${atk}.` }),
    gd({
      id: "r6at06", ts: T(3), findingType: "CredentialAccess:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API used to gain access to an AWS environment was invoked in an anomalous way.",
      srcIp: atk, api: "BatchGetSecretValue", serviceName: "secretsmanager.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key,
      severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
      description: `GuardDuty CredentialAccess:IAMUser/AnomalousBehavior for the SupportEngineer session, API BatchGetSecretValue from ${atk}.`,
    }),
    ct({ ...s(req({ secretId: "prod/payments/psp-api-key" })), id: "r6at07", ts: T(4), eventName: "PutSecretValue", eventSource: "secretsmanager.amazonaws.com", outcome: "failure", errorCode: "AccessDeniedException", severity: "medium", mitre: "T1098", tactic: "Persistence",
      description: `CloudTrail PutSecretValue on prod/payments/psp-api-key by the same session from ${atk}, AccessDeniedException.` }),
    ct({ ...glass, id: "r6at08", ts: T(65), eventName: "ConsoleLogin", eventSource: "signin.amazonaws.com", mfa: false, severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail ConsoleLogin by the IAM user kafka-ops-breakglass (its password sits in prod/kafka/sasl-admin) from ${reuse}, no MFA.` }),
    ct({ ...glass, id: "r6at09", ts: T(68), eventName: "CreateLoginProfile", eventSource: "iam.amazonaws.com", severity: "critical", mitre: "T1098", tactic: "Persistence",
      extra: req({ userName: "svc-ledger-reconcile", passwordResetRequired: "false" }),
      description: `CloudTrail CreateLoginProfile for svc-ledger-reconcile (a service user that never had a console password) by kafka-ops-breakglass from ${reuse}.` }),
  ], "inc:r6:aws-secrets-team");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-org-escape, solo: an administrator's key changes the contacts and takes the account out
// ══════════════════════════════════════════════════════════════════════════════
function orgEscapeSolo(): TelemetryEvent[] {
  const T = at("2026-11-22T23:10:00Z");
  const atk = "192.0.2.113";
  const user = "cloud-admin-legacy";
  const key = "AKIAM8QZ3VR6TEXAMPLE";
  const a = { srcIp: atk, actorName: user, arn: `arn:aws:iam::${ACCT}:user/${user}`, accessKeyId: key, userAgent: CLI };
  const adminRole = "AWSReservedSSO_AdministratorAccess_d41f8a20c7e95b16";
  return withIncident([
    benign(ct({
      ...sso(adminRole, "j.chen@nexacorp.com", "ASIAZ4LK7QW2NEXAMPLE", req({ alternateContactType: "SECURITY", emailAddress: "security-team@nexacorp.com" })),
      id: "r6ao00", ts: T(-900), eventName: "PutAlternateContact", eventSource: "account.amazonaws.com", srcIp: OFFICE, userAgent: CONSOLE, severity: "low",
      description: "CloudTrail PutAlternateContact SECURITY set to security-team@nexacorp.com by an AdministratorAccess Identity Center session from the office console.",
    }), "The yearly contact review: an administrator's console session from the office sets the security contact to the company's own security mailbox."),

    ct({ ...a, id: "r6ao01", ts: T(0), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by ${user} (a legacy IAM user with an old access key) from ${atk}, at 23:10.` }),
    ct({ ...a, id: "r6ao02", ts: T(1), eventName: "DescribeOrganization", eventSource: "organizations.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `CloudTrail DescribeOrganization by ${user} from ${atk}.` }),
    ...(["BILLING", "OPERATIONS", "SECURITY"] as const).map((type, i) => ct({
      ...a, id: `r6ao0${3 + i}`, ts: T(3 + i * 0.4), eventName: "PutAlternateContact", eventSource: "account.amazonaws.com", severity: "high", mitre: "T1098", tactic: "Persistence",
      extra: req({ alternateContactType: type, emailAddress: `${type.toLowerCase()}-desk@acct-recovery.example` }),
      description: `CloudTrail PutAlternateContact ${type} set to ${type.toLowerCase()}-desk@acct-recovery.example by ${user} from ${atk}.`,
    })),
    ct({ ...a, id: "r6ao06", ts: T(5), eventName: "StartPrimaryEmailUpdate", eventSource: "account.amazonaws.com", severity: "critical", mitre: "T1098", tactic: "Persistence",
      extra: req({ primaryEmail: "root-owner@acct-recovery.example" }),
      description: `CloudTrail StartPrimaryEmailUpdate (the root user's email) to root-owner@acct-recovery.example by ${user} from ${atk}.` }),
    ct({ ...a, id: "r6ao07", ts: T(8), eventName: "StopLogging", eventSource: "cloudtrail.amazonaws.com", severity: "critical", mitre: "T1685.002", tactic: "Defense Impairment",
      extra: req({ name: `arn:aws:cloudtrail:us-east-1:${ACCT}:trail/account-local-trail` }),
      description: `CloudTrail StopLogging on account-local-trail by ${user} from ${atk}.` }),
    gd({
      id: "r6ao08", ts: T(9), findingType: "Stealth:IAMUser/CloudTrailLoggingDisabled", gdSeverity: 2, title: "AWS CloudTrail trail account-local-trail was disabled.",
      srcIp: atk, api: "StopLogging", serviceName: "cloudtrail.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "IAMUser", userName: user, accessKeyId: key,
      severity: "medium", mitre: "T1685.002", tactic: "Defense Impairment",
      description: `GuardDuty Stealth:IAMUser/CloudTrailLoggingDisabled: ${user} disabled account-local-trail from ${atk}.`,
    }),
    ct({ ...a, id: "r6ao09", ts: T(12), eventName: "LeaveOrganization", eventSource: "organizations.amazonaws.com", severity: "critical", mitre: "T1666", tactic: "Defense Impairment",
      description: `CloudTrail LeaveOrganization by ${user} from ${atk}: the account leaves the company's organization, its service control policies, the organization trail and the delegated GuardDuty. The last record the security account receives from it.` }),
  ], "inc:r6:aws-org-solo");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-org-escape, team: the guardrail that blocked leaving is detached in the management account first
// ══════════════════════════════════════════════════════════════════════════════
function orgEscapeTeam(): TelemetryEvent[] {
  const T = at("2026-11-23T04:20:00Z");
  const atk = "192.0.2.114";
  const role = "AWSReservedSSO_OrgBilling_b5c28e14f9a07d63";
  const person = "r.avraham@nexacorp.com";
  const key = "ASIAL6TQ3WK8MEXAMPLE";
  const s = (more: Extra = {}) => ({ ...sso(role, person, key, more), srcIp: atk, userAgent: BOTO });
  const member = "418772153611";
  const scp = "p-7d2k9q4x";
  const ms = { actorType: "AssumedRole" as const, actorName: "OrganizationAccountAccessRole", sessionIssuerName: "OrganizationAccountAccessRole",
    arn: `arn:aws:sts::${member}:assumed-role/OrganizationAccountAccessRole/${person}`, accessKeyId: "ASIAN2VD8KR5QEXAMPLE", srcIp: atk, userAgent: BOTO, accountId: member, person };
  const orgAdmin = "AWSReservedSSO_OrgAdmin_3f8d1a26c07e9b54";
  return withIncident([
    ticket({ id: "r6aq00", ts: T(-2000), table: "change_request", number: "CHG0063699", state: "Closed Complete", caller: "l.ferreira@nexacorp.com", severity: "informational",
      shortDescription: "Move sandbox account 418772153620 to the Sandbox OU (SCP set changes)", eventType: "policy_modification",
      description: "ServiceNow change CHG0063699 (Closed Complete): sandbox account moved between organizational units." }),
    benign(ct({
      ...sso(orgAdmin, "l.ferreira@nexacorp.com", "ASIAG7KW2PN4DEXAMPLE", req({ accountId: "418772153620", sourceParentId: "ou-k2p9-7hd4w1qz", destinationParentId: "ou-k2p9-sandbox9x" })),
      id: "r6aq01", ts: T(-1990), eventName: "MoveAccount", eventSource: "organizations.amazonaws.com", srcIp: OFFICE, userAgent: CONSOLE, severity: "low",
      description: "CloudTrail MoveAccount 418772153620 to the Sandbox OU by an OrgAdmin Identity Center session from the office console.",
    }), "The approved move of the sandbox account (CHG0063699), from the office console, by the organization administrator the change names."),

    ct({ ...s(req({ filter: "SERVICE_CONTROL_POLICY" })), id: "r6aq02", ts: T(0), eventName: "ListPolicies", eventSource: "organizations.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `CloudTrail ListPolicies (service control policies) by the OrgBilling Identity Center session of ${person} from ${atk}, Boto3, at 04:20.` }),
    ct({ ...s(), id: "r6aq02b", ts: T(0.5), eventName: "ListAccounts", eventSource: "organizations.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `CloudTrail ListAccounts (every member account of the organization) by the same session from ${atk}.` }),
    ct({ ...s(req({ policyId: scp })), id: "r6aq03", ts: T(1), eventName: "DescribePolicy", eventSource: "organizations.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `CloudTrail DescribePolicy ${scp} (deny-leave-organization-and-disable-security) by the same session from ${atk}.` }),
    ct({ ...s(req({ policyId: scp, targetId: member })), id: "r6aq04", ts: T(3), eventName: "DetachPolicy", eventSource: "organizations.amazonaws.com", severity: "critical", mitre: "T1685", tactic: "Defense Impairment",
      description: `CloudTrail DetachPolicy ${scp} from account ${member} by the same session from ${atk}: the guardrail that forbids leaving the organization no longer applies to it.` }),
    ct({ ...s(req({ roleArn: `arn:aws:iam::${member}:role/OrganizationAccountAccessRole`, roleSessionName: person })), id: "r6aq05", ts: T(4), eventName: "AssumeRole", eventSource: "sts.amazonaws.com", severity: "high", mitre: "T1078.004", tactic: "Privilege Escalation",
      description: `CloudTrail AssumeRole into OrganizationAccountAccessRole of member account ${member} by the same session from ${atk}.` }),
    ct({ ...ms, id: "r6aq06", ts: T(6), eventName: "DeleteDetector", eventSource: "guardduty.amazonaws.com", outcome: "failure", errorCode: "BadRequestException", severity: "high", mitre: "T1685", tactic: "Defense Impairment",
      extra: req({ detectorId: "8cc4e1d27b9a05f3e6d0b1a2c3d4e5f6" }),
      description: `CloudTrail DeleteDetector in member account ${member} by the OrganizationAccountAccessRole session from ${atk}: refused, the detector is managed by the delegated administrator.` }),
    ct({ ...ms, id: "r6aq07", ts: T(8), eventName: "PutContactInformation", eventSource: "account.amazonaws.com", severity: "high", mitre: "T1098", tactic: "Persistence",
      extra: req({ "contactInformation.fullName": "Accounts Desk", "contactInformation.phoneNumber": "+1-555-0147" }),
      description: `CloudTrail PutContactInformation in member account ${member} by the OrganizationAccountAccessRole session from ${atk}.` }),
    ct({ ...ms, id: "r6aq08", ts: T(11), eventName: "LeaveOrganization", eventSource: "organizations.amazonaws.com", severity: "critical", mitre: "T1666", tactic: "Defense Impairment",
      description: `CloudTrail LeaveOrganization by member account ${member} (OrganizationAccountAccessRole session from ${atk}). From now on the account sends nothing to the organization trail or the security account.` }),
    sentinel({
      id: "r6aq09", ts: T(13), srcIp: atk, entity: member, severity: "high", eventType: "cloud_api_call", mitre: "T1685", tactic: "Defense Impairment",
      alertName: "Guardrail policy detached, then the target account left the organization",
      detail: "A DetachPolicy on a service control policy is followed within an hour by LeaveOrganization from the account it protected.",
      startTime: T(3), endTime: T(11),
      extendedProperties: { "Member account": member, "Policy id": scp, "Caller IP": atk, "Session": `${role}/${person}` },
      description: `SIEM analytic: service control policy ${scp} detached from account ${member}, which then called LeaveOrganization, both from ${atk}.`,
    }),
  ], "inc:r6:aws-org-team");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-ses-abuse, solo: a newsletter key probes SES, asks for production access, adds a look-alike domain
// ══════════════════════════════════════════════════════════════════════════════
function sesSolo(): TelemetryEvent[] {
  const T = at("2026-11-24T11:05:00Z");
  const atk = "192.0.2.115";
  const user = "svc-newsletter";
  const key = "AKIAP5RW9KD2QEXAMPLE";
  const a = { srcIp: atk, actorName: user, arn: `arn:aws:iam::${ACCT}:user/${user}`, accessKeyId: key, userAgent: "aws-sdk-go-v2/1.32.4 os/linux lang/go#1.23.2 md/GOOS#linux md/GOARCH#amd64 api/ses#1.29.3" };
  return withIncident([
    benign(ct({
      srcIp: "10.20.6.14", actorName: user, arn: `arn:aws:iam::${ACCT}:user/${user}`, accessKeyId: key, userAgent: "aws-sdk-php/3.325.2 OS/Linux/5.15.0 lang/php#8.3.12",
      id: "r6ap00", ts: T(-60), eventName: "GetSendQuota", eventSource: "ses.amazonaws.com", readOnly: true, severity: "informational",
      description: "CloudTrail GetSendQuota by svc-newsletter from the marketing server's address, PHP SDK, before the weekly newsletter run.",
    }), "The newsletter platform checking its quota before the weekly send: its own server, its own SDK, the hour it runs every week."),

    ct({ ...a, id: "r6ap01", ts: T(0), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetCallerIdentity by svc-newsletter from ${atk}, Go SDK. The key has run only from the marketing server.` }),
    ...(["us-east-1", "eu-west-1", "ap-southeast-2"] as const).map((region, i) => ct({
      ...a, id: `r6ap0${2 + i}`, ts: T(1 + i * 0.3), region, eventName: "GetSendQuota", eventSource: "ses.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail GetSendQuota in ${region} by svc-newsletter from ${atk}.`,
    })),
    ct({ ...a, id: "r6ap05", ts: T(2), eventName: "ListIdentities", eventSource: "ses.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail ListIdentities (the verified sending domains and addresses) by svc-newsletter from ${atk}.` }),
    gd({
      id: "r6ap05b", ts: T(2.2), findingType: "Discovery:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API commonly used to discover information in an AWS environment was invoked in an anomalous way.",
      srcIp: atk, api: "ListIdentities", serviceName: "ses.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "IAMUser", userName: user, accessKeyId: key,
      severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `GuardDuty Discovery:IAMUser/AnomalousBehavior for IAM user ${user}, API ListIdentities (SES) from ${atk}.`,
    }),
    ct({ ...a, id: "r6ap06", ts: T(2.5), eventName: "GetAccount", eventSource: "ses.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail GetAccount (SES v2: sending status, sandbox or production) by svc-newsletter from ${atk}.` }),
    ct({ ...a, id: "r6ap07", ts: T(6), region: "ap-southeast-2", eventName: "CreateEmailIdentity", eventSource: "ses.amazonaws.com", severity: "high", mitre: "T1583.001", tactic: "Resource Development",
      extra: req({ emailIdentity: "nexacorp-billing.example" }),
      description: `CloudTrail CreateEmailIdentity nexacorp-billing.example in ap-southeast-2 (a region the company does not use) by svc-newsletter from ${atk}.` }),
    ct({ ...a, id: "r6ap08", ts: T(9), region: "ap-southeast-2", eventName: "PutAccountDetails", eventSource: "ses.amazonaws.com", severity: "high", mitre: "T1078.004", tactic: "Resource Development",
      extra: req({ mailType: "TRANSACTIONAL", websiteURL: "https://nexacorp-billing.example", productionAccessEnabled: "true" }),
      description: `CloudTrail PutAccountDetails in ap-southeast-2 by svc-newsletter from ${atk}: a request for production sending access, mail type transactional, website nexacorp-billing.example.` }),
    ct({ ...a, id: "r6ap09", ts: T(10), region: "eu-west-1", eventName: "UpdateAccountSendingEnabled", eventSource: "ses.amazonaws.com", severity: "high", mitre: "T1078.004", tactic: "Impact",
      extra: req({ enabled: "true" }),
      description: `CloudTrail UpdateAccountSendingEnabled true in eu-west-1 (sending had been paused there) by svc-newsletter from ${atk}.` }),
    ticket({ id: "r6ap10", ts: T(95), table: "incident", number: "INC0071440", state: "New", caller: "s.patel@nexacorp.com", severity: "medium",
      shortDescription: "Customers forwarding 'overdue invoice' mails sent from our domain through Amazon SES (eu-west-1), not from the billing system", eventType: "policy_modification", mitre: "T1566.002", tactic: "Initial Access",
      description: "ServiceNow incident INC0071440 (New): customers report 'overdue invoice' mails from the company's domain that left through Amazon SES in eu-west-1." }),
  ], "inc:r6:aws-ses-solo");
}

// ══════════════════════════════════════════════════════════════════════════════
// family cloud-aws-ses-abuse, team: SMTP credentials minted from a stolen session, sending in a region nobody watches
// ══════════════════════════════════════════════════════════════════════════════
function sesTeam(): TelemetryEvent[] {
  const T = at("2026-11-25T19:30:00Z");
  const atk = "192.0.2.116";
  const role = "AWSReservedSSO_MarketingOps_4c71e9b2a08d5f36";
  const person = "m.levi@nexacorp.com";
  const key = "ASIAR3KQ7WN5PEXAMPLE";
  const s = (more: Extra = {}) => ({ ...sso(role, person, key, more), srcIp: atk, userAgent: CONSOLE });
  const smtp = "ses-smtp-user.20261125-193412";
  return withIncident([
    benign(ct({
      ...sso(role, "r.avraham@nexacorp.com", "ASIAD6MZ2KT8WEXAMPLE", req({ userName: "ses-smtp-user.20261103-101507" })),
      id: "r6aa00", ts: T(-4000), eventName: "CreateUser", eventSource: "iam.amazonaws.com", srcIp: OFFICE, userAgent: CONSOLE, severity: "low",
      description: "CloudTrail CreateUser ses-smtp-user.20261103-101507 by a MarketingOps Identity Center session from the office console: the SES console's 'Create SMTP credentials' button.",
    }), "SMTP credentials for the events platform, created with the SES console button from the office (the console names the user ses-smtp-user.<date>), during the platform's go-live week."),

    ct({ ...s(), id: "r6aa01", ts: T(0), region: "sa-east-1", eventName: "GetAccount", eventSource: "ses.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail GetAccount (SES v2) in sa-east-1 by the MarketingOps Identity Center session of ${person} from ${atk}, a browser, at 19:30.` }),
    ct({ ...s(), id: "r6aa02", ts: T(1), region: "sa-east-1", eventName: "ListEmailIdentities", eventSource: "ses.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
      description: `CloudTrail ListEmailIdentities in sa-east-1 by the same session from ${atk}.` }),
    ct({ ...s(req({ emailIdentity: "mail.nexacorp-payroll.example" })), id: "r6aa03", ts: T(3), region: "sa-east-1", eventName: "CreateEmailIdentity", eventSource: "ses.amazonaws.com", severity: "high", mitre: "T1583.001", tactic: "Resource Development",
      description: `CloudTrail CreateEmailIdentity mail.nexacorp-payroll.example in sa-east-1 by the same session from ${atk}.` }),
    ct({ ...s(req({ userName: smtp })), id: "r6aa04", ts: T(6), eventName: "CreateUser", eventSource: "iam.amazonaws.com", severity: "high", mitre: "T1136.003", tactic: "Persistence",
      description: `CloudTrail CreateUser ${smtp} by the same session from ${atk}: the SES console's SMTP credentials flow.` }),
    ct({ ...s(req({ userName: smtp, policyName: "AmazonSesSendingAccess", policyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendRawEmail","Resource":"*"}]}` })), id: "r6aa05", ts: T(6.2), eventName: "PutUserPolicy", eventSource: "iam.amazonaws.com", severity: "high", mitre: "T1098", tactic: "Persistence",
      description: `CloudTrail PutUserPolicy AmazonSesSendingAccess (ses:SendRawEmail on *) on ${smtp} by the same session from ${atk}.` }),
    ct({ ...s(req({ userName: smtp })), id: "r6aa06", ts: T(6.4), eventName: "CreateAccessKey", eventSource: "iam.amazonaws.com", severity: "high", mitre: "T1098.001", tactic: "Persistence",
      description: `CloudTrail CreateAccessKey for ${smtp} by the same session from ${atk}: the key the SMTP password is derived from.` }),
    gd({
      id: "r6aa07", ts: T(8), findingType: "Persistence:IAMUser/AnomalousBehavior", gdSeverity: 5, title: "An API commonly used to maintain unauthorized access to an AWS environment was invoked in an anomalous way.",
      srcIp: atk, api: "CreateAccessKey", serviceName: "iam.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey", userType: "AssumedRole", userName: role, accessKeyId: key,
      severity: "medium", mitre: "T1098.001", tactic: "Persistence",
      description: `GuardDuty Persistence:IAMUser/AnomalousBehavior for the MarketingOps session, API CreateAccessKey from ${atk}.`,
    }),
    ct({ ...s(req({ sendingEnabled: "true" })), id: "r6aa08", ts: T(12), region: "sa-east-1", eventName: "PutAccountSendingAttributes", eventSource: "ses.amazonaws.com", severity: "high", mitre: "T1078.004", tactic: "Impact",
      description: `CloudTrail PutAccountSendingAttributes sendingEnabled true in sa-east-1 by the same session from ${atk}.` }),
    ct({ id: "r6aa09", ts: T(14), region: "sa-east-1", eventName: "GetSendQuota", eventSource: "ses.amazonaws.com", srcIp: "192.0.2.117", userAgent: "Python-urllib/3.11", actorType: "IAMUser", actorName: smtp,
      arn: `arn:aws:iam::${ACCT}:user/${smtp}`, accessKeyId: "AKIAW7QN4ZT2KEXAMPLE", readOnly: true, severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `CloudTrail GetSendQuota in sa-east-1 by the new user ${smtp} from 192.0.2.117. SMTP sends themselves are not CloudTrail events: SES sending metrics and the reputation dashboard show them.` }),
  ], "inc:r6:aws-ses-team");
}

export const CLOUD_R6_AWS_STORIES: AiStoryDef[] = [
  { id: "cloud-aws-sso-device-code-analyst", title: "Identity Center Session Opened from the Office, Then Used from Another Address to Read S3",
    complexity: "core", family: "cloud-aws-sso-device-code", mode: "solo", companies: AWS_SHOPS, events: authoredFor("rocketstack", ssoDeviceCodeSolo()) },
  { id: "cloud-aws-sso-device-code-admin", title: "Administrator Identity Center Session Creates a Role an Outside Account Assumes",
    complexity: "advanced", family: "cloud-aws-sso-device-code", mode: "team", companies: AWS_SHOPS, events: authoredFor("rocketstack", ssoDeviceCodeTeam()) },
  { id: "cloud-aws-lambda-url-new-function", title: "Build Key Creates a Lambda Function with a Public URL, Then the Function Reads Secrets",
    complexity: "core", family: "cloud-aws-lambda-url-backdoor", mode: "solo", companies: AWS_SHOPS, events: authoredFor("rocketstack", lambdaUrlSolo()) },
  { id: "cloud-aws-lambda-url-changed-function", title: "Queue Consumer Function Gets New Code, an Outside Layer and a Public URL, Then Creates a User",
    complexity: "advanced", family: "cloud-aws-lambda-url-backdoor", mode: "team", companies: AWS_SHOPS, events: authoredFor("rocketstack", lambdaUrlTeam()) },
  { id: "cloud-aws-secrets-instance-role", title: "Instance Role Credentials Used Outside AWS Read Secrets and Parameters, Then a Stored Key Appears",
    complexity: "core", family: "cloud-aws-secrets-harvest", mode: "solo", companies: AWS_SHOPS, events: authoredFor("rocketstack", secretsSolo()) },
  { id: "cloud-aws-secrets-batch-night", title: "Night-Time BatchGetSecretValue Across Production, Then a Break-Glass User Signs In",
    complexity: "advanced", family: "cloud-aws-secrets-harvest", mode: "team", companies: AWS_SHOPS, events: authoredFor("rocketstack", secretsTeam()) },
  { id: "cloud-aws-org-escape-legacy-key", title: "Legacy Administrator Key Changes Account Contacts, Stops a Trail and Calls LeaveOrganization",
    complexity: "core", family: "cloud-aws-org-escape", mode: "solo", companies: AWS_SHOPS, events: authoredFor("rocketstack", orgEscapeSolo()) },
  { id: "cloud-aws-org-escape-scp-detach", title: "Service Control Policy Detached from a Member Account, Which Then Leaves the Organization",
    complexity: "advanced", family: "cloud-aws-org-escape", mode: "team", companies: AWS_SHOPS, events: authoredFor("rocketstack", orgEscapeTeam()) },
  { id: "cloud-aws-ses-newsletter-key", title: "Newsletter Key Probes SES in Three Regions and Requests Production Sending",
    complexity: "foundation", family: "cloud-aws-ses-abuse", mode: "solo", companies: AWS_SHOPS, events: authoredFor("rocketstack", sesSolo()) },
  { id: "cloud-aws-ses-smtp-credentials", title: "SMTP Credentials Created from a Marketing Session While SES Is Enabled in an Unused Region",
    complexity: "advanced", family: "cloud-aws-ses-abuse", mode: "team", companies: AWS_SHOPS, events: authoredFor("rocketstack", sesTeam()) },
];
