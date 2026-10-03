/**
 * Amazon GuardDuty findings — native source module.
 *
 * Card: docs/log-schemas/cloud-aws-guardduty.md. Native format = the bare finding
 * object (the `GetFindings` / export shape), nested exactly as GuardDuty produces
 * it. The EventBridge envelope (`detail-type:"GuardDuty Finding"`, finding in
 * `detail`) is a second supported kind. No `aws.guardduty.*` ECS flattening, no
 * Wazuh `data.*` envelope.
 *
 * `resource` and `service` are polymorphic (one detail object per resourceType;
 * one action sub-object per actionType) — they are declared as open sub-objects.
 * The finding `id` / `detectorId` are stable per company so a finding correlates
 * with the CloudTrail events behind it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";
import {
  awsAccountId, awsPartition, awsPrincipal, awsRegion, awsRoleId, awsServiceFor, awsSessionKey, awsUserId, awsUserKey,
  entitySeed, isoMs, isPrivateIp, rehomeArns, rn, rs,
} from "./cloud-shared";
import { countryInfo } from "./_identity-common";

const findingKind: KindSchema = {
  required: ["schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource", "service", "severity", "createdAt", "updatedAt", "title", "description"],
  optional: [],
  openPrefixes: ["resource", "service"],
};

const kinds: Record<string, KindSchema> = {
  Finding: findingKind,
  FindingEvent: {
    required: ["version", "id", "detail-type", "source", "account", "time", "region", "detail"],
    optional: ["resources[]", "resources"],
    openPrefixes: ["detail"],
  },
};

const schema: SourceSchema = {
  sourceId: "aws_guardduty",
  category: "cloud_detection",
  card: "cloud-aws-guardduty.md",
  product: "Amazon GuardDuty",
  format: "json",
  vendorMatch: ["guardduty"],
  telemetrySources: ["cloudtrail", "siem"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record["detail-type"] === "GuardDuty Finding" && record["detail"]) return "FindingEvent";
  if (record["schemaVersion"] && record["service"] && record["type"]) return "Finding";
  return null;
}

// ── conversion ────────────────────────────────────────────────────────────────

const G = (ev: TelemetryEvent, name: string) => rs(ev.raw, `aws.guardduty.${name}`, `aws.guardduty.finding.${name}`);
const GN = (ev: TelemetryEvent, name: string) => rn(ev.raw, `aws.guardduty.${name}`, `aws.guardduty.finding.${name}`);

/** Infer resourceType from the finding type when the event didn't state one. */
function resourceTypeFor(type: string): string {
  if (/:S3\b|S3\//.test(type)) return "S3Bucket";
  if (/:EC2\b|EC2\//.test(type)) return "Instance";
  if (/Kubernetes|EKS/.test(type)) return "EKSCluster";
  return "AccessKey";
}
/** Infer actionType from the finding type. */
function actionTypeFor(type: string): string {
  if (/!DNS|DNSDataExfiltration|C&CActivity.*DNS/.test(type)) return "DNS_REQUEST";
  if (/Kubernetes/.test(type)) return "KUBERNETES_API_CALL";
  if (/PortProbe|PortSweep|PortScan/.test(type)) return "PORT_PROBE";
  if (/SSHBruteForce|RDPBruteForce|NetworkConnection|C&CActivity|Backdoor:EC2|TorClient/.test(type)) return "NETWORK_CONNECTION";
  if (/RDS/.test(type)) return "RDS_LOGIN_ATTEMPT";
  return "AWS_API_CALL";
}
/** The API a finding of this type is raised on, when neither the finding nor the event names the call. */
function defaultApiFor(type: string): string {
  const rules: [RegExp, string][] = [
    [/InstanceCredentialExfiltration|Recon:IAMUser|MaliciousIPCaller|TorIPCaller/, "GetCallerIdentity"],
    [/PrivilegeEscalation:IAMUser/, "AttachUserPolicy"],
    [/Persistence:IAMUser/, "CreateAccessKey"],
    [/CredentialAccess:IAMUser/, "GetSecretValue"],
    [/Discovery:IAMUser/, "ListUsers"],
    [/Stealth:IAMUser\/CloudTrailLoggingDisabled/, "StopLogging"],
    [/Stealth:IAMUser\/PasswordPolicyChange/, "UpdateAccountPasswordPolicy"],
    [/ConsoleLoginSuccess/, "ConsoleLogin"],
    [/Policy:S3\/Bucket(Anonymous|Public)AccessGranted/, "PutBucketPolicy"],
    [/Policy:S3\/BucketBlockPublicAccessDisabled/, "DeleteBucketPublicAccessBlock"],
    [/Stealth:S3\/ServerAccessLoggingDisabled/, "PutBucketLogging"],
    [/Impact:S3/, "DeleteObject"],
    [/Discovery:S3/, "ListObjects"],
    [/Exfiltration:S3|S3\//, "GetObject"],
  ];
  return rules.find(([re]) => re.test(type))?.[1] ?? "GetCallerIdentity";
}

/** Hosting / cloud networks a geo label names in parentheses ("Amsterdam (DigitalOcean)"). */
const HOSTING_ASN: [RegExp, number, string][] = [
  [/DigitalOcean/i, 14061, "DIGITALOCEAN-ASN"], [/AWS|Amazon/i, 16509, "AMAZON-02"], [/GCP|Google/i, 396982, "GOOGLE-CLOUD-PLATFORM"],
  [/Cloudflare/i, 13335, "CLOUDFLARENET"], [/GitHub/i, 36459, "GITHUB"], [/Fastly/i, 54113, "FASTLY"], [/OVH/i, 16276, "OVH SAS"], [/Hetzner/i, 24940, "Hetzner Online GmbH"],
  [/M247/i, 9009, "M247 Europe SRL"], [/Scaleway/i, 12876, "SCALEWAY S.A.S."], [/Serverius/i, 50673, "Serverius Holding B.V."], [/Selectel/i, 49505, "Selectel Ltd."],
];

/** GuardDuty `remoteIpDetails` — the authored address with ITS geo (event geo → authored finding geo → the platform's per-IP map). */
function remoteIpDetailsOf(ev: TelemetryEvent, ip: string): Record<string, unknown> {
  const R = (k: string) => G(ev, `service.action.awsApiCallAction.remoteIpDetails.${k}`) ?? G(ev, `service.action.networkConnectionAction.remoteIpDetails.${k}`);
  if (isPrivateIp(ip)) return { ipAddressV4: ip };
  const known = knownGeoForIp(ip);
  const countryRaw = ev.geo?.country ?? R("country.countryName") ?? rs(ev.raw, "GeoLocation.country_name", "source.geo.country_name") ?? known?.country;
  const ci = countryInfo(countryRaw ?? rs(ev.raw, "source.geo.country_iso_code"));
  const cityLabel = ev.geo?.city ?? R("city.cityName") ?? rs(ev.raw, "GeoLocation.city_name", "source.geo.city_name") ?? known?.city ?? ci?.city;
  const host = /\(([^)]+)\)/.exec(cityLabel ?? "")?.[1];
  const city = cityLabel?.replace(/\s*\([^)]*\)\s*$/, "").replace(/^Tor Exit — Unknown$/, "");
  const authoredOrg = R("organization.asnOrg") ?? R("organization.isp");
  // One network per address: the authored operator wins, then a hosting provider the geo label names, then the country's default carrier.
  const hosting = HOSTING_ASN.find(([re]) => (authoredOrg && re.test(authoredOrg)) || (!authoredOrg && host && re.test(host)));
  const lat = ev.geo?.latitude ?? GN(ev, "service.action.awsApiCallAction.remoteIpDetails.geoLocation.lat") ?? known?.lat ?? ci?.lat;
  const lon = ev.geo?.longitude ?? GN(ev, "service.action.awsApiCallAction.remoteIpDetails.geoLocation.lon") ?? known?.lon ?? ci?.lon;
  const asn = R("organization.asn") ?? (hosting ? String(hosting[1]) : !authoredOrg && ci ? String(ci.asn) : undefined);
  const asnOrg = authoredOrg ?? hosting?.[2] ?? ci?.asOrg.toUpperCase();
  const isp = R("organization.isp") ?? authoredOrg ?? (hosting ? hosting[2] : ci?.isp);
  const out: Record<string, unknown> = { ipAddressV4: ip };
  if (asn || asnOrg) out.organization = { ...(asn ? { asn } : {}), asnOrg: asnOrg ?? "", isp: isp ?? asnOrg ?? "", org: isp ?? asnOrg ?? "" };
  if (countryRaw || ci) out.country = { countryName: ci?.name ?? countryRaw, ...(ci ? { countryCode: ci.iso } : {}) };
  if (city) out.city = { cityName: city };
  if (lat !== undefined && lon !== undefined) out.geoLocation = { lat, lon };
  return out;
}

/** accessKeyDetails of the principal behind the finding — the same key / principal id the CloudTrail rows of that principal show. */
function accessKeyDetailsOf(ev: TelemetryEvent, ctx: NativeCtx, acct: string, type: string): Record<string, unknown> {
  let pr = awsPrincipal(ev, ctx, acct);
  // Instance credentials are always a role session (ASIA), never an IAM user's long-term key.
  if (/InstanceCredentialExfiltration/.test(type) && pr.type !== "AssumedRole") pr = { ...pr, type: "AssumedRole", roleName: pr.userName && pr.userName !== "unknown" ? pr.userName : "unknown-role", session: undefined, fallback: true };
  if (pr.type === "AssumedRole") {
    const role = pr.roleName ?? "unknown-role";
    const session = pr.session ?? (pr.principalId?.includes(":") ? pr.principalId.split(":").slice(1).join(":") : role);
    return {
      accessKeyId: pr.accessKeyId ?? awsSessionKey(ctx, role, session),
      principalId: pr.principalId ?? `${awsRoleId(ctx, role)}:${session}`,
      userType: "AssumedRole",
      userName: role,
    };
  }
  if (pr.type === "Root") return { accessKeyId: pr.accessKeyId ?? "", principalId: acct, userType: "Root", userName: "Root" };
  const name = pr.userName ?? "unknown";
  return { accessKeyId: pr.accessKeyId ?? awsUserKey(ctx, name), principalId: pr.principalId ?? awsUserId(ctx, name), userType: pr.type === "FederatedUser" ? "FederatedUser" : "IAMUser", userName: name };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const type = G(ev, "type");
  if (!type) return null; // only GuardDuty findings belong here

  const acct = awsAccountId(ev, ctx);
  const region = awsRegion(ev);
  const part = awsPartition(region);
  const id = G(ev, "id") ?? ctx.hex(entitySeed(ctx, "gdfinding", ev.id), 32);
  const detectorId = G(ev, "service.detectorId") ?? G(ev, "service.detector_id") ?? ctx.hex(entitySeed(ctx, "gddetector", `${acct}:${region}`), 32);
  const sev = GN(ev, "severity") ?? (ev.severity === "critical" ? 9 : ev.severity === "high" ? 8 : ev.severity === "medium" ? 5 : 2);
  const ip = ev.src_ip ?? ev.dst_ip ?? G(ev, "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4");
  const createdAt = G(ev, "createdAt") ?? isoMs(ev.ts);
  const updatedAt = G(ev, "updatedAt") ?? isoMs(ev.ts);

  const resourceType = G(ev, "resource.resourceType") ?? resourceTypeFor(type);
  const actionType = G(ev, "service.action.actionType") ?? actionTypeFor(type);
  const hasPrincipal = !!(G(ev, "resource.accessKeyDetails.accessKeyId") || G(ev, "resource.accessKeyDetails.userName") || rs(ev.raw, "aws.cloudtrail.userIdentity.arn", "aws.cloudtrail.userIdentity.userName") || ev.user_email);

  // ── resource ──
  const resource: Record<string, unknown> = { resourceType };
  const bucket = G(ev, "resource.s3BucketDetails.name") ?? G(ev, "resource.s3BucketDetails.0.name")
    ?? rs(ev.raw, "aws.cloudtrail.requestParameters.bucketName", "s3.bucket", "aws.s3.bucket.name") ?? ev.cloud?.resource;
  if (resourceType === "AccessKey") {
    resource.accessKeyDetails = accessKeyDetailsOf(ev, ctx, acct, type);
  } else if (resourceType === "Instance") {
    const iid = G(ev, "resource.instanceDetails.instanceId") ?? ("i-" + ctx.hex(entitySeed(ctx, "gdinst", ev.hostname ?? ev.id), 17));
    const privIp = ev.src_ip && isPrivateIp(ev.src_ip) ? ev.src_ip : ev.dst_ip && isPrivateIp(ev.dst_ip) ? ev.dst_ip : "10.0.3.47";
    resource.instanceDetails = {
      instanceId: iid,
      instanceType: G(ev, "resource.instanceDetails.instanceType") ?? "t3.large",
      launchTime: isoMs(ev.ts),
      iamInstanceProfile: { arn: `arn:${part}:iam::${acct}:instance-profile/${(ev.hostname ?? "ec2").toLowerCase()}-profile`, id: "AIPA" + ctx.hex(entitySeed(ctx, "gdprof", iid), 17).toUpperCase() },
      networkInterfaces: [{ privateIpAddress: privIp, publicIp: ip && !isPrivateIp(ip) ? ip : "", subnetId: "subnet-" + ctx.hex(iid + ":sub", 17), vpcId: "vpc-" + ctx.hex(acct + ":vpc", 17) }],
      ...(ev.hostname ? { tags: [{ key: "Name", value: ev.hostname }] } : {}),
      instanceState: "running",
      availabilityZone: G(ev, "resource.instanceDetails.availabilityZone") ?? `${region}a`,
      imageId: G(ev, "resource.instanceDetails.imageId") ?? "ami-" + ctx.hex(iid + ":ami", 17),
    };
  } else if (resourceType === "S3Bucket") {
    const name = bucket ?? `${ctx.org}-customer-data`;
    const perm = G(ev, "resource.s3BucketDetails.publicAccess.effectivePermission") ?? G(ev, "resource.s3BucketDetails.0.publicAccess.effectivePermission") ?? (/Anonymous|PublicAccess/.test(type) ? "PUBLIC" : "NOT_PUBLIC");
    resource.s3BucketDetails = [{ arn: `arn:${part}:s3:::${name}`, name, type: "Destination", owner: { id: ctx.hex(entitySeed(ctx, "gds3owner", acct), 64) }, publicAccess: { effectivePermission: perm } }];
    // S3 findings also name the principal that made the calls.
    if (hasPrincipal) resource.accessKeyDetails = accessKeyDetailsOf(ev, ctx, acct, type);
  } else { // EKSCluster
    const cluster = `${ctx.org}-prod`;
    resource.eksClusterDetails = { name: cluster, arn: `arn:${part}:eks:${region}:${acct}:cluster/${cluster}`, status: "ACTIVE", tags: [] };
    resource.kubernetesDetails = { kubernetesUserDetails: { username: "kubernetes-admin", groups: ["system:masters", "system:authenticated"] }, kubernetesWorkloadDetails: { name: "pod", type: "pods", namespace: "kube-system" } };
  }

  // ── service.action ──
  const remoteIpDetails = ip ? remoteIpDetailsOf(ev, ip) : undefined;
  const action: Record<string, unknown> = { actionType };
  if (actionType === "DNS_REQUEST") {
    action.dnsRequestAction = { domain: G(ev, "service.action.dnsRequestAction.domain") ?? rs(ev.raw, "network.domain", "dns.query", "dns.question.name") ?? ev.network?.domain ?? "unknown", protocol: G(ev, "service.action.dnsRequestAction.protocol") ?? "UDP", blocked: false };
  } else if (actionType === "KUBERNETES_API_CALL") {
    action.kubernetesApiCallAction = { requestUri: "/api/v1/namespaces/kube-system/pods/exec", verb: "create", sourceIPs: ip ? [ip] : [], userAgent: "kubectl/v1.30.0 (linux/amd64)", statusCode: 101, ...(remoteIpDetails ? { remoteIpDetails } : {}) };
  } else if (actionType === "NETWORK_CONNECTION") {
    action.networkConnectionAction = { connectionDirection: "OUTBOUND", protocol: "TCP", blocked: false, remotePortDetails: { port: ev.dst_port ?? 443, portName: ev.dst_port === 22 ? "SSH" : ev.dst_port === 3389 ? "RDP" : (ev.dst_port ?? 443) === 443 ? "HTTPS" : "Unknown" }, localIpDetails: { ipAddressV4: (resource.instanceDetails as { networkInterfaces?: { privateIpAddress: string }[] } | undefined)?.networkInterfaces?.[0]?.privateIpAddress ?? "10.0.3.47" }, ...(remoteIpDetails ? { remoteIpDetails } : {}) };
  } else { // AWS_API_CALL — the call actually made (finding → event → type default)
    const api = G(ev, "service.action.awsApiCallAction.api") ?? ev.cloud?.api_call ?? rs(ev.raw, "aws.cloudtrail.eventName") ?? defaultApiFor(type);
    action.awsApiCallAction = {
      api,
      serviceName: G(ev, "service.action.awsApiCallAction.serviceName") ?? awsServiceFor(api),
      callerType: G(ev, "service.action.awsApiCallAction.callerType") ?? "Remote IP",
      ...(bucket && resourceType === "S3Bucket" ? { affectedResources: { "AWS::S3::Bucket": bucket } } : {}),
      ...(remoteIpDetails ? { remoteIpDetails } : {}),
    };
  }

  const service: Record<string, unknown> = {
    serviceName: "guardduty",
    detectorId,
    action,
    resourceRole: resourceType === "Instance" && actionType !== "PORT_PROBE" ? "ACTOR" : "TARGET",
    additionalInfo: {},
    evidence: null,
    eventFirstSeen: G(ev, "service.eventFirstSeen") ?? isoMs(ev.ts),
    eventLastSeen: G(ev, "service.eventLastSeen") ?? isoMs(ev.ts),
    archived: false,
    count: GN(ev, "service.count") ?? 1,
  };

  const record: Record<string, unknown> = {
    schemaVersion: G(ev, "schemaVersion") ?? "2.0",
    accountId: acct,
    region,
    partition: part,
    id,
    arn: G(ev, "arn") ?? `arn:${part}:guardduty:${region}:${acct}:detector/${detectorId}/finding/${id}`,
    type,
    resource,
    service,
    severity: sev,
    createdAt,
    updatedAt,
    title: G(ev, "title") ?? type,
    // GuardDuty's own finding text (authored raw, else keyed to the type) — not the
    // scenario narrative, which states the conclusion (L-05).
    description: G(ev, "description") ?? guardDutyDescription(type, resourceType),
  };

  return { sourceId: "aws_guardduty", kind: "Finding", format: "json", record: rehomeArns(record, part, acct, region), timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "aws_guardduty.high_severity",
    title: "High / critical GuardDuty finding",
    sourceId: "aws_guardduty", severity: "high", mitre: [],
    description: "Any GuardDuty finding with severity ≥ 7 (High) — GuardDuty's own confidence that this is a real threat, to be triaged ahead of lower-severity noise.",
    logic: "SPL: severity>=7",
    match: { field: "severity", op: "gte", value: 7 },
    falsePositives: ["Sample / demo findings (additionalInfo.sample=true) — exclude them."],
  },
  {
    id: "aws_guardduty.instance_credential_exfil",
    title: "EC2 instance credentials used outside AWS",
    sourceId: "aws_guardduty", severity: "high", mitre: ["T1552.005", "T1078.004"],
    description: "InstanceCredentialExfiltration — credentials minted for an EC2 instance role are being used from an external IP, i.e. stolen off the host (SSRF / IMDS theft / container escape).",
    logic: "SPL: type=\"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*\"",
    match: { field: "type", op: "icontains", value: "InstanceCredentialExfiltration" },
    falsePositives: ["A VPN / NAT change that makes legitimate instance traffic appear to originate outside AWS."],
  },
  {
    id: "aws_guardduty.s3_exfil_or_public",
    title: "S3 data exfiltration or public exposure",
    sourceId: "aws_guardduty", severity: "high", mitre: ["T1530"],
    description: "Exfiltration:S3 or Policy:S3/Bucket*Access — bulk reads from, or public exposure of, an S3 bucket flagged by GuardDuty.",
    logic: "SPL: type IN (\"Exfiltration:S3/*\",\"Policy:S3/Bucket*Access*\")",
    match: { any: [{ field: "type", op: "icontains", value: "Exfiltration:S3" }, { field: "type", op: "regex", value: "Policy:S3/Bucket.*Access" }] },
    falsePositives: ["A bucket intentionally made public for static hosting (confirm data classification)."],
  },
  {
    id: "aws_guardduty.privilege_escalation",
    title: "IAM privilege escalation / trust-policy change",
    sourceId: "aws_guardduty", severity: "high", mitre: ["T1098"],
    description: "PrivilegeEscalation findings — anomalous IAM API sequences (CreateUser/AttachPolicy) or a resource trust-policy granting broad/external access.",
    logic: "SPL: type=\"PrivilegeEscalation:*\"",
    match: { field: "type", op: "icontains", value: "PrivilegeEscalation" },
    falsePositives: ["Legitimate admin bootstrapping a new account's IAM through IaC."],
  },
  {
    id: "aws_guardduty.bedrock_logging_disabled",
    title: "Bedrock model logging disabled (GuardDuty)",
    sourceId: "aws_guardduty", severity: "medium", mitre: ["T1562.008"],
    description: "DefenseEvasion:IAMUser/AnomalousBehavior on DeleteModelInvocationLoggingConfiguration — GuardDuty's anomaly detection firing on the call that turns Bedrock model-invocation logging off, the LLMjacking defense-evasion step.",
    logic: "SPL: type=\"DefenseEvasion:IAMUser/AnomalousBehavior\" service.action.awsApiCallAction.api=DeleteModelInvocationLoggingConfiguration",
    match: { all: [{ field: "type", op: "icontains", value: "DefenseEvasion:IAMUser/AnomalousBehavior" }, { field: "service.action.awsApiCallAction.api", op: "eq", value: "DeleteModelInvocationLoggingConfiguration" }] },
    falsePositives: ["Platform team re-configuring Bedrock logging via console."],
  },
  {
    id: "aws_guardduty.kubernetes",
    title: "Kubernetes / EKS attacker behaviour",
    sourceId: "aws_guardduty", severity: "medium", mitre: ["T1609", "T1610"],
    description: "Kubernetes findings — exec into kube-system, anonymous access, privileged workload deployment, or secrets access on an EKS cluster.",
    logic: "SPL: type=\"*:Kubernetes/*\"",
    match: { field: "type", op: "icontains", value: "Kubernetes" },
    falsePositives: ["An operator legitimately exec-ing into a system pod to debug (rare; confirm the user)."],
  },
  {
    id: "aws_guardduty.attack_sequence",
    title: "Correlated attack sequence (Extended Threat Detection)",
    sourceId: "aws_guardduty", severity: "critical", mitre: [],
    description: "AttackSequence findings bundle several correlated signals into one Critical finding — a confirmed multi-step intrusion, not a single anomaly.",
    logic: "SPL: type=\"AttackSequence:*\" OR severity>=9",
    match: { any: [{ field: "type", op: "startsWith", value: "AttackSequence" }, { field: "severity", op: "gte", value: 9 }] },
    falsePositives: ["None expected; AttackSequence is high-confidence by design."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };

/** GuardDuty-style finding description from the finding type (ThreatPurpose:ResourceTypeAffected/ThreatFamilyName). */
function guardDutyDescription(type: string, resourceType: string): string {
  const [purpose = "Finding", rest = ""] = type.split(":");
  const family = rest.split("/")[1]?.split("!")[0] ?? rest;
  const subject = resourceType === "Instance" ? "An EC2 instance" : resourceType === "AccessKey" ? "An IAM principal" :
    resourceType === "S3Bucket" ? "An S3 bucket" : resourceType === "EKSCluster" ? "An EKS cluster" : `A ${resourceType} resource`;
  const what = family.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/\./g, " ").toLowerCase();
  return `${subject} in your AWS environment is involved in activity GuardDuty classifies as ${purpose} (${what || type}).`;
}
