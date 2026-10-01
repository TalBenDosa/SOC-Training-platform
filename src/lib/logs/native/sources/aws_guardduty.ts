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
import { awsAccountId, awsRegion, entitySeed, isoMs, rn, rs, rv } from "./cloud-shared";

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
  if (/SSHBruteForce|RDPBruteForce|NetworkConnection|C&CActivity|Backdoor:EC2/.test(type)) return "NETWORK_CONNECTION";
  if (/RDS/.test(type)) return "RDS_LOGIN_ATTEMPT";
  return "AWS_API_CALL";
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const type = G(ev, "type");
  if (!type) return null; // only GuardDuty findings belong here

  const acct = awsAccountId(ev, ctx);
  const region = awsRegion(ev);
  const id = G(ev, "id") ?? ctx.hex(entitySeed(ctx, "gdfinding", ev.id), 32);
  const detectorId = G(ev, "service.detectorId") ?? G(ev, "service.detector_id") ?? ctx.hex(entitySeed(ctx, "gddetector", ctx.companyId), 32);
  const sev = GN(ev, "severity") ?? (ev.severity === "critical" ? 9 : ev.severity === "high" ? 8 : ev.severity === "medium" ? 5 : 2);
  const ip = ev.src_ip ?? ev.dst_ip ?? G(ev, "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4");
  const createdAt = G(ev, "createdAt") ?? isoMs(ev.ts);
  const updatedAt = G(ev, "updatedAt") ?? isoMs(ev.ts);

  const resourceType = G(ev, "resource.resourceType") ?? resourceTypeFor(type);
  const actionType = G(ev, "service.action.actionType") ?? actionTypeFor(type);

  // ── resource ──
  const resource: Record<string, unknown> = { resourceType };
  const akId = G(ev, "resource.accessKeyDetails.accessKeyId");
  const akUser = G(ev, "resource.accessKeyDetails.userName");
  if (resourceType === "AccessKey" || akId) {
    resource.resourceType = "AccessKey";
    resource.accessKeyDetails = {
      accessKeyId: akId ?? ("AKIA" + ctx.hex(entitySeed(ctx, "gdkey", akUser ?? ev.id), 16).toUpperCase()),
      principalId: G(ev, "resource.accessKeyDetails.principalId") ?? ("AIDA" + ctx.hex(entitySeed(ctx, "gdprin", akUser ?? ev.id), 17).toUpperCase()),
      userType: G(ev, "resource.accessKeyDetails.userType") ?? "IAMUser",
      userName: akUser ?? "svc-account",
    };
  } else if (resourceType === "Instance") {
    const iid = G(ev, "resource.instanceDetails.instanceId") ?? ("i-" + ctx.hex(entitySeed(ctx, "gdinst", ev.id), 17));
    resource.instanceDetails = {
      instanceId: iid,
      instanceType: G(ev, "resource.instanceDetails.instanceType") ?? "t3.large",
      launchTime: isoMs(ev.ts),
      iamInstanceProfile: { arn: `arn:aws:iam::${acct}:instance-profile/ec2-role`, id: "AIPA" + ctx.hex(entitySeed(ctx, "gdprof", iid), 17).toUpperCase() },
      networkInterfaces: [{ privateIpAddress: "10.0.3.47", publicIp: ip ?? "", subnetId: "subnet-" + ctx.hex(iid + ":sub", 17), vpcId: "vpc-" + ctx.hex(iid + ":vpc", 17) }],
      instanceState: "running",
      availabilityZone: `${region}a`,
      imageId: "ami-" + ctx.hex(iid + ":ami", 17),
    };
  } else if (resourceType === "S3Bucket") {
    const bucket = `${ctx.companyId}-customer-data`;
    resource.s3BucketDetails = [{ arn: `arn:aws:s3:::${bucket}`, name: bucket, type: "Destination", owner: { id: ctx.hex(entitySeed(ctx, "gds3owner", bucket), 64) }, publicAccess: { effectivePermission: /Anonymous|PublicAccess/.test(type) ? "PUBLIC" : "NOT_PUBLIC" } }];
    if (akId || akUser) resource.accessKeyDetails = { accessKeyId: akId ?? ("AKIA" + ctx.hex(entitySeed(ctx, "gdkey", akUser ?? ev.id), 16).toUpperCase()), principalId: "AIDA" + ctx.hex(entitySeed(ctx, "gdprin", akUser ?? ev.id), 17).toUpperCase(), userType: "IAMUser", userName: akUser ?? "svc-account" };
  } else { // EKSCluster
    const cluster = `${ctx.companyId}-prod`;
    resource.eksClusterDetails = { name: cluster, arn: `arn:aws:eks:${region}:${acct}:cluster/${cluster}`, status: "ACTIVE", tags: [] };
    resource.kubernetesDetails = { kubernetesUserDetails: { username: "kubernetes-admin", groups: ["system:masters", "system:authenticated"] }, kubernetesWorkloadDetails: { name: "pod", type: "pods", namespace: "kube-system" } };
  }

  // ── service.action ──
  const remoteIpDetails = ip ? {
    ipAddressV4: ip,
    organization: { asn: G(ev, "service.action.awsApiCallAction.remoteIpDetails.organization.asn") ?? "0", asnOrg: G(ev, "service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg") ?? "Unknown", isp: "Unknown", org: "Unknown" },
    country: { countryName: ev.geo?.country ?? G(ev, "service.action.awsApiCallAction.remoteIpDetails.country.countryName") ?? "Unknown" },
    city: { cityName: ev.geo?.city ?? "Unknown" },
    geoLocation: { lat: ev.geo?.latitude ?? 0, lon: ev.geo?.longitude ?? 0 },
  } : undefined;

  const action: Record<string, unknown> = { actionType };
  if (actionType === "DNS_REQUEST") {
    action.dnsRequestAction = { domain: G(ev, "service.action.dnsRequestAction.domain") ?? rs(ev.raw, "mining.pool.primary", "network.domain", "dns.query") ?? "malicious.example", protocol: G(ev, "service.action.dnsRequestAction.protocol") ?? "UDP", blocked: false };
  } else if (actionType === "KUBERNETES_API_CALL") {
    action.kubernetesApiCallAction = { requestUri: "/api/v1/namespaces/kube-system/pods/exec", verb: "create", sourceIPs: ip ? [ip] : [], userAgent: "kubectl/v1.30.0 (linux/amd64)", statusCode: 101, ...(remoteIpDetails ? { remoteIpDetails } : {}) };
  } else if (actionType === "NETWORK_CONNECTION") {
    action.networkConnectionAction = { connectionDirection: "OUTBOUND", protocol: "TCP", blocked: false, remotePortDetails: { port: ev.dst_port ?? 443, portName: "HTTPS" }, localIpDetails: { ipAddressV4: "10.0.3.47" }, ...(remoteIpDetails ? { remoteIpDetails } : {}) };
  } else { // AWS_API_CALL
    action.awsApiCallAction = { api: G(ev, "service.action.awsApiCallAction.api") ?? ev.cloud?.api_call ?? rs(ev.raw, "aws.cloudtrail.eventName") ?? "ListBuckets", serviceName: G(ev, "service.action.awsApiCallAction.serviceName") ?? "s3.amazonaws.com", callerType: "Remote IP", ...(remoteIpDetails ? { remoteIpDetails } : {}) };
  }

  const service: Record<string, unknown> = {
    serviceName: "guardduty",
    detectorId,
    action,
    resourceRole: resourceType === "Instance" ? "ACTOR" : "TARGET",
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
    partition: "aws",
    id,
    arn: G(ev, "arn") ?? `arn:aws:guardduty:${region}:${acct}:detector/${detectorId}/finding/${id}`,
    type,
    resource,
    service,
    severity: sev,
    createdAt,
    updatedAt,
    title: G(ev, "title") ?? type,
    description: ev.description ?? G(ev, "description") ?? type,
  };

  return { sourceId: "aws_guardduty", kind: "Finding", format: "json", record, timeMs: Date.parse(ev.ts) };
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
    id: "aws_guardduty.cryptomining",
    title: "Crypto-mining activity",
    sourceId: "aws_guardduty", severity: "high", mitre: ["T1496"],
    description: "CryptoCurrency / BitcoinTool — an EC2 instance beaconing to mining-pool infrastructure, the hallmark of compute abuse on compromised credentials.",
    logic: "SPL: type IN (\"CryptoCurrency:*\") OR type=\"*BitcoinTool*\"",
    match: { any: [{ field: "type", op: "icontains", value: "CryptoCurrency" }, { field: "type", op: "icontains", value: "BitcoinTool" }] },
    falsePositives: ["A researcher intentionally running a miner in a sandbox account."],
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
    description: "DefenseEvasion:IAMUser/BedrockLoggingDisabled — GuardDuty's detection that model-invocation logging was turned off, the LLMjacking defense-evasion step.",
    logic: "SPL: type=\"*BedrockLoggingDisabled*\"",
    match: { field: "type", op: "icontains", value: "BedrockLoggingDisabled" },
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
