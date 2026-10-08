/**
 * AI-related attack stories — wave 3, part C (live feed & team training). Two advanced
 * chains around AI developer tooling, each grounded in real defender telemetry:
 *
 *  1. ai-mcp-tool-poisoning  (advanced, rocketstack) — a developer connects an AI coding
 *     agent to a third-party MCP (Model Context Protocol) server. A poisoned tool
 *     description (hidden instructions) makes the agent read the local ~/.aws/credentials
 *     file and pass it back in a tool call. Hours later the long-term access key is used
 *     from a hosting provider to enumerate and copy S3 data. EDR process + network +
 *     DNS on the developer host, then AWS CloudTrail (GetCallerIdentity / ListBuckets /
 *     GetObject bursts) with the key ending EXAMPLE, GuardDuty anomalous-behaviour
 *     findings, and a Sentinel correlation that ties the key back to the developer host.
 *       OWASP LLM Top 10 (2025): LLM01 Prompt Injection, LLM03 Supply Chain. MCP tool
 *       poisoning (Invariant Labs, Apr 2025). MITRE ATLAS tool/agent abuse.
 *
 *  2. ai-malicious-model-pickle  (advanced, rocketstack / medcore) — a data scientist
 *     downloads a model file from a public model hub and loads it in a Jupyter
 *     environment on a Linux ML server. Loading the pickle-based file runs embedded code
 *     that opens an outbound connection and installs a cron persistence entry. Linux
 *     auditd (python spawning sh, the connect syscall, the crontab write), EDR on Linux,
 *     the firewall, DNS, and the detection.
 *       OWASP LLM Top 10 (2025): LLM03 Supply Chain; MITRE ATLAS AML.T0010 ML Supply
 *       Chain Compromise / AML.T0011 User Execution of unsafe ML artifacts; Python
 *       `pickle` arbitrary-code-execution on deserialisation (documented CPython risk).
 *
 * Iron laws honoured. EDR has no native "file read" record in the platform's cards, so
 * the agent's access to ~/.aws/credentials is shown as EDR PROCESS telemetry (the agent's
 * own shell tool reading the file) — the on-endpoint artifact a real sensor records. The
 * GuardDuty findings are the anomalous-behaviour family (the leaked key is a developer's
 * LONG-TERM IAM user key, so the EC2-only InstanceCredentialExfiltration type would be
 * wrong). Descriptions stay product-neutral for the swapped categories (EDR / firewall).
 * No exploit code: only what the logs capture.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { AiStoryDef } from "./wave2";
import { csProcess, csNetwork, csDns, csFile, csDetection } from "@/lib/sim/emitters/crowdstrike";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

const UA_AWS_CLI = "aws-cli/2.17.19 Python/3.11.9 Linux/6.8.0-generic exe/x86_64.ubuntu.24 prompt/off";
const UA_BOTO = "Boto3/1.34.100 md/Botocore#1.34.100 ua/2.0 os/linux#6.5.0 md/arch#x86_64 lang/python#3.11.9 cfg/retry-mode#legacy Botocore/1.34.100";

// ══════════════════════════════════════════════════════════════════════════════
// 1. ai-mcp-tool-poisoning — advanced, rocketstack
// ══════════════════════════════════════════════════════════════════════════════
function buildMcpToolPoisoning(): TelemetryEvent[] {
  const INC = "inc:aimcp:1";
  const cx = "rocketstack";
  const host = "LAP-DEV-12";
  const hostIp = "172.16.10.57";
  const user = "j.lee@rocketstack.io";
  const bareUser = "j.lee";
  const corpEgress = "198.51.100.22";                 // the office NAT egress (Israel)
  const key = "AKIAZ7QW3MNP5EXAMPLE";               // the developer's long-term IAM user key
  const iamUser = "j.lee";
  const arn = "arn:aws:iam::418772153604:user/j.lee";
  const mcpDomain = "mcp.toolforge-hub.example";    // the third-party MCP server
  const mcpIp = "203.0.113.88";
  const attackerIp = "203.0.113.140";              // hosting provider, Frankfurt
  const attackerGeo = { country: "Germany", city: "Frankfurt am Main" };
  const bucketA = "rocketstack-prod-datalake";
  const bucketB = "rocketstack-customer-exports";
  const nodePath = "/usr/share/code-assistant/node";

  const events: TelemetryEvent[] = [
    // 0. BASELINE. The key's normal use: the developer's own CLI from the office network.
    {
      ...cloudTrailEvent({
        id: "aimcp00_baseline", ts: "2026-10-05T08:12:44.000Z", companyId: cx,
        eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: corpEgress,
        actorType: "IAMUser", actorName: iamUser, accessKeyId: key, arn, userAgent: UA_AWS_CLI,
        readOnly: true, geo: { country: "Israel", city: "Tel Aviv" }, severity: "informational", userTitle: "Engineer",
        description: "AWS CloudTrail: GetCallerIdentity by the access key AKIAZ7QW3MNP5EXAMPLE from 198.51.100.22 (the office network), the developer checking which identity their CLI uses. This is the key's normal origin.",
      }),
      is_baseline: true, expected_verdict: "fp" as const,
      fp_explanation: "The developer's own long-term key, used from the corporate egress during working hours — its established pattern.",
    },
    // 1. BASELINE. The coding agent's own process, running normally on the host.
    {
      ...csProcess({
        companyId: cx, id: "aimcp01_baseline", ts: "2026-10-06T09:40:10.000Z", host, srcIp: hostIp, user,
        processName: "node", processPath: nodePath, cmdline: `${nodePath} /usr/share/code-assistant/mcp-client.js --workspace /home/${bareUser}/project`,
        parentName: "code-assistant", signed: true, severity: "informational",
        expectedVerdict: "fp", fpExplanation: "The developer's AI coding assistant running against the local project, its ordinary shape before the new MCP server was added.",
        description: "The AI coding assistant's MCP client process started on the host against the local project workspace. This is its normal footprint.",
      }),
      is_baseline: true,
    },
    // 2. DNS: the host resolves the newly-added third-party MCP host.
    csDns({
      companyId: cx, id: "aimcp02", ts: "2026-10-06T10:02:31.000Z", host, srcIp: hostIp, user,
      domain: mcpDomain, resolvedIp: mcpIp, qtype: "A",
      mitre: "T1071.001", tactic: "Command and Control", severity: "low",
      description: `The host resolved ${mcpDomain}, a third-party tool host the developer added to the coding assistant; this is the first lookup of that name from the host.`,
    }),
    // 3. NETWORK: the agent connects to the MCP host.
    csNetwork({
      companyId: cx, id: "aimcp03", ts: "2026-10-06T10:02:31.500Z", host, srcIp: hostIp, user,
      remoteIp: mcpIp, remotePort: 443, domain: mcpDomain, application: "tls",
      processName: "node", processPath: nodePath, pid: 4821,
      bytesOut: 2140, bytesIn: 9802, mitre: "T1071.001", tactic: "Command and Control", severity: "low",
      description: `The coding-assistant process opened a TLS session to ${mcpDomain} and retrieved the external server's tool list. One of the tool descriptions carries hidden instructions the agent reads as if the developer had typed them.`,
    }),
    // 4. PROCESS: the agent's shell tool reads the local AWS credentials file (T1552.001).
    //    EDR has no native file-read record; the on-endpoint artifact is the agent's own
    //    shell tool opening the file — shown as process telemetry.
    csProcess({
      companyId: cx, id: "aimcp04", ts: "2026-10-06T10:03:08.000Z", host, srcIp: hostIp, user,
      processName: "cat", processPath: "/usr/bin/cat", cmdline: `cat /home/${bareUser}/.aws/credentials`,
      parentName: "node", parentPid: 4821, signed: true,
      mitre: "T1552.001", tactic: "Credential Access", severity: "high",
      description: `A shell tool launched by the coding-assistant process read the local cloud-credentials file /home/${bareUser}/.aws/credentials — a file the agent has no task-related reason to open. The read followed immediately after the external tool list was fetched.`,
    }),
    // 5. NETWORK: the agent sends an outbound tool call to the MCP host carrying the file.
    csNetwork({
      companyId: cx, id: "aimcp05", ts: "2026-10-06T10:03:09.200Z", host, srcIp: hostIp, user,
      remoteIp: mcpIp, remotePort: 443, domain: mcpDomain, application: "tls",
      processName: "node", processPath: nodePath, pid: 4821,
      bytesOut: 4610, bytesIn: 512, mitre: "T1041", tactic: "Exfiltration", severity: "high",
      description: `About one second after the credentials file was read, the coding-assistant process sent a larger-than-usual outbound request to ${mcpDomain} (about 4.6 KB out). The tool call's arguments carried the contents of the file back to the external server.`,
    }),
    // 6. CloudTrail: the stolen key authenticates from a hosting provider, hours later.
    cloudTrailEvent({
      id: "aimcp06", ts: "2026-10-06T14:27:02.000Z", companyId: cx,
      eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: attackerIp,
      actorType: "IAMUser", actorName: iamUser, accessKeyId: key, arn, userAgent: UA_BOTO,
      readOnly: true, geo: attackerGeo, severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: "AWS CloudTrail: GetCallerIdentity by the access key AKIAZ7QW3MNP5EXAMPLE from 203.0.113.140 (a hosting provider in Frankfurt) with a scripted Boto3 agent, more than four hours after the file was read on the host. Until now the key had only ever been used from the office network.",
    }),
    // 7. CloudTrail: bucket enumeration.
    cloudTrailEvent({
      id: "aimcp07", ts: "2026-10-06T14:27:49.000Z", companyId: cx,
      eventName: "ListBuckets", eventSource: "s3.amazonaws.com", srcIp: attackerIp,
      actorType: "IAMUser", actorName: iamUser, accessKeyId: key, arn, userAgent: UA_BOTO,
      readOnly: true, geo: attackerGeo, severity: "high", mitre: "T1580", tactic: "Discovery",
      description: "AWS CloudTrail: ListBuckets by the same key from 203.0.113.140, 47 seconds after the identity check — the account's entire S3 bucket inventory read in one call.",
    }),
    // 8. CloudTrail: GetObject burst, first bucket (one representative row; the count is in the text).
    cloudTrailEvent({
      id: "aimcp08", ts: "2026-10-06T14:29:15.000Z", companyId: cx,
      eventName: "GetObject", eventSource: "s3.amazonaws.com", srcIp: attackerIp,
      actorType: "IAMUser", actorName: iamUser, accessKeyId: key, arn, userAgent: UA_BOTO,
      s3Bucket: bucketA, s3Key: "exports/2026-10/customers.parquet", bytes: 48_221_904,
      readOnly: true, geo: attackerGeo, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `AWS CloudTrail: GetObject on s3://${bucketA}/exports/2026-10/customers.parquet by the same key from 203.0.113.140 — one of a burst of several hundred GetObject calls on this bucket within two minutes.`,
    }),
    // 9. CloudTrail: GetObject burst, second bucket.
    cloudTrailEvent({
      id: "aimcp09", ts: "2026-10-06T14:33:41.000Z", companyId: cx,
      eventName: "GetObject", eventSource: "s3.amazonaws.com", srcIp: attackerIp,
      actorType: "IAMUser", actorName: iamUser, accessKeyId: key, arn, userAgent: UA_BOTO,
      s3Bucket: bucketB, s3Key: "daily/2026-10-06/accounts.csv.gz", bytes: 15_882_310,
      readOnly: true, geo: attackerGeo, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `AWS CloudTrail: GetObject on s3://${bucketB}/daily/2026-10-06/accounts.csv.gz by the same key from 203.0.113.140 — the burst moved to a second bucket; across both buckets the key copied tens of gigabytes in minutes.`,
    }),
    // 10. GuardDuty: anomalous S3 access from the key.
    guardDutyFinding({
      id: "aimcp10", ts: "2026-10-06T14:41:12.000Z", companyId: cx,
      findingType: "Exfiltration:S3/AnomalousBehavior", gdSeverity: 8,
      title: "An API used to retrieve data from an S3 bucket was invoked in an anomalous way.",
      api: "GetObject", serviceName: "s3.amazonaws.com", callerType: "Remote IP",
      srcIp: attackerIp, remoteCountry: "Germany", asnOrg: "hosting provider",
      resourceType: "AccessKey", userType: "IAMUser", userName: iamUser, accessKeyId: key, count: 412,
      mitre: "T1530", tactic: "Collection", severity: "high",
      description: "GuardDuty raised Exfiltration:S3/AnomalousBehavior (severity 8, High) for access key AKIAZ7QW3MNP5EXAMPLE: the volume of GetObject calls from 203.0.113.140 is far outside what GuardDuty learned for this credential, and the source network and geography are new for it.",
    }),
    // 11. GuardDuty: the credential itself is being used anomalously.
    guardDutyFinding({
      id: "aimcp11", ts: "2026-10-06T14:42:30.000Z", companyId: cx,
      findingType: "CredentialAccess:IAMUser/AnomalousBehavior", gdSeverity: 7,
      title: "An API commonly used to access credentials or discover resources was invoked in an anomalous way.",
      api: "ListBuckets", serviceName: "s3.amazonaws.com", callerType: "Remote IP",
      srcIp: attackerIp, remoteCountry: "Germany", asnOrg: "hosting provider",
      resourceType: "AccessKey", userType: "IAMUser", userName: iamUser, accessKeyId: key, count: 1,
      mitre: "T1078.004", tactic: "Credential Access", severity: "high",
      description: "GuardDuty raised CredentialAccess:IAMUser/AnomalousBehavior (severity 7, High) for the same key: the discovery and data-access calls from a hosting-provider address do not match the identity's learned behaviour.",
    }),
    // 12. DETECTION: Sentinel ties the abused key back to the developer host.
    sentinelAlert({
      companyId: cx, id: "aimcp12", ts: "2026-10-06T14:55:03.000Z", host, srcIp: attackerIp, user,
      alertName: "AWS access key abused from a new network was last read on a developer endpoint",
      eventType: "cloud_api_call", severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      detail: "A scheduled analytics rule joined the CloudTrail access-key activity from the hosting provider with the endpoint telemetry for the same key's owner.",
      startTime: "2026-10-06T10:03:08.000Z", endTime: "2026-10-06T14:42:30.000Z",
      extendedProperties: {
        "Access key": key,
        "Key owner": user,
        "Key last read on host": host,
        "Reading process": "coding-assistant shell tool (cat ~/.aws/credentials)",
        "First abuse source IP": attackerIp,
      },
      description: `Microsoft Sentinel correlated the access key AKIAZ7QW3MNP5EXAMPLE used from 203.0.113.140 with the same key's owner on ${host}, where a coding-assistant shell tool had read /home/${bareUser}/.aws/credentials and the agent had connected to an external tool host hours earlier. The alert links the cloud abuse to the developer endpoint.`,
    }),
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-malicious-model-pickle — advanced, rocketstack / medcore
// ══════════════════════════════════════════════════════════════════════════════

/** One Linux auditd record authored inline (vendor-native field names), with the
 *  structured fields the native renderer and the feed read. Kept local to this file. */
interface AuditOpts {
  id: string; ts: string; eventType: TelemetryEvent["event_type"]; severity: TelemetryEvent["severity"];
  host: string; user: string; bareUser: string; uid: string; auid: string; ses: string;
  process: NonNullable<TelemetryEvent["process"]>;
  file?: TelemetryEvent["file"];
  dstIp?: string; dstPort?: number;
  mitre?: string; tactic?: string;
  raw: Record<string, string>;
  description: string;
  baseline?: boolean;
}
function auditd(o: AuditOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "linux_audit", vendor: "Linux auditd", event_type: o.eventType, severity: o.severity,
    hostname: o.host, user_email: o.user, ...(o.dstIp ? { dst_ip: o.dstIp } : {}), ...(o.dstPort ? { dst_port: o.dstPort, protocol: "tcp" } : {}),
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.baseline ? { is_baseline: true, expected_verdict: "fp" as const } : {}),
    process: o.process, ...(o.file ? { file: o.file } : {}),
    description: o.description,
    raw: {
      ...o.raw,
      "data.audit.pid": String(o.process.pid),
      ...(o.process.parent_pid !== undefined ? { "data.audit.ppid": String(o.process.parent_pid) } : {}),
      "data.audit.uid": o.uid,
      "data.audit.auid": o.auid,
      "data.audit.ses": o.ses,
      "data.audit.comm": o.process.name,
      "data.audit.exe": o.process.path ?? `/usr/bin/${o.process.name}`,
      "user.name": o.bareUser,
      "user.id": o.uid,
      "host.name": o.host,
      "host.os.type": "linux",
      "process.name": o.process.name,
      "process.executable": o.process.path ?? `/usr/bin/${o.process.name}`,
      "process.pid": String(o.process.pid),
      ...(o.process.parent_pid !== undefined ? { "process.ppid": String(o.process.parent_pid) } : {}),
    },
  };
}

function buildMaliciousModelPickle(): TelemetryEvent[] {
  const INC = "inc:aimp:1";
  const cx = "rocketstack";
  const host = "srv-ml-jupyter01";
  const hostIp = "172.16.10.40";
  const user = "m.ben-david@rocketstack.io";
  const bareUser = "m.ben-david";
  const uid = "1000";
  const ses = "71";
  const hubDomain = "models.open-model-hub.example";
  const hubIp = "203.0.113.30";
  const cbDomain = "sync-cdn.modelpulse.example";    // the callback host
  const cbIp = "198.51.100.88";                        // hosting provider
  const modelUrl = `https://${hubDomain}/repos/resnet50-sentiment-ft/resolve/main/pytorch_model.bin`;
  const helper = `/tmp/.ml/.sync/agentd`;
  const cronFile = `/var/spool/cron/crontabs/${bareUser}`;
  const pythonPath = "/opt/conda/bin/python3.11";

  const events: TelemetryEvent[] = [
    // 0. BASELINE. The notebook kernel running ordinary analysis.
    auditd({
      id: "aimp00_baseline", ts: "2026-10-07T07:50:12.000Z", eventType: "linux_execve", severity: "informational",
      host, user, bareUser, uid, auid: uid, ses, baseline: true,
      process: { name: "python3.11", pid: 20144, path: pythonPath, parent_name: "jupyter-lab", parent_pid: 19980,
        cmdline: `${pythonPath} -c "import pandas as pd; df = load_frame()"`, user: bareUser },
      mitre: undefined, tactic: undefined,
      raw: {
        "data.audit.type": "EXECVE",
        "audit.a0": pythonPath, "audit.a1": "-c", "audit.a2": "import pandas as pd; df = load_frame()",
        "event.action": "executed", "event.outcome": "success",
      },
      description: "auditd EXECVE: the Jupyter kernel ran python for an ordinary analysis cell on the ML server. This is the notebook's normal activity before the external model was loaded.",
    }),
    // 1. DNS: the server resolves the public model hub.
    csDns({
      companyId: cx, id: "aimp01", ts: "2026-10-07T09:14:05.000Z", host, srcIp: hostIp, user,
      domain: hubDomain, resolvedIp: hubIp, qtype: "A", severity: "low",
      description: `The ML server resolved ${hubDomain}, a public model hub, as the data scientist began downloading a pre-trained model.`,
    }),
    // 2. FIREWALL: the model file download (allowed).
    panWeb({
      companyId: cx, id: "aimp02", ts: "2026-10-07T09:14:11.000Z", host, srcIp: hostIp, user,
      url: modelUrl, domain: hubDomain, category: "computer-and-internet-info", method: "GET", action: "allow",
      dstIp: hubIp, status: 200, bytesIn: 99_614_720, bytesOut: 1_204,
      file: { name: "pytorch_model.bin" }, fileType: "unknown",
      mitre: "T1195.002", tactic: "Initial Access", severity: "low",
      description: `The ML server downloaded the model file pytorch_model.bin (about 95 MB) from ${hubDomain} over HTTPS; the session was allowed. The file is a pickle-serialised model whose load step can execute embedded code.`,
    }),
    // 3. auditd EXECVE: loading the model makes python spawn a shell (embedded code runs).
    auditd({
      id: "aimp03", ts: "2026-10-07T09:16:40.000Z", eventType: "linux_execve", severity: "high",
      host, user, bareUser, uid, auid: uid, ses,
      process: { name: "sh", pid: 20390, path: "/bin/sh", parent_name: "python3.11", parent_pid: 20144,
        cmdline: `sh -c ${helper}`, user: bareUser },
      mitre: "T1059.004", tactic: "Execution",
      raw: {
        "data.audit.type": "EXECVE",
        "audit.a0": "sh", "audit.a1": "-c", "audit.a2": helper,
        "event.action": "executed", "event.outcome": "success",
      },
      description: `auditd EXECVE: the python kernel (pid 20144) spawned /bin/sh as a child the moment the downloaded model was loaded — a shell the notebook code never calls for. Loading a pickle-based model file runs any code embedded in it.`,
    }),
    // 4. DNS: the host resolves the callback host just after the shell spawned.
    csDns({
      companyId: cx, id: "aimp04", ts: "2026-10-07T09:16:41.000Z", host, srcIp: hostIp, user,
      domain: cbDomain, resolvedIp: cbIp, qtype: "A",
      mitre: "T1071.001", tactic: "Command and Control", severity: "medium",
      description: `Immediately after the shell was spawned, the host resolved ${cbDomain}, a name it had never looked up before.`,
    }),
    // 5. auditd SYSCALL connect: the outbound connection (the connect syscall).
    auditd({
      id: "aimp05", ts: "2026-10-07T09:16:41.400Z", eventType: "net_connection", severity: "high",
      host, user, bareUser, uid, auid: uid, ses, dstIp: cbIp, dstPort: 443,
      process: { name: "sh", pid: 20390, path: "/bin/sh", parent_name: "python3.11", parent_pid: 20144,
        cmdline: `sh -c ${helper}`, user: bareUser },
      mitre: "T1071.001", tactic: "Command and Control",
      raw: {
        "data.audit.type": "SYSCALL", "data.audit.syscall": "42", "data.audit.success": "yes", "data.audit.exit": "0",
        "network.destination.ip": cbIp, "network.destination.port": "443", "network.destination.domain": cbDomain,
        "source.ip": hostIp, "event.action": "connected", "event.outcome": "success",
      },
      description: `auditd SYSCALL (connect, syscall 42): the shell child of the python kernel opened an outbound TCP connection to ${cbIp}:443. The process reaching the network is a shell, not the notebook.`,
    }),
    // 6. EDR on Linux: the same outbound connection, seen by the endpoint sensor.
    csNetwork({
      companyId: cx, id: "aimp06", ts: "2026-10-07T09:16:41.600Z", host, srcIp: hostIp, user,
      remoteIp: cbIp, remotePort: 443, domain: cbDomain, application: "tls",
      processName: "sh", processPath: "/bin/sh", pid: 20390, parentName: "python3.11", parentPid: 20144,
      bytesOut: 820, bytesIn: 1340, mitre: "T1071.001", tactic: "Command and Control", severity: "high",
      description: `The endpoint sensor recorded the shell process (child of the python interpreter) opening a TLS connection to ${cbDomain}. An interpreter spawning a shell that immediately talks to an external host is a classic code-execution-on-load pattern.`,
    }),
    // 7. FIREWALL: the perimeter sees the same callback session.
    panConnection({
      companyId: cx, id: "aimp07", ts: "2026-10-07T09:16:42.000Z", host, srcIp: hostIp, user,
      domain: cbDomain, dstIp: cbIp, remotePort: 443, app: "ssl", action: "alert",
      category: "malware", mitre: "T1071.001", tactic: "Command and Control", severity: "medium",
      description: `The perimeter firewall logged the outbound session from the ML server to ${cbDomain} (${cbIp}:443); the destination is a newly-seen external host.`,
    }),
    // 8. auditd: the cron persistence entry is written.
    auditd({
      id: "aimp08", ts: "2026-10-07T09:16:55.000Z", eventType: "linux_cron", severity: "high",
      host, user, bareUser, uid, auid: uid, ses,
      process: { name: "crontab", pid: 20415, path: "/usr/bin/crontab", parent_name: "sh", parent_pid: 20390,
        cmdline: "crontab -", user: bareUser },
      file: { name: bareUser, path: cronFile },
      mitre: "T1053.003", tactic: "Persistence",
      raw: {
        "data.audit.type": "SYSCALL", "data.audit.syscall": "257", "data.audit.success": "yes", "data.audit.exit": "4",
        "data.audit.file.name": cronFile, "data.audit.file.mode": "0100600",
        "data.audit.file.ouid": uid, "data.audit.file.ogid": "102", "data.audit.file.nametype": "CREATE",
        "event.action": "created", "event.outcome": "success",
      },
      description: `auditd PATH (objtype=CREATE): the shell used the crontab binary to create ${cronFile} at mode 0100600 — a user cron job that re-launches the dropped helper after reboot.`,
    }),
    // 9. EDR on Linux: the dropped helper written to a hidden directory.
    csFile({
      companyId: cx, id: "aimp09", ts: "2026-10-07T09:16:43.000Z", host, srcIp: hostIp, user,
      path: helper, size: 1_048_576, action: "file_create",
      actorProcess: "sh", actorPid: 20390, actorPath: "/bin/sh", actorParentName: "python3.11", actorParentPid: 20144,
      runAsUser: bareUser, mitre: "T1564.001", tactic: "Defense Evasion", severity: "high",
      description: `The endpoint sensor recorded the shell writing an executable file to ${helper}, a hidden directory under /tmp — the helper the cron job re-launches.`,
    }),
    // 10. DETECTION: the EDR behavioural detection on the chain.
    csDetection({
      companyId: cx, id: "aimp10", ts: "2026-10-07T09:17:20.000Z", host, srcIp: hostIp, user,
      processName: "sh", processPath: "/bin/sh", parentName: "python3.11",
      cmdline: `sh -c ${helper}`, threatName: "SuspiciousInterpreterChild",
      mitre: "T1059.004", tactic: "Execution", technique: "Command and Scripting Interpreter: Unix Shell",
      action: "detected", severity: "high", eventType: "edr_alert",
      description: `The endpoint detection platform flagged a Python interpreter spawning a shell that made an external connection and dropped a file — behaviour consistent with code executing on model load. The process was not blocked.`,
    }),
    // 11. DETECTION: Sentinel correlates the download, the shell, the C2 and the cron entry.
    sentinelAlert({
      companyId: cx, id: "aimp11", ts: "2026-10-07T09:22:10.000Z", host, srcIp: hostIp, user,
      alertName: "Model file loaded then interpreter spawned a shell, external connection and cron persistence",
      eventType: "linux_cron", severity: "high", mitre: "T1053.003", tactic: "Persistence",
      detail: "A scheduled rule joined the model-hub download, the auditd shell-spawn and connect, the firewall session to the callback host, and the crontab write — one chain on one host within minutes.",
      startTime: "2026-10-07T09:14:11.000Z", endTime: "2026-10-07T09:16:55.000Z",
      extendedProperties: {
        "Model source": hubDomain,
        "Callback host": cbDomain,
        "Interpreter": "python3.11 (Jupyter kernel)",
        "Persistence": cronFile,
        "Dropped file": helper,
      },
      description: `Microsoft Sentinel correlated the pickle-model download from ${hubDomain} with the python-spawned shell, its outbound connection to ${cbDomain}, and the new cron entry ${cronFile} on ${host} — a single load-time code-execution chain ending in persistence.`,
    }),
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

export const AI_WAVE3_C_STORIES: AiStoryDef[] = [
  {
    id: "ai-mcp-tool-poisoning",
    title: "Poisoned MCP Tool Makes an AI Coding Agent Leak AWS Keys, Then S3 Is Copied from a Hosting Provider",
    complexity: "advanced", companies: ["rocketstack"], events: buildMcpToolPoisoning(),
  },
  {
    id: "ai-malicious-model-pickle",
    title: "Malicious Model File Runs Code on Load: Shell, Callback and Cron Persistence on an ML Server",
    complexity: "advanced", companies: ["rocketstack", "medcore"], events: buildMaliciousModelPickle(),
  },
];
