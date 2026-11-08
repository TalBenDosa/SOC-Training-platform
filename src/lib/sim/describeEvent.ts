/**
 * The plain-language "what happened" line for a log event — the Description
 * column of the Live SOC feed, shared with the scenario investigation page so
 * both read the same way ("j.chen received an email", "cmd.exe started
 * powershell.exe on FIN-WS-08").
 *
 * It DESCRIBES, it never explains: an attack event's authored description states
 * the conclusion (names the tool, decodes the payload), so it is only used for
 * events with no MITRE technique; everything else is built from observable
 * fields (Windows Event Viewer text for an event code, else per event type).
 * The scenario page strips description + MITRE before the browser, so there it
 * is always the observable-derived line.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { WIN_EVENT_VIEWER_DESCRIPTIONS } from "@/lib/sim/ruleDescriptions";

/** First non-empty string among raw fields (vendor-native names only). */
/** Words that state an investigation's conclusion (kept in step with the technical-integrity gate). */
const ROW_CONCLUSION = /\b(attacker|adversary|malicious|compromis\w*|exfiltrat\w*|lateral movement|persistence|command[- ]and[- ]control|beacon\w*|backdoor|ransomware|stolen|impersonat\w*|infostealer|credential theft|C2)\b/i;

function rawStr(raw: Record<string, unknown> | undefined, ...keys: string[]): string {
  for (const k of keys) {
    // A flat SIEM key ("alert.signature") or the vendor's own nested JSON (Suricata EVE's alert.signature).
    let v: unknown = raw?.[k];
    if (v == null && raw && k.includes(".")) {
      v = k.split(".").reduce<unknown>((o, part) => (o && typeof o === "object" ? (o as Record<string, unknown>)[part] : undefined), raw);
    }
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

/** The vendor's own operation name (CloudTrail eventName, O365 Operation, Azure
 *  operationName) — a raw field the analyst would read anyway, never a verdict.
 *  `event.action` is deliberately NOT used: some sources put conclusions there. */
function operationOf(e: TelemetryEvent): string {
  return rawStr(e.raw, "aws.cloudtrail.eventName", "data.office365.Operation", "azure.auditlogs.operationName",
    "azure.operation.name", "azure.activitylogs.operationName", "gcp.audit.method_name", "protoPayload.methodName",
    "okta.eventType", "github.action", "github.audit.action", "gws.event.name", "google_workspace.event.name",
    "intune.activityType", "vsphere.event.eventTypeId", "aws.guardduty.service.action.awsApiCallAction.api",
    // Azure OpenAI request logs and Azure Storage (StorageBlobLogs) name the operation too.
    "azure.open_ai.operation_name", "OperationName");
}

/** A line built from field values, unless a value would state the conclusion (an alert name, a mail
 *  address): then the plainer line, so the row never gives the verdict away. */
function safe(line: string, plain: string): string {
  return ROW_CONCLUSION.test(line) && !ROW_CONCLUSION.test(plain) ? plain : line;
}

const shortUser = (u: string) => u.split("\\").pop()!.split("@")[0];

/**
 * An Azure API Management gateway row (ApiManagementGatewayLogs): the operation the gateway proxied
 * for which subscription, and its status. A Content Safety Prompt Shields call (text:shieldPrompt) is
 * read from the logged backend response: each analysis and its attackDetected value, as the service
 * returned them, with no wording of ours.
 */
function apimLine(e: TelemetryEvent): string {
  const raw = e.raw ?? {};
  const sub = rawStr(raw, "ApimSubscriptionId");
  const op = rawStr(raw, "OperationId");
  const status = raw.ResponseCode ?? raw.BackendResponseCode;
  if (op === "shieldPrompt") {
    let parsed: { userPromptAnalysis?: { attackDetected?: unknown }; documentsAnalysis?: { attackDetected?: unknown }[] } | null = null;
    try { parsed = JSON.parse(rawStr(raw, "BackendResponseBody")); } catch { parsed = null; }
    const parts: string[] = [];
    if (parsed?.userPromptAnalysis && "attackDetected" in parsed.userPromptAnalysis) parts.push(`userPromptAnalysis attackDetected ${String(parsed.userPromptAnalysis.attackDetected)}`);
    const docs = Array.isArray(parsed?.documentsAnalysis) ? parsed!.documentsAnalysis! : [];
    if (docs.length) parts.push(`documentsAnalysis attackDetected ${docs.map(d => String(d?.attackDetected)).join(", ")}`);
    if (parts.length) return `Prompt Shields (shieldPrompt): ${parts.join("; ")}${sub ? `, ${sub}` : ""}`;
    return `Prompt Shields (shieldPrompt) call through API Management${sub ? `, ${sub}` : ""}${status !== undefined ? `: HTTP ${status}` : ""}`;
  }
  const api = rawStr(raw, "ApiId");
  return `API Management ${rawStr(raw, "Method") || "request"} ${[api, op].filter(Boolean).join("/") || "to an API"}${sub ? ` for ${sub}` : ""}${status !== undefined ? `: HTTP ${status}` : ""}`;
}

/**
 * A directory change names who did it and to whom (Entra AuditLogs initiatedBy / targetResources):
 * "z.yilmaz reset the password of y.mendes", never "y.mendes performed Reset password" (review
 * 2026-11-08: Tier-1 read the help desk agent's change as the account owner's own action).
 */
function auditLine(e: TelemetryEvent, op: string): string | null {
  const actor0 = rawStr(e.raw, "azure.auditlogs.properties.initiatedBy.user.userPrincipalName", "azure.auditlogs.properties.initiatedBy.app.displayName");
  if (!actor0 || !op) return null;
  const target0 = rawStr(e.raw, "azure.auditlogs.properties.targetResources[0].userPrincipalName", "azure.auditlogs.properties.targetResources[0].displayName");
  const actor = shortUser(actor0);
  const target = target0 ? shortUser(target0) : "";
  const self = !target || target.toLowerCase() === actor.toLowerCase();
  const o = op.toLowerCase();
  if (/^reset (user )?password/.test(o)) return self ? `${actor} reset their password` : `${actor} reset the password of ${target}`;
  if (/deleted security info/.test(o)) return self ? `${actor} deleted their security info` : `${actor} deleted the security info of ${target}`;
  if (/registered security info/.test(o)) return self ? `${actor} registered security info` : `${actor} registered security info for ${target}`;
  if (/^change (user )?password/.test(o)) return self ? `${actor} changed their password` : `${actor} changed the password of ${target}`;
  return self ? `${actor} performed ${op}` : `${actor} performed ${op} on ${target}`;
}

/** Sender / recipient of a mail record (ECS email.*, Defender EmailEvents, the UAL mail fields). */
function mailParties(e: TelemetryEvent): { from: string; to: string } {
  return {
    from: rawStr(e.raw, "email.from.address", "SenderFromAddress", "data.office365.Sender", "email.sender.address", "data.office365.P1Sender", "SenderMailFromAddress"),
    to: rawStr(e.raw, "email.to.address", "RecipientEmailAddress", "data.office365.Recipients"),
  };
}

const baseName = (p?: string) => (p ? p.split(/[\\/]/).filter(Boolean).pop() ?? p : "");
const hostOf = (u?: string) => { if (!u) return ""; try { return new URL(u).hostname; } catch { return u.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0]; } };

export interface DescribeOptions {
  /** Prefer a sentence built from the log's fields over the bare Windows Event
   *  Viewer text when the fields say more ("cmd.exe started powershell.exe on
   *  FIN-WS-08" instead of "Process Create"). Used by the scenario page. */
  preferFields?: boolean;
  /** Never use the authored prose — every row (attack or noise) gets the same field-built
   *  sentence, so neither length nor style tells an attack row from noise (team feed). */
  fieldsOnly?: boolean;
}

/** Windows LogonType → the wording analysts (and the live feed) use. */
const LOGON_TYPES: Record<string, string> = {
  "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
  "8": "Network cleartext", "9": "New credentials", "10": "Remote desktop", "11": "Cached interactive",
};

/** Event types whose own fields describe them better than the Event Viewer title. */
const FIELD_RICH = new Set(["process_create", "dns_query", "net_connection", "file_create", "file_modify", "file_access", "file_copy", "registry_set", "registry_delete", "scheduled_task"]);

export function describeEvent(event: TelemetryEvent, opts: DescribeOptions = {}): string {
  // L-05 — the authored description states the CONCLUSION on attack events (names
  // the tool, does the base32/base64 math, gives the domain age, decodes the TXT),
  // which the banner promises the analyst will do themselves. Noise descriptions,
  // by contrast, are factual ("LT-ENG-4400 looked up login.microsoftonline.com").
  // So the authored line is only used for NON-attack events (no mitre_technique);
  // attack events fall through to the factual, observable-derived line below. The
  // interpretation is revealed in the report/debrief, not handed over in the feed.
  // The authored description is a clear, beginner-friendly line — used for NON-attack
  // events (whose authored text is factual). Attack events (mitre_technique present)
  // skip it and fall through to the observable-derived line, so the feed describes
  // rather than explains.
  if (!opts.fieldsOnly && !event.mitre_technique && event.description && event.description.trim().length > 12) {
    return event.description;
  }
  // An alert row names the alert — what the console really shows — never the analysis.
  // The scenario page too (preferFields): GuardDuty / SCC / Suricata / Sentinel rows used to
  // show a generic "System called ..." line instead of the product's finding name.
  const alertName = rawStr(event.raw, "AlertName", "alert.name", "crowdstrike.DetectName", "threat.name", "ThreatName", "data.ms-graph.title",
    "azure.alert.displayName", "AlertDisplayName",
    "aws.guardduty.type", "gcp.scc.finding.category", "finding.category", "suricata.eve.alert.signature", "alert.signature", "signature",
    "cloudwatch.alarm.name");
  // Azure AI Content Safety Prompt Shields: the shield, the attack type and the classification it
  // returned are the observable (it is not a web visit, review 2026-11-08).
  const shieldType = rawStr(event.raw, "promptshields.attack_type");
  if (shieldType) {
    const cls = rawStr(event.raw, "promptshields.classification");
    const app = rawStr(event.raw, "gateway.application");
    const u = event.user_email ?? rawStr(event.raw, "gateway.user_id");
    const where = [u ? shortUser(u) : "", app].filter(Boolean).join(", ");
    return `Prompt Shields: ${shieldType}${cls ? `, ${cls}` : ""}${where ? ` (${where})` : ""}`;
  }
  // A row line never states the conclusion: a finding named for its tactic ("Exfiltration:S3/...",
  // "Ransomware.MedLock") keeps that name in the record and the row falls back to the neutral line.
  const namesConclusion = !opts.fieldsOnly && ROW_CONCLUSION.test(alertName);
  if ((opts.fieldsOnly || opts.preferFields) && alertName && !namesConclusion && (event.is_detection || ["siem", "ueba", "dlp", "av", "ids", "guardduty", "cloud_gcp", "cloudtrail"].includes(event.source) || /alert|detection|quarantine|finding|signature|anomaly/.test(event.event_type))) {
    return `Alert: ${alertName}${event.hostname ? ` on ${event.hostname}` : ""}`;
  }

  // Otherwise fall back to the exact Event Viewer description text for the code
  const eventCode = event.raw?.["event.code"] as string | undefined;
  if (opts.preferFields && event.hostname) {
    const lt = rawStr(event.raw, "winlog.event_data.LogonType") || String(event.raw?.["winlog.event_data.LogonType"] ?? "");
    const kind = LOGON_TYPES[lt];
    if (eventCode === "4624" && kind) return `${kind} logon to ${event.hostname}`;
    if (eventCode === "4625" && kind) return `Failed ${kind.toLowerCase()} logon to ${event.hostname}`;
    if (eventCode === "5145") {
      const share = rawStr(event.raw, "winlog.event_data.ShareName");
      const rel = rawStr(event.raw, "winlog.event_data.RelativeTargetName");
      if (share) return `Accessed network share ${share}${rel ? ` (${rel})` : ""} on ${event.hostname}`;
    }
  }
  const dnsQuery = event.dns?.query || rawStr(event.raw, "winlog.event_data.QueryName", "dns.question.name", "crowdstrike.DomainName");
  const regKey = event.registry?.key || event.registry?.path || rawStr(event.raw, "winlog.event_data.TargetObject", "registry.path");
  const rawImage = rawStr(event.raw, "winlog.event_data.Image", "process.executable", "crowdstrike.ImageFileName", "crowdstrike.FileName");
  const rawParent = rawStr(event.raw, "winlog.event_data.ParentImage", "process.parent.executable", "crowdstrike.ParentBaseFileName");
  const dest = event.network?.domain || event.dst_ip || rawStr(event.raw, "url.domain", "RemoteUrl", "RemoteIP", "id.resp_h", "destination.ip", "destination.domain");
  const hasFields = !!(event.process || rawImage || dnsQuery || event.network?.domain || event.dst_ip || event.file || regKey);
  const useViewer = eventCode && WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode] &&
    !(opts.preferFields && FIELD_RICH.has(event.event_type) && hasFields);
  if (useViewer) {
    const text = WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode!];
    // On the scenario page say WHERE it happened — the live feed shows the host in its own column.
    return opts.preferFields && event.hostname && !text.includes(event.hostname)
      ? `${text.replace(/\.$/, "")} on ${event.hostname}` : text;
  }

  const p    = event.process;
  const n    = event.network;
  const host = event.hostname ? ` on ${event.hostname}` : "";
  const email = event.user_email ?? event.user?.email;
  // The cloud / identity actor the log itself names (IAM user, service account, caller),
  // else the source address: never a bare "System" when the log says who it was.
  const cloudActor = rawStr(event.raw, "aws.cloudtrail.userIdentity.userName", "aws.cloudtrail.user_identity.user_name",
    "userIdentity.userName", "gcp.audit.authentication_info.principal_email", "protoPayload.authenticationInfo.principalEmail",
    "azure.activitylogs.identity.claims_initiated_by_user.name", "azure.caller", "okta.actor.alternateId", "github.actor");
  // The account a host or app log names (auditd / sshd / sudo user, an AI gateway's end user).
  const rawUser = rawStr(event.raw, "sudo.user", "sshd.user", "user.name", "gateway.user_id");
  const who  = email ? email.split("@")[0]
               : event.process?.user ? event.process.user.split("\\").pop()!
               : cloudActor ? cloudActor.split("/").pop()!.split("@")[0]
               : rawUser ? shortUser(rawUser)
               : event.hostname ?? event.src_ip ?? "System";
  const namedActor = !!(email || event.process?.user || cloudActor || rawUser);
  const fileName = event.file?.name || baseName(event.file?.path)
    || baseName(rawStr(event.raw, "file.name", "crowdstrike.FileName", "data.office365.SourceFileName", "file.path"));
  const op = operationOf(event);
  const audit = auditLine(event, op);
  if (audit) return audit;

  // A service-desk record (ServiceNow): the ticket's own number, state and summary
  // are the observable — not a generic "policy modified".
  const ticket = rawStr(event.raw, "servicenow.number");
  if (ticket) {
    const state = rawStr(event.raw, "servicenow.state");
    const summary = rawStr(event.raw, "servicenow.short_description");
    return `Ticket ${ticket}${state ? ` (${state})` : ""}${summary ? `: ${summary}` : ""}`;
  }

  switch (event.event_type) {
    case "process_create":
      if (p) return `${p.parent_name || "System"} started ${p.name}${host}`;
      if (rawImage) return `${rawParent ? baseName(rawParent) : "A process"} started ${baseName(rawImage)}${host}`;
      return `New process started${host}`;
    case "file_create":
      return p ? `${p.name} created ${fileName || "a file"}${host}` : `File created${fileName ? `: ${fileName}` : ""}${host}`;
    case "file_modify":
      return p ? `${p.name} modified ${fileName || "a file"}${host}` : `File modified${fileName ? `: ${fileName}` : ""}${host}`;
    case "file_access":
      return `${p?.name ?? who} opened ${fileName || "a file"}${host}`;
    case "file_copy":
      return `${p?.name ?? who} copied ${fileName || "a file"}${host}`;
    case "process_access": {
      const target = rawStr(event.raw, "winlog.event_data.TargetImage", "crowdstrike.TargetProcessImageFileName",
        "crowdstrike.TargetFileName");
      return `${p?.name ?? "A process"} opened a handle to ${target ? baseName(target) : "another process"}${host}`;
    }
    case "file_delete":
      return `File deleted${fileName ? `: ${fileName}` : ""}${host}`;
    case "net_connection":
      return `${event.hostname || who} connected to ${dest || "an external host"}`;
    case "net_blocked":
      return `Connection blocked to ${n?.domain || event.dst_ip || "external host"}`;
    case "dns_query":
      return `${event.hostname || who} looked up ${dnsQuery || n?.domain || "a domain"}`;
    case "auth_success":
      return `${who} logged in${host}`;
    case "auth_failure": {
      // An identity provider's own result code is part of the record ("error 50126", "error 50072").
      const code = rawStr(event.raw, "azure.signinlogs.properties.status.errorCode", "azure.signinlogs.resultType", "data.office365.ErrorNumber");
      return `${who} failed to log in${host}${code && code !== "0" ? ` (error ${code})` : ""}`;
    }
    case "mfa_challenge":
    case "mfa_push_sent":
      return `${who} received a two-factor auth challenge`;
    case "mfa_denied":
      return `${who} rejected an unexpected two-factor push`;
    case "vpn_login":
      return `${who} connected via VPN`;
    case "vpn_logout":
      return `${who} disconnected from VPN`;
    case "vpn_failed":
      return `${who} failed to connect via VPN`;
    case "account_modify":
      return op ? `${who} performed ${op}` : `${who} changed account settings${host}`;
    case "account_create":
      return `New account created for ${who}`;
    case "account_delete":
      return `Account deleted${host}`;
    case "account_lockout":
      return `${who} account was locked out`;
    case "group_modify":
      return `Group membership changed${host}`;
    case "privilege_escalation":
      return `${who} gained elevated privileges${host}`;
    case "cloud_api_call": {
      if (op && namedActor) return `${who} called ${op}`;
      // A service's own request log names no caller: the resource (and model deployment) that served it.
      const res = rawStr(event.raw, "azure.resource.name", "gcp.resource.name");
      const dep = rawStr(event.raw, "azure.open_ai.properties.model_deployment_name");
      if (op && res && !event.src_ip) return `${op} request to ${res}${dep ? ` (${dep})` : ""}`;
      return op ? `${who} called ${op}` : `${who} made a cloud API call`;
    }
    case "cloud_storage_access": {
      const bkt = rawStr(event.raw, "aws.cloudtrail.requestParameters.bucketName", "AccountName", "azure.resource.name", "gcp.resource.name");
      // StorageBlobLogs ObjectKey is "/<account>/<container>/<blob>" (quoted in the export).
      const objectKey = rawStr(event.raw, "ObjectKey").replace(/^"|"$/g, "").split("/").filter(Boolean).slice(1).join("/");
      const key = rawStr(event.raw, "aws.cloudtrail.requestParameters.key") || objectKey;
      const tgt = [bkt, key].filter(Boolean).join("/");
      return op ? `${who} called ${op} on ${tgt || "cloud storage"}` : `${who} accessed ${tgt || "cloud storage"}`;
    }
    case "role_assignment": {
      const role = rawStr(event.raw, "iam.role.name", "vsphere.event.permission.roleName");
      return `${who} changed a role assignment${role ? ` (${role})` : op ? ` (${op})` : ""}`;
    }
    case "cloud_role_change":
      return `${who} changed a cloud role`;
    case "av_detection":
    case "av_quarantine":
    case "av_blocked":
    case "edr_alert":
      return `Threat detected on ${event.hostname || "endpoint"}`;
    case "email_received": {
      const { from } = mailParties(event);
      return safe(`${who} received an email${from ? ` from ${from}` : ""}`, `${who} received an email`);
    }
    case "email_clicked":
      return `${who} clicked a link in an email`;
    case "email_sent": {
      // The sender is the mailbox the record names (an outbound EmailEvents row has no internal user column).
      const { from, to } = mailParties(event);
      const sender = email ? who : from ? shortUser(from) : who;
      return safe(`${sender} sent an email${to ? ` to ${to}` : ""}`, `${sender} sent an email`);
    }
    case "email_blocked":
    case "email_quarantined": {
      const { from } = mailParties(event);
      const verb = event.event_type === "email_quarantined" ? "quarantined" : "blocked";
      return safe(`Email to ${who}${from ? ` from ${from}` : ""} ${verb}`, `Email to ${who} ${verb}`);
    }
    case "sharepoint_access":
    case "sharepoint_download":
      return `${who} accessed ${fileName || "a file"} in SharePoint${op ? ` (${op})` : ""}`;
    case "teams_message":
      return `${who} sent a Teams message`;
    case "scheduled_task":
      if (opts.preferFields && (p || rawImage)) return `${p?.parent_name || (rawParent ? baseName(rawParent) : "A process")} started ${p?.name || baseName(rawImage)}${host}`;
      return `Scheduled task ran${host}`;
    case "service_install":
      return `New service installed${host}`;
    case "registry_set":
    case "registry_delete":
      if (regKey) {
        const key = baseName(regKey);
        return `${p?.name ?? "A process"} ${event.event_type === "registry_delete" ? "deleted" : "set"} registry value ${key}${host}`;
      }
      return `Registry entry modified${host}`;
    case "dlp_alert":
    case "dlp_block":
      return `Data policy alert for ${who}`;
    case "ids_signature":
    case "ids_blocked": {
      // The firewall's threat entry: its threat name / id and category (PAN-OS threatid, category).
      const tName = rawStr(event.raw, "pan.threat_name", "panw.threat_name", "threat.name", "ids.signature_name");
      const tId = rawStr(event.raw, "pan.threat_id", "panw.threatid", "ids.signature_id").replace(/^SID:/i, "");
      const tCat = rawStr(event.raw, "pan.threat_category", "panw.category", "ids.category");
      if (!tName && !tId) return `Intrusion detection alert${host}`;
      const label = tName ? `${tName}${tId ? ` (${tId})` : ""}` : `ID ${tId}`;
      const route = event.src_ip && event.dst_ip ? ` from ${event.src_ip} to ${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ""}` : host;
      return safe(`Threat ${label}${tCat ? `, ${tCat}` : ""}${route}`, `Intrusion detection alert${host}`);
    }
    case "waf_allow":
      return `Web request to ${n?.domain || "server"}`;
    case "waf_block":
      return `Web request blocked by the WAF${host}`;
    case "db_query":
      return `${who} ran a database query`;
    case "db_auth":
      return `${who} logged in to database`;
    case "ueba_anomaly":
    case "risk_score_change":
      return `Unusual behaviour detected for ${who}`;
    case "nac_quarantine":
      return `Device quarantined on network${host}`;
    case "nac_allow":
      return `Device allowed on network${host}`;
    case "http_request":
      // A server's own access log: the request it answered, not someone browsing.
      if (event.source === "web_server") return `${n?.method ?? "GET"} ${String(event.raw?.["url.path"] ?? "/")} on ${n?.domain ?? "web server"} answered ${n?.status ?? 200}`;
      // An API gateway's own log (Azure API Management): the API operation it proxied, never browsing.
      if (rawStr(event.raw, "Type") === "ApiManagementGatewayLogs") return apimLine(event);
      return `${who} browsed to ${n?.domain || hostOf(n?.url) || hostOf(rawStr(event.raw, "zscaler.url", "data.http.url")) || rawStr(event.raw, "zscaler.hostname", "url.domain") || event.dst_ip || "a website"}`;
    case "http_blocked":
      return `Web request blocked for ${who}`;
    case "mfa_disabled":
      return `MFA removed from account for ${who}`;
    case "policy_modification":
      // An Exchange / PowerShell cmdlet (New-InboxRule, Set-Mailbox) is a command the account ran.
      if (/^[A-Z][a-z]+-[A-Za-z]+$/.test(op)) return `${who} ran ${op}`;
      return op ? `${who} changed a policy (${op})` : `Security policy modified${host}`;
    case "privileged_operation":
      return `Privileged operation performed by ${who}${host}`;
    case "kerberos_tgt":
      return `Kerberos TGT requested for ${who}${host}`;
    case "kerberos_tgs":
      return `Kerberos service ticket requested by ${who}${host}`;
    case "audit_log_cleared":
      return `Security audit log cleared${host}`;
    case "ssh_login":
      return `${who} connected via SSH${host}`;
    case "ssh_failed":
      return `Failed SSH login attempt${host}`;
    case "sudo_command":
      return `${who} ran a privileged command via sudo${host}`;
    case "db_failed":
      return `Failed database login for ${who}`;
    case "k8s_pod_create":
      return `Kubernetes pod created${host}`;
    case "k8s_pod_delete":
      return `Kubernetes pod deleted${host}`;
    case "k8s_exec":
      return `kubectl exec into pod${host}`;
    case "k8s_rbac":
      return `Kubernetes RBAC role binding changed${host}`;
    case "linux_execve":
      return `${who} ran ${p?.name ?? (rawStr(event.raw, "process.name", "audit.comm", "auditd.log.comm") || "a command")}${host}`;
    case "linux_cron":
      return `Cron schedule changed${host}`;
    case "linux_priv_change":
      return `${who} changed user privileges${host}`;
    case "threat_intel_match":
    case "ioc_hit":
      return `Threat-intelligence indicator matched${host}`;
    case "dhcp_lease":
      return `${event.hostname ?? "A device"} received a DHCP address${event.src_ip ? ` (${event.src_ip})` : ""}`;
    default:
      return `${event.event_type.replace(/_/g, " ")}${host}`;
  }
}

/**
 * The Live SOC row layout: the user on its own line and the action under it,
 * with the username stripped from the front of the sentence so it isn't said
 * twice ("j.chen" / "Received an email"). No user → just the sentence.
 */
export function describeEventForRow(event: TelemetryEvent, opts: DescribeOptions = { preferFields: true }): { user?: string; title?: string; action: string } {
  const full = describeEvent(event, opts);
  const email = event.user_email ?? event.user?.email;
  if (!email) return { action: full };
  const user = email.split("@")[0];
  const escaped = user.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const stripped = full.replace(new RegExp(`^${escaped}(?:['’]s)?[\\s\\-:·,]+`, "i"), "").trim();
  // Capitalise only when the username was actually removed ("received an email" →
  // "Received an email"); a sentence that starts with a process keeps its case.
  const action = stripped && stripped !== full ? stripped.charAt(0).toUpperCase() + stripped.slice(1) : full;
  return { user, title: event.user_title ?? event.user?.title, action };
}
