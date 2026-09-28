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
function rawStr(raw: Record<string, unknown> | undefined, ...keys: string[]): string {
  for (const k of keys) { const v = raw?.[k]; if (typeof v === "string" && v.trim()) return v.trim(); }
  return "";
}

/** The vendor's own operation name (CloudTrail eventName, O365 Operation, Azure
 *  operationName) — a raw field the analyst would read anyway, never a verdict.
 *  `event.action` is deliberately NOT used: some sources put conclusions there. */
function operationOf(e: TelemetryEvent): string {
  return rawStr(e.raw, "aws.cloudtrail.eventName", "data.office365.Operation", "azure.auditlogs.operationName",
    "azure.operation.name", "gcp.audit.method_name", "protoPayload.methodName", "okta.eventType", "github.action",
    "gws.event.name", "intune.activityType", "vsphere.event.eventTypeId", "aws.guardduty.service.action.awsApiCallAction.api");
}

const baseName = (p?: string) => (p ? p.split(/[\\/]/).filter(Boolean).pop() ?? p : "");
const hostOf = (u?: string) => { if (!u) return ""; try { return new URL(u).hostname; } catch { return u.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0]; } };

export interface DescribeOptions {
  /** Prefer a sentence built from the log's fields over the bare Windows Event
   *  Viewer text when the fields say more ("cmd.exe started powershell.exe on
   *  FIN-WS-08" instead of "Process Create"). Used by the scenario page. */
  preferFields?: boolean;
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
  if (!event.mitre_technique && event.description && event.description.trim().length > 12) {
    return event.description;
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
  const rawParent = rawStr(event.raw, "winlog.event_data.ParentImage", "process.parent.executable", "crowdstrike.parent_basefilename", "crowdstrike.ParentBaseFileName");
  const dest = event.network?.domain || event.dst_ip || rawStr(event.raw, "url.domain", "RemoteUrl", "RemoteIP", "id.resp_h", "destination.ip", "destination.domain");
  const hasFields = !!(event.process || rawImage || dnsQuery || event.network?.domain || event.dst_ip || event.file || regKey);
  const useViewer = eventCode && WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode] &&
    !(opts.preferFields && FIELD_RICH.has(event.event_type) && hasFields);
  if (useViewer) {
    const text = WIN_EVENT_VIEWER_DESCRIPTIONS[eventCode!];
    // On the scenario page say WHERE it happened — the live feed shows the host in its own column.
    return opts.preferFields && event.hostname && !text.includes(event.hostname)
      ? `${text.replace(/\.$/, "")} — ${event.hostname}` : text;
  }

  const p    = event.process;
  const n    = event.network;
  const host = event.hostname ? ` on ${event.hostname}` : "";
  const email = event.user_email ?? event.user?.email;
  const who  = email ? email.split("@")[0]
               : event.process?.user ? event.process.user.split("\\").pop()!
               : event.hostname ?? "System";
  const fileName = event.file?.name || baseName(event.file?.path)
    || baseName(rawStr(event.raw, "file.name", "crowdstrike.FileName", "data.office365.SourceFileName"));
  const op = operationOf(event);

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
      const target = rawStr(event.raw, "winlog.event_data.TargetImage", "crowdstrike.CrossProcessTargetName",
        "crowdstrike.target_imagefilename", "crowdstrike.TargetFileName");
      return `${p?.name ?? "A process"} opened a handle to ${target ? baseName(target) : "another process"}${host}`;
    }
    case "file_delete":
      return `File deleted${host}`;
    case "net_connection":
      return `${event.hostname || who} connected to ${dest || "an external host"}`;
    case "net_blocked":
      return `Connection blocked to ${n?.domain || event.dst_ip || "external host"}`;
    case "dns_query":
      return `${event.hostname || who} looked up ${dnsQuery || n?.domain || "a domain"}`;
    case "auth_success":
      return `${who} logged in${host}`;
    case "auth_failure":
      return `${who} failed to log in${host}`;
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
    case "cloud_api_call":
      return op ? `${who} called ${op}` : `${who} made a cloud API call`;
    case "cloud_storage_access":
      return op ? `${who} accessed cloud storage (${op})` : `${who} accessed cloud storage`;
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
    case "email_received":
      return `${who} received an email`;
    case "email_clicked":
      return `${who} clicked a link in an email`;
    case "email_sent":
      return `${who} sent an email`;
    case "email_blocked":
    case "email_quarantined":
      return `Suspicious email blocked for ${who}`;
    case "sharepoint_access":
    case "sharepoint_download":
      return `${who} accessed a file in SharePoint`;
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
    case "ids_blocked":
      return `Intrusion detection alert${host}`;
    case "waf_allow":
      return `Web request to ${n?.domain || "server"}`;
    case "waf_block":
      return `Web attack blocked${host}`;
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
      return `${who} browsed to ${n?.domain || hostOf(n?.url) || hostOf(rawStr(event.raw, "zscaler.url", "data.http.url")) || rawStr(event.raw, "zscaler.hostname", "url.domain") || event.dst_ip || "a website"}`;
    case "http_blocked":
      return `Web request blocked for ${who}`;
    case "mfa_disabled":
      return `MFA removed from account for ${who}`;
    case "policy_modification":
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
      return `${who} ran ${p?.name ?? "a command"}${host}`;
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
