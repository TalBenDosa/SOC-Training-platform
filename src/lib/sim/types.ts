/**
 * Telemetry & alert types used across the platform UI and generators.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type AlertStatus = "new" | "triaging" | "investigating" | "contained" | "resolved" | "false_positive" | "escalated";
export type ExpectedVerdict = "tp" | "fp" | "escalate" | "informational";

export type LogSource =
  // Endpoint
  | "edr" | "sysmon" | "av" | "windows_security" | "linux_audit"
  // Network
  | "firewall" | "ids" | "vpn" | "proxy" | "dns" | "dhcp" | "nac" | "waf"
  // Identity
  | "ad" | "okta" | "iam" | "mfa"
  // Cloud / SaaS
  | "o365" | "gws" | "cloudtrail" | "cloud_azure" | "cloud_gcp"
  // Collaboration
  | "exchange" | "sharepoint" | "teams" | "email_gateway"
  // Security tooling
  | "dlp" | "ueba" | "threat_intel" | "db_monitor" | "siem" | "soar"
  // Legacy
  | "k8s_audit";

export type EventType =
  | "process_create" | "process_terminate" | "process_access"
  | "file_create" | "file_access" | "file_modify" | "file_delete" | "file_rename" | "file_copy"
  | "registry_set" | "registry_delete" | "registry_rename"
  | "net_connection" | "net_blocked" | "dns_query" | "http_request" | "http_blocked"
  | "auth_success" | "auth_failure" | "mfa_challenge" | "mfa_denied" | "mfa_push_sent"
  | "account_create" | "account_modify" | "account_delete" | "account_lockout"
  | "group_modify" | "privilege_escalation" | "role_assignment"
  | "email_received" | "email_sent" | "email_clicked" | "email_blocked" | "email_quarantined"
  | "vpn_login" | "vpn_logout" | "vpn_failed"
  | "cloud_api_call" | "cloud_storage_access" | "cloud_role_change"
  | "dlp_alert" | "dlp_block" | "data_classified"
  | "ueba_anomaly" | "risk_score_change"
  | "av_detection" | "av_quarantine" | "av_blocked"
  | "ids_signature" | "ids_blocked"
  | "waf_allow" | "waf_block"
  | "db_query" | "db_auth" | "db_schema_change"
  | "edr_alert" | "scheduled_task" | "service_install"
  | "sharepoint_access" | "sharepoint_download" | "sharepoint_share"
  | "teams_message" | "teams_file_share"
  | "threat_intel_match" | "ioc_hit"
  | "dhcp_lease" | "nac_quarantine" | "nac_allow"
  | "linux_execve" | "linux_priv_change" | "linux_cron"
  | "kerberos_tgt" | "kerberos_tgs" | "audit_log_cleared"
  | "mfa_disabled" | "policy_modification" | "privileged_operation"
  | "ssh_login" | "ssh_failed" | "sudo_command"
  | "db_failed" | "k8s_pod_create" | "k8s_pod_delete" | "k8s_exec" | "k8s_rbac";

export interface TelemetryEvent {
  id: string;
  ts: string;                   // ISO timestamp
  source: LogSource;
  vendor?: string;
  event_type: EventType;
  description?: string;         // Short analyst-facing summary (not revealing answer)
  expected_verdict?: ExpectedVerdict;
  hostname?: string;
  asset_id?: string;
  user?: {
    full_name?: string;
    email?: string;
    department?: string;
    title?: string;
  };
  user_email?: string;          // kept for backwards-compat
  user_title?: string;          // short role label shown as a chip in the feed (e.g. "Developer", "Trader")
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  geo?: { country?: string; city?: string; latitude?: number; longitude?: number };
  process?: {
    name: string;
    pid: number;
    path?: string;
    parent_name?: string;
    parent_pid?: number;
    cmdline?: string;
    user?: string;
    integrity?: "low" | "medium" | "high" | "system";
    hash?: { sha256?: string; md5?: string };
  };
  file?: {
    name?: string;
    path: string;
    sha256?: string;
    md5?: string;
    size?: number;
    extension?: string;
  };
  network?: {
    url?: string;
    domain?: string;
    method?: string;
    status?: number;
    bytes_in?: number;
    bytes_out?: number;
    user_agent?: string;
  };
  registry?: {
    path?: string;
    key?: string;
    value?: string;
  };
  dns?: {
    query?: string;
    query_type?: string;
    response?: string;
    rcode?: string;
  };
  authentication?: {
    method?: string;
    mfa_type?: string;
    result?: string;
    logon_type?: number;
  };
  cloud?: {
    provider?: string;
    service?: string;
    api_call?: string;
    region?: string;
    resource?: string;
  };
  rule?: {
    name?: string;
    category?: string;
    id?: string;
  };
  mitre_technique?: string;
  mitre_tactic?: string;
  severity?: Severity;
  /**
   * Story difficulty tier, stamped when the event is drawn into an attack story.
   * Drives progressive log fidelity: advanced-tier events get realistic benign
   * "noise" metadata so they read like production logs, while foundation-tier
   * events stay clean for a brand-new learner. Absent on benign / company-profile events.
   */
  tier?: "foundation" | "core" | "advanced";
  /** Mark this event as a training False Positive — looks alarming, but is actually benign. */
  fp_explanation?: string;
  /**
   * IT verification result for admin-action events.
   * "confirmed"  → IT says the change was authorised (expected activity — mark benign).
   * "unverified" → IT could not find a ticket — treat as suspicious, investigate.
   */
  it_verify_result?: "confirmed" | "unverified";
  it_verify_message?: string;
  raw: Record<string, unknown>;
}

export interface Alert {
  id: string;
  alert_uid: string;
  title: string;
  description: string;
  source: LogSource;
  vendor: string;
  severity: Severity;
  status: AlertStatus;
  confidence: number;
  risk_score: number;
  mitre_tactic?: string;
  mitre_technique?: string;
  hostname?: string;
  user_email?: string;
  src_ip?: string;
  dst_ip?: string;
  src_country?: string;
  dst_country?: string;
  process?: { name: string; cmdline?: string; parent?: string; sha256?: string };
  url?: string;
  domain?: string;
  detected_at: string;
  related_events: string[];
}

export interface IOC {
  type: "ip" | "domain" | "url" | "sha256" | "md5" | "email" | "user" | "host";
  value: string;
  first_seen?: string;
  last_seen?: string;
  count?: number;
  reputation?: "malicious" | "suspicious" | "unknown" | "clean";
  tags?: string[];
}

export interface ScenarioBundle {
  scenario_id: string;
  title: string;
  threat_actor: string;
  attack_kind: string;
  narrative: string;
  learning_objectives: string[];
  alerts: Alert[];
  events: TelemetryEvent[];
  iocs: IOC[];
  killchain: { ts: string; phase: string; action: string }[];
  questions: ScenarioQuestion[];
}

export interface ScenarioQuestion {
  id: string;
  prompt: string;
  hint?: string;
  kind: "single" | "multi" | "text";
  options?: { value: string; label: string }[];
  answer: string | string[];
  xp: number;
  explanation: string;
}
