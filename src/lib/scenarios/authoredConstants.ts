import type { LogSource, EventType, IOC } from "@/lib/sim/types";

/**
 * Runtime lists for authored-scenario editing + validation. Shared by the client
 * editor (dropdowns) and the server splitter (allowlist validation). Plain
 * module (not server-only) so both sides import the same source of truth.
 */

// Full set — the server validates against this; an unknown value falls back.
export const LOG_SOURCES: LogSource[] = [
  "edr", "sysmon", "av", "windows_security", "linux_audit",
  "firewall", "ids", "vpn", "proxy", "dns", "dhcp", "nac", "waf",
  "ad", "okta", "iam", "mfa",
  "o365", "gws", "cloudtrail", "cloud_azure", "cloud_gcp",
  "exchange", "sharepoint", "teams", "email_gateway",
  "dlp", "ueba", "threat_intel", "db_monitor", "siem", "soar",
  "k8s_audit",
];

export const EVENT_TYPES: EventType[] = [
  "process_create", "process_terminate", "process_access",
  "file_create", "file_access", "file_modify", "file_delete", "file_rename", "file_copy",
  "registry_set", "registry_delete", "registry_rename",
  "net_connection", "net_blocked", "dns_query", "http_request", "http_blocked",
  "auth_success", "auth_failure", "mfa_challenge", "mfa_denied", "mfa_push_sent",
  "account_create", "account_modify", "account_delete", "account_lockout",
  "group_modify", "privilege_escalation", "role_assignment",
  "email_received", "email_sent", "email_clicked", "email_blocked", "email_quarantined",
  "vpn_login", "vpn_logout", "vpn_failed",
  "cloud_api_call", "cloud_storage_access", "cloud_role_change",
  "dlp_alert", "dlp_block", "data_classified",
  "ueba_anomaly", "risk_score_change",
  "av_detection", "av_quarantine", "av_blocked",
  "ids_signature", "ids_blocked",
  "waf_allow", "waf_block",
  "db_query", "db_auth", "db_schema_change",
  "edr_alert", "scheduled_task", "service_install",
  "sharepoint_access", "sharepoint_download", "sharepoint_share",
  "teams_message", "teams_file_share",
  "threat_intel_match", "ioc_hit",
  "dhcp_lease", "nac_quarantine", "nac_allow",
  "linux_execve", "linux_priv_change", "linux_cron",
  "kerberos_tgt", "kerberos_tgs", "audit_log_cleared",
  "mfa_disabled", "policy_modification", "privileged_operation",
  "ssh_login", "ssh_failed", "sudo_command",
  "db_failed", "k8s_pod_create", "k8s_pod_delete", "k8s_exec", "k8s_rbac",
];

export const IOC_TYPES: IOC["type"][] = ["ip", "domain", "url", "sha256", "md5", "email", "user", "host"];

// A short, friendly subset surfaced first in the editor dropdowns (the full
// lists remain available). Keeps the common cases one click away.
export const COMMON_LOG_SOURCES: LogSource[] = [
  "edr", "windows_security", "firewall", "proxy", "dns", "o365", "ad", "okta", "email_gateway", "dlp", "cloudtrail", "siem",
];
export const COMMON_EVENT_TYPES: EventType[] = [
  "process_create", "net_connection", "http_request", "dns_query", "auth_success", "auth_failure",
  "email_received", "file_create", "av_detection", "edr_alert", "cloud_api_call", "dlp_alert",
];
