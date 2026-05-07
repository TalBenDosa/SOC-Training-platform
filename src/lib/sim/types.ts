/**
 * Telemetry & alert types used across the platform UI and generators.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type AlertStatus = "new" | "triaging" | "investigating" | "contained" | "resolved" | "false_positive" | "escalated";

export type LogSource =
  | "edr" | "sysmon" | "firewall" | "vpn" | "dns" | "proxy"
  | "o365" | "ad" | "okta" | "cloudtrail" | "k8s_audit" | "dlp";

export type EventType =
  | "process_create" | "process_terminate"
  | "file_create" | "file_modify" | "file_delete"
  | "registry_set" | "registry_delete"
  | "net_connection" | "dns_query" | "http_request"
  | "auth_success" | "auth_failure" | "mfa_challenge" | "mfa_denied"
  | "account_create" | "account_modify" | "group_modify"
  | "email_received" | "email_sent" | "email_clicked"
  | "vpn_login" | "vpn_logout"
  | "cloud_api_call"
  | "edr_alert" | "av_detection" | "ids_signature";

export interface TelemetryEvent {
  id: string;
  ts: string;                  // ISO timestamp
  source: LogSource;
  vendor?: string;             // CrowdStrike Falcon, Palo Alto, Sentinel...
  event_type: EventType;
  hostname?: string;
  user_email?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  process?: {
    name: string;
    pid: number;
    parent_name?: string;
    parent_pid?: number;
    cmdline?: string;
    user?: string;
    integrity?: "low" | "medium" | "high" | "system";
  };
  file?: { path: string; sha256?: string; size?: number };
  network?: { url?: string; domain?: string; method?: string; status?: number; bytes_in?: number; bytes_out?: number };
  mitre_technique?: string;
  severity?: Severity;
  raw: Record<string, unknown>;
}

export interface Alert {
  id: string;
  alert_uid: string;          // CRWD-9F3A1B2C, MS-A12345
  title: string;
  description: string;
  source: LogSource;
  vendor: string;
  severity: Severity;
  status: AlertStatus;
  confidence: number;         // 0..100
  risk_score: number;         // 0..100
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
  related_events: string[];   // telemetry event ids
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
