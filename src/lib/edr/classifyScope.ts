/**
 * Three-way EDR triage classification for an incident's events.
 * See docs/SPEC-edr-scenario-integration.md §3.
 *
 * The rule mirrors real SOC triage (SIEM screens → escalate to EDR only when the
 * activity is endpoint-observable). It is a DERIVATION/default: a pack may set
 * `edr_scope` explicitly on its detection event; `classifyScope` is the fallback
 * and the basis for the validator.
 *
 *   edr      = host artifacts present, no control-plane facet → investigate in EDR
 *   hybrid   = BOTH a host artifact AND a control-plane facet → detection in SIEM,
 *              pivot into the EDR host it correlates to
 *   non_edr  = control-plane only (cloud IdP / SaaS / network device / email) →
 *              no host process to walk; investigated in SIEM / identity console
 */
import type { TelemetryEvent, LogSource, EventType } from "@/lib/sim/types";

export type EdrScope = "edr" | "hybrid" | "non_edr";

/** Sensors that live ON an endpoint/server — their events are host-observable. */
const HOST_SENSOR_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  "edr", "sysmon", "av", "windows_security", "linux_audit",
]);

/**
 * Sources observable only at a control plane AWAY from any single host — cloud
 * IdPs, SaaS, network devices, email gateways, directory/DC auth. `ad` is here
 * (a DC Kerberos/replication event is a directory-plane fact); when a TOOL runs
 * the attack from a compromised endpoint, that host's process events add the
 * host facet and tip the incident to "hybrid".
 */
const CONTROL_PLANE_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  // network devices
  "firewall", "ids", "vpn", "proxy", "dns", "dhcp", "nac", "waf",
  // identity / directory (cloud IdP + on-prem DC directory plane)
  "ad", "okta", "iam", "mfa",
  // cloud / SaaS / collaboration
  "o365", "gws", "cloudtrail", "cloud_azure", "cloud_gcp",
  "exchange", "sharepoint", "teams", "email_gateway",
  // security tooling / other control planes
  "dlp", "ueba", "threat_intel", "db_monitor", "siem", "soar", "k8s_audit",
]);

/** Event types that are inherently a host-side artifact regardless of source. */
const HOST_EVENT_TYPES: ReadonlySet<EventType> = new Set<EventType>([
  "process_create", "process_terminate", "process_access",
  "file_create", "file_access", "file_modify", "file_delete", "file_rename", "file_copy",
  "registry_set", "registry_delete", "registry_rename",
  "scheduled_task", "service_install",
  "av_detection", "av_quarantine", "av_blocked",
  "linux_execve", "linux_cron", "sudo_command",
]);

/** Host logons (local/interactive/network/SSH) recorded ON the endpoint. */
const HOST_LOGON_EVENT_TYPES: ReadonlySet<EventType> = new Set<EventType>([
  "auth_success", "auth_failure", "ssh_login", "ssh_failed",
]);

/**
 * Does this single event leave a host-observable artifact — a process, a host
 * logon/side-effect, a file/registry/service/scheduled-task/memory op on a
 * specific endpoint? (This is why brute force / password spray AGAINST a
 * server — RDP/SSH/SMB/local, seen as 4625 on the host — is `edr`, while the
 * same spray against a cloud IdP is `non_edr`.)
 */
export function isHostObservable(e: TelemetryEvent): boolean {
  if (e.process?.pid != null) return true;
  if (e.registry) return true;
  if (HOST_EVENT_TYPES.has(e.event_type)) return true;
  // A host logon counts only when reported by an on-host sensor (the Security /
  // Linux audit log), not when it's a cloud IdP sign-in.
  if (HOST_LOGON_EVENT_TYPES.has(e.event_type) && HOST_SENSOR_SOURCES.has(e.source)) return true;
  // Any event straight from an on-host sensor is host-observable by definition.
  if (HOST_SENSOR_SOURCES.has(e.source)) return true;
  return false;
}

/** Does this event live only at a control plane away from a single host? */
export function isControlPlane(e: TelemetryEvent): boolean {
  // A host-observable event is never counted as control-plane, even if its source
  // is dual-listed — the host facet wins for that event.
  if (isHostObservable(e)) return false;
  return CONTROL_PLANE_SOURCES.has(e.source);
}

/**
 * Classify one incident (its full set of events, SIEM + EDR) into the three-way
 * scope. Pass the events that share an `incident_id`.
 */
export function classifyScope(events: readonly TelemetryEvent[]): EdrScope {
  let host = false;
  let control = false;
  for (const e of events) {
    if (isHostObservable(e)) host = true;
    else if (isControlPlane(e)) control = true;
    if (host && control) return "hybrid";
  }
  if (host) return "edr";
  return "non_edr"; // control-plane only, or nothing to walk
}

/** Does this incident warrant an "Investigate in EDR" affordance? */
export function isEdrInvestigable(scope: EdrScope): boolean {
  return scope === "edr" || scope === "hybrid";
}
