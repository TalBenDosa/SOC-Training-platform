/**
 * Three-way EDR triage classification for an incident's events.
 * See docs/SPEC-edr-scenario-integration.md §3.
 *
 * The rule mirrors real SOC triage (SIEM screens → escalate to EDR only when the
 * activity is endpoint-observable). It is a DERIVATION/default: a pack may set
 * `edr_scope` explicitly on its detection event; `classifyScope` is the fallback
 * and the basis for the validator.
 *
 *   edr      = host artifacts present, no independent control-plane facet →
 *              investigate in EDR
 *   hybrid   = host artifact AND an independent control-plane facet (identity /
 *              cloud / email, or an active network detection) → detection often
 *              surfaces in SIEM, pivot into the EDR host it correlates to
 *   non_edr  = control-plane only (cloud IdP / SaaS / network device / email) →
 *              no host process to walk; investigated in SIEM / identity console
 *
 * KEY NUANCE: passive network-transport logs (a firewall/proxy/DNS record of the
 * download, C2 beacon, or exfil that ACCOMPANIES an endpoint attack) are NOT an
 * independent control-plane facet — they are supporting evidence for the endpoint
 * investigation, so they do not tip an otherwise-endpoint incident to "hybrid".
 * What tips it is an identity/cloud/email plane (a real second investigation
 * destination) or an ACTIVE network detection (IDS/WAF fired, a block).
 */
import type { TelemetryEvent, LogSource, EventType } from "@/lib/sim/types";

export type EdrScope = "edr" | "hybrid" | "non_edr";

/** Sensors that live ON an endpoint/server — their events are host-observable. */
const HOST_SENSOR_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  "edr", "sysmon", "av", "windows_security", "linux_audit",
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
 * Independent control-plane facets — a genuine SECOND investigation destination
 * away from the host: identity/directory, cloud/SaaS, and email/collaboration.
 * Presence of one of these alongside a host artifact makes an incident "hybrid".
 */
const IDENTITY_CLOUD_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  "ad", "okta", "iam", "mfa",
  "o365", "gws", "cloudtrail", "cloud_azure", "cloud_gcp",
  "exchange", "sharepoint", "teams", "email_gateway",
]);

/** Network-transport sources — evidence that accompanies an attack, not a plane. */
const NETWORK_TRANSPORT_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  "firewall", "vpn", "proxy", "dns", "dhcp", "nac",
]);

/** Active network detections (a signature fired / a block) — these DO tip. */
const NETWORK_DETECTION_EVENT_TYPES: ReadonlySet<EventType> = new Set<EventType>([
  "net_blocked", "ids_signature", "ids_blocked", "waf_block",
]);

/** Any source that is not host-observable — used for the non_edr determination. */
const ANY_CONTROL_PLANE_SOURCES: ReadonlySet<LogSource> = new Set<LogSource>([
  ...IDENTITY_CLOUD_SOURCES, ...NETWORK_TRANSPORT_SOURCES,
  "ids", "waf", "dlp", "ueba", "threat_intel", "db_monitor", "siem", "soar", "k8s_audit",
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
  if (isHostObservable(e)) return false;
  return ANY_CONTROL_PLANE_SOURCES.has(e.source);
}

/**
 * Is this an INDEPENDENT control-plane facet that tips an endpoint incident to
 * hybrid — an identity/cloud/email plane, or an active network detection? Passive
 * network-transport logs (a plain firewall/proxy record of the download/C2/exfil)
 * return false: they are supporting evidence, not a second investigation.
 */
export function isHybridTippingFacet(e: TelemetryEvent): boolean {
  if (isHostObservable(e)) return false;
  if (IDENTITY_CLOUD_SOURCES.has(e.source)) return true;
  if (e.source === "ids" || e.source === "waf") return true;
  if (NETWORK_DETECTION_EVENT_TYPES.has(e.event_type)) return true;
  // A passive record from a pure transport source does not tip.
  if (NETWORK_TRANSPORT_SOURCES.has(e.source)) return false;
  // Remaining control planes (dlp/ueba/threat_intel/db_monitor/siem/soar/k8s) are
  // tooling/aggregation, not a distinct pivot destination — treat as neutral.
  return false;
}

/**
 * Classify one incident (its full set of events, SIEM + EDR) into the three-way
 * scope. Pass the events that share an `incident_id`.
 */
export function classifyScope(events: readonly TelemetryEvent[]): EdrScope {
  let host = false;
  let tipping = false;
  let anyControl = false;
  for (const e of events) {
    if (isHostObservable(e)) host = true;
    else {
      if (isHybridTippingFacet(e)) tipping = true;
      if (ANY_CONTROL_PLANE_SOURCES.has(e.source)) anyControl = true;
    }
    if (host && tipping) return "hybrid";
  }
  if (host) return "edr";
  void anyControl; // control-plane-only (or nothing to walk) → not an EDR case
  return "non_edr";
}

/** Does this incident warrant an "Investigate in EDR" affordance? */
export function isEdrInvestigable(scope: EdrScope): boolean {
  return scope === "edr" || scope === "hybrid";
}
