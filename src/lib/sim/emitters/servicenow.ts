/**
 * ServiceNow ITSM log EMITTER.
 *
 * The ticketing / IT-service-management control plane — the incident, change
 * request and catalog-item records an analyst reads to see the human process
 * around a technical event: a social-engineered helpdesk ticket, a change window
 * a wiper hid behind, a software-install request behind an AV alert. ServiceNow
 * is pinned to an EXACT field set (no prefixes), so the emitter renders the common
 * record envelope (table, number, state, short_description) and takes every other
 * servicenow.* / incident.* / sla.* / client.* / edr.* field through `extra` —
 * each key checked to be one the registry allows.
 *
 * ServiceNow is source:"soar" and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import type { Ctx } from "./_core";

const VENDOR = "ServiceNow ITSM";

export interface ServiceNowRecordOpts extends Ctx {
  table: string;                    // servicenow.table (incident | change_request | sc_req_item)
  number: string;                   // servicenow.number (e.g. INC0048217, CHG0031882)
  state?: string;                   // servicenow.state (New | Resolved | Implement …)
  shortDescription?: string;        // servicenow.short_description
  eventType?: EventType;            // default "policy_modification"
  callerId?: string;                // servicenow.caller_id (also user_email)
  /** any other servicenow.* / incident.* / sla.* / client.* / edr.* fields */
  extra?: Record<string, string | number>;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function serviceNowRecord(o: ServiceNowRecordOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "soar", vendor: VENDOR, event_type: o.eventType ?? "policy_modification",
    severity: o.severity ?? "low", user_email: o.user ?? o.callerId ?? undefined,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `${o.table} ${o.number}${o.state ? ` (${o.state})` : ""}`,
    raw: {
      "servicenow.table": o.table,
      "servicenow.number": o.number,
      ...(o.state ? { "servicenow.state": o.state } : {}),
      ...(o.shortDescription ? { "servicenow.short_description": o.shortDescription } : {}),
      ...(o.callerId ? { "servicenow.caller_id": o.callerId } : {}),
      ...(o.extra ?? {}),
    },
  };
}
