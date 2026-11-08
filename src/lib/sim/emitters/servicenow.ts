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
  const extra = o.extra ?? {};
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
      ...recordDefaults(o, extra),
      ...extra,
    },
  };
}

/** Incident category / subcategory as stored (the out-of-the-box choice values). */
const CATEGORY: [RegExp, string, string][] = [
  [/password|mfa|authenticator|locked out|access to|account/i, "inquiry", ""],
  [/printer|laptop|battery|monitor|docking|keyboard|hardware/i, "hardware", ""],
  [/vpn|network|wifi|wi-fi|switch|firewall/i, "network", ""],
  [/teams|outlook|software|license|install/i, "software", ""],
];

/**
 * The fields every record of a table carries whatever the update was (review 2026-11-08: story
 * tickets carried 26-45 fields and noise tickets 6-15, so the field count told them apart). Each is
 * filled only when the caller did not author it, and none depends on the row's time (a story that
 * updates one ticket in several rows authors its own opened_at, so it cannot drift between rows).
 */
function recordDefaults(o: ServiceNowRecordOpts, extra: Record<string, string | number>): Record<string, string | number> {
  const has = (k: string) => extra[`servicenow.${k}`] !== undefined;
  // A sys_user reference: an email or a user_name ("svc-nessus").
  const person = (v: unknown) => (typeof v === "string" && /^[\w.@-]+$/.test(v.trim()) ? v.trim() : undefined);
  const out: Record<string, string | number> = {
    // The SIEM integration's envelope (the ServiceNow integration's event.* fields).
    "event.provider": "ServiceNow", "event.module": "servicenow", "event.dataset": "servicenow.event", "log.level": "info",
    "event.created": new Date(Date.parse(o.ts) + 1_000 + (o.number.length * 97) % 900).toISOString(),
  };
  if (!has("impact")) out["servicenow.impact"] = "3 - Low";
  if (!has("urgency")) out["servicenow.urgency"] = "3 - Low";
  if (!has("priority") && !has("impact") && !has("urgency")) out["servicenow.priority"] = "5 - Planning";
  const opener = person(extra["servicenow.opened_by"]) ?? (o.table === "change_request" ? person(extra["servicenow.assigned_to"]) ?? person(extra["servicenow.requested_by"])
    : o.callerId ?? person(extra["servicenow.caller_id"]) ?? person(extra["servicenow.requested_for"]) ?? person(extra["servicenow.assigned_to"]));
  if (!has("opened_by") && opener) out["servicenow.opened_by"] = opener;
  if (o.table === "incident") {
    const text = `${o.shortDescription ?? ""} ${extra["servicenow.description"] ?? ""}`;
    const cat = CATEGORY.find(([re]) => re.test(text));
    if (!has("category")) out["servicenow.category"] = cat?.[1] ?? "inquiry";
    if (!has("subcategory") && cat?.[2]) out["servicenow.subcategory"] = cat[2];
    if (!has("contact_type")) out["servicenow.contact_type"] = /walk-up|walk-in|in person/i.test(text) ? "Walk-in" : "Self-service";
  }
  if (o.table === "change_request" && !has("risk")) out["servicenow.risk"] = "Low";
  return out;
}
