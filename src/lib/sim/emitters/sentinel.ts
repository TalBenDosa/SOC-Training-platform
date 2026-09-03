/**
 * Microsoft Sentinel (SIEM) log EMITTERS.
 *
 * The correlation / enrichment layer — a Sentinel analytics or UEBA alert that ties
 * endpoint + network evidence together and adds host-and-identity context (software
 * installed today, autoruns added, whether the account is a local admin). Same contract
 * as the other emitters: a typed call renders a complete TelemetryEvent whose raw block
 * uses only registry-valid Sentinel fields (the ExtendedProperties./azure./sentinel./
 * ueba. prefixes + the shared ECS fields), with host/IP/identity from the company fabric.
 *
 * Sentinel is control-plane (source:"siem"), so these events carry no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import { resolve, SEV_NAME, type Ctx } from "./_core";

const VENDOR = "Microsoft Sentinel";

export interface SentinelAlertOpts extends Ctx {
  alertName: string;
  ruleId?: string;
  severity?: Severity;
  eventType?: EventType;       // default "ueba_anomaly"
  mitre?: string;
  tactic?: string;
  fullName?: string;           // user.full_name
  department?: string;
  title?: string;
  /** ExtendedProperties.<Name> — string or string[] enrichment values */
  extendedProperties?: Record<string, string | string[]>;
  eventAction?: string;        // default "correlation-alert"
  eventOutcome?: string;       // default "alerted"
  description?: string;
}
export function sentinelAlert(o: SentinelAlertOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "high";
  const ext: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(o.extendedProperties ?? {})) ext[`ExtendedProperties.${k}`] = v;
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: VENDOR, event_type: o.eventType ?? "ueba_anomaly",
    severity: sev, hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} raised ${o.alertName} on ${r.host}`,
    raw: {
      "AlertName": o.alertName,
      ...(o.ruleId ? { "alert.rule.id": o.ruleId } : {}),
      "alert.severity": SEV_NAME[sev],
      "host.name": r.host,
      "host.ip": r.srcIp,
      "target.user.name": r.domainUser,
      ...(o.fullName ? { "user.full_name": o.fullName } : {}),
      ...(o.department ? { "user.department": o.department } : {}),
      ...(o.title ? { "user.title": o.title } : {}),
      ...ext,
      "event.action": o.eventAction ?? "correlation-alert",
      "event.outcome": o.eventOutcome ?? "alerted",
    },
  };
}
