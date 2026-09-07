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
import type { TelemetryEvent, Severity, EventType, ExpectedVerdict } from "../types";
import { resolve, SEV_NAME, type Ctx } from "./_core";
import { netbiosUser } from "../fabric";

const VENDOR = "Microsoft Sentinel";

export interface SentinelAlertOpts extends Ctx {
  alertName: string;
  ruleId?: string;
  detail?: string;                 // alert.description
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
      ...(o.detail ? { "alert.description": o.detail } : {}),
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

// ── UEBA anomaly / entity-risk-score event ────────────────────────────────────────────
// The anomaly-driven half of Sentinel: a behaviour-analytics anomaly (impossible
// travel, anonymous-IP token replay, mass download, suspicious inbox rule) or the
// rolled-up entity RISK SCORE that opens an anomaly-led hunt. Distinct from
// sentinelAlert (a signature/correlation summary): this carries entity/anomaly/
// risk/behavior fields and the boolean UEBA indicator flags.
export interface SentinelUebaOpts extends Ctx {
  srcIp?: string;
  userSam?: string;                // entity.name; else derived from the email local part
  alertName: string;
  alertSeverity?: "Informational" | "Low" | "Medium" | "High";
  eventType?: EventType;           // default "ueba_anomaly"
  /** UEBA boolean indicators set to "true" (e.g. ImpossibleTravelActivity, RiskyUser) */
  indicators?: string[];
  anomaly?: { type?: string; score?: number | string; reason?: string; confidence?: string };
  risk?: { level?: string; score?: number | string; state?: string };
  behavior?: { name?: string; category?: string; score?: number | string; baseline?: string; deviation?: string };
  geoCountry?: string;
  geoCity?: string;
  authStatus?: "success" | "failure";
  mfa?: boolean;
  sessionId?: string;
  deviceCompliant?: boolean;
  fullName?: string;
  department?: string;
  title?: string;
  groups?: string[];
  mitre?: string;
  tactic?: string;
  threatTactic?: string;           // threat.tactic.name
  extendedProperties?: Record<string, string | string[] | number>;
  eventAction?: string;
  eventOutcome?: string;
  severity?: Severity;
  expectedVerdict?: ExpectedVerdict;
  fpExplanation?: string;
  isDetection?: boolean;
  edrScope?: "edr" | "non_edr" | "hybrid";
  userTitle?: string;
  description?: string;
}
export function sentinelUeba(o: SentinelUebaOpts): TelemetryEvent {
  const r = resolve(o);
  const email = r.email ?? `${r.bareUser}@example.com`;
  const sam = o.userSam ?? (email.includes("@") ? email.split("@")[0] : email);
  const ext: Record<string, string | string[] | number> = {};
  for (const [k, v] of Object.entries(o.extendedProperties ?? {})) ext[`ExtendedProperties.${k}`] = v;
  const ind: Record<string, string> = {};
  for (const f of o.indicators ?? []) ind[f] = "true";
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: VENDOR, event_type: o.eventType ?? "ueba_anomaly",
    severity: o.severity ?? "high", src_ip: o.srcIp, user_email: email, user_title: o.userTitle ?? o.title,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isDetection ? { is_detection: true } : {}),
    ...(o.edrScope ? { edr_scope: o.edrScope } : {}),
    ...(o.geoCountry ? { geo: { country: o.geoCountry, city: o.geoCity } } : {}),
    description: o.description ?? `${VENDOR} UEBA raised ${o.alertName} for ${sam}`,
    raw: {
      "AlertName": o.alertName,
      "AlertSeverity": o.alertSeverity ?? SEV_NAME[o.severity ?? "high"],
      ...ind,
      "entity.name": sam,
      "entity.type": "user",
      "user.name": netbiosUser(o.companyId, sam),
      "user.email": email,
      ...(o.fullName ? { "user.full_name": o.fullName } : {}),
      ...(o.department ? { "user.department": o.department } : {}),
      ...(o.title ? { "user.title": o.title } : {}),
      ...(o.groups ? { "user.group.name": o.groups } : {}),
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
      ...(o.geoCountry ? { "source.geo.country_name": o.geoCountry } : {}),
      ...(o.geoCity ? { "source.geo.city_name": o.geoCity } : {}),
      ...(o.authStatus ? { "authentication.status": o.authStatus } : {}),
      ...(o.mfa !== undefined ? { "authentication.mfa": String(o.mfa) } : {}),
      ...(o.deviceCompliant !== undefined ? { "device.compliant": String(o.deviceCompliant) } : {}),
      ...(o.sessionId ? { "session.id": o.sessionId } : {}),
      ...(o.anomaly?.type ? { "anomaly.type": o.anomaly.type } : {}),
      ...(o.anomaly?.score !== undefined ? { "anomaly.score": String(o.anomaly.score) } : {}),
      ...(o.anomaly?.reason ? { "anomaly.reason": o.anomaly.reason } : {}),
      ...(o.anomaly?.confidence ? { "anomaly.confidence": o.anomaly.confidence } : {}),
      ...(o.risk?.level ? { "risk.level": o.risk.level } : {}),
      ...(o.risk?.score !== undefined ? { "risk.score": String(o.risk.score) } : {}),
      ...(o.risk?.state ? { "risk.state": o.risk.state } : {}),
      ...(o.behavior?.name ? { "behavior.name": o.behavior.name } : {}),
      ...(o.behavior?.category ? { "behavior.category": o.behavior.category } : {}),
      ...(o.behavior?.score !== undefined ? { "behavior.score": String(o.behavior.score) } : {}),
      ...(o.behavior?.baseline ? { "behavior.baseline": o.behavior.baseline } : {}),
      ...(o.behavior?.deviation ? { "behavior.deviation": o.behavior.deviation } : {}),
      ...(o.mitre ? { "threat.technique.id": o.mitre } : {}),
      ...(o.threatTactic ? { "threat.tactic.name": o.threatTactic } : {}),
      ...ext,
      "event.action": o.eventAction ?? "correlation-alert",
      "event.outcome": o.eventOutcome ?? "alerted",
    },
  };
}
