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
import { ecsTechnique } from "@/lib/logs/ecsFields";
import { netbiosUser } from "../fabric";

const VENDOR = "Microsoft Sentinel";

/** Deterministic, GUID-shaped id from a seed — so the same event always renders the same
 *  SystemAlertId / VendorOriginalId / TenantId (stable across re-renders, realistic shape). */
function guidFrom(seed: string): string {
  let h = 0x811c9dc5;
  const hex: string[] = [];
  for (let i = 0; i < 32; i++) {
    h ^= (seed.charCodeAt(i % Math.max(1, seed.length)) || 7) + i * 131;
    h = Math.imul(h, 0x01000193) >>> 0;
    hex.push((h & 0xf).toString(16));
  }
  const s = hex.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-4${s.slice(13, 16)}-a${s.slice(17, 20)}-${s.slice(20, 32)}`;
}
const alertTypeSlug = (name: string) => name.replace(/[^A-Za-z0-9]+/g, "") || "CustomAlert";

/**
 * SecurityAlert.Tactics uses Sentinel's own tactic enum (PascalCase, no spaces). ATT&CK v19's Stealth
 * and Defense Impairment are still "DefenseEvasion" in the product's vocabulary. A technique with no
 * authored tactic takes its primary tactic (ATT&CK Enterprise, earliest in matrix order); compact table
 * of parent technique ids (without the "T") per tactic, so the emitter ships no ATT&CK library.
 */
const TACTIC_OF_TECHNIQUE: Record<string, string> = {
  Reconnaissance: "1589 1595 1598",
  ResourceDevelopment: "1583 1584 1585 1608",
  InitialAccess: "1078 1091 1133 1189 1190 1195 1199 1200 1566",
  Execution: "1053 1059 1197 1204 1569 1609 1610 1651",
  Persistence: "1098 1136 1137 1176 1505 1543 1547 1556",
  PrivilegeEscalation: "1055 1068 1134 1548 1611",
  DefenseEvasion: "1027 1036 1070 1218 1564 1684 1553 1578 1685 1686",
  CredentialAccess: "1003 1056 1110 1528 1539 1552 1555 1557 1558 1606 1621",
  Discovery: "1016 1018 1033 1046 1057 1069 1082 1083 1087 1135 1482 1526 1580 1613 1619",
  LateralMovement: "1021 1534 1550 1563",
  Collection: "1005 1039 1074 1114 1115 1213 1530 1560",
  CommandAndControl: "1071 1090 1105 1219 1568 1571 1572 1573",
  Exfiltration: "1030 1041 1048 1052 1537 1567",
  Impact: "1485 1486 1489 1490 1496 1499 1531 1561 1565 1657",
};
const TECH_TACTIC = new Map<string, string>(Object.entries(TACTIC_OF_TECHNIQUE).flatMap(([t, ids]) => ids.split(" ").map(id => [`T${id}`, t] as [string, string])));
const TACTIC_NAME: Record<string, string> = {
  reconnaissance: "Reconnaissance", "resource development": "ResourceDevelopment", "initial access": "InitialAccess", execution: "Execution",
  persistence: "Persistence", "privilege escalation": "PrivilegeEscalation", "defense evasion": "DefenseEvasion", stealth: "DefenseEvasion",
  "defense impairment": "DefenseEvasion", "credential access": "CredentialAccess", discovery: "Discovery", "lateral movement": "LateralMovement",
  collection: "Collection", "command and control": "CommandAndControl", exfiltration: "Exfiltration", impact: "Impact",
};
/** Sentinel tactic tokens for an alert: the authored tactics (any spelling), else the techniques' primary tactic. */
export function sentinelTactics(tactics: string[] | undefined, tactic: string | undefined, mitre: string | undefined): string[] {
  const named = (tactics ?? (tactic ? [tactic] : [])).map(t => TACTIC_NAME[t.trim().toLowerCase()] ?? t.replace(/[^A-Za-z]/g, "")).filter(Boolean);
  if (named.length) return [...new Set(named)];
  const fromTech = (mitre ?? "").split(/[,\s]+/).map(id => TECH_TACTIC.get(id.split(".")[0].toUpperCase())).filter((t): t is string => !!t);
  return [...new Set(fromTech)];
}
/** Deterministic minutes from a seed (the analytic's query window). */
const minutesFrom = (seed: string, lo: number, hi: number) => { let h = 0x811c9dc5; for (let i = 0; i < seed.length; i++) { h ^= seed.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return lo + (h % (hi - lo + 1)); };

/**
 * Sentinel's alert/incident severity enum is High | Medium | Low | Informational —
 * there is no "Critical". A caller asking for critical gets the product's ceiling
 * (High) both in the raw block and on the event, so the feed never shows a
 * severity the named product cannot produce.
 */
function sentinelSev(s: Severity | undefined): Exclude<Severity, "critical"> {
  const v = s ?? "high";
  return v === "critical" ? "high" : v;
}

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
  /** ExtendedProperties.<Name> — string, number or string[] enrichment values */
  extendedProperties?: Record<string, string | number | string[]>;
  eventAction?: string;        // default "correlation-alert"
  eventOutcome?: string;       // default "alerted"
  description?: string;
  // ── SecurityAlert realism (Tal, 2026-10-04) — all optional; defaults are derived from
  //    the event so a plain sentinelAlert({alertName}) already renders a realistic record.
  tenantId?: string;
  vendorName?: string;                 // SecurityAlert.VendorName — default "Microsoft"
  productName?: string;                // SecurityAlert.ProductName — default per source
  providerName?: string;               // SecurityAlert.ProviderName
  alertType?: string;                  // default a slug of alertName
  status?: "New" | "InProgress" | "Resolved" | "Dismissed";   // default "New"
  tactics?: string[];                  // SecurityAlert.Tactics[] — else [tactic]
  startTime?: string; endTime?: string;
  remediationSteps?: string[];
  alertLink?: string;
  /** Explicit SecurityAlert Entities[]; else a host/account/ip set is built from the event. */
  entities?: Record<string, unknown>[];
  /** Defender (MDATP) custom columns, present when the alert originated in MDE. */
  mde?: {
    category?: string; detectionSource?: string; determination?: string;
    classification?: string; investigationState?: string;
    threatName?: string; threatFamilyName?: string;
  };
}
export function sentinelAlert(o: SentinelAlertOpts): TelemetryEvent {
  // A correlation alert about an identity or a cloud resource names no host: never draw one from the
  // fabric (a made-up laptop in Entities / CompromisedEntity points the analyst at a machine that exists
  // nowhere else). The host entity and host fields appear only when the caller names the host.
  const r0 = resolve(o);
  const r = { ...r0, host: o.host ?? "", srcIp: o.srcIp ?? (o.host ? r0.srcIp : "") };
  const sev = sentinelSev(o.severity);
  const ext: Record<string, string | string[] | number> = {};
  for (const [k, v] of Object.entries(o.extendedProperties ?? {})) ext[`ExtendedProperties.${k}`] = v;

  const fromMde = !!o.mde;
  const product = o.productName ?? (fromMde ? "Microsoft Defender Advanced Threat Protection" : "Azure Sentinel");
  const provider = o.providerName ?? (fromMde ? "MDATP" : "ASI Scheduled Alerts");
  const domain = r.email?.includes("@") ? r.email.split("@")[1] : undefined;
  const sam = r.bareUser && r.bareUser !== "-" ? r.bareUser : undefined;
  // SecurityAlert Entities — the real array-of-typed-objects shape (host / account / ip).
  const entities = o.entities ?? [
    ...(r.host ? [{ "$id": "1", Type: "host", HostName: r.host, ...(domain ? { DnsDomain: domain, FQDN: `${r.host}.${domain}` } : {}) }] : []),
    ...(sam ? [{ "$id": "2", Type: "account", Name: sam, ...(domain ? { UPNSuffix: domain } : {}), ...(r.email ? { AadUserId: guidFrom(r.email) } : {}) }] : []),
    ...(r.srcIp ? [{ "$id": "3", Type: "ip", Address: r.srcIp }] : []),
  ];

  return {
    id: o.id, ts: o.ts, source: "siem", vendor: VENDOR, event_type: o.eventType ?? "ueba_anomaly",
    severity: sev, ...(r.host ? { hostname: r.host } : {}), ...(r.srcIp ? { src_ip: r.srcIp } : {}), user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} raised ${o.alertName}${r.host ? ` on ${r.host}` : r.email ? ` for ${r.email}` : ""}`,
    raw: {
      // ── Microsoft Sentinel SecurityAlert schema ──
      "TimeGenerated": o.ts,
      "TenantId": o.tenantId ?? guidFrom(`${o.companyId}:tenant`),
      "DisplayName": o.alertName,
      "AlertName": o.alertName,
      "AlertSeverity": SEV_NAME[sev],
      ...(o.detail ? { "Description": o.detail } : {}),
      "ProviderName": provider,
      "VendorName": o.vendorName ?? "Microsoft",
      "ProductName": product,
      "DetectionProductName": product,
      "AlertType": o.alertType ?? alertTypeSlug(o.alertName),
      "VendorOriginalId": guidFrom(`${o.id}:vendor`),
      "SystemAlertId": guidFrom(`${o.id}:system`),
      // A scheduled analytic reports the span of the events it matched: StartTime = the first,
      // EndTime = the last, both before the alert itself (TimeGenerated / ProcessingEndTime).
      "StartTime": o.startTime ?? new Date(Date.parse(o.ts) - minutesFrom(`${o.id}:start`, 5, 55) * 60_000).toISOString(),
      "EndTime": o.endTime ?? new Date(Date.parse(o.ts) - minutesFrom(`${o.id}:end`, 1, 4) * 60_000).toISOString(),
      "ProcessingEndTime": o.ts,
      "Status": o.status ?? "New",
      "Tactics": sentinelTactics(o.tactics, o.tactic, o.mitre),
      ...(o.mitre ? { "Techniques": o.mitre.split(/[,\s]+/).filter(Boolean) } : {}),
      // The entity the alert is about: the host when it names one, else the account.
      "CompromisedEntity": r.host || r.email || (sam ?? ""),
      "Entities": entities,
      "SourceSystem": "Detection",
      ...(o.alertLink ? { "AlertLink": o.alertLink } : {}),
      ...(o.remediationSteps ? { "RemediationSteps": o.remediationSteps } : {}),
      // ── Defender (MDATP) custom columns, when the alert came from MDE ──
      ...(o.mde?.threatName ? { "ThreatName": o.mde.threatName } : {}),
      ...(o.mde?.threatFamilyName ? { "ThreatFamilyName": o.mde.threatFamilyName } : {}),
      ...(o.mde?.category ? { "MicrosoftDefenderAtp.Category": o.mde.category } : {}),
      ...(o.mde?.detectionSource ? { "MicrosoftDefenderAtp.DetectionSource": o.mde.detectionSource } : {}),
      ...(o.mde?.determination ? { "MicrosoftDefenderAtp.Determination": o.mde.determination } : {}),
      ...(o.mde?.classification ? { "MicrosoftDefenderAtp.Classification": o.mde.classification } : {}),
      ...(o.mde?.investigationState ? { "MicrosoftDefenderAtp.InvestigationState": o.mde.investigationState } : {}),
      // alert rule id + enrichment
      ...(o.ruleId ? { "alert.rule.id": o.ruleId } : {}),
      ...ext,
      // ── ECS mirrors kept for cross-vendor enrichment / describeEvent ──
      ...(r.host ? { "host.name": r.host } : {}),
      ...(r.srcIp ? { "host.ip": r.srcIp } : {}),
      "target.user.name": r.domainUser,
      ...(o.fullName ? { "user.full_name": o.fullName } : {}),
      ...(o.department ? { "user.department": o.department } : {}),
      ...(o.title ? { "user.title": o.title } : {}),
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
  ruleId?: string;                 // alert.rule.id
  threatTactic?: string;           // threat.tactic.name
  threatTechnique?: string;        // threat.technique.name
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
    severity: sentinelSev(o.severity), src_ip: o.srcIp, user_email: email, user_title: o.userTitle ?? o.title,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isDetection ? { is_detection: true } : {}),
    ...(o.edrScope ? { edr_scope: o.edrScope } : {}),
    ...(o.geoCountry ? { geo: { country: o.geoCountry, city: o.geoCity } } : {}),
    description: o.description ?? `${VENDOR} UEBA raised ${o.alertName} for ${sam}`,
    raw: {
      "AlertName": o.alertName,
      "AlertSeverity": o.alertSeverity ?? SEV_NAME[sentinelSev(o.severity)],
      ...(o.ruleId ? { "alert.rule.id": o.ruleId } : {}),
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
      ...ecsTechnique(o.mitre),
      ...(o.threatTechnique ? { "threat.technique.name": o.threatTechnique } : {}),
      ...(o.threatTactic ? { "threat.tactic.name": o.threatTactic } : {}),
      ...ext,
      "event.action": o.eventAction ?? "correlation-alert",
      "event.outcome": o.eventOutcome ?? "alerted",
    },
  };
}
