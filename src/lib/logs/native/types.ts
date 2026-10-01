/**
 * Native log contract (Tal, 2026-10-01: "no schema mixing").
 *
 * Every log the platform shows is rendered in its SOURCE's NATIVE format — the
 * exact structure and field names the product emits / its official API returns,
 * as documented in docs/log-schemas/<card>.md. One module per source lives in
 * ./sources/<sourceId>.ts and exports a {@link NativeSource}.
 *
 * The conversion input is the platform's structured TelemetryEvent (user, host,
 * process, file, network, dns, auth, cloud … plus the legacy `raw` map). Because
 * the input is vendor-neutral, ANY module of a category can render ANY event of
 * that category — that is how one attack story is shown as CrowdStrike for one
 * team and SentinelOne for another.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export type SourceId =
  // EDR
  | "crowdstrike" | "mde" | "sentinelone" | "sophos"
  // Firewall
  | "paloalto" | "fortigate" | "checkpoint" | "cisco_ftd" | "cisco_asa"
  // Identity
  | "entra" | "okta" | "windows_security" | "cyberark"
  // Email & collaboration
  | "m365" | "google_workspace" | "defender_o365" | "proofpoint"
  // Cloud
  | "aws_cloudtrail" | "aws_guardduty" | "aws_vpcflow" | "azure_activity" | "gcp_audit" | "k8s_audit"
  // Remote access / proxy / DNS / host / ITSM
  | "globalprotect" | "anyconnect" | "fortigate_sslvpn" | "zscaler_zpa" | "cloudflare_access"
  | "zscaler_zia" | "windows_dns" | "infoblox" | "sysmon" | "linux_auditd" | "servicenow";

/** The platform category a source belongs to (one vendor per category per session). */
export type SourceCategory =
  | "edr" | "firewall" | "idp" | "onprem_ad" | "pam" | "collab" | "email_security"
  | "cloud" | "cloud_detection" | "network_flow" | "k8s" | "vpn" | "ztna" | "proxy" | "dns"
  | "host_telemetry" | "itsm";

/** Wire format of the source: JSON-native, or text-native rendered as a flat JSON object. */
export type NativeFormat = "json" | "kv" | "csv" | "syslog" | "xml" | "cef" | "ndjson";

/** One rendered log. */
export interface NativeLog {
  sourceId: SourceId;
  /** Event kind within the source, e.g. "ProcessRollup2", "traffic", "user.session.start", "GetObject". */
  kind: string;
  format: NativeFormat;
  /**
   * The native record. JSON-native sources: the object exactly as delivered (nested).
   * Text-native sources: a FLAT object keyed by the vendor's own field names.
   */
  record: Record<string, unknown>;
  /** The wire line for text-native sources (key=value / CSV / syslog / CEF / XML). */
  rawLine?: string;
  /** Epoch ms of the event as the source stamps it (for ordering + use-case windows). */
  timeMs: number;
}

/** Fields of one event kind. Paths are dot-joined; array elements use "[]" (e.g. "events[].name"). */
export interface KindSchema {
  /** Fields that must be present (non-undefined) on every record of this kind. */
  required: string[];
  /** Every other field the source may emit for this kind. Anything outside required ∪ optional is a violation. */
  optional: string[];
  /**
   * Path prefixes whose sub-keys are free-form in the real product (e.g. CloudTrail
   * "requestParameters", Okta "debugContext.debugData", Windows "EventData" variants).
   * Keys below these prefixes are not checked.
   */
  openPrefixes?: string[];
}

export interface SourceSchema {
  sourceId: SourceId;
  category: SourceCategory;
  /** The card this module implements (docs/log-schemas/<card>). */
  card: string;
  /** Display name, e.g. "CrowdStrike Falcon". */
  product: string;
  format: NativeFormat;
  /**
   * TelemetryEvent.vendor strings (lower-cased substring match) that belong to this
   * source natively, e.g. ["crowdstrike", "falcon"].
   */
  vendorMatch: string[];
  /** TelemetryEvent.source values this module can render (any vendor of the category). */
  telemetrySources: string[];
  kinds: Record<string, KindSchema>;
}

/** Per-session / per-company context so identifiers stay consistent across a story. */
export interface NativeCtx {
  companyId: string;
  /** Primary email/AD domain, e.g. "nexacorp.com". */
  domain: string;
  /** NetBIOS domain, e.g. "NEXACORP". */
  netbios: string;
  /** Stable tenant identifiers derived from the company (cloud account id, tenant ids …). */
  tenant: {
    awsAccountId: string;
    azureTenantId: string;
    azureSubscriptionId: string;
    gcpProjectId: string;
    googleCustomerId: string;
    oktaOrg: string;
    crowdstrikeCid: string;
  };
  /** Deterministic hex/uuid helpers seeded from a string (event id + purpose). Never Math.random. */
  hex: (seed: string, len: number) => string;
  uuid: (seed: string) => string;
  /** Deterministic integer in [min, max]. */
  int: (seed: string, min: number, max: number) => number;
}

export interface NativeSource {
  schema: SourceSchema;
  /**
   * Render a platform event in this source's native format. Return null when the
   * event cannot be represented truthfully by this source (never fake a field the
   * product does not have — the spec's rule: such stories are not offered).
   */
  fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null;
  /** Detection use cases written against this source's native fields. */
  useCases: UseCase[];
}

// ── Use cases (detection rules) ──────────────────────────────────────────────

export type Op =
  | "eq" | "neq" | "in" | "nin" | "contains" | "icontains" | "startsWith" | "endsWith"
  | "regex" | "exists" | "missing" | "gt" | "gte" | "lt" | "lte" | "cidr" | "notCidr";

/** A field condition or a boolean combination. Paths use the same dot / "[]" syntax as schemas. */
export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | { field: string; op: Op; value?: unknown };

export interface UseCase {
  /** Stable id, e.g. "aws_cloudtrail.stoplogging". */
  id: string;
  title: string;
  sourceId: SourceId;
  /** Kinds the rule applies to (records of other kinds are ignored). Omit = all kinds. */
  kinds?: string[];
  severity: "low" | "medium" | "high" | "critical";
  mitre: string[];
  /** What it detects and why it matters — shown to students. */
  description: string;
  /** The same logic as analysts would write it (pseudo-SPL / KQL / Sigma-ish), shown to students. */
  logic: string;
  /** Per-record filter. */
  match: Condition;
  /** Optional aggregation: fire when ≥ count matching records share groupBy within windowSec. */
  threshold?: { groupBy: string[]; count: number; windowSec: number; distinct?: string };
  /** Known benign look-alikes analysts should rule out. */
  falsePositives?: string[];
}

export interface UseCaseHit {
  useCaseId: string;
  /** Indexes into the evaluated log array. */
  records: number[];
  groupKey?: string;
}
